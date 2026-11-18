package alerts

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ZacxDev/muster-alerts/internal/outbox"
)

// SecretHeader carries the shared secret (or send it as a bearer token).
const SecretHeader = "X-Muster-Alerts-Secret"

// MaxBodyBytes bounds a webhook body.
const MaxBodyBytes = 1 << 20

// Server receives the webhooks. Every field but Now is required.
type Server struct {
	Secret     string
	Namespace  string
	Box        *outbox.Outbox
	Episodes   *Episodes
	MaxPending int // past this many undelivered events, a new one is answered 503
	Log        *log.Logger
	Now        func() time.Time

	mu sync.Mutex // one notification at a time: episodes and outbox move together
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Handler serves POST /alertmanager, POST /generic and GET /healthz.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /alertmanager", s.guard(s.alertmanager))
	mux.HandleFunc("POST /generic", s.guard(s.generic))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		// Open to anyone (a liveness probe carries no secret), so it says
		// only "up"; how many alerts wait for muster is for the secret's
		// holder.
		out := map[string]any{"ok": true}
		if SecretOK(r, s.Secret) {
			out["pending"] = s.Box.Len()
		}
		answer(w, http.StatusOK, out)
	})
	return mux
}

func answer(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// SecretOK compares the presented secret with the configured one in constant
// time (both hashed first, so neither length leaks). It accepts the secret in
// X-Muster-Alerts-Secret or as "Authorization: Bearer <secret>", which is what
// Alertmanager's http_config.authorization sends.
func SecretOK(r *http.Request, secret string) bool {
	got := r.Header.Get(SecretHeader)
	if got == "" {
		if v, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
			got = v
		}
	}
	if got == "" || secret == "" {
		return false
	}
	a, b := sha256.Sum256([]byte(got)), sha256.Sum256([]byte(secret))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// guard checks the secret BEFORE reading the body, bounds the body, and turns
// the handler's answer into the HTTP one.
func (s *Server) guard(h func(raw []byte) (int, map[string]any)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !SecretOK(r, s.Secret) {
			s.Log.Printf("webhook %s from %s: bad or missing secret, refused", r.URL.Path, r.RemoteAddr)
			answer(w, http.StatusUnauthorized, map[string]any{"error": "bad or missing secret"})
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
		var tooBig *http.MaxBytesError
		switch {
		case errors.As(err, &tooBig):
			answer(w, http.StatusRequestEntityTooLarge, map[string]any{"error": fmt.Sprintf("the body is over %d bytes", MaxBodyBytes)})
			return
		case err != nil:
			answer(w, http.StatusBadRequest, map[string]any{"error": "the body could not be read"})
			return
		}
		code, out := h(raw)
		if code == http.StatusServiceUnavailable {
			w.Header().Set("Retry-After", "60")
		}
		answer(w, code, out)
	}
}

func (s *Server) alertmanager(raw []byte) (int, map[string]any) {
	p, err := ParseAlertmanager(raw)
	if err != nil {
		s.Log.Printf("webhook /alertmanager: %v", err)
		return http.StatusBadRequest, map[string]any{"error": err.Error()}
	}
	group := GroupID("alertmanager", p.GroupKey)
	return s.record(group, func() (Event, bool, error) {
		if p.Status == "firing" {
			ep, err := s.Episodes.Firing(group, earliestStart(p.Alerts, "firing"), s.now())
			if err != nil {
				return Event{}, false, err
			}
			key := TaskKey(s.Namespace, group, ep)
			n := 0
			for _, a := range p.Alerts {
				if a.Status == "firing" {
					n++
				}
			}
			return firingEvent(key, amTitle(p), amBody(p),
				fmt.Sprintf("Alertmanager: %d alert(s) firing since %s", n, time.Unix(ep.Start, 0).UTC().Format(time.RFC3339))), true, nil
		}
		ep, ok := s.Episodes.Resolved(group)
		if !ok {
			// No episode on record (the plugin never saw it fire, or lost
			// its state): the earliest starts-at is the key a firing
			// notification of the same alerts would have used.
			ep = Episode{Start: earliestStart(p.Alerts, "").Unix()}
		}
		var last time.Time
		for _, a := range p.Alerts {
			if a.EndsAt.After(last) {
				last = a.EndsAt
			}
		}
		return resolvedEvent(TaskKey(s.Namespace, group, ep),
			fmt.Sprintf("Alertmanager: resolved, all %d alert(s) in the group ended (last at %s)", len(p.Alerts), last.UTC().Format(time.RFC3339))), true, nil
	}, p.Status == "resolved")
}

func (s *Server) generic(raw []byte) (int, map[string]any) {
	g, err := ParseGeneric(raw)
	if err != nil {
		s.Log.Printf("webhook /generic: %v", err)
		return http.StatusBadRequest, map[string]any{"error": err.Error()}
	}
	group := GroupID("generic", g.ID)
	return s.record(group, func() (Event, bool, error) {
		if g.Status == "firing" {
			var earliest time.Time
			if g.StartedAt != nil {
				earliest = *g.StartedAt
			}
			ep, err := s.Episodes.Firing(group, earliest, s.now())
			if err != nil {
				return Event{}, false, err
			}
			return firingEvent(TaskKey(s.Namespace, group, ep), oneLine("[FIRING] "+g.Title), genericBody(g),
				fmt.Sprintf("alert %s firing since %s", g.ID, time.Unix(ep.Start, 0).UTC().Format(time.RFC3339))), true, nil
		}
		ep, ok := s.Episodes.Resolved(group)
		if !ok && g.StartedAt != nil {
			ep, ok = Episode{Start: g.StartedAt.Unix()}, true
		}
		if !ok {
			return Event{}, false, nil // nothing open to resolve, and no starts-at to name one
		}
		return resolvedEvent(TaskKey(s.Namespace, group, ep), fmt.Sprintf("alert %s resolved", g.ID)), true, nil
	}, g.Status == "resolved")
}

// record turns one notification into (at most) one event and writes it to
// the outbox before answering: once the sender sees 200 the event survives a
// crash. A repeat of an event already recorded is answered 200 as a
// duplicate and writes nothing.
func (s *Server) record(group string, build func() (Event, bool, error), resolves bool) (int, map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ev, ok, err := build()
	if err != nil {
		s.Log.Printf("webhook: state: %v", err)
		return http.StatusInternalServerError, map[string]any{"error": "the alert could not be recorded"}
	}
	if !ok {
		return http.StatusOK, map[string]any{"accepted": 0, "duplicate": 0, "note": "no open alert to resolve"}
	}
	if !s.Box.Has(ev.ID) && s.Box.Len() >= s.MaxPending {
		s.Log.Printf("webhook: %d events wait for muster (ALERTS_MAX_PENDING); refusing new ones with 503 until they drain", s.Box.Len())
		return http.StatusServiceUnavailable, map[string]any{"error": "too many alerts are waiting to reach muster; send it again later"}
	}
	added, err := s.Box.Add(ev.ID, ev.Task)
	if err != nil {
		s.Log.Printf("webhook: %v", err)
		return http.StatusInternalServerError, map[string]any{"error": "the alert could not be recorded"}
	}
	if resolves {
		if err := s.Episodes.Close(group); err != nil {
			s.Log.Printf("webhook: state: %v", err)
		}
	}
	if !added {
		s.Log.Printf("event %s: a repeat of an event already recorded; nothing new", ev.ID)
		return http.StatusOK, map[string]any{"accepted": 0, "duplicate": 1, "event_id": ev.ID}
	}
	s.Log.Printf("event %s: recorded", ev.ID)
	return http.StatusOK, map[string]any{"accepted": 1, "duplicate": 0, "event_id": ev.ID}
}
