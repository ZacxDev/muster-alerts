// Package alerts turns alert notifications (Prometheus Alertmanager's webhook,
// or the plugin's own generic JSON) into muster task events: one task per
// firing episode of an alert group, and an update on that same task when the
// group resolves.
package alerts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ZacxDev/muster-alerts/internal/muster"
)

// MaxListedAlerts bounds how many alerts a task body lists one by one.
const MaxListedAlerts = 20

// Event is one task request for muster, under its own event id.
type Event struct {
	ID   string
	Task muster.Task
}

// ErrMalformed is a payload that is not one this plugin accepts.
var ErrMalformed = errors.New("malformed payload")

func malformed(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, a...))
}

// GroupID is the stable, tag-safe id of an alert group: 16 hex characters of
// the sha256 of its source and key.
func GroupID(source, groupKey string) string {
	sum := sha256.Sum256([]byte(source + "\x00" + groupKey))
	return hex.EncodeToString(sum[:8])
}

// TaskKey is the muster task key of one firing episode: the group plus the
// episode's starts-at, so each episode is its own task and every notification
// within it lands on the same one. A re-fire after a "resolved" with the same
// starts-at adds "-r<n>" (n = 1, 2, …), so it is a task of its own.
func TaskKey(namespace, group string, ep Episode) string {
	if ep.Refire > 0 {
		return fmt.Sprintf("%s:%s-%d-r%d", namespace, group, ep.Start, ep.Refire)
	}
	return fmt.Sprintf("%s:%s-%d", namespace, group, ep.Start)
}

// The two events an episode can produce. The comment starts with the event id,
// because muster dedupes a comment by its text and names the routed event by
// it (docs/plugins.md, "POST /plugin/v1/tasks").
func firingEvent(key, title, body, summary string) Event {
	id := key + "#firing"
	return Event{ID: id, Task: muster.Task{
		Key:          key,
		Create:       &muster.TaskCreate{Title: title, Body: body},
		Comment:      "[" + id + "] " + summary,
		RouteToChief: true,
		Notice:       muster.NoticeAssigned,
	}}
}

func resolvedEvent(key, summary string) Event {
	id := key + "#resolved"
	return Event{ID: id, Task: muster.Task{
		Key:          key,
		Comment:      "[" + id + "] " + summary,
		RouteToChief: true,
		Notice:       muster.NoticeUpdate,
	}}
}

// ---- Alertmanager ------------------------------------------------------------

// AMAlert is one alert in an Alertmanager webhook (version 4).
type AMAlert struct {
	Status       string            `json:"status"`
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	StartsAt     time.Time         `json:"startsAt"`
	EndsAt       time.Time         `json:"endsAt"`
	GeneratorURL string            `json:"generatorURL"`
	Fingerprint  string            `json:"fingerprint"`
}

// AMPayload is Alertmanager's webhook body (version 4).
type AMPayload struct {
	Version           string            `json:"version"`
	GroupKey          string            `json:"groupKey"`
	TruncatedAlerts   int               `json:"truncatedAlerts"`
	Status            string            `json:"status"`
	Receiver          string            `json:"receiver"`
	GroupLabels       map[string]string `json:"groupLabels"`
	CommonLabels      map[string]string `json:"commonLabels"`
	CommonAnnotations map[string]string `json:"commonAnnotations"`
	ExternalURL       string            `json:"externalURL"`
	Alerts            []AMAlert         `json:"alerts"`
}

// ParseAlertmanager decodes and checks an Alertmanager webhook body.
func ParseAlertmanager(raw []byte) (AMPayload, error) {
	var p AMPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, malformed("not Alertmanager webhook JSON: %v", err)
	}
	switch {
	case p.Version != "4":
		return p, malformed(`version must be "4" (Alertmanager's webhook format)`)
	case strings.TrimSpace(p.GroupKey) == "":
		return p, malformed("groupKey is required")
	case p.Status != "firing" && p.Status != "resolved":
		return p, malformed(`status must be "firing" or "resolved"`)
	case len(p.Alerts) == 0:
		return p, malformed("alerts is empty")
	}
	for i, a := range p.Alerts {
		if a.Status != "firing" && a.Status != "resolved" {
			return p, malformed(`alerts[%d].status must be "firing" or "resolved"`, i)
		}
		if a.StartsAt.IsZero() {
			return p, malformed("alerts[%d].startsAt is required", i)
		}
	}
	return p, nil
}

// earliestStart is the earliest startsAt among the alerts with status (or
// among all of them, status ""), and zero if there are none.
func earliestStart(alerts []AMAlert, status string) time.Time {
	var t time.Time
	for _, a := range alerts {
		if (status == "" || a.Status == status) && (t.IsZero() || a.StartsAt.Before(t)) {
			t = a.StartsAt
		}
	}
	return t
}

func labelList(m map[string]string) string {
	keys := slices.Sorted(maps.Keys(m))
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, ", ")
}

func amTitle(p AMPayload) string {
	name := p.CommonLabels["alertname"]
	if name == "" {
		name = p.GroupLabels["alertname"]
	}
	if name == "" {
		name = "alert group"
	}
	title := "[FIRING] " + name
	if sev := p.CommonLabels["severity"]; sev != "" {
		title += " (" + sev + ")"
	}
	if gl := labelList(p.GroupLabels); gl != "" {
		title += ": " + gl
	}
	return oneLine(title)
}

// MaxTaskBodyBytes bounds a task body. muster keeps at most 16 KiB of one and
// cuts from the END, so the plugin puts what names the alert (receiver, group
// key, links) first and trims the rest itself, with TrimmedMarker.
const MaxTaskBodyBytes = 15 << 10

// TrimmedMarker ends a body the plugin trimmed.
const TrimmedMarker = "\n[trimmed: the full alert is at its source]"

// trimBody cuts s to MaxTaskBodyBytes in all, on a character boundary, marking
// the cut.
func trimBody(s string) string {
	if len(s) <= MaxTaskBodyBytes {
		return s
	}
	s = s[:MaxTaskBodyBytes-len(TrimmedMarker)]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s + TrimmedMarker
}

func amBody(p AMPayload) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Receiver: %s\n", p.Receiver)
	fmt.Fprintf(&b, "Group key: %s\n", p.GroupKey)
	if p.ExternalURL != "" {
		fmt.Fprintf(&b, "Alertmanager: %s\n", p.ExternalURL)
	}
	b.WriteString("\n")
	firing := 0
	for _, a := range p.Alerts {
		if a.Status == "firing" {
			firing++
		}
	}
	fmt.Fprintf(&b, "Alertmanager reports %d firing alert(s) in group {%s}.\n", firing, labelList(p.GroupLabels))
	if v := p.CommonAnnotations["summary"]; v != "" {
		fmt.Fprintf(&b, "\nSummary: %s\n", v)
	}
	if v := p.CommonAnnotations["description"]; v != "" {
		fmt.Fprintf(&b, "Description: %s\n", v)
	}
	if v := labelList(p.CommonLabels); v != "" {
		fmt.Fprintf(&b, "Common labels: %s\n", v)
	}
	b.WriteString("\nAlerts:\n")
	for i, a := range p.Alerts {
		if i == MaxListedAlerts {
			fmt.Fprintf(&b, "- … and %d more\n", len(p.Alerts)-MaxListedAlerts)
			break
		}
		fmt.Fprintf(&b, "- [%s] %s (since %s)\n", a.Status, labelList(a.Labels), a.StartsAt.UTC().Format(time.RFC3339))
		if v := a.Annotations["summary"]; v != "" && v != p.CommonAnnotations["summary"] {
			fmt.Fprintf(&b, "  summary: %s\n", v)
		}
		if a.GeneratorURL != "" {
			fmt.Fprintf(&b, "  source: %s\n", a.GeneratorURL)
		}
	}
	if p.TruncatedAlerts > 0 {
		fmt.Fprintf(&b, "(%d more alert(s) were left out by Alertmanager's max_alerts)\n", p.TruncatedAlerts)
	}
	return trimBody(b.String())
}

// ---- Generic -----------------------------------------------------------------

// Generic is the plugin's own simple webhook format, for any sender that is not
// Alertmanager. See the README, "The generic format".
type Generic struct {
	ID        string            `json:"id"`
	Status    string            `json:"status"`
	Title     string            `json:"title"`
	Body      string            `json:"body"`
	URL       string            `json:"url"`
	StartedAt *time.Time        `json:"started_at"`
	Labels    map[string]string `json:"labels"`
}

// ParseGeneric decodes and checks a generic webhook body. Unknown fields are
// refused, so a typo is a 400 rather than a silently missing value.
func ParseGeneric(raw []byte) (Generic, error) {
	var g Generic
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&g); err != nil {
		return g, malformed("not the generic alert JSON: %v", err)
	}
	if dec.More() {
		return g, malformed("one JSON object per request")
	}
	switch {
	case g.ID == "" || len(g.ID) > 200 || strings.IndexFunc(g.ID, func(r rune) bool { return unicode.IsControl(r) }) >= 0:
		return g, malformed("id must be 1-200 bytes without control characters")
	case g.Status != "firing" && g.Status != "resolved":
		return g, malformed(`status must be "firing" or "resolved"`)
	case g.Status == "firing" && strings.TrimSpace(g.Title) == "":
		return g, malformed("title is required when firing")
	case g.StartedAt != nil && g.StartedAt.IsZero():
		return g, malformed("started_at must be an RFC 3339 time")
	}
	return g, nil
}

func genericBody(g Generic) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Alert id: %s\n", g.ID)
	if g.URL != "" {
		fmt.Fprintf(&b, "Link: %s\n", g.URL)
	}
	if g.StartedAt != nil {
		fmt.Fprintf(&b, "Started: %s\n", g.StartedAt.UTC().Format(time.RFC3339))
	}
	if v := labelList(g.Labels); v != "" {
		fmt.Fprintf(&b, "Labels: %s\n", v)
	}
	if body := strings.TrimSpace(g.Body); body != "" {
		b.WriteString("\n")
		b.WriteString(body)
		b.WriteString("\n")
	}
	return trimBody(b.String())
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 200 {
		s = string(r[:199]) + "…"
	}
	return s
}
