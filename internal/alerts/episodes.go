package alerts

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ZacxDev/muster-alerts/internal/atomicfile"
)

// EpisodesFile holds the open firing episodes, one per alert group.
const EpisodesFile = "episodes.json"

// episode is one alert group's latest firing episode: when it started (the
// starts-at in its task key), its re-fire count, when the plugin last heard
// it, and whether it was closed by a "resolved".
//
// A closed episode is kept (until retention) for its start and count: a group
// that fires again after resolving, with the SAME starts-at (a generic sender
// that resends its started_at, or an Alertmanager alert that flaps back with
// its original startsAt), is a new episode with the next re-fire count, so its
// task key is new and the outbox does not take it for a repeat of the first.
type episode struct {
	Start    int64     `json:"start"` // unix seconds
	Refire   int       `json:"refire,omitempty"`
	LastSeen time.Time `json:"last_seen"`
	Closed   bool      `json:"closed,omitempty"`
}

// Episode names one firing episode: its start and re-fire count, the two
// parts of its task key besides the group.
type Episode struct {
	Start  int64
	Refire int
}

// Episodes is the durable map from an alert group to its open episode. It is
// what keeps one firing episode on one task key while the group's alerts come
// and go, and what starts a new key once the group has gone quiet.
type Episodes struct {
	mu        sync.Mutex
	dir       string
	retention time.Duration
	m         map[string]episode
}

// OpenEpisodes reads dir/episodes.json, dropping any episode not heard from
// within retention (a group that stopped without a "resolved").
func OpenEpisodes(dir string, retention time.Duration, now time.Time) (*Episodes, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	e := &Episodes{dir: dir, retention: retention, m: map[string]episode{}}
	b, err := os.ReadFile(filepath.Join(dir, EpisodesFile))
	switch {
	case errors.Is(err, os.ErrNotExist):
		return e, nil
	case err != nil:
		return nil, err
	}
	if err := json.Unmarshal(b, &e.m); err != nil {
		return nil, fmt.Errorf("%s is unreadable; fix or move it before starting", filepath.Join(dir, EpisodesFile))
	}
	e.prune(now)
	return e, nil
}

// prune drops every episode not heard from within retention.
func (e *Episodes) prune(now time.Time) {
	for g, ep := range e.m {
		if now.Sub(ep.LastSeen) > e.retention {
			delete(e.m, g)
		}
	}
}

// Firing returns the episode start for a firing notification of group, whose
// currently firing alerts started at earliest (zero: not known). The rule:
//
//   - an open episode CONTINUES when some alert firing now started no later
//     than the plugin last heard the group firing (the group never went
//     quiet), or when the start is not known;
//   - otherwise, or when the episode was closed by a "resolved", a NEW
//     episode starts, at earliest (or at now when not known). When that is
//     the same start as the group's previous episode, its re-fire count is
//     one more, so the two never share a key.
//
// So an alert joining or leaving a group mid-episode keeps the key, and a
// group that resolved (with or without telling us) starts a fresh key when it
// fires again. It records the notification (last seen = now) durably.
func (e *Episodes) Firing(group string, earliest, now time.Time) (Episode, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.prune(now)
	ep, ok := e.m[group]
	if !ok || ep.Closed || (!earliest.IsZero() && earliest.After(ep.LastSeen)) {
		start := earliest
		if start.IsZero() {
			start = now
		}
		next := episode{Start: start.Unix()}
		if ok && ep.Start == next.Start {
			next.Refire = ep.Refire + 1
		}
		ep = next
	}
	ep.LastSeen = now.UTC()
	e.m[group] = ep
	return Episode{ep.Start, ep.Refire}, e.save()
}

// Resolved returns group's latest episode, open or already closed (a repeat
// of the "resolved" then names the same event), and whether there is one. It
// does not close it: call Close once the event is recorded.
func (e *Episodes) Resolved(group string) (Episode, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	ep, ok := e.m[group]
	return Episode{ep.Start, ep.Refire}, ok
}

// Close ends group's episode, durably. Its start and re-fire count are kept
// (until retention) so a re-fire with the same start gets the next count.
func (e *Episodes) Close(group string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	ep, ok := e.m[group]
	if !ok || ep.Closed {
		return nil
	}
	ep.Closed = true
	e.m[group] = ep
	return e.save()
}

func (e *Episodes) save() error {
	b, err := json.Marshal(e.m)
	if err != nil {
		return err
	}
	return atomicfile.Write(e.dir, EpisodesFile, b)
}
