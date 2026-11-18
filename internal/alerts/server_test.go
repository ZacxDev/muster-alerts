package alerts_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ZacxDev/muster-alerts/internal/alerts"
	"github.com/ZacxDev/muster-alerts/internal/deliver"
	"github.com/ZacxDev/muster-alerts/internal/muster"
	"github.com/ZacxDev/muster-alerts/internal/mustertest"
	"github.com/ZacxDev/muster-alerts/internal/outbox"
)

const secret = "test-shared-secret-0123456789"

type rig struct {
	t     *testing.T
	dir   string
	now   time.Time
	srv   *alerts.Server
	web   *httptest.Server
	box   *outbox.Outbox
	fake  *mustertest.Fake
	d     *deliver.Deliverer
	logs  bytes.Buffer
	limit int
}

func newRig(t *testing.T) *rig {
	r := &rig{t: t, dir: t.TempDir(), now: time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC), limit: 100}
	r.fake = mustertest.New()
	t.Cleanup(r.fake.Close)
	r.start()
	return r
}

// start opens the state dir and serves the webhook: a (re)start of the plugin.
func (r *rig) start() {
	t := r.t
	box, err := outbox.Open(r.dir, 0, func() time.Time { return r.now })
	if err != nil {
		t.Fatal(err)
	}
	eps, err := alerts.OpenEpisodes(r.dir, 30*24*time.Hour, r.now)
	if err != nil {
		t.Fatal(err)
	}
	r.box = box
	r.srv = &alerts.Server{Secret: secret, Namespace: "alert", Box: box, Episodes: eps, MaxPending: r.limit,
		Log: log.New(&r.logs, "", 0), Now: func() time.Time { return r.now }}
	r.web = httptest.NewServer(r.srv.Handler())
	c, _ := muster.New(r.fake.URL, mustertest.Token)
	r.d = &deliver.Deliverer{Client: c, Box: box, Log: log.New(&r.logs, "", 0),
		Sleep: func(ctx context.Context, d time.Duration) error { return ctx.Err() }}
	t.Cleanup(func() { r.web.Close(); box.Close() })
}

func (r *rig) restart() {
	r.web.Close()
	r.box.Close()
	r.start()
}

func (r *rig) post(path string, body any, hdr ...string) (int, map[string]any) {
	r.t.Helper()
	var raw []byte
	switch b := body.(type) {
	case string:
		raw = []byte(b)
	default:
		raw, _ = json.Marshal(b)
	}
	req, _ := http.NewRequest("POST", r.web.URL+path, bytes.NewReader(raw))
	if len(hdr) == 0 {
		hdr = []string{alerts.SecretHeader, secret}
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	b, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(b, &out)
	return resp.StatusCode, out
}

func (r *rig) drain() {
	r.t.Helper()
	if err := r.d.Drain(context.Background()); err != nil {
		r.t.Fatal(err)
	}
}

func alert(status, instance string, start time.Time) alerts.AMAlert {
	a := alerts.AMAlert{Status: status, StartsAt: start,
		Labels:       map[string]string{"alertname": "DiskFull", "instance": instance, "severity": "critical"},
		Annotations:  map[string]string{"summary": "disk almost full"},
		GeneratorURL: "https://prometheus.example.com/graph?g0.expr=disk", Fingerprint: "fp-" + instance}
	if status == "resolved" {
		a.EndsAt = start.Add(time.Hour)
	}
	return a
}

func payload(status string, as ...alerts.AMAlert) alerts.AMPayload {
	return alerts.AMPayload{Version: "4", GroupKey: `{}:{alertname="DiskFull"}`, Status: status, Receiver: "muster",
		GroupLabels: map[string]string{"alertname": "DiskFull"}, CommonLabels: map[string]string{"alertname": "DiskFull", "severity": "critical"},
		CommonAnnotations: map[string]string{"summary": "disk almost full"}, ExternalURL: "https://alertmanager.example.com", Alerts: as}
}

var t0 = time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)

// ---- the secret --------------------------------------------------------------

func TestABadOrMissingSecretIsRefusedAndRecordsNothing(t *testing.T) {
	r := newRig(t)
	good := payload("firing", alert("firing", "db1", t0))
	for name, hdr := range map[string][]string{
		"missing":          {"X-Other", "x"},
		"wrong":            {alerts.SecretHeader, "test-shared-secret-0123456780"},
		"prefix":           {alerts.SecretHeader, secret[:len(secret)-1]},
		"longer":           {alerts.SecretHeader, secret + "x"},
		"empty":            {alerts.SecretHeader, ""},
		"bearer wrong":     {"Authorization", "Bearer nope"},
		"basic not bearer": {"Authorization", "Basic " + secret},
	} {
		code, out := r.post("/alertmanager", good, hdr...)
		if code != 401 || out["error"] != "bad or missing secret" {
			t.Errorf("%s: %d %v, want 401", name, code, out)
		}
	}
	// A bad secret is refused before the body is read: a malformed body
	// with a bad secret is a 401, not a 400.
	if code, _ := r.post("/generic", "{not json", alerts.SecretHeader, "nope"); code != 401 {
		t.Errorf("malformed body + bad secret = %d, want 401", code)
	}
	if n := r.box.Len(); n != 0 {
		t.Fatalf("%d events recorded with a bad secret", n)
	}
	for name, hdr := range map[string][]string{
		"header": {alerts.SecretHeader, secret},
		"bearer": {"Authorization", "Bearer " + secret},
	} {
		if code, out := r.post("/alertmanager", good, hdr...); code != 200 {
			t.Errorf("%s: %d %v, want 200", name, code, out)
		}
	}
}

func TestSecretOKNeedsAConfiguredSecret(t *testing.T) {
	req := httptest.NewRequest("POST", "/", nil)
	if alerts.SecretOK(req, "") {
		t.Fatal("no secret presented, none configured: accepted")
	}
	req.Header.Set(alerts.SecretHeader, "")
	if alerts.SecretOK(req, "") {
		t.Fatal("an empty secret matched an empty configuration")
	}
}

// ---- malformed ---------------------------------------------------------------

func TestAMalformedPayloadIsA400AndRecordsNothing(t *testing.T) {
	r := newRig(t)
	noStart := payload("firing", alert("firing", "db1", t0))
	noStart.Alerts[0].StartsAt = time.Time{}
	v3 := payload("firing", alert("firing", "db1", t0))
	v3.Version = "3"
	for name, tc := range map[string]struct {
		path string
		body any
	}{
		"not json":           {"/alertmanager", "{nope"},
		"wrong version":      {"/alertmanager", v3},
		"no group key":       {"/alertmanager", alerts.AMPayload{Version: "4", Status: "firing", Alerts: []alerts.AMAlert{alert("firing", "db1", t0)}}},
		"no alerts":          {"/alertmanager", payload("firing")},
		"bad status":         {"/alertmanager", payload("burning", alert("firing", "db1", t0))},
		"no startsAt":        {"/alertmanager", noStart},
		"generic not json":   {"/generic", "[1,2"},
		"generic no id":      {"/generic", map[string]any{"status": "firing", "title": "x"}},
		"generic no title":   {"/generic", map[string]any{"id": "a", "status": "firing"}},
		"generic bad status": {"/generic", map[string]any{"id": "a", "status": "on", "title": "x"}},
		"generic unknown":    {"/generic", map[string]any{"id": "a", "status": "firing", "title": "x", "sevrity": "typo"}},
		"generic two docs":   {"/generic", `{"id":"a","status":"firing","title":"x"}{"id":"b"}`},
		"generic bad time":   {"/generic", `{"id":"a","status":"firing","title":"x","started_at":"yesterday"}`},
		"generic ctrl id":    {"/generic", map[string]any{"id": "a\nb", "status": "firing", "title": "x"}},
	} {
		if code, out := r.post(tc.path, tc.body); code != 400 || out["error"] == nil {
			t.Errorf("%s: %d %v, want 400", name, code, out)
		}
	}
	if n := r.box.Len(); n != 0 {
		t.Fatalf("%d events recorded from malformed payloads", n)
	}
}

func TestAnOversizeBodyIsA413(t *testing.T) {
	r := newRig(t)
	big := `{"id":"a","status":"firing","title":"x","body":"` + strings.Repeat("a", alerts.MaxBodyBytes) + `"}`
	if code, _ := r.post("/generic", big); code != 413 {
		t.Fatalf("oversize = %d, want 413", code)
	}
}

// ---- dedupe ------------------------------------------------------------------

// The dedupe, end to end: Alertmanager repeats a group's notification (its
// repeat_interval, a group_interval with a new alert, a retry after a lost
// answer). The first files the task; every repeat is a duplicate, and muster
// sees one request.
func TestARepeatNotificationNeverFilesTwice(t *testing.T) {
	r := newRig(t)
	first := payload("firing", alert("firing", "db1", t0))
	code, out := r.post("/alertmanager", first)
	if code != 200 || out["accepted"] != 1.0 {
		t.Fatalf("first = %d %v", code, out)
	}
	key := alerts.TaskKey("alert", alerts.GroupID("alertmanager", first.GroupKey), alerts.Episode{Start: t0.Unix()})
	if out["event_id"] != key+"#firing" {
		t.Fatalf("event id = %v, want %s#firing", out["event_id"], key)
	}
	r.drain()

	r.now = r.now.Add(4 * time.Hour) // repeat_interval
	if code, out := r.post("/alertmanager", first); code != 200 || out["duplicate"] != 1.0 || out["accepted"] != 0.0 {
		t.Fatalf("repeat = %d %v", code, out)
	}
	r.now = r.now.Add(5 * time.Minute) // a second alert joins the group
	joined := payload("firing", alert("firing", "db1", t0), alert("firing", "db2", r.now.Add(-time.Minute)))
	if code, out := r.post("/alertmanager", joined); code != 200 || out["duplicate"] != 1.0 {
		t.Fatalf("joined = %d %v", code, out)
	}
	r.drain()
	if n := r.fake.RequestCount(); n != 1 {
		t.Fatalf("muster got %d requests, want 1", n)
	}
	tasks := r.fake.Tasks()
	if len(tasks) != 1 || tasks[0].Key != key || tasks[0].Title != "[FIRING] DiskFull (critical): alertname=DiskFull" {
		t.Fatalf("tasks = %+v", tasks)
	}
	req := r.fake.Reqs()[0]
	for _, want := range []string{`"route_to_chief":true`, `"notice":"assigned"`, `"comment":"[` + key + `#firing] Alertmanager: 1 alert(s) firing since 2026-11-18T09:00:00Z"`} {
		if !strings.Contains(req, want) {
			t.Errorf("request lacks %s: %s", want, req)
		}
	}
}

// Restart between recording and delivering: the event is delivered after the
// restart, and a repeat after the restart is still a duplicate.
func TestARestartKeepsTheEventAndTheDedupe(t *testing.T) {
	r := newRig(t)
	p := payload("firing", alert("firing", "db1", t0))
	r.post("/alertmanager", p)
	r.restart() // before any delivery
	if code, out := r.post("/alertmanager", p); out["duplicate"] != 1.0 {
		t.Fatalf("repeat after restart = %d %v", code, out)
	}
	r.drain()
	if n := len(r.fake.Tasks()); n != 1 {
		t.Fatalf("tasks = %d, want 1", n)
	}
	r.restart()
	if _, out := r.post("/alertmanager", p); out["duplicate"] != 1.0 {
		t.Fatalf("repeat after a delivered restart = %v", out)
	}
	r.drain()
	if n := r.fake.RequestCount(); n != 1 {
		t.Fatalf("muster got %d requests, want 1", n)
	}
}

// ---- resolved ----------------------------------------------------------------

func TestResolvedAddsAnUpdateToTheSameTask(t *testing.T) {
	r := newRig(t)
	r.post("/alertmanager", payload("firing", alert("firing", "db1", t0), alert("firing", "db2", t0.Add(time.Minute))))
	r.now = r.now.Add(time.Hour)
	code, out := r.post("/alertmanager", payload("resolved", alert("resolved", "db1", t0), alert("resolved", "db2", t0.Add(time.Minute))))
	if code != 200 || out["accepted"] != 1.0 {
		t.Fatalf("resolved = %d %v", code, out)
	}
	r.drain()
	tasks := r.fake.Tasks()
	if len(tasks) != 1 || len(tasks[0].Comments) != 2 {
		t.Fatalf("tasks = %+v, want one with two comments", tasks)
	}
	key := tasks[0].Key
	if want := "[" + key + "#resolved] Alertmanager: resolved, all 2 alert(s) in the group ended (last at 2026-11-18T10:01:00Z)"; tasks[0].Comments[1] != want {
		t.Fatalf("resolved comment = %q\nwant %q", tasks[0].Comments[1], want)
	}
	if req := r.fake.Reqs()[1]; !strings.Contains(req, `"notice":"update"`) || strings.Contains(req, `"create"`) {
		t.Fatalf("the resolved request should be a routed update with no create: %s", req)
	}
	// A repeat of the resolved notification is a duplicate.
	if _, out := r.post("/alertmanager", payload("resolved", alert("resolved", "db1", t0), alert("resolved", "db2", t0.Add(time.Minute)))); out["duplicate"] != 1.0 {
		t.Fatalf("repeat resolved = %v", out)
	}
}

func TestTheSameGroupFiringAgainAfterResolvingIsANewTask(t *testing.T) {
	r := newRig(t)
	r.post("/alertmanager", payload("firing", alert("firing", "db1", t0)))
	r.post("/alertmanager", payload("resolved", alert("resolved", "db1", t0)))
	t1 := t0.Add(3 * time.Hour)
	r.now = t1.Add(time.Minute)
	if _, out := r.post("/alertmanager", payload("firing", alert("firing", "db1", t1))); out["accepted"] != 1.0 {
		t.Fatalf("re-fire = %v", out)
	}
	r.drain()
	tasks := r.fake.Tasks()
	if len(tasks) != 2 || tasks[0].Key == tasks[1].Key {
		t.Fatalf("tasks = %+v, want two with different keys", tasks)
	}
}

// The episode keeps its key while the group never goes quiet, even once its
// earliest alert has resolved; it starts a new key once the group went quiet
// without a "resolved" (send_resolved: false).
func TestTheEpisodeKeyIsStableAndRestartsAfterSilence(t *testing.T) {
	r := newRig(t)
	t1 := t0.Add(10 * time.Minute)
	r.post("/alertmanager", payload("firing", alert("firing", "db1", t0), alert("firing", "db2", t1)))
	r.now = r.now.Add(5 * time.Minute)
	if _, out := r.post("/alertmanager", payload("firing", alert("resolved", "db1", t0), alert("firing", "db2", t1))); out["duplicate"] != 1.0 {
		t.Fatalf("earliest resolved, group still firing = %v, want a duplicate of the same episode", out)
	}
	// Silence: the group stopped (no resolved sent), then fires again later.
	t9 := r.now.Add(6 * time.Hour)
	r.now = t9.Add(time.Minute)
	_, out := r.post("/alertmanager", payload("firing", alert("firing", "db3", t9)))
	if out["accepted"] != 1.0 || !strings.HasSuffix(out["event_id"].(string), fmt.Sprintf("-%d#firing", t9.Unix())) {
		t.Fatalf("after silence = %v, want a new episode keyed at %d", out, t9.Unix())
	}
}

// ---- generic -----------------------------------------------------------------

func TestTheGenericFormatFilesAndResolves(t *testing.T) {
	r := newRig(t)
	g := map[string]any{"id": "backup-nightly", "status": "firing", "title": "Nightly backup failed",
		"body": "exit 1", "url": "https://ci.example.com/run/7", "labels": map[string]string{"team": "ops"}}
	if code, out := r.post("/generic", g); code != 200 || out["accepted"] != 1.0 {
		t.Fatalf("firing = %d %v", code, out)
	}
	if _, out := r.post("/generic", g); out["duplicate"] != 1.0 {
		t.Fatalf("repeat = %v", out)
	}
	g["status"] = "resolved"
	if _, out := r.post("/generic", g); out["accepted"] != 1.0 {
		t.Fatalf("resolved = %v", out)
	}
	r.drain()
	tasks := r.fake.Tasks()
	if len(tasks) != 1 || tasks[0].Title != "[FIRING] Nightly backup failed" || len(tasks[0].Comments) != 2 {
		t.Fatalf("tasks = %+v", tasks)
	}
	for _, want := range []string{"exit 1", "Labels: team=ops", "Link: https://ci.example.com/run/7", "Alert id: backup-nightly"} {
		if !strings.Contains(tasks[0].Body, want) {
			t.Errorf("body lacks %q:\n%s", want, tasks[0].Body)
		}
	}
	// A resolved with nothing open and no started_at names no task.
	if code, out := r.post("/generic", map[string]any{"id": "never-fired", "status": "resolved"}); code != 200 || out["accepted"] != 0.0 {
		t.Fatalf("resolve of nothing = %d %v", code, out)
	}
}

// ---- storm -------------------------------------------------------------------

// An alert storm: past ALERTS_MAX_PENDING undelivered events a NEW event is
// answered 503 (the sender retries later) and recorded nowhere; a repeat of a
// recorded one is still a 200 duplicate.
func TestAStormPastMaxPendingIsRefusedWith503(t *testing.T) {
	r := newRig(t)
	r.srv.MaxPending = 2
	gen := func(id string) map[string]any { return map[string]any{"id": id, "status": "firing", "title": id} }
	r.post("/generic", gen("a"))
	r.post("/generic", gen("b"))
	req, _ := http.NewRequest("POST", r.web.URL+"/generic", strings.NewReader(`{"id":"c","status":"firing","title":"c"}`))
	req.Header.Set(alerts.SecretHeader, secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 503 || resp.Header.Get("Retry-After") != "60" {
		t.Fatalf("third = %d (Retry-After %q), want 503", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	if _, out := r.post("/generic", gen("a")); out["duplicate"] != 1.0 {
		t.Fatalf("a repeat while full = %v, want a duplicate", out)
	}
	r.drain()
	if code, _ := r.post("/generic", gen("c")); code != 200 {
		t.Fatalf("after draining = %d, want 200", code)
	}
}

// ---- the wire ----------------------------------------------------------------

// Every request is a COPY task: muster refuses event_id there (400 "event_id
// is only for reference"), and so does the fake. The event's identity is the
// key plus the comment, which starts with the event id.
func TestNoRequestCarriesEventID(t *testing.T) {
	r := newRig(t)
	r.post("/alertmanager", payload("firing", alert("firing", "db1", t0)))
	r.post("/alertmanager", payload("resolved", alert("resolved", "db1", t0)))
	r.post("/generic", map[string]any{"id": "x", "status": "firing", "title": "x"})
	r.drain()
	reqs := r.fake.Reqs()
	if len(reqs) != 3 {
		t.Fatalf("requests = %d, want 3", len(reqs))
	}
	for _, q := range reqs {
		if strings.Contains(q, "event_id") || strings.Contains(q, "reference") {
			t.Fatalf("a copy-task request carries a reference field: %s", q)
		}
	}
	if tasks := r.fake.Tasks(); len(tasks) != 2 || len(tasks[0].Comments) != 2 {
		t.Fatalf("tasks = %+v, want 2 (the first with its resolved update)", tasks)
	}
}

// A retry is byte for byte the first request, even across a restart and even
// when the sender's next notification for the episode reads differently: the
// outbox resends the bytes it recorded, never a re-rendering.
func TestARetryIsByteIdentical(t *testing.T) {
	r := newRig(t)
	r.post("/alertmanager", payload("firing", alert("firing", "db1", t0)))
	r.fake.Set(func(f *mustertest.Fake) { f.Unavailable = 1 })
	ctx, cancel := context.WithCancel(context.Background())
	r.d.Sleep = func(context.Context, time.Duration) error { cancel(); return context.Canceled }
	_ = r.d.Drain(ctx)
	r.restart()
	r.now = r.now.Add(time.Minute)
	r.post("/alertmanager", payload("firing", alert("firing", "db1", t0), alert("firing", "db2", r.now)))
	r.drain()
	reqs := r.fake.Reqs()
	if len(reqs) != 2 || reqs[0] != reqs[1] {
		t.Fatalf("requests =\n%s\nwant two identical", strings.Join(reqs, "\n"))
	}
}
