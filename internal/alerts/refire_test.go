package alerts_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ZacxDev/muster-alerts/internal/alerts"
)

// The auditor's reproduction: a group fires, resolves, and fires again with
// the SAME starts-at (a generic sender resending started_at). The re-fire is a
// new episode: it must file a task, not vanish as a duplicate of the first.
func TestAReFireAfterResolveWithTheSameStartIsFiled(t *testing.T) {
	r := newRig(t)
	g := map[string]any{"id": "backup-nightly", "status": "firing", "title": "Nightly backup failed", "started_at": t0.Format(time.RFC3339)}
	if _, out := r.post("/generic", g); out["accepted"] != 1.0 {
		t.Fatalf("first firing = %v", out)
	}
	g["status"] = "resolved"
	if _, out := r.post("/generic", g); out["accepted"] != 1.0 {
		t.Fatalf("resolved = %v", out)
	}
	r.now = r.now.Add(time.Hour)
	g["status"] = "firing"
	_, out := r.post("/generic", g)
	if out["accepted"] != 1.0 {
		t.Fatalf("re-fire after resolve with the same started_at = %v, want accepted (a new episode)", out)
	}
	group := alerts.GroupID("generic", "backup-nightly")
	if want := alerts.TaskKey("alert", group, alerts.Episode{Start: t0.Unix(), Refire: 1}) + "#firing"; out["event_id"] != want {
		t.Fatalf("re-fire event id = %v, want %s", out["event_id"], want)
	}
	// Its repeat is a duplicate, and its resolve lands on the re-fire's task.
	if _, out := r.post("/generic", g); out["duplicate"] != 1.0 {
		t.Fatalf("repeat of the re-fire = %v", out)
	}
	g["status"] = "resolved"
	if _, out := r.post("/generic", g); out["accepted"] != 1.0 || !strings.HasSuffix(out["event_id"].(string), "-r1#resolved") {
		t.Fatalf("resolve of the re-fire = %v", out)
	}
	r.drain()
	tasks := r.fake.Tasks()
	if len(tasks) != 2 || tasks[0].Key == tasks[1].Key || len(tasks[1].Comments) != 2 {
		t.Fatalf("tasks = %+v, want two (the re-fire with its own resolve)", tasks)
	}
}

// The same through Alertmanager: an alert that flaps back with its original
// startsAt after the group resolved.
func TestAnAlertmanagerReFireWithTheSameStartsAtIsFiled(t *testing.T) {
	r := newRig(t)
	r.post("/alertmanager", payload("firing", alert("firing", "db1", t0)))
	r.post("/alertmanager", payload("resolved", alert("resolved", "db1", t0)))
	r.now = r.now.Add(10 * time.Minute)
	if _, out := r.post("/alertmanager", payload("firing", alert("firing", "db1", t0))); out["accepted"] != 1.0 {
		t.Fatalf("Alertmanager re-fire with the same startsAt = %v, want accepted", out)
	}
	r.drain()
	if tasks := r.fake.Tasks(); len(tasks) != 2 {
		t.Fatalf("tasks = %d, want 2", len(tasks))
	}
}

// The secret is checked BEFORE the body is read: an oversize body with a bad
// secret is a 401, never a 413 (which would mean the body was read first).
func TestAnOversizeBodyWithABadSecretIsA401(t *testing.T) {
	r := newRig(t)
	big := `{"id":"a","status":"firing","title":"x","body":"` + strings.Repeat("a", alerts.MaxBodyBytes) + `"}`
	for _, path := range []string{"/generic", "/alertmanager"} {
		if code, _ := r.post(path, big, alerts.SecretHeader, "not-the-secret"); code != 401 {
			t.Errorf("%s: oversize body + bad secret = %d, want 401 (secret checked before the body is read)", path, code)
		}
	}
}

// /healthz is open, so it says only "up"; the pending count needs the secret.
func TestHealthzShowsPendingOnlyWithTheSecret(t *testing.T) {
	r := newRig(t)
	r.post("/generic", map[string]any{"id": "a", "status": "firing", "title": "a"})
	get := func(hdr ...string) map[string]any {
		req, _ := http.NewRequest("GET", r.web.URL+"/healthz", nil)
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		var out map[string]any
		if resp.StatusCode != 200 || json.Unmarshal(b, &out) != nil {
			t.Fatalf("healthz = %d %s", resp.StatusCode, b)
		}
		return out
	}
	for name, hdr := range map[string][]string{"none": nil, "wrong": {alerts.SecretHeader, "nope"}} {
		if out := get(hdr...); out["ok"] != true || out["pending"] != nil {
			t.Errorf("healthz with %s secret = %v, want ok and no pending count", name, out)
		}
	}
	if out := get(alerts.SecretHeader, secret); out["ok"] != true || out["pending"] != 1.0 {
		t.Errorf("healthz with the secret = %v, want pending 1", out)
	}
	if out := get("Authorization", "Bearer "+secret); out["pending"] != 1.0 {
		t.Errorf("healthz with the bearer secret = %v, want pending 1", out)
	}
}

// muster cuts a task body over 16 KiB from the end: what names the alert
// (receiver, group key; a generic alert's id and link) comes first, and the
// plugin trims the rest itself.
func TestALongBodyPutsTheReceiverAndGroupKeyFirst(t *testing.T) {
	r := newRig(t)
	p := payload("firing", alert("firing", "db1", t0))
	p.CommonAnnotations["description"] = strings.Repeat("very long description ", 2000) + "END-OF-DESCRIPTION"
	r.post("/alertmanager", p)
	r.post("/generic", map[string]any{"id": "big-one", "status": "firing", "title": "big", "url": "https://ci.example.com/run/9",
		"body": strings.Repeat("output line\n", 3000) + "END-OF-BODY"})
	r.drain()
	tasks := r.fake.Tasks()
	if len(tasks) != 2 {
		t.Fatalf("tasks = %d", len(tasks))
	}
	am, gen := tasks[0].Body, tasks[1].Body
	wantAM := "Receiver: muster\nGroup key: {}:{alertname=\"DiskFull\"}\nAlertmanager: https://alertmanager.example.com\n\nAlertmanager reports 1 firing alert(s)"
	if !strings.HasPrefix(am, wantAM) {
		t.Errorf("Alertmanager body does not start with the receiver and group key:\n%.300s", am)
	}
	if !strings.HasPrefix(gen, "Alert id: big-one\nLink: https://ci.example.com/run/9\n") {
		t.Errorf("generic body does not start with the id and link:\n%.300s", gen)
	}
	for name, b := range map[string]string{"alertmanager": am, "generic": gen} {
		if !strings.HasSuffix(b, "\n[trimmed: the full alert is at its source]") || strings.Contains(b, "END-OF-") {
			t.Errorf("%s body was not trimmed with the marker: …%s", name, b[max(0, len(b)-120):])
		}
		if len(b) > 15<<10 || len(b) < 15<<10-16 {
			t.Errorf("%s body is %d bytes, want about 15 KiB", name, len(b))
		}
	}
}
