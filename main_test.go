package main

import (
	"bytes"
	"context"
	"errors"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/ZacxDev/muster-alerts/internal/deliver"
	"github.com/ZacxDev/muster-alerts/internal/muster"
	"github.com/ZacxDev/muster-alerts/internal/mustertest"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func with(kv ...string) map[string]string {
	m := map[string]string{"MUSTER_URL": "http://127.0.0.1:8105", "MUSTER_PLUGIN_TOKEN": "mpl_x", "ALERTS_SECRET": "aaaaaaaaaaaaaaaa"}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" {
			delete(m, kv[i])
		} else {
			m[kv[i]] = kv[i+1]
		}
	}
	return m
}

func TestLoadConfigDefaults(t *testing.T) {
	c, err := LoadConfig(env(with()))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:9095" || c.Namespace != "alert" || c.PerHour != 60 || c.Burst != 10 || c.MaxPending != 500 || c.StateDir != "./state" || c.NonLoopback {
		t.Fatalf("defaults = %+v", c)
	}
	c, err = LoadConfig(env(with("ALERTS_LISTEN", "0.0.0.0:9095", "ALERTS_ALLOW_NON_LOOPBACK", "1", "ALERTS_MAX_PER_HOUR", "5", "ALERTS_BURST", "2", "ALERTS_MAX_PENDING", "9", "ALERTS_TASK_NAMESPACE", "pager")))
	if err != nil || !c.NonLoopback || c.PerHour != 5 || c.Burst != 2 || c.MaxPending != 9 || c.Namespace != "pager" {
		t.Fatalf("set = %+v, %v", c, err)
	}
}

func TestLoadConfigRefuses(t *testing.T) {
	for _, bad := range []map[string]string{
		with("MUSTER_URL", "http://muster.example.com"),
		with("MUSTER_PLUGIN_TOKEN", ""),
		with("ALERTS_SECRET", ""),
		with("ALERTS_SECRET", "short"),
		with("ALERTS_LISTEN", "9095"),
		with("ALERTS_LISTEN", "0.0.0.0:9095"), // non-loopback without the opt-in
		with("ALERTS_LISTEN", "[::]:9095"),
		with("ALERTS_MAX_PER_HOUR", "0"),
		with("ALERTS_BURST", "many"),
		with("ALERTS_TASK_NAMESPACE", "Alert"),
	} {
		if _, err := LoadConfig(env(bad)); err == nil {
			t.Errorf("LoadConfig(%v) accepted it", bad)
		}
	}
}

func TestTheStartupLineNamesNoSecret(t *testing.T) {
	c, err := LoadConfig(env(with("MUSTER_PLUGIN_TOKEN", "mpl_s3cretT0ken", "ALERTS_SECRET", "s3cret-s3cret-s3cret")))
	if err != nil {
		t.Fatal(err)
	}
	got := startupLine(c, "127.0.0.1:9095", 0)
	want := `muster-alerts: talking to http://127.0.0.1:8105; webhooks on http://127.0.0.1:9095 (/alertmanager, /generic); namespace "alert"; at most 60 tasks/hour (burst 10); 0 events pending`
	if got != want {
		t.Fatalf("startup line = %q\nwant %q", got, want)
	}
	if strings.Contains(got, "s3cret") {
		t.Fatalf("a secret is in the startup line: %q", got)
	}
}

// The namespace check at startup, against the fake muster, which answers GET
// /plugin/v1/tasks as muster's handlePluginTaskList does: 400 for a namespace
// not in MUSTER_PLUGIN_TASK_NAMESPACES.
func TestPreflightRefusesANamespaceMusterDoesNotList(t *testing.T) {
	fake := mustertest.New()
	defer fake.Close()
	c, _ := muster.New(fake.URL, mustertest.Token)
	var logs bytes.Buffer
	cfg, err := LoadConfig(env(with()))
	if err != nil {
		t.Fatal(err)
	}
	if err := preflight(context.Background(), c, cfg, log.New(&logs, "", 0)); err != nil {
		t.Fatalf("preflight with a listed namespace = %v", err)
	}
	cfg.Namespace = "pager"
	err = preflight(context.Background(), c, cfg, log.New(&logs, "", 0))
	want := `muster does not accept the task namespace "pager" (set by ALERTS_TASK_NAMESPACE): add it to MUSTER_PLUGIN_TASK_NAMESPACES on the muster server`
	if err == nil || !errors.Is(err, deliver.ErrStop) || !strings.Contains(err.Error(), want) {
		t.Fatalf("preflight with an unlisted namespace = %v\nwant it to contain %q", err, want)
	}
	if n := fake.RequestCount(); n != 0 {
		t.Fatalf("preflight posted %d tasks", n)
	}
}

// The image does not opt out of the loopback rule: no ENV line in the
// Dockerfile sets ALERTS_ALLOW_NON_LOOPBACK, and with the image's own
// environment alone the plugin refuses to start until it is given at run time.
func TestTheImageNeedsTheNonLoopbackOptInAtRunTime(t *testing.T) {
	raw, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	image := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "ENV" {
			continue
		}
		for _, kv := range f[1:] {
			k, v, _ := strings.Cut(kv, "=")
			image[k] = v
		}
	}
	if v, ok := image["ALERTS_ALLOW_NON_LOOPBACK"]; ok {
		t.Fatalf("the Dockerfile sets ALERTS_ALLOW_NON_LOOPBACK=%s; it must be given at run time", v)
	}
	if image["ALERTS_LISTEN"] != "0.0.0.0:9095" {
		t.Fatalf("the image's ALERTS_LISTEN = %q, want 0.0.0.0:9095", image["ALERTS_LISTEN"])
	}
	_, err = LoadConfig(env(with("ALERTS_LISTEN", image["ALERTS_LISTEN"])))
	if err == nil || !strings.Contains(err.Error(), "ALERTS_ALLOW_NON_LOOPBACK=1") {
		t.Fatalf("the image's environment without the opt-in = %v, want a refusal naming ALERTS_ALLOW_NON_LOOPBACK=1", err)
	}
	if _, err := LoadConfig(env(with("ALERTS_LISTEN", image["ALERTS_LISTEN"], "ALERTS_ALLOW_NON_LOOPBACK", "1"))); err != nil {
		t.Fatalf("the image's environment with -e ALERTS_ALLOW_NON_LOOPBACK=1 = %v", err)
	}
}
