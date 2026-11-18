// Command muster-alerts turns alerts into muster tasks. It receives Prometheus
// Alertmanager webhooks (and a simple generic JSON webhook), files one muster
// task per firing alert group through POST /plugin/v1/tasks, routed to your
// chief, and adds an update to that task when the group resolves.
//
// Configuration is read from the environment only (see .env.example and the
// README's table).
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"syscall"
	"time"

	"github.com/ZacxDev/muster-alerts/internal/alerts"
	"github.com/ZacxDev/muster-alerts/internal/deliver"
	"github.com/ZacxDev/muster-alerts/internal/muster"
	"github.com/ZacxDev/muster-alerts/internal/outbox"
)

const name = "muster-alerts"

func main() {
	logger := log.New(os.Stderr, "", log.LstdFlags)
	if err := run(logger); err != nil {
		logger.Printf("%s: %v", name, err)
		os.Exit(1)
	}
}

// Config is everything the plugin reads from its environment.
type Config struct {
	URL, Token  string
	Listen      string
	Secret      string
	Namespace   string
	PerHour     int
	Burst       int
	MaxPending  int
	StateDir    string
	NonLoopback bool
}

var namespaceRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// MinSecretLen is the shortest ALERTS_SECRET accepted.
const MinSecretLen = 16

func intEnv(getenv func(string) string, key string, def, lo, hi int) (int, error) {
	v := getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		return 0, fmt.Errorf("%s %q must be a whole number from %d to %d", key, v, lo, hi)
	}
	return n, nil
}

// LoadConfig reads and checks the environment through getenv.
func LoadConfig(getenv func(string) string) (Config, error) {
	base, err := muster.CheckBaseURL(getenv("MUSTER_URL"))
	if err != nil {
		return Config{}, err
	}
	c := Config{URL: base, Token: getenv("MUSTER_PLUGIN_TOKEN"), Listen: "127.0.0.1:9095",
		Secret: getenv("ALERTS_SECRET"), Namespace: "alert", StateDir: "./state"}
	if c.Token == "" {
		return Config{}, errors.New("MUSTER_PLUGIN_TOKEN is not set (mint one on muster's /plugins page)")
	}
	if len(c.Secret) < MinSecretLen {
		return Config{}, fmt.Errorf("ALERTS_SECRET must be set, at least %d characters (e.g. openssl rand -hex 32)", MinSecretLen)
	}
	if v := getenv("ALERTS_LISTEN"); v != "" {
		c.Listen = v
	}
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return Config{}, fmt.Errorf("ALERTS_LISTEN %q is not host:port", c.Listen)
	}
	c.NonLoopback = !muster.IsLoopbackHost(host)
	if c.NonLoopback && getenv("ALERTS_ALLOW_NON_LOOPBACK") != "1" {
		return Config{}, fmt.Errorf("ALERTS_LISTEN %q is not a loopback address: the webhook is plain HTTP, so set ALERTS_ALLOW_NON_LOOPBACK=1 only behind TLS or on a private network", c.Listen)
	}
	if v := getenv("ALERTS_TASK_NAMESPACE"); v != "" {
		c.Namespace = v
	}
	if !namespaceRE.MatchString(c.Namespace) {
		return Config{}, fmt.Errorf("ALERTS_TASK_NAMESPACE %q must be lower-case letters, digits, - or _ (it must also be in muster's MUSTER_PLUGIN_TASK_NAMESPACES)", c.Namespace)
	}
	if c.PerHour, err = intEnv(getenv, "ALERTS_MAX_PER_HOUR", 60, 1, 3600); err != nil {
		return Config{}, err
	}
	if c.Burst, err = intEnv(getenv, "ALERTS_BURST", 10, 1, 1000); err != nil {
		return Config{}, err
	}
	if c.MaxPending, err = intEnv(getenv, "ALERTS_MAX_PENDING", 500, 1, 100000); err != nil {
		return Config{}, err
	}
	if v := getenv("STATE_DIR"); v != "" {
		c.StateDir = v
	}
	return c, nil
}

func run(logger *log.Logger) error {
	cfg, err := LoadConfig(os.Getenv)
	if err != nil {
		return err
	}
	client, err := muster.New(cfg.URL, cfg.Token)
	if err != nil {
		return err
	}
	box, err := outbox.Open(cfg.StateDir, outbox.DefaultRetention, nil)
	if err != nil {
		return err
	}
	defer box.Close()
	eps, err := alerts.OpenEpisodes(cfg.StateDir, outbox.DefaultRetention, time.Now())
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := preflight(ctx, client, cfg, logger); err != nil {
		return err
	}
	srv := &alerts.Server{Secret: cfg.Secret, Namespace: cfg.Namespace, Box: box, Episodes: eps, MaxPending: cfg.MaxPending, Log: logger}
	hs := &http.Server{Addr: cfg.Listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	logger.Print(startupLine(cfg, ln.Addr().String(), box.Len()))
	if cfg.NonLoopback {
		logger.Printf("%s: WARNING: listening on a non-loopback address over plain HTTP (ALERTS_ALLOW_NON_LOOPBACK=1)", name)
	}
	d := &deliver.Deliverer{Client: client, Box: box, Log: logger, Limiter: deliver.NewLimiter(cfg.PerHour, cfg.Burst, nil)}
	errc := make(chan error, 2)
	go func() { errc <- d.Run(ctx) }()
	go func() {
		if err := hs.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()
	var result error
	select {
	case <-ctx.Done():
	case result = <-errc:
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = hs.Shutdown(sctx)
	stop()
	if result != nil && !errors.Is(result, context.Canceled) {
		return result
	}
	return nil
}

// preflight is what must hold before the webhook opens: the token works (GET
// /plugin/v1/self) and muster files tasks under the namespace.
func preflight(ctx context.Context, client *muster.Client, cfg Config, logger *log.Logger) error {
	if err := deliver.Hello(ctx, client, logger); err != nil {
		return err
	}
	return deliver.CheckNamespace(ctx, client, cfg.Namespace, "ALERTS_TASK_NAMESPACE")
}

// startupLine names muster by scheme and host only (muster.Redact), and never
// the secret.
func startupLine(cfg Config, addr string, pending int) string {
	return fmt.Sprintf("%s: talking to %s; webhooks on http://%s (/alertmanager, /generic); namespace %q; at most %d tasks/hour (burst %d); %d events pending",
		name, muster.Redact(cfg.URL), addr, cfg.Namespace, cfg.PerHour, cfg.Burst, pending)
}
