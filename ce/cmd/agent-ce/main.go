//go:build linux

// Package main is the leitwacht Community Edition agent. CE is a YAML-
// driven, backend-free build of the leitwacht data plane: it loads
// rules from a local file, enforces egress with the same eBPF +
// nftables + DNS proxy stack that EE uses, and ships violations to
// stdout (NDJSON), Prometheus, and an optional webhook.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/advisory"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/enforcer"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/handler"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/policy"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/procenv"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/version"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/watcher"
	"gitlab.com/leitwacht/leitwacht-agent/ce/config"
	"gitlab.com/leitwacht/leitwacht-agent/ce/ruleyaml"
	"gitlab.com/leitwacht/leitwacht-agent/ce/sinks"
)

func main() {
	bootLog := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	bootLog.Info("leitwacht-ce starting", "version", version.Version, "commit", version.Commit)

	cfg, err := config.Load()
	if err != nil {
		bootLog.Error("load config", "error", err)
		os.Exit(1)
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parseLevel(cfg.LogLevel)}))
	log.Info("config loaded",
		"rules_path", cfg.RulesPath,
		"runtime", cfg.ContainerRuntime,
		"default_action", cfg.DefaultAction,
		"prom", cfg.PromEnabled,
		"webhook", cfg.WebhookURL != "",
	)

	// Daemon-lifetime context. Created early so sinks can attach to it
	// and short-circuit in-flight work on shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Rule loader — also satisfies policy.WatcherReadiness.
	loader, err := ruleyaml.New(cfg.RulesPath, log)
	if err != nil {
		log.Error("load rules", "path", cfg.RulesPath, "error", err)
		os.Exit(1)
	}

	// CE policy: direct lookup against the YAML loader. No backend, no
	// stale-cache layer — the loader is fully synchronous and the
	// handler fails open with the default action when the loader isn't
	// ready (or has no entry for the project).
	policyProvider := policy.NewResolver(loader, loader)

	// Sinks: stdout always on, prom optional, webhook optional.
	hostname := hostnameOrFallback()

	multi := &sinks.Multi{}
	var stdout *sinks.Stdout
	if cfg.StdoutEnabled {
		stdout = sinks.NewStdout(os.Stderr, hostname, log)
		defer func() { _ = stdout.Close() }()
		multi.Violations = append(multi.Violations, stdout)
		multi.Advisories = append(multi.Advisories, stdout)
	}

	var promReg *prometheus.Registry
	if cfg.PromEnabled {
		promReg = prometheus.NewRegistry()
		p := sinks.NewProm(promReg)
		multi.Violations = append(multi.Violations, p)
		multi.Advisories = append(multi.Advisories, p)
	}

	var webhook *sinks.Webhook
	if cfg.WebhookURL != "" {
		webhook = sinks.NewWebhook(ctx, cfg.WebhookURL, cfg.WebhookTimeout, hostname, cfg.WebhookAuth, log)
		multi.Violations = append(multi.Violations, webhook)
		multi.Advisories = append(multi.Advisories, webhook)
	}

	if len(multi.Violations) == 0 {
		log.Error("no violation sinks configured — would silently drop reports")
		os.Exit(1)
	}

	// Enforcer.
	mgr, honeypotCfg, err := newEnforcer(cfg, log)
	if err != nil {
		log.Error("start enforcer", "error", err)
		os.Exit(1)
	}
	log.Info("enforcer ready", "honeypot_lsm", mgr.LSMLoaded(), "max_concurrent", cfg.MaxConcurrentEnf)

	// BuildKit step attribution. No-op when LEITWACHT_CE_BUILDKIT_GRPC_ADDR
	// is empty (the default): the enforcer's egress path still calls
	// LookupBuildKitBinding on every event, but the default hook
	// returns (zero, false) so violations are emitted without build
	// step fields — i.e., unchanged from pre-BuildKit behaviour.
	//
	// The call needs mgr.ReportFunc set, so it runs after the manager
	// is wired up (line below). Returned attach is closed on shutdown.
	if mgr.BucketInterval > 0 {
		mgr.ReportFunc = multi.ReportAsync
	}

	buildKitAttach, err := startBuildKitAttribution(ctx, cfg, log, mgr)
	if err != nil {
		log.Error("start buildkit attribution", "error", err)
		os.Exit(1)
	}

	if buildKitAttach != nil {
		defer func() {
			if err := buildKitAttach.Close(); err != nil {
				log.Warn("buildkit egress attach close", "error", err)
			}
		}()
	}

	// Watcher.
	w, err := newWatcher(cfg, log)
	if err != nil {
		log.Error("init watcher", "runtime", cfg.ContainerRuntime, "error", err)
		os.Exit(1)
	}
	defer w.Close()
	log.Info("watcher initialized", "runtime", cfg.ContainerRuntime)

	unknownMode := handler.UnknownEnforce
	if strings.EqualFold(cfg.UnknownProjectMode, "pass") {
		unknownMode = handler.UnknownPass
	}

	h := &handler.Handler{
		Watcher:            w,
		Policy:             policyProvider,
		Enforcer:           mgr,
		ViolationSink:      multi,
		AdvisorySink:       multi,
		Logger:             log,
		DefaultAction:      cfg.DefaultAction,
		UnknownProjectMode: unknownMode,
	}

	wireHoneypotKill(mgr, w, multi, log)
	emitHoneypotAdvisory(honeypotCfg, mgr, multi)

	// Channel-depth gauge: surfaces back-pressure against containerd's
	// event subscription. A persistently non-zero value means CI bursts
	// are outpacing the handler — bump LEITWACHT_CE_EVENT_BUFFER and/or
	// LEITWACHT_CE_MAX_CONCURRENT, or check for stuck handlers.
	if promReg != nil {
		promReg.MustRegister(prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{
				Name: "leitwacht_ce_event_channel_depth",
				Help: "Current depth of the container-event channel (configured size: LEITWACHT_CE_EVENT_BUFFER).",
			},
			func() float64 { return float64(w.ChannelDepth()) },
		))

		// Webhook drop counter: incremented every time a report fails to
		// encode or the webhook ring buffer overflows. Flat at zero means
		// the SIEM forwarder is healthy. Sampled via CounterFunc so the
		// counter survives sink lifecycle independently of scrape timing.
		if webhook != nil {
			promReg.MustRegister(prometheus.NewCounterFunc(
				prometheus.CounterOpts{
					Name: "leitwacht_ce_webhook_dropped_total",
					Help: "Webhook reports dropped (encode failure, queue overflow, or in-flight cancellation).",
				},
				func() float64 { return float64(webhook.Dropped()) },
			))
		}

		// Stdout drop counter: incremented when the async drainer queue
		// fills (a slow writer — typically a network mount or slow log
		// shipper). A persistently rising value means the writer can't
		// keep up; reduce volume or replace the writer with a fast sink.
		if stdout != nil {
			promReg.MustRegister(prometheus.NewCounterFunc(
				prometheus.CounterOpts{
					Name: "leitwacht_ce_stdout_dropped_total",
					Help: "NDJSON records dropped because the async stdout queue overflowed.",
				},
				func() float64 { return float64(stdout.Dropped()) },
			))
		}
	}

	// File watcher for hot-reload.
	go func() {
		if err := loader.Run(ctx.Done()); err != nil {
			log.Error("rule watcher exited", "error", err)
		}
	}()

	// HTTP server (/healthz always; /metrics only when Prom is enabled).
	// Always starting the server means K8s liveness/readiness probes
	// stay functional even when an operator disables Prometheus —
	// otherwise a hung agent goes unrestarted by kubelet, which is the
	// exact failure mode probes exist to catch.
	//
	// Bind synchronously so a misconfigured PROM_ADDR crashes the
	// daemon immediately instead of running silently with no observability.
	if err := startMetricsServer(ctx, promReg, cfg.PromAddr, cfg.PromEnabled, log); err != nil {
		log.Error("metrics server bind failed", "addr", cfg.PromAddr, "error", err)
		os.Exit(1)
	}

	recoverRunning(ctx, w, h, log)
	runEventLoop(ctx, log, h, mgr, w.Watch(ctx), multi)
}

func parseLevel(v string) slog.Level {
	switch strings.ToLower(v) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func hostnameOrFallback() string {
	if h := os.Getenv("HOSTNAME_OVERRIDE"); h != "" {
		return h
	}
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

func newEnforcer(cfg *config.Config, log *slog.Logger) (*enforcer.Manager, enforcer.HoneypotConfig, error) {
	upstreams := splitTrim(cfg.DNSUpstream, ",")
	trusted := parseTrustedCIDRs(cfg.TrustedCIDRs, log)

	platform := &enforcer.LinuxPlatform{Logger: log}
	honeypotCfg := enforcer.HoneypotConfig{Enabled: cfg.HoneypotEnabled, Dir: cfg.HoneypotDir}

	mgr := enforcer.NewManager(log, cfg.MaxConcurrentEnf, upstreams, trusted, platform, honeypotCfg)
	mgr.NetnsGrace = cfg.NetnsGrace
	mgr.IsDocker = cfg.ContainerRuntime == "docker"
	mgr.AgentVersion = version.Version
	mgr.BucketInterval = cfg.BucketInterval

	// When opted in via LEITWACHT_CE_RECORD_ENV_NAMES, attach env-var
	// NAMES (never values) of the offending PID to each violation
	// report. Best-effort: skipped silently if /proc is unreadable or
	// the process exited. Note that GitLab Runner sets CI_JOB_TOKEN in
	// every job's env, so it'll appear on every violation — accurate
	// but noisy. See docs/EVENT_FLOW.md for guidance.
	if cfg.RecordEnvNames {
		mgr.EnvNamesFn = procenv.Names
		log.Info("env-name capture enabled (LEITWACHT_CE_RECORD_ENV_NAMES=true)")
	}

	if err := mgr.StartHoneypot(); err != nil {
		return nil, honeypotCfg, fmt.Errorf("start honeypot lsm: %w", err)
	}
	return mgr, honeypotCfg, nil
}

func newWatcher(cfg *config.Config, log *slog.Logger) (watcher.ContainerWatcher, error) {
	scope := watcher.Scope{Label: cfg.ScopeLabel, Env: cfg.ScopeEnv}

	if cfg.ContainerRuntime == "containerd" {
		addr := cfg.ContainerSocket
		if addr == "" {
			addr = "/run/containerd/containerd.sock"
		}
		w, err := watcher.NewContainerd(addr, cfg.ContainerdNS, cfg.RunnerPodNamespace, cfg.EventBuffer, log)
		if err != nil {
			return nil, err
		}
		w.SetScope(scope)
		return w, nil
	}

	w, err := watcher.New(cfg.ContainerSocket, cfg.EventBuffer, log)
	if err != nil {
		return nil, err
	}
	w.SetScope(scope)
	return w, nil
}

func wireHoneypotKill(mgr *enforcer.Manager, w watcher.ContainerWatcher, sink *sinks.Multi, log *slog.Logger) {
	mgr.OnHoneypotEvent = func(ev enforcer.HoneypotEvent) {
		if ev.ContainerID != "" {
			if err := w.KillContainer(context.Background(), ev.ContainerID); err != nil {
				log.Warn("honeypot kill failed", "container", ev.ContainerID, "error", err)
			}
		}
		// Synthesize an advisory so operators see the honeypot trip.
		_ = sink.ReportAdvisory(context.Background(), &advisory.Advisory{
			ContainerID: ev.ContainerID,
			Kind:        advisory.KindBPFLSMUnavailable, // closest catch-all today
			Message:     fmt.Sprintf("honeypot tripped: %s", ev.HoneypotPath),
			ActionTaken: "killed",
		})
		// And ship the final egress stats if we still have them.
		if result := mgr.Detach(ev.ContainerID); result != nil {
			sink.ReportAsync(context.Background(), result.Info, &result.Stats, false, time.Time{})
		}
	}
}

func emitHoneypotAdvisory(cfg enforcer.HoneypotConfig, mgr *enforcer.Manager, sink *sinks.Multi) {
	if !cfg.Enabled || mgr.LSMLoaded() {
		return
	}
	_ = sink.ReportAdvisory(context.Background(), &advisory.Advisory{
		Kind:        advisory.KindBPFLSMUnavailable,
		Message:     "BPF LSM not supported by kernel — honeypot enforcement inactive",
		ActionTaken: "warned",
	})
}

func recoverRunning(ctx context.Context, w watcher.ContainerWatcher, h *handler.Handler, log *slog.Logger) {
	recovered, err := w.RecoverRunning(ctx)
	if err != nil {
		log.Warn("recovery scan failed", "error", err)
		return
	}

	sandbox := make([]watcher.ContainerEvent, 0, len(recovered))
	others := make([]watcher.ContainerEvent, 0, len(recovered))
	for _, ev := range recovered {
		if ev.Action == "pod_sandbox_start" {
			sandbox = append(sandbox, ev)
		} else {
			others = append(others, ev)
		}
	}
	for _, ev := range sandbox {
		h.HandlePodSandboxStart(ctx, ev)
	}
	for _, ev := range others {
		switch ev.Action {
		case "sibling_start":
			h.HandleSiblingStart(ctx, ev)
		default:
			h.HandleStart(ctx, ev)
		}
	}
	log.Info("recovery complete", "containers", len(others), "sandboxes", len(sandbox))
}

func runEventLoop(
	ctx context.Context,
	log *slog.Logger,
	h *handler.Handler,
	mgr *enforcer.Manager,
	events <-chan watcher.ContainerEvent,
	sink *sinks.Multi,
) {
	log.Info("agent ready, watching for containers")
	for {
		select {
		case <-ctx.Done():
			log.Info("shutting down, detaching enforcers")
			mgr.StopHoneypot()
			results := mgr.DetachAll()
			for _, r := range results {
				sink.ReportAsync(ctx, r.Info, &r.Stats, false, time.Time{})
			}
			log.Info("shutdown complete", "detached", len(results))
			return
		case ev, ok := <-events:
			if !ok {
				log.Info("event stream closed")
				return
			}
			dispatch(ctx, h, ev)
		}
	}
}

func dispatch(ctx context.Context, h *handler.Handler, ev watcher.ContainerEvent) {
	switch ev.Action {
	case "start":
		h.HandleStart(ctx, ev)
	case "sibling_start":
		h.HandleSiblingStart(ctx, ev)
	case "pod_sandbox_start":
		h.HandlePodSandboxStart(ctx, ev)
	case "pod_sandbox_die":
		h.HandlePodSandboxDie(ctx, ev)
	case "die":
		h.HandleDie(ctx, ev)
	}
}

func startMetricsServer(ctx context.Context, reg *prometheus.Registry, addr string, promEnabled bool, log *slog.Logger) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	if promEnabled && reg != nil {
		mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Bind synchronously so the caller sees address-in-use immediately.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	go func() {
		log.Info("metrics server listening", "addr", addr)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("metrics server failed", "error", err)
		}
	}()

	return nil
}

func splitTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseTrustedCIDRs(raw string, log *slog.Logger) []net.IPNet {
	if raw == "" {
		return nil
	}
	var out []net.IPNet
	for _, s := range strings.Split(raw, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		_, cidr, err := net.ParseCIDR(s)
		if err != nil {
			log.Error("invalid trusted CIDR", "cidr", s, "error", err)
			continue
		}
		out = append(out, *cidr)
	}
	return out
}
