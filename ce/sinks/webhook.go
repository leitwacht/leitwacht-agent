package sinks

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/advisory"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/enforcer"
)

// Webhook posts a JSON envelope per report to a single configured URL.
// It is fire-and-forget: failures are logged, never retried, never
// surface to the handler. The post runs on its own goroutine so a slow
// upstream cannot delay enforcement.
//
// Concurrency is bounded by maxInflight (default 32). When the cap is
// reached, additional reports are dropped — the dropped counter
// increments and a warning is logged. This protects the daemon from a
// goroutine storm if the webhook upstream stalls during a busy
// container churn period.
//
// Use Webhook for low-volume, best-effort delivery to a SIEM or chat
// channel. For durable / queued delivery, run a local NDJSON consumer
// against the stdout sink.
type Webhook struct {
	client   *http.Client
	url      string
	hostname string
	header   string
	log      *slog.Logger

	// ctx is the sink's own context, deliberately independent of the
	// daemon's shutdown context: the final per-container reports are
	// emitted after that context is cancelled and must still go out.
	ctx context.Context
	sem chan struct{}
	wg  sync.WaitGroup

	dropped atomic.Int64
}

// DefaultWebhookConcurrency caps the number of in-flight webhook
// deliveries. Tuned for SIEM-class destinations that handle a few
// requests/sec; raise via NewWebhookWithLimits if the upstream supports
// higher throughput.
const DefaultWebhookConcurrency = 32

// NewWebhook returns a Webhook sink with default concurrency limits.
// parent is accepted for API compatibility but is intentionally not
// used for cancellation: shutdown-time reports (emitted after the
// daemon context is cancelled) must still be delivered. Call Flush
// before exit to wait for in-flight posts.
// authHeader (e.g., "Bearer abc...") is sent verbatim if non-empty;
// surrounding whitespace is trimmed.
func NewWebhook(parent context.Context, url string, timeout time.Duration, hostname, authHeader string, log *slog.Logger) *Webhook {
	return NewWebhookWithLimits(parent, url, timeout, hostname, authHeader, DefaultWebhookConcurrency, log)
}

// NewWebhookWithLimits exposes the concurrency cap so tests and tuned
// production deployments can override it. maxInflight <= 0 falls back
// to DefaultWebhookConcurrency.
func NewWebhookWithLimits(_ context.Context, url string, timeout time.Duration, hostname, authHeader string, maxInflight int, log *slog.Logger) *Webhook {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if maxInflight <= 0 {
		maxInflight = DefaultWebhookConcurrency
	}
	return &Webhook{
		client:   &http.Client{Timeout: timeout},
		url:      url,
		hostname: hostname,
		header:   strings.TrimSpace(authHeader),
		log:      log,
		ctx:      context.Background(),
		sem:      make(chan struct{}, maxInflight),
	}
}

// Flush blocks until all in-flight posts finish or timeout elapses,
// whichever comes first, and reports whether everything drained. Call it
// once after the last report has been emitted. Posts are still bounded
// individually by the HTTP client timeout.
func (w *Webhook) Flush(timeout time.Duration) bool {
	done := make(chan struct{})

	go func() {
		w.wg.Wait()
		close(done)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-done:
		return true
	case <-timer.C:
		w.log.Warn("webhook sink: flush timed out with posts still in flight", "timeout", timeout)

		return false
	}
}

// Dropped returns the count of webhook posts that failed to encode or
// send. Surfaced for diagnostics.
func (w *Webhook) Dropped() int64 { return w.dropped.Load() }

// ReportAsync posts a violation envelope.
func (w *Webhook) ReportAsync(
	ctx context.Context,
	info enforcer.ContainerInfo,
	stats *enforcer.EgressStats,
	interim bool,
	bucketTS time.Time,
) {
	rec := violationRecord{
		Type:        "violation_report",
		Hostname:    w.hostname,
		ContainerID: info.ContainerID,
		ProjectPath: info.ProjectPath,
		JobID:       info.JobID,
		JobName:     info.JobName,
		JobURL:      info.JobURL,
		Action:      info.Action,
		Interim:     interim,
		BucketTS:    bucketTS,
		EmittedAt:   time.Now().UTC(),
	}
	if stats != nil {
		rec.BytesSent = stats.TotalBytesSent
		rec.Violations = stats.Violations
		rec.DNSActivity = stats.DNSActivity
		rec.Overflow = stats.OverflowCount
	}
	w.dispatch(rec)
}

// ReportAdvisory posts an advisory envelope.
func (w *Webhook) ReportAdvisory(_ context.Context, a *advisory.Advisory) error {
	if a == nil {
		return nil
	}
	occurred := a.OccurredAt
	if occurred.IsZero() {
		occurred = time.Now().UTC()
	}
	rec := advisoryRecord{
		Type:         "advisory",
		Hostname:     w.hostname,
		ContainerID:  a.ContainerID,
		ProjectPath:  a.ProjectPath,
		JobID:        a.JobID,
		JobURL:       a.JobURL,
		Kind:         string(a.Kind),
		Message:      a.Message,
		ActionTaken:  a.ActionTaken,
		PolicyAction: a.PolicyAction,
		OccurredAt:   occurred,
	}
	w.dispatch(rec)
	return nil
}

// dispatch acquires a slot in the in-flight semaphore and runs post on
// a goroutine. When the cap is reached it drops the report rather than
// queueing — better to lose a few records than to OOM the agent on a
// stuck upstream.
func (w *Webhook) dispatch(body any) {
	select {
	case w.sem <- struct{}{}:
	default:
		w.dropped.Add(1)
		w.log.Warn("webhook sink: in-flight cap reached, dropping",
			"cap", cap(w.sem))
		return
	}

	w.wg.Add(1)

	go func() {
		defer func() { <-w.sem }()
		defer w.wg.Done()
		w.post(body)
	}()
}

func (w *Webhook) post(body any) {
	buf, err := json.Marshal(body)
	if err != nil {
		w.dropped.Add(1)
		w.log.Warn("webhook sink: marshal failed", "error", err)
		return
	}

	// Bound the call by the client timeout.
	postCtx, cancel := context.WithTimeout(w.ctx, w.client.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(postCtx, http.MethodPost, w.url, bytes.NewReader(buf))
	if err != nil {
		w.dropped.Add(1)
		w.log.Warn("webhook sink: build request failed", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if w.header != "" {
		req.Header.Set("Authorization", w.header)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		w.dropped.Add(1)
		w.log.Warn("webhook sink: post failed", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		w.dropped.Add(1)
		preview, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		w.log.Warn("webhook sink: non-2xx response",
			"status", resp.StatusCode,
			"body", string(preview))
		return
	}
}
