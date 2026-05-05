package sinks

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/advisory"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/enforcer"
)

// stdoutQueueDepth bounds the per-sink async write queue. Sized for a
// single host's legitimate peak NDJSON volume; a slow writer pushing
// the queue past this threshold drops records and increments the
// dropped counter — propagated to leitwacht_ce_stdout_dropped_total.
const stdoutQueueDepth = 1024

// Stdout writes one NDJSON record per violation/advisory to the
// configured writer (typically os.Stderr). Encoding happens on the
// caller's goroutine; the actual Write happens on a single drainer
// goroutine so a slow writer (network mount, ratelimited syslog
// forwarder) cannot back-pressure other sinks fanned out by Multi.
//
// On queue overflow records are dropped — the dropped counter is
// exposed via Dropped(). Operators get a Prometheus signal via
// leitwacht_ce_stdout_dropped_total before silent loss.
//
// Call Close() on shutdown to flush remaining buffered records and
// stop the drainer goroutine cleanly.
type Stdout struct {
	w        io.Writer
	mu       sync.Mutex // serialises Writes (writer may not be concurrency-safe)
	hostname string
	log      *slog.Logger

	// Producer/consumer plumbing. We never close(queue) — closing the
	// queue while a producer is mid-`select` would race the closed flag
	// and panic on send-to-closed. Instead, Close() flips `closed` (so
	// new producers fast-path drop) and signals the drainer via
	// `shutdown`; the drainer drains whatever's already in `queue` and
	// exits. Producers that beat the closed-flag check still race-free
	// hit a buffered chan that nobody closes.
	queue    chan []byte
	dropped  atomic.Int64
	shutdown chan struct{}
	done     chan struct{}
	closed   atomic.Bool
}

// NewStdout returns a Stdout sink. Hostname is stamped into every
// record so multi-node logs can be filtered by host. Spawns a single
// drainer goroutine; call Close() to stop it.
func NewStdout(w io.Writer, hostname string, log *slog.Logger) *Stdout {
	s := &Stdout{
		w:        w,
		hostname: hostname,
		log:      log,
		queue:    make(chan []byte, stdoutQueueDepth),
		shutdown: make(chan struct{}),
		done:     make(chan struct{}),
	}

	go s.drain()

	return s
}

// Dropped returns the count of records dropped because the async
// queue was full. Surfaced as leitwacht_ce_stdout_dropped_total.
func (s *Stdout) Dropped() int64 { return s.dropped.Load() }

// Close stops the drainer goroutine after flushing the queue.
// Idempotent. Safe to call concurrently with in-flight ReportAsync /
// ReportAdvisory calls — those either land in the queue (drainer will
// flush them) or hit the closed fast-path and increment Dropped().
func (s *Stdout) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}

	close(s.shutdown)
	<-s.done

	return nil
}

// drain pulls from queue until shutdown is signalled. After shutdown,
// drains whatever's already buffered (non-blocking) so flushed records
// at-or-before Close() reach the writer. Producers that race the
// shutdown flag may still queue; we accept up to one queue's worth of
// records may be lost on shutdown, which is the intended trade-off for
// a panic-free producer fast path.
func (s *Stdout) drain() {
	defer close(s.done)

	for {
		select {
		case buf := <-s.queue:
			s.write(buf)
		case <-s.shutdown:
			// Drain whatever's already buffered, non-blocking.
			for {
				select {
				case buf := <-s.queue:
					s.write(buf)
				default:
					return
				}
			}
		}
	}
}

func (s *Stdout) write(buf []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.w.Write(buf); err != nil {
		s.log.Warn("stdout sink: write failed", "error", err)
	}
}

type violationRecord struct {
	Type        string                      `json:"type"`
	Hostname    string                      `json:"hostname"`
	ContainerID string                      `json:"container_id"`
	ProjectPath string                      `json:"project_path,omitempty"`
	JobID       string                      `json:"job_id,omitempty"`
	JobName     string                      `json:"job_name,omitempty"`
	JobURL      string                      `json:"job_url,omitempty"`
	Action      string                      `json:"action,omitempty"`
	Interim     bool                        `json:"interim"`
	BucketTS    time.Time                   `json:"bucket_ts,omitempty"`
	BytesSent   int64                       `json:"bytes_sent"`
	Violations  []enforcer.Violation        `json:"violations,omitempty"`
	DNSActivity []enforcer.DNSActivityEntry `json:"dns_activity,omitempty"`
	Overflow    int64                       `json:"overflow_count,omitempty"`
	EmittedAt   time.Time                   `json:"emitted_at"`
}

type advisoryRecord struct {
	Type         string    `json:"type"`
	Hostname     string    `json:"hostname"`
	ContainerID  string    `json:"container_id,omitempty"`
	ProjectPath  string    `json:"project_path,omitempty"`
	JobID        string    `json:"job_id,omitempty"`
	JobURL       string    `json:"job_url,omitempty"`
	Kind         string    `json:"kind"`
	Message      string    `json:"message,omitempty"`
	ActionTaken  string    `json:"action_taken,omitempty"`
	PolicyAction string    `json:"policy_action,omitempty"`
	OccurredAt   time.Time `json:"occurred_at"`
}

// ReportAsync renders a violation report as NDJSON and queues it for
// the drainer. Marshalling happens on the caller's goroutine — that
// keeps the queue holding bytes (cheap) instead of struct values
// (would need GC pressure analysis).
func (s *Stdout) ReportAsync(
	_ context.Context,
	info enforcer.ContainerInfo,
	stats *enforcer.EgressStats,
	interim bool,
	bucketTS time.Time,
) {
	rec := violationRecord{
		Type:        "violation_report",
		Hostname:    s.hostname,
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
	s.enqueue(rec)
}

// ReportAdvisory renders an advisory as NDJSON.
func (s *Stdout) ReportAdvisory(_ context.Context, a *advisory.Advisory) error {
	if a == nil {
		return nil
	}
	occurred := a.OccurredAt
	if occurred.IsZero() {
		occurred = time.Now().UTC()
	}
	s.enqueue(advisoryRecord{
		Type:         "advisory",
		Hostname:     s.hostname,
		ContainerID:  a.ContainerID,
		ProjectPath:  a.ProjectPath,
		JobID:        a.JobID,
		JobURL:       a.JobURL,
		Kind:         string(a.Kind),
		Message:      a.Message,
		ActionTaken:  a.ActionTaken,
		PolicyAction: a.PolicyAction,
		OccurredAt:   occurred,
	})
	return nil
}

func (s *Stdout) enqueue(v any) {
	if s.closed.Load() {
		s.dropped.Add(1)
		return
	}

	buf, err := json.Marshal(v)
	if err != nil {
		s.log.Warn("stdout sink: marshal failed", "error", err)
		return
	}
	buf = append(buf, '\n')

	select {
	case s.queue <- buf:
	default:
		// Queue full — drop and count. Operator sees this via
		// leitwacht_ce_stdout_dropped_total. Logging here would
		// compound the problem (more I/O on a writer that's already
		// behind).
		s.dropped.Add(1)
	}
}
