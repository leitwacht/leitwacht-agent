package sinks

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/advisory"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/enforcer"
)

// TestWebhookDeliversViolationsAndAdvisories starts an httptest server
// in front of a Webhook sink, fires one violation report and one
// advisory through, and verifies both arrive with the expected JSON
// envelope and Authorization header. Webhook delivery is the CE answer
// for SIEM integrations and we want regressions caught at unit level.
func TestWebhookDeliversViolationsAndAdvisories(t *testing.T) {
	var (
		mu       sync.Mutex
		received []map[string]any
		auth     string
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var rec map[string]any
		if err := json.Unmarshal(body, &rec); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		mu.Lock()
		received = append(received, rec)
		auth = r.Header.Get("Authorization")
		mu.Unlock()

		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	sink := NewWebhook(context.Background(), srv.URL, 2*time.Second, "node-1", "Bearer secret-token", slog.Default())

	sink.ReportAsync(context.Background(), enforcer.ContainerInfo{
		ContainerID: "c1",
		ProjectPath: "team/app",
		Action:      "block",
	}, &enforcer.EgressStats{
		Violations: []enforcer.Violation{{Domain: "evil.example.com", Action: "dns_blocked"}},
	}, false, time.Time{})

	if err := sink.ReportAdvisory(context.Background(), &advisory.Advisory{
		ContainerID: "c1",
		Kind:        advisory.KindSocketMount,
	}); err != nil {
		t.Fatalf("ReportAdvisory: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(received)
		mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()

	if len(received) != 2 {
		t.Fatalf("got %d posts, want 2 (dropped=%d)", len(received), sink.Dropped())
	}
	if auth != "Bearer secret-token" {
		t.Errorf("Authorization = %q, want Bearer secret-token", auth)
	}

	types := map[string]bool{}
	for _, r := range received {
		types[r["type"].(string)] = true
	}
	if !types["violation_report"] || !types["advisory"] {
		t.Errorf("missing type: got %+v", types)
	}
}

// TestWebhookCountsDroppedOnNon2xx verifies that an upstream returning
// 5xx increments the drop counter rather than blocking the daemon.
func TestWebhookCountsDroppedOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer srv.Close()

	sink := NewWebhook(context.Background(), srv.URL, 1*time.Second, "node-1", "", slog.Default())
	sink.ReportAsync(context.Background(), enforcer.ContainerInfo{ContainerID: "c1"},
		&enforcer.EgressStats{}, false, time.Time{})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if sink.Dropped() > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("Dropped() = %d, want >=1 after 5xx response", sink.Dropped())
}

// TestWebhookDeliversAfterParentCancelAndFlush covers shutdown: the final
// reports are emitted after the daemon context is cancelled and must still
// reach the upstream; Flush waits for them.
func TestWebhookDeliversAfterParentCancelAndFlush(t *testing.T) {
	var got atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond) // still in flight when Flush starts
		got.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	parent, cancel := context.WithCancel(context.Background())
	sink := NewWebhook(parent, srv.URL, 2*time.Second, "node-1", "", slog.Default())

	cancel()

	for i := 0; i < 3; i++ {
		sink.ReportAsync(parent, enforcer.ContainerInfo{ContainerID: "c1"}, &enforcer.EgressStats{}, false, time.Time{})
	}

	if !sink.Flush(3 * time.Second) {
		t.Fatal("Flush timed out")
	}

	if n := got.Load(); n != 3 {
		t.Fatalf("delivered %d posts after parent cancel, want 3 (dropped=%d)", n, sink.Dropped())
	}
}

func TestWebhookFlushTimesOut(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))

	defer srv.Close()
	defer close(release)

	sink := NewWebhook(context.Background(), srv.URL, 5*time.Second, "node-1", "", slog.Default())
	sink.ReportAsync(context.Background(), enforcer.ContainerInfo{}, nil, false, time.Time{})

	if sink.Flush(50 * time.Millisecond) {
		t.Fatal("Flush reported drained while a post was blocked")
	}
}
