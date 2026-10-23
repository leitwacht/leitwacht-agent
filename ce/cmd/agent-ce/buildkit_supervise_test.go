//go:build linux

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/enforcer"
)

type flakyJoiner struct {
	runs     atomic.Int32
	failFor  int32
	failWith error
}

func (f *flakyJoiner) Run(ctx context.Context) error {
	if f.runs.Add(1) <= f.failFor {
		return f.failWith
	}

	<-ctx.Done()

	return ctx.Err()
}

func TestSuperviseJoiner_RestartsAfterExit(t *testing.T) {
	t.Parallel()

	j := &flakyJoiner{failFor: 2, failWith: errors.New("boom")}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		superviseJoinerWith(ctx, j, slog.New(slog.NewTextHandler(io.Discard, nil)), 5*time.Millisecond, 20*time.Millisecond)
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for j.runs.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	if got := j.runs.Load(); got < 3 {
		t.Fatalf("joiner runs = %d, want >= 3 (restarted after failures)", got)
	}

	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("supervisor did not stop on ctx cancel")
	}
}

func TestSuperviseJoiner_StopsOnUnsupported(t *testing.T) {
	t.Parallel()

	j := &flakyJoiner{failFor: 100, failWith: enforcer.ErrCgroupJoinUnsupported}
	done := make(chan struct{})

	go func() {
		superviseJoinerWith(context.Background(), j, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Millisecond, 2*time.Millisecond)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("supervisor kept restarting an unsupported joiner")
	}

	if got := j.runs.Load(); got != 1 {
		t.Fatalf("runs = %d, want 1", got)
	}
}
