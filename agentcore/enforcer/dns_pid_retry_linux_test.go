//go:build linux

package enforcer

import (
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

// retryFakeClock advances by step on every yield.
type retryFakeClock struct {
	t     time.Time
	step  time.Duration
	yield int
}

func (c *retryFakeClock) now() time.Time { return c.t }
func (c *retryFakeClock) y()             { c.yield++; c.t = c.t.Add(c.step) }

func TestLookupWithRetry_MissThenHit(t *testing.T) {
	clk := &retryFakeClock{t: time.Unix(0, 0), step: 100 * time.Microsecond}
	calls := 0

	err := lookupWithRetry(func() error {
		calls++
		if calls < 3 {
			return ebpf.ErrKeyNotExist
		}

		return nil
	}, dnsPIDRetryBudget, clk.now, clk.y)
	if err != nil {
		t.Fatalf("want nil, got %v", err)
	}

	// The first retries are back-to-back: no yield.
	if calls != 3 || clk.yield != 0 {
		t.Fatalf("calls=%d yields=%d", calls, clk.yield)
	}
}

func TestLookupWithRetry_PersistentMissBounded(t *testing.T) {
	clk := &retryFakeClock{t: time.Unix(0, 0), step: 100 * time.Microsecond}
	calls := 0

	err := lookupWithRetry(func() error {
		calls++

		return ebpf.ErrKeyNotExist
	}, dnsPIDRetryBudget, clk.now, clk.y)
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("want ErrKeyNotExist, got %v", err)
	}

	// 3 immediate retries (4 calls, no time passes), then 1ms budget /
	// 100us per yield: 10 yields, 14 calls in total.
	if calls != 14 || clk.yield != 10 {
		t.Fatalf("calls=%d yields=%d", calls, clk.yield)
	}
}

func TestLookupWithRetry_OtherErrorNoRetry(t *testing.T) {
	boom := errors.New("boom")
	calls := 0

	err := lookupWithRetry(func() error {
		calls++

		return boom
	}, dnsPIDRetryBudget, time.Now, func() { t.Fatal("must not yield") })
	if !errors.Is(err, boom) || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

// Real-clock guard: a persistent miss must stay near the ~1 ms budget
// (regression guard against sub-ms time.Sleep rounding). Generous bound
// to avoid CI flakiness.
func TestLookupWithRetry_RealClockPersistentMissFast(t *testing.T) {
	start := time.Now()
	err := lookupWithRetry(func() error {
		return ebpf.ErrKeyNotExist
	}, dnsPIDRetryBudget, time.Now, runtime.Gosched)

	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("want ErrKeyNotExist, got %v", err)
	}

	if d := time.Since(start); d > 20*time.Millisecond {
		t.Fatalf("persistent miss took %v, want <20ms", d)
	}
}
