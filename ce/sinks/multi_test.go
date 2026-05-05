package sinks

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/advisory"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/enforcer"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/violation"
)

type recorderViolation struct {
	mu    sync.Mutex
	count int
}

func (r *recorderViolation) ReportAsync(_ context.Context, _ enforcer.ContainerInfo,
	_ *enforcer.EgressStats, _ bool, _ time.Time) {
	r.mu.Lock()
	r.count++
	r.mu.Unlock()
}

func (r *recorderViolation) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}

type recorderAdvisory struct {
	count int
	err   error
}

func (r *recorderAdvisory) ReportAdvisory(_ context.Context, _ *advisory.Advisory) error {
	r.count++
	return r.err
}

// TestMultiFansOutToAllSinks verifies that a single ReportAsync /
// ReportAdvisory call dispatches to every configured sink. The CE main
// wires stdout + prom + (optional) webhook through Multi, so a regression
// here means a sink silently goes dark.
func TestMultiFansOutToAllSinks(t *testing.T) {
	a, b := &recorderViolation{}, &recorderViolation{}
	c, d := &recorderAdvisory{}, &recorderAdvisory{}

	m := &Multi{
		Violations: []violation.Sink{a, b},
		Advisories: []advisory.Sink{c, d},
	}

	m.ReportAsync(context.Background(), enforcer.ContainerInfo{},
		&enforcer.EgressStats{}, false, time.Time{})

	if a.Count() != 1 || b.Count() != 1 {
		t.Errorf("ReportAsync fan-out: a=%d b=%d, want 1/1", a.Count(), b.Count())
	}

	if err := m.ReportAdvisory(context.Background(), &advisory.Advisory{}); err != nil {
		t.Errorf("ReportAdvisory: unexpected error %v", err)
	}
	if c.count != 1 || d.count != 1 {
		t.Errorf("ReportAdvisory fan-out: c=%d d=%d, want 1/1", c.count, d.count)
	}
}

// TestMultiAdvisoryReturnsFirstError ensures that a single failing
// advisory sink doesn't suppress later sinks (call still happens) but
// the first error is surfaced — important so an alerting failure on
// stdout doesn't hide a bigger problem on the webhook.
func TestMultiAdvisoryReturnsFirstError(t *testing.T) {
	boom := errors.New("boom")
	c := &recorderAdvisory{err: boom}
	d := &recorderAdvisory{}

	m := &Multi{Advisories: []advisory.Sink{c, d}}

	err := m.ReportAdvisory(context.Background(), &advisory.Advisory{})
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want boom", err)
	}
	if d.count != 1 {
		t.Errorf("downstream sink not called after upstream error: count=%d", d.count)
	}
}
