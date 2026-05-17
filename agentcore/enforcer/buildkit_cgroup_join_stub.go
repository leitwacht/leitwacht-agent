//go:build !linux

package enforcer

import (
	"context"
)

// InotifyCgroupSource is a non-Linux placeholder. The cgroup-join
// layer is Linux-only because it relies on inotify and the cgroup v2
// inode-as-cgroup-id convention; non-Linux callers get a source whose
// Run returns ErrCgroupJoinUnsupported immediately so the agent's
// main loop can degrade gracefully.
type InotifyCgroupSource struct {
	WatchPaths []string
}

// NewInotifyCgroupSource matches the Linux signature so callers stay
// portable. WatchPaths is accepted but ignored.
func NewInotifyCgroupSource(paths []string) *InotifyCgroupSource {
	return &InotifyCgroupSource{WatchPaths: paths}
}

// Run returns ErrCgroupJoinUnsupported.
func (s *InotifyCgroupSource) Run(_ context.Context, creates chan<- CgroupCreateEvent, removes chan<- CgroupRemoveEvent) error {
	close(creates)
	close(removes)

	return ErrCgroupJoinUnsupported
}

// cgroupInode is unimplemented off Linux; the join layer's stat
// fallback handles this by treating every stat as a no-op.
func cgroupInode(_ string) (uint64, error) {
	return 0, ErrCgroupJoinUnsupported
}

//nolint:gochecknoinits // platform-specific stat-fn binding; init is the right shape.
func init() {
	defaultStatFn = cgroupInode
}
