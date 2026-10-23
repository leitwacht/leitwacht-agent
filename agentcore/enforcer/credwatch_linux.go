//go:build linux

package enforcer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// credwatchLSMImpl holds the loaded BPF LSM objects and link.
type credwatchLSMImpl struct {
	objs *credwatchObjects
	link link.Link
}

func (c *credwatchLSMImpl) Close() {
	if c.link != nil {
		c.link.Close() //nolint:errcheck,gosec // cleanup
	}

	if c.objs != nil {
		c.objs.Close() //nolint:errcheck,gosec // cleanup
	}
}

// loadCredwatchLSM loads the BPF LSM program and attaches it.
// Returns the loaded objects and LSM link, or an error if BPF LSM is unavailable.
func loadCredwatchLSM() (*credwatchObjects, link.Link, error) {
	spec, err := loadCredwatch()
	if err != nil {
		return nil, nil, fmt.Errorf("load credwatch spec: %w", err)
	}

	verifyErr := verifyStructSize(spec.Types, "credwatch_event", credwatchEventSize)
	if verifyErr != nil {
		return nil, nil, fmt.Errorf("credwatch bytecode verify: %w", verifyErr)
	}

	var objs credwatchObjects

	err = spec.LoadAndAssign(&objs, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("load credwatch bpf objects: %w", err)
	}

	lsmLink, err := link.AttachLSM(link.LSMOptions{
		Program: objs.CredwatchFileOpen,
	})
	if err != nil {
		objs.Close() //nolint:errcheck,gosec // cleanup

		return nil, nil, fmt.Errorf("attach lsm: %w", err)
	}

	return &objs, lsmLink, nil
}

// startCredwatchReader starts the ring buffer reader goroutine.
// It calls onEvent for each decoded event. Returns a stop function.
func startCredwatchReader(objs *credwatchObjects, logger *slog.Logger, onEvent func(credwatchEventBPF)) (func(), error) {
	reader, err := ringbuf.NewReader(objs.CredwatchEvents)
	if err != nil {
		return nil, fmt.Errorf("open credwatch ringbuf: %w", err)
	}

	var wg sync.WaitGroup

	done := make(chan struct{})

	wg.Go(func() {
		<-done
		reader.Close() //nolint:errcheck,gosec // cleanup
	})

	wg.Go(func() {
		for {
			record, err := reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}

				logger.Debug("credwatch ringbuf read error", "error", err)

				continue
			}

			raw := record.RawSample
			logger.Debug("credwatch ringbuf event", "raw_len", len(raw))

			// Parse the packed struct directly from raw bytes.
			// Layout: cgroup_id(8) + pid(4) + comm(16) + path(128) + timestamp_ns(8) = 164
			if len(raw) < credwatchEventSize {
				logger.Warn("credwatch event too short", "len", len(raw))

				continue
			}

			evt := credwatchEventBPF{
				CgroupID:    binary.LittleEndian.Uint64(raw[0:8]),
				PID:         binary.LittleEndian.Uint32(raw[8:12]),
				TimestampNs: binary.LittleEndian.Uint64(raw[156:164]),
			}
			copy(evt.Comm[:], raw[12:28])
			copy(evt.Path[:], raw[28:156])

			onEvent(evt)
		}
	})

	stop := func() {
		close(done)
		wg.Wait()
	}

	return stop, nil
}

// populateWatchedPathMaps populates the watched_filenames and watched_suffixes
// BPF maps from the configured WatchedPaths and ExcludedPaths. Called once at
// StartCredwatch time (global, not per-container).
func populateWatchedPathMaps(objs *credwatchObjects, watchedPaths, excludedPaths []string) error {
	excluded := make(map[string]struct{}, len(excludedPaths))
	for _, p := range excludedPaths {
		excluded[p] = struct{}{}
	}

	for _, suffix := range watchedPaths {
		if _, isExcluded := excluded[suffix]; isExcluded {
			continue
		}

		// Populate watched_suffixes map (the full suffix, e.g. "/.ssh/id_rsa")
		var suffixKey [64]byte
		copy(suffixKey[:], suffix)

		if err := objs.WatchedSuffixes.Put(suffixKey[:], uint8(1)); err != nil {
			return fmt.Errorf("put watched_suffixes %q: %w", suffix, err)
		}

		// Populate watched_filenames map (the last path component, e.g. "id_rsa")
		filename := path.Base(suffix)
		if filename == "." || filename == "/" {
			continue
		}

		var fnameKey [64]byte
		copy(fnameKey[:], filename)

		if err := objs.WatchedFilenames.Put(fnameKey[:], uint8(1)); err != nil {
			return fmt.Errorf("put watched_filenames %q: %w", filename, err)
		}
	}

	return nil
}

// populateCredwatchMaps adds a container's cgroup ID to known_containers
// with the appropriate flags (monitored + optional exemption mode).
// allowCredWatch and observeOnly are not mutually exclusive at the
// flag level, but if both are set allowCredWatch wins because the
// BPF program's ALLOW check fires first (no event emitted).
func populateCredwatchMaps(objs *credwatchObjects, cgID uint64, allowCredWatch, observeOnly bool) error {
	flags := uint8(credwatchFlagMonitored)
	if allowCredWatch {
		flags |= credwatchFlagAllowCredWatch
	}
	if observeOnly {
		flags |= credwatchFlagObserveOnly
	}

	cfg := cgroupCredwatchConfig{Flags: flags}

	err := objs.KnownContainers.Put(cgID, cfg)
	if err != nil {
		return fmt.Errorf("put known_containers: %w", err)
	}

	return nil
}

// removeCredwatchMaps removes a container's entry from the known_containers map.
func removeCredwatchMaps(objs *credwatchObjects, cgID uint64) {
	_ = objs.KnownContainers.Delete(cgID)
}

// cgroupCredwatchConfig matches the BPF struct cgroup_proc_config (packed, 1 byte).
type cgroupCredwatchConfig struct {
	Flags uint8
}

// StartCredwatch loads the credential file watch LSM.
// Tolerant: if LSM is unavailable, logs a warning and returns nil (like proc_mem).
func (m *Manager) StartCredwatch() error {
	if !m.credwatchCfg.Enabled {
		m.logger.Info("credwatch enforcement disabled")

		return nil
	}

	objs, lsmLink, err := loadCredwatchLSM()
	if err != nil {
		m.logger.Warn("credwatch LSM unavailable, skipping", "error", err)

		return nil
	}

	lsm := &credwatchLSMImpl{objs: objs, link: lsmLink}
	m.credwatchState = lsm
	m.credwatchLSMLoaded = true

	// Populate watched suffix and filename maps from config.
	if err := populateWatchedPathMaps(objs, m.credwatchCfg.WatchedPaths, m.credwatchCfg.ExcludedPaths); err != nil {
		lsm.Close()
		m.credwatchState = nil
		m.credwatchLSMLoaded = false

		return fmt.Errorf("populate credwatch path maps: %w", err)
	}

	stop, err := startCredwatchReader(objs, m.logger, m.handleCredwatchBPFEvent)
	if err != nil {
		lsm.Close()
		m.credwatchState = nil
		m.credwatchLSMLoaded = false

		return fmt.Errorf("start credwatch reader: %w", err)
	}

	m.credwatchStop = stop
	m.logger.Info("credwatch LSM loaded",
		"watched_suffixes", len(m.credwatchCfg.WatchedPaths),
		"excluded", len(m.credwatchCfg.ExcludedPaths),
	)

	return nil
}

// StopCredwatch shuts down the credential file watch LSM.
func (m *Manager) StopCredwatch() {
	if !m.credwatchLSMLoaded {
		return
	}

	if m.credwatchStop != nil {
		m.credwatchStop()
	}

	if lsm, ok := m.credwatchState.(*credwatchLSMImpl); ok {
		lsm.Close()
	}

	m.credwatchState = nil
	m.credwatchLSMLoaded = false
	m.logger.Info("credwatch LSM stopped")
}

// CredwatchLSMLoaded returns whether the credwatch LSM program is active.
func (m *Manager) CredwatchLSMLoaded() bool {
	return m.credwatchLSMLoaded
}

// AttachCredwatch populates credwatch BPF maps for a container's single
// cgroup. Prefer AttachCredwatchPaths when the container has more than
// one relevant cgroup (scope + leaf).
func (m *Manager) AttachCredwatch(containerID, cgroupPath string, allowCredWatch, observeOnly bool) {
	m.AttachCredwatchPaths(containerID, []string{cgroupPath}, allowCredWatch, observeOnly)
}

// AttachCredwatchPaths populates credwatch BPF maps for every cgroup of
// a container. The BPF program keys on bpf_get_current_cgroup_id(),
// which is the task's leaf cgroup: a Docker container whose PID lives in
// .../docker-<id>.scope/init reports the /init leaf, not the scope the
// egress program is attached at, so both ids must be registered or the
// main process's own credential reads go unseen.
// Non-fatal: logs warnings on failure (egress enforcement continues).
func (m *Manager) AttachCredwatchPaths(containerID string, cgroupPaths []string, allowCredWatch, observeOnly bool) {
	if !m.credwatchLSMLoaded {
		return
	}

	lsm, ok := m.credwatchState.(*credwatchLSMImpl)
	if !ok {
		return
	}

	var cgIDs []uint64

	for _, p := range cgroupPaths {
		cgID, err := cgroupID(p)
		if err != nil {
			m.logger.Warn("credwatch: failed to get cgroup id", "container", truncID(containerID), "path", p, "error", err)

			continue
		}

		if err := populateCredwatchMaps(lsm.objs, cgID, allowCredWatch, observeOnly); err != nil {
			m.logger.Warn("credwatch: failed to populate maps", "container", truncID(containerID), "cgroup_id", cgID, "error", err)

			continue
		}

		cgIDs = append(cgIDs, cgID)
	}

	if len(cgIDs) == 0 {
		return
	}

	m.mu.Lock()
	m.credwatchContainers[containerID] = &credwatchContainerState{
		CgroupID:    cgIDs[0],
		CgroupIDs:   cgIDs,
		ObserveOnly: observeOnly,
	}

	for _, id := range cgIDs {
		m.credwatchCgroupToContainer[id] = containerID
	}
	m.mu.Unlock()

	m.logger.Info("credwatch maps populated",
		"container", truncID(containerID),
		"cgroup_ids", cgIDs,
		"allow_credwatch", allowCredWatch,
		"observe_only", observeOnly,
	)
}

// DetachCredwatch removes a container's credwatch entries from BPF maps.
func (m *Manager) DetachCredwatch(containerID string) {
	if !m.credwatchLSMLoaded {
		return
	}

	lsm, ok := m.credwatchState.(*credwatchLSMImpl)
	if !ok {
		return
	}

	m.mu.Lock()
	state, exists := m.credwatchContainers[containerID]
	if exists {
		delete(m.credwatchContainers, containerID)

		for _, id := range state.allCgroupIDs() {
			delete(m.credwatchCgroupToContainer, id)
		}
	}
	m.mu.Unlock()

	if !exists {
		return
	}

	for _, id := range state.allCgroupIDs() {
		removeCredwatchMaps(lsm.objs, id)
	}

	m.logger.Debug("credwatch maps cleaned", "container", truncID(containerID))
}

// handleCredwatchBPFEvent is called by the ring buffer reader for each event.
func (m *Manager) handleCredwatchBPFEvent(evt credwatchEventBPF) {
	m.mu.Lock()
	containerID := m.credwatchCgroupToContainer[evt.CgroupID]
	observeOnly := false
	if state := m.credwatchContainers[containerID]; state != nil {
		observeOnly = state.ObserveOnly
	}
	m.mu.Unlock()

	// BPF stamps evt.TimestampNs with bpf_ktime_get_ns() (CLOCK_MONOTONIC);
	// convert to wall-clock epoch ns here so downstream last_seen isn't ~1970
	// and the server doesn't TTL-purge the row. See clock.go.
	nowWallNs := time.Now().UnixNano()
	nowMonoNs := nowMonotonicNs()

	event := CredwatchEvent{
		ContainerID: containerID,
		CgroupID:    evt.CgroupID,
		PID:         evt.PID,
		Comm:        nullTerminated(evt.Comm[:]),
		Path:        nullTerminated(evt.Path[:]),
		TimestampNs: monotonicToWallNs(int64(evt.TimestampNs), nowMonoNs, nowWallNs), //nolint:gosec // monotonic ns fits int64
		ObserveOnly: observeOnly,
	}

	m.logger.Warn("credential file access detected",
		"container", containerID,
		"pid", evt.PID,
		"comm", event.Comm,
		"path", event.Path,
	)

	if m.OnCredwatchEvent != nil {
		m.OnCredwatchEvent(event)
	}
}

// ParsePathList splits a comma-separated path list, trimming whitespace and
// skipping empty entries.
func ParsePathList(s string) []string {
	if s == "" {
		return nil
	}

	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}

	return result
}
