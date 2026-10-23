//go:build linux

package enforcer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// procMemLSMImpl holds the loaded BPF LSM objects and link.
type procMemLSMImpl struct {
	objs *procMemObjects
	link link.Link
}

func (p *procMemLSMImpl) Close() {
	if p.link != nil {
		p.link.Close() //nolint:errcheck,gosec // cleanup
	}

	if p.objs != nil {
		p.objs.Close() //nolint:errcheck,gosec // cleanup
	}
}

// loadProcMemLSM loads the BPF LSM program and attaches it.
// Returns the loaded objects and LSM link, or an error if BPF LSM is unavailable.
func loadProcMemLSM() (*procMemObjects, link.Link, error) {
	spec, err := loadProcMem()
	if err != nil {
		return nil, nil, fmt.Errorf("load proc_mem spec: %w", err)
	}

	verifyErr := verifyStructSize(spec.Types, "proc_mem_event", procMemEventSize)
	if verifyErr != nil {
		return nil, nil, fmt.Errorf("proc_mem bytecode verify: %w", verifyErr)
	}

	var objs procMemObjects

	err = spec.LoadAndAssign(&objs, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("load proc_mem bpf objects: %w", err)
	}

	lsmLink, err := link.AttachLSM(link.LSMOptions{
		Program: objs.ProcMemFileOpen,
	})
	if err != nil {
		objs.Close() //nolint:errcheck,gosec // cleanup

		return nil, nil, fmt.Errorf("attach lsm: %w", err)
	}

	return &objs, lsmLink, nil
}

// startProcMemReader starts the ring buffer reader goroutine.
// It calls onEvent for each decoded event. Returns a stop function.
func startProcMemReader(objs *procMemObjects, logger *slog.Logger, onEvent func(procMemEventBPF)) (func(), error) {
	reader, err := ringbuf.NewReader(objs.ProcMemEvents)
	if err != nil {
		return nil, fmt.Errorf("open proc_mem ringbuf: %w", err)
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

				logger.Debug("proc_mem ringbuf read error", "error", err)

				continue
			}

			raw := record.RawSample
			logger.Debug("proc_mem ringbuf event", "raw_len", len(raw))

			// Parse the packed struct directly from raw bytes.
			// Layout: cgroup_id(8) + pid(4) + comm(16) + path(64) + timestamp_ns(8) = 100
			if len(raw) < procMemEventSize {
				logger.Warn("proc_mem event too short", "len", len(raw))

				continue
			}

			evt := procMemEventBPF{
				CgroupID:    binary.LittleEndian.Uint64(raw[0:8]),
				PID:         binary.LittleEndian.Uint32(raw[8:12]),
				TimestampNs: binary.LittleEndian.Uint64(raw[92:100]),
			}
			copy(evt.Comm[:], raw[12:28])
			copy(evt.Path[:], raw[28:92])

			onEvent(evt)
		}
	})

	stop := func() {
		close(done)
		wg.Wait()
	}

	return stop, nil
}

// populateProcMemMaps adds a container's cgroup ID to known_containers
// with the appropriate flags (monitored, and optionally allow_proc_read).
func populateProcMemMaps(objs *procMemObjects, cgID uint64, allowProcRead, observeOnly bool) error {
	flags := uint8(procMemFlagMonitored)
	if allowProcRead {
		flags |= procMemFlagAllowProcRead
	}
	if observeOnly {
		flags |= procMemFlagObserveOnly
	}

	cfg := cgroupProcConfig{Flags: flags}

	err := objs.KnownContainers.Put(cgID, cfg)
	if err != nil {
		return fmt.Errorf("put known_containers: %w", err)
	}

	return nil
}

// removeProcMemMaps removes a container's entry from the known_containers map.
func removeProcMemMaps(objs *procMemObjects, cgID uint64) {
	_ = objs.KnownContainers.Delete(cgID)
}

// cgroupProcConfig matches the BPF struct cgroup_proc_config (packed, 1 byte).
type cgroupProcConfig struct {
	Flags uint8
}

// StartProcMem loads the /proc/*/mem read detection LSM.
// Tolerant: if LSM is unavailable, logs a warning and returns nil (like credwatch).
func (m *Manager) StartProcMem() error {
	if !m.procMemCfg.Enabled {
		m.logger.Info("proc_mem enforcement disabled")

		return nil
	}

	objs, lsmLink, err := loadProcMemLSM()
	if err != nil {
		m.logger.Warn("proc_mem LSM unavailable, skipping", "error", err)

		return nil
	}

	lsm := &procMemLSMImpl{objs: objs, link: lsmLink}
	m.procMemState = lsm
	m.procMemLSMLoaded = true

	stop, err := startProcMemReader(objs, m.logger, m.handleProcMemBPFEvent)
	if err != nil {
		lsm.Close()
		m.procMemState = nil
		m.procMemLSMLoaded = false

		return fmt.Errorf("start proc_mem reader: %w", err)
	}

	m.procMemStop = stop
	m.logger.Info("proc_mem LSM loaded")

	return nil
}

// StopProcMem shuts down the /proc/*/mem read detection LSM.
func (m *Manager) StopProcMem() {
	if !m.procMemLSMLoaded {
		return
	}

	if m.procMemStop != nil {
		m.procMemStop()
	}

	if lsm, ok := m.procMemState.(*procMemLSMImpl); ok {
		lsm.Close()
	}

	m.procMemState = nil
	m.procMemLSMLoaded = false
	m.logger.Info("proc_mem LSM stopped")
}

// ProcMemLSMLoaded returns whether the proc_mem LSM program is active.
func (m *Manager) ProcMemLSMLoaded() bool {
	return m.procMemLSMLoaded
}

// AttachProcMem populates proc_mem BPF maps for a container.
// Non-fatal: logs warnings on failure (egress enforcement continues).
func (m *Manager) AttachProcMem(containerID, cgroupPath string, allowProcRead, observeOnly bool) {
	if !m.procMemLSMLoaded {
		return
	}

	lsm, ok := m.procMemState.(*procMemLSMImpl)
	if !ok {
		return
	}

	cgID, err := cgroupID(cgroupPath)
	if err != nil {
		m.logger.Warn("proc_mem: failed to get cgroup id", "container", truncID(containerID), "error", err)

		return
	}

	if err := populateProcMemMaps(lsm.objs, cgID, allowProcRead, observeOnly); err != nil {
		m.logger.Warn("proc_mem: failed to populate maps", "container", truncID(containerID), "error", err)

		return
	}

	m.mu.Lock()
	m.procMemContainers[containerID] = &procMemContainerState{CgroupID: cgID, ObserveOnly: observeOnly}
	m.procMemCgroupMap[cgID] = containerID
	m.mu.Unlock()

	m.logger.Info("proc_mem maps populated",
		"container", truncID(containerID),
		"cgroup_id", cgID,
		"allow_proc_read", allowProcRead,
		"observe_only", observeOnly,
	)
}

// DetachProcMem removes a container's proc_mem entries from BPF maps.
func (m *Manager) DetachProcMem(containerID string) {
	if !m.procMemLSMLoaded {
		return
	}

	lsm, ok := m.procMemState.(*procMemLSMImpl)
	if !ok {
		return
	}

	m.mu.Lock()
	state, exists := m.procMemContainers[containerID]
	if exists {
		delete(m.procMemContainers, containerID)
		delete(m.procMemCgroupMap, state.CgroupID)
	}
	m.mu.Unlock()

	if !exists {
		return
	}

	removeProcMemMaps(lsm.objs, state.CgroupID)
	m.logger.Debug("proc_mem maps cleaned", "container", truncID(containerID))
}

// handleProcMemBPFEvent is called by the ring buffer reader for each event.
func (m *Manager) handleProcMemBPFEvent(evt procMemEventBPF) {
	m.mu.Lock()
	containerID := m.procMemCgroupMap[evt.CgroupID]
	observeOnly := false
	if state := m.procMemContainers[containerID]; state != nil {
		observeOnly = state.ObserveOnly
	}
	m.mu.Unlock()

	// BPF stamps evt.TimestampNs with bpf_ktime_get_ns() (CLOCK_MONOTONIC);
	// convert to wall-clock epoch ns here so downstream last_seen isn't ~1970
	// and the server doesn't TTL-purge the row. See clock.go.
	nowWallNs := time.Now().UnixNano()
	nowMonoNs := nowMonotonicNs()

	event := ProcMemEvent{
		ContainerID: containerID,
		CgroupID:    evt.CgroupID,
		PID:         evt.PID,
		Comm:        nullTerminated(evt.Comm[:]),
		Path:        nullTerminated(evt.Path[:]),
		TimestampNs: monotonicToWallNs(int64(evt.TimestampNs), nowMonoNs, nowWallNs), //nolint:gosec // monotonic ns fits int64
		ObserveOnly: observeOnly,
	}

	m.logger.Warn("proc_mem read detected",
		"container", containerID,
		"pid", evt.PID,
		"comm", event.Comm,
		"path", event.Path,
	)

	if m.OnProcMemEvent != nil {
		m.OnProcMemEvent(event)
	}
}
