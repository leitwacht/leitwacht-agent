//go:build linux

package enforcer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const honeypotEventSize = 48

// honeypotEventBPF matches the BPF struct honeypot_event (packed, 48 bytes).
type honeypotEventBPF struct {
	CgroupID    uint64
	PID         uint32
	Dev         uint32
	Ino         uint64
	Comm        [16]byte
	TimestampNs uint64
}

// nullTerminated returns a string from a null-terminated byte slice.
func nullTerminated(buf []byte) string {
	for i, c := range buf {
		if c == 0 {
			return string(buf[:i])
		}
	}

	return string(buf)
}

// honeypotLSMImpl holds the loaded BPF LSM objects and link.
type honeypotLSMImpl struct {
	objs *honeypotObjects
	link link.Link
}

func (h *honeypotLSMImpl) Close() {
	if h.link != nil {
		h.link.Close() //nolint:errcheck,gosec // cleanup
	}

	if h.objs != nil {
		h.objs.Close() //nolint:errcheck,gosec // cleanup
	}
}

// loadHoneypotLSM loads the BPF LSM program and attaches it.
// Returns the loaded objects and LSM link, or an error if BPF LSM is unavailable.
func loadHoneypotLSM() (*honeypotObjects, link.Link, error) {
	spec, err := loadHoneypot()
	if err != nil {
		return nil, nil, fmt.Errorf("load honeypot spec: %w", err)
	}

	verifyErr := verifyStructSize(spec.Types, "honeypot_event", honeypotEventSize)
	if verifyErr != nil {
		return nil, nil, fmt.Errorf("honeypot bytecode verify: %w", verifyErr)
	}

	var objs honeypotObjects

	err = spec.LoadAndAssign(&objs, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("load honeypot bpf objects: %w", err)
	}

	lsmLink, err := link.AttachLSM(link.LSMOptions{
		Program: objs.HoneypotFileOpen,
	})
	if err != nil {
		objs.Close() //nolint:errcheck,gosec // cleanup

		return nil, nil, fmt.Errorf("attach lsm: %w", err)
	}

	return &objs, lsmLink, nil
}

// startHoneypotReader starts the ring buffer reader goroutine.
// It calls onEvent for each decoded event. Returns a stop function.
func startHoneypotReader(objs *honeypotObjects, logger *slog.Logger, onEvent func(honeypotEventBPF)) (func(), error) {
	reader, err := ringbuf.NewReader(objs.HoneypotEvents)
	if err != nil {
		return nil, fmt.Errorf("open honeypot ringbuf: %w", err)
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

				logger.Debug("honeypot ringbuf read error", "error", err)

				continue
			}

			raw := record.RawSample
			logger.Debug("honeypot ringbuf event", "raw_len", len(raw))

			// Parse the packed struct directly from raw bytes.
			// Layout: cgroup_id(8) + pid(4) + dev(4) + ino(8) + comm(16) + timestamp_ns(8) = 48
			if len(raw) < honeypotEventSize {
				logger.Warn("honeypot event too short", "len", len(raw))

				continue
			}

			evt := honeypotEventBPF{
				CgroupID:    binary.LittleEndian.Uint64(raw[0:8]),
				PID:         binary.LittleEndian.Uint32(raw[8:12]),
				Dev:         binary.LittleEndian.Uint32(raw[12:16]),
				Ino:         binary.LittleEndian.Uint64(raw[16:24]),
				TimestampNs: binary.LittleEndian.Uint64(raw[40:48]),
			}
			copy(evt.Comm[:], raw[24:40])

			onEvent(evt)
		}
	})

	stop := func() {
		close(done)
		wg.Wait()
	}

	return stop, nil
}

// statFile returns the device number and inode of a file.
func statFile(path string) (uint32, uint64, error) {
	var st syscall.Stat_t

	err := syscall.Stat(path, &st)
	if err != nil {
		return 0, 0, fmt.Errorf("stat %s: %w", path, err)
	}

	return uint32(st.Dev), st.Ino, nil //nolint:gosec // dev_t fits uint32
}

// cgroupID returns the inode number of a cgroup directory,
// which matches what bpf_get_current_cgroup_id() returns.
func cgroupID(cgroupPath string) (uint64, error) {
	var st syscall.Stat_t

	err := syscall.Stat(cgroupPath, &st)
	if err != nil {
		return 0, fmt.Errorf("stat cgroup %s: %w", cgroupPath, err)
	}

	return st.Ino, nil
}

// populateHoneypotMaps adds a container's cgroup ID to known_containers
// and stats all honeypot files to populate honeypot_inodes.
func populateHoneypotMaps(objs *honeypotObjects, cgID uint64, honeypotDir string) ([]honeypotInodeEntry, error) {
	// Add cgroup to known_containers
	err := objs.KnownContainers.Put(cgID, uint8(1))
	if err != nil {
		return nil, fmt.Errorf("put known_containers: %w", err)
	}

	entries, err := os.ReadDir(honeypotDir)
	if err != nil {
		return nil, fmt.Errorf("read honeypot dir %s: %w", honeypotDir, err)
	}

	var inodes []honeypotInodeEntry

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		path := filepath.Join(honeypotDir, entry.Name())

		dev, ino, err := statFile(path)
		if err != nil {
			continue
		}

		key := honeypotKey{Dev: dev, Ino: ino}

		putErr := objs.HoneypotInodes.Put(key, uint8(1))
		if putErr != nil {
			continue
		}

		inodes = append(inodes, honeypotInodeEntry{
			Key:  key,
			Path: entry.Name(),
		})
	}

	return inodes, nil
}

// removeHoneypotMaps removes a container's entries from the BPF maps.
func removeHoneypotMaps(objs *honeypotObjects, state *honeypotContainerState) {
	_ = objs.KnownContainers.Delete(state.CgroupID)
	for _, entry := range state.Inodes {
		_ = objs.HoneypotInodes.Delete(entry.Key)
	}
}

// StartHoneypot loads BPF programs: the honeypot LSM and the DNS PID
// tracker kprobe. Both are optional — failures log warnings but don't
// block enforcement.
func (m *Manager) StartHoneypot() error {
	// DNS PID tracker (kprobe on udp_sendmsg for process attribution).
	tracker, err := NewDNSPIDTracker(m.logger)
	if err != nil {
		m.logger.Warn("dns pid tracker unavailable, process attribution disabled", "error", err)
	} else {
		m.dnsPIDTracker = tracker
		m.logger.Info("dns pid tracker loaded")
	}

	// Honeypot LSM.
	if !m.honeypotCfg.Enabled {
		m.logger.Info("honeypot enforcement disabled")

		return nil
	}

	objs, lsmLink, err := loadHoneypotLSM()
	if err != nil {
		m.logger.Warn("honeypot LSM unavailable, skipping", "error", err)

		return nil
	}

	lsm := &honeypotLSMImpl{objs: objs, link: lsmLink}
	m.honeypotState = lsm

	stop, err := startHoneypotReader(objs, m.logger, m.handleHoneypotBPFEvent)
	if err != nil {
		lsm.Close()

		m.honeypotState = nil

		return fmt.Errorf("start honeypot reader: %w", err)
	}

	m.honeypotStop = stop
	m.lsmLoaded = true
	m.logger.Info("honeypot LSM loaded", "honeypot_dir", m.honeypotCfg.Dir)

	return nil
}

// StopHoneypot shuts down honeypot-related BPF programs (LSM + DNS PID
// tracker). Per-container enforcers and netns contexts are torn down
// separately via Detach / DetachAll.
func (m *Manager) StopHoneypot() {
	if m.dnsPIDTracker != nil {
		m.dnsPIDTracker.Close()
		m.dnsPIDTracker = nil
		m.logger.Info("dns pid tracker stopped")
	}

	if !m.lsmLoaded {
		return
	}

	if m.honeypotStop != nil {
		m.honeypotStop()
	}

	if lsm, ok := m.honeypotState.(*honeypotLSMImpl); ok {
		lsm.Close()
	}

	m.honeypotState = nil
	m.lsmLoaded = false
	m.logger.Info("honeypot LSM stopped")
}

// LSMLoaded returns whether the honeypot LSM program is active.
func (m *Manager) LSMLoaded() bool {
	return m.lsmLoaded
}

// AttachHoneypot populates honeypot BPF maps for a container.
// Non-fatal: logs warnings on failure (egress enforcement continues).
func (m *Manager) AttachHoneypot(containerID, cgroupPath string) {
	if !m.lsmLoaded {
		return
	}

	lsm, ok := m.honeypotState.(*honeypotLSMImpl)
	if !ok {
		return
	}

	cgID, err := cgroupID(cgroupPath)
	if err != nil {
		m.logger.Warn("honeypot: failed to get cgroup id", "container", containerID[:12], "error", err)

		return
	}

	inodes, err := populateHoneypotMaps(lsm.objs, cgID, m.honeypotCfg.Dir)
	if err != nil {
		m.logger.Warn("honeypot: failed to populate maps", "container", containerID[:12], "error", err)

		return
	}

	m.mu.Lock()
	state := &honeypotContainerState{
		CgroupID: cgID,
		Inodes:   inodes,
	}
	m.containers[containerID] = state
	m.cgroupToContainer[cgID] = containerID
	m.mu.Unlock()

	m.logger.Info("honeypot maps populated",
		"container", containerID[:12],
		"cgroup_id", cgID,
		"inodes", len(inodes),
	)
}

// DetachHoneypot removes a container's honeypot entries from BPF maps.
func (m *Manager) DetachHoneypot(containerID string) {
	if !m.lsmLoaded {
		return
	}

	lsm, ok := m.honeypotState.(*honeypotLSMImpl)
	if !ok {
		return
	}

	m.mu.Lock()

	state, exists := m.containers[containerID]
	if exists {
		delete(m.containers, containerID)
		delete(m.cgroupToContainer, state.CgroupID)
	}
	m.mu.Unlock()

	if !exists {
		return
	}

	removeHoneypotMaps(lsm.objs, state)
	m.logger.Debug("honeypot maps cleaned", "container", containerID[:12])
}

// handleHoneypotBPFEvent is called by the ring buffer reader for each event.
func (m *Manager) handleHoneypotBPFEvent(evt honeypotEventBPF) {
	m.mu.Lock()
	containerID := m.cgroupToContainer[evt.CgroupID]

	// Look up the honeypot path from the inode
	var honeypotPath string

	if state, ok := m.containers[containerID]; ok {
		for _, entry := range state.Inodes {
			if entry.Key.Dev == evt.Dev && entry.Key.Ino == evt.Ino {
				honeypotPath = entry.Path

				break
			}
		}
	}
	m.mu.Unlock()

	event := HoneypotEvent{
		ContainerID:  containerID,
		CgroupID:     evt.CgroupID,
		PID:          evt.PID,
		Dev:          evt.Dev,
		Ino:          evt.Ino,
		Comm:         nullTerminated(evt.Comm[:]),
		HoneypotPath: honeypotPath,
		TimestampNs:  int64(evt.TimestampNs), //nolint:gosec // ns timestamp fits int64
	}

	m.logger.Warn("honeypot triggered",
		"container", containerID,
		"pid", evt.PID,
		"comm", event.Comm,
		"path", honeypotPath,
	)

	if m.OnHoneypotEvent != nil {
		m.OnHoneypotEvent(event)
	}
}
