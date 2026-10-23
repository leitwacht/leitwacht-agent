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

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// credwatchLSMImpl holds the loaded BPF LSM objects and link.
type credwatchLSMImpl struct {
	objs *credwatchObjects
	link link.Link
	// pathLinks are the optional path_rename / path_link hooks.
	pathLinks []link.Link
}

func (c *credwatchLSMImpl) Close() {
	for _, l := range c.pathLinks {
		l.Close() //nolint:errcheck,gosec // cleanup
	}

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
		// The path_rename / path_link programs need the kernel to expose
		// those LSM hooks (CONFIG_SECURITY_PATH). Without them, retry
		// with only the file_open program rather than losing credwatch.
		fallbackObjs, fallbackErr := loadCredwatchFileOpenOnly()
		if fallbackErr != nil {
			return nil, nil, fmt.Errorf("load credwatch bpf objects: %w", err)
		}

		slog.Warn("credwatch: full program set failed to load, running with file_open only (no rename/link protection)",
			"error", err)

		objs = *fallbackObjs
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

// loadCredwatchFileOpenOnly loads the credwatch collection without the
// optional path_rename / path_link programs.
func loadCredwatchFileOpenOnly() (*credwatchObjects, error) {
	spec, err := loadCredwatch()
	if err != nil {
		return nil, err
	}

	delete(spec.Programs, "credwatch_path_rename")
	delete(spec.Programs, "credwatch_path_link")

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, err
	}

	objs := &credwatchObjects{}
	objs.CredwatchFileOpen = coll.Programs["credwatch_file_open"]
	objs.CredwatchEvents = coll.Maps["credwatch_events"]
	objs.KnownContainers = coll.Maps["known_containers"]
	objs.PathBuf = coll.Maps["path_buf"]
	objs.WatchedFilenames = coll.Maps["watched_filenames"]
	objs.WatchedSuffixes = coll.Maps["watched_suffixes"]
	objs.ReserveFailures = coll.Maps["reserve_failures"]
	objs.WatchedPairs = coll.Maps["watched_pairs"]
	objs.WatchedDirs = coll.Maps["watched_dirs"]

	// Close everything in the collection that is not part of objs
	// (.rodata/.bss maps, variables) so its fds do not leak.
	keep := map[*ebpf.Map]bool{}
	for _, m := range []*ebpf.Map{
		objs.CredwatchEvents, objs.KnownContainers, objs.PathBuf, objs.WatchedFilenames,
		objs.WatchedSuffixes, objs.ReserveFailures, objs.WatchedPairs, objs.WatchedDirs,
	} {
		keep[m] = true
	}

	for _, m := range coll.Maps {
		if !keep[m] {
			m.Close() //nolint:errcheck,gosec // cleanup
		}
	}

	return objs, nil
}

// attachCredwatchPathHooks attaches the rename/hardlink hooks, which
// stop a watched credential file being moved or linked to a name the
// file_open prefilter does not watch. Non-fatal: a kernel without these
// hooks keeps the file_open protection.
func attachCredwatchPathHooks(objs *credwatchObjects, logger *slog.Logger) []link.Link {
	var links []link.Link

	for name, prog := range map[string]*ebpf.Program{
		"path_rename": objs.CredwatchPathRename,
		"path_link":   objs.CredwatchPathLink,
	} {
		if prog == nil {
			continue
		}

		l, err := link.AttachLSM(link.LSMOptions{Program: prog})
		if err != nil {
			logger.Warn("credwatch: path hook unavailable", "hook", name, "error", err)

			continue
		}

		links = append(links, l)
	}

	return links
}

// CredwatchReserveFailures returns the number of credwatch events lost
// because the ring buffer was full (summed across CPUs).
func (m *Manager) CredwatchReserveFailures() uint64 {
	lsm, ok := m.credwatchState.(*credwatchLSMImpl)
	if !ok || lsm.objs == nil {
		return 0
	}

	return readReserveFailures(lsm.objs.ReserveFailures)
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
		monitorReserveFailures(done, "credwatch", func() uint64 { return readReserveFailures(objs.ReserveFailures) }, logger, reserveFailureInterval)
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
			// Layout: cgroup_id(8) + pid(4) + comm(16) + path(128) + timestamp_ns(8) + kind(1) = 165
			if len(raw) < credwatchEventSize {
				logger.Warn("credwatch event too short", "len", len(raw))

				continue
			}

			evt := credwatchEventBPF{
				CgroupID:    binary.LittleEndian.Uint64(raw[0:8]),
				PID:         binary.LittleEndian.Uint32(raw[8:12]),
				TimestampNs: binary.LittleEndian.Uint64(raw[156:164]),
				Kind:        raw[164],
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

// genericDirNames are directory names too common to treat as "a
// credentials directory" on their own: a suffix whose directory has no
// distinguishing grandparent (e.g. "/secrets/vault_token") does not
// protect renames of that directory. With a grandparent the pair
// ("rancher", "k3s") is specific enough regardless of the name.
var genericDirNames = map[string]struct{}{
	".config": {}, "config": {}, "secrets": {}, "rancher": {}, "etc": {}, "home": {},
	"root": {}, "usr": {}, "var": {}, "lib": {}, "run": {}, "tmp": {}, "opt": {},
	".local": {}, "share": {}, ".cache": {}, "cache": {},
}

// splitSuffix returns the last three components of a watched suffix:
// the file name, its immediate parent directory and that directory's
// parent ("" if absent).
func splitSuffix(suffix string) (grandparent, parent, name string) {
	parts := strings.Split(strings.Trim(suffix, "/"), "/")
	name = parts[len(parts)-1]

	if len(parts) > 1 {
		parent = parts[len(parts)-2]
	}

	if len(parts) > 2 {
		grandparent = parts[len(parts)-3]
	}

	return grandparent, parent, name
}

// populateWatchedPathMaps populates the watched_filenames,
// watched_suffixes, watched_pairs and watched_dirs BPF maps from the
// configured WatchedPaths and ExcludedPaths. Excluded suffixes are
// skipped entirely, so no hook (open, rename, link) acts on them.
// Called once at StartCredwatch time (global, not per-container).
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

		// watched_pairs: struct pair_key { char parent[32]; char name[64]; }.
		// Strings are truncated to leave room for the NUL, matching what
		// the BPF side reads.
		grandparent, parent, name := splitSuffix(suffix)

		var pairKey [96]byte
		copy(pairKey[:31], parent)
		copy(pairKey[32:95], name)

		if err := objs.WatchedPairs.Put(pairKey[:], uint8(1)); err != nil {
			return fmt.Errorf("put watched_pairs %q: %w", suffix, err)
		}

		// watched_dirs: (grandparent, directory) of the file. Generic
		// directory names are only protected when a grandparent
		// distinguishes them.
		if _, generic := genericDirNames[parent]; parent != "" && (!generic || grandparent != "") {
			var dirKey [96]byte
			copy(dirKey[:31], grandparent)
			copy(dirKey[32:95], parent)

			if err := objs.WatchedDirs.Put(dirKey[:], uint8(1)); err != nil {
				return fmt.Errorf("put watched_dirs %q: %w", parent, err)
			}
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
	lsm.pathLinks = attachCredwatchPathHooks(objs, m.logger)
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

// AttachCredwatch populates credwatch BPF maps for a container.
// Non-fatal: logs warnings on failure (egress enforcement continues).
func (m *Manager) AttachCredwatch(containerID, cgroupPath string, allowCredWatch, observeOnly bool) {
	if !m.credwatchLSMLoaded {
		return
	}

	lsm, ok := m.credwatchState.(*credwatchLSMImpl)
	if !ok {
		return
	}

	cgID, err := cgroupID(cgroupPath)
	if err != nil {
		m.logger.Warn("credwatch: failed to get cgroup id", "container", containerID[:12], "error", err)

		return
	}

	if err := populateCredwatchMaps(lsm.objs, cgID, allowCredWatch, observeOnly); err != nil {
		m.logger.Warn("credwatch: failed to populate maps", "container", containerID[:12], "error", err)

		return
	}

	m.mu.Lock()
	m.credwatchContainers[containerID] = &credwatchContainerState{
		CgroupID:    cgID,
		ObserveOnly: observeOnly,
	}
	m.credwatchCgroupToContainer[cgID] = containerID
	m.mu.Unlock()

	m.logger.Info("credwatch maps populated",
		"container", containerID[:12],
		"cgroup_id", cgID,
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
		delete(m.credwatchCgroupToContainer, state.CgroupID)
	}
	m.mu.Unlock()

	if !exists {
		return
	}

	removeCredwatchMaps(lsm.objs, state.CgroupID)
	m.logger.Debug("credwatch maps cleaned", "container", containerID[:12])
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
		Reason:      credwatchReason(evt.Kind),
		ObserveOnly: observeOnly,
	}

	m.logger.Warn("credential file access detected",
		"container", containerID,
		"pid", evt.PID,
		"comm", event.Comm,
		"path", event.Path,
		"reason", event.Reason,
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
