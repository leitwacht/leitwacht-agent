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

// watchClasses is the class assignment for every BPF watched_* map key,
// computed in userspace so the precedence rules are unit-testable
// without loading BPF.
type watchClasses struct {
	suffixes  map[[64]byte]uint8
	filenames map[[64]byte]uint8
	pairs     map[[96]byte]uint8
	dirs      map[[96]byte]uint8
}

// buildWatchClasses applies the precedence rules: exclude beats
// report-only beats watched for a suffix listed in several classes. On
// a shared (parent, name) pair or directory key derived from different
// suffixes, the watched class is never downgraded by report-only.
// Report-only files register their parent directory as class 2, so
// moving the directory is reported (and allowed), not invisible.
func buildWatchClasses(watchedPaths, reportOnlyPaths, excludedPaths []string) watchClasses {
	wc := watchClasses{
		suffixes:  map[[64]byte]uint8{},
		filenames: map[[64]byte]uint8{},
		pairs:     map[[96]byte]uint8{},
		dirs:      map[[96]byte]uint8{},
	}

	excluded := make(map[string]struct{}, len(excludedPaths))
	for _, p := range excludedPaths {
		excluded[p] = struct{}{}
	}

	reportOnly := make(map[string]struct{}, len(reportOnlyPaths))
	for _, p := range reportOnlyPaths {
		reportOnly[p] = struct{}{}
	}

	for _, suffix := range watchedPaths {
		_, ex := excluded[suffix]
		_, ro := reportOnly[suffix]

		if !ex && !ro {
			wc.add(suffix, credwatchClassWatched)
		}
	}

	for _, suffix := range reportOnlyPaths {
		if _, ex := excluded[suffix]; !ex {
			wc.add(suffix, credwatchClassReportOnly)
		}
	}

	return wc
}

// setClass stores class under key unless it would downgrade a watched
// entry already there.
func setClass[K comparable](m map[K]uint8, key K, class uint8) {
	if class == credwatchClassReportOnly && m[key] == credwatchClassWatched {
		return
	}

	m[key] = class
}

func (wc *watchClasses) add(suffix string, class uint8) {
	var suffixKey [64]byte
	copy(suffixKey[:], suffix)
	wc.suffixes[suffixKey] = class

	filename := path.Base(suffix)
	if filename == "." || filename == "/" {
		return
	}

	// watched_filenames is a presence flag; the class lives elsewhere.
	var fnameKey [64]byte
	copy(fnameKey[:], filename)
	wc.filenames[fnameKey] = 1

	// struct pair_key { char parent[32]; char name[64]; }: strings are
	// truncated to leave room for the NUL, matching the BPF side.
	grandparent, parent, name := splitSuffix(suffix)

	var pairKey [96]byte
	copy(pairKey[:31], parent)
	copy(pairKey[32:95], name)
	setClass(wc.pairs, pairKey, class)

	// (grandparent, directory) of the file. Generic directory names are
	// only registered when a grandparent distinguishes them.
	_, generic := genericDirNames[parent]
	if parent == "" || (generic && grandparent == "") {
		return
	}

	var dirKey [96]byte
	copy(dirKey[:31], grandparent)
	copy(dirKey[32:95], parent)
	setClass(wc.dirs, dirKey, class)
}

// populateWatchedPathMaps writes buildWatchClasses' result into the
// watched_filenames, watched_suffixes, watched_pairs and watched_dirs
// BPF maps. Excluded suffixes are never inserted, so no hook (open,
// rename, link) acts on them.
// Called once at StartCredwatch time (global, not per-container).
func populateWatchedPathMaps(objs *credwatchObjects, watchedPaths, reportOnlyPaths, excludedPaths []string) error {
	wc := buildWatchClasses(watchedPaths, reportOnlyPaths, excludedPaths)

	for k, v := range wc.suffixes {
		if err := objs.WatchedSuffixes.Put(k[:], v); err != nil {
			return fmt.Errorf("put watched_suffixes: %w", err)
		}
	}

	for k, v := range wc.filenames {
		if err := objs.WatchedFilenames.Put(k[:], v); err != nil {
			return fmt.Errorf("put watched_filenames: %w", err)
		}
	}

	for k, v := range wc.pairs {
		if err := objs.WatchedPairs.Put(k[:], v); err != nil {
			return fmt.Errorf("put watched_pairs: %w", err)
		}
	}

	for k, v := range wc.dirs {
		if err := objs.WatchedDirs.Put(k[:], v); err != nil {
			return fmt.Errorf("put watched_dirs: %w", err)
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
	if err := populateWatchedPathMaps(objs, m.credwatchCfg.WatchedPaths, m.credwatchCfg.ReportOnlyPaths, m.credwatchCfg.ExcludedPaths); err != nil {
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
		"report_only_suffixes", len(m.credwatchCfg.ReportOnlyPaths),
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
		Reason:      credwatchReason(evt.Kind),
		ObserveOnly: observeOnly,
		ReportOnly:  credwatchKindReportOnlyFlag(evt.Kind),
	}
	// Defence in depth: a consumer that only knows ObserveOnly (and
	// kills otherwise) must not kill on a report-only event. Consumers
	// that know ReportOnly check it first to tell the two apart.
	if event.ReportOnly {
		event.ObserveOnly = true
	}

	m.logger.Warn("credential file access detected",
		"container", containerID,
		"pid", evt.PID,
		"comm", event.Comm,
		"path", event.Path,
		"reason", event.Reason,
		"report_only", event.ReportOnly,
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
