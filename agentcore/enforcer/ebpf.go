//go:build linux

package enforcer

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

var (
	errNoCgroupV2     = errors.New("no cgroupv2 entry found")
	errCgroupBadID    = errors.New("cannot extract container ID from cgroup path")
	errCgroupNotFound = errors.New("cgroup not found for container")
)

// PackAllowKey packs an IP and port into the 6-byte allow_key format
// matching the eBPF struct: __u32 ip (network order) + __u16 port (network order).
func PackAllowKey(ip net.IP, port int) [6]byte {
	var key [6]byte

	ip4 := ip.To4()
	if ip4 == nil {
		return key
	}

	copy(key[0:4], ip4)
	binary.BigEndian.PutUint16(key[4:6], uint16(port)) //nolint:gosec // port range fits uint16

	return key
}

// NOTE: The actual eBPF program loading, map manipulation, and cgroup attachment
// requires the generated bpf2go code (ebpf_bpf.go). That is generated via:
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 ebpf egress.c -- -I/usr/include -I/usr/include/x86_64-linux-gnu -O2 -Wall -g
//
// The generated file provides:
//   - ebpfObjects: struct with all maps and programs
//   - loadEbpfObjects(): loads the compiled BPF bytecode

// getCgroupPath resolves the cgroupv2 path for a container process.
//
// When the agent runs inside a K8S pod with its own cgroup namespace,
// /proc/<pid>/cgroup returns a path relative to the agent's cgroup root
// (e.g., "/../../../besteffort/pod<uid>/<id>"). Simply joining with
// /sys/fs/cgroup doesn't work because the ".." components escape the mount.
//
// Strategy: extract the container ID from /proc/<pid>/cgroup (last path
// segment) and find it under /sys/fs/cgroup/kubepods/ by walking the tree.
// Falls back to direct path construction for non-K8S (Docker bare metal).
func getCgroupPath(pid int) (string, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", fmt.Errorf("open cgroup file: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only file, close error is not actionable

	var cgroupRelPath string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// cgroupv2 unified: "0::/path"
		if after, ok := strings.CutPrefix(line, "0::"); ok {
			if after == "" {
				after = "/"
			}

			cgroupRelPath = after

			break
		}
	}

	scanErr := scanner.Err()
	if scanErr != nil {
		return "", fmt.Errorf("read cgroup file: %w", scanErr)
	}

	if cgroupRelPath == "" {
		return "", fmt.Errorf("%w: /proc/%d/cgroup", errNoCgroupV2, pid)
	}

	// If the path is absolute and doesn't start with "/..", it's directly usable
	// (Docker bare metal where agent runs on host, not in a cgroup namespace).
	if !strings.Contains(cgroupRelPath, "..") {
		return "/sys/fs/cgroup" + cgroupRelPath, nil
	}

	// K8S: the path is relative with ".." components. Extract the container ID
	// (last path segment) and find it under /sys/fs/cgroup/kubepods/.
	containerID := filepath.Base(cgroupRelPath)
	if containerID == "" || containerID == "." || containerID == "/" {
		return "", fmt.Errorf("%w: %q", errCgroupBadID, cgroupRelPath)
	}

	return findCgroupByID("/sys/fs/cgroup/kubepods", containerID)
}

// findCgroupByID searches the cgroup tree for a directory matching the container ID.
func findCgroupByID(root, containerID string) (string, error) {
	var result string

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return filepath.SkipDir
		}

		if d.IsDir() && d.Name() == containerID {
			result = path

			return filepath.SkipAll
		}

		return nil
	})
	if err != nil {
		return "", fmt.Errorf("walk cgroup tree: %w", err)
	}

	if result == "" {
		return "", fmt.Errorf("%w: %s under %s", errCgroupNotFound, containerID[:12], root)
	}

	return result, nil
}

// dropEvent matches the eBPF struct drop_event (packed, 36 bytes on
// the wire). dst_ip(4) + dst_port(2) + protocol(1) + cgroup_id(8) +
// reason(1) + pid(4) + comm(16) = 36.
//
// NOTE: Documentation only. Do NOT `binary.Read` this struct — Go's
// natural u64 alignment would place CgroupID at offset 8 (with
// implicit padding), producing a ~40-byte in-memory layout that
// disagrees with the packed wire format. The ringbuf decoder in
// platform_linux.go reads fields individually at explicit byte
// offsets from record.RawSample, which is the contract that matches
// the kernel.
type dropEvent struct {
	DstIP      [4]byte
	DstPort    [2]byte
	Protocol   uint8
	CgroupID   uint64
	Reason     uint8
	PID        uint32
	Comm       [16]byte
	BinaryPath [256]byte
}

// Drop reason codes — must match DROP_REASON_* in egress.c.
const (
	dropReasonPolicy   uint8 = 1
	dropReasonSinkhole uint8 = 2
)
