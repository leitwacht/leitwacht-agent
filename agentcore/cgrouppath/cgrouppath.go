// Package cgrouppath converts the cgroup path a container runtime reports
// (an OCI spec's linux.cgroupsPath) into a filesystem path under the cgroup
// v2 mount.
//
// Runtimes report the value in one of two notations depending on the
// kubelet / runtime cgroup driver:
//
//   - cgroupfs: an absolute path ("/kubepods/burstable/pod<uid>/<id>").
//     Relative paths are rejected: they are relative to the runtime's own
//     cgroup, which is not known here.
//   - systemd: "<slice>:<prefix>:<name>", for example
//     "kubepods-burstable-pod<uid>.slice:cri-containerd:<id>". The slice is
//     expanded into its nested parents by systemd's naming rule
//     (a-b-c.slice lives at a.slice/a-b.slice/a-b-c.slice) and the unit is
//     "<prefix>-<name>.scope".
package cgrouppath

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// DefaultMount is the usual cgroup v2 mount point.
const DefaultMount = "/sys/fs/cgroup"

// ErrInvalidPath is wrapped by every rejection from Resolve.
var ErrInvalidPath = errors.New("invalid cgroup path")

// Resolve returns the filesystem path for a runtime-reported cgroupsPath
// under mountRoot (DefaultMount when empty). It never uses string
// concatenation and rejects ".." components and components that would
// escape the mount.
func Resolve(mountRoot, cgroupsPath string) (string, error) {
	if mountRoot == "" {
		mountRoot = DefaultMount
	}

	if cgroupsPath == "" {
		return "", fmt.Errorf("%w: empty", ErrInvalidPath)
	}

	if strings.ContainsRune(cgroupsPath, 0) {
		return "", fmt.Errorf("%w: NUL byte", ErrInvalidPath)
	}

	if strings.Contains(cgroupsPath, ":") {
		return resolveSystemd(mountRoot, cgroupsPath)
	}

	// Relative cgroupfs paths are relative to the runtime's own cgroup, not
	// the mount root, so they cannot be resolved here.
	if !strings.HasPrefix(cgroupsPath, "/") {
		return "", fmt.Errorf("%w: relative path %q", ErrInvalidPath, cgroupsPath)
	}

	for _, part := range strings.Split(cgroupsPath, "/") {
		if part == ".." {
			return "", fmt.Errorf("%w: %q contains \"..\"", ErrInvalidPath, cgroupsPath)
		}
	}

	clean := filepath.Clean("/" + cgroupsPath)
	if clean == "/" {
		return "", fmt.Errorf("%w: %q names the cgroup root", ErrInvalidPath, cgroupsPath)
	}

	return filepath.Join(mountRoot, clean), nil
}

func resolveSystemd(mountRoot, cgroupsPath string) (string, error) {
	parts := strings.Split(cgroupsPath, ":")
	if len(parts) != 3 {
		return "", fmt.Errorf("%w: systemd notation needs slice:prefix:name, got %q", ErrInvalidPath, cgroupsPath)
	}

	slice, prefix, name := parts[0], parts[1], parts[2]
	if name == "" {
		return "", fmt.Errorf("%w: empty unit name in %q", ErrInvalidPath, cgroupsPath)
	}

	if prefix == "" {
		return "", fmt.Errorf("%w: empty prefix in %q", ErrInvalidPath, cgroupsPath)
	}

	if slice == "" {
		slice = "system.slice"
	}

	for _, s := range []string{slice, prefix, name} {
		if strings.ContainsAny(s, "/\x00") || s == ".." || strings.Contains(s, "..") {
			return "", fmt.Errorf("%w: unsafe component in %q", ErrInvalidPath, cgroupsPath)
		}
	}

	dirs, err := ExpandSlice(slice)
	if err != nil {
		return "", err
	}

	unit := name
	if !strings.HasSuffix(name, ".slice") {
		unit = prefix + "-" + name + ".scope"
	}

	elems := append([]string{mountRoot}, dirs...)
	elems = append(elems, unit)

	return filepath.Join(elems...), nil
}

// ExpandSlice returns the nested directory names for a systemd slice unit:
// "a-b-c.slice" -> ["a.slice", "a-b.slice", "a-b-c.slice"]. The root slice
// "-.slice" yields no directories.
func ExpandSlice(slice string) ([]string, error) {
	if slice == "-.slice" {
		return nil, nil
	}

	base, ok := strings.CutSuffix(slice, ".slice")
	if !ok || base == "" {
		return nil, fmt.Errorf("%w: %q is not a slice unit", ErrInvalidPath, slice)
	}

	segs := strings.Split(base, "-")
	out := make([]string, 0, len(segs))

	for i, s := range segs {
		if s == "" {
			return nil, fmt.Errorf("%w: empty segment in slice %q", ErrInvalidPath, slice)
		}

		out = append(out, strings.Join(segs[:i+1], "-")+".slice")
	}

	return out, nil
}
