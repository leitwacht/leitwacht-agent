package enforcer

import (
	"errors"
	"path/filepath"
	"regexp"
)

// ErrNotPodShape is returned by PodCgroupFromContainer when the input path is
// not a recognised Kubernetes pod cgroup shape. Docker, Podman, plain
// containerd (no CRI), and unfamiliar layouts all surface this error and
// route the caller to the per-container attach fallback.
var ErrNotPodShape = errors.New("cgroup path is not a Kubernetes pod shape")

// podUIDPattern matches the pod-UID UUID segment as a SUFFIX of a cgroup
// basename. Accepts both dashes (cgroupfs driver) and underscores (systemd
// driver — kubelet rewrites dashes to underscores in slice unit names).
// The trailing `(?:\.slice)?$` anchors at the end so the basename must
// terminate in `pod<UID>` or `pod<UID>.slice` — this rejects QoS slices
// (`kubepods-burstable.slice`) and container scopes
// (`cri-containerd-<id>.scope`) while still matching:
//
//	pod<UID>                                 (cgroupfs leaf)
//	kubepods-pod<UID>.slice                  (systemd, guaranteed)
//	kubepods-burstable-pod<UID>.slice        (systemd, burstable/besteffort)
//
// We deliberately do not require a literal "kubepods" prefix: under a
// cgroup namespace (e.g. Talos), the kernel rewrites that prefix to
// dot-dot segments but the pod<UID> element is invariant.
var podUIDPattern = regexp.MustCompile(
	`pod[0-9a-fA-F]{8}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{12}(?:\.slice)?$`,
)

// PodCgroupFromContainer returns the pod cgroup path for a container cgroup.
//
// Recognised shapes (the parent of the container scope is the pod slice):
//
//	systemd, burstable/besteffort:
//	  …/kubepods.slice/kubepods-<qos>.slice/kubepods-<qos>-pod<UID>.slice/<scope>
//	systemd, guaranteed:
//	  …/kubepods.slice/kubepods-pod<UID>.slice/<scope>
//	cgroupfs:
//	  …/kubepods/<qos>/pod<UID>/<container-id>
//
// Inputs are expected to be absolute filesystem paths under the cgroup
// mount, as produced by cgrouppath.Resolve from the runtime's cgroupsPath
// (which handles both cgroupfs and systemd "slice:prefix:name" notation).
// Cgroup-namespaced relative forms with leading `..` segments do not reach
// this function — they would only appear when reading `/proc/<pid>/cgroup`
// from the agent's own namespace, which is not how the enforcer obtains
// container cgroup paths.
//
// Algorithm: take the parent directory of the input. If its base name
// matches `pod<UUID>` (with optional `.slice` suffix for systemd), return
// the parent. Otherwise return ErrNotPodShape. The pod-UID anchor is the
// discriminator — Docker (`/docker/<id>`), Podman, and plain ctr containers
// have no such parent and naturally fall through.
func PodCgroupFromContainer(containerCgroup string) (string, error) {
	if containerCgroup == "" {
		return "", ErrNotPodShape
	}

	parent := filepath.Dir(containerCgroup)
	if parent == "." || parent == "/" || parent == containerCgroup {
		return "", ErrNotPodShape
	}

	base := filepath.Base(parent)
	if !podUIDPattern.MatchString(base) {
		return "", ErrNotPodShape
	}

	return parent, nil
}
