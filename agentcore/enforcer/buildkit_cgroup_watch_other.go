//go:build !linux

package enforcer

import "errors"

// newPlatformDirWatcher is unavailable off Linux; the resolver falls
// back to polling.
func newPlatformDirWatcher() (CgroupDirWatcher, error) {
	return nil, errors.New("directory watching unsupported on this platform")
}
