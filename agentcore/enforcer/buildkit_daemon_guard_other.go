//go:build !linux

package enforcer

import "sync/atomic"

type fileID struct{ dev, ino uint64 }

func statID(string) (fileID, bool) { return fileID{}, false }

func statInRoot(string, string) (fileID, bool) { return fileID{}, false }

var openat2Unavailable atomic.Bool
