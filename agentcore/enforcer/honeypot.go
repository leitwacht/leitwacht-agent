package enforcer

import "time"

// HoneypotEvent is the Go-side representation of a BPF honeypot detection event.
type HoneypotEvent struct {
	ContainerID  string
	CgroupID     uint64
	PID          uint32
	Dev          uint32
	Ino          uint64
	Comm         string
	HoneypotPath string
	TimestampNs  int64
}

// HoneypotConfig holds honeypot enforcement configuration.
type HoneypotConfig struct {
	Enabled bool
	Dir     string // directory containing honeypot decoy files
}

// honeypotKey matches the BPF struct honeypot_key (packed).
type honeypotKey struct {
	Dev uint32
	Ino uint64
}

// honeypotInodeEntry tracks a honeypot inode and its logical path for a container.
type honeypotInodeEntry struct {
	Key  honeypotKey
	Path string // logical path for reporting (e.g., "~/.aws/credentials")
}

// honeypotContainerState tracks honeypot inode entries and cgroup ID per container.
type honeypotContainerState struct {
	CgroupID uint64
	Inodes   []honeypotInodeEntry
	AddedAt  time.Time
}
