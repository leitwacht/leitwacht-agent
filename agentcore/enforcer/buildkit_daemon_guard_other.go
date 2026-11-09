//go:build !linux

package enforcer

type fileID struct{ dev, ino uint64 }

func statID(string) (fileID, bool) { return fileID{}, false }

func statInRoot(string, string) (fileID, bool) { return fileID{}, false }

func walkInRoot(string, string) (fileID, bool) { return fileID{}, false }
