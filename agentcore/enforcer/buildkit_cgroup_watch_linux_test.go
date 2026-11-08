//go:build linux

package enforcer

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInotifyDirWatcher_SignalsOnCreate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	w, err := newPlatformDirWatcher()
	if err != nil {
		t.Skipf("inotify unavailable: %v", err)
	}

	defer w.Close()

	if err := w.Watch([]string{dir, filepath.Join(dir, "missing")}); err != nil {
		t.Fatal(err)
	}

	if err := os.Mkdir(filepath.Join(dir, "x"), 0o750); err != nil {
		t.Fatal(err)
	}

	select {
	case <-w.Events():
	case <-time.After(3 * time.Second):
		t.Fatal("no event after mkdir")
	}

	if err := w.Watch(nil); err != nil { // drop all watches
		t.Fatal(err)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}
