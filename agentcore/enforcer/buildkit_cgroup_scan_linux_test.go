//go:build linux

package enforcer

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func runSourceOnce(t *testing.T, scan bool) []CgroupCreateEvent {
	t.Helper()

	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "existing"), 0o750); err != nil {
		t.Fatal(err)
	}

	src := NewInotifyCgroupSource([]string{dir})
	src.ScanExisting = scan

	creates := make(chan CgroupCreateEvent, 8)
	removes := make(chan CgroupRemoveEvent, 8)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() { done <- src.Run(ctx, creates, removes) }()

	// Live creates (retried until the watch is established) prove
	// the watch is up, ordering the initial scan ahead of them.
	deadline := time.After(3 * time.Second)
	tick := time.NewTicker(10 * time.Millisecond)

	defer tick.Stop()

	var got []CgroupCreateEvent

	for n, seen := 0, false; !seen; {
		select {
		case e := <-creates:
			got = append(got, e)
			seen = strings.HasPrefix(e.ContainerID, "live")
		case <-tick.C:
			n++

			if err := os.Mkdir(filepath.Join(dir, "live"+strconv.Itoa(n)), 0o750); err != nil {
				t.Fatal(err)
			}
		case <-deadline:
			t.Fatal("no live create event")
		}
	}

	cancel()
	<-done

	return got
}

func TestInotifyCgroupSource_ScanExisting(t *testing.T) {
	t.Parallel()

	has := func(evs []CgroupCreateEvent, id string) bool {
		for _, e := range evs {
			if e.ContainerID == id {
				return true
			}
		}

		return false
	}

	if got := runSourceOnce(t, true); !has(got, "existing") {
		t.Fatalf("ScanExisting=true missed pre-existing child: %v", got)
	}

	if got := runSourceOnce(t, false); has(got, "existing") {
		t.Fatalf("ScanExisting=false reported pre-existing child: %v", got)
	}
}
