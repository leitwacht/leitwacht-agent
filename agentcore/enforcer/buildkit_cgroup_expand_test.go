package enforcer

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestExpandCgroupGlobs(t *testing.T) {
	// Stage a temp cgroup-shaped tree:
	//
	//   <root>/system.slice/docker-AAA.scope/buildkit/
	//   <root>/system.slice/docker-BBB.scope/buildkit/
	//   <root>/system.slice/docker-CCC.scope/   (no buildkit subdir)
	//   <root>/standalone/buildkit/
	root := t.TempDir()

	mustMkdir := func(rel string) string {
		t.Helper()

		p := filepath.Join(root, rel)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", p, err)
		}

		return p
	}

	wantA := mustMkdir("system.slice/docker-AAA.scope/buildkit")
	wantB := mustMkdir("system.slice/docker-BBB.scope/buildkit")
	mustMkdir("system.slice/docker-CCC.scope") // no buildkit child
	wantStandalone := mustMkdir("standalone/buildkit")

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	cases := []struct {
		name     string
		patterns []string
		want     []string
	}{
		{
			name:     "single plain path",
			patterns: []string{wantStandalone},
			want:     []string{wantStandalone},
		},
		{
			name:     "glob expands across siblings",
			patterns: []string{filepath.Join(root, "system.slice/docker-*.scope/buildkit")},
			want:     []string{wantA, wantB},
		},
		{
			name: "mix of plain + glob is deduplicated",
			patterns: []string{
				filepath.Join(root, "system.slice/docker-*.scope/buildkit"),
				wantA,
				wantStandalone,
			},
			want: []string{wantA, wantB, wantStandalone},
		},
		{
			name:     "glob matches zero paths drops silently",
			patterns: []string{filepath.Join(root, "no-such/*/buildkit")},
			want:     []string{},
		},
		{
			name:     "non-existent plain path drops",
			patterns: []string{filepath.Join(root, "missing")},
			want:     []string{},
		},
		{
			name:     "malformed glob drops",
			patterns: []string{filepath.Join(root, "[")},
			want:     []string{},
		},
		{
			name:     "empty input returns nil",
			patterns: nil,
			want:     []string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ExpandCgroupGlobs(tc.patterns, log)
			sort.Strings(got)

			want := append([]string{}, tc.want...)
			sort.Strings(want)

			if len(got) != len(want) {
				t.Fatalf("got %d, want %d (%v vs %v)", len(got), len(want), got, want)
			}

			for i := range want {
				if got[i] != want[i] {
					t.Errorf("[%d] got %q, want %q", i, got[i], want[i])
				}
			}
		})
	}
}
