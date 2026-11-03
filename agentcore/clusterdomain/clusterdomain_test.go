package clusterdomain

import (
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	t.Parallel()

	good := map[string]string{"cluster.local": "cluster.local", "  K8s.Example. ": "k8s.example", "a-b.c1": "a-b.c1"}
	for in, want := range good {
		if got, err := Normalize(in); err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", in, got, err, want)
		}
	}

	for _, bad := range []string{"", "  ", ".", "a..b", "-a.b", "a-.b", "a_b.c", "a b.c", strings.Repeat("a", 64) + ".x", "exämple.com"} {
		if _, err := Normalize(bad); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
}
