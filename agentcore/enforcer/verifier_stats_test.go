//go:build linux

package enforcer

import (
	"os"
	"regexp"
	"testing"

	"github.com/cilium/ebpf"
)

var processedInsnsRE = regexp.MustCompile(`processed (\d+) insns`)

// logVerifierStats loads spec with verifier stats enabled and logs the
// "processed N insns" figure per program, so growth towards the 1M
// complexity limit is visible before a kernel rejects the program.
func logVerifierStats(t *testing.T, spec *ebpf.CollectionSpec) {
	t.Helper()

	opts := ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats}}

	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		t.Skip("load failed (LSM/BPF unavailable?): ", err)
	}

	defer coll.Close()

	for name, prog := range coll.Programs {
		m := processedInsnsRE.FindStringSubmatch(prog.VerifierLog)
		if m == nil {
			t.Logf("%s: no stats in verifier log", name)

			continue
		}

		t.Logf("VERIFIER %s: processed %s insns", name, m[1])
	}
}

func TestVerifierStatsCredwatch(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	spec, err := loadCredwatch()
	if err != nil {
		t.Fatal(err)
	}

	logVerifierStats(t, spec)
}

func TestVerifierStatsEgress(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	spec, err := loadEbpf()
	if err != nil {
		t.Fatal(err)
	}

	logVerifierStats(t, spec)
}
