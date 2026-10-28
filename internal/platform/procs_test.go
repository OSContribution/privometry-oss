package platform

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestSplitCommandLine(t *testing.T) {
	for in, want := range map[string][]string{
		`agy --dangerously-skip-permissions`:                  {"agy", "--dangerously-skip-permissions"},
		`"C:\Program Files\Antigravity\agy.exe"  --mode auto`: {`C:\Program Files\Antigravity\agy.exe`, "--mode", "auto"},
		`node /usr/local/bin/gemini --approval-mode "yolo"`:   {"node", "/usr/local/bin/gemini", "--approval-mode", "yolo"},
		"": nil,
	} {
		if got := SplitCommandLine(in); !slices.Equal(got, want) {
			t.Errorf("SplitCommandLine(%q) = %q, want %q", in, got, want)
		}
	}
}

// ProcessArgs sees this test binary among the running processes.
func TestProcessArgsSeesThisProcess(t *testing.T) {
	procs, err := ProcessArgs()
	if err != nil {
		t.Skipf("no process list here: %v", err)
	}
	self := filepath.Base(os.Args[0])
	if !slices.ContainsFunc(procs, func(args []string) bool { return strings.HasSuffix(args[0], self) }) {
		t.Errorf("%s not among %d processes", self, len(procs))
	}
}
