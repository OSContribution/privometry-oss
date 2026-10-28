package platform

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// ProcessArgs returns the arguments of the processes running now, each with
// the program first. Callers look for specific flags and must never store or
// log what they read: command lines can hold secrets. Linux reads
// /proc/<pid>/cmdline, macOS asks ps, Windows asks CIM; on macOS and Windows a
// command line is split on spaces, outside double quotes.
func ProcessArgs() ([][]string, error) {
	switch runtime.GOOS {
	case "linux":
		return procArgs()
	case "windows":
		out, err := run("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
			"Get-CimInstance Win32_Process | ForEach-Object { $_.CommandLine }")
		if err != nil {
			return nil, err
		}
		return splitLines(out), nil
	}
	out, err := run("ps", "-axww", "-o", "args=")
	if err != nil {
		return nil, err
	}
	return splitLines(out), nil
}

func run(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}

func procArgs() ([][]string, error) {
	dirs, err := filepath.Glob("/proc/[0-9]*/cmdline")
	if err != nil {
		return nil, err
	}
	var out [][]string
	for _, p := range dirs {
		raw, err := os.ReadFile(p)
		if err != nil || len(raw) == 0 {
			continue // gone, or a kernel thread
		}
		out = append(out, strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00"))
	}
	return out, nil
}

func splitLines(out []byte) [][]string {
	var procs [][]string
	for _, line := range bytes.Split(out, []byte("\n")) {
		if args := SplitCommandLine(strings.TrimSpace(string(line))); len(args) > 0 {
			procs = append(procs, args)
		}
	}
	return procs
}

// SplitCommandLine splits a command line on spaces outside double quotes.
func SplitCommandLine(s string) []string {
	var args []string
	var cur strings.Builder
	quoted, any := false, false
	for _, r := range s {
		switch {
		case r == '"':
			quoted, any = !quoted, true
		case (r == ' ' || r == '\t') && !quoted:
			if any {
				args = append(args, cur.String())
				cur.Reset()
				any = false
			}
		default:
			cur.WriteRune(r)
			any = true
		}
	}
	if any {
		args = append(args, cur.String())
	}
	return args
}
