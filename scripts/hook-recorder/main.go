// Command hook-recorder is a spike tool. Register it as an agent hook and it
// saves each raw stdin payload to a file, then exits 0 with no output so the
// agent proceeds exactly as if no hook were installed.
//
//	hook-recorder -agent claude_code -event PreToolUse -out /tmp/recordings
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

func main() {
	agent := flag.String("agent", "unknown", "agent product, e.g. claude_code")
	event := flag.String("event", "unknown", "hook event name as configured")
	out := flag.String("out", os.Getenv("PRIVOMETRY_RECORD_DIR"), "directory for recordings")
	flag.Parse()

	// Never interfere with the agent: every failure is reported on stderr only.
	if err := record(*agent, *event, *out); err != nil {
		fmt.Fprintln(os.Stderr, "hook-recorder:", err)
	}
}

func record(agent, event, out string) error {
	if out == "" {
		return fmt.Errorf("no output dir: pass -out or set PRIVOMETRY_RECORD_DIR")
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 4<<20))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(out, 0o700); err != nil {
		return err
	}
	var pretty bytes.Buffer
	if json.Indent(&pretty, raw, "", "  ") != nil {
		pretty.Reset()
		pretty.Write(raw) // keep non-JSON payloads verbatim
	}
	name := fmt.Sprintf("%s-%s-%s.json", agent, event, time.Now().UTC().Format("20060102T150405.000000000"))
	return os.WriteFile(filepath.Join(out, name), pretty.Bytes(), 0o600)
}
