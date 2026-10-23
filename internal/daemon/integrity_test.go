package daemon_test

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	adapterdefs "github.com/privometry/privometry-oss/adapter-defs"
	"github.com/privometry/privometry-oss/internal/adapters/registry"
	"github.com/privometry/privometry-oss/internal/contract"
	"github.com/privometry/privometry-oss/internal/daemon"
	"github.com/privometry/privometry-oss/internal/guard"
	"github.com/privometry/privometry-oss/internal/platform"
	"github.com/privometry/privometry-oss/internal/policy"
	"github.com/privometry/privometry-oss/internal/timeline"
)

func TestIntegrity(t *testing.T) {
	home := t.TempDir()
	data, err := os.MkdirTemp("/tmp", "privometry-i-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(data)
	env := platform.Env{GOOS: "linux", Home: home, Getenv: func(k string) string {
		if k == "PRIVOMETRY_HOME" {
			return data
		}
		return ""
	}}
	reg, _ := registry.Load(adapterdefs.FS)
	packs, _ := policy.BuiltinPacks()
	claude, _ := reg.Get(contract.AgentProductClaudeCode)
	gopts := guard.Options{Env: env, HookCommand: "/usr/local/bin/privometry-hook", AgentVersion: "2.1.304"}
	c, err := guard.Install(claude, gopts)
	if err != nil || c.Apply() != nil {
		t.Fatal(err)
	}
	claudeJSON := filepath.Join(home, ".claude.json")
	os.WriteFile(claudeJSON, []byte(`{"numStartups": 1, "mcpServers": {}}`), 0o644)

	d, err := daemon.New(daemon.Config{Env: env, Registry: reg, Packs: packs, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	check := func(want int, why string) {
		t.Helper()
		n, err := d.CheckIntegrity()
		if err != nil || n != want {
			t.Fatalf("%s: %d events, %v; want %d", why, n, err, want)
		}
	}
	check(0, "first observation")
	check(0, "nothing changed")

	// Claude Code rewrites ~/.claude.json constantly; only the MCP server map counts.
	os.WriteFile(claudeJSON, []byte(`{"numStartups": 2, "mcpServers": {}}`), 0o644)
	check(0, "unrelated ~/.claude.json change")
	os.WriteFile(claudeJSON, []byte(`{"numStartups": 2, "mcpServers": {"x": {"command": "npx"}}}`), 0o644)
	check(1, "new MCP server")

	u, _ := guard.Uninstall(claude, gopts)
	u.Apply()
	check(2, "hook removed: a config change and an integrity alert")

	rows := validEvents(t, d)
	if rows[0].Event.Type != "integrity" || rows[0].Event.Integrity.Check != "hook_removed" || rows[1].Event.Type != "config_change" {
		t.Fatalf("events: %s %s", rows[0].Event.Type, rows[1].Event.Type)
	}
	if rows[2].Event.Config.Holds[0] != "mcp_servers" {
		t.Errorf("MCP change holds %v", rows[2].Event.Config.Holds)
	}
	if rows[0].Event.Integrity.Path != "~/<redacted_path>" {
		t.Errorf("integrity path must be redacted: %q", rows[0].Event.Integrity.Path)
	}

	// Reinstalling is a change, not an alert; removing again alerts again.
	c, _ = guard.Install(claude, gopts)
	c.Apply()
	check(1, "reinstall")
	if rows, _ := d.Store().Events(timeline.Query{Limit: 1}); rows[0].Event.Type != "config_change" {
		t.Errorf("reinstall recorded %s", rows[0].Event.Type)
	}
}
