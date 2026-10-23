package platform

import "testing"

func env(goos string, vars map[string]string) Env {
	home := "/home/dev"
	if goos == "darwin" {
		home = "/Users/dev"
	}
	if goos == "windows" {
		home = `C:\Users\dev`
	}
	return Env{GOOS: goos, Home: home, Getenv: func(k string) string { return vars[k] }}
}

func TestOS(t *testing.T) {
	for goos, want := range map[string]string{"darwin": "macos", "linux": "linux", "windows": "windows", "freebsd": "other"} {
		if got := env(goos, nil).OS(); got != want {
			t.Errorf("OS(%s) = %q, want %q", goos, got, want)
		}
	}
}

func TestLocations(t *testing.T) {
	win := map[string]string{"LOCALAPPDATA": `C:\Users\dev\AppData\Local`, "USERNAME": "dev"}
	tests := []struct {
		name string
		e    Env
		fn   func(Env) (string, error)
		want string
	}{
		{"mac db", env("darwin", nil), Env.DBPath, "/Users/dev/.privometry/privometry.db"},
		{"linux socket", env("linux", nil), Env.IPCAddress, "/home/dev/.privometry/privometryd.sock"},
		{"linux user policy", env("linux", nil), Env.UserPolicyPath, "/home/dev/.privometry/policy.yaml"},
		{"windows db", env("windows", win), Env.DBPath, `C:\Users\dev\AppData\Local\Privometry\privometry.db`},
		{"windows pipe", env("windows", win), Env.IPCAddress, `\\.\pipe\privometry-dev`},
	}
	for _, tc := range tests {
		got, err := tc.fn(tc.e)
		if err != nil || got != tc.want {
			t.Errorf("%s = %q, %v; want %q", tc.name, got, err, tc.want)
		}
	}
	if _, err := env("windows", nil).DataDir(); err == nil {
		t.Error("windows DataDir without LOCALAPPDATA should fail")
	}
}

func TestExpandPath(t *testing.T) {
	win := env("windows", map[string]string{"APPDATA": `C:\Users\dev\AppData\Roaming`, "PROGRAMDATA": `C:\ProgramData`})
	tests := []struct {
		e        Env
		in, want string
	}{
		{env("darwin", nil), "~", "/Users/dev"},
		{env("darwin", nil), "~/.claude/settings.json", "/Users/dev/.claude/settings.json"},
		{env("linux", nil), "/etc/claude-code/managed-settings.json", "/etc/claude-code/managed-settings.json"},
		{env("linux", nil), ".mcp.json", ".mcp.json"},
		{win, `%USERPROFILE%\.cursor\mcp.json`, `C:\Users\dev\.cursor\mcp.json`},
		{win, `%appdata%\Cursor\User\settings.json`, `C:\Users\dev\AppData\Roaming\Cursor\User\settings.json`},
		{win, `~\.codex\config.toml`, `C:\Users\dev\.codex\config.toml`},
		{win, `%ProgramData%\OpenAI\Codex\requirements.toml`, `C:\ProgramData\OpenAI\Codex\requirements.toml`},
	}
	for _, tc := range tests {
		got, err := tc.e.ExpandPath(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("ExpandPath(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	if _, err := win.ExpandPath(`%LOCALAPPDATA%\x`); err == nil {
		t.Error("unset LOCALAPPDATA should fail")
	}
}
