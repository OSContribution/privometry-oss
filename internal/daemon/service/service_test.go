package service

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/platform"
)

type recorder struct {
	calls  []string
	output map[string]string
	fail   map[string]bool
}

func (r *recorder) run(name string, args ...string) (string, error) {
	cmd := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, cmd)
	for prefix, out := range r.output {
		if strings.HasPrefix(cmd, prefix) {
			return out, nil
		}
	}
	for prefix := range r.fail {
		if strings.HasPrefix(cmd, prefix) {
			return "not loaded", errors.New("exit status 5")
		}
	}
	return "", nil
}

func opts(t *testing.T, goos string, vars map[string]string, r *recorder) Options {
	return Options{Env: platform.Env{GOOS: goos, Home: "/home/dev", Getenv: func(k string) string { return vars[k] }},
		Privometryd: "/opt/privometry tools/privometryd", Root: t.TempDir(), Run: r.run, UID: 501}
}

func TestLaunchd(t *testing.T) {
	r := &recorder{fail: map[string]bool{"launchctl bootout": true}}
	o := opts(t, "darwin", map[string]string{"PRIVOMETRY_HOME": "/tmp/p&q"}, r)
	p, err := For(o)
	if err != nil {
		t.Fatal(err)
	}
	if p.Path != "/home/dev/Library/LaunchAgents/dev.privometry.privometryd.plist" {
		t.Errorf("path %s", p.Path)
	}
	text := string(p.Content)
	for _, want := range []string{"<string>/opt/privometry tools/privometryd</string>", "<string>/tmp/p&amp;q</string>", "<key>KeepAlive</key>", "/tmp/p&amp;q/privometryd.log"} {
		if !strings.Contains(text, want) {
			t.Errorf("plist lacks %s:\n%s", want, text)
		}
	}
	// A not-yet-loaded agent makes bootout fail; install still bootstraps.
	if err := Install(p, o); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.calls, "; "); got != "launchctl bootout gui/501/dev.privometry.privometryd; launchctl bootstrap gui/501 /home/dev/Library/LaunchAgents/dev.privometry.privometryd.plist" {
		t.Errorf("calls: %s", got)
	}
	r.output = map[string]string{"launchctl print": "gui/501/dev.privometry.privometryd = {\n\tstate = running\n\tpid = 4242\n}"}
	if s := Check(p, o); !s.Installed || !s.Current || !s.Running || s.PID != 4242 {
		t.Errorf("status %+v", s)
	}
	if err := Uninstall(p, o); err != nil {
		t.Fatal(err)
	}
	if s := Check(p, o); s.Installed {
		t.Error("plist left after uninstall")
	}

	// plutil validates the generated file where it exists (macOS).
	if runtime.GOOS == "darwin" {
		if _, err := exec.LookPath("plutil"); err == nil {
			f := filepath.Join(t.TempDir(), "x.plist")
			os.WriteFile(f, p.Content, 0o644)
			if out, err := exec.Command("plutil", "-lint", f).CombinedOutput(); err != nil {
				t.Errorf("plutil: %s", out)
			}
		}
	}
}

func TestSystemd(t *testing.T) {
	r := &recorder{}
	o := opts(t, "linux", map[string]string{"XDG_CONFIG_HOME": "/home/dev/.cfg", "PRIVOMETRY_HOME": "/srv/privometry data"}, r)
	p, err := For(o)
	if err != nil {
		t.Fatal(err)
	}
	if p.Path != "/home/dev/.cfg/systemd/user/privometryd.service" {
		t.Errorf("path %s", p.Path)
	}
	text := string(p.Content)
	for _, want := range []string{`ExecStart="/opt/privometry tools/privometryd"`, `Environment="PRIVOMETRY_HOME=/srv/privometry data"`, "Restart=on-failure", "WantedBy=default.target"} {
		if !strings.Contains(text, want) {
			t.Errorf("unit lacks %s:\n%s", want, text)
		}
	}
	if err := Install(p, o); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.calls, "; "); got != "systemctl --user daemon-reload; systemctl --user enable privometryd.service; systemctl --user restart privometryd.service" {
		t.Errorf("calls: %s", got)
	}
	r.output = map[string]string{"systemctl --user show": "MainPID=77\nActiveState=active\n"}
	if s := Check(p, o); !s.Running || s.PID != 77 {
		t.Errorf("status %+v", s)
	}
	// A changed privometryd path makes the installed unit out of date.
	o.Privometryd = "/usr/local/bin/privometryd"
	p2, _ := For(o)
	if s := Check(p2, o); !s.Installed || s.Current {
		t.Errorf("stale unit: %+v", s)
	}
	r.fail = map[string]bool{"systemctl --user restart": true}
	r.output = nil
	if err := Install(p2, o); err == nil || !strings.Contains(err.Error(), "restart") {
		t.Errorf("a failing restart must be reported: %v", err)
	}
	if _, err := For(Options{Env: platform.Env{GOOS: "windows", Home: `C:\Users\dev`, Getenv: func(k string) string {
		return map[string]string{"LOCALAPPDATA": `C:\x`}[k]
	}}}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("windows: %v", err)
	}
}
