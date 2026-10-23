// Package service installs privometryd as a per-user background service: a
// launchd agent on macOS and a systemd user unit on Linux. It runs as the
// user, never as root, and restarts the daemon if it exits.
package service

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/platform"
)

// Label is the launchd label; Unit is the systemd unit name.
const (
	Label = "dev.privometry.privometryd"
	Unit  = "privometryd.service"
)

// Runner runs a service manager command and returns its combined output.
type Runner func(name string, args ...string) (string, error)

// Options describe the install.
type Options struct {
	Env         platform.Env
	Privometryd string // absolute path of privometryd
	Root        string // prefixes written paths, for tests
	Run         Runner
	UID         int
}

// ErrUnsupported is returned on systems without a supported service manager.
var ErrUnsupported = errors.New("service: background service install is not supported on this OS yet")

// Plan is the service file and the commands that load it.
type Plan struct {
	Path    string // where the file goes (without Root)
	Content []byte
	Load    [][]string // commands to (re)load and start
	Unload  [][]string // commands to stop and unload
}

// For returns the plan for env's OS.
func For(opts Options) (*Plan, error) {
	dataDir, err := opts.Env.DataDir()
	if err != nil {
		return nil, err
	}
	log := filepath.Join(dataDir, "privometryd.log")
	privometryHome := opts.Env.Getenv("PRIVOMETRY_HOME")
	switch opts.Env.GOOS {
	case "darwin":
		path := filepath.Join(opts.Env.Home, "Library", "LaunchAgents", Label+".plist")
		domain := fmt.Sprintf("gui/%d", opts.UID)
		return &Plan{
			Path:    path,
			Content: plist(opts.Privometryd, log, privometryHome),
			Load:    [][]string{{"launchctl", "bootout", domain + "/" + Label}, {"launchctl", "bootstrap", domain, path}},
			Unload:  [][]string{{"launchctl", "bootout", domain + "/" + Label}},
		}, nil
	case "linux":
		config := opts.Env.Getenv("XDG_CONFIG_HOME")
		if config == "" {
			config = filepath.Join(opts.Env.Home, ".config")
		}
		path := filepath.Join(config, "systemd", "user", Unit)
		return &Plan{
			Path:    path,
			Content: unit(opts.Privometryd, privometryHome),
			Load:    [][]string{{"systemctl", "--user", "daemon-reload"}, {"systemctl", "--user", "enable", Unit}, {"systemctl", "--user", "restart", Unit}},
			Unload:  [][]string{{"systemctl", "--user", "disable", "--now", Unit}},
		}, nil
	}
	return nil, ErrUnsupported
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

func plist(privometryd, log, privometryHome string) []byte {
	env := ""
	if privometryHome != "" {
		env = "\t<key>EnvironmentVariables</key>\n\t<dict>\n\t\t<key>PRIVOMETRY_HOME</key>\n\t\t<string>" + xmlEscape(privometryHome) + "</string>\n\t</dict>\n"
	}
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + Label + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + xmlEscape(privometryd) + `</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>10</integer>
	<key>ProcessType</key>
	<string>Adaptive</string>
` + env + `	<key>StandardOutPath</key>
	<string>` + xmlEscape(log) + `</string>
	<key>StandardErrorPath</key>
	<string>` + xmlEscape(log) + `</string>
</dict>
</plist>
`)
}

// systemdQuote quotes a value for an ExecStart= or Environment= line.
func systemdQuote(s string) string {
	if !strings.ContainsAny(s, " \t\"'\\%$") {
		return s
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%", "$", "$$")
	return `"` + r.Replace(s) + `"`
}

func unit(privometryd, privometryHome string) []byte {
	env := ""
	if privometryHome != "" {
		env = "Environment=" + systemdQuote("PRIVOMETRY_HOME="+privometryHome) + "\n"
	}
	return []byte(`[Unit]
Description=Privometry daemon (local guard for coding agents)
Documentation=https://gitlab.com/cn-solutions/privometry/privometry-oss

[Service]
ExecStart=` + systemdQuote(privometryd) + `
` + env + `Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
`)
}

// Install writes the service file and loads it. Loading an already loaded
// service restarts it, so this also upgrades.
func Install(p *Plan, opts Options) error {
	// Create the data directory first, private, so the service manager does
	// not create it with its default mode when it opens the log file.
	if dir, err := opts.Env.DataDir(); err == nil {
		if err := platform.EnsurePrivateDir(filepath.Join(opts.Root, dir)); err != nil {
			return err
		}
	}
	real := filepath.Join(opts.Root, p.Path)
	if err := os.MkdirAll(filepath.Dir(real), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(real, p.Content, 0o644); err != nil {
		return err
	}
	for i, cmd := range p.Load {
		if out, err := opts.Run(cmd[0], cmd[1:]...); err != nil {
			// launchctl bootout fails when the agent is not loaded yet; that is fine.
			if i == 0 && cmd[0] == "launchctl" {
				continue
			}
			return fmt.Errorf("%s: %v: %s", strings.Join(cmd, " "), err, strings.TrimSpace(out))
		}
	}
	return nil
}

// Uninstall stops the service and removes its file.
func Uninstall(p *Plan, opts Options) error {
	for _, cmd := range p.Unload {
		opts.Run(cmd[0], cmd[1:]...) // not loaded is fine
	}
	err := os.Remove(filepath.Join(opts.Root, p.Path))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Status is the service manager's view of privometryd.
type Status struct {
	Installed bool   `json:"installed"` // the service file exists
	Current   bool   `json:"current"`   // and matches what Install would write
	Running   bool   `json:"running"`
	PID       int    `json:"pid,omitempty"`
	Path      string `json:"path"`
}

var (
	launchdPID   = regexp.MustCompile(`(?m)^\s*pid = (\d+)`)
	launchdState = regexp.MustCompile(`(?m)^\s*state = running`)
	systemdPID   = regexp.MustCompile(`(?m)^MainPID=(\d+)`)
)

// Check reports whether the service is installed, current and running.
func Check(p *Plan, opts Options) Status {
	s := Status{Path: p.Path}
	got, err := os.ReadFile(filepath.Join(opts.Root, p.Path))
	if err != nil {
		return s
	}
	s.Installed, s.Current = true, bytes.Equal(got, p.Content)
	switch opts.Env.GOOS {
	case "darwin":
		out, err := opts.Run("launchctl", "print", fmt.Sprintf("gui/%d/%s", opts.UID, Label))
		if err == nil && launchdState.MatchString(out) {
			s.Running = true
			if m := launchdPID.FindStringSubmatch(out); m != nil {
				s.PID, _ = strconv.Atoi(m[1])
			}
		}
	case "linux":
		out, err := opts.Run("systemctl", "--user", "show", "-p", "MainPID", "-p", "ActiveState", Unit)
		if err == nil && strings.Contains(out, "ActiveState=active") {
			s.Running = true
			if m := systemdPID.FindStringSubmatch(out); m != nil {
				s.PID, _ = strconv.Atoi(m[1])
			}
		}
	}
	return s
}

// Restart restarts a loaded service.
func Restart(opts Options) error {
	var cmd []string
	switch opts.Env.GOOS {
	case "darwin":
		cmd = []string{"launchctl", "kickstart", "-k", fmt.Sprintf("gui/%d/%s", opts.UID, Label)}
	case "linux":
		cmd = []string{"systemctl", "--user", "restart", Unit}
	default:
		return ErrUnsupported
	}
	if out, err := opts.Run(cmd[0], cmd[1:]...); err != nil {
		return fmt.Errorf("%s: %v: %s", strings.Join(cmd, " "), err, strings.TrimSpace(out))
	}
	return nil
}
