// Package platform resolves OS-specific locations and checks file ownership and permissions.
package platform

import (
	"errors"
	"os"
	"runtime"
	"strings"
)

// Env is the slice of the process environment that path resolution depends on.
// Tests build one directly so every OS can be exercised from any host.
type Env struct {
	GOOS   string
	Home   string
	Getenv func(string) string
}

// CurrentEnv describes the running process.
func CurrentEnv() (Env, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Env{}, err
	}
	return Env{GOOS: runtime.GOOS, Home: home, Getenv: os.Getenv}, nil
}

// OS returns the event-schema name of the operating system: macos, linux, windows or other.
func (e Env) OS() string {
	switch e.GOOS {
	case "darwin":
		return "macos"
	case "linux", "windows":
		return e.GOOS
	default:
		return "other"
	}
}

func (e Env) sep() string {
	if e.GOOS == "windows" {
		return `\`
	}
	return "/"
}

func (e Env) join(parts ...string) string {
	s := e.sep()
	out := strings.TrimRight(parts[0], `/\`)
	for _, p := range parts[1:] {
		out += s + strings.Trim(p, `/\`)
	}
	return out
}

// DataDir is where the daemon keeps its database and socket:
// ~/.privometry on macOS and Linux, %LOCALAPPDATA%\Privometry on Windows.
// PRIVOMETRY_HOME overrides it, for tests and side-by-side installs.
func (e Env) DataDir() (string, error) {
	if dir := e.Getenv("PRIVOMETRY_HOME"); dir != "" {
		return dir, nil
	}
	if e.GOOS == "windows" {
		local := e.Getenv("LOCALAPPDATA")
		if local == "" {
			return "", errors.New("platform: LOCALAPPDATA is not set")
		}
		return e.join(local, "Privometry"), nil
	}
	if e.Home == "" {
		return "", errors.New("platform: home directory is unknown")
	}
	return e.join(e.Home, ".privometry"), nil
}

// DBPath is the timeline SQLite file.
func (e Env) DBPath() (string, error) {
	dir, err := e.DataDir()
	if err != nil {
		return "", err
	}
	return e.join(dir, "privometry.db"), nil
}

// IPCAddress is the daemon endpoint: a Unix socket in the data dir, or a
// per-user named pipe on Windows.
func (e Env) IPCAddress() (string, error) {
	if e.GOOS == "windows" {
		user := e.Getenv("USERNAME")
		if user == "" {
			return "", errors.New("platform: USERNAME is not set")
		}
		return `\\.\pipe\privometry-` + user, nil
	}
	dir, err := e.DataDir()
	if err != nil {
		return "", err
	}
	return e.join(dir, "privometryd.sock"), nil
}

// UserPolicyPath is the developer's override layer, ~/.privometry/policy.yaml.
func (e Env) UserPolicyPath() (string, error) {
	dir, err := e.DataDir()
	if err != nil {
		return "", err
	}
	return e.join(dir, "policy.yaml"), nil
}

// ExpandPath expands the prefixes adapter definitions may use: "~",
// "%USERPROFILE%", "%APPDATA%", "%LOCALAPPDATA%" and "%ProgramData%". Other paths are returned unchanged.
func (e Env) ExpandPath(p string) (string, error) {
	switch {
	case p == "~":
		return e.homeOrErr()
	case strings.HasPrefix(p, "~/"), strings.HasPrefix(p, `~\`):
		home, err := e.homeOrErr()
		if err != nil {
			return "", err
		}
		return e.join(home, p[2:]), nil
	}
	for _, v := range []string{"USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA"} {
		token := "%" + v + "%"
		if len(p) >= len(token) && strings.EqualFold(p[:len(token)], token) {
			val := e.Getenv(v)
			if val == "" && v == "USERPROFILE" {
				val = e.Home
			}
			if val == "" {
				return "", errors.New("platform: " + v + " is not set")
			}
			rest := p[len(token):]
			if rest == "" {
				return val, nil
			}
			return e.join(val, rest), nil
		}
	}
	return p, nil
}

func (e Env) homeOrErr() (string, error) {
	if e.Home == "" {
		return "", errors.New("platform: home directory is unknown")
	}
	return e.Home, nil
}
