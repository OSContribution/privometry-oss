// Package guard installs and removes Privometry's hook in each coding agent's
// config, and reports whether it is in place. Changes are computed first, so
// callers can show them before writing.
package guard

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/adapters/registry"
	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/platform"
	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/scanner/parsers"
)

// Options say where the hook lives and what is installed.
type Options struct {
	Env          platform.Env
	HookCommand  string // absolute path of privometry-hook
	AgentVersion string // detected agent version; "" if unknown
	Root         string // prefixes paths, for tests
}

// Change is a computed edit to one agent's config file.
type Change struct {
	Agent      string
	Path       string // as configured, without Root
	real       string
	Before     []byte // nil when the file does not exist
	After      []byte
	FailClosed bool     // whether a fail-closed setting was added
	Events     []string // events registered

	// TrustInstructions is set when the agent runs new hooks only after the
	// user approves them (Codex).
	TrustInstructions string
	// Warnings explain settings that would keep the hook from running.
	Warnings []string
}

// Changed reports whether applying would modify the file.
func (c *Change) Changed() bool { return !bytes.Equal(c.Before, c.After) }

// Apply writes the change. The first time Privometry edits a file it keeps a copy
// at <file>.privometry-backup; the new content replaces the file atomically with
// the same permissions.
func (c *Change) Apply() error {
	if !c.Changed() {
		return nil
	}
	mode := fs.FileMode(0o600)
	if c.Before != nil {
		info, err := os.Stat(c.real)
		if err != nil {
			return err
		}
		mode = info.Mode().Perm()
		backup := c.real + ".privometry-backup"
		if _, err := os.Stat(backup); errors.Is(err, fs.ErrNotExist) {
			if err := os.WriteFile(backup, c.Before, mode); err != nil {
				return fmt.Errorf("backup: %w", err)
			}
		}
	} else if err := os.MkdirAll(filepath.Dir(c.real), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(c.real), "."+filepath.Base(c.real)+".privometry-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(c.After); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), c.real)
}

// ErrUnsupported is returned for agents whose registration format guard does
// not write yet.
var ErrUnsupported = errors.New("guard: installing hooks for this agent is not supported yet")

func settingsPath(a registry.Adapter, opts Options) (string, string, error) {
	paths, err := a.Paths(a.Hooks.Install.Free.Paths, opts.Env, "")
	if err != nil {
		return "", "", err
	}
	if len(paths) == 0 {
		return "", "", fmt.Errorf("guard: %s has no install path on %s", a.Agent, opts.Env.OS())
	}
	return paths[0], filepath.Join(opts.Root, paths[0]), nil
}

func load(real string) ([]byte, *object, error) {
	raw, err := os.ReadFile(real)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, newObject(), nil
	}
	if err != nil {
		return nil, nil, err
	}
	o, err := parseOrdered(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("guard: %s is not valid JSON, so Privometry will not edit it: %w", real, err)
	}
	return raw, o, nil
}

// layout reads and writes one registration format.
type layout interface {
	// remove deletes Privometry's entries and returns how many it removed.
	remove(doc *object) int
	// add registers one command for an event.
	add(doc *object, ev registry.HookEvent, entry *object)
	// find returns Privometry's entry for an event, or nil.
	find(doc *object, event string) *object
	// empty reports whether the document holds nothing but what Privometry added.
	cleanup(doc *object)
}

func layoutFor(a registry.Adapter) (layout, error) {
	switch a.Hooks.Registration {
	case registry.HooksRegistrationClaudeSettings, registry.HooksRegistrationCodexHooks:
		return groupedLayout{}, nil
	case registry.HooksRegistrationCursorHooks:
		return flatLayout{}, nil
	}
	return nil, fmt.Errorf("%w (%s)", ErrUnsupported, a.Agent)
}

// Install computes the edit that registers privometry-hook for every hook event in
// the agent's definition, replacing any earlier Privometry entries.
func Install(a registry.Adapter, opts Options) (*Change, error) {
	lay, err := layoutFor(a)
	if err != nil {
		return nil, err
	}
	path, real, err := settingsPath(a, opts)
	if err != nil {
		return nil, err
	}
	before, doc, err := load(real)
	if err != nil {
		return nil, err
	}
	lay.remove(doc)

	c := &Change{Agent: string(a.Agent), Path: path, real: real, Before: before}
	fc := a.Hooks.FailClosedOption
	failClosed := fc != nil && (fc.MinVersion == "" || opts.AgentVersion != "" && atLeast(opts.AgentVersion, fc.MinVersion))
	for _, ev := range a.Hooks.Events {
		entry := newObject()
		if a.Hooks.Registration != registry.HooksRegistrationCursorHooks {
			entry.set("type", "command")
		}
		entry.set("command", shellQuote(opts.HookCommand)+" "+string(a.Agent)+" "+ev.Name)
		if a.Hooks.TimeoutSeconds != nil {
			entry.set("timeout", *a.Hooks.TimeoutSeconds)
		}
		if failClosed && decisionRole(ev.Role) {
			entry.set(fc.Key, fc.Value)
			c.FailClosed = true
		}
		lay.add(doc, ev, entry)
		c.Events = append(c.Events, ev.Name)
	}
	if t := a.Hooks.Trust; t != nil && t.Required {
		c.TrustInstructions = t.Instructions
	}
	c.Warnings = warnings(a, opts)
	c.After = encode(doc)
	return c, nil
}

// Uninstall computes the edit that removes every Privometry hook entry.
func Uninstall(a registry.Adapter, opts Options) (*Change, error) {
	lay, err := layoutFor(a)
	if err != nil {
		return nil, err
	}
	path, real, err := settingsPath(a, opts)
	if err != nil {
		return nil, err
	}
	before, doc, err := load(real)
	if err != nil {
		return nil, err
	}
	c := &Change{Agent: string(a.Agent), Path: path, real: real, Before: before, After: before}
	if before == nil || lay.remove(doc) == 0 {
		return c, nil
	}
	lay.cleanup(doc)
	c.After = encode(doc)
	return c, nil
}

// Status is whether Privometry's hook is in place for one agent.
type Status struct {
	Agent         string   `json:"agent"`
	Path          string   `json:"path"`
	State         string   `json:"state"` // installed, partial, stale, missing, unsupported
	Missing       []string `json:"missing,omitempty"`
	FailClosed    bool     `json:"fail_closed"`
	TrustRequired bool     `json:"trust_required,omitempty"`
	Detail        string   `json:"detail,omitempty"`
}

// Check reports the hook's state: installed when every event is registered
// with this privometry-hook, stale when entries point at another binary.
func Check(a registry.Adapter, opts Options) Status {
	s := Status{Agent: string(a.Agent)}
	lay, err := layoutFor(a)
	if err != nil {
		s.State = "unsupported"
		return s
	}
	path, real, err := settingsPath(a, opts)
	s.Path = path
	if err != nil {
		s.State, s.Detail = "missing", err.Error()
		return s
	}
	_, doc, err := load(real)
	if err != nil {
		s.State, s.Detail = "missing", err.Error()
		return s
	}
	found, stale := 0, false
	for _, ev := range a.Hooks.Events {
		entry := lay.find(doc, ev.Name)
		if entry == nil {
			s.Missing = append(s.Missing, ev.Name)
			continue
		}
		found++
		cmd, _ := entry.get("command").(string)
		if opts.HookCommand != "" && !strings.HasPrefix(cmd, shellQuote(opts.HookCommand)+" ") {
			stale = true
		}
		if fc := a.Hooks.FailClosedOption; fc != nil && decisionRole(ev.Role) && entry.get(fc.Key) != nil {
			s.FailClosed = true
		}
	}
	switch {
	case found == 0:
		s.State = "missing"
	case stale:
		s.State, s.Detail = "stale", "hook entries point at a different privometry-hook; run privometry guard install"
	case len(s.Missing) > 0:
		s.State = "partial"
	default:
		s.State = "installed"
	}
	if t := a.Hooks.Trust; t != nil && t.Required && found > 0 {
		s.TrustRequired = true
		if s.Detail == "" {
			s.Detail = t.Instructions
		}
	}
	return s
}

// Installed reports whether any Privometry hook is registered for the agent's
// decision events. The daemon uses it to skip calls another agent imports.
func Installed(a registry.Adapter, opts Options) bool {
	lay, err := layoutFor(a)
	if err != nil {
		return false
	}
	_, real, err := settingsPath(a, opts)
	if err != nil {
		return false
	}
	_, doc, err := load(real)
	if err != nil {
		return false
	}
	for _, ev := range a.Hooks.Events {
		if decisionRole(ev.Role) && lay.find(doc, ev.Name) != nil {
			return true
		}
	}
	return false
}

// groupedLayout is Claude Code's and Codex's shape:
// {"hooks": {"<Event>": [{"matcher": "...", "hooks": [{"type": "command", ...}]}]}}.
type groupedLayout struct{}

func (groupedLayout) remove(doc *object) int {
	hooks, _ := doc.get("hooks").(*object)
	if hooks == nil {
		return 0
	}
	return removePrivometry(hooks)
}

func (groupedLayout) add(doc *object, ev registry.HookEvent, entry *object) {
	hooks, _ := doc.get("hooks").(*object)
	if hooks == nil {
		hooks = newObject()
		doc.set("hooks", hooks)
	}
	group := newObject()
	if ev.Matcher != "" {
		group.set("matcher", ev.Matcher)
	}
	group.set("hooks", []any{entry})
	list, _ := hooks.get(ev.Name).([]any)
	hooks.set(ev.Name, append(list, group))
}

func (groupedLayout) find(doc *object, event string) *object {
	hooks, _ := doc.get("hooks").(*object)
	if hooks == nil {
		return nil
	}
	groups, _ := hooks.get(event).([]any)
	for _, g := range groups {
		group, _ := g.(*object)
		if group == nil {
			continue
		}
		entries, _ := group.get("hooks").([]any)
		for _, e := range entries {
			if entry, _ := e.(*object); entry != nil {
				if cmd, _ := entry.get("command").(string); isPrivometry(cmd) {
					return entry
				}
			}
		}
	}
	return nil
}

func (groupedLayout) cleanup(doc *object) {
	if hooks, ok := doc.get("hooks").(*object); ok && len(hooks.keys) == 0 {
		doc.del("hooks")
	}
}

// flatLayout is Cursor's shape:
// {"version": 1, "hooks": {"<event>": [{"command": "...", "matcher": "..."}]}}.
type flatLayout struct{}

func (flatLayout) remove(doc *object) int {
	hooks, _ := doc.get("hooks").(*object)
	if hooks == nil {
		return 0
	}
	removed := 0
	for _, event := range append([]string{}, hooks.keys...) {
		entries, ok := hooks.get(event).([]any)
		if !ok {
			continue
		}
		var keep []any
		for _, e := range entries {
			if entry, _ := e.(*object); entry != nil {
				if cmd, _ := entry.get("command").(string); isPrivometry(cmd) {
					removed++
					continue
				}
			}
			keep = append(keep, e)
		}
		if len(keep) == 0 {
			hooks.del(event)
		} else if len(keep) != len(entries) {
			hooks.set(event, keep)
		}
	}
	return removed
}

func (flatLayout) add(doc *object, ev registry.HookEvent, entry *object) {
	if doc.get("version") == nil {
		doc.keys = append([]string{"version"}, doc.keys...)
		doc.vals["version"] = 1
	}
	hooks, _ := doc.get("hooks").(*object)
	if hooks == nil {
		hooks = newObject()
		doc.set("hooks", hooks)
	}
	if ev.Matcher != "" {
		entry.set("matcher", ev.Matcher)
	}
	list, _ := hooks.get(ev.Name).([]any)
	hooks.set(ev.Name, append(list, entry))
}

func (flatLayout) find(doc *object, event string) *object {
	hooks, _ := doc.get("hooks").(*object)
	if hooks == nil {
		return nil
	}
	entries, _ := hooks.get(event).([]any)
	for _, e := range entries {
		if entry, _ := e.(*object); entry != nil {
			if cmd, _ := entry.get("command").(string); isPrivometry(cmd) {
				return entry
			}
		}
	}
	return nil
}

func (flatLayout) cleanup(doc *object) {
	if hooks, ok := doc.get("hooks").(*object); ok && len(hooks.keys) == 0 {
		doc.del("hooks")
		if len(doc.keys) == 1 && doc.get("version") != nil {
			doc.del("version") // the file held only what Privometry added
		}
	}
}

// warnings explains settings that would stop the hook from running.
func warnings(a registry.Adapter, opts Options) []string {
	if a.Agent != "codex_cli" {
		return nil
	}
	for _, tier := range a.ConfigTiers {
		if tier.Tier != "user" || tier.Format != registry.FileFormatToml {
			continue
		}
		paths, _ := a.Paths(tier.Paths, opts.Env, "")
		for _, p := range paths {
			raw, err := os.ReadFile(filepath.Join(opts.Root, p))
			if err != nil {
				continue
			}
			doc, err := parsers.Parse("toml", raw)
			if err != nil {
				continue
			}
			for _, key := range []string{"/features/hooks", "/features/codex_hooks"} {
				if v, ok := parsers.Lookup(doc, key).(bool); ok && !v {
					return []string{fmt.Sprintf("hooks are turned off in %s ([features] %s = false); Codex will not run Privometry until you remove that line",
						p, strings.TrimPrefix(key, "/features/"))}
				}
			}
		}
	}
	return nil
}

func decisionRole(r registry.HookEventRole) bool {
	switch r {
	case registry.HookEventRolePreTool, registry.HookEventRolePreShell, registry.HookEventRolePreMCP, registry.HookEventRolePreFileRead:
		return true
	}
	return false
}

// isPrivometry reports whether a hook command runs privometry-hook.
func isPrivometry(cmd string) bool {
	first := strings.Trim(strings.Fields(cmd + " ")[0], `"'`)
	if strings.HasPrefix(cmd, "'") || strings.HasPrefix(cmd, `"`) {
		q := cmd[0]
		if end := strings.IndexByte(cmd[1:], q); end >= 0 {
			first = cmd[1 : end+1]
		}
	}
	base := filepath.Base(first)
	return base == "privometry-hook" || base == "privometry-hook.exe"
}

// removePrivometry deletes Privometry's entries from a Claude-style hooks map and
// prunes groups and events left empty. It returns how many it removed.
func removePrivometry(hooks *object) int {
	removed := 0
	for _, event := range append([]string{}, hooks.keys...) {
		groups, ok := hooks.get(event).([]any)
		if !ok {
			continue
		}
		var keepGroups []any
		for _, g := range groups {
			group, ok := g.(*object)
			if !ok {
				keepGroups = append(keepGroups, g)
				continue
			}
			entries, _ := group.get("hooks").([]any)
			var keep []any
			for _, e := range entries {
				entry, ok := e.(*object)
				if cmd, _ := entry.get("command").(string); ok && isPrivometry(cmd) {
					removed++
					continue
				}
				keep = append(keep, e)
			}
			if len(keep) == 0 && len(entries) > 0 {
				continue
			}
			if len(keep) != len(entries) {
				group.set("hooks", keep)
			}
			keepGroups = append(keepGroups, group)
		}
		if len(keepGroups) == 0 {
			hooks.del(event)
		} else {
			hooks.set(event, keepGroups)
		}
	}
	return removed
}

// shellQuote quotes a path for a hook command when it needs it.
func shellQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t'\"$`\\;&|<>()*?[]{}!#~") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func atLeast(version, min string) bool {
	if min == "" {
		return true
	}
	a, b := registry.ParseVersion(version), registry.ParseVersion(min)
	if a == "" || b == "" {
		return false
	}
	return (&registry.Adapter{Versions: ">=" + b}).Supports(a)
}
