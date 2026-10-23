// Package hookclient is privometry-hook: the small program coding agents run on
// every hook event. It forwards the event to the daemon and prints the
// daemon's reply. When the daemon cannot answer in time, it decides alone
// using the fail mode of each rule category: closed denies, ask asks, open
// gives no opinion so the agent's own permission flow applies. It never
// auto-approves on its own.
//
// It must start fast: it loads no policy engine, YAML or database.
package hookclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/contract"
	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/events"
	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/ipc"
	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/platform"
	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/policy/intent"
	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/redact"
)

// DefaultTimeout is how long privometry-hook waits for the daemon. The first call
// for a new repo compiles its policy, so this is above the 10 ms p95 target
// for a warm daemon.
const DefaultTimeout = 200 * time.Millisecond

// maxSpool caps the spool while no daemon imports it.
const maxSpool = 10 << 20

// Files shared with the daemon (see internal/daemon).
const (
	failModesFile = "failmodes.json"
	spoolFile     = "spool.jsonl"
)

// ProbeEnv carries a one-time probe token from privometry doctor. Without a
// daemon to check it the token means nothing, so the fail-mode path still
// spools its decision.
const ProbeEnv = "PRIVOMETRY_HOOK_PROBE"

// Options configure one run.
type Options struct {
	Env     platform.Env
	Timeout time.Duration
	Now     func() time.Time
}

// Run handles one hook invocation: privometry-hook <agent> <event>.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer, opts Options) int {
	if opts.Timeout == 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if len(args) == 1 && args[0] == "version" {
		return 0
	}
	if len(args) != 2 {
		fmt.Fprintln(stderr, "usage: privometry-hook <agent> <event>")
		return 0 // never break the agent over a bad registration
	}
	agent, event := args[0], args[1]
	start := opts.Now()
	payload, err := io.ReadAll(io.LimitReader(stdin, ipc.MaxMessage))
	if err != nil {
		payload = nil
	}

	reason := "daemon_unavailable"
	if addr, err := opts.Env.IPCAddress(); err == nil {
		resp, err := ipc.Call(addr, ipc.Request{Op: "hook", Hook: &ipc.HookRequest{Agent: agent, Event: event, Payload: payload, Probe: opts.Env.Getenv(ProbeEnv)}}, opts.Timeout)
		if err == nil {
			io.WriteString(stdout, resp.Stdout)
			io.WriteString(stderr, resp.Stderr)
			return resp.ExitCode
		}
		var ne net.Error
		switch {
		case errors.As(err, &ne) && ne.Timeout():
			reason = "timeout"
		case resp.Error != "":
			reason = "internal_error"
		}
	}
	return fallback(agent, event, payload, reason, start, stdout, opts)
}

// format is how one agent's decision event expects its reply.
type format struct {
	style string // claude (hookSpecificOutput) or cursor (permission)
	ask   bool   // whether the event honors ask
}

// formats lists the decision events privometry-hook can answer alone. The daemon
// renders replies from the adapter definitions; a test keeps these in step.
var formats = map[string]map[string]format{
	"claude_code": {"PreToolUse": {"claude", true}},
	"codex_cli":   {"PreToolUse": {"claude", false}},
	"cursor": {"preToolUse": {"cursor", false}, "beforeShellExecution": {"cursor", true},
		"beforeMCPExecution": {"cursor", true}, "beforeReadFile": {"cursor", false}},
}

var defaultFailModes = map[string]string{"catastrophic": "closed", "secrets": "ask", "exfiltration": "ask", "unapproved_mcp": "open", "other": "open"}
var failStrength = map[string]int{"open": 1, "ask": 2, "closed": 3}

func fallback(agent, event string, payload []byte, reason string, start time.Time, stdout io.Writer, opts Options) int {
	f, ok := formats[agent][event]
	if !ok {
		return 0 // not a decision event: nothing to decide
	}
	var p map[string]any
	_ = json.Unmarshal(payload, &p)
	action, native := actionOf(agent, event, p)
	cwd := str(p["cwd"])
	if cwd == "" {
		cwd = opts.Env.Home
	}
	ctx := intent.Context{Cwd: cwd, Home: opts.Env.Home, RepoRoot: intent.WorkspaceRoot(cwd, opts.Env.Home, platform.GitRoot(cwd)), TempDirs: []string{os.TempDir()}}
	modes := loadFailModes(opts.Env)

	category, mode := "other", modes["other"]
	risk := "none"
	for _, r := range intent.Extract(action, ctx) {
		c := categoryOf(r)
		if m := modes[c]; failStrength[m] > failStrength[mode] {
			category, mode = c, m
		}
		if riskOrder[r.Facts.Risk] > riskOrder[risk] {
			risk = r.Facts.Risk
		}
	}

	verdict := map[string]string{"closed": "deny", "ask": "ask", "open": ""}[mode]
	if verdict == "ask" && !f.ask {
		verdict = "deny"
	}
	message := "Privometry could not reach its daemon (" + strings.ReplaceAll(reason, "_", " ") + "), so it applied the " + mode + " fail mode for " + category + " actions. Run: privometry doctor"
	if verdict != "" {
		io.WriteString(stdout, reply(f.style, event, verdict, message))
	}
	spool(opts, agent, native, action, risk, category, mode, reason, opts.Now().Sub(start))
	return 0
}

var riskOrder = map[string]int{"": 0, "none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

func categoryOf(r intent.Request) string {
	has := func(list []string, s string) bool {
		for _, x := range list {
			if x == s {
				return true
			}
		}
		return false
	}
	switch {
	case has(r.Facts.Category, "catastrophic") || r.Facts.Risk == "critical":
		return "catastrophic"
	case has(r.Facts.Intent, "secret_read"):
		return "secrets"
	case has(r.Facts.Intent, "network_upload"):
		return "exfiltration"
	}
	return "other"
}

// actionOf reads the action from a payload without the adapter definitions.
func actionOf(agent, event string, p map[string]any) (intent.Action, string) {
	native := str(p["session_id"])
	if agent == "cursor" {
		native = str(p["conversation_id"])
	}
	switch event {
	case "beforeShellExecution":
		return intent.Action{Kind: "shell_exec", Command: str(p["command"])}, native
	case "beforeReadFile":
		return intent.Action{Kind: "file_read", Path: str(p["file_path"])}, native
	case "beforeMCPExecution":
		return intent.Action{Kind: "mcp_call", MCPServer: str(p["mcp_server_name"]), MCPTool: str(p["tool_name"])}, native
	}
	tool := str(p["tool_name"])
	in, _ := p["tool_input"].(map[string]any)
	switch {
	case tool == "Bash" || tool == "Shell" || tool == "PowerShell":
		return intent.Action{Kind: "shell_exec", Command: str(in["command"])}, native
	case tool == "Read":
		return intent.Action{Kind: "file_read", Path: str(in["file_path"])}, native
	case tool == "Write" || tool == "Edit" || tool == "NotebookEdit":
		return intent.Action{Kind: "file_write", Path: str(in["file_path"])}, native
	case tool == "Delete":
		return intent.Action{Kind: "file_delete", Path: str(in["file_path"])}, native
	case tool == "WebFetch":
		return intent.Action{Kind: "network_fetch", URL: str(in["url"])}, native
	case strings.HasPrefix(tool, "mcp__") || strings.HasPrefix(tool, "MCP:"):
		return intent.Action{Kind: "mcp_call", MCPTool: tool}, native
	}
	return intent.Action{Kind: "other"}, native
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// reply renders a decision in the agent's native shape.
func reply(style, event, verdict, message string) string {
	var v any
	if style == "cursor" {
		v = map[string]string{"permission": verdict, "user_message": message, "agent_message": message}
	} else {
		v = map[string]any{"hookSpecificOutput": map[string]string{
			"hookEventName": event, "permissionDecision": verdict, "permissionDecisionReason": message}}
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func loadFailModes(env platform.Env) map[string]string {
	modes := map[string]string{}
	for k, v := range defaultFailModes {
		modes[k] = v
	}
	dir, err := env.DataDir()
	if err != nil {
		return modes
	}
	raw, err := os.ReadFile(filepath.Join(dir, failModesFile))
	if err != nil {
		return modes
	}
	var f struct {
		FailModes map[string]string `json:"fail_modes"`
	}
	if json.Unmarshal(raw, &f) == nil {
		for k, v := range f.FailModes {
			if _, ok := failStrength[v]; ok {
				modes[k] = v
			}
		}
	}
	return modes
}

// spool appends a fail_mode event for the daemon to import. Failures are
// ignored: recording must never block the agent.
func spool(opts Options, agent, native string, a intent.Action, risk, category, mode, reason string, elapsed time.Duration) {
	dir, err := opts.Env.DataDir()
	if err != nil || os.MkdirAll(dir, 0o700) != nil {
		return
	}
	target := a.Command + a.Path + a.URL + a.MCPTool
	ev := events.Event{
		Schema: events.EventSchema, EventID: contract.NewID("evt"), Type: events.EventTypeFailMode,
		OccurredAt: contract.At(opts.Now()), User: events.User{LocalUser: os.Getenv("USER")},
		Agent:  &events.Agent{Product: contract.AgentProduct(agent), NativeSessionID: native},
		Action: &events.Action{Kind: contract.ActionKind(a.Kind), Target: redact.Redact(target, redact.Context{Home: opts.Env.Home}), Risk: contract.Risk(orNone(risk))},
		FailMode: &events.FailMode{Reason: events.FailModeReason(reason), Category: contract.RuleCategory(category),
			Mode: contract.FailMode(mode), EvaluatedBy: events.FailModeEvaluatedByHookClient, ElapsedMs: ptr(float64(elapsed.Microseconds()) / 1000)},
		Redaction: map[string]contract.PrivacyLevel{"action.target": contract.PrivacyLevelRedacted, "user.local_user": contract.PrivacyLevelClear},
	}
	if ev.User.LocalUser == "" {
		ev.User.LocalUser = "unknown"
	}
	line, err := json.Marshal(map[string]any{"event": ev, "target_clear": target})
	if err != nil {
		return
	}
	path := filepath.Join(dir, spoolFile)
	if info, err := os.Stat(path); err == nil && info.Size() > maxSpool {
		return // the daemon has been gone a long time; doctor reports it
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(append(line, '\n'))
}

func orNone(r string) string {
	if r == "" {
		return "none"
	}
	return r
}

func ptr[T any](v T) *T { return &v }
