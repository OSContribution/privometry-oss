package daemon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/adapters/registry"
	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/contract"
	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/events"
	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/ipc"
	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/platform"
	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/policy"
	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/policy/engine"
	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/policy/intent"
	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/redact"
	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/scanner/parsers"
)

// call is one hook invocation, with payload fields read through the
// adapter's request pointers.
type call struct {
	adapter registry.Adapter
	event   registry.HookEvent
	product contract.AgentProduct // may differ from the adapter when another agent imports its hooks
	payload any
	field   func(name string) any
	probe   bool // decide, but record nothing (privometry doctor)
}

func (c call) str(name string) string {
	v := c.field(name)
	if s, ok := v.(string); ok {
		return s
	}
	if v == nil {
		return ""
	}
	if b, err := json.Marshal(v); err == nil {
		return string(b)
	}
	return ""
}

func (d *Daemon) hook(h ipc.HookRequest) (ipc.Response, error) {
	a, ok := d.cfg.Registry.Get(contract.AgentProduct(h.Agent))
	if !ok {
		return ipc.Response{}, fmt.Errorf("%w %q", errUnknownAgent, h.Agent)
	}
	ev, ok := a.Event(h.Event)
	if !ok {
		return ipc.Response{}, nil // not an event Privometry handles: no opinion
	}
	dec := json.NewDecoder(bytes.NewReader(h.Payload))
	dec.UseNumber()
	var payload any
	if err := dec.Decode(&payload); err != nil {
		return ipc.Response{}, fmt.Errorf("payload: %w", err)
	}
	c := call{adapter: a, event: ev, product: a.Agent, payload: payload}
	c.field = func(name string) any {
		if ptr, ok := ev.Request[name]; ok {
			return parsers.Lookup(payload, ptr)
		}
		return nil
	}
	c.product = d.caller(a, payload)
	if h.Probe != "" && d.takeProbe(h.Probe) {
		c.probe = true
		switch ev.Role {
		case registry.HookEventRolePreTool, registry.HookEventRolePreShell, registry.HookEventRolePreMCP, registry.HookEventRolePreFileRead:
			return d.decide(c)
		}
		return none(ev), nil
	}
	if c.product != a.Agent && d.hookedNatively(c.product) {
		// Cursor runs Claude Code's hooks too. When Cursor has its own Privometry
		// hook, that one decides; this imported call gives no opinion.
		return none(ev), nil
	}

	switch ev.Role {
	case registry.HookEventRolePreTool, registry.HookEventRolePreShell, registry.HookEventRolePreMCP, registry.HookEventRolePreFileRead:
		return d.decide(c)
	case registry.HookEventRolePostTool:
		return d.postTool(c)
	case registry.HookEventRoleSessionStart:
		_, err := d.session(c)
		return none(ev), err
	case registry.HookEventRoleSessionEnd:
		s, err := d.session(c)
		if err == nil {
			err = d.store.EndSession(s.ID, d.cfg.Now())
		}
		return none(ev), err
	case registry.HookEventRolePromptSubmit:
		return none(ev), d.promptSubmit(c)
	case registry.HookEventRoleConfigChange:
		return none(ev), d.configChange(c)
	}
	return none(ev), nil
}

// promptSubmit records that a user query entered an agent session without
// persisting the raw prompt. The keyed fingerprint permits local correlation
// while preventing offline guessing if an event database is copied.
func (d *Daemon) promptSubmit(c call) error {
	sess, err := d.session(c)
	if err != nil {
		return err
	}
	prompt := c.str("prompt")
	chars := int64(utf8.RuneCountInString(prompt))
	ev := &events.Event{
		Schema: events.EventSchema, EventID: contract.NewID("evt"), Type: events.EventTypePrompt,
		OccurredAt: contract.At(d.cfg.Now()), Device: d.device, User: events.User{LocalUser: localUser()},
		Agent: &events.Agent{Product: c.product, Version: c.str("agent_version"), SessionID: sess.ID,
			NativeSessionID: sess.Native, Pattern: events.AgentPatternInteractive},
		Prompt: &events.Prompt{PromptID: c.str("prompt_id"), Fingerprint: d.content.Hash(prompt), Characters: chars},
		Redaction: map[string]contract.PrivacyLevel{
			"prompt.fingerprint": contract.PrivacyLevelHashed,
			"user.local_user":    contract.PrivacyLevelClear,
		},
	}
	if remote := remoteOf(sess); remote != "" {
		ev.Repo = &events.Repo{Remote: remote}
	}
	return d.store.Append(ev, fmt.Sprintf("Query submitted (%d characters)", chars))
}

// caller detects another agent running this agent's hooks, from the payload
// markers in that agent's definition.
func (d *Daemon) caller(a registry.Adapter, payload any) contract.AgentProduct {
	for _, other := range a.Hooks.ImportedBy {
		o, ok := d.cfg.Registry.Get(other.Agent)
		if !ok {
			continue
		}
		for _, ptr := range o.Hooks.PayloadMarkers {
			if parsers.Lookup(payload, ptr) != nil {
				return o.Agent
			}
		}
	}
	return a.Agent
}

func none(ev registry.HookEvent) ipc.Response {
	r, ok := ev.Responses["none"]
	if !ok {
		return ipc.Response{}
	}
	out, _ := render(r, "")
	return out
}

func (d *Daemon) session(c call) (*sessionInfo, error) {
	native := c.str("session_id")
	if native == "" {
		native = "unknown"
	}
	cwd := c.str("cwd")
	git := platform.GitRoot(cwd)
	s, err := d.store.Session(string(c.product), native, platform.GitRemote(git), d.cfg.Now())
	if err != nil {
		return nil, err
	}
	info := &sessionInfo{ID: s.ID, Native: native, Untrusted: s.UntrustedInputSeen, Sources: s.UntrustedSources, Injected: s.InjectionSeen,
		Cwd: cwd, Git: git, Root: intent.WorkspaceRoot(cwd, d.cfg.Env.Home, git)}
	d.noteRoot(info.Root)
	return info, nil
}

func remoteOf(s *sessionInfo) string { return platform.GitRemote(s.Git) }

type sessionInfo struct {
	ID, Native, Cwd string
	Git             string // git root, for the repo policy and remote
	Root            string // workspace root: git root, or the working folder
	Untrusted       bool
	Sources         []string
	Injected        bool // the session read injected instructions
}

// actions turns a pre-decision hook into intent actions. apply_patch style
// tools yield one write per file in the patch.
func (c call) actions() (toolName string, out []intent.Action) {
	switch c.event.Role {
	case registry.HookEventRolePreShell:
		return "Shell", []intent.Action{{Kind: "shell_exec", Command: c.str("command")}}
	case registry.HookEventRolePreFileRead:
		return "Read", []intent.Action{{Kind: "file_read", Path: c.str("file_path")}}
	case registry.HookEventRolePreMCP:
		server, tool := c.str("mcp_server"), c.str("tool_name")
		if s, t, ok := c.adapter.MCPTool(tool); ok {
			tool = t
			if server == "" {
				server = s
			}
		}
		return c.str("tool_name"), []intent.Action{{Kind: "mcp_call", MCPServer: server, MCPTool: tool}}
	}
	toolName = c.str("tool_name")
	kind := c.adapter.ToolKind(toolName)
	input := c.field("tool_input")
	target, _ := c.adapter.ToolTarget(toolName)
	get := func(ptr string) string {
		if ptr == "" {
			return ""
		}
		s, _ := parsers.Lookup(input, ptr).(string)
		return s
	}
	switch kind {
	case "shell_exec":
		return toolName, []intent.Action{{Kind: kind, Command: get(target.Command)}}
	case "file_read", "file_write", "file_delete":
		if target.Patch != "" {
			for _, p := range patchFiles(get(target.Patch)) {
				out = append(out, intent.Action{Kind: "file_write", Path: p})
			}
			if len(out) > 0 {
				return toolName, out
			}
		}
		return toolName, []intent.Action{{Kind: kind, Path: get(target.Path)}}
	case "network_fetch":
		return toolName, []intent.Action{{Kind: kind, URL: get(target.URL)}}
	case "mcp_call":
		server, tool, _ := c.adapter.MCPTool(toolName)
		if s := c.str("mcp_server"); s != "" {
			server = s
		}
		return toolName, []intent.Action{{Kind: kind, MCPServer: server, MCPTool: tool}}
	}
	return toolName, []intent.Action{{Kind: kind}}
}

// patchFiles lists the files an apply_patch body touches.
func patchFiles(patch string) []string {
	var out []string
	for _, line := range strings.Split(patch, "\n") {
		for _, prefix := range []string{"*** Update File: ", "*** Add File: ", "*** Delete File: ", "*** Move to: "} {
			if p, ok := strings.CutPrefix(line, prefix); ok {
				out = append(out, strings.TrimSpace(p))
			}
		}
	}
	return out
}

func (d *Daemon) decide(c call) (ipc.Response, error) {
	start := time.Now()
	useID := c.str("tool_use_id")
	if resp, ok := d.recalled(useID); ok && !c.probe {
		return resp, nil
	}
	var sess *sessionInfo
	var err error
	if c.probe {
		cwd := c.str("cwd")
		git := platform.GitRoot(cwd)
		sess = &sessionInfo{Cwd: cwd, Git: git, Root: intent.WorkspaceRoot(cwd, d.cfg.Env.Home, git)}
	} else if sess, err = d.session(c); err != nil {
		return ipc.Response{}, err
	}
	p, err := d.policyFor(sess.Git)
	if err != nil {
		return ipc.Response{}, err
	}
	cwd := sess.Cwd
	if cwd == "" {
		cwd = d.cfg.Env.Home
	}
	ctx := intent.Context{Cwd: cwd, Home: d.cfg.Env.Home, RepoRoot: sess.Root, TempDirs: []string{os.TempDir()}}
	remote := remoteOf(sess)
	toolName, actions := c.actions()
	pieces := c.pieces(actions)
	hits, complete := d.scanPieces(pieces, time.Now().Add(contentBudget))
	sum := summarize(hits)
	found := policy.Content{SecretTypes: sum.SecretTypes, Injection: sum.Injection, HiddenContent: sum.HiddenContent}

	var best policy.Decision
	var bestAction intent.Action
	for i, a := range actions {
		dec, err := p.Decide(policy.Input{
			Agent: engine.Agent{Product: string(c.product), Version: c.str("agent_version"), Pattern: "interactive"},
			Repo:  remote, Action: a, Context: ctx, UntrustedInputSeen: sess.Untrusted, InjectionSeen: sess.Injected, Content: found})
		if err != nil {
			return ipc.Response{}, err
		}
		if i == 0 || strength[dec.Verdict] > strength[best.Verdict] {
			best, bestAction = dec, a
		}
	}

	native := best.Verdict
	if !hasVerdict(c.event, native) {
		native = string(c.event.Fallback[native])
		if native == "" {
			native = "deny"
		}
	}
	message := messageFor(best)
	tpl, ok := c.event.Responses[native]
	if !ok {
		return ipc.Response{}, fmt.Errorf("adapter %s event %s has no %s reply", c.adapter.Agent, c.event.Name, native)
	}
	resp, err := render(tpl, message)
	if err != nil {
		return ipc.Response{}, err
	}
	resp.Verdict = best.Verdict

	if c.probe {
		return resp, nil
	}
	if best.Verdict != "deny" {
		d.noteMemoryWrites(actions, ctx)
	}
	ev := d.actionEvent(c, sess, toolName, useID, bestAction, best, native, remote, time.Since(start))
	ev.Action.SecretTypes = sum.SecretTypes
	target := targetOf(bestAction)
	if err := d.store.Append(ev, target); err != nil {
		return ipc.Response{}, err
	}
	d.recordFindings(c, sess, ev.Action, ev.MCP, remote, hits, pieces, actionTaken(best.Verdict))
	if !complete {
		// Out of time before deciding: finish after the reply and raise
		// whatever the first pass missed.
		action, mcp := ev.Action, ev.MCP
		d.background(func() {
			all, _ := d.scanPieces(pieces, time.Time{})
			var rest []hit
			for _, h := range all {
				if !slices.ContainsFunc(hits, func(x hit) bool { return x.piece == h.piece && x.DetectorID == h.DetectorID && x.Start == h.Start }) {
					rest = append(rest, h)
				}
			}
			d.recordFindings(c, sess, action, mcp, remote, rest, pieces, events.ContentFindingActionTakenNone)
		})
	}
	resp.EventID = ev.EventID
	d.remember(useID, resp)
	return resp, nil
}

var strength = map[string]int{"allow": 1, "ask": 2, "deny": 3}

func hasVerdict(ev registry.HookEvent, v string) bool {
	for _, x := range ev.Verdicts {
		if string(x) == v {
			return true
		}
	}
	return false
}

// messageFor is the one line the agent shows the developer.
func messageFor(d policy.Decision) string {
	switch {
	case d.Verdict == "allow" && d.Source == "auto_approve":
		return "Privometry auto-approved: " + d.Reason
	case d.Verdict == "allow":
		return "Privometry allowed by " + strings.Join(d.RuleIDs, ", ")
	case len(d.RuleIDs) > 0:
		return fmt.Sprintf("Privometry: %s (%s)", d.Message, d.RuleIDs[0])
	}
	return d.Message // "Privometry asks because this ..."
}

func targetOf(a intent.Action) string {
	switch {
	case a.Command != "":
		return a.Command
	case a.Path != "":
		return a.Path
	case a.URL != "":
		return a.URL
	}
	return strings.Trim(a.MCPServer+"/"+a.MCPTool, "/")
}

// Render fills a reply template's strings with the message. Exported so the
// hook client's built-in fallback replies can be tested against it.
func Render(tpl registry.Response, message string) (ipc.Response, error) { return render(tpl, message) }

// render fills a reply template's strings with the message.
func render(tpl registry.Response, message string) (ipc.Response, error) {
	resp := ipc.Response{ExitCode: int(tpl.ExitCode), Stderr: strings.ReplaceAll(tpl.Stderr, "{message}", message)}
	if tpl.Stdout == nil {
		return resp, nil
	}
	out, err := json.Marshal(fill(tpl.Stdout, message))
	if err != nil {
		return resp, err
	}
	resp.Stdout = string(out)
	return resp, nil
}

func fill(v any, message string) any {
	switch x := v.(type) {
	case string:
		return strings.ReplaceAll(x, "{message}", message)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = fill(e, message)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = fill(e, message)
		}
		return out
	}
	return v
}

// postTool marks the session when untrusted content entered it, and scans
// the tool's output for injected instructions and credentials.
func (d *Daemon) postTool(c call) (ipc.Response, error) {
	sess, err := d.session(c)
	if err != nil {
		return ipc.Response{}, err
	}
	toolName := c.str("tool_name")
	d.scanOutput(c, sess, toolName)
	if k := c.adapter.ToolKind(toolName); k == "file_write" || k == "file_delete" {
		_, actions := c.actions()
		for _, p := range d.memoryTargets(actions, sess) {
			d.memoryWritten(c, p)
		}
	}
	if source := untrustedSource(c); source != "" {
		return none(c.event), d.store.MarkUntrusted(sess.ID, source)
	}
	return none(c.event), nil
}

// untrustedSource names the kind of untrusted content a finished tool call
// brought into the session, or "" for none. Reading the repo's own files is
// not counted, so the flag stays meaningful.
func untrustedSource(c call) string {
	tool := c.str("tool_name")
	switch c.adapter.ToolKind(tool) {
	case "network_fetch", "web_search":
		return "web_fetch"
	case "mcp_call":
		return "mcp_response"
	case "shell_exec":
		target, _ := c.adapter.ToolTarget(tool)
		cmd, _ := parsers.Lookup(c.field("tool_input"), target.Command).(string)
		cmds, _ := intent.ParseShell(cmd)
		for _, x := range cmds {
			switch {
			case x.Program == "curl" || x.Program == "wget" || x.Program == "http":
				return "web_fetch"
			case x.Program == "gh" && (strings.HasPrefix(x.Subcommand, "issue view") || strings.HasPrefix(x.Subcommand, "pr view") ||
				strings.HasPrefix(x.Subcommand, "api") || strings.HasPrefix(x.Subcommand, "issue list") || strings.HasPrefix(x.Subcommand, "pr diff")):
				return "issue_or_pr_text"
			}
		}
	}
	return ""
}

// actionEvent builds the privometry.event/v1 record of a decision.
func (d *Daemon) actionEvent(c call, sess *sessionInfo, toolName, useID string, a intent.Action, dec policy.Decision,
	native, remote string, latency time.Duration) *events.Event {
	ctx := redact.Context{Home: d.cfg.Env.Home, RepoRoot: sess.Root}
	f := dec.Facts
	action := &events.Action{Kind: contract.ActionKind(a.Kind), ToolName: toolName, ToolUseID: useID,
		Target: redact.Redact(targetOf(a), ctx), PathClass: contract.PathClass(f.PathClass), Risk: contract.Risk(orNone(f.Risk))}
	for _, i := range f.Intent {
		action.Intent = append(action.Intent, contract.Intent(i))
	}
	for _, cat := range f.Category {
		action.Categories = append(action.Categories, contract.RuleCategory(cat))
	}
	decision := &events.Decision{Verdict: contract.Verdict(dec.Verdict), Source: events.DecisionSource(dec.Source),
		Mode: events.DecisionModeEnforce, RuleIDs: dec.RuleIDs, LatencyMs: float64(latency.Microseconds()) / 1000}
	if dec.WouldVerdict != "" {
		decision.WouldVerdict = contract.Verdict(dec.WouldVerdict)
		if len(dec.RuleIDs) == 0 && dec.Verdict == "allow" {
			decision.Mode = events.DecisionModeMonitor
		}
	}
	if native != dec.Verdict {
		decision.NativeVerdict = contract.Verdict(native)
	}
	untrustedSeen := sess.Untrusted
	var sources []events.ContextUntrustedSource
	for _, s := range sess.Sources {
		sources = append(sources, events.ContextUntrustedSource(s))
	}
	ev := &events.Event{
		Schema: events.EventSchema, EventID: contract.NewID("evt"), Type: events.EventTypeAction,
		OccurredAt: contract.At(d.cfg.Now()), Device: d.device,
		User:   events.User{LocalUser: localUser()},
		Agent:  &events.Agent{Product: c.product, Version: c.str("agent_version"), SessionID: sess.ID, NativeSessionID: sess.Native, Pattern: events.AgentPatternInteractive},
		Action: action, Decision: decision,
		Context:   &events.Context{UntrustedInputSeen: untrustedSeen, UntrustedSources: sources, CwdScope: cwdScope(sess, d.cfg.Env.Home), InjectionSeen: injected(sess)},
		Redaction: map[string]contract.PrivacyLevel{"action.target": contract.PrivacyLevelRedacted, "user.local_user": contract.PrivacyLevelClear},
		// Why: shown by the timeline. Messages and reasons hold no targets.
		Ext: map[string]any{"x_privometry_reason": dec.Reason, "x_privometry_message": messageFor(dec)},
	}
	if remote != "" {
		ev.Repo = &events.Repo{Remote: remote}
	}
	ev.MCP = mcpOf(a)
	return ev
}

// mcpOf is the event's mcp section for an MCP call, else nil.
func mcpOf(a intent.Action) *events.MCP {
	if a.Kind != "mcp_call" {
		return nil
	}
	m := &events.MCP{ServerName: a.MCPServer, Transport: events.MCPTransportStdio, Tool: a.MCPTool, CatalogStatus: contract.CatalogStatusUnknown}
	if m.ServerName == "" {
		m.ServerName = "unknown"
	}
	return m
}

// injected is the event's injection_seen, set only when true.
func injected(s *sessionInfo) *bool {
	if !s.Injected {
		return nil
	}
	t := true
	return &t
}

func orNone(r string) string {
	if r == "" {
		return "none"
	}
	return r
}

func cwdScope(s *sessionInfo, home string) events.ContextCwdScope {
	switch {
	case s.Root != "":
		return events.ContextCwdScopeRepo
	case s.Cwd == home || strings.HasPrefix(s.Cwd, home+"/"):
		return events.ContextCwdScopeHome
	case s.Cwd == "/" || strings.HasPrefix(s.Cwd, "/etc") || strings.HasPrefix(s.Cwd, "/usr"):
		return events.ContextCwdScopeSystem
	}
	return events.ContextCwdScopeOther
}

func localUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u := os.Getenv("USERNAME"); u != "" {
		return u
	}
	return "unknown"
}

// configChange records a config_change event from the agent's own hook.
func (d *Daemon) configChange(c call) error {
	sess, err := d.session(c)
	if err != nil {
		return err
	}
	tier := contract.ConfigTierUser
	switch c.str("config_source") {
	case "project_settings", "local_settings":
		tier = contract.ConfigTierProject
	case "policy_settings":
		tier = contract.ConfigTierManaged
	}
	holds := events.ConfigHoldSettings
	if c.str("config_source") == "skills" {
		holds = events.ConfigHoldSkills
	}
	path := c.str("config_path")
	if path == "" {
		path = "unknown"
	}
	ev := &events.Event{
		Schema: events.EventSchema, EventID: contract.NewID("evt"), Type: events.EventTypeConfigChange,
		OccurredAt: contract.At(d.cfg.Now()), Device: d.device, User: events.User{LocalUser: localUser()},
		Agent: &events.Agent{Product: c.product, SessionID: sess.ID, NativeSessionID: sess.Native},
		Config: &events.Config{Change: events.ConfigChangeModified, Tier: tier, Path: redact.Redact(path, redact.Context{Home: d.cfg.Env.Home, RepoRoot: sess.Root}),
			Holds: []events.ConfigHold{holds}, DetectedBy: events.ConfigDetectedByAgentHook},
		Redaction: map[string]contract.PrivacyLevel{"config.path": contract.PrivacyLevelRedacted, "user.local_user": contract.PrivacyLevelClear},
	}
	return d.store.Append(ev, path)
}
