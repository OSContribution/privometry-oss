package daemon

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/adapters/registry"
	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/contract"
	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/events"
)

// bypassEvery is how often running agents are checked for bypass flags.
const bypassEvery = 5 * time.Minute

// runtimes start an agent that is a script; the agent is the next argument.
var runtimes = []string{"node", "bun", "deno", "python", "python3"}

// CheckBypass looks for running agents started with one of their adapter's
// bypass_flags (a flag that skips permission prompts or hooks) and records an
// integrity event the first time each agent and flag is seen running, again
// after it stopped. Command lines are read in memory and dropped; only the
// agent and the flag are kept. It returns how many events it recorded.
func (d *Daemon) CheckBypass() (int, error) {
	procs, err := d.cfg.ProcessArgs()
	if err != nil {
		return 0, err
	}
	now := map[string]bool{}
	n := 0
	for _, args := range procs {
		a, ok := d.agentOf(args)
		if !ok {
			continue
		}
		flag := bypassFlag(args, a.Detect.BypassFlags)
		if flag == "" {
			continue
		}
		key := string(a.Agent) + " " + flag
		if d.bypassSeen[key] || now[key] {
			now[key] = true
			continue
		}
		now[key] = true
		if err := d.recordBypass(a, flag); err != nil {
			return n, err
		}
		n++
	}
	d.bypassSeen = now
	return n, nil
}

// agentOf finds the adapter whose process or binary name runs args.
func (d *Daemon) agentOf(args []string) (registry.Adapter, bool) {
	prog := progName(args[0])
	if slices.Contains(runtimes, prog) && len(args) > 1 {
		prog = progName(args[1])
	}
	for _, a := range d.cfg.Registry.All() {
		if len(a.Detect.BypassFlags) == 0 {
			continue
		}
		for _, name := range append(slices.Clone(a.Detect.Processes), a.Detect.Binaries...) {
			if strings.EqualFold(prog, name) {
				return a, true
			}
		}
	}
	return registry.Adapter{}, false
}

func progName(p string) string {
	base := p[strings.LastIndexAny(p, `/\`)+1:]
	switch ext := filepath.Ext(base); strings.ToLower(ext) {
	case ".exe", ".js", ".mjs", ".cjs":
		base = strings.TrimSuffix(base, ext)
	}
	return base
}

// bypassFlag returns the first of flags that args carries. An entry with a
// value ("--approval-mode yolo") matches the value as the next argument or
// after "=".
func bypassFlag(args, flags []string) string {
	for _, f := range flags {
		name, value, withValue := strings.Cut(f, " ")
		for i, a := range args[1:] {
			switch {
			case !withValue && a == name:
				return f
			case withValue && a == name+"="+value:
				return f
			case withValue && a == name && i+2 < len(args) && args[i+2] == value:
				return f
			}
		}
	}
	return ""
}

func (d *Daemon) recordBypass(a registry.Adapter, flag string) error {
	what := "skips its permission prompts"
	if a.Agent == contract.AgentProductAntigravity {
		what = "turns its hooks off, so Privometry neither sees nor decides what it does"
	}
	in := &events.Integrity{Check: events.IntegrityCheckHooksBypassed, AgentProduct: a.Agent,
		Detail: fmt.Sprintf("%s is running with %s, which %s.", a.DisplayName, flag, what)}
	ev := &events.Event{Schema: events.EventSchema, EventID: contract.NewID("evt"), Type: events.EventTypeIntegrity,
		OccurredAt: contract.At(d.cfg.Now()), Device: d.device, User: events.User{LocalUser: localUser()}, Integrity: in,
		Redaction: map[string]contract.PrivacyLevel{"user.local_user": contract.PrivacyLevelClear}}
	d.cfg.Logger.Warn("agent running in bypass mode", "agent", a.Agent, "flag", flag)
	return d.appendEvent(ev, "")
}
