// Package daemon is privometryd: it answers hook calls from privometry-hook, keeps
// per-session state, and records every decision in the local timeline.
package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"gitlab.com/cn-solutions/privometry/privometry-oss/detectorpacks"
	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/content"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/adapters/registry"
	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/buildinfo"
	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/contract"
	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/events"
	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/guard"
	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/ipc"
	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/platform"
	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/policy"
	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/policy/merge"
	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/policy/rulepack"
	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/timeline"
)

// Files in the data directory shared with privometry-hook.
const (
	FailModesFile = "failmodes.json" // written by the daemon, read by privometry-hook
	SpoolFile     = "spool.jsonl"    // appended by privometry-hook, imported by the daemon
	DBFile        = "privometry.db"
)

// Config is what a daemon needs.
type Config struct {
	Env      platform.Env
	Registry *registry.Registry
	Packs    []rulepack.Pack
	// Detectors are the content detector packs; nil means the shipped ones.
	Detectors []*content.Pack
	Logger    *slog.Logger
	Now       func() time.Time // nil means time.Now
}

// Daemon answers hook calls.
type Daemon struct {
	cfg      Config
	dataDir  string
	store    *timeline.Store
	deviceID string
	device   events.Device

	started time.Time

	mu       sync.Mutex
	policies map[string]*cachedPolicy // by repo root; "" is no repo
	recent   map[string]recentCall    // by tool_use_id, for dedupe
	hooked   map[contract.AgentProduct]hookedState
	probes   map[string]time.Time // one-time probe tokens and their expiry

	content     *content.Engine
	roots       map[string]time.Time // workspaces agents worked in, for project memory files
	agentWrites map[string]time.Time // memory files agents were allowed to write, for attribution
	bg          sync.WaitGroup       // background scans
	bgSlots     chan struct{}
}

type hookedState struct {
	stamp string
	on    bool
}

type cachedPolicy struct {
	p     *policy.Policy
	stamp string // policy file mtimes and sizes when loaded
	until time.Time
}

type recentCall struct {
	resp ipc.Response
	at   time.Time
}

// New opens the timeline in the data directory.
func New(cfg Config) (*Daemon, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	dir, err := cfg.Env.DataDir()
	if err != nil {
		return nil, err
	}
	if err := platform.EnsurePrivateDir(dir); err != nil {
		return nil, err
	}
	// launchd and systemd create the log file with their default mode.
	_ = os.Chmod(filepath.Join(dir, "privometryd.log"), 0o600)
	store, err := timeline.Open(filepath.Join(dir, DBFile))
	if err != nil {
		return nil, err
	}
	id, err := store.DeviceID()
	if err != nil {
		store.Close()
		return nil, err
	}
	if cfg.Detectors == nil {
		if cfg.Detectors, err = content.Load(detectorpacks.FS); err != nil {
			store.Close()
			return nil, err
		}
	}
	salt, err := contentSalt(store.State, store.SetState)
	if err != nil {
		store.Close()
		return nil, err
	}
	d := &Daemon{cfg: cfg, dataDir: dir, store: store, deviceID: id, started: cfg.Now(),
		policies: map[string]*cachedPolicy{}, recent: map[string]recentCall{}, hooked: map[contract.AgentProduct]hookedState{},
		content: content.New(cfg.Detectors, content.Options{Salt: salt}), bgSlots: make(chan struct{}, 2),
		roots: map[string]time.Time{}, agentWrites: map[string]time.Time{}}
	d.device = events.Device{DeviceID: id, OS: contract.OS(cfg.Env.OS()), OSVersion: osVersion(), Arch: arch(), SensorVersion: sensorVersion()}
	if _, err := d.policyFor(""); err != nil {
		d.cfg.Logger.Warn("baseline policy failed to load", "err", err)
	}
	return d, nil
}

// Close waits for background scans and closes the timeline.
func (d *Daemon) Close() error {
	d.bg.Wait()
	return d.store.Close()
}

// Wait blocks until background scans finish, for tests.
func (d *Daemon) Wait() { d.bg.Wait() }

// Store exposes the timeline, for tests and the CLI.
func (d *Daemon) Store() *timeline.Store { return d.store }

// Run listens on the IPC socket until ctx ends, importing the hook client's
// spool and pruning old rows in the background.
func (d *Daemon) Run(ctx context.Context) error {
	release, err := lock(d.dataDir)
	if err != nil {
		return err
	}
	defer release()
	addr, err := d.cfg.Env.IPCAddress()
	if err != nil {
		return err
	}
	l, err := ipc.Listen(addr)
	if err != nil {
		return err
	}
	d.cfg.Logger.Info("privometryd listening", "socket", addr, "version", buildinfo.Version)
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	go d.housekeeping(ctx)
	err = ipc.Serve(l, d.Handle, 5*time.Second)
	os.Remove(addr)
	return err
}

func (d *Daemon) housekeeping(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	lastPrune := time.Time{}
	for {
		if _, err := d.CheckIntegrity(); err != nil {
			d.cfg.Logger.Warn("integrity check failed", "err", err)
		}
		if _, err := d.CheckMemory(); err != nil {
			d.cfg.Logger.Warn("memory check failed", "err", err)
		}
		if n, err := d.ImportSpool(); err != nil {
			d.cfg.Logger.Warn("spool import failed", "err", err)
		} else if n > 0 {
			d.cfg.Logger.Info("imported fail-mode events", "count", n)
		}
		if now := d.cfg.Now(); now.Sub(lastPrune) > 24*time.Hour {
			if _, err := d.store.Prune(now.Add(-30*24*time.Hour), now.Add(-7*24*time.Hour)); err != nil {
				d.cfg.Logger.Warn("prune failed", "err", err)
			}
			lastPrune = now
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Handle answers one IPC request.
func (d *Daemon) Handle(req ipc.Request) ipc.Response {
	switch req.Op {
	case "ping":
		return ipc.Response{OK: true}
	case "status":
		st, err := d.Status()
		if err != nil {
			return ipc.Response{Error: err.Error()}
		}
		data, _ := json.Marshal(st)
		return ipc.Response{OK: true, Data: data}
	case "events":
		var q timeline.Query
		if len(req.Query) > 0 {
			if err := json.Unmarshal(req.Query, &q); err != nil {
				return ipc.Response{Error: "bad query: " + err.Error()}
			}
		}
		rows, err := d.store.Events(q)
		if err != nil {
			return ipc.Response{Error: err.Error()}
		}
		if rows == nil {
			rows = []timeline.Row{}
		}
		data, _ := json.Marshal(rows)
		return ipc.Response{OK: true, Data: data}
	case "probe":
		data, _ := json.Marshal(map[string]string{"token": d.newProbe()})
		return ipc.Response{OK: true, Data: data}
	case "hook":
		if req.Hook == nil {
			return ipc.Response{Error: "hook request without hook"}
		}
		resp, err := d.hook(*req.Hook)
		if err != nil {
			d.cfg.Logger.Error("hook failed", "agent", req.Hook.Agent, "event", req.Hook.Event, "err", err)
			return ipc.Response{Error: err.Error()}
		}
		resp.OK = true
		return resp
	}
	return ipc.Response{Error: fmt.Sprintf("unknown op %q", req.Op)}
}

// Ops are the IPC operations this build answers. A CLI newer than the
// running daemon finds the ones it needs missing and asks for a restart.
var Ops = []string{"ping", "status", "events", "hook", "probe"}

// Status is what "privometry daemon status" shows.
type Status struct {
	Version   string                   `json:"version"`
	Ops       []string                 `json:"ops"`
	PID       int                      `json:"pid"`
	StartedAt contract.Time            `json:"started_at"`
	DataDir   string                   `json:"data_dir"`
	DeviceID  string                   `json:"device_id"`
	Policies  int                      `json:"policies_cached"`
	Agents    []timeline.AgentActivity `json:"agents"`
}

// Status reports the daemon's state and each agent's hook activity.
func (d *Daemon) Status() (Status, error) {
	agents, err := d.store.Activity()
	if err != nil {
		return Status{}, err
	}
	d.mu.Lock()
	n := len(d.policies)
	d.mu.Unlock()
	return Status{Version: buildinfo.Version, Ops: Ops, PID: os.Getpid(), StartedAt: contract.At(d.started), DataDir: d.dataDir,
		DeviceID: d.deviceID, Policies: n, Agents: agents}, nil
}

// policyFor returns the merged policy for a repo: shipped packs, the user
// policy and the repo policy. It is reloaded when either file changes, and at
// the next exception expiry.
func (d *Daemon) policyFor(repoRoot string) (*policy.Policy, error) {
	stamp := stampOf(d.cfg.Env.Home, repoRoot)
	d.mu.Lock()
	c, ok := d.policies[repoRoot]
	d.mu.Unlock()
	now := d.cfg.Now()
	if ok && c.stamp == stamp && (c.until.IsZero() || now.Before(c.until)) {
		return c.p, nil
	}
	sources, errs := policy.LocalSources(d.cfg.Env.Home, repoRoot)
	for _, err := range errs {
		d.cfg.Logger.Warn("policy file ignored", "err", err)
	}
	in := merge.Input{Packs: d.cfg.Packs, Policies: sources, Now: now}
	res, err := merge.Merge(in)
	if err != nil {
		return nil, err
	}
	for _, diag := range res.Diagnostics {
		d.cfg.Logger.Warn("policy diagnostic", "layer", diag.Layer, "source", diag.Source, "message", diag.Message)
	}
	p, err := policy.New(res)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.policies[repoRoot] = &cachedPolicy{p: p, stamp: stamp, until: merge.NextExpiry(in)}
	d.mu.Unlock()
	if repoRoot == "" {
		d.writeFailModes(res)
	}
	return p, nil
}

func stampOf(home, repoRoot string) string {
	var s string
	for _, p := range []string{filepath.Join(home, policy.UserPolicyPath), filepath.Join(repoRoot, policy.RepoPolicyPath)} {
		if info, err := os.Stat(p); err == nil {
			s += fmt.Sprintf("%s:%d:%d;", p, info.ModTime().UnixNano(), info.Size())
		}
	}
	return s
}

// FailModes is the file privometry-hook reads to decide alone when the daemon is
// unreachable.
type FailModes struct {
	UpdatedAt contract.Time                `json:"updated_at"`
	FailModes map[string]contract.FailMode `json:"fail_modes"`
}

func (d *Daemon) writeFailModes(res *merge.Result) {
	b, _ := json.MarshalIndent(FailModes{UpdatedAt: contract.At(d.cfg.Now()), FailModes: res.FailModes}, "", "  ")
	tmp := filepath.Join(d.dataDir, FailModesFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		err = os.Rename(tmp, filepath.Join(d.dataDir, FailModesFile))
		if err != nil {
			d.cfg.Logger.Warn("could not write fail modes", "err", err)
		}
	}
}

// hookedNatively reports whether an agent has its own Privometry hook installed,
// cached until its hook file changes.
func (d *Daemon) hookedNatively(agent contract.AgentProduct) bool {
	a, ok := d.cfg.Registry.Get(agent)
	if !ok {
		return false
	}
	stamp := ""
	if paths, err := a.Paths(a.Hooks.Install.Free.Paths, d.cfg.Env, ""); err == nil && len(paths) > 0 {
		if info, err := os.Stat(paths[0]); err == nil {
			stamp = fmt.Sprintf("%d:%d", info.ModTime().UnixNano(), info.Size())
		}
	}
	d.mu.Lock()
	h, ok := d.hooked[agent]
	d.mu.Unlock()
	if ok && h.stamp == stamp {
		return h.on
	}
	on := stamp != "" && guard.Installed(a, guard.Options{Env: d.cfg.Env})
	d.mu.Lock()
	d.hooked[agent] = hookedState{stamp: stamp, on: on}
	d.mu.Unlock()
	return on
}

// remember caches a hook response by tool_use_id for two minutes, so the same
// tool call reported through two hook sources (Cursor runs Claude Code hooks
// too) is decided and recorded once.
// probeTTL is how long a probe token stays valid.
const probeTTL = 30 * time.Second

func (d *Daemon) newProbe() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	tok := hex.EncodeToString(b)
	now := d.cfg.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.probes == nil {
		d.probes = map[string]time.Time{}
	}
	for t, exp := range d.probes {
		if now.After(exp) {
			delete(d.probes, t)
		}
	}
	d.probes[tok] = now.Add(probeTTL)
	return tok
}

// takeProbe consumes a probe token, reporting whether it was valid.
func (d *Daemon) takeProbe(tok string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	exp, ok := d.probes[tok]
	delete(d.probes, tok)
	return ok && !d.cfg.Now().After(exp)
}

func (d *Daemon) remember(id string, resp ipc.Response) {
	if id == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.cfg.Now()
	for k, v := range d.recent {
		if now.Sub(v.at) > 2*time.Minute {
			delete(d.recent, k)
		}
	}
	d.recent[id] = recentCall{resp: resp, at: now}
}

func (d *Daemon) recalled(id string) (ipc.Response, bool) {
	if id == "" {
		return ipc.Response{}, false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	r, ok := d.recent[id]
	if !ok || d.cfg.Now().Sub(r.at) > 2*time.Minute {
		return ipc.Response{}, false
	}
	return r.resp, true
}

func arch() contract.Arch {
	switch runtime.GOARCH {
	case "amd64", "arm64":
		return contract.Arch(runtime.GOARCH)
	}
	return contract.ArchOther
}

func sensorVersion() string {
	if v := buildinfo.Version; v != "dev" && registry.ParseVersion(v) == v {
		return v
	}
	return "0.0.0-dev"
}

var errUnknownAgent = errors.New("unknown agent")
