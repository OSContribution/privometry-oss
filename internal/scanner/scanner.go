// Package scanner runs a full scan: discovery, posture checks, content scans
// of memory files, skills and configs, and the result that reports render.
// See internal/scanner/report for output formats.
package scanner

import (
	"bufio"
	"os"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/privometry/privometry-oss/detectorpacks"
	"github.com/privometry/privometry-oss/internal/adapters/registry"
	"github.com/privometry/privometry-oss/internal/buildinfo"
	"github.com/privometry/privometry-oss/internal/content"
	"github.com/privometry/privometry-oss/internal/contract"
	"github.com/privometry/privometry-oss/internal/scanner/discover"
	"github.com/privometry/privometry-oss/internal/scanner/parsers"
	"github.com/privometry/privometry-oss/internal/scanner/posture"
)

// ResultSchema identifies the JSON report. It is v0 until the scan report has
// its own spec (before the GitHub Action in M6); fields may still change.
const ResultSchema = "privometry.scan/v0"

// Result is one scan.
type Result struct {
	Schema        string            `json:"schema"`
	ScannedAt     contract.Time     `json:"scanned_at"`
	SensorVersion string            `json:"sensor_version"`
	OS            string            `json:"os"`
	Arch          string            `json:"arch"`
	Machine       bool              `json:"machine"`
	Repo          string            `json:"repo,omitempty"`
	Agents        []discover.Agent  `json:"agents"`
	Findings      []posture.Finding `json:"findings"`
	// ContentFindings are content detector hits in memory and instruction
	// files, skills and agent configs (PRD SCAN-05 to SCAN-07).
	ContentFindings []ContentFinding `json:"content_findings"`
	Summary         map[string]int   `json:"summary"`
}

// ContentFinding is one detector hit in a file at rest. The excerpt masks
// credentials; it is shown to the developer and never uploaded.
type ContentFinding struct {
	Detector   string                `json:"detector"`
	Title      string                `json:"title"`
	Category   string                `json:"category"`
	Severity   contract.Risk         `json:"severity"`
	Confidence string                `json:"confidence"`
	Agent      contract.AgentProduct `json:"agent"`
	Tier       contract.ConfigTier   `json:"tier"`
	Source     string                `json:"source"`
	Path       string                `json:"path"`
	Line       int                   `json:"line"`
	SecretType string                `json:"secret_type,omitempty"`
	Excerpt    string                `json:"excerpt"`
}

var (
	engineOnce sync.Once
	engine     *content.Engine
	engineErr  error
)

// detectors loads the shipped detector packs once.
func detectors() (*content.Engine, error) {
	engineOnce.Do(func() {
		packs, err := content.Load(detectorpacks.FS)
		if err != nil {
			engineErr = err
			return
		}
		engine = content.New(packs, content.Options{})
	})
	return engine, engineErr
}

// maxScanFile bounds how much of one file the content scan reads.
const maxScanFile = 1 << 20

// scanContent runs the detectors over each agent's memory files, skills and
// config files, once per file. Credentials in config files are left to the
// secret_in_config posture check, which names the setting.
func scanContent(agents []discover.Agent) ([]ContentFinding, error) {
	eng, err := detectors()
	if err != nil {
		return nil, err
	}
	out := []ContentFinding{}
	seen := map[string]bool{}
	add := func(a discover.Agent, tier contract.ConfigTier, display, text string, src content.Source, lines bool) {
		for _, f := range eng.Scan(src, text) {
			if src == content.SourceAgentConfig && f.Category == content.CategoryCredential {
				continue
			}
			line := f.Line
			if !lines {
				line = 0
			}
			out = append(out, ContentFinding{Detector: f.DetectorID, Title: f.Title, Category: string(f.Category),
				Severity: contract.Risk(f.Severity), Confidence: string(f.Confidence), Agent: a.Product, Tier: tier,
				Source: string(src), Path: display, Line: line, SecretType: f.SecretType, Excerpt: f.Excerpt})
		}
	}
	scan := func(a discover.Agent, tier contract.ConfigTier, display, real string, src content.Source) {
		if seen[real] {
			return
		}
		seen[real] = true
		raw, err := os.ReadFile(real)
		if err != nil {
			return
		}
		if len(raw) > maxScanFile {
			raw = raw[:maxScanFile]
		}
		add(a, tier, display, string(raw), src, true)
	}
	for _, a := range agents {
		for _, m := range a.MemoryFiles {
			scan(a, m.Tier, m.Path, m.RealPath, content.SourceMemoryFile)
		}
		for _, c := range a.Configs {
			if slices.Equal(c.Holds, []string{"mcp_servers"}) {
				// A file Privometry reads only for its MCP servers (~/.claude.json
				// is mostly the agent's own state): scan just the servers.
				if seen[c.RealPath] {
					continue
				}
				seen[c.RealPath] = true
				var b strings.Builder
				for _, srv := range a.MCPServers {
					if srv.Path == c.Path {
						b.WriteString(content.Flatten(parsers.Lookup(c.Doc, srv.Pointer)))
					}
				}
				add(a, c.Tier, c.Path, b.String(), content.SourceAgentConfig, false)
				continue
			}
			src := content.SourceAgentConfig
			if slices.Contains(c.Holds, "skills") {
				src = content.SourceSkill
			}
			scan(a, c.Tier, c.Path, c.RealPath, src)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if r1, r2 := posture.Rank(out[i].Severity), posture.Rank(out[j].Severity); r1 != r2 {
			return r1 > r2
		}
		return out[i].Path < out[j].Path
	})
	return out, nil
}

// Scan discovers agents and checks their posture.
func Scan(reg *registry.Registry, opts discover.Options) (*Result, error) {
	agents, err := discover.Run(reg, opts)
	if err != nil {
		return nil, err
	}
	findings := posture.Run(reg, agents, opts.Env, opts.Root)
	if findings == nil {
		findings = []posture.Finding{}
	}
	locate(agents, findings)
	cfs, err := scanContent(agents)
	if err != nil {
		return nil, err
	}

	res := &Result{
		Schema:          ResultSchema,
		ScannedAt:       contract.At(time.Now()),
		SensorVersion:   buildinfo.Version,
		OS:              opts.Env.OS(),
		Arch:            runtime.GOARCH,
		Machine:         opts.Machine,
		Agents:          agents,
		Findings:        findings,
		ContentFindings: cfs,
		Summary:         map[string]int{},
	}
	if res.Agents == nil {
		res.Agents = []discover.Agent{}
	}
	if opts.RepoRoot != "" {
		res.Repo = discover.Display(opts.RepoRoot, opts.Env.Home, "")
	}
	for _, f := range findings {
		res.Summary[string(f.Severity)]++
	}
	for _, f := range cfs {
		res.Summary[string(f.Severity)]++
	}
	return res, nil
}

// locate sets each finding's line from its JSON pointer: the first line that
// holds the pointer's last key. Good enough for annotations; 0 when unknown.
func locate(agents []discover.Agent, findings []posture.Finding) {
	real := map[string]string{}
	for _, a := range agents {
		for _, c := range a.Configs {
			real[c.Path] = c.RealPath
		}
	}
	for i := range findings {
		f := &findings[i]
		p, ok := real[f.Path]
		if !ok || f.Pointer == "" {
			continue
		}
		key := f.Pointer[strings.LastIndex(f.Pointer, "/")+1:]
		key = strings.NewReplacer("~1", "/", "~0", "~").Replace(key)
		if isIndex(key) { // an array element: look for its parent key instead
			parent := strings.TrimSuffix(f.Pointer, "/"+key)
			key = parent[strings.LastIndex(parent, "/")+1:]
		}
		f.Line = lineOf(p, key)
	}
}

func isIndex(s string) bool {
	return s != "" && strings.Trim(s, "0123456789") == ""
}

func lineOf(path, key string) int {
	file, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer file.Close()
	sc := bufio.NewScanner(file)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if strings.Contains(line, `"`+key+`"`) || strings.HasPrefix(strings.TrimSpace(line), key+" ") ||
			strings.HasPrefix(strings.TrimSpace(line), key+"=") || strings.Contains(line, "."+key+"]") || strings.Contains(line, "["+key+"]") {
			return n
		}
	}
	return 0
}
