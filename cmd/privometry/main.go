// Command privometry is the Privometry CLI: scan, guard, daemon, timeline, policy and
// doctor; login arrives with the cloud milestones.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	adapterdefs "github.com/privometry/privometry-oss/adapter-defs"
	"github.com/privometry/privometry-oss/internal/adapters/registry"
	"github.com/privometry/privometry-oss/internal/buildinfo"
	"github.com/privometry/privometry-oss/internal/contract"
	"github.com/privometry/privometry-oss/internal/platform"
	"github.com/privometry/privometry-oss/internal/scanner"
	"github.com/privometry/privometry-oss/internal/scanner/discover"
	"github.com/privometry/privometry-oss/internal/scanner/posture"
	"github.com/privometry/privometry-oss/internal/scanner/report"
)

const usage = `Usage: privometry <command> [flags]

Commands:
  scan      Find coding agents, MCP servers, hooks and risky settings
  guard     Install, remove or check Privometry's hook in each coding agent
  daemon    Run privometryd in the background at login, or check on it
  timeline  Show what agents did and what Privometry decided
  policy    Test rule packs and policies, or explain a decision
  doctor    Check that Privometry is protecting this machine
  update    Install the latest signed release
  version   Print the version

Run "privometry scan -h" for scan flags.
`

// Exit codes: 0 success, 1 findings at or above --fail-on, 2 usage or runtime error.
func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "scan":
		return scan(args[1:], stdout, stderr)
	case "policy":
		return policyCmd(args[1:], stdout, stderr)
	case "guard":
		return guardCmd(args[1:], stdout, stderr)
	case "daemon":
		return daemonCmd(args[1:], stdout, stderr)
	case "timeline":
		return timelineCmd(args[1:], stdout, stderr)
	case "doctor":
		return doctorCmd(args[1:], stdout, stderr)
	case "update":
		return updateCmd(args[1:], stdout, stderr)
	case "version", "--version":
		fmt.Fprintln(stdout, buildinfo.String("privometry"))
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "privometry: unknown command %q\n\n%s", args[0], usage)
	return 2
}

func scan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "table", "output format: table, json or sarif")
	repo := fs.String("repo", "", "repo to scan for project config (default: the git repo containing the current directory)")
	noRepo := fs.Bool("no-repo", false, "do not scan any repo")
	noMachine := fs.Bool("no-machine", false, "skip user and managed config and installed agents (for CI)")
	failOn := fs.String("fail-on", "", "exit 1 if a finding is at least this severity: low, medium, high or critical")
	out := fs.String("output", "", "write the report to this file instead of stdout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *failOn != "" && posture.Rank(contract.Risk(*failOn)) == 0 {
		fmt.Fprintf(stderr, "privometry scan: --fail-on must be low, medium, high or critical\n")
		return 2
	}

	env, err := platform.CurrentEnv()
	if err != nil {
		return fail(stderr, err)
	}
	opts := discover.Options{Env: env, Machine: !*noMachine}
	if !*noRepo {
		root := *repo
		if root == "" {
			cwd, _ := os.Getwd()
			root = platform.GitRoot(cwd)
		}
		if root != "" {
			if opts.RepoRoot, err = filepath.Abs(root); err != nil {
				return fail(stderr, err)
			}
			if info, err := os.Stat(opts.RepoRoot); err != nil || !info.IsDir() {
				return fail(stderr, fmt.Errorf("--repo %s is not a directory", root))
			}
		}
	}
	if !opts.Machine && opts.RepoRoot == "" {
		return fail(stderr, errors.New("nothing to scan: --no-machine needs a repo"))
	}

	reg, err := registry.Load(adapterdefs.FS)
	if err != nil {
		return fail(stderr, err)
	}
	res, err := scanner.Scan(reg, opts)
	if err != nil {
		return fail(stderr, err)
	}

	w := stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			return fail(stderr, err)
		}
		defer f.Close()
		w = f
	}
	if err := report.Write(w, *format, res); err != nil {
		return fail(stderr, err)
	}

	if *failOn != "" {
		threshold := posture.Rank(contract.Risk(*failOn))
		for _, f := range res.Findings {
			if posture.Rank(f.Severity) >= threshold {
				return 1
			}
		}
		for _, f := range res.ContentFindings {
			if posture.Rank(f.Severity) >= threshold {
				return 1
			}
		}
	}
	return 0
}

func fail(stderr io.Writer, err error) int {
	fmt.Fprintln(stderr, "privometry:", err)
	return 2
}
