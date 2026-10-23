package intent

import (
	"path"
	"regexp"
	"strings"
)

// Context is where an action runs.
type Context struct {
	Cwd      string // absolute working directory
	Home     string // the user's home directory
	RepoRoot string // repository root, or empty outside a repo
	TempDirs []string
}

// resolve turns a path argument into a clean absolute path. ok is false when
// the path depends on a variable other than $HOME.
func (c Context) resolve(p string) (abs string, ok bool) {
	switch {
	case p == "~" || p == "$HOME" || p == "${HOME}":
		p = c.Home
	case strings.HasPrefix(p, "~/"):
		p = c.Home + p[1:]
	case strings.HasPrefix(p, "$HOME/"):
		p = c.Home + p[5:]
	case strings.HasPrefix(p, "${HOME}/"):
		p = c.Home + p[7:]
	}
	if strings.Contains(p, "$") {
		return "", false
	}
	p = strings.ReplaceAll(p, `\`, "/")
	if !strings.HasPrefix(p, "/") {
		p = path.Join(c.Cwd, p)
	}
	// A glob is classified by the directory it expands in.
	if i := strings.IndexAny(p, "*?["); i >= 0 {
		p = path.Dir(p[:i+1])
	}
	return path.Clean(p), true
}

func within(p, dir string) bool {
	return dir != "" && (p == dir || strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/"))
}

// secretStores are home-relative directories and files that hold credentials.
var secretStores = []string{
	".ssh", ".aws", ".gnupg", ".config/gcloud", ".azure", ".kube", ".docker/config.json", ".netrc",
	".npmrc", ".pypirc", ".git-credentials", ".config/gh/hosts.yml", ".password-store", "Library/Keychains",
	".terraform.d/credentials.tfrc.json", ".config/op", ".vault-token",
}

// publicInStores are files inside secret stores that hold no secret.
var publicInStores = regexp.MustCompile(`/\.ssh/(known_hosts|config|authorized_keys|[^/]+\.pub)$|/\.aws/config$`)

var (
	secretNameRE = regexp.MustCompile(`(?i)(^\.env(\..+)?$|^id_(rsa|dsa|ecdsa|ed25519)(_[a-z0-9]+)?$|\.(pem|key|p12|pfx|jks|keystore|ppk)$|^credentials(\.json)?$|^service[-_]?account.*\.json$|\.tfstate(\.backup)?$|^\.htpasswd$|^secrets?\.(ya?ml|json|toml)$)`)
	exampleRE    = regexp.MustCompile(`(?i)\.(example|sample|template|defaults?|dist|schema)$|\.pub$`)
)

var systemDirs = []string{"/etc", "/usr", "/bin", "/sbin", "/var", "/opt", "/System", "/Library", "/Applications",
	"/private/etc", "/private/var", "/boot", "/dev", "/proc", "/sys", "/lib", "/lib64", "/root", "/srv", "/Windows", "/Program Files"}

// classify returns the path_class of an absolute path and whether the file
// itself holds secrets (a .env file in the repo is still class repo).
// Classify returns the path class of an absolute path, and whether the file
// is a credential by name or location.
func (c Context) Classify(p string) (class string, secret bool) { return c.classify(p) }

func (c Context) classify(p string) (class string, secret bool) {
	base := path.Base(p)
	secret = secretNameRE.MatchString(base) && !exampleRE.MatchString(base)
	for _, s := range secretStores {
		if dir := path.Join(c.Home, s); within(p, dir) {
			return "secret_store", secret || !publicInStores.MatchString(p)
		}
	}
	switch {
	case within(p, c.RepoRoot):
		return "repo", secret
	case c.isTemp(p):
		return "temp", secret
	case within(p, c.Home):
		return "home", secret
	case p == "/":
		return "system", secret
	}
	for _, d := range systemDirs {
		if within(p, d) {
			return "system", secret
		}
	}
	return "other", secret
}

func (c Context) isTemp(p string) bool {
	for _, d := range append([]string{"/tmp", "/private/tmp", "/var/tmp", "/var/folders", "/private/var/folders"}, c.TempDirs...) {
		if within(p, d) {
			return true
		}
	}
	return false
}

// agentConfigRE matches files that make an agent or git run commands later:
// writing them is a persistence technique.
var agentConfigRE = regexp.MustCompile(`(^|/)(\.claude/settings(\.local)?\.json|\.claude\.json|\.mcp\.json|\.cursor/(hooks|mcp)\.json|\.codex/(config\.toml|hooks\.json)|\.git/hooks/[^/]+|\.privometry/policy\.yaml|\.vscode/(settings|tasks)\.json|\.(bash|zsh)rc|\.profile|\.bash_profile|\.zprofile)$`)

// memoryFileRE matches files agents load as standing instructions or memory:
// every memory_files path in adapter-defs (a test keeps them in step), plus
// the instruction files of agents Privometry has no adapter for yet.
var memoryFileRE = regexp.MustCompile(`(^|/)(CLAUDE(\.local)?\.md|AGENTS(\.override)?\.md|GEMINI\.md|\.cursorrules|` +
	`\.cursor/rules/([^/]+/)?[^/]+\.mdc|\.claude/rules/([^/]+/)?[^/]+\.md|\.claude/projects/[^/]+/memory/[^/]+\.md|` +
	`\.codex/memories/[^/]+\.md|\.github/copilot-instructions\.md|\.github/instructions/[^/]+\.instructions\.md)$`)

// agentFileRE matches agent settings, hook and MCP files, skills and Privometry's
// own policy: every config_tiers and mcp_sources path in adapter-defs.
var agentFileRE = regexp.MustCompile(`(^|/)(\.claude/settings(\.local)?\.json|managed-settings(\.d/[^/]+)?\.json|\.claude\.json|\.mcp\.json|` +
	`\.claude/skills/([^/]+/){1,3}SKILL\.md|\.cursor/(hooks|mcp|cli-config)\.json|hooks\.json|` +
	`\.codex/(config\.toml|hooks\.json)|requirements\.toml|\.codex/rules/[^/]+\.rules|\.privometry/policy\.yaml)$`)

// targetClassOf says what kind of file a resolved path is, for the
// target_class fact: an agent's memory or instruction file, an agent config,
// other files in the repo (code), or anything else.
func targetClassOf(p, class string) string {
	switch {
	case memoryFileRE.MatchString(p):
		return "memory_file"
	case agentFileRE.MatchString(p):
		return "agent_config"
	case class == "repo":
		return "code"
	}
	return "other"
}

// WorkspaceRoot is where an agent session is working: the git root when
// there is one, otherwise the working folder itself when it is inside the
// home folder (but not home itself), so a project that is not under git still
// keeps its own files out of the "home" class. Returns "" when neither applies.
func WorkspaceRoot(cwd, home, gitRoot string) string {
	if gitRoot != "" {
		return gitRoot
	}
	cwd = path.Clean(cwd)
	if home == "" || cwd == path.Clean(home) || !within(cwd, home) {
		return ""
	}
	for _, s := range secretStores {
		if within(cwd, path.Join(home, s)) {
			return ""
		}
	}
	return cwd
}
