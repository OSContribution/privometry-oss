# privometry-oss implementation plan

Covers P0 (the seven specs) and P1 (open-source MVP): scanner and guard for Claude Code, Cursor and Codex CLI on macOS and Linux, local timeline, repository CI integration, and signed releases. Edge work for P2 is listed at the end.

Sources: Privometry PRD, Contracts v1 (P0), Database design v1 (edge SQLite), console and local guard prototype.

## Approach

1. **Specs before code.** Go types are generated from `specs/`, and the platform repo pins the same specs.
2. **Release the scanner before the guard.** `privometry scan` is useful on its own and low risk, so design partners can start early.
3. **Check hook formats in week 1.** The adapter example in the contracts is illustrative; real payloads are recorded into `test/fixtures/` before adapters are written.
4. **Measure latency from day one.** Hook decision p95 ≤ 10 ms and hook-client cold start ≤ 20 ms get a CI benchmark from the first hook commit.

## Milestones

| # | Milestone | Main packages | Delivers | ~Weeks |
|---|---|---|---|---|
| M0 | Foundations | `go.mod`, `Makefile`, `.github/workflows`, `internal/platform`, ADRs | CI (lint, test, race), `.goreleaser.yaml` skeleton, OS paths and permission helpers, ADR-0001, 0003, 0006. Hook-format spike: real payloads from Claude Code, Cursor and Codex in `test/fixtures/` | 1 |
| M1 | P0 specs | `specs/*`, `internal/events` | JSON Schema 2020-12 for common, event, policy, adapter, rulepack, riskfeed, entitlements; `openapi.yaml`; valid and invalid examples; `privometry.cedarschema`; conformance vectors (policy verdicts, signatures, redaction); generated Go types; DSSE verify library and root key set | 1–3 |
| M2 | Scanner | `scanner/*`, `adapters/registry`, `adapter-defs/*.yaml`, `redact` | Load adapter definitions; detect agents and versions; parse config tiers and MCP sources; posture checks; table, JSON and SARIF output; machine and repo modes; secret names and locations only (EDGE-06 to 10). First release: `privometry scan` | 2–5 |
| M3 | Policy engine | `policy/intent`, `compiler`, `engine`, `session`, `autoapprove`, `rulepacks/` | Shell intent parser producing facts; YAML-to-Cedar compiler; four-layer merge, strongest verdict wins; three-step verdict mapping; monitor policy set; risk-based auto-approval; untrusted-input session state; four default rule packs with tests; `privometry policy test` | 3–6 |
| M4 | Daemon and hooks | `daemon`, `ipc`, `cmd/privometry-hook`, `adapters/<agent>`, `timeline` | launchd and systemd service; user-only Unix socket; small hook client with built-in closed rules for when the daemon is down; `guard install` / `uninstall` per agent; native response per agent; SQLite tables per the DB design (WAL, gap-free `device_seq`); fail modes; latency benchmark | 5–8 |
| M5 | Developer experience | `ui/timeline-web`, `update`, `integrity`, `config` | Terminal and embedded web timeline; `doctor` and redacted diagnostic bundle; signed self-update that refuses downgrades; config hashing (head start on EDGE-24) | 7–9 |
| M6 | Content scanning | `specs/detectorpack/v1`, `internal/content`, `detectorpacks/`, `adapter-defs/*.yaml`, `daemon`, `scanner` | PRD SCAN-01 to SCAN-11: memory and instruction file discovery per agent and tier; hashing with person-or-agent attribution; detector engine (pattern, entropy, Unicode, structure; keyword prefilter, allowlists, masked excerpts, salted fingerprints); detector packs for credentials, injected and safety-weakening instructions, hidden content; facts `secret_detected`, `injection_detected`, `injection_seen`, `hidden_content`, `target_class`; `content_finding` events and the local `content_findings` table; pack rules to ask on secrets in commands, writes and MCP arguments, deny secrets to the network, ask on memory edits and deny them after injection; at-rest scans in `privometry scan` and daily; 5 ms p95 for inputs up to 64 KB | 9–11 |
| M7 | CI integration and release | `.gitlab-ci.yml`, `action/`, `.goreleaser.yaml`, `docs/` | GitLab CI integration plus the optional GitHub Action (flag agent-config and memory-file changes in merge/pull requests, run content detectors, validate `.privometry/policy.yaml`, publish findings, enforce a severity gate); Homebrew, Scoop, binaries, signatures, SBOM, license scan; design-partner beta | 8–10 |
| P2 | Edge for Team | `cloud/*`, `mcpshim`, Windows, Gemini and Copilot adapters | Enrollment and mTLS, bundle and entitlement sync, upload queue, heartbeat and kill switch, stdio MCP shim, named-pipe IPC | After P1 gate |

**Critical path:** hook-format spike → adapter definitions → intent parser and compiler → hook client and daemon → latency gate. M1 and M2 run in parallel with the start of M3.

Week estimates assume 2–3 engineers.

## Libraries

| Need | Choice | Reason |
|---|---|---|
| Policy | `github.com/cedar-policy/cedar-go` | ADR-0006 |
| Shell parsing | `mvdan.cc/sh/v3` | Real POSIX/Bash parser; finds `rm -rf` inside `sh -c`, `xargs`, `&&` chains |
| SQLite | `modernc.org/sqlite` | No cgo, so cross-compiles cleanly |
| JSON Schema | `github.com/santhosh-tekuri/jsonschema/v6` | 2020-12 support |
| DSSE | `github.com/secure-systems-lab/go-securesystemslib/dsse` | Standard implementation |
| CLI, TUI, service | `cobra`, `bubbletea`, `kardianos/service` | Hook client stays on plain `os.Args` for cold start |
| IDs | `github.com/oklog/ulid/v2` | Prefixed ULIDs |

## Resolved conflicts between documents

1. `specs/common/v1/` and `specs/conformance/` were missing from the repo layout; added.
2. Repo policy file is `.privometry/policy.yaml` (Contracts v1), not `.agent-policy.yaml`.
3. ADR-0006 (Cedar) belongs in this repo.
4. The hook client does not embed Cedar. It carries a small hard-coded matcher for closed fail-mode categories (catastrophic by default) and asks the daemon for everything else.

## Progress

- M0 done: module, CI, goreleaser skeleton, `internal/platform`, ADRs 0001, 0003, 0006, hook spike (Claude Code fixtures).
- M1 specs drafted and tested: all seven contracts plus bundle, adapter set, key set, feature registry, and conformance vectors for policy verdicts, signatures and redaction. Go types are generated from the schemas (`scripts/gen-types`, drift-checked in CI). M1 is complete apart from freezing the drafts after review.
- Pulled forward: `internal/signing` (DSSE verify, key set rotation) and `internal/redact` (redaction and hashing), each passing the shared vectors.
- M2 scanner done: `privometry scan` with table, JSON (`privometry.scan/v0`) and SARIF output, machine and repo modes, `--fail-on`, eight posture checks, secret-safe reports; see `docs/scanner.md` for checks and known gaps. Verified on a real macOS machine.
- M3 done: shell intent parser and extractors (`internal/policy/intent`), compiler with overrides and exceptions, layer merge (`internal/policy/merge`), `policy.Decide` (p95 55 µs), four rule packs, and `privometry policy test` (pack and policy tests, plus explaining one action). Session state for untrusted input moves to M4 with the daemon. See `docs/policy-engine.md`.
- M4 done: `privometryd` (IPC, per-repo policy cache, session state, dedupe, spool import, single-instance lock, status), SQLite timeline, `privometry-hook` with fail modes, `privometry daemon install/uninstall/status/restart` (launchd, systemd), and `privometry guard` for Claude Code, Cursor and Codex (with the Codex trust step). Verified with a real Claude Code session; hook round trip p95 under 9 ms. See `docs/daemon.md`.
- M5 done: `privometry timeline` (terminal, `--follow`, JSON) and `--web` (embedded page on 127.0.0.1 behind a per-run token, Host check and strict CSP); config integrity watcher with `hook_removed` and `hook_modified` alerts; `privometry doctor` with a real test decision (one-time probe token, nothing recorded) and a redacted `--bundle`; signed self-update (`specs/release/v1`, `internal/update`, `privometry update`) that refuses downgrades, expired manifests and digest mismatches, and refuses everything until release keys exist. See `docs/developer-experience.md`.
- M6 done: contracts for content scanning (`content_finding` events, `action.secret_types`, `context.injection_seen`, `config.changed_by`; policy facts `secret_detected`, `injection_detected`, `injection_seen`, `hidden_content`, `target_class`; `detectorpack/v1`; `memory_files` and `tool_targets.*.content` in `adapter/v1`), the detector engine and three detector packs (32 detectors; 64 KB in 1.1 to 3.6 ms p95), the daemon scanning commands, URLs, MCP arguments and written content before each decision and tool output after it, `injection_seen` sessions, memory file hashing with person-or-agent attribution and persisted daily rescans, Claude Code `InstructionsLoaded` scanning, lightweight credential detection in the hook client's fail-mode path, rules on the new facts (`privometry/secrets` 1.1.0, `privometry/exfiltration` 1.1.0, new `privometry/agent-instructions` 1.0.0), and `privometry scan` reporting memory files and content findings in table, JSON and SARIF. See `docs/content-scanning.md`.
- Rule packs: `privometry/core-catastrophic` (17 rules, 43 tests), `privometry/secrets` (8, 19), `privometry/exfiltration` (8, 18), `privometry/mcp-allowlist` (3, 6), all 1.0.0.

## Open items

- [x] Codex CLI pre-tool hook exists, but has no `ask` and no fail-closed switch; see `docs/spikes/hook-formats.md`.
- [ ] Record Cursor and Codex payloads (spike follow-up).
- [x] Fix the adapter response shape in Contracts v1 (`hookSpecificOutput` for Claude Code and Codex, `permission` for Cursor).
- [ ] `release` Ed25519 key and root key set: who holds and rotates them. Blocks `privometry update`, which ships with no release keys and refuses every update until `internal/update/keys/release-keys.json` exists.
- [x] Release manifest host: `privometry update` defaults to the GitLab latest-release direct asset `release.json` for `cn-solutions/privometry/privometry-oss`.
- [x] Fail-mode defaults per category: catastrophic is closed; secrets and exfiltration ask; unapproved MCP and other actions are open. The shared definition is `contract.DefaultFailModes`.
- [ ] P1 team size, to firm up estimates.
- [x] Contracts v1 defines seven event types (`prompt` and `content_finding` were added after the original five-type draft); historical changelog entries retain their original wording.
- [x] SCAN-02 person-or-agent attribution: classify a change as `agent` within two minutes of an allowed agent write to that path, otherwise `person`. Keep the window configurable in a later release if operational evidence requires it.
- [x] Credential detection in the hook client's fail-mode path (daemon down), using the redaction recognizers without loading the detector engine.
- [x] Local capture set to `redacted` (Database design v1): the daemon applies it at the persistence boundary, including spool imports.
- [x] Rename the credential detector pack to `privometry/credentials`; the rule pack remains `privometry/secrets`, making their separate namespaces explicit before publication.
- [x] Native GitLab CI foundation: validation, race tests and coverage, repository-only policy/content scanning with a high-severity gate and retained SARIF, and release-binary builds. Production release publishing, package feeds, SBOM, and signing remain in M7.
