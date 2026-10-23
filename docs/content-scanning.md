# Content scanning

How Privometry finds leaked credentials and instructions aimed at agents (PRD SCAN-01 to SCAN-16): the contracts, the detector engine and packs, the daemon's checks before and after each tool call, memory file hashing, the rules on the new facts, and `privometry scan` at rest.

```
text an agent sends, writes or loads
        │
        ▼
internal/content (detector packs) ──► findings ──► content_finding events (timeline)
        │
        └──► Summary ──► policy facts: secret_detected, injection_detected, hidden_content
                                       (+ injection_seen from the session, target_class from the path)
                                       └──► Cedar rules decide ask or deny
```

## Contracts

| Spec | What changed |
|---|---|
| `event-schema/v1` | New event type `content_finding` (detector, category, severity, confidence, source, `secret_type`, `location` with a salted `path_hash`, salted `fingerprint`, `action_taken`; never a value or a raw path). `action.secret_types` and `context.injection_seen` |
| `policy/v1` | Facts `secret_detected` (kinds, or `any`), `injection_detected`, `injection_seen`, `hidden_content`, `target_class`; the same five attributes in `privometry.cedarschema`; example `content-scanning.yaml` with 10 shared verdict vectors |
| `rulepack/v1` | Rule tests can set the five facts |
| `detectorpack/v1` (new) | `privometry.detectorpack/v1` manifests and `privometry.detectors/v1` files |
| `adapter/v1` | `memory_files` per agent: tier, kind (`instructions`, `rules`, `memory`), format, paths, `nested`, `imports`, `written_by_agent` |

## Memory and instruction files

`adapter-defs/*.yaml` list where each agent keeps them:

| Agent | Files |
|---|---|
| Claude Code | Managed, user (`~/.claude/CLAUDE.md`) and project `CLAUDE.md` (also nested and in `.claude/`), `CLAUDE.local.md`, `~/.claude/rules/` and `.claude/rules/`, automatic memory in `~/.claude/projects/*/memory/*.md` |
| Codex CLI | `~/.codex/AGENTS.md`, `AGENTS.override.md`, project `AGENTS.md` (nested), experimental `~/.codex/memories/` |
| Cursor | `.cursor/rules/*.mdc` (moved from `config_tiers`), `AGENTS.md`, legacy `.cursorrules`; user rules and memories live in the app, not in files |

The extractors set `target_class` for every file an action touches: `memory_file` (the paths above, plus `GEMINI.md` and Copilot's instruction files), `agent_config` (every config tier and MCP source, skills, `.privometry/policy.yaml`), `code` (anything else in the repo) or `other`. The hook client cannot load adapter definitions, so the patterns are built in; `TestTargetClassMatchesAdapterDefs` checks all 60 adapter paths against them.

## Detector packs

`detectorpacks/` ships three packs, loaded with `content.Load(detectorpacks.FS)`:

| Pack | Detectors | Finds |
|---|---|---|
| `privometry/secrets` 1.0.0 | 18 | AWS, GitHub, GitLab, Slack, Stripe, OpenAI, Anthropic, Google, GCP service account and npm credentials, private keys, JWTs, passwords in connection strings, bearer tokens, random values assigned to secret-named variables |
| `privometry/injection` 1.0.0 | 8 | Ignore-previous-instructions, fake system messages, hide-from-user, skip-approvals, disable-protection, download-and-run, send-secrets-out, data in image URLs |
| `privometry/hidden-content` 1.0.0 | 6 | Invisible and direction-changing characters, Unicode tag text, variation-selector runs, private-use characters, instructions in HTML comments, encoded instructions, text pushed off-screen |

Each detector has `samples.match` and `samples.no_match`; `content.Check` (run by `detectorpacks/detectorpacks_test.go`) requires every detector to fire on each match sample and stay quiet on each other one, for every source it applies to. Sample credentials are split with `{{}}` so secret scanners never see a contiguous token. Known example values (AWS's documented keys) are in `allow` lists.

Detector pack IDs are their own namespace: `privometry/secrets` is both a rule pack (what to do) and a detector pack (what to find).

## The engine

`internal/content`:

- **Kinds.** `pattern` (RE2), `entropy` (a pattern picks values, kept when random enough), `unicode` (hidden character classes; emoji joiners, right-to-left marks and a single emoji variation selector are ignored), `structure` (HTML comments, base64 and hex blobs that decode to readable text, mid-line whitespace gaps, Markdown image URLs), each optionally filtered by a pattern on the content.
- **Keywords.** One Aho-Corasick pass finds every detector's keywords; a pattern runs only on short windows around its hits (128 bytes before, 384 after, within the line), so most of a large input is never examined and Go's regexp uses its fast backtracker.
- **Findings.** Detector, category, severity, confidence, source, line, a masked excerpt for the local timeline (credentials show their first four characters and length; hidden characters are shown as `<U+200B>` and tag text is decoded), and for credentials an `hmac-sha256` fingerprint under the engine's salt. When a provider detector and a generic one find the same value, only the provider finding is kept. At most 20 findings per detector per scan.
- **Summary.** `content.Summarize` turns findings into the policy facts: sorted secret kinds, the strongest injection level, and whether anything is hidden.
- **Budget (SCAN-11).** `PreActionLimit` is 64 KB. `ScanWithin` takes a deadline and runs credential detectors first; on the hook path the daemon decides on what was found in time and finishes the scan after the action, raising findings instead of blocking.

Measured on an M-series Mac, all 32 shipped detectors on 64 KB:

| Content | p50 | p95 |
|---|---|---|
| Go source | 1.2 ms | 1.6 ms |
| Markdown documentation | 3.0 ms | 3.6 ms |
| YAML, JSON Schema, JavaScript | 1.1–1.4 ms | 1.1–1.7 ms |
| Adversarial: a keyword on every line | 8 ms | 10 ms (bounded by `ScanWithin`) |

## In the daemon

**Before each decision** (SCAN-04, SCAN-11) the daemon scans what the tool call carries, once per call: the command, the URL, an MCP call's arguments (flattened to `key: value` lines, so JSON escaping cannot hide characters) and written content (`tool_targets.*.content` in the adapter, or the lines an `apply_patch` adds). The scan has a 5 ms budget measured from its start; anything not reached is scanned after the reply and raises findings with `action_taken: none`. The summary becomes the facts `secret_detected`, `injection_detected` and `hidden_content` for every request of the call, and `action.secret_types` on the action event.

**After each tool call** the daemon scans the tool's output in the background (up to 256 KB; writes are skipped, their output echoes the input). Injected or safety-weakening instructions of medium or high level, or exfiltration instructions, mark the session `injection_seen` for the rest of the session; that fact and `context.injection_seen` are on every later decision.

**Findings** become `content_finding` events: detector, category, severity, confidence, source, `secret_type` and salted fingerprint for credentials, location (path class, salted path hash, line), and `action_taken` from the decision (`blocked`, `asked`, `none`). The local timeline keeps `path:line` and the masked excerpt in `target_clear`; nothing else holds a value. At most 20 per tool call. The salt is a random per-device key in the timeline's state until the device enrolls with an organization.

**Memory files** (SCAN-02) are hashed every minute with the other watched files: user and managed memory files of every agent, and the project files at the root of each workspace an agent worked in during the last 24 hours. A file seen for the first time is scanned (`source: memory_file`); a changed one records a `config_change` event with `holds` `instructions`, `rules` or `memory` and `changed_by`:

- `agent` when an agent session was allowed to write that file through a hooked tool less than two minutes earlier, or when the agent's own `PostToolUse` reports the write (checked at once, which also covers nested files the watcher does not list);
- `person` otherwise.

The new content is scanned again and its findings recorded.

## Rules on the content facts

| Pack | Rule | Verdict | When |
|---|---|---|---|
| `privometry/secrets` 1.1.0 | `secret-in-command` | ask | A literal credential in a shell command |
| | `secret-written-to-file` | ask | A credential written into a file other than `.env` or `.env.local` |
| | `secret-in-mcp-arguments` | ask | A credential passed to an MCP tool |
| `privometry/exfiltration` 1.1.0 | `secret-to-network` | deny | A fetch carrying a credential |
| | `secret-in-network-command` | deny | `curl`, `wget`, `nc` and similar with a literal credential |
| `privometry/agent-instructions` 1.0.0 (new) | `ask-instruction-edit` | ask | Writing or deleting an instruction file (by tool or shell redirect); automatic memory folders are exempt |
| | `block-memory-edit-after-injection` | deny | Any memory or instruction edit once the session has `injection_seen` (SCAN-03) |
| | `ask-safety-weakening-write` | ask | Writing text with `injection_detected` medium or high |
| | `ask-hidden-content-write` | ask | Writing text with `hidden_content` |

For shell commands, `target_class` is set only on paths the command writes or deletes, so `cat CLAUDE.md` is not an edit.

## privometry scan

`privometry scan` lists each agent's memory files (`memory_files` in the JSON report, a column in the table), including nested project files found by walking the repo (skipping `.git`, `node_modules`, `vendor`, build folders; at most 8 levels and 5,000 folders). It scans memory files, skills and agent config files, and reports `content_findings` in all three formats: a section in the table, a list in the JSON, and SARIF results with one rule per detector. Content findings count toward `--fail-on`. Credentials in config files are left to the `secret_in_config` posture check, and files read only for their MCP servers (`~/.claude.json`, which is mostly the agent's own state) are scanned only within the server entries.

On the development Mac this found 33 Claude Code memory files. The first run raised 5 findings, all false positives: skills that quote "ignore previous instructions" as an example of what to distrust, a skill telling Claude not to "tell the user to use a card", and two strings in `~/.claude.json`'s cached state. The patterns now skip quoted phrases and phrasing guidance, `~/.claude.json` is scanned only within its MCP servers, and each case is a `no_match` sample; the rerun reports none.

## Still to do

- Claude Code's `InstructionsLoaded` hook scans each loaded `CLAUDE.md` or rule file immediately, including nested files that are not discoverable from the workspace root. Unchanged files are deduplicated by content hash.
- The hook client's fail-mode path (daemon down) does not detect credentials yet.
- Memory files are not rescanned daily when unchanged, so a new detector pack version only applies to files that change; snapshots and rollback are P2 (SCAN-14).
- Content agents read is scanned for injection (SCAN-12, a P2 Should) but with phrasing heuristics: security docs that discuss prompt injection without quoting it can still mark a session.
- Detector packs are embedded only; signed distribution and per-repo allowlists (SCAN-09) come with the pack signing work.
- The GitHub Action (SCAN-08) is M7.
