# Spike: agent hook formats (M0)

Date: 2026-10-23. Goal: confirm how each P1 agent lets Privometry intercept a tool call before it runs, and what that means for the adapter definitions and the hook client.

## Status

| Agent | Pre-tool hook | Evidence | Fixtures |
|---|---|---|---|
| Claude Code 2.1.304 | `PreToolUse`, full allow / ask / deny | Recorded from a real headless session | `test/fixtures/claude_code/2.1.304/hooks/` (14 payloads) |
| Cursor | `preToolUse` plus `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile` | Official docs only | Pending: needs a run in the Cursor IDE |
| Codex CLI | `PreToolUse`, allow / deny only | Official docs only | Pending: local install is broken (missing native binary) |

Sources: [Claude Code hooks](https://code.claude.com/docs/en/hooks.md), [Claude Code settings](https://code.claude.com/docs/en/settings.md), [Cursor hooks](https://cursor.com/docs/hooks.md), [Cursor third-party hooks](https://cursor.com/docs/reference/third-party-hooks.md), [Codex hooks](https://developers.openai.com/codex/hooks.md), [Codex managed configuration](https://developers.openai.com/codex/enterprise/managed-configuration.md).

## Comparison

| | Claude Code | Cursor | Codex CLI |
|---|---|---|---|
| Hook file, user tier | `~/.claude/settings.json` | `~/.cursor/hooks.json` | `~/.codex/hooks.json` or `[hooks]` in `config.toml` |
| Project tier | `.claude/settings.json`, `.claude/settings.local.json` | `.cursor/hooks.json` | `.codex/hooks.json` (trusted projects only) |
| Managed tier | `managed-settings.json` (+ `managed-settings.d/`), MDM plist or registry | `/Library/Application Support/Cursor/hooks.json`, `/etc/cursor/hooks.json`, `C:\ProgramData\Cursor\hooks.json` | `requirements.toml` (`/etc/codex/`, `%ProgramData%\OpenAI\Codex\`, MDM key) |
| Relocation env var | `CLAUDE_CONFIG_DIR` | none documented | `CODEX_HOME` |
| Decision output | `hookSpecificOutput.permissionDecision` + `permissionDecisionReason` | `permission` + `user_message` + `agent_message` | same as Claude Code |
| `ask` from pre-tool | Yes | Only on `beforeShellExecution` and `beforeMCPExecution` | No: an `ask` marks the hook failed and the call proceeds |
| Default on hook failure | Open | Open (bad JSON on permission hooks fails closed) | Open |
| Fail-closed switch | `"onFailure": "block"` (v2.1.295+) | `"failClosed": true` | None |
| Shell tool name | `Bash` (also `PowerShell`) | `Shell` | `Bash` |
| File tools | `Read`, `Write`, `Edit` | `Read`, `Write`, `Delete` | `apply_patch` (also matches `Edit`, `Write`) |
| MCP tool name | `mcp__<server>__<tool>`, plus `mcp_server.source` (v2.1.274+) | `MCP:<tool>` with `mcp_server_name` | `mcp__<server>__<tool>` |
| Config-change event | `ConfigChange` (settings and skills) | None | None |
| Managed-only lock | `allowManagedHooksOnly` | Not found | `allow_managed_hooks_only` |

## What the recordings showed (Claude Code)

- The `PreToolUse` payload matches the docs: `session_id`, `transcript_path`, `cwd`, `prompt_id`, `permission_mode`, `hook_event_name`, `tool_name`, `tool_input`, `tool_use_id`.
- There is one undocumented field, `effort: {"level": ...}`. Parsers must ignore unknown fields.
- `tool_input.file_path` is absolute for `Read`, `Write` and `Edit`. `Bash` carries `command` and `description`.
- `PermissionRequest` fired for `rm -rf ./out.txt` after `PreToolUse` returned nothing, so it is a usable second checkpoint.
- `ConfigChange` fired with `source: "skills"` when a synced skill changed mid-session. Claude Code reports config drift itself.
- No MCP call was recorded. That needs a run with a local MCP server.

## Consequences for the design

1. **The adapter contracts use agent-specific response shapes.** Claude Code and Codex expect `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": ..., "permissionDecisionReason": ...}}`. Cursor expects `{"permission": ..., "user_message": ..., "agent_message": ...}`. `specs/adapter/v1` and its examples now enforce these shapes.
2. **The hook client always answers; its own crash is the only thing that fails closed.** We register with `onFailure: block` (Claude Code) and `failClosed: true` (Cursor). The hook client then applies the category fail mode itself when the daemon is unreachable: it returns `allow` for open categories and `deny` for closed ones. This keeps the ADR-0006 rule: the hook client uses a small built-in matcher, not Cedar.
3. **Codex is guarded in P1, but without `ask` and without fail-closed.** An `ask` verdict maps to `deny` with a message telling the developer how to allow it. Optionally a matching execpolicy `prompt` rule can be generated as a backstop. Its `doctor` and timeline must say plainly that Codex coverage is fail-open. User-tier hooks also need a one-time hash trust in Codex (`/hooks`), so `guard install` has to walk the developer through it.
4. **Cursor needs per-event registration.** Register `beforeShellExecution` and `beforeMCPExecution` (they honor `ask`), `beforeReadFile` (secrets), and `preToolUse` for writes and deletes.
5. **Cursor runs Claude Code hooks by default ("Third-Party Imports").** A Privometry hook installed for Claude Code also fires inside Cursor. The hook client must detect the caller from the payload (`cursor_version` or `conversation_id` present) and the daemon must dedupe on `tool_use_id`. Otherwise one action is evaluated and logged twice.
6. **The adapter definition needs more fields:** the macOS managed path for Claude Code, `managed-settings.d/` directories, MDM sources, Codex `requirements.toml` and `CODEX_HOME`, and per-event response formats.
7. **Only Claude Code has a config-change event**, so the daemon's file watcher (`internal/config`) stays the primary source of `config_change` events.

## Still open

- [ ] Record Cursor payloads: install the recorder in a test project's `.cursor/hooks.json` and run one agent session in the IDE.
- [ ] Record Codex payloads after reinstalling it (`npm i -g @openai/codex`), including the hook-trust flow.
- [ ] Record a Claude Code MCP call (`mcp_server` field) and a `WebFetch`.
- [ ] Measure the hook round trip each agent adds, to set the latency budget against real overhead.

## Reproducing

```bash
make hook-recorder
# register bin/hook-recorder -agent <product> -event <Event> -out <dir> for each event in a scratch project,
# run the agent, then sanitize the recordings before copying them into test/fixtures/.
```
