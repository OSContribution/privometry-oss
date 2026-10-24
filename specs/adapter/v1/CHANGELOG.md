# adapter/v1

## 1.0.0-draft.2 (2026-10-23)

- MCP source pointers may contain a whole-segment `*` wildcard. The Claude Code definition uses `/projects/*/mcpServers` to discover project-scoped servers in `~/.claude.json`.
- The Claude Code definition includes its installed-plugin registry at `~/.claude/plugins/installed_plugins.json`.
- `memory_files` (PRD SCAN-01): files an agent loads as standing instructions or memory, with `tier`, `kind` (`instructions`, `rules`, `memory`), `format`, `paths`, and `nested` (project tier only: the same path in any folder below the repo root), `imports` (the agent follows `@path` imports) and `written_by_agent` (automatic memory).
- The shipped definitions list Claude Code (`CLAUDE.md` at managed, user and project tiers, `CLAUDE.local.md`, `.claude/rules/`, automatic memory in `~/.claude/projects/*/memory/`), Codex CLI (`AGENTS.md`, `AGENTS.override.md`, experimental memories) and Cursor (`.cursor/rules/*.mdc`, moved here from `config_tiers`, plus `AGENTS.md` and `.cursorrules`).
- `tool_targets.*.content`: where a tool's written text lives (Claude Code `Write` `/content`, `Edit` `/new_string`, `NotebookEdit` `/new_source`), so the content scanner checks it before the write.
- `detect.app_binaries`: the agent's own binary inside a desktop app. Its presence means the app is installed, and it answers `version_cmd` when the binary on PATH is missing or broken. The Codex definition lists the engine inside the ChatGPT app (`/Applications/ChatGPT.app/Contents/Resources/codex`, run by the Codex desktop app as `codex app-server`, reading the same `~/.codex` config and hooks) and is now named "Codex".
- Examples: `memory_files` in the Claude Code example; 2 new invalid examples.

## 1.0.0-draft.1 (2026-10-23)

- Replies are defined per hook event, with the verdicts each event honors and a `fallback` for verdicts it cannot express. The schema requires a `fallback.ask` whenever an enforcing event cannot ask.
- Corrected reply shapes (Contracts v1 used a flat `permissionDecision`):
  - Claude Code and Codex: `{"hookSpecificOutput": {"hookEventName", "permissionDecision", "permissionDecisionReason"}}`.
  - Cursor: `{"permission", "user_message", "agent_message"}`.
  The schema enforces the right shape for each `hooks.registration` value.
- New sections: `verified` (fixture provenance), `hooks.registration`, `fail_closed_option`, `trust`, `imported_by`, `payload_markers`, `tool_targets`, `mcp_tools`.
- Examples: Claude Code (verified against 2.1.304 fixtures), Cursor and Codex (documentation only), and 10 invalid definitions.
- `adapter-set.schema.json`: the signed set of adapter definitions (`set_version`, `min_sensor_version`). Example generated from the three definitions by `scripts/gen-conformance`; 3 invalid examples.
