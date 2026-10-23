# event-schema/v1

## 1.0.0-draft.2 (2026-10-23)

- Content scanning (PRD SCAN-01 to SCAN-11, Contracts v1 `content_finding`):
  - new event type `content_finding` with its section: `detector_id` (`<pack>:<name>`), `pack_version`, `category` (six), `severity`, `confidence`, `source` (eight), `secret_type`, `location` (`path_class`, salted `path_hash`, `line`, `tier`, `agent_product`; never a raw path), `fingerprint`, `action_taken`;
  - `secret_type` is required for credentials, and `secret_type` and `fingerprint` are only allowed on credentials;
  - findings from `action_argument`, `file_write` or `tool_output` must carry `agent` and `action`;
  - `action.secret_types`: credential kinds found in an action, never values;
  - `context.injection_seen`: stays true for the rest of a session once injected content was read.
- `secret_type` is a snake_case name rather than an enum, so detector packs can add kinds.
- `config.holds` gains `instructions`, `rules` and `memory` for agents' memory and instruction files, and `config.changed_by` (`person`, `agent`, `unknown`) records who changed one (PRD SCAN-02).
- Examples: 14 valid, 27 invalid.

## 1.0.0-draft.1 (2026-10-23)

- Envelope and the five event types from Contracts v1 (`action`, `config_change`, `integrity`, `fail_mode`, `inventory`), with required sections per type and `mcp` required for `mcp_call` actions.
- Defined the type-specific sections the contract left open: `config`, `integrity`, `fail_mode`, `inventory`.
- Additions beyond Contracts v1, from the hook spike:
  - `agent.native_session_id`: the agent's own session ID; `session_id` stays a Privometry `ses_` ID.
  - `action.tool_use_id`: lets the daemon dedupe when Cursor also runs Claude Code hooks.
  - `decision.native_verdict`: what the agent actually received when it cannot express the verdict (Codex has no ask).
  - `decision.would_verdict` required in monitor mode, where `verdict` must be `allow`.
- Examples: 10 valid, 19 invalid.
