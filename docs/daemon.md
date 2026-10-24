# Daemon, hook client and guard

How a tool call is decided on the developer's machine.

```
agent ──stdin──► privometry-hook ──Unix socket──► privometryd ──► policy ──► timeline (SQLite)
                     │  (daemon down or slow)
                     └──► fail modes alone ──► spool.jsonl ──(imported later)──► timeline
```

## privometryd

The daemon (`cmd/privometryd`, `internal/daemon`). Install it as a per-user background service with `privometry daemon install`, or run `privometryd` in the foreground. Timeline targets are redacted at the SQLite persistence boundary by default, including events imported from the fallback spool.

- **Socket**: `~/.privometry/privometryd.sock`, mode 0600 in a 0700 folder. One JSON request and response per connection (`internal/ipc`). A lock file (`privometryd.lock`) keeps it to one daemon per data folder.
- **Per hook call**: reads the payload through the adapter's request pointers, maps the tool to an action (`tool_kinds`, `tool_targets`, MCP name template, `apply_patch` files), looks up the session, decides with the merged policy (shipped packs, `~/.privometry/policy.yaml`, the repo's `.privometry/policy.yaml`), renders the agent's native reply from the adapter's templates, and records the event.
- **Workspace**: the git root, or the working folder when it is inside home and not under git, so a project folder's own files are not treated as "home".
- **Policies** are cached per repo and reloaded when either policy file changes, or when an exception expires.
- **Verdicts the agent cannot express** use the event's fallback (Codex has no ask: it receives deny); the event records `native_verdict`.
- **Dedupe**: a tool call reported twice (Cursor also runs Claude Code's hooks) is decided once, by `tool_use_id`, for two minutes. The caller is detected from payload markers, so Cursor's calls are recorded as Cursor.
- **Session state**: post-tool hooks mark a session as having seen untrusted input after web fetches and searches, MCP responses, `curl`/`wget`, and `gh issue`/`pr` reads. The flag feeds `untrusted_input_seen` in every later decision and survives daemon restarts.
- **Housekeeping**: imports the hook client's spool every minute; prunes events after 30 days and idle sessions after 7.
- **Imported hooks**: Cursor also runs Claude Code's hooks. When Cursor has its own Privometry hook, the imported Claude Code call gives no opinion and is not recorded, so each action is decided once.
- **Status**: `privometry daemon status` (and `guard status`) ask the daemon for its version, uptime and the last hook call per agent. The daemon also lists the IPC operations it answers, so a CLI newer than the running daemon says to restart it.
- **Integrity**: every minute it hashes the agents' config files and records config changes and removed or modified Privometry hooks; see `docs/developer-experience.md`.
- **Probes**: `privometry doctor` gets a one-time token (`probe` operation) so its test hook call is decided but not recorded.
- **Content scanning**: commands, URLs, MCP arguments and written content are scanned before each decision (5 ms budget), tool output after it; findings become `content_finding` events and facts for the rules, and memory files are hashed with person-or-agent attribution. See `docs/content-scanning.md`.
- **Data**: `~/.privometry/` (or `$PRIVOMETRY_HOME`): `privometry.db`, `failmodes.json`, `spool.jsonl`, `privometryd.log`, all 0600.

## privometry daemon

```bash
privometry daemon install --dry-run   # show the service file and commands
privometry daemon install             # write it, load it, wait for privometryd to answer
privometry daemon status              # service state, daemon version and uptime, last hook call per agent
privometry daemon restart
privometry daemon uninstall
```

| OS | Service | File |
|---|---|---|
| macOS | launchd agent `dev.privometry.privometryd` (`launchctl bootstrap gui/<uid>`), `RunAtLoad`, `KeepAlive`, log in `~/.privometry/privometryd.log` | `~/Library/LaunchAgents/dev.privometry.privometryd.plist` |
| Linux | systemd user unit, `Restart=on-failure`, enabled for login | `~/.config/systemd/user/privometryd.service` (honors `XDG_CONFIG_HOME`) |

The service runs as the user, never root. `PRIVOMETRY_HOME` is carried into the service when set. Installing again rewrites the file and restarts the daemon, which is how upgrades work; `status` flags a service file that no longer matches. Windows is P2.

## Timeline

`internal/timeline`, SQLite in WAL mode (`modernc.org/sqlite`, no cgo). Tables follow the database design: `events` (one row per event, the full `privometry.event/v1` payload with the target redacted, plus `target_clear`, which never leaves the device), `sessions`, and `state` (device ID, `device_seq`). `device_seq` is incremented in the same transaction as the insert, so the sequence has no gaps. Every stored event validates against the event schema in tests.

## privometry-hook

The client agents run (`cmd/privometry-hook`, `internal/hookclient`): `privometry-hook <agent> <event>`, payload on stdin.

- Sends the call to the daemon with a 200 ms budget (`PRIVOMETRY_HOOK_TIMEOUT_MS`) and prints its reply.
- If the daemon is down, slow or fails, it decides alone: extracts facts with the same extractors, maps each request to a category, and applies the fail mode from `failmodes.json` (written by the daemon) or the defaults: catastrophic **closed** (deny), secrets and exfiltration **ask** (deny where the agent cannot ask), everything else **open**.
- **Open never auto-approves**: it prints nothing, so the agent's own permission prompt still applies.
- Each fallback decision is appended to `spool.jsonl` (capped at 10 MB) as a `fail_mode` event.
- Its fallback replies are built in and tested against the adapter templates, so they cannot drift.
- It loads no policy engine, database, YAML or schema code: 3.5 MB.

## privometry guard

```bash
privometry guard install --dry-run      # show the change to ~/.claude/settings.json
privometry guard install                # register privometry-hook for every hook event
privometry guard status                 # installed, partial, stale or missing, per agent
privometry guard uninstall              # remove only Privometry's entries
```

- Edits the settings file as ordered JSON, so the user's keys stay in place and their own hooks are untouched; installing twice changes nothing.
- Keeps a copy at `settings.json.privometry-backup` before the first change and writes atomically with the same permissions. Refuses to touch a file that is not valid JSON.
- Adds `onFailure: block` to decision hooks only when the detected Claude Code version supports it (2.1.295 and later); older or unknown versions might reject the key.
- Honors `CLAUDE_CONFIG_DIR` and `CODEX_HOME`.

| Agent | File | Fail closed | Notes |
|---|---|---|---|
| Claude Code | `~/.claude/settings.json` | `onFailure: block` on `PreToolUse`, version 2.1.295 and later | |
| Cursor | `~/.cursor/hooks.json` | `failClosed: true` on decision events | Shell and MCP events can ask; `preToolUse` covers writes, deletes and subagents |
| Codex CLI | `~/.codex/hooks.json` | Not available: if `privometry-hook` crashes, the action proceeds | `UserPromptSubmit` records privacy-preserving query metadata; `PreToolUse` guards actions. Codex runs a new user hook only after you trust it: open Codex and run `/hooks` once. `install` prints this step and warns if `[features] hooks = false` in `config.toml` |

After upgrading from a version that only registered tool hooks, run `privometry guard install --agent codex_cli` again and approve the updated hook set through Codex `/hooks`. Query events store a device-keyed fingerprint, prompt identifier and character count. The raw query text is never written to the timeline event database.

`guard status` shows each agent's state and its last hook call from the daemon. A Codex hook that is installed but has never fired shows "no calls yet: Open Codex, run /hooks and trust the Privometry hook once".

## Measured

On an M-series Mac, spawning `privometry-hook` from a script:

| Path | p50 | p95 |
|---|---|---|
| Daemon running (`ls`, `rm -rf ~`, a `bash -c` pipeline) | 4.1–4.4 ms | 5.3–8.4 ms |
| Daemon down (fail modes alone) | 3.8 ms | 5.3 ms |

The decision inside the daemon takes under 1 ms. Verified end to end with a real Claude Code 2.1.304 session: `ls` and a repo-local write were auto-approved without `--allowedTools`, `rm -rf ~/…` was denied by `home-recursive-delete`, `cat .env` was stopped by `read-env-file`, and with the daemon stopped the same `rm` was denied by the hook client's closed fail mode and recorded once the daemon came back.

## Known gaps

- Privometry cannot read Codex's hook trust state; it infers it from whether Codex has called the hook yet.
- `guard` rewrites the settings file in two-space JSON. Content is preserved, but a file formatted differently (inline arrays, tabs) is reformatted; `--dry-run` shows exactly what changes.
- Cursor and Codex installs are tested against their documented formats, not yet against recorded sessions.
- The launchd agent is verified on a real Mac; the systemd unit is tested with a fake runner only.
- MCP calls whose tool name does not look read-only are medium risk, so they ask under `unmatched: auto`. That includes host apps' own MCP tools (the Claude desktop app's `ccd_*` tools); allow the ones you trust in `~/.privometry/policy.yaml`.
- The fail modes file reflects the user and built-in layers only; a repo policy's stricter fail modes apply only while the daemon runs.
- Reading repo files does not mark a session untrusted, so issue text pasted into a repo file is not tracked.
- The 200 ms hook budget is above the contract's proposed 100 ms, because the first call for a new repo compiles its policy.
- Windows named pipes and service install are P2.
