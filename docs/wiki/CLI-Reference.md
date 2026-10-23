# CLI Reference

The main executable is `privometry`. Exit code `0` means success, `1` means a policy/finding/health condition was detected, and `2` means invalid usage or a runtime error.

## `privometry scan`

Discovers agents and reports risky configuration.

```sh
privometry scan [--format table|json|sarif] [--repo PATH] [--no-repo]
                 [--no-machine] [--fail-on SEVERITY] [--output FILE]
```

- `--repo`: scan a specific repository; otherwise the containing Git repository is used.
- `--no-repo`: scan machine configuration only.
- `--no-machine`: scan repository configuration only, suitable for CI.
- `--fail-on low|medium|high|critical`: return exit code 1 at or above the threshold.
- `--output`: write the report to a file.

CI example:

```sh
privometry scan --no-machine --format sarif --fail-on high --output privometry.sarif
```

## `privometry daemon`

Manages the per-user daemon service.

```sh
privometry daemon install|uninstall|status|restart
  [--privometryd PATH] [--dry-run] [--format table|json]
```

Service installation currently supports launchd on macOS and systemd user services on Linux.

## `privometry guard`

Registers or removes native agent hooks.

```sh
privometry guard install|uninstall|status
  [--agent AGENT] [--hook PATH] [--dry-run] [--format table|json]
```

Agent identifiers are `claude_code`, `codex_cli`, and `cursor`. Installation preserves unrelated agent hooks.

## `privometry timeline`

Queries redacted local events.

```sh
privometry timeline [--agent AGENT] [--verdict allow|ask|deny]
  [--type TYPE] [--search TEXT] [--since DURATION] [--limit N]
  [--format table|json] [--follow] [--web] [--port PORT] [--no-open]
```

Event types are `action`, `config_change`, `integrity`, `fail_mode`, `inventory`, and `content_finding`. The web view binds to loopback and uses a per-run access token.

## `privometry policy test`

Tests policy files or rule-pack directories and can explain synthetic actions.

```sh
privometry policy test [--layer user|repo|org] [--tests DIR] [PATH...]
privometry policy test --command COMMAND [--untrusted] [--agent AGENT]
privometry policy test --read PATH
privometry policy test --write PATH
privometry policy test --fetch URL
```

With no path, Privometry looks for `.privometry/policy.yaml` in the current repository and `~/.privometry/policy.yaml`.

## `privometry doctor`

Checks binary consistency, permissions, service and daemon health, a real synthetic hook decision, fail modes, installed hooks, policy, spool state, and integrity alerts.

```sh
privometry doctor [--format table|json] [--no-probe]
privometry doctor --bundle [--output FILE]
```

Inspect diagnostic archives before sharing even though the bundle is redacted.

## `privometry update`

Checks or installs a signed release:

```sh
privometry update --check
privometry update [--manifest URL]
```

`PRIVOMETRY_UPDATE_URL` supplies an alternate manifest. Development builds and builds without release trust keys refuse self-update.

## `privometry version`

Prints the version, commit, and build date injected by the release build.

## Environment variables

| Variable | Meaning |
| --- | --- |
| `PRIVOMETRY_HOME` | Override the runtime data directory |
| `PRIVOMETRY_HOOK_TIMEOUT_MS` | Override hook-to-daemon timeout |
| `PRIVOMETRY_UPDATE_URL` | Override signed release manifest URL |
| `PRIVOMETRY_RECORD_DIR` | Development-only hook recorder output directory |
| `NO_COLOR` | Disable terminal color |

`PRIVOMETRY_HOOK_PROBE` is an internal, one-time doctor token and is not a supported operator setting.
