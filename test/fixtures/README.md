# Fixtures

Real agent config files and hook payloads, organized as `<agent>/<version>/<kind>/`. Adapter tests parse every file here, so a vendor change that breaks parsing fails CI (see Contracts v1, "Adapter fixtures").

| Path | Source | Recorded |
|---|---|---|
| `claude_code/2.1.304/hooks/` | Headless session with `scripts/hook-recorder` on every event | 2026-10-23 |

Rules:

- Sanitize before committing: home directory becomes `/home/dev`, project paths `/home/dev/acme-api`, and nothing machine- or person-specific remains.
- Never commit secrets, real prompts with private content, or real MCP server URLs.
- Keep payloads byte-for-byte otherwise, including undocumented fields.
