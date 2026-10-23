# edge-api/v1

## 1.0.0-draft.1 (2026-10-23)

- `openapi.yaml` (OpenAPI 3.1) for the nine endpoints of Contracts v1: enroll, certificate renewal, bundle, event batches, inventory, heartbeat, approvals (create and long-poll), risk feed and adapters.
- Bodies live in `messages.schema.json` as plain JSON Schema, so they are validated like every other contract; each has examples in `examples/<Message>/`.
- Additions beyond Contracts v1:
  - Enrollment returns an organization `hash_key` (HMAC key for hashed privacy levels); the bundle carries the organization's `privacy` settings.
  - Heartbeat reports `keyset_version`, `active_stops` and `acked_commands`; commands repeat until acknowledged and have `cmd_` IDs.
  - Hook status adds `untrusted` for Codex hooks the user has not approved yet.
  - Inventory snapshots use the event schema's inventory item and get an `inv_` receipt ID.
  - Rejected events in a batch carry a problem `type` and are not retried.
- Security: `mutualTLS` everywhere except enrollment (bearer enrollment token), the community risk feed and adapters (public).
- `TestEdgeAPI` checks the operation list, unique operation IDs, Idempotency-Key on every POST, problem+json on every error, Retry-After on 429, and that every `$ref` resolves and compiles. It is not a full OpenAPI validator.
- Server host `api.privometry.dev` is a placeholder.
