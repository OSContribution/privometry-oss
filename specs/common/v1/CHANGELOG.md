# common/v1

## 1.0.0-draft.1 (2026-10-23)

- Shared `$defs`: prefixed ULID IDs, timestamps, durations, semver, sha256 digests, privacy levels, redaction map, `ext`, and common enums (agent product, OS, arch, config tier, verdict, rule category, risk, path class, fail mode).
- DSSE envelope schema with standard field names and Privometry key-role IDs.
- Examples: one envelope signed with a published test key, five invalid envelopes.

## 1.0.0-draft.2 (2026-10-23)

- `keyset.schema.json`: role keys with validity windows. The sensor pins a root key set; rotations are key sets signed by a current root key with a higher version.
- New shared definitions: `component_id` (`mcp_`, `skl_`, `plg_`, `ext_`), `keyid`, `https_url`, `action_kind`, `intent`, `catalog_status`.
- Hashed privacy level: `hmac-sha256:<hex>` of the trimmed value under the organization hash key. HMAC replaces the "salted SHA-256" of Contracts v1, which is weaker against guessing when the salt leaks.
- Examples moved to `examples/dsse/` and `examples/keyset/`.
