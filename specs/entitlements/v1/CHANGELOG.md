# entitlements/v1

## 1.0.0-draft.1 (2026-10-23)

- `entitlements.schema.json` as in Contracts v1. Additions and constraints:
  - `valid_until` is null only for the free edition, which is always `active`;
  - `state: trial` requires `edition: trial`;
  - `key_id` must be a `license:` key.
- `license.schema.json`: the license file payload. `air_gapped` licenses must carry a `binding`; the free edition never has a license file.
- `feature-registry.json` (with `feature-registry.schema.json`): every feature key, the editions that include it, and whether it is local. Local features must include the free edition; `TestFeatureRegistry` checks that entitlement examples use registered keys and never switch a local feature off (ADR-0003). Extension keys use the `x_` prefix.
- Examples: 5 valid and 10 invalid entitlements, 2 valid and 5 invalid licenses.
