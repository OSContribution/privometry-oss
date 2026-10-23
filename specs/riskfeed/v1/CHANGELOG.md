# riskfeed/v1

## 1.0.0-draft.1 (2026-10-23)

- `riskfeed.schema.json`: one document type for snapshots and deltas (`kind`), with `feed` (community or curated), an increasing `sequence`, `base_sequence` and `removed` on deltas only.
- Entries follow Contracts v1, including the four-subscore model. The schema enforces:
  - score 0–100, each subscore 0–25, and the level matching the score band (0–24 low, 25–49 medium, 50–74 high, 75–100 critical);
  - `known_malicious` or `tool_description_injection` forces score 100 and `default_verdict: deny`;
  - component ID prefix matching `kind`: `mcp_`, `skl_`, `plg_`, `ext_` (new prefixes for skills, plugins and IDE extensions).
- `TestRiskScoreSums` checks what the schema cannot: the score equals the subscore sum unless `score_breakdown.override` says why not.
- Advisories carry `PRIVOMETRY-ADV-YYYY-NNNN` IDs, optional aliases (CVE, GHSA) and an optional CVSS 3.1 or 4.0 vector.
- Signal list fixed for v1 (15 values); new signals are added in minor releases.
- Examples: 2 valid, 13 invalid.
