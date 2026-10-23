# Platform Integration

The Go edge communicates with the private Java platform through `specs/edge-api/v1`. The control plane, ingest service, processor, and MCP gateway must consume the same versioned contracts as the edge.

> Implementation status: the v1 contracts and generated Go message types exist, while enrollment, bundle synchronization, upload, heartbeat, approval, risk-feed, and adapter-set clients are staged for later cloud milestones. This page defines the integration target and required security behavior; it does not imply that every client path is implemented today.

## Ownership boundary

| Capability | Go edge | Java platform |
| --- | --- | --- |
| Local scanning and enforcement | Owns | Observes aggregated/redacted state |
| Hook latency and fail modes | Owns | Must not be required |
| Local timeline | Owns | Receives permitted redacted events |
| Device enrollment and certificates | Client | Authority |
| Policy authoring and distribution | Verifies/applies | Authors/signs/distributes |
| Entitlement enforcement | Reads signed capabilities | Issues and meters |
| Billing and invoices | None | Separate billing domain |
| MCP gateway | Local shim | Hosted/self-hosted Java gateway |

## Edge API operations

The v1 API defines:

- `POST /enroll`
- `POST /certs:renew`
- `GET /bundle`
- `POST /events:batch`
- `POST /inventory`
- `POST /heartbeat`
- approval create/read operations
- `GET /riskfeed`
- `GET /adapters`

Use the OpenAPI operation IDs and message schemas as the source of truth. Do not create Java-only request shapes.

## Enrollment

1. The operator obtains a short-lived enrollment token from the control plane.
2. The edge generates a device key and certificate-signing request locally.
3. `/enroll` returns device identity, certificate material, endpoints, and redaction/hash configuration.
4. Private device keys remain on the endpoint with restrictive permissions.
5. `/certs:renew` rotates certificates before expiry using authenticated device identity.

Enrollment or renewal failure must not disable local scanning, hooks, policy, or the timeline.

## Policy bundles

The edge requests the current bundle and activates it only after:

- DSSE payload-type verification;
- Ed25519 signature verification by a trusted policy key;
- key-role and validity-window checks;
- schema validation;
- rollback/version checks;
- entitlement-envelope verification.

The platform should support conditional fetches and return no change when the device already has the current version. The edge retains the last verified bundle while offline.

## Events and upload

Events use `event-schema/v1` and carry a per-device sequence. The edge batches events through `/events:batch`; the response acknowledges accepted/rejected counts and rejection categories.

Integration requirements:

- redact before enqueueing or upload;
- preserve device ordering and idempotency;
- bound batches and offline storage;
- reject unknown or malformed schema versions explicitly;
- never log client certificates, raw commands, full paths, or unredacted payloads;
- apply retention by signed entitlement in the processor/storage tier.

## Inventory and heartbeat

Inventory snapshots describe agents, versions, MCP servers, hooks, policy state, and posture without secret values. Heartbeats report operational health, queue depth, version, hook state, and policy/bundle state. Heartbeat gaps are a platform finding, not a signal to disable the endpoint.

## Approvals

An `ask` decision may be routed to the platform when organization policy enables remote approval. Approval requests are time-bounded and linked to a normalized action, rule IDs, device, user, and session. On timeout or connectivity failure, the edge follows the configured safe fallback; it does not silently allow.

## Risk feeds and adapters

Risk feeds and adapter sets are signed release artifacts. The edge validates sequence, publication time, minimum sensor version, schema, and signature role before replacing embedded data. A rejected update leaves the last valid or embedded set active.

## Entitlements and licenses

The edge consumes capabilities and limits, not billing state. A self-hosted license is an offline signed artifact. Invalid or expired licensing can restrict paid synchronization, retention, or enterprise management features, but local protection continues.

## Java integration checklist

- Generate Java types from the exact published schemas.
- Run all valid/invalid examples in platform CI.
- Run shared DSSE signature vectors against the Java verifier.
- Enforce mTLS and tenant context before message processing.
- Keep licensing checks out of local-protection decisions.
- Return stable machine-readable error types.
- Preserve unknown-event isolation so one rejected event does not poison a batch.
