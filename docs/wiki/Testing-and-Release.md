# Testing and Release

## Test layers

| Layer | Coverage |
| --- | --- |
| Unit | Parsers, intent extraction, policy merge/compiler/engine, redaction, permissions |
| Contract | Every valid example passes and every invalid example fails |
| Conformance | Policy verdicts, redaction vectors, and DSSE signature behavior |
| Component | Scanner, daemon, hook client, IPC, timeline, updater, web UI |
| Adapter | Discovery, paths, hook mapping, install/uninstall, native replies |
| Race | Concurrent daemon, scanner, and storage paths |
| Release dry run | Cross-platform GoReleaser build and archive layout |

## Local release gate

```sh
make fmt
make lint
make test
make race
make check-generated
make build
```

Verify deterministic conformance output:

```sh
go run ./scripts/gen-conformance
git diff --exit-code -- specs
```

Tests that bind local sockets require an execution environment that permits Unix/TCP loopback listeners.

## Continuous integration

The native GitLab pipeline in `.gitlab-ci.yml` runs for merge requests, the default branch, tags, and manually started pipelines. It performs formatting and vet checks, verifies generated types and deterministic conformance vectors, runs race-enabled tests with a coverage artifact, builds all binaries, validates the repository policy, and scans repository configuration and memory files. High or critical Privometry findings fail the pipeline; the SARIF report remains downloadable for 30 days even when the security job fails.

The existing GitHub workflows are optional mirrors for downstream users. They run the Linux/macOS test matrix, linting, a GoReleaser snapshot, CodeQL, JSON syntax checks, SBOM generation, and dependency inventory. GitLab remains the canonical project and CI environment.

The Go build and module caches are stored below the CI project directory and keyed per GitLab project. No user configuration or machine-wide agent state is scanned in CI; `--no-machine` limits the security gate to the checked-out repository. The release-compliance job also creates a deterministic CycloneDX 1.5 SBOM and a dependency-license policy report from the modules linked into the four release commands. A missing or unrecognized dependency license fails the job, while both reports remain available for review.

Contract validation in Go is stronger than syntax-only validation: it compiles schemas and checks all positive and negative fixtures.

## Versioning

- Git tags use `vMAJOR.MINOR.PATCH`.
- Binaries report the semantic version without the `v` prefix when injected by GoReleaser.
- Public contract versions are independent directories such as `policy/v1`.
- Rule packs and detector packs have their own semantic versions and minimum sensor versions.
- Adapter sets, risk feeds, key sets, and bundles carry monotonic versions or sequences where their schemas require them.

## Build artifacts

GoReleaser builds static binaries for macOS and Linux on `amd64` and `arm64`:

- `privometry`
- `privometryd`
- `privometry-hook`
- `privometry-mcp-shim`

Archives include `LICENSE`, `NOTICE`, `README.md`, `privometry.cdx.json`, and `dependency-licenses.json`, plus a checksum manifest. Generate and inspect the compliance files locally with `make release-metadata`. Windows release packaging is not enabled yet.

## Signing requirements

The runtime understands signed releases, but repository release automation must not be considered production-ready until the release trust root, key custody, artifact signing, and rotation process are configured and audited.

A production release requires:

1. an offline or hardware-protected root key process;
2. role-specific release keys with validity windows;
3. a DSSE-signed `privometry.release/v1` manifest;
4. SHA-256 and size metadata for every platform archive;
5. published checksums and SBOM;
6. a tested rotation and revocation procedure;
7. a rollback-safe stable manifest endpoint.

Never commit private signing keys. The edge intentionally refuses self-update when it has no trusted release keys.

## Release procedure

1. Ensure `main` is green and generated output is clean.
2. Review contract, rule-pack, detector-pack, adapter, and migration changelogs.
3. Build and smoke-test each target architecture.
4. Create and sign the release manifest through the approved signing system.
5. Tag the exact commit.
6. Let the release workflow build immutable artifacts.
7. Verify downloaded artifacts independently before publishing the stable manifest.
8. Exercise `privometry update --check` and a full update from the previous supported version.
9. Verify daemon restart, hooks, policy, timeline, and offline behavior.

## Rollback

The self-updater refuses downgrades. An operational rollback is therefore a package-manager or explicit reinstall procedure, not an unsigned manifest change. Never weaken version or signature checks to recover a release.
