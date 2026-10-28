# Release keys

Privometry trusts only the key set in `release-keys.json` in this folder,
embedded at build time, for everything signed with the `release` role:

- self-update manifests (`privometry update`, payload type
  `application/vnd.privometry.release+json`);
- adapter definition sets (`privometry definitions`, payload type
  `application/vnd.privometry.adapters+json`);
- Privometry's detector pack sets (`privometry definitions`, payload type
  `application/vnd.privometry.detectorpacks+json`).

The file is a `privometry.keyset/v1` document
(`specs/common/v1/keyset.schema.json`) holding one or more `release` keys.

No key set ships yet: until the release key owner is decided (an open item in
`docs/implementation-plan.md`), this file is absent. Every update is refused
with "this build has no release signing keys", and no signed definition set
is accepted, so the sensor runs on the definitions and detector packs built
into it. Builds from source and package-manager installs are unaffected.

When the key exists, add `release-keys.json` here, sign each artifact as DSSE
with its payload type, and rotate keys with a new key set signed by a root
key.

## Root keys

`root-keys.json`, when present, holds the `root` keys that sign each region's
key set (`application/vnd.privometry.keyset+json`). An enrolled device gets
its region's key set from `/edge/v1/enroll` and verifies it against these
keys; the key set names the `policy` key that signs bundles and the `license`
key that signs entitlements. No root key exists yet either, so a device pins
the key set it gets at enrollment after checking that a root key listed in it
signed it, and `privometry device status` says so.

Never put test keys here: the conformance test keys have published seeds.
