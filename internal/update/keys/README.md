# Release keys

`privometry update` trusts only the key set in `release-keys.json` in this folder,
embedded at build time. It is a `privometry.keyset/v1` document
(`specs/common/v1/keyset.schema.json`) holding one or more `release` keys.

No key set ships yet: until the release key owner is decided (an open item in
`docs/implementation-plan.md`), this file is absent and every update is
refused with "this build has no release signing keys". Builds from source and
package-manager installs are unaffected.

When the key exists, add `release-keys.json` here, publish each release's
manifest (`specs/release/v1`) signed as DSSE with payload type
`application/vnd.privometry.release+json`, and rotate keys with a new key set
signed by a root key.

Never put test keys here: the conformance test keys have published seeds.
