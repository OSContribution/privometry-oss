// Package detectorpacks embeds the content detector packs shipped in the
// sensor. The test in this folder is the release gate every pack must pass.
package detectorpacks

import "embed"

// FS holds each pack's manifest and detector files.
//
//go:embed */pack.yaml */detectors/*.yaml
var FS embed.FS
