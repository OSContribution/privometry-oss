// Package adapterdefs embeds the adapter definitions shipped in the sensor
// binary. Newer signed sets from the cloud replace them at run time (P2).
package adapterdefs

import "embed"

// FS holds every *.yaml definition in this folder.
//
//go:embed *.yaml
var FS embed.FS
