// Package detectorpacks_test is the release gate for the detector packs: each
// detector must fire on its match samples and stay quiet on the others.
package detectorpacks_test

import (
	"testing"

	"github.com/privometry/privometry-oss/detectorpacks"
	"github.com/privometry/privometry-oss/internal/content"
)

func TestPacks(t *testing.T) {
	packs, err := content.Load(detectorpacks.FS)
	if err != nil {
		t.Fatal(err)
	}
	if len(packs) != 3 {
		t.Fatalf("expected the three Privometry detector packs, found %d", len(packs))
	}
	for _, p := range packs {
		t.Run(p.Manifest.ID, func(t *testing.T) {
			for _, err := range content.Check(p) {
				t.Error(err)
			}
			t.Logf("%s %s: %d detectors", p.Manifest.ID, p.Manifest.Version, len(p.Detectors))
		})
	}
}
