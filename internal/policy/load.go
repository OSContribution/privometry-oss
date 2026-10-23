package policy

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"

	"github.com/privometry/privometry-oss/internal/policy/compiler"
	"github.com/privometry/privometry-oss/internal/policy/merge"
	"github.com/privometry/privometry-oss/internal/policy/rulepack"
	"github.com/privometry/privometry-oss/rulepacks"
	"github.com/privometry/privometry-oss/specs"
)

// BuiltinPacks returns the rule packs shipped in the sensor.
func BuiltinPacks() ([]rulepack.Pack, error) { return rulepack.Load(rulepacks.FS) }

// LoadFile reads a policy file, validates it and tags it with its layer.
func LoadFile(path, layer string) (merge.Source, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return merge.Source{}, err
	}
	if err := specs.Validate("policy/v1/policy.schema.json", path, raw); err != nil {
		return merge.Source{}, err
	}
	var p compiler.Policy
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return merge.Source{}, fmt.Errorf("%s: %w", path, err)
	}
	return merge.Source{Layer: layer, Policy: p}, nil
}

// Local paths of the user and repo policy files.
const (
	UserPolicyPath = ".privometry/policy.yaml" // under the home folder
	RepoPolicyPath = ".privometry/policy.yaml" // under the repo root
)

// LocalSources loads the user policy (~/.privometry/policy.yaml) and the repo
// policy (<repo>/.privometry/policy.yaml) when they exist. A file that fails to
// load is reported in errs and skipped, so a broken repo file cannot turn
// protection off.
func LocalSources(home, repoRoot string) (sources []merge.Source, errs []error) {
	try := func(path, layer string) {
		src, err := LoadFile(path, layer)
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			errs = append(errs, fmt.Errorf("%s policy ignored: %w", layer, err))
		default:
			sources = append(sources, src)
		}
	}
	if home != "" {
		try(filepath.Join(home, UserPolicyPath), merge.User)
	}
	if repoRoot != "" {
		try(filepath.Join(repoRoot, RepoPolicyPath), merge.Repo)
	}
	return sources, errs
}
