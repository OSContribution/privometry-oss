//go:build !windows

package keystore

import "gitlab.com/cn-solutions/privometry/privometry-oss/internal/platform"

func dpapiStore(platform.Env) Store { return nil }
