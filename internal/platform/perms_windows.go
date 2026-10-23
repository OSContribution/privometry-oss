//go:build windows

package platform

import "io/fs"

// Windows ACL checks arrive with Windows support in P2.
func checkOwner(string, fs.FileInfo) error { return nil }

func writableByOthers(fs.FileInfo) bool { return false }
