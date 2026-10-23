//go:build unix

package platform

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

func checkOwner(path string, info fs.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("platform: cannot read owner of %s", path)
	}
	if uid := os.Getuid(); int(st.Uid) != uid {
		return fmt.Errorf("%w: %s is owned by uid %d, not %d", ErrInsecure, path, st.Uid, uid)
	}
	return nil
}

func writableByOthers(info fs.FileInfo) bool {
	return info.Mode().Perm()&0o022 != 0
}
