package platform

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// ErrInsecure reports a file or directory that other users can tamper with or read.
var ErrInsecure = errors.New("platform: insecure permissions")

// EnsurePrivateDir creates dir (and parents) with mode 0700 if missing, then
// verifies that it is owned by the current user and closed to everyone else.
// An existing directory the user owns but left open to others (for example
// one launchd created for a log file) is tightened to 0700; a symlink or a
// directory owned by someone else is refused.
func EnsurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSymlink == 0 && info.Mode().Perm()&0o077 != 0 && checkOwner(dir, info) == nil {
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
	}
	return CheckPrivate(dir)
}

// CheckPrivate fails unless path is owned by the current user and grants no
// permissions to group or others. Used for the data dir, database and socket.
func CheckPrivate(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is a symlink", ErrInsecure, path)
	}
	if err := checkOwner(path, info); err != nil {
		return err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%w: %s has mode %#o, want no group or other access", ErrInsecure, path, perm)
	}
	return nil
}

// WritableByOthers reports whether users other than the owner can modify path.
// The scanner uses it for the "writable system config directory" posture check.
func WritableByOthers(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return writableByOthers(info), nil
}
