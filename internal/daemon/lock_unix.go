//go:build unix

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// lock takes an exclusive lock on <dir>/privometryd.lock, so only one daemon runs
// per data directory even if its socket file was deleted.
func lock(dir string) (func(), error) {
	path := filepath.Join(dir, "privometryd.lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		pid, _ := os.ReadFile(path)
		f.Close()
		return nil, fmt.Errorf("another privometryd is running (pid %s, lock %s)", string(pid), path)
	}
	f.Truncate(0)
	f.WriteAt([]byte(strconv.Itoa(os.Getpid())), 0)
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
