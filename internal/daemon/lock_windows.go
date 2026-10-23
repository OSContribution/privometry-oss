//go:build windows

package daemon

// lock is a no-op on Windows until the named-pipe transport lands (P2).
func lock(string) (func(), error) { return func() {}, nil }
