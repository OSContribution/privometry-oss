// Package ipc is the protocol between privometry-hook (and the CLI) and the
// daemon: one newline-terminated JSON request and one response per
// connection, over a Unix socket only the user can reach.
package ipc

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/platform"
)

// Version is the protocol version; the daemon rejects others.
const Version = 1

// MaxMessage bounds one message. Hook payloads are small, but Write tool
// inputs carry whole files.
const MaxMessage = 8 << 20

// Request is one call to the daemon.
type Request struct {
	V    int          `json:"v"`
	Op   string       `json:"op"` // hook, ping, status, events or probe
	Hook *HookRequest `json:"hook,omitempty"`
	// Query is the argument of non-hook operations, such as events.
	Query json.RawMessage `json:"query,omitempty"`
}

// HookRequest carries one agent hook invocation as received on stdin.
type HookRequest struct {
	Agent   string          `json:"agent"`   // agent product, for example claude_code
	Event   string          `json:"event"`   // the agent's event name, for example PreToolUse
	Payload json.RawMessage `json:"payload"` // the hook's stdin, verbatim
	// Probe is a one-time token from the probe operation. A hook call that
	// carries a valid one is decided as usual but not recorded, so privometry
	// doctor can test the whole path without writing fake agent activity.
	Probe string `json:"probe,omitempty"`
}

// Response is the daemon's answer. For a hook, Stdout, Stderr and ExitCode
// are exactly what privometry-hook writes and returns.
type Response struct {
	V        int    `json:"v"`
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
	Verdict  string `json:"verdict,omitempty"`
	EventID  string `json:"event_id,omitempty"`
	// Data carries the result of non-hook operations, such as status.
	Data json.RawMessage `json:"data,omitempty"`
}

// Call sends req to the daemon at addr and waits for the response, all
// within timeout.
func Call(addr string, req Request, timeout time.Duration) (Response, error) {
	req.V = Version
	conn, err := net.DialTimeout("unix", addr, timeout)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return Response{}, err
	}
	if err := writeMessage(conn, req); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := readMessage(conn, &resp); err != nil {
		return Response{}, err
	}
	if !resp.OK {
		return resp, fmt.Errorf("daemon: %s", resp.Error)
	}
	return resp, nil
}

func writeMessage(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

func readMessage(r io.Reader, v any) error {
	br := bufio.NewReaderSize(io.LimitReader(r, MaxMessage+1), 64<<10)
	line, err := br.ReadBytes('\n')
	if err != nil && !(errors.Is(err, io.EOF) && len(line) > 0) {
		return err
	}
	if len(line) > MaxMessage {
		return errors.New("ipc: message too large")
	}
	return json.Unmarshal(line, v)
}

// MaxSocketPath is the longest Unix socket path every supported OS accepts
// (macOS allows 104 bytes including the terminator).
const MaxSocketPath = 103

// Listen opens the daemon socket at addr. The parent directory must be
// private to the user; a stale socket left by a crashed daemon is removed,
// but a live one is an error.
func Listen(addr string) (net.Listener, error) {
	if len(addr) > MaxSocketPath {
		return nil, fmt.Errorf("ipc: socket path is %d bytes, over the %d-byte limit: %s (set PRIVOMETRY_HOME to a shorter folder)", len(addr), MaxSocketPath, addr)
	}
	if err := platform.EnsurePrivateDir(filepath.Dir(addr)); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(addr); err == nil {
		if c, err := net.DialTimeout("unix", addr, 200*time.Millisecond); err == nil {
			c.Close()
			return nil, fmt.Errorf("ipc: another daemon is listening on %s", addr)
		}
		if err := os.Remove(addr); err != nil {
			return nil, err
		}
	}
	l, err := net.Listen("unix", addr)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(addr, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Handler answers one request.
type Handler func(Request) Response

// Serve accepts connections until l is closed, answering each request with h
// on its own goroutine. Each connection must finish within timeout.
func Serve(l net.Listener, h Handler, timeout time.Duration) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go func() {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(timeout))
			var req Request
			resp := Response{}
			switch err := readMessage(conn, &req); {
			case err != nil:
				resp.Error = "bad request: " + err.Error()
			case req.V != Version:
				resp.Error = fmt.Sprintf("protocol version %d not supported (want %d)", req.V, Version)
			default:
				resp = h(req)
			}
			resp.V = Version
			_ = writeMessage(conn, resp)
		}()
	}
}
