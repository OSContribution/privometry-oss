package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyTest(t *testing.T) {
	broken := filepath.Join(t.TempDir(), "web-app")
	if err := os.CopyFS(broken, os.DirFS("../../policies/examples/web-app")); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(broken, "policy.yaml"))
	noException := string(raw[:strings.Index(string(raw), "exceptions:")])
	if err := os.WriteFile(filepath.Join(broken, "policy.yaml"), []byte(noException), 0o644); err != nil {
		t.Fatal(err)
	}
	invalid := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(invalid, []byte("schema: privometry.policy/v1\nname: x\nrules:\n  - id: r\n    when: { programme: rm }\n    verdict: deny\n    message: no\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		args []string
		code int
		out  string
	}{
		{"pack passes", []string{"test", "../../rulepacks/secrets"}, 0, "PASS pack privometry/secrets: 11 rules"},
		{"example policy passes", []string{"test", "../../policies/examples/web-app/policy.yaml"}, 0, "PASS policy web-app"},
		{"missing exception fails", []string{"test", filepath.Join(broken, "policy.yaml")}, 1, "want ask []"},
		{"schema error fails", []string{"test", invalid}, 1, "programme"},
		{"explain a command", []string{"test", "--command", "cd ~ && rm -rf old"}, 0, "Verdict: deny (policy)"},
		{"explain a read", []string{"test", "--read", "/tmp/x/.env.local"}, 0, "privometry/secrets:read-env-file"},
		{"explain with an extra policy", []string{"test", "--command", "git push -f", "../../policies/examples/web-app/policy.yaml"}, 0, "Verdict: deny"},
		{"missing subcommand", []string{}, 2, ""},
		{"bad layer", []string{"test", "--layer", "team", "x.yaml"}, 2, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(append([]string{"policy"}, tc.args...), &stdout, &stderr)
			if code != tc.code {
				t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", code, tc.code, stdout.String(), stderr.String())
			}
			if !strings.Contains(stdout.String(), tc.out) {
				t.Errorf("output lacks %q:\n%s", tc.out, stdout.String())
			}
		})
	}
}
