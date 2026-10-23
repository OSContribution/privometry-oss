package specs_test

import (
	"os"
	"path"
	"slices"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/privometry/privometry-oss/specs"
)

// TestEdgeAPI checks openapi.yaml against the edge API contract. It is not a
// full OpenAPI validator; CI should also run an OpenAPI 3.1 linter.
func TestEdgeAPI(t *testing.T) {
	const dir = "edge-api/v1"
	raw, err := os.ReadFile(dir + "/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if v, _ := doc["openapi"].(string); !strings.HasPrefix(v, "3.1.") {
		t.Fatalf("openapi version %q, want 3.1.x", v)
	}

	// The nine endpoints of Contracts v1 (approvals has two operations).
	want := []string{
		"GET /adapters", "GET /approvals/{approval_id}", "GET /bundle", "GET /riskfeed",
		"POST /approvals", "POST /certs:renew", "POST /enroll", "POST /events:batch",
		"POST /heartbeat", "POST /inventory",
	}
	var got []string
	ids := map[string]bool{}
	paths := doc["paths"].(map[string]any)
	for p, item := range paths {
		for method, op := range item.(map[string]any) {
			op := op.(map[string]any)
			name := strings.ToUpper(method) + " " + p
			got = append(got, name)
			id, _ := op["operationId"].(string)
			if id == "" || ids[id] {
				t.Errorf("%s: missing or duplicate operationId %q", name, id)
			}
			ids[id] = true
			if method == "post" && !hasParam(op, "#/components/parameters/IdempotencyKey") {
				t.Errorf("%s: POST must accept Idempotency-Key", name)
			}
			responses := op["responses"].(map[string]any)
			if _, ok := responses["429"]; !ok {
				t.Errorf("%s: must document 429", name)
			}
			for code, r := range responses {
				if (code[0] == '4' || code[0] == '5') && !isProblem(doc, r) {
					t.Errorf("%s %s: error responses must be application/problem+json", name, code)
				}
			}
		}
	}
	sort.Strings(got)
	if !slices.Equal(got, want) {
		t.Errorf("operations:\n got %v\nwant %v", got, want)
	}
	if tm := lookup(doc, "#/components/responses/TooManyRequests/headers/Retry-After"); tm == nil {
		t.Error("429 responses must carry Retry-After")
	}

	// Every $ref resolves: local refs inside the document, file refs compile.
	walkRefs(doc, func(ref string) {
		if strings.HasPrefix(ref, "#") {
			if lookup(doc, ref) == nil {
				t.Errorf("unresolved local $ref %s", ref)
			}
			return
		}
		file, frag, _ := strings.Cut(ref, "#")
		target := path.Clean(path.Join(dir, file))
		if frag != "" {
			target += "#" + frag
		}
		if _, err := specs.Schema(target); err != nil {
			t.Errorf("$ref %s: %v", ref, err)
		}
	})
}

func hasParam(op map[string]any, ref string) bool {
	params, _ := op["parameters"].([]any)
	for _, p := range params {
		if m, ok := p.(map[string]any); ok && m["$ref"] == ref {
			return true
		}
	}
	return false
}

func isProblem(doc map[string]any, r any) bool {
	m, _ := r.(map[string]any)
	if ref, ok := m["$ref"].(string); ok {
		m, _ = lookup(doc, ref).(map[string]any)
	}
	content, _ := m["content"].(map[string]any)
	_, ok := content["application/problem+json"]
	return ok
}

func lookup(doc map[string]any, ref string) any {
	var cur any = doc
	for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		part = strings.NewReplacer("~1", "/", "~0", "~").Replace(part)
		if cur, ok = m[part]; !ok {
			return nil
		}
	}
	return cur
}

func walkRefs(v any, fn func(string)) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if s, ok := e.(string); ok && k == "$ref" {
				fn(s)
				continue
			}
			walkRefs(e, fn)
		}
	case []any:
		for _, e := range x {
			walkRefs(e, fn)
		}
	}
}
