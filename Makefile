GO        ?= go
PKG       := github.com/privometry/privometry-oss
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE      ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS   := -s -w \
	-X $(PKG)/internal/buildinfo.Version=$(VERSION) \
	-X $(PKG)/internal/buildinfo.Commit=$(COMMIT) \
	-X $(PKG)/internal/buildinfo.Date=$(DATE)
BINARIES  := privometry privometryd privometry-hook privometry-mcp-shim

.PHONY: all build test race lint fmt tidy clean hook-recorder generate check-generated

all: lint test build

build:
	@mkdir -p bin
	@for b in $(BINARIES); do \
		CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/$$b ./cmd/$$b || exit 1; \
	done

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

lint:
	$(GO) vet ./...
	@command -v golangci-lint >/dev/null && golangci-lint run || echo "golangci-lint not installed; skipped"

fmt:
	gofmt -s -w .

tidy:
	$(GO) mod tidy

# Regenerate Go types and signed conformance vectors from specs/.
generate:
	$(GO) run ./scripts/gen-types
	$(GO) run ./scripts/gen-conformance

check-generated:
	$(GO) run ./scripts/gen-types -check

# Spike tool: logs raw hook payloads from real agents into test/fixtures.
hook-recorder:
	@mkdir -p bin
	CGO_ENABLED=0 $(GO) build -o bin/hook-recorder ./scripts/hook-recorder

clean:
	rm -rf bin dist
