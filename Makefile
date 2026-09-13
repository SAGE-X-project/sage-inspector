GO ?= go
export GOTOOLCHAIN ?= auto

.PHONY: build test lint
build:
	$(GO) build -ldflags "-X main.Version=$$(git describe --tags --always --dirty)" -o bin/sage-inspector ./cmd/sage-inspector

test:
	$(GO) test -race ./...

lint:
	golangci-lint run ./...

# New foundation can build/test without loading the historical SAGE core.
.PHONY: build-foundation test-foundation
build-foundation:
	$(GO) build -o bin/sage-conformance ./cmd/sage-conformance

test-foundation:
	$(GO) test -race ./pkg/conformance ./internal/conformancecli ./cmd/sage-conformance ./examples/reference-adapter
	$(GO) vet ./pkg/conformance ./internal/conformancecli ./cmd/sage-conformance ./examples/reference-adapter
