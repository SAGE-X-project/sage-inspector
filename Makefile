GO ?= go
export GOTOOLCHAIN ?= auto

.PHONY: build test lint
build:
	$(GO) build -ldflags "-X main.Version=$$(git describe --tags --always --dirty)" -o bin/sage-inspector ./cmd/sage-inspector

test:
	$(GO) test -race ./...

lint:
	golangci-lint run ./...
