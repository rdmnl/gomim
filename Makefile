.DEFAULT_GOAL := help
SHELL := /usr/bin/env bash

BIN     := gomim
PKG     := ./cmd/gomim
DIST    := dist
COVER   := coverage.out

GO            ?= go
# Resolve $GOBIN (or fall back to $GOPATH/bin) so tools installed via
# `go install` are usable even if the user hasn't put it on $PATH.
GOBIN_DIR     := $(shell $(GO) env GOBIN)
ifeq ($(GOBIN_DIR),)
GOBIN_DIR     := $(shell $(GO) env GOPATH)/bin
endif
export PATH := $(GOBIN_DIR):$(PATH)

GOVULNCHECK   ?= govulncheck
GORELEASER    ?= goreleaser

# Tools we install on demand via `make tools`.
GOVULNCHECK_VERSION   ?= latest

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make <target>\n\nTargets:\n"} \
		/^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# ---------------------------------------------------------------------------
# Pipeline (mirrors .github/workflows/ci.yml)
# ---------------------------------------------------------------------------

.PHONY: ci
ci: scan test build ## Run the full local CI pipeline

.PHONY: scan
scan: ## Check Go module deps for known vulnerabilities
	@command -v $(GOVULNCHECK) >/dev/null || { echo "govulncheck not found — run 'make tools'"; exit 1; }
	$(GOVULNCHECK) ./...

.PHONY: test
test: ## Run tests with race detector + coverage
	$(GO) vet ./...
	$(GO) test -race -count=1 -coverprofile=$(COVER) ./...

.PHONY: cover
cover: test ## Open HTML coverage report
	$(GO) tool cover -html=$(COVER)

.PHONY: build
build: ## Build a snapshot release locally with GoReleaser
	@command -v $(GORELEASER) >/dev/null || { echo "goreleaser not found — install: brew install goreleaser"; exit 1; }
	$(GORELEASER) release --snapshot --clean --skip=publish,sign

# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------

.PHONY: dev
dev: ## Quick local build of the binary into ./bin/
	mkdir -p bin
	$(GO) build -o bin/$(BIN) $(PKG)

.PHONY: install
install: ## Install gomim to $GOPATH/bin (or $GOBIN)
	$(GO) install $(PKG)

.PHONY: run
run: ## Run gomim from source (use ARGS="-ui 127.0.0.1:8081" etc.)
	$(GO) run $(PKG) $(ARGS)

.PHONY: fmt
fmt: ## gofmt -s -w on the whole tree
	$(GO) fmt ./...

.PHONY: tidy
tidy: ## go mod tidy
	$(GO) mod tidy

.PHONY: clean
clean: ## Remove build artifacts and coverage
	rm -rf bin $(DIST) $(COVER)

.PHONY: tools
tools: ## Install lightweight dev tools (govulncheck)
	$(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	@echo
	@echo "goreleaser is NOT installed via 'go install' on purpose:"
	@echo "  it pulls hundreds of MB of cloud SDKs, cosign, sigstore, etc."
	@echo
	@echo "Install it via your package manager instead:"
	@echo "  macOS:  brew install goreleaser"
	@echo "  Linux:  see https://goreleaser.com/install"
