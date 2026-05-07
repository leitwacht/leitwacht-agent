.DEFAULT_GOAL := help

GO ?= go
GOOS ?= $(shell $(GO) env GOOS)
GOARCH ?= $(shell $(GO) env GOARCH)

# Build metadata stamped into binaries via -ldflags.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w \
  -X gitlab.com/leitwacht/leitwacht-agent/agentcore/version.Version=$(VERSION) \
  -X gitlab.com/leitwacht/leitwacht-agent/agentcore/version.Commit=$(COMMIT)

BIN_DIR := bin

.PHONY: help
help:
	@awk 'BEGIN{FS=":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: tidy
tidy: ## go mod tidy
	$(GO) mod tidy

.PHONY: fmt
fmt: ## gofmt the tree
	gofmt -w .

.PHONY: lint
lint: ## go vet + gofmt -l (CI-equivalent)
	$(GO) vet ./...
	@out="$$(gofmt -l .)"; \
	  if [ -n "$$out" ]; then echo "gofmt issues:"; echo "$$out"; exit 1; fi

.PHONY: test
test: ## fast unit tests (Linux build tags, no integration)
	$(GO) test -race -count=1 -tags=linux ./...

.PHONY: test-ce
test-ce: ## CE-only unit + component tests (cross-platform)
	$(GO) test -race -count=1 ./ce/...

.PHONY: ebpf-generate
ebpf-generate: ## regenerate eBPF .o + Go bindings (requires clang + llvm-strip)
	$(GO) generate ./agentcore/enforcer/...

.PHONY: check-ebpf-drift
check-ebpf-drift: ## fail if committed eBPF artefacts don't match the .c sources
	@$(GO) generate ./agentcore/enforcer/... >/dev/null
	@if ! git diff --quiet -- 'agentcore/enforcer/*_bpfel.go' 'agentcore/enforcer/*_bpfel.o'; then \
		echo "ebpf drift detected — regenerate via 'make ebpf-generate' (clang from debian bookworm) and commit:"; \
		git diff --stat -- 'agentcore/enforcer/*_bpfel.go' 'agentcore/enforcer/*_bpfel.o'; \
		exit 1; \
	fi

.PHONY: ci-checks
ci-checks: lint test check-ebpf-drift ## run the same checks CI runs (lint + tests + eBPF drift)

.PHONY: integration
integration: ## agentcore integration tests (Linux + root + containerd)
	$(GO) test -tags='integration linux' -count=1 -v ./agentcore/enforcer/...

.PHONY: e2e
e2e: ## CE end-to-end smoke (Linux + root + Docker; see tests/e2e/README.md)
	sudo -E bash tests/e2e/run.sh

.PHONY: integration-suite
integration-suite: ## full driver: env audit + e2e + agentcore integration with logs (Linux + root)
	sudo -E bash tests/integration/run.sh

.PHONY: build
build: $(BIN_DIR)/agent-ce $(BIN_DIR)/leitwacht-initc ## build all binaries

$(BIN_DIR)/agent-ce: ## CE daemon
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 \
	  $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $@ ./ce/cmd/agent-ce

$(BIN_DIR)/leitwacht-initc:
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 \
	  $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $@ ./agentcore/cmd/leitwacht-initc

.PHONY: docker-agent-ce
docker-agent-ce: ## build the agent-ce container image locally
	docker build -f Dockerfile.agent-ce \
	  --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) \
	  -t leitwacht/agent-ce:$(VERSION) .

.PHONY: helm-lint
helm-lint: ## lint + template the CE Helm chart
	helm lint ./ce/helm/agent-ce
	helm template e2e ./ce/helm/agent-ce --set dnsUpstream=10.0.0.10:53 >/dev/null

.PHONY: clean
clean:
	rm -rf $(BIN_DIR)
