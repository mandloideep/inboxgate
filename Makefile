GO ?= go
GOVULNCHECK_VERSION := v1.7.0
TOOLS_BIN := $(CURDIR)/.tools/govulncheck-$(GOVULNCHECK_VERSION)/bin
GOVULNCHECK := $(TOOLS_BIN)/govulncheck
BUILD_DIR := $(CURDIR)/.build

export GOCACHE := $(CURDIR)/.cache/go-build
export GOBIN := $(TOOLS_BIN)

.PHONY: build check fmt-check help test test-race tidy-check verify vet vuln

help:
	@printf '%s\n' 'Targets:'
	@printf '%s\n' '  check       Run every required local and CI check'
	@printf '%s\n' '  build       Build the InboxGate binary'
	@printf '%s\n' '  test        Run unit and integration tests'
	@printf '%s\n' '  test-race   Run tests with the race detector'
	@printf '%s\n' '  vuln        Scan reachable Go code for known vulnerabilities'

fmt-check:
	@unformatted="$$(gofmt -l $$(find . -type f -name '*.go' -not -path './.git/*' -not -path './.cache/*' -not -path './.tools/*'))"; \
	format_status=$$?; \
	if [ "$$format_status" -ne 0 ]; then \
		printf '%s\n' "gofmt failed with status $$format_status" >&2; \
		exit "$$format_status"; \
	fi; \
	if [ -n "$$unformatted" ]; then \
		printf '%s\n' 'Go files require gofmt:' "$$unformatted"; \
		exit 1; \
	fi

tidy-check:
	$(GO) mod tidy -diff

verify:
	$(GO) mod verify

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

$(GOVULNCHECK):
	mkdir -p $(TOOLS_BIN)
	$(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

vuln: $(GOVULNCHECK)
	$(GOVULNCHECK) ./...

build:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GO) build -trimpath -o $(BUILD_DIR)/inboxgate ./cmd/inboxgate

check: fmt-check tidy-check verify vet test test-race vuln build
