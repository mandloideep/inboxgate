GO ?= go
GOVULNCHECK_VERSION := v1.7.0
TOOLS_BIN := $(CURDIR)/.tools/govulncheck-$(GOVULNCHECK_VERSION)/bin
GOVULNCHECK := $(TOOLS_BIN)/govulncheck
ACTIONLINT_VERSION := v1.7.12
ACTIONLINT_BIN := $(CURDIR)/.tools/actionlint-$(ACTIONLINT_VERSION)/bin
ACTIONLINT := $(ACTIONLINT_BIN)/actionlint
BUILD_DIR := $(CURDIR)/.build

export GOCACHE := $(CURDIR)/.cache/go-build

.PHONY: actionlint build check fmt-check help release-contract storage-cross-build test test-fuzz test-race tidy-check turso-fork-test turso-fork-test-race turso-fork-tidy-check turso-fork-verify turso-fork-vet verify vet vuln

help:
	@printf '%s\n' 'Targets:'
	@printf '%s\n' '  check       Run every required local and CI check'
	@printf '%s\n' '  build       Build the InboxGate binary'
	@printf '%s\n' '  test        Run unit and integration tests'
	@printf '%s\n' '  test-fuzz   Run every bounded MCP fuzz invariant'
	@printf '%s\n' '  test-race   Run tests with the race detector'
	@printf '%s\n' '  vuln        Scan reachable Go code for known vulnerabilities'
	@printf '%s\n' '  actionlint  Validate every GitHub Actions workflow'
	@printf '%s\n' '  turso-fork-test  Run the credential-free nested Turso fork tests'
	@printf '%s\n' '  turso-fork-test-race  Run the credential-free nested Turso fork tests with the race detector'
	@printf '%s\n' '  storage-cross-build  Compile the Turso adapter for every release target with CGO disabled'
	@printf '%s\n' '  release-contract  Exercise pinned release construction and SBOM generation on Linux amd64'

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

test-fuzz:
	@set -eu; \
	for target in FuzzParseBearerToken FuzzParseAuthorization FuzzRoutingHeaders FuzzStructuralEnvelope FuzzCapabilityRendering; do \
		printf '%s\n' "Running bounded $$target"; \
		$(GO) test -run='^$$' -fuzz="^$$target$$" -fuzztime=2s -parallel=1 ./internal/mcp; \
	done; \
	printf '%s\n' 'Running bounded FuzzSnapshotCompositionIsBoundedAndDeterministic'; \
	$(GO) test -run='^$$' -fuzz='^FuzzSnapshotCompositionIsBoundedAndDeterministic$$' -fuzztime=2s -parallel=1 ./internal/accountstatus; \
	printf '%s\n' 'Running bounded FuzzOperatorSummaryRenderingIsBoundedAndClosedWorld'; \
	$(GO) test -run='^$$' -fuzz='^FuzzOperatorSummaryRenderingIsBoundedAndClosedWorld$$' -fuzztime=2s -parallel=1 ./internal/mcp; \
	for target in FuzzListRequestAndCursorDecodingRemainClosedAndBounded FuzzPreviewTruncationNeverSplitsUTF8OrExceedsLimit; do \
		printf '%s\n' "Running bounded $$target"; \
		$(GO) test -run='^$$' -fuzz="^$$target$$" -fuzztime=2s -parallel=1 ./internal/reviewinspect; \
	done; \
	printf '%s\n' 'Running bounded FuzzReviewInspectionTursoDecoder'; \
	$(GO) test -run='^$$' -fuzz='^FuzzReviewInspectionTursoDecoder$$' -fuzztime=2s -parallel=1 ./internal/storage/turso; \
	printf '%s\n' 'Running bounded FuzzReviewToolEnvelopesRemainBoundedAndClosed'; \
	$(GO) test -run='^$$' -fuzz='^FuzzReviewToolEnvelopesRemainBoundedAndClosed$$' -fuzztime=2s -parallel=1 ./internal/mcp

test-race:
	$(GO) test -race ./...

$(GOVULNCHECK):
	mkdir -p $(TOOLS_BIN)
	GOBIN=$(TOOLS_BIN) $(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

vuln: $(GOVULNCHECK)
	$(GOVULNCHECK) ./...

$(ACTIONLINT):
	mkdir -p $(ACTIONLINT_BIN)
	GOBIN=$(ACTIONLINT_BIN) $(GO) install github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)

actionlint: $(ACTIONLINT)
	$(ACTIONLINT) $$(find .github/workflows -type f \( -name '*.yml' -o -name '*.yaml' \) -print)

turso-fork-tidy-check:
	@unset TURSO_DATABASE_URL TURSO_AUTH_TOKEN; $(GO) -C third_party/tursogo-serverless mod tidy -diff

turso-fork-verify:
	@unset TURSO_DATABASE_URL TURSO_AUTH_TOKEN; $(GO) -C third_party/tursogo-serverless mod verify

turso-fork-vet:
	@unset TURSO_DATABASE_URL TURSO_AUTH_TOKEN; $(GO) -C third_party/tursogo-serverless vet ./...

turso-fork-test:
	@unset TURSO_DATABASE_URL TURSO_AUTH_TOKEN; $(GO) -C third_party/tursogo-serverless test ./...

turso-fork-test-race:
	@unset TURSO_DATABASE_URL TURSO_AUTH_TOKEN; $(GO) -C third_party/tursogo-serverless test -race ./...

storage-cross-build:
	@set -eu; \
	target_count=0; \
	for target in $$($(GO) run ./cmd/release list-targets); do \
		target_os=$${target%/*}; \
		target_arch=$${target#*/}; \
		printf '%s\n' "Compiling Turso adapter for $$target"; \
		CGO_ENABLED=0 GOOS="$$target_os" GOARCH="$$target_arch" $(GO) build -mod=readonly -buildvcs=false ./internal/storage/turso; \
		target_count=$$((target_count + 1)); \
	done; \
	if [ "$$target_count" -ne 6 ]; then \
		printf '%s\n' "Turso adapter target count = $$target_count, want 6" >&2; \
		exit 1; \
	fi

release-contract:
	@set -eu; \
	if [ "$$($(GO) env GOOS)/$$($(GO) env GOARCH)" != "linux/amd64" ]; then \
		printf '%s\n' 'Real Syft release contract runs on canonical Linux amd64 CI; synthetic acquisition tests run on this host.'; \
		exit 0; \
	fi; \
	contract_dir="$$(mktemp -d /tmp/inboxgate-release-contract.XXXXXX)"; \
	trap 'rm -rf "$$contract_dir"' EXIT INT TERM; \
	contract_version='v0.1.0'; \
	contract_commit='0000000000000000000000000000000000000000'; \
	$(GO) run ./cmd/release acquire-syft --output "$$contract_dir/tools/syft"; \
	GOCACHE="$$contract_dir/cache-first" $(GO) run ./cmd/release build-binaries --root . --output "$$contract_dir/first" --version "$$contract_version" --commit "$$contract_commit"; \
	GOCACHE="$$contract_dir/cache-second" $(GO) run ./cmd/release build-binaries --root . --output "$$contract_dir/second" --version "$$contract_version" --commit "$$contract_commit"; \
	$(GO) run ./cmd/release validate-native --output "$$contract_dir/first" --version "$$contract_version" --commit "$$contract_commit"; \
	$(GO) run ./cmd/release package --root . --output "$$contract_dir/first" --version "$$contract_version" --commit "$$contract_commit"; \
	$(GO) run ./cmd/release package --root . --output "$$contract_dir/second" --version "$$contract_version" --commit "$$contract_commit"; \
	$(GO) run ./cmd/release compare --first "$$contract_dir/first" --second "$$contract_dir/second"; \
	SYFT_CHECK_FOR_APP_UPDATE=false SYFT_CACHE_DIR="$$contract_dir/syft-cache" "$$contract_dir/tools/syft" scan "dir:$$contract_dir/first/binaries" --source-name InboxGate --source-version "$$contract_version" --config .github/syft.yaml --output "spdx-json=$$contract_dir/first/assets/inboxgate_0.1.0_sbom.spdx.json"; \
	$(GO) run ./cmd/release validate-sbom --path "$$contract_dir/first/assets/inboxgate_0.1.0_sbom.spdx.json" --version "$$contract_version" --workspace "$$contract_dir"; \
	$(GO) run ./cmd/release checksums --assets "$$contract_dir/first/assets"; \
	$(GO) run ./cmd/release validate-assets --assets "$$contract_dir/first/assets" --version "$$contract_version" --workspace "$$contract_dir"

build:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GO) build -trimpath -o $(BUILD_DIR)/inboxgate ./cmd/inboxgate

check: fmt-check tidy-check verify vet test test-fuzz test-race vuln actionlint turso-fork-tidy-check turso-fork-verify turso-fork-vet turso-fork-test turso-fork-test-race storage-cross-build release-contract build
