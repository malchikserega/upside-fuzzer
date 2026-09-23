# UpsideFuzz — unified developer commands. Every target here runs exactly what
# .github/workflows/e2e.yml runs in CI, so `make test`/`make lint` locally
# gives you the same verdict CI will, before you push.
#
# Requires: Go 1.22+, Python 3.9+ (stdlib only), .NET SDK 8+, Docker (for
# `make e2e`/`make build-images` only -- everything else runs natively).

.PHONY: help build test lint e2e clean \
        build-void build-images \
        test-go test-python test-dotnet test-grammar-cli test-compat \
        lint-go lint-python fmt

help:
	@echo "Targets:"
	@echo "  build              Build the void binary (src/void/cmd/void)"
	@echo "  build-images       Build the void-fuzzer and upsidefuzz-cli Docker images"
	@echo "  test               Run every unit/compat test suite (Go, Python, .NET, wrapper smoke tests)"
	@echo "  test-go            go test ./... -race (includes the stateful-security fixture matrix)"
	@echo "  test-python        grammarc + fuzzprep + campaign/scenarios unit tests"
	@echo "  test-dotnet        analyzer.Tests + instrumentor.Tests"
	@echo "  test-grammar-cli   compile-grammar.sh CLI regression suite (scripts/test/)"
	@echo "  test-compat        Compatibility-wrapper smoke tests (tests/integration/compatibility/)"
	@echo "  lint               gofmt -l + go vet (Go); python3 -m py_compile sweep (Python)"
	@echo "  fmt                gofmt -w every Go file"
	@echo "  e2e                Full pipeline E2E regression gate (scripts/e2e/e2e-test.sh) -- needs Docker"
	@echo "  clean              Remove local build artifacts (src/void/cmd/void/void, __pycache__)"

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

build: build-void

build-void:
	go -C src/void build -o cmd/void/void ./cmd/void

build-images:
	docker build -t void-fuzzer -f deployments/docker/Dockerfile.void .
	docker build -t upsidefuzz-cli -f deployments/docker/Dockerfile.cli .

# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

test: test-go test-python test-dotnet test-grammar-cli test-compat

test-go:
	go -C src/void test ./... -race

test-python:
	cd tools/grammar && python3 -m unittest \
		grammarc.test_oas grammarc.test_boundary grammarc.test_body_serializer \
		grammarc.test_dependencies grammarc.test_emit_dict grammarc.test_multipart \
		grammarc.test_response_schemas grammarc.test_roslyn_merge -v
	cd tools/prep && python3 -m unittest fuzzprep.test_fuzz_prep_multi -v
	cd tools && python3 -m unittest campaign.test_campaign campaign.test_scenarios -v

test-dotnet:
	dotnet test tools/dotnet/instrumentor.Tests/instrumentor.Tests.csproj
	dotnet test tools/dotnet/analyzer.Tests/analyzer.Tests.csproj

test-grammar-cli:
	./scripts/test/test-compile-grammar-cli.sh

test-compat:
	cd tests/integration/compatibility && python3 -m unittest test_compat_wrappers -v

# ---------------------------------------------------------------------------
# Lint
# ---------------------------------------------------------------------------

lint: lint-go lint-python

lint-go:
	@test -z "$$(gofmt -l src/void/cmd src/void/internal)" || (echo "gofmt: files need formatting:"; gofmt -l src/void/cmd src/void/internal; exit 1)
	go -C src/void vet ./...

lint-python:
	python3 -m py_compile $$(find tools src/cli/upsidefuzz bin -name '*.py' -not -path '*__pycache__*')

fmt:
	gofmt -w src/void/cmd src/void/internal

# ---------------------------------------------------------------------------
# E2E (needs Docker)
# ---------------------------------------------------------------------------

e2e:
	./scripts/e2e/e2e-test.sh

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------

clean:
	rm -f src/void/cmd/void/void
	find . -name '__pycache__' -not -path './arxiv*' -not -path './.claude/*' -exec rm -rf {} + 2>/dev/null || true
