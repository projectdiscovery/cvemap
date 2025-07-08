# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOMOD=$(GOCMD) mod
GOTEST=$(GOCMD) test
GOFLAGS := -v
# This should be disabled if the binary uses pprof
LDFLAGS := -s -w

ifneq ($(shell go env GOOS),darwin)
LDFLAGS := -extldflags "-static"
endif
    
all: build
build:
	$(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS)' -o "cvemap" cmd/cvemap/main.go
build-vulnx:
	$(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS) -X github.com/projectdiscovery/cvemap/cmd/vulnx/clis.Version=v1.0.0' -o "vulnx" cmd/vulnx/main.go
integration:
	cd cmd/integration-test; bash run.sh
tidy:
	$(GOMOD) tidy

# Quality checks
fmt:
	@echo "🛠️  Formatting code..."
	@gofmt -w .
	@if command -v goimports >/dev/null 2>&1; then goimports -w .; fi

vet:
	@echo "🔍 Running go vet..."
	@$(GOCMD) vet ./...

test:
	@echo "🧪 Running tests..."
	@$(GOTEST) -v ./...

lint:
	@echo "🧐 Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run --timeout=5m; \
	else \
		echo "⚠️  golangci-lint not found, skipping linting"; \
	fi

# Pre-commit checks - run all quality checks
pre-push: fmt tidy vet lint test build
	@echo "✅ All pre-commit checks passed!"

# Set up pre-commit hooks (using pre-commit package)
pre-commit:
	@echo "🔧 Setting up pre-commit hooks..."
	@if command -v pre-commit >/dev/null 2>&1; then \
		pre-commit install; \
		echo "✅ Pre-commit hooks installed"; \
	else \
		echo "❌ pre-commit not found. Install with: pip install pre-commit"; \
	fi

# Alternative: Install manual script as Git hook (no external dependencies)
git-hooks:
	@echo "🔧 Installing manual script as Git hook..."
	@chmod +x scripts/git-hook-install.sh
	@./scripts/git-hook-install.sh

# Fix common dependency and module issues
fix-deps:
	@echo "🔧 Fixing dependencies..."
	@chmod +x scripts/fix-dependencies.sh
	@./scripts/fix-dependencies.sh

.PHONY: all build build-vulnx integration tidy fmt vet test lint pre-push pre-commit git-hooks fix-deps
