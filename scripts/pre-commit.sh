#!/bin/bash

# CVEMap Pre-Commit Check Script
# Run this script before pushing to GitHub to avoid CI failures

set -e

echo "🚀 Running pre-commit checks for CVEMap..."

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Check if we're in the right directory
if [ ! -f "go.mod" ]; then
    print_error "go.mod not found. Please run this script from the project root."
    exit 1
fi

# 1. Format Go code
echo "📝 Formatting Go code..."
if command -v gofmt >/dev/null 2>&1; then
    gofmt -w .
    print_status "Go formatting complete"
else
    print_warning "gofmt not found, skipping formatting"
fi

# 2. Fix imports
echo "📦 Fixing imports..."
if command -v goimports >/dev/null 2>&1; then
    if goimports -w . 2>/dev/null; then
        print_status "Import fixing complete"
    else
        print_warning "goimports failed (possibly old version), skipping import fixing"
    fi
else
    print_warning "goimports not found, skipping import fixing"
fi

# 3. Tidy dependencies
echo "🧹 Tidying dependencies..."
go mod tidy
print_status "Dependencies tidied"

# 4. Vet code
echo "🔍 Vetting code..."
if go vet ./...; then
    print_status "Go vet passed"
else
    print_error "Go vet failed"
    exit 1
fi

# 5. Run linter (if available)
echo "🧐 Running linter..."
if command -v golangci-lint >/dev/null 2>&1; then
    if golangci-lint run --timeout=5m 2>/dev/null; then
        print_status "Linting passed"
    else
        # Try to detect version compatibility issues
        linter_output=$(golangci-lint run --timeout=5m 2>&1 | head -5)
        if echo "$linter_output" | grep -q "unsupported version\|could not load export data"; then
            print_warning "Linting failed due to version compatibility issues, skipping"
        else
            print_error "Linting failed"
            echo "First few linting errors:"
            echo "$linter_output"
            exit 1
        fi
    fi
else
    print_warning "golangci-lint not found, skipping linting"
fi

# 6. Build project
echo "🔨 Building project..."
if go build ./...; then
    print_status "Build successful"
else
    print_error "Build failed"
    exit 1
fi

# 7. Run tests
echo "🧪 Running tests..."
if go test -v ./...; then
    print_status "All tests passed"
else
    print_error "Tests failed"
    exit 1
fi

# 8. Check for common issues
echo "🔎 Checking for common issues..."

# Check for TODO/FIXME comments in new code (optional warning)
if git diff --cached --name-only | grep -E '\.go$' | xargs grep -n "TODO\|FIXME" 2>/dev/null; then
    print_warning "Found TODO/FIXME comments in staged files"
fi

# Check for fmt.Print* statements that might be debug code
if git diff --cached --name-only | grep -E '\.go$' | xargs grep -n "fmt\.Print" 2>/dev/null; then
    print_warning "Found fmt.Print* statements in staged files - consider removing debug code"
fi

echo ""
echo -e "${GREEN}🎉 All pre-commit checks passed! Ready to push to GitHub.${NC}"
echo ""
echo "To set up automatic pre-commit hooks, run:"
echo "  pip install pre-commit"
echo "  pre-commit install"
echo ""
