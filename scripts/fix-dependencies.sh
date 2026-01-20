#!/bin/bash

# Vulnx Dependency Fixer
# Helps resolve common Go module and dependency issues

set -e

echo "🔧 Fixing Vulnx dependencies..."

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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

echo "📦 Cleaning module cache..."
if go clean -modcache 2>/dev/null; then
    print_status "Module cache cleaned"
else
    print_warning "Failed to clean module cache (possibly insufficient permissions)"
fi

echo "🧹 Tidying dependencies..."
if go mod tidy; then
    print_status "Dependencies tidied"
else
    print_error "Failed to tidy dependencies"
    exit 1
fi

echo "⬇️ Downloading dependencies..."
if go mod download; then
    print_status "Dependencies downloaded"
else
    print_error "Failed to download dependencies"
    exit 1
fi

echo "🔍 Verifying dependencies..."
if go mod verify; then
    print_status "Dependencies verified"
else
    print_warning "Dependency verification had issues"
fi

echo "🔨 Testing build..."
if go build ./...; then
    print_status "Build successful"
else
    print_error "Build failed"
    exit 1
fi

echo "🧪 Running quick test..."
if go test -short ./...; then
    print_status "Quick tests passed"
else
    print_warning "Some tests failed (this may be normal)"
fi

echo ""
echo -e "${GREEN}🎉 Dependency fixing complete!${NC}"
echo ""
echo "Try running your pre-commit hook again:"
echo "  git commit -m \"test: verify dependencies fixed\""
echo ""
