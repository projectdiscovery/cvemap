# Pre-Commit and Pre-Push Scripts

This directory contains scripts and configuration for running quality checks locally before pushing to GitHub, helping to avoid CI failures.

## Quick Setup

### Option 1: Zero Dependencies Git Hook (Simple & Fast)

1. Install our manual script as a Git hook:
   ```bash
   make git-hooks
   ```

2. Now our script runs automatically on every `git commit` (no external dependencies!)

### Option 2: Pre-commit Framework (Advanced Features)

1. Install pre-commit:
   ```bash
   pip install pre-commit
   ```

2. Install the hooks:
   ```bash
   make pre-commit
   ```

3. Now pre-commit will run automatically on every `git commit` with advanced features

### Option 3: Manual Pre-Commit Script

1. Make the script executable:
   ```bash
   chmod +x scripts/pre-commit.sh
   ```

2. Run before pushing:
   ```bash
   ./scripts/pre-commit.sh
   ```

## Which Option Should You Choose?

| Feature | Git Hook (Option 1) | Pre-commit Framework (Option 2) | Manual Script (Option 3) |
|---------|-------------------|-------------------------|----------------------|
| **Setup Complexity** | ✅ Simple (`make git-hooks`) | ⚠️ Requires Python/pip | ✅ Simple |
| **Dependencies** | ✅ Zero external deps | ❌ Requires pre-commit package | ✅ Zero deps |
| **Performance** | ⚠️ Always runs all checks | ✅ Smart file filtering | ⚠️ Manual only |
| **Automation** | ✅ Automatic on commit | ✅ Automatic on commit | ❌ Manual |
| **Team Consistency** | ✅ One command setup | ✅ One command setup | ❌ Manual setup |
| **Advanced Features** | ❌ Basic functionality | ✅ YAML config, updates | ❌ Basic |

**Recommendations:**
- **Choose Option 1** (Git Hook) if you want simplicity and no external dependencies
- **Choose Option 2** (Pre-commit Framework) if you want advanced features and have Python available
- **Choose Option 3** (Manual) for occasional use or debugging

## Troubleshooting Dependency Issues

If you see linting errors like "undefined: retryablehttp" or "could not load export data", try:

```bash
# Quick fix for dependency issues
make fix-deps

# Or manually:
chmod +x scripts/fix-dependencies.sh
./scripts/fix-dependencies.sh
```

**Common issues:**
- Module cache out of sync → `go clean -modcache && go mod download`
- Missing dependencies → `go mod tidy`
- Version compatibility → Update Go or golangci-lint
- Build cache stale → `go clean -cache`

## What Gets Checked

The pre-commit/pre-push process runs:

- **gofmt** - Format Go code
- **goimports** - Fix imports
- **go mod tidy** - Clean up dependencies
- **go vet** - Static analysis
- **golangci-lint** - Comprehensive linting (if installed)
- **go build** - Ensure code compiles
- **go test** - Run all tests
- **Basic checks** - Trailing whitespace, large files, etc.

## Installing golangci-lint (Optional but Recommended)

```bash
# macOS
brew install golangci-lint

# Linux
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin

# Windows
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

## Installing goimports (Optional but Recommended)

```bash
go install golang.org/x/tools/cmd/goimports@latest
```

## Usage Tips

- Run `./scripts/pre-commit.sh` before any push to GitHub
- The script will exit with error code 1 if any check fails
- All warnings are non-blocking, but errors will prevent the script from completing
- The pre-commit hooks will automatically format your code and fix issues when possible

## Skipping Checks (Emergency Use Only)

If you need to skip pre-commit hooks temporarily:

```bash
git commit --no-verify -m "emergency commit"
```

**Note:** Only use `--no-verify` in genuine emergencies, as it defeats the purpose of these quality checks.
