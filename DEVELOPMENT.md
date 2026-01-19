# Development Guide

This guide contains information for developers working on vulnx.

## Prerequisites

- Go 1.22 or later
- Git

## Building

```bash
# Build main vulnx binary
make build

# Build vulnx binary
make build-vulnx

# Build and run tests
make test

# Build everything
make all
```

## Code Quality & Pre-Commit Setup

To avoid CI failures and maintain code quality, choose one of these automation options:

### Option 1: Zero Dependencies (Recommended for simple setups)
```bash
# Uses our manual script directly as Git hook
make git-hooks
```

### Option 2: Pre-commit Package (Recommended for advanced features)
```bash
# Install pre-commit framework
pip install pre-commit

# Set up hooks with advanced features
make pre-commit
```

### Manual Quality Checks

```bash
# Run all pre-commit checks
make pre-push

# Or run individual checks
make fmt      # Format code
make test     # Run tests
make lint     # Run linter
make vet      # Static analysis
make tidy     # Tidy dependencies
```

### Alternative Script

```bash
# Make executable and run
chmod +x scripts/pre-commit.sh
./scripts/pre-commit.sh
```

## Troubleshooting

### Dependency Issues

If you encounter dependency issues (like "undefined: retryablehttp"), run:
```bash
make fix-deps  # Fixes common Go module issues
```

### Build Issues

```bash
# Clean and rebuild
go clean
go mod tidy
make build
```

### Test Issues

```bash
# Run tests with verbose output
make test GOFLAGS=-v

# Run specific test
go test -v ./pkg/specific/package
```

## Development Workflow

1. **Fork and clone** the repository
2. **Create a feature branch** from `main`
3. **Set up pre-commit hooks** (see above)
4. **Make your changes** with tests
5. **Run quality checks** (`make pre-push`)
6. **Commit and push** your changes
7. **Create a pull request**

## Code Style

- Follow standard Go conventions
- Use `gofmt` and `goimports` for formatting
- Add tests for new functionality
- Keep functions focused and small
- Use meaningful variable names
- Add comments for exported functions

## Testing

### Unit Tests

```bash
# Run all tests
make test

# Run tests with coverage
go test -cover ./...

# Run specific test file
go test -v ./pkg/tools/renderer/
```

### Integration Tests

```bash
# Run integration tests
make integration
```

## Project Structure

```
vulnx/
├── cmd/
│   ├── vulnx/          # Main CLI application
│   └── integration-test/ # Integration tests
├── pkg/
│   ├── runner/          # Core application logic
│   ├── service/         # API service layer
│   ├── types/           # Type definitions
│   ├── tools/           # CLI tools and MCP handlers
│   └── utils/           # Utility functions
├── static/              # Static assets
└── scripts/             # Build and development scripts
```

## Contributing

1. **Issues**: Check existing issues before creating new ones
2. **Pull Requests**:
   - Keep them focused and small
   - Include tests for new features
   - Update documentation as needed
   - Follow the existing code style
3. **Documentation**: Update relevant docs for user-facing changes

## Release Process

1. Update version in relevant files
2. Run full test suite
3. Create release notes
4. Tag release
5. Build and publish binaries

## Getting Help

- Check existing issues and discussions
- Review the main README for user documentation
- Join our community for development questions

These checks include Go formatting, import fixing, testing, linting, and building. Running them locally prevents GitHub CI failures and keeps the codebase clean.
