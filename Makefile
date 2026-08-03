.PHONY: all ci clean build test fmt clippy doc audit security coverage bench check install-tools help \
        fmt-check build-examples test-doc doc-check doc-links \
        deny outdated security-geiger security-supply-chain semver-check \
        markdownlint package-check \
        msrv msrv-install security-enhanced ci-local validate analyze examples release-prep dev

RUST_MSRV := 1.97.1

# Default target
all: ci-local

# CI simulation - matches GitHub Actions CI workflow
ci: ci-local

# Install required tools
install-tools:
	@echo "📦 Installing required tools..."
	@command -v cargo-audit >/dev/null 2>&1 || cargo install --locked cargo-audit --version 0.22.2
	@command -v cargo-outdated >/dev/null 2>&1 || cargo install --locked cargo-outdated
	@command -v cargo-deny >/dev/null 2>&1 || cargo install --locked cargo-deny --version 0.20.2
	@command -v cargo-llvm-cov >/dev/null 2>&1 || cargo install --locked cargo-llvm-cov --version 0.8.7
	@command -v cargo-deadlinks >/dev/null 2>&1 || cargo install --locked cargo-deadlinks
	@command -v cargo-geiger >/dev/null 2>&1 || cargo install cargo-geiger --locked
	@command -v cargo-supply-chain >/dev/null 2>&1 || cargo install cargo-supply-chain --locked
	@command -v cargo-semver-checks >/dev/null 2>&1 || cargo install cargo-semver-checks --locked
	@echo "✅ Tools installed"

# Format code
fmt:
	@echo "🎨 Formatting code..."
	@cargo fmt
	@echo "✅ Code formatted"

# Check formatting without modifying
fmt-check:
	@echo "🔍 Checking code format..."
	@cargo fmt -- --check
	@echo "✅ Format check passed"

# Lint Markdown documentation
markdownlint:
	@echo "📝 Linting Markdown..."
	@npx --yes markdownlint-cli2@0.23.2
	@python3 scripts/check_docs.py
	@echo "✅ Markdown lint passed"

# Verify the contents and relative links of the crates.io archive
package-check:
	@echo "📦 Checking Cargo package contents..."
	@python3 scripts/check_package.py
	@echo "✅ Cargo package contents passed"

# Run clippy linter
clippy:
	@echo "📎 Running clippy..."
	@cargo clippy --locked --all-targets -- -D warnings
	@echo "✅ Clippy passed"

# Build the project
build:
	@echo "🔨 Building project..."
	@cargo build --locked --release
	@echo "✅ Build successful"

# Run tests
test:
	@echo "🧪 Running tests..."
	@cargo test --locked
	@echo "✅ Tests passed"

# Build examples
build-examples:
	@echo "🔨 Building examples..."
	@cargo build --locked --examples
	@echo "✅ Examples built successfully"

# Test documentation examples
test-doc:
	@echo "📚 Testing documentation examples..."
	@cargo test --locked --doc
	@echo "✅ Doc tests passed"

# Generate documentation
doc:
	@echo "📖 Generating documentation..."
	@cargo doc --locked --no-deps
	@echo "✅ Documentation generated"

# Check documentation with warnings as errors
doc-check:
	@echo "📖 Checking documentation..."
	@RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --document-private-items
	@echo "✅ Documentation check passed"

# Run security audit
audit:
	@echo "🔒 Running security audit..."
	@cargo audit
	@echo "✅ Security audit passed"

# Check with cargo-deny
deny:
	@echo "🚫 Running cargo-deny checks..."
	@cargo deny check
	@echo "✅ Cargo deny checks passed"

# Check outdated dependencies
outdated:
	@echo "📊 Checking for outdated dependencies..."
	@cargo outdated
	@echo "✅ Outdated check complete"

# Security analysis with cargo-geiger (unsafe code detection)
security-geiger:
	@echo "🔍 Analyzing unsafe code usage..."
	@cargo geiger --output-format GitHubMarkdown > unsafe-report.md
	@echo "✅ Unsafe code analysis complete (see unsafe-report.md)"

# Supply chain security analysis
security-supply-chain:
	@echo "🔗 Analyzing supply chain security..."
	@cargo supply-chain crates > supply-chain-report.txt 2>&1
	@echo "✅ Supply chain analysis complete (see supply-chain-report.txt)"

# Check documentation links
doc-links:
	@echo "🔗 Checking documentation links..."
	@cargo doc --locked --no-deps --document-private-items
	@cargo deadlinks --dir target/doc
	@echo "✅ Documentation link check complete"

# Semantic versioning checks
semver-check:
	@echo "📋 Checking semantic versioning..."
	@cargo semver-checks check-release
	@echo "✅ Semantic versioning check complete"

# Combined security checks
security: audit deny outdated security-geiger security-supply-chain
	@echo "✅ All security checks complete"

# Generate test coverage
coverage:
	@echo "📊 Generating test coverage..."
	@cargo llvm-cov --locked --html
	@echo "✅ Coverage report generated at target/llvm-cov/html/index.html"

# Run benchmarks
bench:
	@echo "⚡ Running benchmarks..."
	@cargo bench --locked
	@echo "✅ Benchmarks complete"

# Check MSRV (Minimum Supported Rust Version)
msrv:
	@echo "🦀 Checking MSRV ($(RUST_MSRV))..."
	@if rustup toolchain list | grep -q "$(RUST_MSRV)"; then \
		cargo +$(RUST_MSRV) check --locked; \
	else \
		echo "⚠️  MSRV toolchain $(RUST_MSRV) not installed. Installing..."; \
		rustup toolchain install $(RUST_MSRV) --component rustfmt,clippy; \
		cargo +$(RUST_MSRV) check --locked; \
	fi
	@echo "✅ MSRV check complete"

# Install MSRV toolchain if not present
msrv-install:
	@echo "🦀 Installing MSRV toolchain ($(RUST_MSRV))..."
	@rustup toolchain install $(RUST_MSRV) --component rustfmt,clippy
	@echo "✅ MSRV toolchain installed"

# Quick check (faster than full build)
check:
	@echo "⚡ Quick check..."
	@cargo check --locked
	@echo "✅ Check passed"

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	@cargo clean
	@rm -f unsafe-report.md supply-chain-report.txt
	@echo "✅ Clean complete"

# Run examples
examples:
	@echo "🎯 Running examples..."
	@cargo run --locked --example basic_detection
	@cargo run --locked --example validate_responses
	@echo "✅ Examples ran successfully"

# Release preparation
release-prep: fmt-check clippy markdownlint package-check test build-examples test-doc doc-check audit deny
	@cargo package --locked
	@cargo publish --dry-run --locked
	@echo "✅ Ready for release!"

# Development workflow - format, build, and test
dev: fmt build test
	@echo "✅ Development checks passed!"

# Enhanced security analysis (matches CI/CD security workflow)
security-enhanced: security security-supply-chain security-geiger semver-check
	@echo "✅ Enhanced security analysis complete!"

# CI-equivalent validation (matches GitHub Actions CI workflow)
ci-local: fmt-check clippy markdownlint package-check build test build-examples test-doc doc-check
	@echo "✅ Local CI validation complete!"

# Full validation (everything - matches all CI/CD workflows)
validate: all coverage security-enhanced
	@echo "🎉 Full validation complete!"

# Complete analysis (all tools, all checks)
analyze: validate security-enhanced doc-links semver-check
	@echo "🎯 Complete analysis finished!"

# Help target
help:
	@echo "FluxPrompt SDK - Makefile targets"
	@echo ""
	@echo "🎯 Main targets:"
	@echo "  make all          - Run all standard checks (format, lint, build, test, doc, security)"
	@echo "  make dev          - Quick development check (format, build, test)"
	@echo "  make ci-local     - Simulate full CI checks locally"
	@echo "  make validate     - Full validation including coverage and security checks"
	@echo "  make analyze      - Complete analysis (all tools, all checks)"
	@echo ""
	@echo "🔨 Individual targets:"
	@echo "  make fmt          - Format code"
	@echo "  make fmt-check    - Check formatting without modifying"
	@echo "  make clippy       - Run clippy linter"
	@echo "  make markdownlint - Lint Markdown files"
	@echo "  make package-check - Verify crates.io package contents"
	@echo "  make build        - Build the project"
	@echo "  make test         - Run tests"
	@echo "  make test-doc     - Test documentation examples"
	@echo "  make doc          - Generate documentation"
	@echo "  make doc-check    - Check documentation with strict warnings"
	@echo "  make doc-links    - Check documentation links"
	@echo ""
	@echo "🔒 Security targets:"
	@echo "  make security     - Run all security checks"
	@echo "  make audit        - Run security audit"
	@echo "  make deny         - Run cargo-deny checks"
	@echo "  make security-geiger       - Analyze unsafe code usage"
	@echo "  make security-supply-chain - Supply chain analysis"
	@echo "  make semver-check - Check semantic versioning"
	@echo ""
	@echo "🧪 Testing targets:"
	@echo "  make coverage              - Generate test coverage report"
	@echo ""
	@echo "🛠️  Utility targets:"
	@echo "  make msrv         - Check minimum supported Rust version"
	@echo "  make msrv-install - Install MSRV toolchain"
	@echo "  make outdated     - Check for outdated dependencies"
	@echo "  make bench        - Run benchmarks"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make examples     - Run example programs"
	@echo ""
	@echo "📦 Tool installation:"
	@echo "  make install-tools - Install required cargo tools"
