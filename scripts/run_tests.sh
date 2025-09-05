#!/bin/bash

# Comprehensive test runner for FluxPrompt SDK
# This script runs all types of tests and generates coverage reports

set -e  # Exit on any error

echo "🧪 FluxPrompt SDK Test Suite Runner"
echo "=================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ]; then
    print_error "Cargo.toml not found. Please run this script from the project root."
    exit 1
fi

# Create reports directory
mkdir -p reports

# 1. Run Unit Tests
print_status "Running unit tests..."
if cargo test --lib --verbose > reports/unit_tests.log 2>&1; then
    print_success "Unit tests passed!"
else
    print_error "Unit tests failed. Check reports/unit_tests.log for details."
    cat reports/unit_tests.log | tail -20
fi

# 2. Run Integration Tests
print_status "Running integration tests..."
if cargo test --test integration_tests --verbose > reports/integration_tests.log 2>&1; then
    print_success "Integration tests passed!"
else
    print_warning "Integration tests had issues. Check reports/integration_tests.log for details."
fi

# 3. Run Property-Based Tests
print_status "Running property-based tests..."
if timeout 300 cargo test --test property_tests --verbose > reports/property_tests.log 2>&1; then
    print_success "Property-based tests passed!"
else
    print_warning "Property-based tests had issues or timed out. Check reports/property_tests.log for details."
fi

# 4. Run Attack Vector Tests
print_status "Running attack vector tests..."
if cargo test --test attack_vectors --verbose > reports/attack_vector_tests.log 2>&1; then
    print_success "Attack vector tests passed!"
else
    print_warning "Attack vector tests had issues. Check reports/attack_vector_tests.log for details."
fi

# 5. Run Performance Tests (with timeout)
print_status "Running performance tests (this may take a while)..."
if timeout 600 cargo test --test performance_tests --verbose --release > reports/performance_tests.log 2>&1; then
    print_success "Performance tests completed!"
else
    print_warning "Performance tests had issues or timed out. Check reports/performance_tests.log for details."
fi

# 6. Run Test Utilities Tests
print_status "Running test utilities tests..."
if cargo test --test test_utilities --verbose > reports/test_utilities.log 2>&1; then
    print_success "Test utilities tests passed!"
else
    print_warning "Test utilities tests had issues. Check reports/test_utilities.log for details."
fi

# 7. Generate Code Coverage (if tarpaulin is available)
print_status "Generating code coverage report..."
if command -v cargo-tarpaulin >/dev/null 2>&1; then
    if cargo tarpaulin --out Html --output-dir reports/coverage > reports/coverage.log 2>&1; then
        print_success "Code coverage report generated in reports/coverage/"
        
        # Extract coverage percentage
        if grep -q "coverage:" reports/coverage.log; then
            COVERAGE=$(grep "coverage:" reports/coverage.log | tail -1 | grep -oE '[0-9]+\.[0-9]+%')
            print_status "Code coverage: $COVERAGE"
        fi
    else
        print_warning "Code coverage generation failed. Check reports/coverage.log for details."
    fi
else
    print_warning "cargo-tarpaulin not found. Install with: cargo install cargo-tarpaulin"
    print_warning "Skipping code coverage report generation."
fi

# 8. Run Clippy for code quality
print_status "Running Clippy for code quality checks..."
if cargo clippy --all-targets --all-features -- -D warnings > reports/clippy.log 2>&1; then
    print_success "Clippy checks passed!"
else
    print_warning "Clippy found issues. Check reports/clippy.log for details."
fi

# 9. Check documentation
print_status "Checking documentation..."
if cargo doc --no-deps --document-private-items > reports/doc_check.log 2>&1; then
    print_success "Documentation check passed!"
else
    print_warning "Documentation check had issues. Check reports/doc_check.log for details."
fi

# 10. Run benchmarks (if available)
print_status "Running benchmarks..."
if cargo bench --bench detection_benchmarks > reports/benchmarks.log 2>&1; then
    print_success "Benchmarks completed!"
else
    print_warning "Benchmarks had issues. Check reports/benchmarks.log for details."
fi

# 11. Security audit (if cargo-audit is available)
print_status "Running security audit..."
if command -v cargo-audit >/dev/null 2>&1; then
    if cargo audit > reports/security_audit.log 2>&1; then
        print_success "Security audit passed!"
    else
        print_warning "Security audit found issues. Check reports/security_audit.log for details."
    fi
else
    print_warning "cargo-audit not found. Install with: cargo install cargo-audit"
    print_warning "Skipping security audit."
fi

# Summary
echo ""
echo "🏁 Test Suite Summary"
echo "===================="
echo "Reports generated in the 'reports/' directory:"
echo "  - unit_tests.log - Unit test results"
echo "  - integration_tests.log - Integration test results"
echo "  - property_tests.log - Property-based test results"
echo "  - attack_vector_tests.log - Attack vector test results"
echo "  - performance_tests.log - Performance test results"
echo "  - test_utilities.log - Test utilities results"
echo "  - coverage/ - Code coverage report (HTML)"
echo "  - clippy.log - Code quality checks"
echo "  - doc_check.log - Documentation checks"
echo "  - benchmarks.log - Performance benchmarks"
echo "  - security_audit.log - Security audit results"
echo ""

# Check for critical failures
CRITICAL_FAILURES=0

if ! grep -q "test result: ok" reports/unit_tests.log 2>/dev/null; then
    print_error "CRITICAL: Unit tests failed!"
    ((CRITICAL_FAILURES++))
fi

if [ $CRITICAL_FAILURES -eq 0 ]; then
    print_success "All critical tests passed! 🎉"
    echo "The FluxPrompt SDK is ready for use."
    exit 0
else
    print_error "$CRITICAL_FAILURES critical test failures found!"
    echo "Please fix critical issues before using the SDK."
    exit 1
fi