#!/usr/bin/env bash
# Run all tests with coverage

set -e

echo "Running ZeroStyl test suite..."
echo ""

# Run workspace tests
echo "Running unit and integration tests..."
cargo test --workspace --all-features

# Run doc tests
echo "Running documentation tests..."
cargo test --doc --workspace

# Generate coverage report (only if cargo-tarpaulin is installed)
if command -v cargo-tarpaulin &>/dev/null; then
	echo "Generating coverage report..."
	cargo tarpaulin --workspace --all-features --out Html --output-dir target/coverage

	echo ""
	echo "All tests passed!"
	echo "Coverage report: target/coverage/index.html"
else
	echo ""
	echo "All tests passed!"
	echo "Install cargo-tarpaulin to generate coverage reports: cargo install cargo-tarpaulin"
fi
