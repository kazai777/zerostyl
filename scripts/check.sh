#!/usr/bin/env bash
# Full validation - run before committing

set -e

echo "Running full validation checks..."
echo ""

# Build
echo "Building workspace..."
cargo build --workspace --all-features

# Tests
echo "Running tests..."
cargo test --workspace --all-features

# Linting
echo "Running clippy..."
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Formatting
echo "Checking code formatting..."
cargo fmt --all -- --check

echo ""
echo "All checks passed! Ready to commit."
