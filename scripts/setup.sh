#!/usr/bin/env bash
# Setup script - Install dependencies and tools

set -e # Exit on error

echo "Setting up ZeroStyl development environment..."

# Check if Rust is installed
if ! command -v cargo &>/dev/null; then
	echo "Rust is not installed. Please install from https://rustup.rs/"
	exit 1
fi

echo "Rust is installed ($(rustc --version))"

# Install required tools
echo "Installing development tools..."
echo "   - cargo-tarpaulin (coverage tool)"
echo "   - cargo-watch (auto-reload during dev)"

if ! command -v cargo-tarpaulin &>/dev/null; then
	cargo install cargo-tarpaulin
else
	echo "   ✓ cargo-tarpaulin already installed"
fi

if ! command -v cargo-watch &>/dev/null; then
	cargo install cargo-watch
else
	echo "   ✓ cargo-watch already installed"
fi

echo "Building workspace..."
cargo build --workspace

echo "Running tests..."
cargo test --workspace

echo ""
echo "Setup complete! You're ready to contribute to ZeroStyl."
echo ""
echo "Next steps:"
echo "  - Run './scripts/test.sh' to run all tests"
echo "  - Run './scripts/check.sh' to validate code quality"
echo "  - See docs/CONTRIBUTING.md for development guidelines"
