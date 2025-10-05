#!/usr/bin/env bash
# Clean build artifacts and caches

set -e

echo "Cleaning ZeroStyl workspace..."

# Remove build artifacts
echo "Removing target/ directory..."
cargo clean

# Remove coverage artifacts
if [ -d "target/coverage" ]; then
	echo "Removing coverage reports..."
	rm -rf target/coverage
fi

# Remove lock file (optional - uncomment if needed)
# if [ -f "Cargo.lock" ]; then
#     echo "Removing Cargo.lock..."
#     rm Cargo.lock
# fi

echo ""
echo "Workspace cleaned!"
echo "Run './scripts/setup.sh' to rebuild"
