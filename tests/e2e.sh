#!/usr/bin/env bash
# End-to-end smoke test: build the CLI, then for each fast circuit run
# `generate` and `verify` in an isolated cache dir.
#
# Usage:
#   tests/e2e.sh           # runs example, state_mask, private_vote (≈ 15 s)
#   INCLUDE_SLOW=1 tests/e2e.sh  # also runs tx_privacy (k=14, ≈ +90 s)
#
# Exit code 0 = every circuit produced a proof that verified.

set -euo pipefail

cd "$(dirname "$0")/.."

CACHE=$(mktemp -d)
trap "rm -rf '$CACHE'" EXIT

CIRCUITS=(example state_mask private_vote)
if [[ "${INCLUDE_SLOW:-0}" == "1" ]]; then
    CIRCUITS+=(tx_privacy)
fi

echo "Building zerostyl-prove..."
cargo build -p zerostyl-cli --quiet

BIN="$(cargo metadata --format-version 1 --no-deps | \
    grep -o '"target_directory":"[^"]*"' | cut -d'"' -f4)/debug/zerostyl-prove"

for c in "${CIRCUITS[@]}"; do
    echo
    echo "=== $c ==="
    WORK="$CACHE/$c"
    mkdir -p "$WORK"

    "$BIN" generate \
        --circuit "$c" \
        --witnesses "witnesses/${c}_valid.json" \
        --output "$WORK/proof.bin" \
        --cache-dir "$CACHE/keys"

    "$BIN" verify \
        --circuit "$c" \
        --proof "$WORK/proof.bin" \
        --inputs "$WORK/public_inputs.json" \
        --cache-dir "$CACHE/keys"
done

echo
echo "All ${#CIRCUITS[@]} circuit(s) verified OK."
