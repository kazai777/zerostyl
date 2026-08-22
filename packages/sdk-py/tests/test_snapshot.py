"""Locks the generated bindings for the demo circuit against a committed
snapshot. Set ``REGEN_SDK_PY_SNAPSHOTS=1`` to overwrite the snapshot after an
intentional generator change."""

import os
from pathlib import Path

from zerostyl_sdk import generate_bindings, parse_abi_schema

DEMO_ABI = (
    Path(__file__).resolve().parents[3] / "examples" / "zk_private_demo" / "abi.json"
)
SNAPSHOT = Path(__file__).parent / "snapshots" / "zk_private_demo_snap.py"


def test_demo_bindings_match_snapshot():
    abi = parse_abi_schema(DEMO_ABI.read_text(encoding="utf-8"))
    generated = generate_bindings(abi)
    compile(generated, "<generated>", "exec")

    if os.environ.get("REGEN_SDK_PY_SNAPSHOTS"):
        SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
        SNAPSHOT.write_text(generated, encoding="utf-8")
        return

    assert SNAPSHOT.exists(), (
        f"snapshot {SNAPSHOT} missing — run REGEN_SDK_PY_SNAPSHOTS=1 python -m pytest"
    )
    on_disk = SNAPSHOT.read_text(encoding="utf-8").replace("\r\n", "\n")
    assert on_disk == generated.replace("\r\n", "\n"), (
        "snapshot out of sync — run REGEN_SDK_PY_SNAPSHOTS=1 python -m pytest"
    )
