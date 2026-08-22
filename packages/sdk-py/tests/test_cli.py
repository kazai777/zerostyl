import json
import subprocess
import sys
from pathlib import Path

from zerostyl_sdk.cli import main

DEMO_ABI = (
    Path(__file__).resolve().parents[3] / "examples" / "zk_private_demo" / "abi.json"
)


def test_generate_to_stdout(capsys):
    assert main(["generate", "--abi", str(DEMO_ABI)]) == 0
    out = capsys.readouterr().out
    assert "class DepositWitness:" in out


def test_generate_to_file(tmp_path):
    out_file = tmp_path / "bindings.py"
    assert main(["generate", "--abi", str(DEMO_ABI), "--out", str(out_file)]) == 0
    content = out_file.read_text(encoding="utf-8")
    compile(content, str(out_file), "exec")
    assert "DEPOSIT_CIRCUIT" in content


def test_missing_abi_file_fails(tmp_path, capsys):
    assert main(["generate", "--abi", str(tmp_path / "nope.json")]) == 1
    assert "cannot read" in capsys.readouterr().err


def test_invalid_abi_fails(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"abi_version": 1}), encoding="utf-8")
    assert main(["generate", "--abi", str(bad)]) == 1
    assert "error:" in capsys.readouterr().err


def test_module_entry_point_runs():
    result = subprocess.run(
        [sys.executable, "-m", "zerostyl_sdk", "generate", "--abi", str(DEMO_ABI)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "class DepositWitness:" in result.stdout
