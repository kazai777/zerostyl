"""Command-line interface: ``zerostyl-sdk-py generate --abi <file> [--out <file>]``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .codegen.generator import generate_bindings
from .types import parse_abi_schema


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="zerostyl-sdk-py",
        description="Generate typed Python bindings from a ZeroStyl abi.json",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser("generate", help="generate bindings from an abi.json")
    generate.add_argument("--abi", "-a", required=True, help="path to the abi.json file")
    generate.add_argument(
        "--out", "-o", help="output .py file (prints to stdout when omitted)"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command != "generate":  # pragma: no cover — argparse enforces this
        return 2

    abi_path = Path(args.abi)
    try:
        abi = parse_abi_schema(abi_path.read_text(encoding="utf-8"))
    except OSError as exc:
        print(f"error: cannot read {abi_path}: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    bindings = generate_bindings(abi)
    if args.out:
        Path(args.out).write_text(bindings, encoding="utf-8")
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(bindings, end="")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
