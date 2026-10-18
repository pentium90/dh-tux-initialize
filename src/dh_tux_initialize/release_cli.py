"""Small public command line entry point used by the release binary."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from . import __version__
from .discovery import discover
from .setup import run_setup


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dh-tux-initialize",
        description="DH-Tux-Initialize\n\nInitialize Dahua IP cameras from Linux.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    parser.parse_args(list(sys.argv[1:] if argv is None else argv))

    try:
        print("Scanning for Dahua devices...", flush=True)
        devices = discover()
    except KeyboardInterrupt:
        print("\nAborted.")
        return 130
    except (OSError, ValueError) as exc:
        print(f"DHIP scan failed: {exc}", file=sys.stderr)
        return 2

    try:
        run_setup(devices, rescan_fn=discover)
    except KeyboardInterrupt:
        print("\nAborted.")
        return 130
    return 0
