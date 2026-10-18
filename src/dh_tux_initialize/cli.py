"""Command-line interface for DH-Tux-Initialize."""

from __future__ import annotations

import argparse
import importlib
import json
import math
import sys
from collections.abc import Sequence
from typing import Any

from . import __version__
from .discovery import (
    DEFAULT_SCAN_ROUNDS,
    DEFAULT_SCAN_TIMEOUT,
    DiscoveredDevice,
    discover,
)
from .init_protocol import DEFAULT_INIT_IP, DEFAULT_INIT_TIMEOUT, InitializationClient
from .ip_ranges import parse_ipv4_range
from .setup import run_setup


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dh-tux-initialize",
        description="Discover and initialize Dahua IP devices on the local Layer 2 network.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--debug", action="store_true", help="Print DHIP JSON for TX and RX")

    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")
    scan = commands.add_parser("scan", help="Search for Dahua devices using DHIP multicast")
    _add_scan_tuning_options(scan)
    scan.add_argument(
        "--interface",
        metavar="IPV4",
        help="Local IPv4 address of the network interface used for multicast",
    )
    # Allow --debug both before and after the subcommand.
    scan.add_argument(
        "--debug",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Print DHIP JSON for TX and RX",
    )
    setup = commands.add_parser(
        "setup",
        help="Interactively configure discovered cameras after confirmation",
    )
    setup.add_argument(
        "--all",
        action="store_true",
        help="Compatibility option; all discovered devices are always shown",
    )
    _add_scan_tuning_options(setup)
    setup.add_argument(
        "--interface",
        metavar="IPV4",
        help="Local IPv4 address of the network interface used for multicast",
    )
    setup.add_argument(
        "--debug",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Print DHIP JSON for TX and RX",
    )
    diagnose = commands.add_parser(
        "diagnose",
        help="Run read-only discovery diagnostics",
    )
    diagnostic_phases = ("probe", "quick")
    if not getattr(sys, "frozen", False):
        diagnostic_phases += ("deep",)
    diagnose.add_argument(
        "--phase",
        choices=diagnostic_phases,
        default="quick",
        help="Diagnostic phase to run (default: quick scan)",
    )
    diagnose.add_argument("--ip", help="Target IPv4 address for --phase probe")
    diagnose.add_argument(
        "--timeout",
        type=_positive_float,
        default=DEFAULT_SCAN_TIMEOUT,
        metavar="SECONDS",
        help="Receive timeout for discovery probes (default: 2.5)",
    )
    if "deep" in diagnostic_phases:
        diagnose.add_argument(
            "--range",
            dest="scan_range",
            type=parse_ipv4_range,
            metavar="CIDR",
            help="IPv4 CIDR to probe during the deep phase",
        )
    diagnose.set_defaults(scan_range=None)
    diagnose.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Print detailed discovery diagnostics",
    )
    init_caps = commands.add_parser(
        "init-capabilities",
        help="Read initialization status, capabilities, and encryption info",
    )
    init_caps.add_argument(
        "--ip",
        default=DEFAULT_INIT_IP,
        metavar="IPV4",
        help=f"Dahua factory-default camera IPv4 address (default: {DEFAULT_INIT_IP})",
    )
    init_caps.add_argument(
        "--timeout",
        type=_positive_float,
        default=DEFAULT_INIT_TIMEOUT,
        metavar="SECONDS",
        help=f"HTTP timeout in seconds (default: {DEFAULT_INIT_TIMEOUT:g})",
    )
    init_caps.add_argument("--port", type=int, default=80, help="HTTP port (default: 80)")
    init_caps.add_argument(
        "--https",
        action="store_true",
        help="Use HTTPS for the read-only capability queries",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = list(sys.argv[1:] if argv is None else argv)
    if _should_default_to_setup(arguments):
        arguments.insert(0, "setup")
    args = parser.parse_args(arguments)
    if args.command == "scan":
        try:
            devices = discover(
                timeout=args.scan_timeout,
                rounds=args.scan_rounds,
                interface_ip=args.interface,
                debug=args.debug,
            )
        except (OSError, ValueError) as exc:
            print(f"DHIP scan failed: {exc}", file=sys.stderr)
            return 2
        print_devices(devices)
        return 0

    if args.command == "setup":
        try:
            print("Scanning for Dahua devices...", flush=True)
            devices = discover(
                timeout=args.scan_timeout,
                rounds=args.scan_rounds,
                interface_ip=args.interface,
                debug=args.debug,
            )
        except KeyboardInterrupt:
            print("\nAborted.")
            return 130
        except (OSError, ValueError) as exc:
            print(f"DHIP scan failed: {exc}", file=sys.stderr)
            return 2
        try:
            run_setup(
                devices,
                show_all=args.all,
                rescan_fn=lambda: discover(
                    timeout=args.scan_timeout,
                    rounds=args.scan_rounds,
                    interface_ip=args.interface,
                    debug=args.debug,
                ),
            )
        except KeyboardInterrupt:
            # Guard interrupts raised outside run_setup's input loop.
            print("\nAborted.")
            return 130
        return 0

    if args.command == "init-capabilities":
        try:
            client = InitializationClient(
                args.ip,
                timeout=args.timeout,
                port=args.port,
                scheme="https" if args.https else "http",
            )
            diagnostics = client.inspect()
            print(json.dumps(diagnostics.report(), ensure_ascii=False, indent=2))
        except (OSError, ValueError) as exc:
            print(f"Initialization capability query failed: {exc}", file=sys.stderr)
            return 2
        return 0

    if args.command == "diagnose":
        if args.phase == "probe" and not args.ip:
            parser.error("diagnose --phase probe requires --ip IPV4")
        if args.phase != "probe" and args.ip:
            parser.error("--ip is only valid with diagnose --phase probe")
        if args.phase == "deep" and args.scan_range is None:
            parser.error("diagnose --phase deep requires --range CIDR")
        if args.phase != "deep" and args.scan_range is not None:
            parser.error("--range is only valid with diagnose --phase deep")
        try:
            run_diagnostics(args)
        except (OSError, ValueError) as exc:
            print(f"DHIP diagnostics failed: {exc}", file=sys.stderr)
            return 2
        return 0

    parser.error("unknown command")
    return 2


def _should_default_to_setup(arguments: Sequence[str]) -> bool:
    """Preserve setup as the default command while keeping root help available."""
    commands = {"scan", "setup", "diagnose", "init-capabilities"}
    if arguments and arguments[0] in commands:
        return False
    if len(arguments) > 1 and arguments[0] == "--debug" and arguments[1] in commands:
        return False
    if any(argument in {"-h", "--help", "--version"} for argument in arguments):
        return False
    return True


def print_devices(devices: Sequence[DiscoveredDevice]) -> None:
    if not devices:
        print("No Dahua devices found.")
        return

    columns: list[tuple[str, Any]] = [
        ("MAC", lambda device: device.mac),
        ("Current IP", lambda device: device.ipv4),
        ("Model", lambda device: device.model),
        ("Serial", lambda device: device.serial_number),
        ("Firmware", lambda device: device.firmware),
        ("Init (raw)", _format_init_value),
    ]
    rows = [
        [_format_value(getter(device)) for _label, getter in columns]
        for device in devices
    ]
    widths = [
        max(len(label), *(len(row[index]) for row in rows))
        for index, (label, _getter) in enumerate(columns)
    ]
    header = "  ".join(label.ljust(widths[index]) for index, (label, _) in enumerate(columns))
    separator = "  ".join("─" * width for width in widths)
    print(header)
    print(separator)
    for row in rows:
        print("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)))


def _format_value(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, (dict, list, bool, int, float)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return str(value)


def _format_init_value(device: DiscoveredDevice) -> str:
    if not device.has_init_value:
        return "—"
    return json.dumps(device.init_value, ensure_ascii=False, separators=(",", ":"))


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be finite and greater than zero")
    return parsed


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _add_scan_tuning_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--scan-timeout",
        "--timeout",
        dest="scan_timeout",
        type=_positive_float,
        default=DEFAULT_SCAN_TIMEOUT,
        metavar="SECONDS",
        help=f"Total seconds to collect replies (default: {DEFAULT_SCAN_TIMEOUT:g})",
    )
    parser.add_argument(
        "--scan-rounds",
        type=_positive_int,
        default=DEFAULT_SCAN_ROUNDS,
        metavar="COUNT",
        help=f"Number of multicast/broadcast probe bursts (default: {DEFAULT_SCAN_ROUNDS})",
    )


def run_diagnostics(args: argparse.Namespace) -> None:
    """Run read-only discovery diagnostics for explicitly selected targets."""
    phase = args.phase
    if phase == "probe":
        from .diagnostic_discovery import direct_probe

        for record in direct_probe(args.ip, timeout=args.timeout):
            print(json.dumps(_probe_record_dict(record), ensure_ascii=False, separators=(",", ":")))
        return

    if phase == "quick":
        devices = discover(
            timeout=args.timeout,
            rounds=DEFAULT_SCAN_ROUNDS,
            debug=args.debug,
        )
    else:
        try:
            deep_discovery = importlib.import_module(
                ".deep_discovery", package=__package__
            )
        except ModuleNotFoundError:
            print("Deep diagnostics are not included in this release binary.", file=sys.stderr)
            return
        devices = deep_discovery.deep_discover(
            str(args.scan_range),
            timeout=args.timeout,
            workers=deep_discovery.DEFAULT_DEEP_SCAN_WORKERS,
            debug=args.debug,
        )
    print(f"Found {len(devices)} device(s)")
    for device in devices:
        print(
            f"{device.ipv4:<15} {_format_value(device.mac):<19} "
            f"{_format_value(device.serial_number):<24} "
            f"{_format_value(device.model):<24} {device.initialization_status}"
        )


def _probe_record_dict(record: Any) -> dict[str, Any]:
    return {
        "destination_ip": record.destination_ip,
        "local_ip": record.local_ip,
        "local_port": record.local_port,
        "send_timestamp": record.send_timestamp,
        "receive_timestamp": record.receive_timestamp,
        "elapsed_ms": round(record.elapsed_ms, 3),
        "sender_ip": record.sender_ip,
        "sender_port": record.sender_port,
        "response_length": record.response_length,
        "valid_dhip_framing": record.valid_dhip_framing,
        "json_parse_success": record.json_parse_success,
        "model": record.model,
        "mac": record.mac,
        "serial": record.serial,
        "init_raw": record.init_raw,
        "accepted": record.accepted,
        "rejection_reason": record.rejection_reason,
    }


if __name__ == "__main__":
    raise SystemExit(main())
