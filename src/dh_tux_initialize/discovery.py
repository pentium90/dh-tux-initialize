"""Read-only Dahua discovery using passive DHIP multicast probes."""

from __future__ import annotations

import ipaddress
import json
import math
import socket
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, TextIO

from .protocol import (
    decode_json_datagram,
    encode_frame,
    extract_device_info,
    has_valid_dhip_framing,
)

DISCOVER_GROUP = "239.255.255.251"
DISCOVER_BROADCAST = "255.255.255.255"
DISCOVER_PORT = 37810
DISCOVER_METHOD = "DHDiscover.search"
DISCOVER_PARAMS = {"mac": "", "uni": 1}
DEFAULT_SCAN_TIMEOUT = 2.5
DEFAULT_SCAN_ROUNDS = 3
DISCOVERY_ROUND_INTERVAL = 0.5
DISCOVERY_PROBE_STAGGER = 0.05


@dataclass(frozen=True)
class DiscoveredDevice:
    """A device response, retaining the reported values without coercion."""

    info: Mapping[str, Any]
    message: Mapping[str, Any]
    source_ip: str
    discovery_sources: frozenset[str] = frozenset()
    identity_sources: Mapping[str, str] = field(default_factory=dict)
    valid_dhip_identity: bool = False
    dahua_verified: bool = False
    vendor_evidence: frozenset[str] = frozenset()

    @property
    def mac(self) -> Any:
        return _first_value(self.info, "Mac", "mac", "MAC") or _first_value(
            self.message, "mac", "Mac", "MAC"
        )

    @property
    def ipv4(self) -> Any:
        address = _first_value(self.info, "IPv4Address", "ipv4Address")
        if isinstance(address, Mapping):
            address = _first_value(address, "IPAddress", "ipAddress", "IP")
        if address is None:
            address = _first_value(self.info, "IPAddress", "ipAddress", "IP", "IPv4")
        return address if address not in (None, "") else self.source_ip

    @property
    def model(self) -> Any:
        return _first_value(self.info, "DeviceType", "deviceType", "Model", "model")

    @property
    def serial_number(self) -> Any:
        return _first_value(self.info, "SerialNo", "serialNumber", "serial", "sn")

    @property
    def firmware(self) -> Any:
        return _first_value(self.info, "Version", "version", "firmwareVersion")

    @property
    def init_value(self) -> Any:
        # Keep the source type and value exactly as decoded (including 0/False).
        for key in ("Init", "init"):
            if key in self.info:
                return self.info[key]
        return None

    @property
    def has_init_value(self) -> bool:
        return "Init" in self.info or "init" in self.info

    @property
    def initialization_status(self) -> str:
        """Return a conservative human-readable initialization status.

        ``Init`` is a bit field. Only its two low bits are currently defined;
        higher bits are preserved in ``init_value`` but have no status meaning.
        """
        value = self.init_value
        # bool is an int subclass in Python but is not an integer Init bitfield.
        if not isinstance(value, int) or isinstance(value, bool):
            return "Unknown"
        status_bits = value & 0x03
        return {
            0: "Legacy",
            1: "Uninitialized",
            2: "Initialized",
            3: "Unknown",
        }[status_bits]

    @property
    def provisionable(self) -> bool:
        """Only a DHIP-verified identity with an Uninitialized Init bit is eligible."""
        return (
            self.valid_dhip_identity
            and self.initialization_status == "Uninitialized"
            and bool(self.mac)
        )




def _udp_socket(
    interface_ip: str | None = None,
    *,
    join_multicast: bool = False,
) -> socket.socket:
    """Create a credential-free UDP socket with a fresh ephemeral source port.

    The passive scan joins the multicast group; unicast host probes use the
    same broadcast settings without joining it. Reuse options stay disabled so
    concurrent per-host sockets cannot share a port and race to consume replies.
    """
    bind_ip = interface_ip or "0.0.0.0"
    interface_bytes = socket.inet_aton(bind_ip)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        if join_multicast:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            if interface_ip is not None:
                sock.setsockopt(
                    socket.IPPROTO_IP, socket.IP_MULTICAST_IF, interface_bytes
                )
            membership = socket.inet_aton(DISCOVER_GROUP) + interface_bytes
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)

        sock.bind((bind_ip, 0))
        return sock
    except OSError:
        sock.close()
        raise


def _device_from_datagram(
    datagram: bytes,
    sender_ip: str,
    *,
    source: str,
    debug: bool = False,
    output: TextIO | None = None,
) -> DiscoveredDevice | None:
    """Apply the existing DHIP parser and preserve the reported device data."""
    stream = output or sys.stderr
    try:
        message = decode_json_datagram(datagram)
    except ValueError as exc:
        if debug:
            print(
                f"RX {sender_ip}: invalid JSON ({exc}); data={datagram.hex()}",
                file=stream,
            )
        return None

    if debug:
        _debug_json(stream, f"RX {sender_ip}", message)

    info = extract_device_info(message)
    if not info:
        return None
    return DiscoveredDevice(
        info=info,
        message=message,
        source_ip=sender_ip,
        discovery_sources=frozenset({source}),
        identity_sources=_identity_field_sources(info, "dhip", message),
        valid_dhip_identity=has_valid_dhip_framing(datagram),
        dahua_verified=True,
    )


def _collect_replies(
    sock: socket.socket,
    deadline: float,
    *,
    probe: bytes,
    source: str,
    devices: list[DiscoveredDevice] | None = None,
    stop_at: float | None = None,
    max_replies: int | None = None,
    debug: bool = False,
    output: TextIO | None = None,
) -> list[DiscoveredDevice]:
    """Collect DHIP replies to an absolute deadline, optionally yielding to TX.

    ``stop_at`` lets a multi-round passive scan service the socket continuously
    but return to its transmission scheduler at the next planned probe time.
    """
    found = list(devices or [])
    receive_until = min(deadline, stop_at) if stop_at is not None else deadline
    while True:
        remaining = receive_until - time.monotonic()
        if remaining <= 0:
            break
        sock.settimeout(remaining)
        try:
            datagram, sender = sock.recvfrom(8192)
        except OSError:
            break
        if datagram == probe:
            continue
        device = _device_from_datagram(
            datagram,
            sender[0],
            source=source,
            debug=debug,
            output=output,
        )
        if device is not None and not any(
            _same_device(existing, device) for existing in found
        ):
            found.append(device)
            if max_replies is not None and len(found) >= max_replies:
                break
    return found


def discover(
    timeout: float = DEFAULT_SCAN_TIMEOUT,
    interface_ip: str | None = None,
    *,
    rounds: int = DEFAULT_SCAN_ROUNDS,
    debug: bool = False,
    debug_stream: TextIO | None = None,
) -> list[DiscoveredDevice]:
    """Run several multicast/broadcast probe bursts within one scan window.

    ``interface_ip`` selects the local IPv4 address used for multicast and
    broadcast. Probe transmissions are staggered, and replies are collected
    between transmissions until the single absolute scan deadline.
    """
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be a finite value greater than zero")
    if not isinstance(rounds, int) or isinstance(rounds, bool) or rounds <= 0:
        raise ValueError("rounds must be a positive integer")
    if interface_ip is not None:
        try:
            parsed_ip = ipaddress.ip_address(interface_ip)
        except ValueError as exc:
            raise ValueError(f"invalid interface IPv4 address: {interface_ip}") from exc
        if parsed_ip.version != 4:
            raise ValueError("interface must be an IPv4 address")

    output = debug_stream or sys.stderr
    probe_json = {"method": DISCOVER_METHOD, "params": dict(DISCOVER_PARAMS)}
    probe = encode_frame(probe_json)
    sock = _udp_socket(interface_ip, join_multicast=True)
    try:
        devices: list[DiscoveredDevice] = []
        scan_started = time.monotonic()
        deadline = scan_started + timeout
        probe_stagger = min(DISCOVERY_PROBE_STAGGER, timeout / (rounds * 4))
        if rounds > 1:
            round_interval = min(
                DISCOVERY_ROUND_INTERVAL,
                (timeout - 2 * probe_stagger) / (rounds - 1),
            )
        else:
            round_interval = DISCOVERY_ROUND_INTERVAL

        rounds_sent = 0
        next_round_at = scan_started
        broadcast_at: float | None = None

        def send_probe(label: str, address: str) -> None:
            if debug:
                print(f"TX {label} {address}:{DISCOVER_PORT}", file=output)
                _debug_json(output, "TX", probe_json)
            sock.sendto(probe, (address, DISCOVER_PORT))

        while True:
            now = time.monotonic()
            remaining = deadline - now
            if remaining <= 0:
                break

            if broadcast_at is not None and broadcast_at <= now:
                send_probe("broadcast", DISCOVER_BROADCAST)
                broadcast_at = None
                continue

            if rounds_sent < rounds and next_round_at <= now:
                if debug:
                    print(f"Probe burst {rounds_sent + 1}/{rounds}", file=output)
                send_probe("multicast", DISCOVER_GROUP)
                rounds_sent += 1
                broadcast_at = now + probe_stagger
                next_round_at = scan_started + rounds_sent * round_interval
                continue

            next_event_at = deadline
            if broadcast_at is not None:
                next_event_at = min(next_event_at, broadcast_at)
            if rounds_sent < rounds:
                next_event_at = min(next_event_at, next_round_at)
            if next_event_at <= now:
                continue
            devices = _collect_replies(
                sock,
                deadline,
                probe=probe,
                source="quick",
                devices=devices,
                stop_at=next_event_at,
                debug=debug,
                output=output,
            )
        if debug:
            elapsed = time.monotonic() - scan_started
            uninitialized = sum(
                device.initialization_status == "Uninitialized" for device in devices
            )
            print(f"Quick scan: {elapsed:.2f} s", file=output)
            print(f"Probe bursts: {rounds_sent}", file=output)
            print(f"Unique DHIP devices: {len(devices)}", file=output)
            print(f"Uninitialized devices: {uninitialized}", file=output)
        return devices
    finally:
        sock.close()















































def merge_devices(
    *device_groups: Iterable[DiscoveredDevice],
) -> list[DiscoveredDevice]:
    """Merge repeated sightings of the same IP endpoint without physical dedup."""
    merged: list[DiscoveredDevice] = []
    for group in device_groups:
        for device in group:
            match_index = next(
                (
                    index
                    for index, existing in enumerate(merged)
                    if _same_device(existing, device)
                ),
                None,
            )
            if match_index is None:
                merged.append(device)
                continue

            existing = merged[match_index]
            merged_info = dict(existing.info)
            field_sources = dict(existing.identity_sources)
            for key, value in device.info.items():
                field_name = _identity_field_for_key(key)
                current_source = field_sources.get(field_name) if field_name else None
                incoming_source = device.identity_sources.get(field_name) if field_name else None
                if (
                    current_source
                    and _identity_source_priority(current_source)
                    > _identity_source_priority(incoming_source or "unknown")
                ):
                    continue
                merged_info[key] = value
            for field_name, source in device.identity_sources.items():
                current_source = field_sources.get(field_name)
                if (
                    current_source is None
                    or _identity_source_priority(source) >= _identity_source_priority(current_source)
                ):
                    field_sources[field_name] = source
            valid_dhip_identity = existing.valid_dhip_identity or device.valid_dhip_identity
            if valid_dhip_identity:
                merged_info["DiscoveryMethod"] = "DHIP"
            vendor_evidence = existing.vendor_evidence | device.vendor_evidence
            if vendor_evidence:
                merged_info["DahuaEvidence"] = tuple(sorted(vendor_evidence))
            merged[match_index] = DiscoveredDevice(
                info=merged_info,
                message=(
                    device.message if device.valid_dhip_identity or not existing.valid_dhip_identity
                    else existing.message
                ),
                source_ip=(
                    device.source_ip if device.valid_dhip_identity or not existing.valid_dhip_identity
                    else existing.source_ip
                ),
                discovery_sources=existing.discovery_sources | device.discovery_sources,
                identity_sources=field_sources,
                valid_dhip_identity=valid_dhip_identity,
                dahua_verified=existing.dahua_verified or device.dahua_verified,
                vendor_evidence=vendor_evidence,
            )
    return merged


def _first_value(mapping: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        value = mapping.get(key)
        if value is not None and value != "":
            return value
    return None


def _identity_field_sources(
    info: Mapping[str, Any],
    source: str,
    message: Mapping[str, Any] | None = None,
) -> dict[str, str]:
    values = {
        "model": _first_value(info, "DeviceType", "deviceType", "Model", "model"),
        "mac": _first_value(info, "Mac", "mac", "MAC"),
        "serial": _first_value(info, "SerialNo", "serialNumber", "serial", "sn"),
        "firmware": _first_value(info, "Version", "version", "firmwareVersion"),
        "init": _first_value(info, "Init", "init"),
    }
    if values["mac"] in (None, "") and message is not None:
        values["mac"] = _first_value(message, "Mac", "mac", "MAC")
    return {field_name: source for field_name, value in values.items() if value not in (None, "")}


def _identity_field_for_key(key: str) -> str | None:
    return {
        "devicetype": "model",
        "model": "model",
        "mac": "mac",
        "macaddress": "mac",
        "serialno": "serial",
        "serialnumber": "serial",
        "serial": "serial",
        "sn": "serial",
        "version": "firmware",
        "firmwareversion": "firmware",
        "init": "init",
    }.get(key.replace("_", "").casefold())


def _identity_source_priority(source: str) -> int:
    return {
        "dhip": 100,
        "onvif-get-device-information": 50,
        "onvif-wsd-scope": 40,
    }.get(source, 0)


def _same_device(left: DiscoveredDevice, right: DiscoveredDevice) -> bool:
    """Treat each configured IP address as a separate endpoint."""
    left_ip = _normalize_ip(left.ipv4)
    right_ip = _normalize_ip(right.ipv4)
    return bool(left_ip and right_ip and left_ip == right_ip)


def _normalize_mac(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return (
        str(value)
        .strip()
        .casefold()
        .replace(":", "")
        .replace("-", "")
        .replace(".", "")
        .replace(" ", "")
    )


def _normalize_identifier(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return str(value).strip().casefold() or None


def _normalize_ip(value: Any) -> str | None:
    if value in (None, ""):
        return None
    rendered = str(value).strip()
    try:
        return str(ipaddress.ip_address(rendered))
    except ValueError:
        return rendered.casefold() or None


def _debug_json(stream: TextIO, label: str, value: Mapping[str, Any]) -> None:
    rendered = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
    print(f"{label} JSON:\n{rendered}", file=stream)
