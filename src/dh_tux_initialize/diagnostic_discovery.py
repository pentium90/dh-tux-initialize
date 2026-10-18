"""Read-only unicast discovery diagnostics retained for developer workflows."""

from __future__ import annotations

import ipaddress
import math
import socket
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .discovery import (
    DEFAULT_SCAN_TIMEOUT,
    DISCOVER_METHOD,
    DISCOVER_PARAMS,
    DISCOVER_PORT,
    DiscoveredDevice,
    _first_value,
    _identity_field_sources,
    _udp_socket,
)
from .protocol import decode_json_datagram, encode_frame, extract_device_info, has_valid_dhip_framing


@dataclass(frozen=True)
class ProbeRecord:
    """One received response (or timeout) for a direct unicast probe."""

    destination_ip: str
    local_ip: str
    local_port: int
    send_timestamp: str
    receive_timestamp: str | None
    elapsed_ms: float
    sender_ip: str | None
    sender_port: int | None
    response_length: int | None
    valid_dhip_framing: bool | None
    json_parse_success: bool | None
    model: Any = None
    mac: Any = None
    serial: Any = None
    init_raw: Any = None
    accepted: bool = False
    rejection_reason: str | None = None
    device: DiscoveredDevice | None = field(default=None, repr=False, compare=False)



def direct_probe(
    host: str | ipaddress.IPv4Address,
    timeout: float = DEFAULT_SCAN_TIMEOUT,
    port: int = DISCOVER_PORT,
    *,
    probe: bytes | None = None,
    stop_after_accept: bool = False,
) -> list[ProbeRecord]:
    """Send an unauthenticated DHIP search to one host and record its replies.

    Each call owns a fresh ephemeral UDP socket. By default it listens to the
    full timeout so duplicate or malformed replies are visible in diagnostics;
    production Deep Scan stops after the first accepted response.
    """
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("probe timeout must be a finite value greater than zero")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("probe port must be between 1 and 65535")
    try:
        host_ip = str(ipaddress.IPv4Address(host))
    except ipaddress.AddressValueError as exc:
        raise ValueError(f"invalid probe IPv4 address: {host}") from exc

    request = probe or encode_frame(
        {"method": DISCOVER_METHOD, "params": dict(DISCOVER_PARAMS)}
    )
    sock: socket.socket | None = None
    sent_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    started = time.monotonic()
    deadline = started + timeout
    local_ip = "0.0.0.0"
    local_port = 0
    records: list[ProbeRecord] = []
    accepted_once = False
    try:
        # Deliberately do not share this socket with another host probe.
        sock = _udp_socket()
        # A UDP connect selects the route/source address without transmitting
        # a datagram; send() below still emits the unchanged DHIP search frame.
        sock.connect((host_ip, port))
        try:
            local_ip, local_port = sock.getsockname()[:2]
        except (AttributeError, OSError):
            pass
        sent_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        started = time.monotonic()
        deadline = started + timeout
        sock.send(request)
        try:
            local_ip, local_port = sock.getsockname()[:2]
        except (AttributeError, OSError):
            pass

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                datagram, sender = sock.recvfrom(65_535)
            except socket.timeout:
                break
            except OSError:
                break

            received_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
            elapsed_ms = max(0.0, (time.monotonic() - started) * 1000)
            sender_ip, sender_port = sender[0], sender[1]
            framed = has_valid_dhip_framing(datagram)
            message: Mapping[str, Any] | None = None
            info: Mapping[str, Any] | None = None
            try:
                message = decode_json_datagram(datagram)
            except ValueError:
                pass
            json_ok = message is not None
            if message is not None:
                info = extract_device_info(message)

            reason: str | None = None
            device: DiscoveredDevice | None = None
            if sender_ip != host_ip:
                reason = "sender_ip_mismatch"
            elif not framed:
                reason = "invalid_dhip_framing"
            elif not json_ok:
                reason = "json_parse_failed"
            elif not info:
                reason = "missing_device_info"
            elif accepted_once:
                reason = "duplicate_reply"
            else:
                device = DiscoveredDevice(
                    info=info,
                    message=message or {},
                    source_ip=sender_ip,
                    discovery_sources=frozenset({"deep"}),
                    identity_sources=_identity_field_sources(info, "dhip", message),
                    valid_dhip_identity=True,
                    dahua_verified=True,
                )
                accepted_once = True

            mac = _first_value(info, "Mac", "mac", "MAC") if info else None
            if mac is None and message is not None:
                mac = _first_value(message, "mac", "Mac", "MAC")

            record = ProbeRecord(
                destination_ip=host_ip,
                local_ip=local_ip,
                local_port=local_port,
                send_timestamp=sent_at,
                receive_timestamp=received_at,
                elapsed_ms=elapsed_ms,
                sender_ip=sender_ip,
                sender_port=sender_port,
                response_length=len(datagram),
                valid_dhip_framing=framed,
                json_parse_success=json_ok,
                model=_first_value(info, "DeviceType", "deviceType", "Model", "model") if info else None,
                mac=mac,
                serial=_first_value(info, "SerialNo", "serialNumber", "serial", "sn") if info else None,
                init_raw=info.get("Init", info.get("init")) if info else None,
                accepted=device is not None,
                rejection_reason=reason,
                device=device,
            )
            records.append(record)
            if record.accepted and stop_after_accept:
                break

        if not records:
            records.append(
                ProbeRecord(
                    destination_ip=host_ip,
                    local_ip=local_ip,
                    local_port=local_port,
                    send_timestamp=sent_at,
                    receive_timestamp=None,
                    elapsed_ms=max(0.0, (time.monotonic() - started) * 1000),
                    sender_ip=None,
                    sender_port=None,
                    response_length=None,
                    valid_dhip_framing=None,
                    json_parse_success=None,
                    rejection_reason="no_reply",
                )
            )
    except OSError as exc:
        if not records:
            records.append(
                ProbeRecord(
                    destination_ip=host_ip,
                    local_ip=local_ip,
                    local_port=local_port,
                    send_timestamp=sent_at,
                    receive_timestamp=None,
                    elapsed_ms=max(0.0, (time.monotonic() - started) * 1000),
                    sender_ip=None,
                    sender_port=None,
                    response_length=None,
                    valid_dhip_framing=None,
                    json_parse_success=None,
                    rejection_reason=(
                        f"socket_error:{type(exc).__name__}:errno={exc.errno}"
                    ),
                )
            )
    finally:
        if sock is not None:
            sock.close()
    return records
