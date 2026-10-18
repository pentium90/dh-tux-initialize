"""Small DHIP frame encoder and JSON parser for discovery datagrams."""

from __future__ import annotations

import json
import struct
from collections.abc import Mapping
from typing import Any

DHIP_MAGIC = 0x50494844  # little-endian bytes spell ``DHIP``
DHIP_HEADER_SIZE = 32
_HEADER = struct.Struct("<8I")


class ProtocolError(ValueError):
    """A datagram does not contain a valid DHIP or JSON discovery message."""


def encode_frame(
    payload: Mapping[str, Any],
    *,
    session_id: int = 0,
    request_id: int | None = None,
) -> bytes:
    """Encode one JSON object using the 32-byte DHIP header.

    The discovery probe leaves the session and request IDs at zero. RPC
    requests mirror their JSON ``id`` in the header's request ID field.
    """
    if not isinstance(payload, Mapping):
        raise TypeError("DHIP payload must be a mapping")
    if not isinstance(session_id, int) or isinstance(session_id, bool) or not 0 <= session_id <= 0xFFFFFFFF:
        raise ValueError("DHIP session ID must be an unsigned 32-bit integer")
    if request_id is None:
        candidate = payload.get("id", 0)
        request_id = candidate if isinstance(candidate, int) and not isinstance(candidate, bool) else 0
    if not isinstance(request_id, int) or isinstance(request_id, bool) or not 0 <= request_id <= 0xFFFFFFFF:
        raise ValueError("DHIP request ID must be an unsigned 32-bit integer")

    body = json.dumps(
        payload,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    header = _HEADER.pack(
        DHIP_HEADER_SIZE,
        DHIP_MAGIC,
        session_id,
        request_id,
        len(body),  # package length = JSON length + binary data length
        0,  # package index
        len(body),  # JSON message length
        0,  # binary data length
    )
    return header + body


def decode_json_datagram(datagram: bytes) -> dict[str, Any]:
    """Decode a DHIP-framed discovery response or a bare JSON response.

    Some device families return the JSON body without a DHIP header. The
    DHIP discovery responses use both forms, so this parser accepts both.
    """
    body = datagram
    if len(datagram) >= 8 and datagram[4:8] == b"DHIP":
        if len(datagram) < DHIP_HEADER_SIZE:
            raise ProtocolError("truncated DHIP header")

        (
            header_size,
            _magic,
            _session_id,
            _request_id,
            package_length,
            _package_index,
            message_length,
            data_length,
        ) = _HEADER.unpack_from(datagram)

        if header_size != DHIP_HEADER_SIZE:
            raise ProtocolError(f"unexpected DHIP header size: {header_size}")
        if package_length != message_length + data_length:
            raise ProtocolError("inconsistent DHIP payload lengths")
        available = len(datagram) - DHIP_HEADER_SIZE
        if package_length > available or message_length > available:
            raise ProtocolError("truncated DHIP payload")

        body = datagram[DHIP_HEADER_SIZE : DHIP_HEADER_SIZE + message_length]

    # A few firmware versions terminate the JSON text with NUL bytes.
    body = body.rstrip(b"\x00")
    try:
        message = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"invalid JSON discovery payload: {exc}") from exc

    if not isinstance(message, dict):
        raise ProtocolError("discovery JSON must be an object")
    return message


def has_valid_dhip_framing(datagram: bytes) -> bool:
    """Return whether a datagram contains a complete, internally consistent DHIP frame.

    Bare JSON remains supported by :func:`decode_json_datagram` for passive
    compatibility, but direct unicast admission can require a real DHIP frame.
    """
    if len(datagram) < DHIP_HEADER_SIZE or datagram[4:8] != b"DHIP":
        return False
    try:
        (
            header_size,
            magic,
            _session_id,
            _request_id,
            package_length,
            _package_index,
            message_length,
            data_length,
        ) = _HEADER.unpack_from(datagram)
    except struct.error:
        return False
    if header_size != DHIP_HEADER_SIZE or magic != DHIP_MAGIC:
        return False
    if package_length != message_length + data_length:
        return False
    available = len(datagram) - DHIP_HEADER_SIZE
    return package_length <= available and message_length <= available


def extract_device_info(message: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """Return the device-info object from common DHIP response envelopes."""
    params = message.get("params")
    if isinstance(params, Mapping):
        device_info = params.get("deviceInfo")
        if isinstance(device_info, Mapping):
            return device_info

        # Some firmwares put the device fields directly in ``params``.
        if _looks_like_device_info(params):
            return params

    # Also allow a direct device-info object as returned by a few variants.
    if _looks_like_device_info(message):
        return message
    return None


def _looks_like_device_info(value: Mapping[str, Any]) -> bool:
    known_fields = {
        "DeviceType", "deviceType", "Model", "model", "SerialNo",
        "serialNumber", "Mac", "mac", "IPv4Address", "IPAddress", "IP",
        "Version", "firmwareVersion", "Init",
    }
    for field in known_fields:
        if field not in value:
            continue
        field_value = value[field]
        # The search request itself contains ``params.mac == ""``. Do not
        # mistake that multicast loopback copy for a discovered device.
        if field in {"Mac", "mac", "MAC"}:
            if field_value not in (None, ""):
                return True
        elif field_value is not None:
            return True
    return False
