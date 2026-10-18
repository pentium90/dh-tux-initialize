"""Sessionless initialization RPC transport over Dahua's DHIP multicast path."""

from __future__ import annotations

import ipaddress
import socket
import time
from collections.abc import Mapping
from typing import Any, Callable

from .protocol import decode_json_datagram, encode_frame

DHIP_INIT_GROUP = "239.255.255.251"
DHIP_INIT_PORT = 37810
_METHOD_ALIASES = {
    # The initialization state comes from DHDiscover.search's deviceInfo.Init
    # field rather than a DevInit.getStatus RPC.
    "DevInit.getStatus": "DHDiscover.search",
    # Capability reads before account creation use userManager.getCaps.
    "DevInit.getDevCaps": "userManager.getCaps",
}


class DhipInitializationTransportError(RuntimeError):
    """A safe, user-displayable DHIP transport failure without request data."""


SocketFactory = Callable[..., Any]


class DhipInitializationTransport:
    """Send one sessionless DHIP initialization request.

    The request uses the discovery multicast group. Its envelope puts the
    selected camera MAC beside ``method`` at the root, keeps ``uni`` in
    ``params``, and uses zeroed DHIP request/session IDs. Responses are emitted
    as multicast notifications on UDP/37810, so the socket binds that port and
    joins the group before sending. A request is sent exactly once; no write is
    retried.
    """

    def __init__(
        self,
        target_ip: str,
        target_mac: str | None = None,
        *,
        interface_ip: str | None = None,
        socket_factory: SocketFactory | None = None,
    ) -> None:
        try:
            self.target_ip = str(ipaddress.IPv4Address(target_ip))
        except (ipaddress.AddressValueError, TypeError):
            raise ValueError("DHIP target must be an IPv4 address") from None
        self.target_mac = _normalize_mac(target_mac) if target_mac else None
        if interface_ip is None:
            self.interface_ip = None
        else:
            try:
                self.interface_ip = str(ipaddress.IPv4Address(interface_ip))
            except (ipaddress.AddressValueError, TypeError):
                raise ValueError("DHIP interface must be an IPv4 address") from None
        self._socket_factory = socket_factory or socket.socket

    def post_json(
        self,
        url: str,
        body: Mapping[str, Any],
        *,
        timeout: float,
    ) -> Mapping[str, Any]:
        del url  # The device address is kept separately from the multicast endpoint.
        if not isinstance(body, Mapping):
            raise DhipInitializationTransportError("DHIP request must be a JSON object")
        method = body.get("method")
        request_id = body.get("id")
        if not isinstance(method, str) or not method:
            raise DhipInitializationTransportError("DHIP request method is missing")
        if not isinstance(request_id, int) or isinstance(request_id, bool) or not 0 <= request_id <= 0xFFFFFFFF:
            raise DhipInitializationTransportError("DHIP request ID is invalid")
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise DhipInitializationTransportError("DHIP request timeout is invalid")
        if method == "DevInit.account" and self.target_mac is None:
            raise DhipInitializationTransportError(
                "DHIP DevInit.account requires the selected camera MAC"
            )

        request = dict(body)
        wire_method = _METHOD_ALIASES.get(method, method)
        params = request.get("params")
        if params is None:
            routed_params: dict[str, Any] = {}
        elif isinstance(params, Mapping):
            routed_params = dict(params)
        else:
            raise DhipInitializationTransportError("DHIP initialization params must be an object")
        # Targeted initialization RPCs use a root-level MAC. The discovery
        # query instead has an empty params.mac and no root MAC, so the
        # response can be filtered by its device identity.
        if method == "DevInit.getStatus":
            routed_params = {"mac": "", "uni": 1}
            request.pop("mac", None)
        else:
            routed_params.pop("mac", None)
            request["mac"] = _format_mac(self.target_mac) if self.target_mac else ""
        routed_params["uni"] = 1
        request["params"] = routed_params
        request["method"] = wire_method
        # Initialization methods run before login; never fabricate a session.
        request.pop("session", None)
        # Multicast notifications are correlated by method and MAC; the
        # request uses neither a JSON-RPC id nor a nonzero DHIP request ID.
        request.pop("id", None)

        try:
            packet = encode_frame(request, session_id=0, request_id=0)
        except (TypeError, ValueError):
            raise DhipInitializationTransportError("DHIP request could not be encoded") from None

        sock = None
        try:
            sock = self._socket_factory(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            if self.interface_ip is not None:
                sock.setsockopt(
                    socket.IPPROTO_IP,
                    socket.IP_MULTICAST_IF,
                    socket.inet_aton(self.interface_ip),
                )
            membership = socket.inet_aton(DHIP_INIT_GROUP) + socket.inet_aton(
                self.interface_ip or "0.0.0.0"
            )
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
            sock.bind((self.interface_ip or "0.0.0.0", DHIP_INIT_PORT))
            sock.sendto(packet, (DHIP_INIT_GROUP, DHIP_INIT_PORT))
            deadline = time.monotonic() + float(timeout)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise DhipInitializationTransportError(
                        f"DHIP UDP/37810 response timed out for {method}"
                    )
                sock.settimeout(remaining)
                try:
                    datagram, sender = sock.recvfrom(65_535)
                except socket.timeout:
                    raise DhipInitializationTransportError(
                        f"DHIP UDP/37810 response timed out for {method}"
                    ) from None
                try:
                    response = decode_json_datagram(datagram)
                except ValueError:
                    continue
                if not self._is_target_response(response, sender[0]):
                    continue
                if not _matches_request(response, method):
                    continue
                return _normalize_response(response, request_id, method)
        except DhipInitializationTransportError:
            raise
        except OSError as exc:
            # OSError's message describes the socket operation and contains no
            # RPC payload; retaining it makes routing failures actionable.
            detail = str(exc).strip() or exc.__class__.__name__
            raise DhipInitializationTransportError(
                f"DHIP UDP/37810 transport failed for {method}: {detail}"
            ) from None
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def _is_target_response(self, response: Mapping[str, Any], sender_ip: str) -> bool:
        response_mac = response.get("mac") or response.get("Mac") or response.get("MAC")
        if response_mac:
            try:
                normalized = _normalize_mac(str(response_mac))
            except ValueError:
                return False
            if self.target_mac is not None:
                return normalized == self.target_mac
        try:
            sender = str(ipaddress.IPv4Address(sender_ip))
        except (ipaddress.AddressValueError, TypeError):
            return False
        return sender == self.target_ip


def _matches_request(
    response: Mapping[str, Any],
    request_method: str,
) -> bool:
    response_method = response.get("method")
    callback_methods = {
        "Security.getEncryptInfo": {"client.notifyEncryptInfo"},
        "DevInit.account": {"client.notifyDevInit", "client.notifyDevInitNext"},
        "DevInit.getStatus": {"client.notifyDevInfo"},
    }
    if response_method in callback_methods.get(request_method, set()):
        return True
    direct_methods = {request_method, _METHOD_ALIASES.get(request_method)}
    if response_method in direct_methods:
        # Ignore the multicast loopback copy of our request, which has no
        # result/error fields. DHIP responses may be ID-less.
        return "result" in response or "error" in response
    # Some DHIP services answer with a JSON-RPC result but omit the method.
    # There is only one in-flight request on this per-call socket.
    return response_method in (None, "") and (
        "result" in response or "error" in response
    )


def _normalize_response(
    response: Mapping[str, Any], request_id: int, request_method: str
) -> Mapping[str, Any]:
    response_method = response.get("method")
    expected_callbacks = {
        "Security.getEncryptInfo": {"client.notifyEncryptInfo"},
        "DevInit.account": {"client.notifyDevInit", "client.notifyDevInitNext"},
        "DevInit.getStatus": {"client.notifyDevInfo"},
        "DevInit.getDevCaps": {"userManager.getCaps"},
    }
    if response_method in expected_callbacks.get(request_method, set()):
        params = response.get("params")
        if not isinstance(params, Mapping):
            raise DhipInitializationTransportError(
                f"DHIP {request_method} callback has no params"
            )
        normalized_params = dict(params)
        if request_method == "DevInit.getStatus":
            device_info = normalized_params.get("deviceInfo")
            if isinstance(device_info, Mapping):
                normalized_params = dict(device_info)
        result = params.get("result", response.get("result", True))
        normalized: dict[str, Any] = {
            "id": request_id,
            "result": result,
            "params": normalized_params,
        }
        error = params.get("error", response.get("error"))
        if error not in (None, ""):
            normalized["error"] = error
        return normalized
    normalized = dict(response)
    normalized.setdefault("id", request_id)
    return normalized


def _normalize_mac(value: str) -> str:
    compact = "".join(character for character in value if character.isalnum()).casefold()
    if len(compact) != 12 or any(character not in "0123456789abcdef" for character in compact):
        raise ValueError("DHIP target MAC is invalid")
    return compact


def _format_mac(value: str) -> str:
    return ":".join(value[index : index + 2] for index in range(0, 12, 2))
