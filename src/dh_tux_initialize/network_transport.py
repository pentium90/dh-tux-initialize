"""Dahua DHIP network configuration over multicast.

``DHDiscover.setConfig`` requests carry the selected MAC at the JSON root,
credentials under ``params``, and IPv4 settings under
``params.deviceConfig.IPv4Address``. The DHCP field is spelled ``DhcpEnable``.
This is the LAN path used when the camera's address is outside the host subnet;
it does not open an authenticated HTTP connection.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import socket
import time
from collections.abc import Mapping
from typing import Any, Callable

from .init_transport import DHIP_INIT_GROUP, DHIP_INIT_PORT
from .protocol import decode_json_datagram, encode_frame

DHIP_NETWORK_METHOD = "DHDiscover.setConfig"


class DhipNetworkTransportError(RuntimeError):
    """Safe transport error for a DHIP network configuration call."""


SocketFactory = Callable[..., Any]


class DhipNetworkTransport:
    """Send one DHCP request over the DHIP multicast LAN."""

    __slots__ = ("target_ip", "target_mac", "interface_ip", "_socket_factory")

    def __init__(
        self,
        target_ip: str,
        target_mac: str,
        *,
        interface_ip: str | None = None,
        socket_factory: SocketFactory | None = None,
    ) -> None:
        try:
            self.target_ip = str(ipaddress.IPv4Address(target_ip))
        except (ipaddress.AddressValueError, TypeError):
            raise ValueError("DHIP target must be an IPv4 address") from None
        self.target_mac = _normalize_mac(target_mac)
        if interface_ip is None:
            self.interface_ip = None
        else:
            try:
                self.interface_ip = str(ipaddress.IPv4Address(interface_ip))
            except (ipaddress.AddressValueError, TypeError):
                raise ValueError("DHIP interface must be an IPv4 address") from None
        self._socket_factory = socket_factory or socket.socket

    def __repr__(self) -> str:
        return (
            f"DhipNetworkTransport(target_ip={self.target_ip!r}, "
            f"target_mac={self.target_mac!r})"
        )

    def set_dhcp(
        self,
        *,
        username: str,
        password: str,
        device_config: Mapping[str, Any],
        timeout: float,
    ) -> Mapping[str, Any]:
        """Perform the two-request DHIP Default authentication exchange."""
        if not isinstance(username, str) or not username:
            raise DhipNetworkTransportError("DHIP username is invalid")
        if not isinstance(password, str) or not password:
            raise DhipNetworkTransportError("DHIP password is invalid")
        if not isinstance(device_config, Mapping):
            raise DhipNetworkTransportError("DHIP device configuration is invalid")
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
            raise DhipNetworkTransportError("DHIP request timeout is invalid")

        # First send the requested configuration with an empty password. The
        # camera's notifyCfgChange response selects the Default mode; then
        # resend the same configuration with the configured password and
        # authorityType=Default. Never include either request in an exception
        # or diagnostic.
        request = {
            "method": DHIP_NETWORK_METHOD,
            "mac": _format_mac(self.target_mac),
            "params": {
                "userName": username,
                "password": "",
                "deviceConfig": dict(device_config),
                "uni": 1,
            },
        }

        sock = None
        try:
            sock = self._socket_factory(
                socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP
            )
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
            self._send_request(sock, request, (password,))
            challenge = self._receive_notify_response(
                sock, float(timeout), "challenge", (password,), request
            )
            realm, random_value = self._validate_default_challenge(
                challenge, (password,)
            )
            h1, h2 = _default_authentication_hashes(
                username, password, realm, random_value
            )
            sensitive_values = (password, h1, h2)

            authenticated_request = {
                "method": DHIP_NETWORK_METHOD,
                "mac": _format_mac(self.target_mac),
                "params": {
                    **request["params"],
                    "password": h2,
                    "authorityType": "Default",
                },
            }
            self._send_request(sock, authenticated_request, sensitive_values)
            response = self._receive_notify_response(
                sock,
                float(timeout),
                "authenticated response",
                sensitive_values,
                authenticated_request,
            )
            response = _normalize_set_config_response(response)
            params = response.get("params")
            if isinstance(params, Mapping) and "encryption" in params:
                if params.get("encryption") != "Default":
                    raise DhipNetworkTransportError(
                        "DHDiscover.setConfig response used unsupported authentication mode"
                    )
            response = _replace_sensitive_values(response, (h1, h2))
            if response.get("result") is not True:
                return response
            return response
        except DhipNetworkTransportError:
            raise
        except OSError as exc:
            detail = str(exc).strip() or exc.__class__.__name__
            detail = _redact_text(detail, (password,))
            raise DhipNetworkTransportError(
                f"DHIP UDP/37810 transport failed for DHDiscover.setConfig: {detail}"
            ) from None
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def _send_request(
        self, sock: Any, request: Mapping[str, Any], sensitive_values: tuple[str, ...]
    ) -> None:
        try:
            packet = encode_frame(request, session_id=0, request_id=0)
        except (TypeError, ValueError):
            raise DhipNetworkTransportError(
                "DHIP DHCP request could not be encoded"
            ) from None
        try:
            sock.sendto(packet, (DHIP_INIT_GROUP, DHIP_INIT_PORT))
        except OSError as exc:
            detail = str(exc).strip() or exc.__class__.__name__
            detail = _redact_text(detail, sensitive_values)
            raise DhipNetworkTransportError(
                f"DHIP UDP/37810 transport failed for DHDiscover.setConfig: {detail}"
            ) from None

    def _receive_notify_response(
        self,
        sock: Any,
        timeout: float,
        phase: str,
        sensitive_values: tuple[str, ...],
        sent_request: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DhipNetworkTransportError(
                    f"DHIP UDP/37810 response timed out for DHDiscover.setConfig {phase}"
                )
            sock.settimeout(remaining)
            try:
                datagram, _sender = sock.recvfrom(65_535)
            except socket.timeout:
                raise DhipNetworkTransportError(
                    f"DHIP UDP/37810 response timed out for DHDiscover.setConfig {phase}"
                ) from None
            try:
                response = decode_json_datagram(datagram)
            except ValueError:
                continue

            # The multicast socket can receive its own outgoing datagram.
            # Drop exact payload echoes before interpreting a response.
            if response == sent_request:
                continue

            method = response.get("method")
            response_mac = response.get("mac")
            # This socket also hears other cameras and unrelated multicast
            # traffic. Only the selected device can answer this transaction.
            if not _matches_mac(response_mac, self.target_mac):
                continue
            if method != "client.notifyCfgChange":
                # Ignore unrelated multicast traffic, but fail closed if the
                # selected device responds to this transaction with another
                # RPC method.
                raise DhipNetworkTransportError(
                    f"DHDiscover.setConfig {phase} used unexpected response: "
                    f"{_safe_response_diagnostic(response, sensitive_values)}"
                )
            return response

    @staticmethod
    def _validate_default_challenge(
        response: Mapping[str, Any], sensitive_values: tuple[str, ...]
    ) -> tuple[str, str]:
        if response.get("method") != "client.notifyCfgChange":
            raise DhipNetworkTransportError(
                "DHDiscover.setConfig challenge used unexpected response: "
                f"{_safe_response_diagnostic(response, sensitive_values)}"
            )
        params = response.get("params")
        if not isinstance(params, Mapping):
            raise DhipNetworkTransportError(
                "DHDiscover.setConfig challenge parameters were invalid"
            )
        if params.get("encryption") != "Default":
            raise DhipNetworkTransportError(
                "DHDiscover.setConfig challenge used unsupported authentication mode"
            )
        normalized = _normalize_set_config_response(response)
        if normalized.get("result") is not False:
            raise DhipNetworkTransportError(
                "DHDiscover.setConfig challenge did not request authentication"
            )
        realm = params.get("realm")
        if not isinstance(realm, str) or not realm:
            raise DhipNetworkTransportError(
                "DHDiscover.setConfig challenge realm was missing or invalid"
            )
        random_value = params.get("random")
        if not isinstance(random_value, str) or not random_value:
            raise DhipNetworkTransportError(
                "DHDiscover.setConfig challenge random was missing or invalid"
            )
        return realm, random_value


def _default_authentication_hashes(
    username: str, credential: str, realm: str, random_value: str
) -> tuple[str, str]:
    """Return the two uppercase MD5 values used by DHIP Default authentication."""
    h1_input = f"{username}:{realm}:{credential}"
    try:
        h1 = hashlib.md5(h1_input.encode("utf-8")).hexdigest().upper()
        h2_input = f"{username}:{random_value}:{h1}"
        h2 = hashlib.md5(h2_input.encode("utf-8")).hexdigest().upper()
    except UnicodeEncodeError:
        raise DhipNetworkTransportError(
            "DHDiscover.setConfig authentication input was invalid"
        ) from None
    return h1, h2


def build_dhcp_device_config(
    device_info: Mapping[str, Any],
    current_ip: str,
) -> dict[str, Any]:
    """Build the DHIP IPv4 settings object, preserving known current fields."""
    ipv4_config: dict[str, Any] = {}
    raw_ipv4 = device_info.get("IPv4Address")
    if isinstance(raw_ipv4, Mapping):
        for key in ("IPAddress", "SubnetMask", "DefaultGateway"):
            value = raw_ipv4.get(key)
            if key == "IPAddress" and isinstance(value, Mapping):
                value = value.get("IPAddress") or value.get("ipAddress") or value.get("IP")
            if isinstance(value, str) and value:
                ipv4_config[key] = value

    ipv4_config.setdefault("IPAddress", current_ip)
    ipv4_config["DhcpEnable"] = True

    config: dict[str, Any] = {"IPv4Address": ipv4_config}
    port = device_info.get("Port")
    if isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535:
        config["Port"] = port
    return config


def _normalize_set_config_response(response: Mapping[str, Any]) -> Mapping[str, Any]:
    params = response.get("params")
    if isinstance(params, Mapping) and (
        response.get("method") == "client.notifyCfgChange"
        or ("result" not in response and "result" in params)
        or ("error" not in response and "error" in params)
    ):
        normalized: dict[str, Any] = dict(response)
        error = params.get("error", response.get("error"))
        params_result = params.get("result")
        response_result = response.get("result")
        if error not in (None, ""):
            normalized["result"] = False
        elif (
            params_result is not None
            and response_result is not None
            and params_result != response_result
        ):
            normalized.pop("result", None)
        elif params_result is not None:
            normalized["result"] = params_result
        elif response_result is not None:
            normalized["result"] = response_result
        else:
            normalized.pop("result", None)
        if error not in (None, ""):
            normalized["error"] = error
        return normalized
    return response


def _safe_response_diagnostic(
    response: Mapping[str, Any], sensitive_values: tuple[str, ...]
) -> str:
    safe_response = _redact_response_value(response, sensitive_values)
    return json.dumps(safe_response, ensure_ascii=False, sort_keys=True)


def _redact_response_value(
    value: Any, sensitive_values: tuple[str, ...], key: str | None = None
) -> Any:
    if key is not None:
        normalized_key = "".join(character for character in key.casefold() if character.isalnum())
        if normalized_key in {
            "password",
            "passwd",
            "pwd",
            "passphrase",
            "credential",
            "credentials",
            "authorization",
            "token",
            "secret",
        }:
            return "<redacted>"
    if isinstance(value, Mapping):
        return {
            _redact_text(str(response_key), sensitive_values): _redact_response_value(
                response_value, sensitive_values, str(response_key)
            )
            for response_key, response_value in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact_response_value(item, sensitive_values) for item in value]
    if isinstance(value, str):
        return _redact_text(value, sensitive_values)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)


def _redact_text(value: str, sensitive_values: tuple[str, ...]) -> str:
    for sensitive_value in sensitive_values:
        if sensitive_value:
            value = value.replace(sensitive_value, "<redacted>")
    return value


def _replace_sensitive_values(value: Any, sensitive_values: tuple[str, ...]) -> Any:
    """Keep derived credentials out of responses later used in diagnostics."""
    if isinstance(value, Mapping):
        return {
            _redact_text(str(key), sensitive_values): _replace_sensitive_values(
                item, sensitive_values
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_replace_sensitive_values(item, sensitive_values) for item in value]
    if isinstance(value, str):
        return _redact_text(value, sensitive_values)
    return value


def _matches_mac(value: Any, target_mac: str) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        return _normalize_mac(value) == target_mac
    except ValueError:
        return False


def _normalize_mac(value: str) -> str:
    compact = "".join(character for character in value if character.isalnum()).casefold()
    if len(compact) != 12 or any(character not in "0123456789abcdef" for character in compact):
        raise ValueError("DHIP target MAC is invalid")
    return compact


def _format_mac(value: str) -> str:
    return ":".join(value[index : index + 2] for index in range(0, 12, 2))
