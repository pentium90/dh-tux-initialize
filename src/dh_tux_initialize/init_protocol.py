"""Dahua factory-initialization RPC protocol and injectable JSON transport."""

from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from .init_crypto import (
    CryptoProtocolError,
    EncryptionProfile,
    describe_security_encrypt_info,
    encrypt_parameters,
    parse_security_encrypt_info,
)
from .init_transport import (
    DHIP_INIT_PORT,
    DhipInitializationTransport,
    DhipInitializationTransportError,
)

# Dahua factory-default IPv4 address, not a private-environment test endpoint.
DEFAULT_INIT_IP = "192.168.1.108"
DEFAULT_INIT_TIMEOUT = 2.5
OUTSIDE_CMD_PATH = "/OutsideCmd"

READ_METHODS = (
    "DevInit.getStatus",
    "DevInit.getDevCaps",
    "Security.getEncryptInfo",
)
USER_MANAGER_CAPS_METHOD = "userManager.getCaps"
_DISCOVERY_INIT_UNSET = object()

# These optional DevInit settings use enum value 0 for the disabled state: no
# Easy4ip/P2P registration or update polling.
MINIMUM_ACCESS_PARAMS = {"NetAccess": 0, "UpgradeCheck": 0}


class InitializationError(ValueError):
    """A safe, non-secret protocol or transport failure."""


class JsonTransport(Protocol):
    """Small injection point used by the client and its tests."""

    def post_json(
        self,
        url: str,
        body: Mapping[str, Any],
        *,
        timeout: float,
    ) -> Mapping[str, Any]: ...


class UrllibJsonTransport:
    """Default JSON-over-HTTP transport with secret-safe error messages."""

    def post_json(
        self,
        url: str,
        body: Mapping[str, Any],
        *,
        timeout: float,
    ) -> Mapping[str, Any]:
        try:
            request_body = json.dumps(
                body,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        except (ValueError, TypeError):
            # Do not let a serialization error echo an account payload.
            raise InitializationError("HTTP request JSON encoding failed") from None

        try:
            request = urllib.request.Request(
                url,
                data=request_body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            detail = f"HTTP {exc.code} {exc.reason}".strip()
            raise InitializationError(f"HTTP transport failed: {detail}") from None
        except urllib.error.URLError as exc:
            reason = exc.reason
            detail = str(reason).strip() or reason.__class__.__name__
            raise InitializationError(f"HTTP transport failed: {detail}") from None
        except OSError as exc:
            detail = str(exc).strip() or exc.__class__.__name__
            raise InitializationError(f"HTTP transport failed: {detail}") from None

        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise InitializationError("camera returned invalid JSON") from None
        if not isinstance(decoded, Mapping):
            raise InitializationError("camera response must be a JSON object")
        return decoded


class DevInitAccountPayload(Mapping[str, str]):
    """Account plaintext held only until encryption; repr always redacts pwd."""

    __slots__ = ("_password",)
    _keys = ("name", "pwd", "CellPhone", "Mail")

    def __init__(self, password: str) -> None:
        if not isinstance(password, str):
            raise InitializationError("admin password must be text")
        self._password = password

    def __getitem__(self, key: str) -> str:
        if key == "name":
            return "admin"
        if key == "pwd":
            return self._password
        if key in {"CellPhone", "Mail"}:
            return ""
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return iter(self._keys)

    def __len__(self) -> int:
        return len(self._keys)

    def __repr__(self) -> str:
        return "DevInitAccountPayload(name='admin', pwd=<redacted>, CellPhone='', Mail='')"


@dataclass(frozen=True, repr=False)
class InitializationDiagnostics:
    """Three read-only method responses for a single uninitialized device."""

    ip: str
    status: Mapping[str, Any]
    dev_caps: Mapping[str, Any]
    encrypt_info: Mapping[str, Any]

    def __repr__(self) -> str:
        return (
            "InitializationDiagnostics("
            f"ip={self.ip!r}, methods={READ_METHODS!r}, "
            "responses=<omitted>)"
        )

    def report(self) -> dict[str, Any]:
        """Return a readable report with RSA key material shortened."""
        crypto_details = describe_security_encrypt_info(
            self.encrypt_info,
            self.dev_caps,
            status=self.status,
        )
        if isinstance(self.encrypt_info.get("diagnostic_error"), str):
            crypto: dict[str, Any] = {
                "supported": False,
                "reason": self.encrypt_info["diagnostic_error"],
                **crypto_details,
            }
        else:
            try:
                profile = parse_security_encrypt_info(
                    self.encrypt_info,
                    self.dev_caps,
                    status=self.status,
                )
            except CryptoProtocolError as exc:
                crypto = {
                    "supported": False,
                    "reason": str(exc),
                    **crypto_details,
                }
            else:
                crypto = {
                    "supported": True,
                    **crypto_details,
                    "encryption_scheme": f"RSA/PKCS#1 v1.5 + {profile.cipher_name}",
                    "device_cipher": profile.cipher,
                    "security_baseline_version": profile.security_baseline_version,
                    "rsa_modulus_bits": profile.rsa_modulus_bits,
                    "rsa_modulus_bytes": profile.rsa_modulus_bytes,
                    "rsa_exponent": profile.rsa_exponent,
                    "session_key_length_bytes": profile.session_key_bytes,
                    "rsa_encrypted_salt_length_bytes": profile.rsa_salt_bytes,
                    "advertised_ciphers": list(profile.advertised_ciphers),
                    "advertised_aes_padding": list(profile.advertised_padding),
                }
        return {
            "target_ip": self.ip,
            READ_METHODS[0]: _redact_key_material(self.status),
            READ_METHODS[1]: _redact_key_material(self.dev_caps),
            READ_METHODS[2]: _redact_key_material(self.encrypt_info),
            "crypto_profile": crypto,
            "supported_DevInit_capabilities": _supported_devinit_capabilities(self.dev_caps),
        }


def build_account_payload(password: str) -> DevInitAccountPayload:
    """Build the exact admin account object without exposing its password in repr."""
    return DevInitAccountPayload(password)


def build_account_request(
    password: str,
    profile: EncryptionProfile,
    *,
    request_id: int = 1,
    random_key: str | bytes | None = None,
    rsa_encryptor: Callable[..., bytes] | None = None,
) -> dict[str, Any]:
    """Build, but do not send, an encrypted and sessionless account request."""
    encrypted = encrypt_parameters(
        build_account_payload(password),
        profile,
        random_key=random_key,
        rsa_encryptor=rsa_encryptor,
    )
    return _sessionless_request("DevInit.account", encrypted.as_dict(), request_id)


def build_access_request(
    profile: EncryptionProfile,
    *,
    request_id: int = 1,
    random_key: str | bytes | None = None,
    rsa_encryptor: Callable[..., bytes] | None = None,
) -> dict[str, Any]:
    """Build the encrypted minimum access request, without sending it.

    Easy4ip (P2P/cloud registration) and automatic update checks are optional.
    Leaving both disabled maps to 0 for ``NetAccess`` and ``UpgradeCheck``.
    """
    encrypted = encrypt_parameters(
        dict(MINIMUM_ACCESS_PARAMS),
        profile,
        random_key=random_key,
        rsa_encryptor=rsa_encryptor,
    )
    return _sessionless_request("DevInit.access", encrypted.as_dict(), request_id)


class InitializationClient:
    """Read DevInit capabilities and explicitly dispatch initialization calls.

    The diagnostics path calls only the three methods in ``READ_METHODS``.
    Account/access writes require their separate explicit methods and use the
    sessionless DHIP UDP/37810 initialization path by default.
    """

    def __init__(
        self,
        ip: str = DEFAULT_INIT_IP,
        *,
        target_mac: str | None = None,
        transport: JsonTransport | None = None,
        timeout: float = DEFAULT_INIT_TIMEOUT,
        scheme: str = "http",
        port: int = 80,
    ) -> None:
        try:
            normalized_ip = str(ipaddress.IPv4Address(ip))
        except (ipaddress.AddressValueError, TypeError):
            raise InitializationError("target must be an IPv4 address") from None
        if scheme not in {"http", "https"}:
            raise InitializationError("HTTP scheme is unsupported")
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise InitializationError("HTTP port is invalid")
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise InitializationError("timeout must be greater than zero")
        self.ip = normalized_ip
        self.timeout = float(timeout)
        if transport is None:
            self.url = f"dhip://{normalized_ip}:{DHIP_INIT_PORT}"
            self.transport = DhipInitializationTransport(normalized_ip, target_mac)
        else:
            # Keep the injectable HTTP-shaped interface for existing callers
            # and tests. Production initialization uses the DHIP transport.
            self.url = f"{scheme}://{normalized_ip}:{port}{OUTSIDE_CMD_PATH}"
            self.transport = transport
        self._request_id = 0
        self._password_for_errors: str | None = None

    def inspect(self) -> InitializationDiagnostics:
        """Call only DevInit status, DevInit caps, and encryption info reads."""
        responses: list[Mapping[str, Any]] = []
        for method in READ_METHODS:
            try:
                responses.append(self._call(method, None))
            except InitializationError as exc:
                responses.append({"diagnostic_error": str(exc)})
        return InitializationDiagnostics(
            ip=self.ip,
            status=responses[0],
            dev_caps=responses[1],
            encrypt_info=responses[2],
        )

    def initialize_account(
        self,
        password: str,
        *,
        discovery_init_value: Any = _DISCOVERY_INIT_UNSET,
        random_key: str | bytes | None = None,
        rsa_encryptor: Callable[..., bytes] | None = None,
    ) -> Mapping[str, Any]:
        """Create the first admin account. Call only as an explicit write action."""
        status = self._call("DevInit.getStatus", None)
        _require_rpc_success(status, "DevInit.getStatus")
        # DHIP/DHDiscover's Init field is a bit field, while DevInit.getStatus
        # can return a separate status enum. Prefer the selected device's
        # authoritative discovery value when it was present; malformed or
        # unknown values remain unknown and therefore cannot authorize a write.
        if discovery_init_value is _DISCOVERY_INIT_UNSET:
            state = _initialization_state(status)
        else:
            state = _discovery_initialization_state(discovery_init_value)
        if state != "uninitialized":
            if state == "initialized":
                raise InitializationError("DevInit.account refused: camera is already initialized")
            raise InitializationError("DevInit.account refused: initialization state is unknown")

        # Query userManager.getCaps to enrich the crypto profile. Some models
        # do not answer or expose relevant fields, so an empty response or
        # query failure is non-fatal.
        try:
            dev_caps = self._call(USER_MANAGER_CAPS_METHOD, None)
            _require_rpc_success(dev_caps, USER_MANAGER_CAPS_METHOD)
        except InitializationError:
            dev_caps = {}

        encrypt_info = self._call("Security.getEncryptInfo", None)
        _require_rpc_success(encrypt_info, "Security.getEncryptInfo")
        try:
            profile = parse_security_encrypt_info(
                encrypt_info,
                dev_caps,
                status=status,
            )
        except CryptoProtocolError as exc:
            raise InitializationError(str(exc)) from None
        encrypted = encrypt_parameters(
            build_account_payload(password),
            profile,
            random_key=random_key,
            rsa_encryptor=rsa_encryptor,
        )
        self._password_for_errors = password
        try:
            return self._call("DevInit.account", encrypted.as_dict())
        finally:
            self._password_for_errors = None

    def get_status(self) -> Mapping[str, Any]:
        """Read current initialization status through sessionless DHIP."""
        return self._call("DevInit.getStatus", None)

    def configure_minimum_access(
        self,
        *,
        random_key: str | bytes | None = None,
        rsa_encryptor: Callable[..., bytes] | None = None,
    ) -> Mapping[str, Any]:
        """Disable optional features using DevInit encryption."""
        diagnostics = self.inspect()
        try:
            profile = parse_security_encrypt_info(
                diagnostics.encrypt_info,
                diagnostics.dev_caps,
                status=diagnostics.status,
            )
        except CryptoProtocolError as exc:
            raise InitializationError(str(exc)) from None
        self._request_id += 1
        return self._post(build_access_request(
            profile,
            request_id=self._request_id,
            random_key=random_key,
            rsa_encryptor=rsa_encryptor,
        ))

    def _call(self, method: str, params: Any) -> Mapping[str, Any]:
        self._request_id += 1
        return self._post(_sessionless_request(method, params, self._request_id))

    def _post(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        try:
            response = self.transport.post_json(self.url, request, timeout=self.timeout)
        except DhipInitializationTransportError as exc:
            method = request.get("method")
            allowed_methods = {*READ_METHODS, USER_MANAGER_CAPS_METHOD, "DevInit.account", "DevInit.access"}
            safe_method = method if method in allowed_methods else "camera"
            detail = str(exc)
            if self._password_for_errors:
                detail = detail.replace(self._password_for_errors, "<redacted>")
            raise InitializationError(f"{safe_method} failed: {detail}") from None
        except InitializationError as exc:
            # Preserve safe protocol failures from an injected transport while
            # redacting the active password if a transport included it.
            method = request.get("method")
            allowed_methods = {*READ_METHODS, USER_MANAGER_CAPS_METHOD, "DevInit.account", "DevInit.access"}
            safe_method = method if method in allowed_methods else "camera"
            detail = str(exc)
            if self._password_for_errors:
                detail = detail.replace(self._password_for_errors, "<redacted>")
            raise InitializationError(f"{safe_method} failed: {detail}") from None
        except Exception:
            # Transport implementations may mention request data in their own
            # exceptions. Suppress that context so credentials cannot escape.
            method = request.get("method")
            allowed_methods = {*READ_METHODS, USER_MANAGER_CAPS_METHOD, "DevInit.account", "DevInit.access"}
            safe_method = method if method in allowed_methods else "camera"
            raise InitializationError(f"{safe_method} request failed") from None
        if not isinstance(response, Mapping):
            raise InitializationError("camera response must be a JSON object")
        return response


def _sessionless_request(method: str, params: Any, request_id: int) -> dict[str, Any]:
    if not isinstance(request_id, int) or isinstance(request_id, bool) or request_id < 0:
        raise InitializationError("request id is invalid")
    return {"method": method, "params": params, "id": request_id}


def _require_rpc_success(response: Mapping[str, Any], method: str) -> None:
    if response.get("result") is True:
        return
    diagnostic_error = response.get("diagnostic_error")
    if isinstance(diagnostic_error, str) and diagnostic_error:
        prefix = f"{method} failed:"
        if diagnostic_error.startswith(prefix):
            raise InitializationError(diagnostic_error)
        raise InitializationError(f"{method} failed: {diagnostic_error}")
    error = response.get("error")
    if isinstance(error, Mapping):
        code = error.get("code")
        message = error.get("message") or error.get("description")
        if code is not None and message:
            detail = f"{code}: {message}"
        elif message:
            detail = str(message)
        elif code is not None:
            detail = f"error code {code}"
        else:
            detail = "camera returned result=false"
    elif error not in (None, ""):
        detail = str(error)
    else:
        detail = "camera returned result=false"
    raise InitializationError(f"{method} failed: {detail}")


def _initialization_state(response: Mapping[str, Any]) -> str:
    params = response.get("params")
    if not isinstance(params, Mapping):
        return "unknown"
    status = params.get("status")
    if isinstance(status, str):
        normalized = status.strip().casefold()
        if normalized in {"initialized", "uninitialized"}:
            return normalized
    init_value = params.get("Init")
    if isinstance(init_value, int) and not isinstance(init_value, bool):
        if init_value == 0:
            return "initialized"
        if init_value == 1:
            return "uninitialized"
    if isinstance(init_value, str):
        if init_value.strip() == "0":
            return "initialized"
        if init_value.strip() == "1":
            return "uninitialized"
    return "unknown"


def _discovery_initialization_state(init_value: Any) -> str:
    """Interpret DHIP/DHDiscover Init bit fields conservatively."""
    if not isinstance(init_value, int) or isinstance(init_value, bool):
        return "unknown"
    return {
        1: "uninitialized",
        2: "initialized",
    }.get(init_value & 0x03, "unknown")


def _redact_key_material(value: Any) -> Any:
    if isinstance(value, Mapping):
        safe: dict[str, Any] = {}
        for key, item in value.items():
            normalized = "".join(ch for ch in str(key).casefold() if ch.isalnum())
            if normalized in {"pub", "publickey", "rsapublickey"}:
                safe[str(key)] = _shorten_public_key_value(item)
            else:
                safe[str(key)] = _redact_key_material(item)
        return safe
    if isinstance(value, list):
        return [_redact_key_material(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_key_material(item) for item in value]
    return value


def _shorten_public_key_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        safe = dict(value)
        for name, modulus in tuple(safe.items()):
            normalized = "".join(ch for ch in str(name).casefold() if ch.isalnum())
            if normalized in {"n", "modulus"}:
                safe[name] = _shorten(str(modulus)) if isinstance(modulus, (str, int)) else "<redacted>"
        return safe
    if not isinstance(value, str):
        return _redact_key_material(value)
    return _shorten_public_key(value)


def _shorten_public_key(value: str) -> str:
    if len(value) <= 96:
        return value
    if value.casefold().startswith("n:") and ",e:" in value.casefold():
        modulus, exponent = value.split(",", 1)
        _, modulus_value = modulus.split(":", 1)
        _, exponent_value = exponent.split(":", 1)
        return f"N:{_shorten(modulus_value)},E:{exponent_value}"
    return _shorten(value)


def _shorten(value: str) -> str:
    if len(value) <= 48:
        return value
    return f"{value[:20]}…{value[-12:]}"


def _supported_devinit_capabilities(value: Mapping[str, Any]) -> Any:
    """Extract explicit DevInit method/support flags when the device exposes them."""
    selected: dict[str, Any] = {}

    def visit(node: Any, depth: int = 0) -> None:
        if depth > 12:
            return
        if isinstance(node, Mapping):
            for key, item in node.items():
                name = str(key)
                normalized = "".join(ch for ch in name.casefold() if ch.isalnum())
                if normalized in {
                    "account", "access", "getstatus", "getdevcaps", "supportdevinit",
                    "supportaccount", "supportaccess", "supportgetstatus", "supportgetdevcaps",
                }:
                    selected[name] = _redact_key_material(item)
                elif normalized in {"method", "methods", "supportedmethods", "supportedmethod"}:
                    methods = item if isinstance(item, (list, tuple)) else [item]
                    matching = [method for method in methods if isinstance(method, str) and method.startswith("DevInit.")]
                    if matching:
                        selected[name] = matching
                if isinstance(item, (Mapping, list, tuple)):
                    visit(item, depth + 1)
        elif isinstance(node, (list, tuple)):
            for item in node:
                visit(item, depth + 1)

    visit(value)
    return selected or "not separately exposed; see DevInit.getDevCaps"
