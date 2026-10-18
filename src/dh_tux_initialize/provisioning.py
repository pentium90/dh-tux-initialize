"""Apply the supported account and IPv4 network steps for a saved setup plan."""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Callable, Mapping, Sequence
from typing import TYPE_CHECKING, Any, Protocol

from .init_protocol import InitializationClient
from .network_transport import DhipNetworkTransport, build_dhcp_device_config

if TYPE_CHECKING:
    from .discovery import DiscoveredDevice
    from .setup import SetupPlan

DEFAULT_PROVISIONING_TIMEOUT = 5.0


class ProvisioningError(ValueError):
    """A safe, user-displayable error from a provisioning step."""


class DhipDhcpTransport(Protocol):
    """Injectable transport boundary for a DHIP DHCP request."""

    def set_dhcp(
        self,
        *,
        username: str,
        password: str,
        device_config: Mapping[str, Any],
        timeout: float,
    ) -> Mapping[str, Any]: ...


class DahuaNetworkClient:
    """Configure IPv4 through Dahua DHIP ``DHDiscover.setConfig``."""

    __slots__ = (
        "ip", "mac", "username", "_password", "device_info", "timeout", "transport"
    )

    def __init__(
        self,
        ip: str,
        mac: str,
        username: str,
        password: str,
        *,
        device_info: Mapping[str, Any] | None = None,
        transport: DhipDhcpTransport | None = None,
        timeout: float = DEFAULT_PROVISIONING_TIMEOUT,
    ) -> None:
        try:
            self.ip = str(ipaddress.IPv4Address(ip))
        except (ipaddress.AddressValueError, TypeError):
            raise ProvisioningError("camera address must be IPv4") from None
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ProvisioningError("timeout must be greater than zero")
        if not isinstance(mac, str) or not mac.strip():
            raise ProvisioningError("selected camera MAC is required for DHCP")
        self.mac = mac
        self.username = username
        self._password = password
        self.device_info = device_info if isinstance(device_info, Mapping) else {}
        self.timeout = float(timeout)
        self.transport = (
            transport
            if transport is not None
            else DhipNetworkTransport(self.ip, self.mac)
        )

    def __repr__(self) -> str:
        return (
            f"DahuaNetworkClient(ip={self.ip!r}, mac={self.mac!r}, "
            f"username={self.username!r}, "
            "password=<redacted>)"
        )

    def enable_dhcp(self) -> None:
        """Enable DHCP using the IPv4 section defined by DHIP."""
        self._set_network_config(build_dhcp_device_config(self.device_info, self.ip))

    def set_static_ipv4(self, ipv4: str, netmask: str, gateway: str) -> None:
        """Set a static IPv4 address through the same DHIP path."""
        address, mask, default_gateway = _validated_static_ipv4(
            ipv4, netmask, gateway
        )
        device_config = build_dhcp_device_config(self.device_info, address)
        ipv4_config = device_config["IPv4Address"]
        ipv4_config.update(
            {
                "IPAddress": address,
                "SubnetMask": mask,
                "DefaultGateway": default_gateway,
                "DhcpEnable": False,
            }
        )
        self._set_network_config(device_config)

    def _set_network_config(self, device_config: Mapping[str, Any]) -> None:
        try:
            response = self.transport.set_dhcp(
                username=self.username,
                password=self._password,
                device_config=device_config,
                timeout=self.timeout,
            )
        except Exception as exc:
            message = _redact(str(exc), self._password)
            raise ProvisioningError(message or "DHIP DHCP request failed") from None
        if not isinstance(response, Mapping):
            raise ProvisioningError("camera returned a non-object DHIP response")
        _require_network_rpc_success(response, self._password)


InitializationClientFactory = Callable[[str], InitializationClient]


def provision_device(
    plan: SetupPlan,
    device: DiscoveredDevice,
    *,
    initialization_client_factory: InitializationClientFactory | None = None,
    rediscover_fn: Callable[[], Sequence[DiscoveredDevice]] | None = None,
    network_transport: DhipDhcpTransport | None = None,
    timeout: float = DEFAULT_PROVISIONING_TIMEOUT,
) -> None:
    """Initialize admin, verify it over DHIP, then apply the saved IPv4 plan."""
    static_values = _validated_network_plan(plan)
    if not device.provisionable:
        raise ProvisioningError("selected camera is no longer uninitialized")
    if _mac_key(plan.mac) != _mac_key(str(device.mac)):
        raise ProvisioningError("setup plan does not match the selected camera MAC")
    try:
        ip = str(ipaddress.IPv4Address(str(device.ipv4)))
    except (ipaddress.AddressValueError, TypeError):
        raise ProvisioningError("selected camera has no valid IPv4 address") from None

    try:
        if initialization_client_factory is None:
            initialization_client = InitializationClient(ip, target_mac=str(device.mac))
        else:
            initialization_client = initialization_client_factory(ip)
        account_kwargs = {}
        if device.has_init_value:
            account_kwargs["discovery_init_value"] = device.init_value
        account_response = initialization_client.initialize_account(
            plan.password,
            **account_kwargs,
        )
    except Exception as exc:
        raise ProvisioningError(_redact(str(exc), plan.password)) from None
    _require_rpc_success(account_response, "DevInit.account", plan.password)

    _verify_account_initialization(
        device,
        rediscover_fn=rediscover_fn,
        password=plan.password,
    )

    network = DahuaNetworkClient(
        ip,
        str(device.mac),
        plan.username,
        plan.password,
        device_info=device.info,
        transport=network_transport,
        timeout=timeout,
    )
    try:
        if static_values is None:
            network.enable_dhcp()
        else:
            network.set_static_ipv4(*static_values)
    except Exception as exc:
        raise ProvisioningError(_redact(str(exc), plan.password)) from None


def validate_network_plan(plan: SetupPlan) -> None:
    """Validate a saved DHCP or static plan before Finish starts any writes."""
    _validated_network_plan(plan)


def _validated_network_plan(plan: SetupPlan) -> tuple[str, str, str] | None:
    if plan.network_mode == "dhcp":
        return None
    if plan.network_mode != "static":
        raise ProvisioningError("unsupported network configuration mode")
    return _validated_static_ipv4(plan.ipv4, plan.netmask, plan.gateway)


def _validated_static_ipv4(
    ipv4: str | None, netmask: str | None, gateway: str | None
) -> tuple[str, str, str]:
    if any(
        not isinstance(value, str) or not value.strip()
        for value in (ipv4, netmask, gateway)
    ):
        raise ProvisioningError("static network plan is incomplete")
    try:
        address = ipaddress.IPv4Address(ipv4.strip())
        mask_address = ipaddress.IPv4Address(netmask.strip())
        gateway_address = ipaddress.IPv4Address(gateway.strip())
        network = ipaddress.IPv4Network(f"{address}/{mask_address}", strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, TypeError):
        raise ProvisioningError("static network plan contains invalid IPv4 values") from None

    if address == gateway_address or gateway_address not in network:
        raise ProvisioningError("static IP and gateway must be different and on the same network")
    if network.prefixlen < 31 and (
        address in {network.network_address, network.broadcast_address}
        or gateway_address in {network.network_address, network.broadcast_address}
    ):
        raise ProvisioningError("static IP and gateway must be valid host addresses")
    return str(address), str(network.netmask), str(gateway_address)


def _require_rpc_success(
    response: Mapping[str, Any], method: str, password: str
) -> None:
    if response.get("result") is True:
        return
    error: Any = response.get("error")
    if isinstance(error, Mapping):
        code = error.get("code")
        message = error.get("message") or error.get("description")
        detail = f"{code}: {message}" if code is not None and message else message
        if detail is None:
            detail = f"error code {code}" if code is not None else "camera returned result=false"
    elif error not in (None, ""):
        detail = str(error)
    else:
        detail = response.get("message") or "camera returned result=false"
    raise ProvisioningError(f"{method} failed: {_redact(str(detail), password)}")


def _require_network_rpc_success(
    response: Mapping[str, Any], password: str
) -> None:
    """Report the complete safe DHIP response without exposing credentials."""
    if response.get("result") is True:
        return
    diagnostics = _safe_response_value(response, password)
    serialized = json.dumps(diagnostics, ensure_ascii=False, sort_keys=True)
    raise ProvisioningError(f"DHDiscover.setConfig failed: {serialized}")


def _safe_response_value(value: Any, password: str, key: str | None = None) -> Any:
    """Copy JSON response data while redacting credential-bearing fields/values."""
    if key is not None:
        normalized_key = re.sub(r"[^a-z0-9]", "", key.casefold())
        if normalized_key in {
            "password",
            "passwd",
            "pwd",
            "passphrase",
            "credential",
            "credentials",
        }:
            return "<redacted>"
    if isinstance(value, Mapping):
        return {
            _redact(str(response_key), password): _safe_response_value(
                response_value, password, str(response_key)
            )
            for response_key, response_value in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_safe_response_value(item, password) for item in value]
    if isinstance(value, str):
        return _redact(value, password)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    # Protocol responses are JSON, but keep unexpected transport objects safe
    # without invoking potentially sensitive repr()/str() implementations.
    return f"<{type(value).__name__}>"


def _verify_account_initialization(
    selected_device: DiscoveredDevice,
    *,
    rediscover_fn: Callable[[], Sequence[DiscoveredDevice]] | None,
    password: str,
) -> DiscoveredDevice:
    if rediscover_fn is None:
        from .discovery import discover

        rediscover_fn = discover
    try:
        devices = list(rediscover_fn())
    except Exception as exc:
        message = _redact(str(exc), password)
        raise ProvisioningError(
            f"DHIP rediscovery after DevInit.account failed: {message or 'discovery failed'}"
        ) from None

    selected_mac = _mac_key(str(selected_device.mac))
    rediscovered = next(
        (
            candidate
            for candidate in devices
            if candidate.valid_dhip_identity
            and candidate.mac is not None
            and _mac_key(str(candidate.mac)) == selected_mac
        ),
        None,
    )
    if rediscovered is None:
        raise ProvisioningError(
            f"DHIP rediscovery did not find camera MAC {selected_device.mac} after DevInit.account"
        )

    init_value = rediscovered.init_value
    if not isinstance(init_value, int) or isinstance(init_value, bool):
        raise ProvisioningError(
            "DHIP rediscovery verification failed: initialization state is unknown"
        )
    state_bits = init_value & 0x03
    if state_bits == 2:
        return rediscovered
    if state_bits == 1:
        raise ProvisioningError(
            "DHIP rediscovery verification failed: camera remains uninitialized"
        )
    raise ProvisioningError(
        "DHIP rediscovery verification failed: initialization state is unknown"
    )


def _mac_key(mac: str) -> str:
    return re.sub(r"[:-]", "", mac).casefold()


def _redact(value: str, password: str) -> str:
    if password:
        return value.replace(password, "<redacted>")
    return value
