"""Optional subnet-wide discovery and vendor fallback diagnostics."""

from __future__ import annotations

import errno
import http.client
import ipaddress
import json
import math
import re
import selectors
import socket
import ssl
import struct
import subprocess
import sys
import time
import uuid
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, TextIO
from urllib.parse import unquote, urlsplit
from xml.etree import ElementTree

from .discovery import (
    DISCOVER_BROADCAST,
    DISCOVER_GROUP,
    DISCOVER_METHOD,
    DISCOVER_PARAMS,
    DISCOVER_PORT,
    DiscoveredDevice,
    _device_from_datagram,
    _identity_source_priority,
    _udp_socket,
)
from .diagnostic_discovery import direct_probe
from .ip_ranges import (
    _PRIVATE_IPV4_NETWORKS,
    validate_ipv4_range,
)
from .protocol import encode_frame, has_valid_dhip_framing

DEFAULT_DEEP_SCAN_TIMEOUT = 2.5
DEFAULT_DEEP_SCAN_WORKERS = 4
DEFAULT_DEEP_FALLBACK_TIMEOUT = 0.8
DEFAULT_ONVIF_TIMEOUT = 1.0
DEFAULT_SERVICE_SCREEN_TIMEOUT = 0.25
MAX_DEEP_SCAN_BATCH_SIZE = 256
MAX_SERVICE_SCREEN_CONNECTIONS = 128
MAX_FALLBACK_WORKERS = 128
MAX_ONVIF_WORKERS = 128
MAX_DEEP_SCAN_WORKERS = 128


@dataclass(frozen=True)
class DeepScanTimings:
    network: str
    dhip_seconds: float
    screening_seconds: float
    fallback_seconds: float
    onvif_seconds: float
    total_seconds: float
    dhip_endpoints: int
    fallback_endpoints: int
    total_endpoints: int


def active_ipv4_networks() -> list[ipaddress.IPv4Network]:
    """Return IPv4 subnets from active non-loopback interfaces and routes."""
    networks: list[ipaddress.IPv4Network] = []
    try:
        result = subprocess.run(
            ["ip", "-j", "-4", "addr", "show", "up"],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
        if result.returncode == 0:
            interfaces = json.loads(result.stdout)
            for interface in interfaces:
                flags = interface.get("flags", [])
                if "UP" not in flags or "LOOPBACK" in flags:
                    continue
                for address in interface.get("addr_info", []):
                    if address.get("family") != "inet":
                        continue
                    local = ipaddress.IPv4Address(address["local"])
                    if local.is_loopback or local.is_multicast or local.is_unspecified:
                        continue
                    network = ipaddress.ip_network(
                        f"{local}/{address['prefixlen']}", strict=False
                    )
                    if network not in networks:
                        networks.append(network)
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError):
        pass

    # /proc/net/route is a standard Linux fallback and also includes directly
    # connected subnets where the `ip` utility is unavailable.
    try:
        with open("/proc/net/route", encoding="ascii") as routes:
            next(routes, None)
            for line in routes:
                fields = line.split()
                if len(fields) < 8:
                    continue
                destination = int(fields[1], 16)
                flags = int(fields[3], 16)
                mask = int(fields[7], 16)
                if not (flags & 0x1) or flags & 0x2 or mask == 0:
                    continue
                network_address = socket.inet_ntoa(struct.pack("=I", destination))
                netmask = socket.inet_ntoa(struct.pack("=I", mask))
                network = ipaddress.ip_network(
                    f"{network_address}/{netmask}", strict=False
                )
                if network.is_loopback or network.is_multicast or network.is_unspecified:
                    continue
                if network not in networks:
                    networks.append(network)
    except (OSError, ValueError):
        pass
    return networks


def deep_discover(
    range_override: str | ipaddress.IPv4Network | None = None,
    *,
    timeout: float = DEFAULT_DEEP_SCAN_TIMEOUT,
    workers: int = DEFAULT_DEEP_SCAN_WORKERS,
    progress: Callable[[str], None] | None = None,
    debug: bool = False,
    debug_stream: TextIO | None = None,
) -> list[DiscoveredDevice]:
    """Probe bounded batches, then screen and enrich only DHIP-silent hosts."""
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("deep scan timeout must be a finite value greater than zero")
    if (
        not isinstance(workers, int)
        or isinstance(workers, bool)
        or not 1 <= workers <= MAX_DEEP_SCAN_WORKERS
    ):
        raise ValueError(f"deep scan workers must be between 1 and {MAX_DEEP_SCAN_WORKERS}")

    if range_override is None:
        networks = [validate_ipv4_range(network) for network in active_ipv4_networks()]
    else:
        networks = [validate_ipv4_range(range_override)]
    if not networks:
        raise OSError("no active IPv4 subnets found; provide --range CIDR")
    networks = sorted(
        set(networks),
        key=lambda network: (int(network.network_address), network.prefixlen),
    )

    output = debug_stream or sys.stderr
    probe = encode_frame({"method": DISCOVER_METHOD, "params": dict(DISCOVER_PARAMS)})
    devices: list[DiscoveredDevice] = []
    seen_hosts: set[str] = set()
    # Retain the workers argument for existing callers; socket readiness and
    # fallback pools now provide the bounded concurrency.
    _ = workers

    for network in networks:
        network_started = time.monotonic()
        if progress is not None:
            progress(f"Deep scanning {network}...")
        hosts = [str(host) for host in network.hosts() if str(host) not in seen_hosts]
        seen_hosts.update(hosts)
        if not hosts:
            continue

        results_by_host: dict[str, DiscoveredDevice] = {}
        dhip_started = time.monotonic()
        batches = [
            hosts[index:index + MAX_DEEP_SCAN_BATCH_SIZE]
            for index in range(0, len(hosts), MAX_DEEP_SCAN_BATCH_SIZE)
        ]
        for batch in batches:
            results_by_host.update(
                _probe_dhip_batch(batch, probe, timeout=timeout, debug=debug, output=output)
            )
        if progress is not None:
            progress(f"{len(hosts)}/{len(hosts)}")
        dhip_seconds = time.monotonic() - dhip_started
        silent_hosts = [host for host in hosts if host not in results_by_host]

        screening_started = time.monotonic()
        try:
            screened = _screen_service_hosts(
                silent_hosts,
                timeout=DEFAULT_SERVICE_SCREEN_TIMEOUT,
            )
        except (OSError, ValueError) as exc:
            screened = {}
            if debug:
                print(f"Service screening failed: {exc}", file=output)
        screening_seconds = time.monotonic() - screening_started
        http_candidates = [host for host in silent_hosts if 80 in screened.get(host, set())]
        fallback_started = time.monotonic()
        fallback_devices: list[DiscoveredDevice] = []
        if http_candidates:
            with ThreadPoolExecutor(
                max_workers=min(MAX_FALLBACK_WORKERS, len(http_candidates)),
                thread_name_prefix="dahua-fallback",
            ) as executor:
                futures = {
                    executor.submit(probe_fallback, host): host
                    for host in http_candidates
                }
                for future, host in futures.items():
                    try:
                        fallback = future.result()
                    except OSError:
                        fallback = None
                    if fallback is not None:
                        results_by_host[host] = fallback
                        fallback_devices.append(fallback)
        fallback_seconds = time.monotonic() - fallback_started

        onvif_started = time.monotonic()
        if fallback_devices:
            try:
                enriched = enrich_onvif_devices(
                    fallback_devices,
                    timeout=DEFAULT_ONVIF_TIMEOUT,
                )
            except Exception as exc:
                enriched = []
                if debug:
                    print(f"ONVIF enrichment failed: {exc}", file=output)
            for device in enriched:
                results_by_host[str(device.ipv4)] = device
        onvif_seconds = time.monotonic() - onvif_started

        network_devices = [results_by_host[host] for host in hosts if host in results_by_host]
        devices.extend(network_devices)
        total_seconds = time.monotonic() - network_started
        if debug:
            _print_deep_scan_timings(
                DeepScanTimings(
                    network=str(network),
                    dhip_seconds=dhip_seconds,
                    screening_seconds=screening_seconds,
                    fallback_seconds=fallback_seconds,
                    onvif_seconds=onvif_seconds,
                    total_seconds=total_seconds,
                    dhip_endpoints=len(network_devices) - len(fallback_devices),
                    fallback_endpoints=len(fallback_devices),
                    total_endpoints=len(network_devices),
                ),
                output=output,
            )

    return devices


def _probe_dhip_batch(
    hosts: list[str],
    probe: bytes,
    *,
    timeout: float,
    debug: bool = False,
    output: TextIO | None = None,
) -> dict[str, DiscoveredDevice]:
    """Send one unicast per target and collect all replies to one deadline."""
    found: dict[str, DiscoveredDevice] = {}
    sockets: dict[str, socket.socket] = {}
    selector = selectors.DefaultSelector()
    stream = output or sys.stderr
    try:
        if debug:
            print(f"DHIP batch: {len(hosts)} direct unicast probes", file=stream)
        for host in hosts:
            sock: socket.socket | None = None
            try:
                sock = _udp_socket()
                sock.connect((host, DISCOVER_PORT))
                sock.setblocking(False)
                selector.register(sock, selectors.EVENT_READ, host)
                sockets[host] = sock
            except OSError as exc:
                if sock is not None:
                    try:
                        selector.unregister(sock)
                    except (KeyError, ValueError):
                        pass
                    sock.close()
                if debug:
                    print(f"TX {host}: socket error {exc}", file=stream)

        for host, sock in tuple(sockets.items()):
            try:
                sock.send(probe)
            except OSError as exc:
                _close_selector_socket(selector, sockets, host, sock)
                if debug:
                    print(f"TX {host}: send error {exc}", file=stream)

        deadline = time.monotonic() + timeout
        while sockets:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            ready = selector.select(remaining)
            if not ready:
                break
            for key, _events in ready:
                sock = key.fileobj
                host = key.data
                while True:
                    if time.monotonic() >= deadline:
                        break
                    try:
                        datagram, sender = sock.recvfrom(65_535)
                    except BlockingIOError:
                        break
                    except OSError:
                        _close_selector_socket(selector, sockets, host, sock)
                        break
                    if sender[0] != host:
                        if debug:
                            print(f"RX {host}: ignored sender {sender[0]}", file=stream)
                        continue
                    if not has_valid_dhip_framing(datagram):
                        if debug:
                            print(f"RX {host}: ignored invalid DHIP frame", file=stream)
                        continue
                    device = _device_from_datagram(datagram, sender[0], source="deep")
                    if device is None:
                        continue
                    found[host] = device
                    _close_selector_socket(selector, sockets, host, sock)
                    break
        return found
    finally:
        selector.close()
        for sock in sockets.values():
            sock.close()


def _close_selector_socket(
    selector: selectors.BaseSelector,
    sockets: dict[str, socket.socket],
    host: str,
    sock: socket.socket,
) -> None:
    try:
        selector.unregister(sock)
    except (KeyError, ValueError):
        pass
    sockets.pop(host, None)
    sock.close()


def _screen_service_hosts(
    hosts: list[str],
    *,
    timeout: float,
) -> dict[str, set[int]]:
    """Screen both relevant TCP ports with at most 128 concurrent connects."""
    open_ports: dict[str, set[int]] = {host: set() for host in hosts}
    host_batch_size = MAX_SERVICE_SCREEN_CONNECTIONS // 2
    pending_connect = {
        errno.EINPROGRESS,
        errno.EWOULDBLOCK,
        errno.EALREADY,
        errno.EINTR,
    }
    immediate_success = {0, errno.EISCONN}

    for index in range(0, len(hosts), host_batch_size):
        batch = hosts[index:index + host_batch_size]
        selector = selectors.DefaultSelector()
        active: dict[socket.socket, tuple[str, int]] = {}
        try:
            for host in batch:
                for port in (37777, 80):
                    sock: socket.socket | None = None
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.setblocking(False)
                        result = sock.connect_ex((host, port))
                        if result in immediate_success:
                            open_ports[host].add(port)
                            sock.close()
                        elif result in pending_connect:
                            selector.register(sock, selectors.EVENT_WRITE)
                            active[sock] = (host, port)
                        else:
                            sock.close()
                    except OSError:
                        if sock is not None:
                            sock.close()

            deadline = time.monotonic() + timeout
            while active:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                ready = selector.select(remaining)
                if not ready:
                    break
                for key, _events in ready:
                    sock = key.fileobj
                    host, port = active.pop(sock)
                    try:
                        if sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0:
                            open_ports[host].add(port)
                        selector.unregister(sock)
                    except OSError:
                        pass
                    finally:
                        sock.close()
        finally:
            selector.close()
            for sock in active:
                sock.close()
    return open_ports


def _print_deep_scan_timings(
    timings: DeepScanTimings,
    *,
    output: TextIO,
) -> None:
    print(f"Deep scan {timings.network}", file=output)
    print(f"DHIP probe/collect:       {timings.dhip_seconds:.2f} s", file=output)
    print(f"service screening:        {timings.screening_seconds:.2f} s", file=output)
    print(f"RPC2/CGI fallback:        {timings.fallback_seconds:.2f} s", file=output)
    print(f"ONVIF enrichment:         {timings.onvif_seconds:.2f} s", file=output)
    print(f"total:                    {timings.total_seconds:.2f} s", file=output)
    print(f"DHIP:       {timings.dhip_endpoints} endpoints", file=output)
    print(f"fallback:   {timings.fallback_endpoints} endpoints", file=output)
    print(f"total:      {timings.total_endpoints} endpoints", file=output)


def probe_host(
    host: str | ipaddress.IPv4Address,
    timeout: float = DEFAULT_DEEP_SCAN_TIMEOUT,
    port: int = DISCOVER_PORT,
    *,
    probe: bytes | None = None,
) -> DiscoveredDevice | None:
    """Discover one host using authoritative DHIP, then vendor-specific hints."""
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("probe timeout must be a finite value greater than zero")
    if (
        not isinstance(port, int)
        or isinstance(port, bool)
        or not 1 <= port <= 65535
    ):
        raise ValueError("probe port must be between 1 and 65535")
    try:
        host_ip = ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError as exc:
        raise ValueError(f"invalid probe IPv4 address: {host}") from exc

    probe = probe or encode_frame(
        {"method": DISCOVER_METHOD, "params": dict(DISCOVER_PARAMS)}
    )
    records = direct_probe(
        host_ip,
        timeout=timeout,
        port=port,
        probe=probe,
        stop_after_accept=True,
    )
    device = next((record.device for record in records if record.accepted), None)
    if device is not None:
        return device
    return probe_fallback(host_ip)


def probe_fallback(
    host: str | ipaddress.IPv4Address,
    *,
    timeout: float = DEFAULT_DEEP_FALLBACK_TIMEOUT,
) -> DiscoveredDevice | None:
    """Identify a DHIP-silent Dahua endpoint using unauthenticated signatures.

    RPC2_Login's empty-password challenge is the primary signal. The read-only
    CGI Digest challenge is retained as corroborating evidence and as a
    secondary signature for devices where the RPC2 challenge is unavailable.
    An open service TCP port is deliberately not treated as vendor identity.
    """
    host_ip = str(ipaddress.IPv4Address(host))
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("fallback timeout must be a finite value greater than zero")

    if _probe_rpc2_login_challenge(host_ip, timeout=timeout):
        return _fallback_device(host_ip, "rpc2-login-challenge")
    if _probe_dahua_cgi_signature(host_ip, timeout=timeout):
        return _fallback_device(host_ip, "http-digest-realm")
    return None


def _probe_rpc2_login_challenge(host_ip: str, *, timeout: float) -> bool:
    """Request only the RPC2 first-step challenge; never send a credential proof."""
    request = http.client.HTTPConnection(host_ip, 80, timeout=timeout)
    payload = json.dumps(
        {
            "method": "global.login",
            "params": {"userName": "admin", "password": "", "clientType": "Web3.0"},
            "id": 1,
        },
        separators=(",", ":"),
    )
    try:
        request.request(
            "POST",
            "/RPC2_Login",
            body=payload,
            headers={"Content-Type": "application/json", "Connection": "close"},
        )
        response = request.getresponse()
        body = response.read(16_384)
        return response.status == 200 and _is_dahua_rpc2_challenge(body)
    except (OSError, http.client.HTTPException):
        return False
    finally:
        request.close()


def _is_dahua_rpc2_challenge(body: bytes) -> bool:
    try:
        message = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(message, dict):
        return False
    params = message.get("params")
    error = message.get("error")
    if not isinstance(params, dict):
        params = {}
    if not isinstance(error, dict):
        error = {}
    return bool(
        message.get("result") is False
        and params.get("realm")
        and params.get("random")
    ) or error.get("code") == 268632079


def _probe_dahua_cgi_signature(host_ip: str, *, timeout: float) -> bool:
    request = http.client.HTTPConnection(host_ip, 80, timeout=timeout)
    try:
        request.request(
            "GET",
            "/cgi-bin/magicBox.cgi?action=getSystemInfo",
            headers={"Connection": "close"},
        )
        response = request.getresponse()
        challenge = response.getheader("WWW-Authenticate", "")
        return response.status == 401 and _is_dahua_digest_challenge(challenge)
    except (OSError, http.client.HTTPException):
        return False
    finally:
        request.close()


def _is_dahua_digest_challenge(value: str) -> bool:
    return bool(
        re.match(r"\s*Digest\b", value, re.IGNORECASE)
        and re.search(
            r'realm="Login to Dahua device"',
            value,
            re.IGNORECASE,
        )
    )


def _fallback_device(
    host_ip: str,
    method: str,
    evidence: Iterable[str] = (),
) -> DiscoveredDevice:
    evidence_set = frozenset(evidence) or frozenset({method})
    info = {
        "IPv4Address": {"IPAddress": host_ip},
        "DiscoveryMethod": method,
        "DahuaEvidence": tuple(sorted(evidence_set)),
    }
    message = {"method": "deep.readOnlyFallback", "params": {"deviceInfo": info}}
    return DiscoveredDevice(
        info=info,
        message=message,
        source_ip=host_ip,
        discovery_sources=frozenset({"deep"}),
        dahua_verified=True,
        vendor_evidence=evidence_set,
    )


def enrich_onvif_devices(
    devices: Iterable[DiscoveredDevice],
    *,
    timeout: float = DEFAULT_ONVIF_TIMEOUT,
) -> list[DiscoveredDevice]:
    """Best-effort unauthenticated ONVIF identity enrichment for Dahua fallbacks."""
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("ONVIF timeout must be a finite value greater than zero")
    device_list = list(devices)
    candidates = [
        device for device in device_list
        if device.dahua_verified and not device.valid_dhip_identity
    ]
    if not candidates:
        return device_list

    target_ips = [str(device.ipv4) for device in candidates]
    try:
        matches = _ws_discover(target_ips, timeout=timeout)
    except OSError:
        matches = {}

    def enrich_one(device: DiscoveredDevice) -> DiscoveredDevice:
        host_ip = str(device.ipv4)
        match = matches.get(host_ip, {})
        xaddrs = match.get("xaddrs", ())
        scopes = match.get("scopes", ())
        info = dict(device.info)
        field_sources = dict(device.identity_sources)

        for scope in scopes:
            try:
                parsed = urlsplit(scope)
            except ValueError:
                continue
            if parsed.scheme.lower() != "onvif" or parsed.netloc.lower() != "www.onvif.org":
                continue
            components = [part for part in parsed.path.split("/") if part]
            if len(components) < 2:
                continue
            scope_name = components[0].casefold()
            value = unquote("/".join(components[1:])).strip()
            if scope_name in {"hardware", "model"}:
                _set_enriched_field(info, field_sources, "model", value, "onvif-wsd-scope")
            elif scope_name == "macaddress":
                _set_enriched_field(info, field_sources, "mac", value, "onvif-wsd-scope")

        endpoint = _onvif_device_endpoint(host_ip, xaddrs)
        if endpoint is not None:
            device_info = _onvif_get_device_information(endpoint, timeout=timeout)
            if device_info:
                _set_enriched_field(
                    info, field_sources, "model", device_info.get("Model"),
                    "onvif-get-device-information",
                )
                _set_enriched_field(
                    info, field_sources, "serial", device_info.get("SerialNumber"),
                    "onvif-get-device-information",
                )
                _set_enriched_field(
                    info, field_sources, "firmware", device_info.get("FirmwareVersion"),
                    "onvif-get-device-information",
                )

        return DiscoveredDevice(
            info=info,
            message=device.message,
            source_ip=device.source_ip,
            discovery_sources=device.discovery_sources,
            identity_sources=field_sources,
            valid_dhip_identity=device.valid_dhip_identity,
            dahua_verified=device.dahua_verified,
            vendor_evidence=device.vendor_evidence,
        )

    with ThreadPoolExecutor(
        max_workers=min(MAX_ONVIF_WORKERS, len(candidates)),
        thread_name_prefix="onvif-enrichment",
    ) as executor:
        return list(executor.map(enrich_one, candidates))


def _onvif_device_endpoint(
    host_ip: str,
    xaddrs: Iterable[str],
) -> tuple[str, str, int, str] | None:
    """Use a same-device XAddr when usable, otherwise the standard device path."""
    for value in xaddrs:
        try:
            parsed = urlsplit(value)
            address = ipaddress.ip_address(parsed.hostname or "")
            port = parsed.port
        except ValueError:
            continue
        if str(address) != host_ip or parsed.scheme.lower() not in {"http", "https"}:
            continue
        port = port or (443 if parsed.scheme.lower() == "https" else 80)
        path = parsed.path or "/onvif/device_service"
        if parsed.query:
            path += "?" + parsed.query
        return parsed.scheme.lower(), host_ip, port, path
    return "http", host_ip, 80, "/onvif/device_service"


def _onvif_get_device_information(
    endpoint: tuple[str, str, int, str],
    *,
    timeout: float,
) -> dict[str, str]:
    scheme, host_ip, port, path = endpoint
    request_type = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
    kwargs: dict[str, Any] = {"timeout": timeout}
    request = None
    envelope = (
        b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
        b'xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
        b'<s:Body><tds:GetDeviceInformation/></s:Body></s:Envelope>'
    )
    try:
        if scheme == "https":
            kwargs["context"] = ssl.create_default_context()
        request = request_type(host_ip, port, **kwargs)
        request.request(
            "POST",
            path,
            body=envelope,
            headers={
                "Content-Type": "application/soap+xml; charset=utf-8",
                "Accept": "application/soap+xml, text/xml",
                "Connection": "close",
            },
        )
        response = request.getresponse()
        body = response.read(65_536)
        if response.status != 200:
            return {}
    except (OSError, http.client.HTTPException, ValueError):
        return {}
    finally:
        if request is not None:
            try:
                request.close()
            except OSError:
                pass

    try:
        root = decode_xml(body)
    except ValueError:
        return {}
    fields = {"Manufacturer", "Model", "FirmwareVersion", "SerialNumber"}
    return {
        node.tag.rsplit("}", 1)[-1]: node.text.strip()
        for node in root.iter()
        if node.tag.rsplit("}", 1)[-1] in fields and node.text and node.text.strip()
    }


def decode_xml(body: bytes):
    """Parse a bounded ONVIF response without adding an XML dependency."""
    try:
        return ElementTree.fromstring(body)
    except ElementTree.ParseError as exc:
        raise ValueError("invalid ONVIF XML") from exc


def _ws_discover(
    target_ips: Iterable[str],
    *,
    timeout: float,
) -> dict[str, dict[str, set[str]]]:
    """Send one unauthenticated Probe per interface and share one receive window."""
    targets = set(target_ips)
    matches = {ip: {"xaddrs": set(), "scopes": set()} for ip in targets}
    by_source: dict[str, set[str]] = {}
    for ip in targets:
        route = None
        try:
            route = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            route.connect((ip, 3702))
            source_ip = route.getsockname()[0]
            if source_ip and source_ip != "0.0.0.0":
                by_source.setdefault(source_ip, set()).add(ip)
        except OSError:
            continue
        finally:
            if route is not None:
                route.close()

    if not by_source:
        return matches

    message_id = "urn:uuid:" + str(uuid.uuid4())
    probe = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
        'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
        f'<s:Header><a:MessageID>{message_id}</a:MessageID>'
        '<a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>'
        '<a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>'
        '</s:Header><s:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types>'
        '</d:Probe></s:Body></s:Envelope>'
    ).encode("utf-8")
    selector = selectors.DefaultSelector()
    sockets: dict[str, socket.socket] = {}
    try:
        for source_ip in by_source:
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
                sock.setsockopt(
                    socket.IPPROTO_IP,
                    socket.IP_MULTICAST_IF,
                    socket.inet_aton(source_ip),
                )
                sock.bind((source_ip, 0))
                sock.setblocking(False)
                selector.register(sock, selectors.EVENT_READ, source_ip)
                sockets[source_ip] = sock
                sock.sendto(probe, ("239.255.255.250", 3702))
            except OSError:
                if sock is not None:
                    try:
                        selector.unregister(sock)
                    except (KeyError, ValueError):
                        pass
                    sock.close()
                sockets.pop(source_ip, None)

        deadline = time.monotonic() + timeout
        while sockets:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            ready = selector.select(remaining)
            if not ready:
                break
            for key, _events in ready:
                sock = key.fileobj
                source_ip = key.data
                interface_targets = by_source[source_ip]
                while True:
                    if time.monotonic() >= deadline:
                        break
                    try:
                        response, sender = sock.recvfrom(65_535)
                    except BlockingIOError:
                        break
                    except OSError:
                        _close_selector_socket(selector, sockets, source_ip, sock)
                        break
                    source = sender[0]
                    if source not in interface_targets:
                        continue
                    try:
                        root = decode_xml(response)
                    except ValueError:
                        continue
                    for node in root.iter():
                        local_name = node.tag.rsplit("}", 1)[-1]
                        if local_name == "XAddrs" and node.text:
                            matches[source]["xaddrs"].update(node.text.split())
                        elif local_name == "Scopes" and node.text:
                            matches[source]["scopes"].update(node.text.split())
        return matches
    finally:
        selector.close()
        for sock in sockets.values():
            sock.close()


def _set_enriched_field(
    info: dict[str, Any],
    field_sources: dict[str, str],
    field_name: str,
    value: Any,
    source: str,
) -> None:
    if value is None:
        return
    text = str(value).strip()
    if not text:
        return
    current_source = field_sources.get(field_name)
    if current_source and _identity_source_priority(current_source) > _identity_source_priority(source):
        return
    key = {"model": "DeviceType", "serial": "SerialNo", "firmware": "Version", "mac": "Mac"}[field_name]
    info[key] = text
    field_sources[field_name] = source
