"""IPv4 range validation shared by deep-scan code and its CLI options."""

from __future__ import annotations

import ipaddress

MAX_DEEP_SCAN_HOSTS = 65_536
_PRIVATE_IPV4_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "127.0.0.0/8",
    )
)



def validate_ipv4_range(
    value: str | ipaddress.IPv4Network,
    *,
    max_hosts: int = MAX_DEEP_SCAN_HOSTS,
) -> ipaddress.IPv4Network:
    """Validate and canonicalize a bounded IPv4 CIDR before probing it.

    The host count is checked arithmetically before expanding ``network.hosts``
    so a mistyped broad prefix cannot create an unbounded scan or task queue.
    """
    if isinstance(value, str) and "/" not in value:
        raise ValueError("deep scan range must include an IPv4 prefix length")
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid IPv4 CIDR range: {value}") from exc
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("deep scan range must be IPv4")
    if not any(network.subnet_of(private) for private in _PRIVATE_IPV4_NETWORKS):
        raise ValueError("deep scan range must be private or link-local IPv4")
    if not isinstance(max_hosts, int) or isinstance(max_hosts, bool) or max_hosts <= 0:
        raise ValueError("maximum deep scan host count must be a positive integer")
    host_count = _usable_host_count(network)
    if host_count > max_hosts:
        raise ValueError(
            f"deep scan range contains {host_count} hosts; limit is {max_hosts}"
        )
    return network


def parse_ipv4_range(value: str | ipaddress.IPv4Network) -> ipaddress.IPv4Network:
    """Parse a safe IPv4 CIDR for the CLI, accepting and canonicalizing host bits."""
    return validate_ipv4_range(value)


def _usable_host_count(network: ipaddress.IPv4Network) -> int:
    if network.prefixlen >= 31:
        return network.num_addresses
    return max(0, network.num_addresses - 2)
