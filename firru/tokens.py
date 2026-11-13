"""
firru.tokens — Token normalization and IP utilities.
"""

import ipaddress
import re
import socket


def normalize_token(name: str) -> str:
    """
    Convert a hostname/FQDN or IP to a lowercase aerleon token.
    Dots become underscores; hyphens are preserved (aerleon allows [-_a-zA-Z0-9]).
    IPs become v4_1_2_3_4_32 / v6_... style tokens.
    """
    if not name:
        raise ValueError(f"normalize_token called with empty name: {name!r}")
    if is_ip_land(name):
        net = ipaddress.ip_network(name, strict=False)
        name = f"v{net.version}_{net}"
    return re.sub(r'[^A-Za-z0-9_-]', '_', name.strip()).lower()


def is_ip_land(addr_str: str) -> bool:
    """Return True if addr_str is a valid IPv4/v6 address or CIDR."""
    try:
        ipaddress.ip_network(addr_str, strict=False)
        return True
    except ValueError:
        return False


# Build reverse mapping of IPPROTO_* constants once at import time
_PROTO_MAP = {
    v: k[8:].lower()
    for k, v in socket.__dict__.items()
    if k.startswith("IPPROTO_")
}


def proto_name(number: int) -> str:
    """Return protocol name ('tcp', 'udp', 'icmp') or 'other(<num>)' for unknown."""
    return _PROTO_MAP.get(number, f"other({number})")


_MAPPED = ipaddress.ip_network("::ffff:0:0/96")


def is_loopback(addr):
    """Loopback, for an address or a network, string or object, IPv4-mapped
    IPv6 included: `::ffff:127.0.0.1` is the IPv4 loopback reached through a
    dual-stack socket. Python counts it as loopback only from 3.13 on, so on
    3.11 and 3.12 such a listener would read as reachable."""
    try:
        net = ipaddress.ip_network(addr, strict=False)
    except (TypeError, ValueError):
        return False
    if net.version == 6 and net.prefixlen >= 96 and net.subnet_of(_MAPPED):
        net = ipaddress.ip_network((int(net.network_address) & 0xFFFFFFFF,
                                    net.prefixlen - 96))
    return net.is_loopback
