#!/usr/local/bin/python3

# Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


"""Address classification owned by the plugin, not by the Python runtime.

Classes, as the map uses them:

* public (1): globally reachable unicast, the remote side of a map flow.
* private (2): not globally reachable, or shared address space (100.64.0.0/10, CGNAT and
  VPN overlays): the site's inside. Loopback is neither.
* 0: neither (loopback, multicast).

The special-purpose networks below are the IANA IPv4 and IPv6 Special-Purpose Address
Registries ("Globally Reachable: False" entries, with their globally reachable exceptions).
IPv4-mapped IPv6 addresses (::ffff:0:0/96) are classified as the IPv4 address they carry.
The state collector receives the same table as R rows (lib/collector.py), so both sides always
agree, whatever ipaddress module the firewall's Python ships.
"""

import bisect
import functools
import ipaddress

PUBLIC = 1
PRIVATE = 2

# IANA "Globally Reachable: False", most general first; exceptions below override them.
NOT_GLOBAL_4 = (
    "0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
    "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "240.0.0.0/4", "255.255.255.255/32",
)
GLOBAL_EXCEPTIONS_4 = ("192.0.0.9/32", "192.0.0.10/32")
SHARED_4 = "100.64.0.0/10"
LOOPBACK_4 = "127.0.0.0/8"
MULTICAST_4 = "224.0.0.0/4"
# 192.0.0.170/31 (NAT64 discovery) is inside 192.0.0.0/24 and not an exception: not global.

NOT_GLOBAL_6 = (
    "::1/128", "::/128", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "2002::/16",
    "3fff::/20", "fc00::/7", "fe80::/10",
)
GLOBAL_EXCEPTIONS_6 = ("2001:1::1/128", "2001:1::2/128", "2001:3::/32", "2001:4:112::/48", "2001:20::/28",
                       "2001:30::/28")
LOOPBACK_6 = "::1/128"
MULTICAST_6 = "ff00::/8"
MAPPED_6 = ipaddress.IPv6Network("::ffff:0:0/96")


def _classify4(value):
    address = ipaddress.IPv4Address(value)

    def within(networks):
        return any(address in ipaddress.IPv4Network(network) for network in networks)

    if within((LOOPBACK_4, MULTICAST_4)):
        return 0
    if within((SHARED_4,)):
        return PRIVATE
    if within(NOT_GLOBAL_4) and not within(GLOBAL_EXCEPTIONS_4):
        return PRIVATE
    return PUBLIC


def _classify6(value):
    address = ipaddress.IPv6Address(value)
    if address in MAPPED_6:
        return _classify4(int(address) & 0xFFFFFFFF)

    def within(networks):
        return any(address in ipaddress.IPv6Network(network) for network in networks)

    if within((LOOPBACK_6, MULTICAST_6)):
        return 0
    if within(NOT_GLOBAL_6) and not within(GLOBAL_EXCEPTIONS_6):
        return PRIVATE
    return PUBLIC


def _ranges(version):
    """Sorted, disjoint (low, high, flags) integer ranges covering the whole address space."""
    if version == 4:
        networks = (*NOT_GLOBAL_4, *GLOBAL_EXCEPTIONS_4, SHARED_4, LOOPBACK_4, MULTICAST_4)
        size, classify = 32, _classify4
        bounds = {0, 1 << 32}
    else:
        networks = (*NOT_GLOBAL_6, *GLOBAL_EXCEPTIONS_6, LOOPBACK_6, MULTICAST_6, str(MAPPED_6))
        size, classify = 128, _classify6
        bounds = {0, 1 << 128}
        mapped = int(MAPPED_6.network_address)
        bounds.update(mapped + low for low, _, _ in _ranges(4))
        bounds.update(mapped + high + 1 for _, high, _ in _ranges(4))
    for text in networks:
        network = ipaddress.ip_network(text)
        bounds.update((int(network.network_address), int(network.broadcast_address) + 1))
    ordered = sorted(bounds)
    ranges = []
    for low, stop in zip(ordered, ordered[1:]):
        flags = classify(low)
        if ranges and ranges[-1][2] == flags and ranges[-1][1] + 1 == low:
            ranges[-1] = (ranges[-1][0], stop - 1, flags)
        else:
            ranges.append((low, stop - 1, flags))
    assert ranges[-1][1] == (1 << size) - 1
    return ranges


RANGES = {4: _ranges(4), 6: _ranges(6)}
_STARTS = {version: [low for low, _, _ in ranges] for version, ranges in RANGES.items()}


@functools.lru_cache(maxsize=65536)
def address_flags(value):
    """PUBLIC, PRIVATE or 0 for an address (text or ipaddress object); 0 for anything else."""
    try:
        address = ipaddress.ip_address(value)
    except (TypeError, ValueError):
        return 0
    ranges = RANGES[address.version]
    return ranges[bisect.bisect_right(_STARTS[address.version], int(address)) - 1][2]


def rows():
    """The helper's R rows: every range with its flags, in address order."""
    result = []
    for version, cls in ((4, ipaddress.IPv4Address), (6, ipaddress.IPv6Address)):
        result.extend(f"R {cls(low)} {cls(high)} {flags}" for low, high, flags in RANGES[version])
    return result
