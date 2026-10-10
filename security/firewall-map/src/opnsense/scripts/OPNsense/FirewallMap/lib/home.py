#!/usr/local/bin/python3

# Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
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

"""Where the firewall stands on the map: one home, or a second one only for IPv6 that is
genuinely elsewhere.

A firewall is in one place. IPv4 is the baseline: GeoIP has located IPv4 for decades and a
public WAN address (or the address found by external IP discovery behind an upstream NAT) is a
reliable signal; coordinates set in the settings override everything. IPv6 is different: the
firewall's WAN address usually comes from the provider's infrastructure pool, which GeoIP often
knows only by country, while the prefix delegated to the inside networks is the site itself.
IPv6 therefore joins the IPv4 home when any precise IPv6 location agrees with it, and gets its
own home only when it is precise and somewhere else (or always joins, by setting).

Tunnel and VPN interfaces never count: their addresses are located where the tunnel ends. A
vague location (no city, or a radius of 500 km or more: a database's "somewhere in this
country") is no evidence either way.
"""

import math
import re

from .common import public_ip

# interfaces whose addresses are located elsewhere (the far end of a tunnel or VPN)
TUNNEL = re.compile(r"^(wg|ovpn[cs]?|openvpn|tun|tap|gif|gre|ipsec|enc|vti|zt|tailscale|lo)\d*$")
# a location this coarse (or without a city) says only "somewhere in this country"
VAGUE_KM = 500
# two locations agree within this distance, or within their two radii together when larger
AGREE_KM = 50
SOURCES = ("coordinates", "ipv4_wan", "external_ip", "ipv4", "ipv6_inside", "ipv6_wan", "approximate")


def distance_km(a, b):
    """Great-circle distance between two {"lat", "lon"} places."""
    lat1, lat2 = math.radians(a["lat"]), math.radians(b["lat"])
    dlat, dlon = lat2 - lat1, math.radians(b["lon"] - a["lon"])
    h = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return 2 * 6371.0 * math.asin(min(1.0, math.sqrt(h)))


def precise(location):
    """A location that names a city within VAGUE_KM."""
    accuracy = (location or {}).get("accuracy_km")
    return bool(location and location.get("city") and (accuracy is None or accuracy < VAGUE_KM))


def agree(a, b):
    """Whether two locations describe the same place, given their accuracy."""
    return distance_km(a, b) <= max(AGREE_KM, (a.get("accuracy_km") or 0) + (b.get("accuracy_km") or 0))


def tunnel(device):
    return bool(device and TUNNEL.match(device))


def _home(location, source, evidence, name=None):
    place = ", ".join(part for part in (location.get("city") or location.get("region"),
                                        location.get("country_name") or location.get("country")) if part)
    return {"lat": location["lat"], "lon": location["lon"], "name": name or place or "Firewall",
            "city": location.get("city"), "region": location.get("region"),
            "country": location.get("country_name") or location.get("country"),
            "country_code": location.get("country"), "accuracy_km": location.get("accuracy_km"),
            "source": source, "evidence": evidence}


class HomePlan:
    """The homes and which of them each of the firewall's addresses starts from."""

    def __init__(self, homes=(), assigned=None, ipv4=None, ipv6=None):
        self.homes = list(homes)
        self.assigned = dict(assigned or {})
        self.ipv4, self.ipv6 = ipv4, ipv6

    def home(self, address):
        """The home an address of this firewall (or its private WAN address) is drawn at."""
        if address in self.assigned:
            return self.assigned[address]
        return self.ipv6 if ":" in str(address) else self.ipv4

    def location(self, address):
        """The map location of one of the firewall's addresses: its home, under its own id."""
        home = self.home(address)
        if home is None:
            return None
        entry = {key: home[key] for key in ("name", "lat", "lon", "city", "region", "country", "country_code",
                                             "accuracy_km")}
        return dict(entry, id=address, local=True, home=home["source"])

    def describe(self):
        """For the Status page: each home, why it is there, and the address families it serves."""
        rows = []
        for home in self.homes:
            families = sorted({"IPv6" if ":" in address else "IPv4"
                               for address, assigned in self.assigned.items() if assigned is home}
                              | ({"IPv4"} if home is self.ipv4 else set()) | ({"IPv6"} if home is self.ipv6 else set()))
            rows.append({key: home[key] for key in ("name", "lat", "lon", "accuracy_km", "source", "evidence")}
                        | {"families": families})
        return rows


def plan(addresses, locate, primary_wan=None, coordinates=None, external=None, ipv6_home="auto"):
    """The firewall's homes.

    addresses: {device: addresses} for every interface; locate(address) -> GeoIP location or None;
    coordinates: (lat, lon) from the settings; external: (address, location) found by external IP
    discovery behind an upstream NAT; ipv6_home: "auto" (own home only when precise and elsewhere)
    or "ipv4" (always the IPv4 home).
    """
    devices = {}
    for device, items in sorted(addresses.items()):
        for address in sorted(items):
            if public_ip(address):
                devices.setdefault(address, device)
    if coordinates is not None:
        home = {"lat": coordinates[0], "lon": coordinates[1], "name": "Firewall", "city": None, "region": None,
                "country": None, "country_code": None, "accuracy_km": None, "source": "coordinates",
                "evidence": None}
        return HomePlan([home], {address: home for address in devices}, home, home)

    evidence = [address for address, device in devices.items() if not tunnel(device)]
    located = {address: locate(address) for address in evidence}
    wan_first = lambda address: (devices[address] != primary_wan, address)  # noqa: E731
    inside_first = lambda address: (devices[address] == primary_wan, address)  # noqa: E731
    ipv4 = sorted((address for address in evidence if ":" not in address), key=wan_first)
    ipv6 = sorted((address for address in evidence if ":" in address), key=inside_first)

    homes, assigned = [], {}
    home4 = None
    # behind an upstream NAT the discovered address is the IPv4 baseline, when it is precise (a
    # carrier-grade NAT gateway often is not)
    if external is not None and precise(external[1]):
        home4 = _home(external[1], "external_ip", external[0])
        homes.append(home4)
    for address in ipv4:
        location = located[address]
        if not precise(location):
            continue
        if home4 is None:
            home4 = _home(location, "ipv4_wan" if devices[address] == primary_wan else "ipv4", address)
            homes.append(home4)
            assigned[address] = home4
        elif agree(location, home4):
            assigned[address] = home4
        else:
            # another WAN that is precisely somewhere else (multi-WAN across sites)
            other = _home(location, "ipv4", address)
            homes.append(other)
            assigned[address] = other

    precise6 = [address for address in ipv6 if precise(located[address])]
    home6 = home4
    if home4 is not None:
        if ipv6_home != "ipv4" and precise6 and not any(agree(located[address], home4) for address in precise6):
            address = precise6[0]
            home6 = _home(located[address], "ipv6_wan" if devices[address] == primary_wan else "ipv6_inside", address)
            homes.append(home6)
    elif precise6:
        address = precise6[0]
        home4 = home6 = _home(located[address], "ipv6_wan" if devices[address] == primary_wan else "ipv6_inside",
                              address)
        homes.append(home6)
    else:
        # nothing precise: one home at the best of what there is (IPv4 first, then the tightest radius)
        if external is not None and external[1]:
            located[external[0]] = external[1]
        candidates = [address for address in ([external[0]] if external else []) + ipv4 + ipv6
                      if located.get(address)]
        if candidates:
            address = min(candidates, key=lambda item: (":" in item, located[item].get("accuracy_km") or VAGUE_KM))
            home4 = home6 = _home(located[address], "approximate", address)
            homes.append(home4)
    for address in devices:
        if address not in assigned:
            home = home6 if ":" in address else home4
            if home is not None:
                assigned[address] = home
    return HomePlan(homes, assigned, home4, home6)
