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
# POSSIBILITY OF SUCH DAMAGE.

"""Names for addresses in Firewall Map+: DHCP leases and reservations, reverse DNS."""

import ipaddress
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor

from .common import ip_object, service_name


HOSTNAME_TTL = 6 * 3600
HOSTNAME_LOOKUPS_PER_SAMPLE = 8
MAX_HOSTNAMES = 5000
KEA_LEASES = "/var/db/kea/kea-leases4.csv"
KEA6_LEASES = "/var/db/kea/kea-leases6.csv"
DNSMASQ_LEASES = "/var/db/dnsmasq.leases"
# Kea's configuration as OPNsense renders it (its reservations carry the host names)
KEA_CONFIGS = ("/usr/local/etc/kea/kea-dhcp4.conf", "/usr/local/etc/kea/kea-dhcp6.conf")


def kea_reservations(paths=KEA_CONFIGS):
    """IP -> hostname from the Kea reservations, IPv4 ("ip-address") and IPv6 ("ip-addresses")."""
    names = {}
    for path in paths:
        try:
            with open(path) as handle:
                document = json.load(handle)
        except (OSError, ValueError):
            continue  # not configured (an empty file) or not installed
        for service in document.values() if isinstance(document, dict) else []:
            if not isinstance(service, dict):
                continue
            subnets = service.get("subnet4") or service.get("subnet6") or []
            reservations = [*service.get("reservations", []), *(item for subnet in subnets for item in subnet.get("reservations", []))]
            for reservation in reservations:
                name = str(reservation.get("hostname") or "").strip()
                for address in [reservation.get("ip-address"), *reservation.get("ip-addresses", [])]:
                    try:
                        if name and address:
                            names[str(ipaddress.ip_address(str(address).strip()))] = name
                    except ValueError:
                        continue
    return names


def lease_names(kea=KEA_LEASES, dnsmasq=DNSMASQ_LEASES, kea_configs=KEA_CONFIGS, now=None, kea6=KEA6_LEASES):
    """IP -> hostname from DHCP: Kea reservations win over Kea leases, then dnsmasq leases."""
    now = time.time() if now is None else now
    leases = {}
    for path in (kea, kea6):
        try:
            with open(path, errors="replace") as handle:
                header = handle.readline().strip().split(",")
                column = {name: index for index, name in enumerate(header)}
                for line in handle:
                    fields = line.rstrip("\n").split(",")
                    try:
                        address = str(ipaddress.ip_address(fields[column["address"]]))
                        name = fields[column["hostname"]].strip().rstrip(".")
                        expire = int(fields[column["expire"]] or 0)
                    except (KeyError, IndexError, ValueError):
                        continue
                    # Kea appends lease updates: the latest line for an address wins, and an
                    # expired, released or nameless latest line clears the name.
                    if name and expire >= now:
                        leases[address] = name
                    else:
                        leases.pop(address, None)
        except OSError:
            pass
    try:
        with open(dnsmasq, errors="replace") as handle:
            for line in handle:
                fields = line.split()
                if len(fields) >= 4 and fields[3] != "*":
                    try:
                        leases.setdefault(str(ipaddress.ip_address(fields[2])), fields[3])
                    except ValueError:
                        continue
    except OSError:
        pass
    leases.update(kea_reservations(kea_configs))
    return leases


# (networks, {address: device}): the same inside hosts are described on every sample
_devices = (None, {})


def describe_inside(address, names, networks, interfaces):
    global _devices
    seen_networks, devices = _devices
    if seen_networks is not networks or len(devices) >= 4096:
        devices = {}
        _devices = (networks, devices)
    if address in devices:
        device = devices[address]
    else:
        parsed = ip_object(address)
        device = devices[address] = next((device for network, device in networks
                                          if network.version == parsed.version and parsed in network), None)
    return {
        "ip": address,
        "name": names.get(address),
        "interface": interfaces.get(device, device) if device else None,
    }


class HostnameResolver:
    """Reverse DNS for visible endpoints, only while a viewer asked for it; results are cached."""

    def __init__(self, ttl=HOSTNAME_TTL, per_sample=HOSTNAME_LOOKUPS_PER_SAMPLE, store=None):
        self.ttl = ttl
        self.per_sample = per_sample
        self.store = store
        # (name, monotonic time looked up); names cached in the store survive restarts
        now = time.monotonic()
        wall = time.time()
        self.names = {}
        if store is not None:
            store.prune("hostname", max_age=ttl, keep=MAX_HOSTNAMES)
            for address, (name, stamp) in store.get_all("hostname", max_age=ttl).items():
                self.names[address] = (name, now - (wall - stamp))
        self.pending = {}
        self.pool = ThreadPoolExecutor(max_workers=4)

    @staticmethod
    def _reverse(address):
        try:
            return socket.gethostbyaddr(address)[0]
        except (OSError, UnicodeError):
            return None

    def update(self, addresses, now):
        resolved = []
        for address, future in list(self.pending.items()):
            if future.done():
                self.names[address] = (future.result(), now)
                resolved.append((address, (future.result(), time.time())))
                del self.pending[address]
        if resolved and self.store is not None:
            self.store.put_many("hostname", resolved)
            self.store.prune("hostname", max_age=self.ttl, keep=MAX_HOSTNAMES)
        for address in [address for address, (_, stamp) in self.names.items() if now - stamp >= self.ttl]:
            del self.names[address]
        while len(self.names) > MAX_HOSTNAMES:
            del self.names[min(self.names, key=lambda address: self.names[address][1])]
        budget = self.per_sample - len(self.pending)
        for address in addresses:
            if budget <= 0:
                break
            cached = self.names.get(address)
            if address in self.pending or (cached and now - cached[1] < self.ttl):
                continue
            self.pending[address] = self.pool.submit(self._reverse, address)
            budget -= 1

    def get(self, address):
        cached = self.names.get(address)
        return cached[0] if cached else None


def describe_target(target, names, networks, interfaces, local_addresses):
    """'tcp|192.168.1.2|443' -> the inside host (or this firewall) a remote connection was aimed at."""
    protocol, address, port = target.split("|")
    service = service_name(protocol, port or None)
    if address in local_addresses:
        return {"ip": address, "port": port, "protocol": protocol, "name": "firewall", "interface": None,
                "service": service, "firewall": True}
    described = describe_inside(address, names, networks, interfaces)
    described.update({"port": port, "protocol": protocol, "service": service})
    return described
