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

"""Shared PF configuration, interface, table and IDS policy helpers."""

import ipaddress
import re
import subprocess

from .common import PFCTL, RULES_DEBUG, host_port, ip_object, private_ip, public_ip

IFCONFIG = "/sbin/ifconfig"


class _Record:
    """A compact presentation record with dictionary-compatible field access."""
    __slots__ = ()

    def __getitem__(self, key):
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key) from None

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def get(self, key, default=None):
        return getattr(self, key, default)

    def keys(self):
        return self.__slots__

    def __iter__(self):
        return iter(self.__slots__)

    def __contains__(self, key):
        return key in self.__slots__

    def __eq__(self, other):
        if isinstance(other, (_Record, dict)):
            return dict(self) == dict(other)
        return NotImplemented

    def __repr__(self):
        return f"{type(self).__name__}({', '.join(f'{key}={getattr(self, key)!r}' for key in self.__slots__)})"


def _network_device(address, networks, exclude_device=None):
    """Interface whose configured network contains address, optionally excluding one device."""
    try:
        parsed = ip_object(address)
    except (TypeError, ValueError):
        return None
    for network, device in networks or []:
        if device != exclude_device and network.version == parsed.version and parsed in network:
            return device
    return None


def inside_address(address, networks=None, local_addresses=None, exclude_device=None):
    """Whether address belongs to the protected side, including a routed public subnet.

    RFC1918/ULA addresses retain their historic meaning. A globally routed address is inside only
    when it belongs to a configured interface network other than the state's outside interface.
    """
    if private_ip(address):
        return True
    if address in (local_addresses or set()):
        return False
    return _network_device(address, networks, exclude_device) is not None


def interface_networks(output):
    """[(IPv4Network/IPv6Network, device)] for addresses configured on interfaces."""
    networks = []
    device = None
    for line in output.splitlines():
        header = re.match(r"^(\S+?):\s+flags=", line)
        if header:
            device = header.group(1)
            continue
        match = re.search(r"\binet\s+(\d+(?:\.\d+){3})\s+netmask\s+(0x[0-9a-fA-F]+)", line)
        if match and device:
            try:
                prefix = bin(int(match.group(2), 16)).count("1")
                networks.append((ipaddress.ip_network(f"{match.group(1)}/{prefix}", strict=False), device))
            except ValueError:
                continue
        match6 = re.search(r"\binet6\s+([^\s%]+)(?:%\S+)?\s+prefixlen\s+(\d+)", line)
        if match6 and device:
            try:
                networks.append((ipaddress.ip_network(f"{match6.group(1)}/{match6.group(2)}", strict=False), device))
            except ValueError:
                continue
    # most specific first, so a host matches its own subnet before a wider one
    networks.sort(key=lambda item: -item[0].prefixlen)
    return networks


def interface_addresses(output):
    """{device: {exact local addresses}} from ifconfig -a, including private WAN addresses."""
    addresses = {}
    device = None
    for line in output.splitlines():
        header = re.match(r"^(\S+?):\s+flags=", line)
        if header:
            device = header.group(1)
            continue
        match = re.search(r"\binet\s+(\d+(?:\.\d+){3})", line)
        match6 = re.search(r"\binet6\s+([^\s%]+)", line)
        value = match.group(1) if match else match6.group(1) if match6 else None
        if value and device:
            try:
                address = str(ipaddress.ip_address(value))
            except ValueError:
                continue
            addresses.setdefault(device, set()).add(address)
    return addresses


def host_info():
    """Return (public addresses, CARP role, interface networks, exact addresses by device)."""
    try:
        output = subprocess.run(
            [IFCONFIG, "-a"], capture_output=True, check=False, text=True, timeout=2,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return set(), None, [], {}
    candidates = re.findall(r"\binet\s+(\d+(?:\.\d+){3})", output)
    candidates += re.findall(r"\binet6\s+([^\s%]+)", output)
    addresses = {str(ipaddress.ip_address(address)) for address in candidates if public_ip(address)}
    roles = set(re.findall(r"\bcarp: (MASTER|BACKUP|INIT)\b", output))
    if not roles:
        role = None
    elif "MASTER" in roles:
        role = "master"
    else:
        role = "backup"
    return addresses, role, interface_networks(output), interface_addresses(output)


def blocked_rule_tables(path=RULES_DEBUG):
    """Tables referenced by block or reject rules in the running ruleset."""
    tables = set()
    try:
        with open(path, errors="replace") as handle:
            for line in handle:
                if line.startswith(("block", "reject")):
                    tables.update(re.findall(r"<([A-Za-z0-9_.-]+)>", line.split(" label ")[0]))
    except OSError:
        pass
    return tables


def pf_tables():
    """Names of the pf tables loaded now."""
    try:
        return subprocess.run([PFCTL, "-sT"], capture_output=True, check=False, text=True, timeout=10).stdout.split()
    except (OSError, subprocess.TimeoutExpired):
        return []


def rule_descriptions(path=RULES_DEBUG):
    """Map rule labels to their descriptions, as the firewall log view does."""
    descriptions = {}
    try:
        with open(path, errors="replace") as handle:
            for line in handle:
                if " label " in line:
                    label = line.split(" label ")[-1]
                    if label.count('"') >= 2:
                        descriptions[label.split('"')[1]] = "".join(label.split('"')[2:]).strip().strip("# : ")
    except OSError:
        pass
    return descriptions


PORT_FORWARD = re.compile(
    r"^rdr (?:pass )?on (?P<iface>\S+) inet6? proto (?P<proto>\{[^}]*\}|\S+) from .*? to .*? port \{?(?P<ports>[\d:, ]+)\}?"
    r" -> (?P<target>\S+)(?: port (?P<tport>\d+))?(?:.*?# (?P<descr>.*))?$")


def port_forwards(path=RULES_DEBUG, table_lookup=None):
    """Port forwards from the running ruleset: protocol and public port(s) -> inside host and port."""
    def lookup(name):
        try:
            out = subprocess.run([PFCTL, "-t", name, "-T", "show"], capture_output=True, text=True, timeout=5).stdout
        except (OSError, subprocess.TimeoutExpired):
            return None
        first = out.split()
        return first[0] if first else None
    table_lookup = table_lookup or lookup
    forwards = []
    try:
        with open(path, errors="replace") as handle:
            for line in handle:
                if not line.startswith("rdr "):
                    continue
                match = PORT_FORWARD.match(line.strip())
                if not match:
                    continue
                target = match["target"]
                if target.startswith("$"):
                    target = table_lookup(target[1:])
                try:
                    parsed_target = ipaddress.ip_address(target)
                except (TypeError, ValueError):
                    continue
                if parsed_target.is_loopback or parsed_target.is_unspecified or parsed_target.is_multicast:
                    continue  # captive portal and other redirects to the firewall itself
                ports = []
                for part in re.split(r"[ ,]+", match["ports"].strip()):
                    low, _, high = part.partition(":")
                    if low.isdigit():
                        ports.append((int(low), int(high) if high.isdigit() else int(low)))
                forwards.append({
                    "protocols": set(re.findall(r"tcp|udp", match["proto"])),
                    "ports": ports, "target": target, "target_port": match["tport"],
                    "description": (match["descr"] or "").strip(),
                })
    except OSError:
        pass
    return forwards


def forward_target(forwards, protocol, port):
    """(inside host:port, rule description) a port forward sends this public port to, or (None, None)."""
    if not port or not str(port).isdigit():
        return None, None
    port = int(port)
    for forward in forwards or []:
        if protocol in forward["protocols"] and any(low <= port <= high for low, high in forward["ports"]):
            return host_port(forward["target"], forward["target_port"] or port), forward["description"]
    return None, None


def outside_key(protocol, public_ip, public_port, remote_ip, remote_port):
    """The connection as seen outside NAT, which is what Suricata on WAN observes."""
    return (protocol, public_ip, str(public_port or ""), remote_ip, str(remote_port or ""))
