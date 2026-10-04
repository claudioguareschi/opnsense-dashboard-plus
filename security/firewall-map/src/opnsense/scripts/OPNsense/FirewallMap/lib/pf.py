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

"""PF state table, ruleset and interface parsing for Firewall Map+."""

import functools
import ipaddress
import re
import subprocess
import xml.etree.ElementTree as ElementTree

from .common import CONFIG_XML, PFCTL, RULES_DEBUG, config_root, host_port, normalize_ip, private_ip, public_ip


IFCONFIG = "/sbin/ifconfig"
COUNTERS = re.compile(r"(?P<packets_in>\d+):(?P<packets_out>\d+) pkts,\s+(?P<bytes_in>\d+):(?P<bytes_out>\d+) bytes")
AGE = re.compile(r"\bage (?:(?P<days>\d+)d)?(?P<h>\d+):(?P<m>\d+):(?P<s>\d+)")
RLABEL = re.compile(r"\brlabel ([^,\s]+)")
STATE_ID = re.compile(r"\bid: (?P<id>[0-9a-f]+) creatorid: (?P<creator>[0-9a-f]+)")


def endpoint(value):
    """Split the endpoint syntax emitted by pfctl for both address families.

    PF renders IPv4 ports as ``192.0.2.1:443`` and IPv6 ports as
    ``2001:db8::1[443]``. Bracketed ``[2001:db8::1]:443`` is accepted too because it is
    the unambiguous representation used by the API and UI.
    """
    value = value.strip("()")
    if value.startswith("[") and "]" in value:
        address, _, rest = value[1:].partition("]")
        return {"address": normalize_ip(address), "port": rest.lstrip(":") or None}
    if value.count(":") > 1:
        address, marker, rest = value.partition("[")
        return {"address": normalize_ip(address), "port": rest.rstrip("]") or None} if marker else {
            "address": normalize_ip(value), "port": None,
        }
    # IPv4 (the common case, kept free of parsing: this runs per state); pfctl prints it canonical
    address, _, port = value.partition(":")
    if address and (not port or port.isdigit()):
        return {"address": address, "port": port or None}
    return {"address": None, "port": None}


def _state_header(line):
    """The endpoints of one state from its first line, or None when the map never draws it.

    "A [(A')] -> B [(B')] STATE": a translation follows the endpoint it belongs to.
    """
    parts = line.split()
    arrow = next((index for index, part in enumerate(parts) if part in ("->", "<-")), None)
    if len(parts) < 6 or arrow is None or arrow < 3 or arrow + 1 >= len(parts):
        return None
    direction = "out" if parts[arrow] == "->" else "in"
    left = endpoint(parts[2])
    right = endpoint(parts[arrow + 1])
    translated = arrow > 3 and parts[3].startswith("(")
    if not translated and not public_ip(left["address"]) and not public_ip(right["address"]):
        # LAN-internal state (or the LAN side of a NAT pair): never drawn, skip its details
        return None
    return {
        "interface": parts[0],
        "protocol": parts[1],
        "state": parts[-1],
        "direction": direction,
        "src": left if direction == "out" else right,
        "dst": right if direction == "out" else left,
        "nat": endpoint(parts[3]) if translated else None,
    }


def _counters_record(header, line):
    """The record for a state from its header and its "age ..., pkts, bytes" detail line."""
    counters = COUNTERS.search(line)
    if not counters:
        return None
    age = AGE.search(line)
    return {
        **header,
        "id": None,
        "origif": None,
        "age": (
            sum(int(age.group(unit) or 0) * seconds for unit, seconds in (("days", 86400), ("h", 3600), ("m", 60), ("s", 1)))
        ) if age else None,
        **{key: int(value) for key, value in counters.groupdict().items()},
        # the rule that created the state (same label as in the firewall log)
        "rule": (RLABEL.search(line) or [None, None])[1] if "rlabel" in line else None,
    }


def parse_states(output):
    """Parse `pfctl -vv -s state` using the same endpoint fields as OPNsense's state API."""
    records = []
    header = None
    skipping = False
    for line in output.splitlines():
        if not line.startswith((" ", "\t")):
            header = _state_header(line)
            skipping = header is None
            continue
        # dispatch on the detail line's first word: running every pattern over every line was
        # the collector's largest CPU cost
        if skipping:
            continue  # detail lines of a skipped state must not attach to the previous record
        stripped = line.lstrip()
        if stripped.startswith("id:"):
            state_id = STATE_ID.search(stripped)
            if state_id and records and records[-1].get("id") is None:
                records[-1]["id"] = f"{state_id.group('id')}/{state_id.group('creator')}"
        elif stripped.startswith("origif:"):
            if records and records[-1].get("origif") is None:
                # the interface the state was created on: for NAT states, the egress (WAN, VPN, ...)
                records[-1]["origif"] = stripped.split()[1]
        elif header is not None and stripped.startswith("age "):
            record = _counters_record(header, line)
            if record:
                records.append(record)
                header = None
    return records


def _network_device(address, networks, exclude_device=None):
    """Interface whose configured network contains address, optionally excluding one device."""
    try:
        parsed = ipaddress.ip_address(address)
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


def _origin_address(record, local_addresses, networks):
    """Best same-family firewall address to use as the map origin for a routed state."""
    inside = inside_endpoint(record, networks, local_addresses)
    if inside is None:
        return None
    other = record["dst"] if inside is record["src"] else record["src"]
    try:
        version = ipaddress.ip_address(other["address"]).version
    except (TypeError, ValueError):
        return None
    same_family = [address for address in local_addresses
                   if ipaddress.ip_address(address).version == version]
    on_egress = [address for address in same_family
                 if _network_device(address, networks) == record.get("origif")]
    return min(on_egress or same_family, default=None)


def flow_endpoints(record, local_addresses, networks=None):
    """Return (firewall public address, remote address) or None for non-map traffic.

    NAT states carry the firewall's public address explicitly; other states are kept
    only when one endpoint is a public address configured on this firewall.
    """
    src = record["src"]["address"]
    dst = record["dst"]["address"]
    nat = record["nat"]["address"] if record["nat"] else None
    if nat and public_ip(nat):
        local = nat
    elif src in local_addresses:
        local = src
    elif dst in local_addresses:
        local = dst
    elif nat and private_ip(src) and public_ip(dst) and local_addresses:
        # outbound NAT to a tunnel address (e.g. a WireGuard or IPsec egress): draw it from the
        # firewall's own location, the egress interface tells which path it took
        try:
            version = ipaddress.ip_address(dst).version
            local = min(address for address in local_addresses if ipaddress.ip_address(address).version == version)
        except (TypeError, ValueError):
            return None
        return local, dst
    else:
        # With a routed prefix there is no NAT and neither state endpoint is an address assigned
        # to the firewall. Identify the protected endpoint from the interface networks, then draw
        # the flow from a same-family firewall address while retaining the host as `inside`.
        if not networks:
            return None
        inside = inside_endpoint(record, networks, local_addresses)
        if inside is None or not public_ip(inside["address"]):
            return None
        remote_side = record["dst"] if inside is record["src"] else record["src"]
        if not public_ip(remote_side["address"]):
            return None
        local = _origin_address(record, local_addresses, networks)
        return (local, remote_side["address"]) if local else None
    remote = dst if local == src else src
    if not public_ip(remote) or remote == local or remote in local_addresses:
        return None
    return local, remote


def inside_endpoint(record, networks=None, local_addresses=None):
    """The protected endpoint behind NAT or within a directly routed interface prefix."""
    for side in (record["nat"], record["src"], record["dst"]):
        if side and private_ip(side["address"]):
            return side
    # Public prefixes are unambiguous only when pfctl supplied the state's outside interface.
    outside = record.get("origif")
    if outside:
        for side in (record["src"], record["dst"]):
            if inside_address(side["address"], networks, local_addresses, outside):
                return side
    return None


def lan_rule_index(records):
    """Rules of the inside-facing states, keyed by (protocol, inside address:port, remote address:port).

    A NATed connection has two states: the one on the inside interface was created by the rule the
    operator wrote (e.g. "IoT to Internet"), the one on WAN by the automatic outbound rule. The map
    reports the first.
    """
    index = {}
    for record in records:
        rule = record.get("rule")
        if not rule or record["nat"]:
            continue
        src, dst = record["src"], record["dst"]
        if private_ip(src["address"]) and public_ip(dst["address"]):
            index[(record["protocol"], src["address"], src["port"], dst["address"], dst["port"])] = rule
    return index


def rule_for(record, pair, lan_rules, networks=None, local_addresses=None):
    inside = inside_endpoint(record, networks, local_addresses)
    if inside and lan_rules:
        far = record["src"] if record["src"]["address"] == pair[1] else record["dst"]
        rule = lan_rules.get((record["protocol"], inside["address"], inside["port"], far["address"], far["port"]))
        if rule:
            return rule
    return record.get("rule")


def orientation(record, remote, networks=None, local_addresses=None):
    """(remote started it, the service's port) for one state.

    A state normally starts at its initiator. When the opening packet passed the other CARP
    node (asymmetric paths), the reply from an inside server creates an "outbound" state from a
    well-known port to an ephemeral one: that connection was really started by the remote side.
    """
    if record["src"]["address"] == remote:
        return True, record["dst"]["port"]
    # behind outbound NAT the source port that matters is the inside host's, not the translated one
    source, target = (inside_endpoint(record, networks, local_addresses) or record["src"])["port"], record["dst"]["port"]
    # the client side must look ephemeral: keeps NFS (reserved port to 2049) and IKE (500 to 4500) outbound
    numeric = record["protocol"] in ("tcp", "udp") and source and target and source.isdigit() and target.isdigit()
    if numeric and int(source) < 1024 and int(target) >= 10000:
        return True, source
    return False, target


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


def host_info():
    """Return (public IP addresses on this firewall, CARP role or None, interface networks)."""
    try:
        output = subprocess.run(
            [IFCONFIG, "-a"], capture_output=True, check=False, text=True, timeout=2,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return set(), None, []
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
    return addresses, role, interface_networks(output)


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


def config_aliases(config=CONFIG_XML):
    """Firewall aliases from config.xml: [{"name", "type", "enabled", "description"}]."""
    try:
        root = config_root(config)
    except (OSError, ElementTree.ParseError):
        return []
    return [{
        "name": alias.findtext("name"),
        "type": alias.findtext("type"),
        "enabled": alias.findtext("enabled") != "0",
        "description": alias.findtext("description") or "",
    } for alias in root.iterfind(".//OPNsense/Firewall/Alias/aliases/alias")]


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


def interface_names(path=CONFIG_XML):
    """Map devices (igb1, vlan01, ...) to their configured names (WAN, LAN, ...)."""
    names = {}
    try:
        interfaces = config_root(path).find("interfaces")
    except (OSError, ElementTree.ParseError):
        return names
    for node in list(interfaces) if interfaces is not None else []:
        device = node.findtext("if")
        if device:
            names[device] = (node.findtext("descr") or "").strip() or node.tag.upper()
    return names


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


def state_outside(record, pair):
    """(outside key, inside endpoint) of a PF state touching a public remote address, else None."""
    local, remote = pair
    nat = record["nat"]
    # pfctl prints the wire side first for outbound states ("wire (original) -> remote") and last
    # for inbound ones ("original (wire) <- remote"); the outbound NAT source port, including the
    # firewall's own randomized DNS ports, is only right on the wire side
    if record["direction"] == "out":
        public = record["src"]
    else:
        public = nat if nat else record["dst"]
    if nat and public["address"] != local:
        return None  # NAT to a tunnel address: Suricata on WAN never sees this tuple
    far = record["src"] if record["src"]["address"] == remote else record["dst"]
    if far["address"] != remote:
        return None
    return outside_key(record["protocol"], public["address"], public["port"], remote, far["port"])


# Walking the state table costs about 2 kB of memory and 20 µs per state. The map walks at most
# as many states as fit in a small share of the firewall's RAM (a 4 GB box: about 100,000), so a
# flood or a very busy firewall stops the sampling instead of risking memory; never fewer than
# MIN, and never more than MAX, which already takes about 5 s per sample.
BYTES_PER_STATE = 2048
STATE_MEMORY_SHARE = 0.05
MIN_SAMPLED_STATES = 25000
MAX_SAMPLED_STATES = 250000
STATE_COUNT = re.compile(r"current entries\s+(\d+)")


class TooManyStates(RuntimeError):
    def __init__(self, count, limit):
        super().__init__(f"{count} states (limit {limit})")
        self.count = count
        self.limit = limit


def state_count():
    """The number of states pf holds now (cheap: a counter, not a walk), or None when unknown."""
    try:
        output = subprocess.run([PFCTL, "-si"], capture_output=True, check=False, text=True, timeout=5).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = STATE_COUNT.search(output)
    return int(match.group(1)) if match else None


@functools.lru_cache(maxsize=1)
def physical_memory():
    """Installed RAM in bytes (hw.physmem), or None when unknown."""
    try:
        output = subprocess.run(["/sbin/sysctl", "-n", "hw.physmem"], capture_output=True, check=False, text=True, timeout=5).stdout
        return int(output.strip()) or None
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None


def state_limit(memory=None):
    """How many states the map may walk on this firewall, from its RAM (see STATE_MEMORY_SHARE)."""
    memory = physical_memory() if memory is None else memory
    if not memory:
        return 100000
    limit = int(memory * STATE_MEMORY_SHARE / BYTES_PER_STATE) // 5000 * 5000
    return max(MIN_SAMPLED_STATES, min(MAX_SAMPLED_STATES, limit))


def sample_states(limit=None):
    limit = state_limit() if limit is None else limit
    count = state_count()
    if count is not None and count > limit:
        raise TooManyStates(count, limit)
    result = subprocess.run(
        [PFCTL, "-vv", "-s", "state"], capture_output=True, check=False, text=True, timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError("pfctl failed")
    return parse_states(result.stdout)
