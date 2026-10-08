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

"""Test/development-only PF text and normalization oracle; never shipped."""

import ipaddress
import re
import sys

from lib.common import (connection_target, host_port, normalize_ip, private_ip, public_ip, service_name,
                        service_port_label)
from lib import pf as shared
from lib.pf import _Record, _network_device, inside_address, outside_key

COUNTERS = re.compile(r"(?P<packets_in>\d+):(?P<packets_out>\d+) pkts,\s+(?P<bytes_in>\d+):(?P<bytes_out>\d+) bytes")
AGE = re.compile(r"\bage (?:(?P<days>\d+)d)?(?P<h>\d+):(?P<m>\d+):(?P<s>\d+)")
RLABEL = re.compile(r"\brlabel ([^,\s]+)")
AGE_UNITS = (("days", 86400), ("h", 3600), ("m", 60), ("s", 1))
MAX_SAMPLE_STRINGS = 65536
STATE_ID = re.compile(r"\bid: (?P<id>[0-9a-f]+) creatorid: (?P<creator>[0-9a-f]+)")
# the whole "age ..., expires in ..., pkts, bytes" line as pfctl prints it
DETAIL = re.compile(r"age (?:(\d+)d)?(\d+):(\d+):(\d+), expires in [^,]*, (\d+):(\d+) pkts, (\d+):(\d+) bytes")


class Endpoint(_Record):
    """One side of a state: address, and port as text (None for ICMP or when PF shows none)."""
    __slots__ = ("address", "port")

    def __init__(self, address, port):
        self.address = address
        self.port = port

    def __hash__(self):
        return hash((self.address, self.port))


class PfState(_Record):
    """One PF state as the map uses it.

    interface, protocol, state     where it lives and its TCP/UDP state ("ESTABLISHED:ESTABLISHED")
    direction                      "out" or "in", as PF created it
    src, dst                       Endpoints in that direction; nat: the inside Endpoint behind NAT, or None
    id                             "id/creatorid", unique per state; origif: the interface it was created on
    age                            seconds since it was created (None when PF shows no age)
    packets_in/out, bytes_in/out   counters
    rule                           the label of the rule that created it (same as in the firewall log)
    """
    __slots__ = ("interface", "protocol", "state", "direction", "src", "dst", "nat", "id", "origif", "age",
                 "packets_in", "packets_out", "bytes_in", "bytes_out", "rule")

    def __init__(self, interface=None, protocol=None, state=None, direction=None, src=None, dst=None, nat=None,
                 id=None, origif=None, age=None, packets_in=None, packets_out=None, bytes_in=None, bytes_out=None,
                 rule=None):
        # one assignment per field: this runs once per state and sample
        self.interface, self.protocol, self.state, self.direction = interface, protocol, state, direction
        self.src, self.dst, self.nat, self.id, self.origif, self.age = src, dst, nat, id, origif, age
        self.packets_in, self.packets_out, self.bytes_in, self.bytes_out = packets_in, packets_out, bytes_in, bytes_out
        self.rule = rule

    __hash__ = None


class _StringPool:
    """Bounded value-preserving sharing for one parsing/derivation phase, never a cache.

    Full pools still reuse admitted strings, but leave new values alone. Clearing on exit
    also releases the lookup contents when an aborted sample's traceback is retained.
    """
    __slots__ = ("values", "limit")

    def __init__(self, limit=MAX_SAMPLE_STRINGS):
        self.values = {}
        self.limit = limit

    def share(self, value):
        if value is None:
            return None
        previous = self.values.get(value)
        if previous is not None:
            return previous
        if len(self.values) < self.limit:
            self.values[value] = value
        return value

    def __enter__(self):
        return self

    def __exit__(self, *error):
        self.values.clear()


def endpoint(value, addresses=None, ports=None):
    """Split the endpoint syntax emitted by pfctl for both address families.

    PF renders IPv4 ports as ``192.0.2.1:443`` and IPv6 ports as
    ``2001:db8::1[443]``. Bracketed ``[2001:db8::1]:443`` is accepted too because it is
    the unambiguous representation used by the API and UI.
    """
    value = value.strip("()")
    if value.startswith("[") and "]" in value:
        address, _, rest = value[1:].partition("]")
        address, port = normalize_ip(address), rest.lstrip(":") or None
    elif value.count(":") > 1:
        address, marker, rest = value.partition("[")
        address, port = (normalize_ip(address), rest.rstrip("]") or None) if marker else (normalize_ip(value), None)
    else:
        # IPv4 (the common case, kept free of parsing: this runs per state); pfctl prints it canonical
        address, _, port = value.partition(":")
        if address and (not port or port.isdigit()):
            port = port or None
        else:
            address = port = None
    if addresses is not None:
        address = addresses.share(address)
    if ports is not None:
        port = ports.share(port)
    return Endpoint(address, port)


def _state_header(line, addresses=None, ports=None):
    """The endpoints of one state from its first line, or None when the map never draws it.

    "A [(A')] -> B [(B')] STATE": a translation follows the endpoint it belongs to.
    """
    parts = line.split()
    arrow = next((index for index, part in enumerate(parts) if part in ("->", "<-")), None)
    if len(parts) < 6 or arrow is None or arrow < 3 or arrow + 1 >= len(parts):
        return None
    direction = "out" if parts[arrow] == "->" else "in"
    left = endpoint(parts[2], addresses, ports)
    right = endpoint(parts[arrow + 1], addresses, ports)
    translated = arrow > 3 and parts[3].startswith("(")
    if not translated and not public_ip(left["address"]) and not public_ip(right["address"]):
        # LAN-internal state (or the LAN side of a NAT pair): never drawn, skip its details
        return None
    # the same few interface, protocol and state names repeat across the whole table: one copy each
    # (interface, protocol, state, direction, src, dst, nat), in PfState's order
    return (
        sys.intern(parts[0]),
        sys.intern(parts[1]),
        sys.intern(parts[-1]),
        direction,
        left if direction == "out" else right,
        right if direction == "out" else left,
        endpoint(parts[3], addresses, ports) if translated else None,
    )


def _counters_record(header, line, stripped=None):
    """The record for a state from its header and its "age ..., pkts, bytes" detail line."""
    # the usual layout in one match; anything else takes the field by field search below
    detail = DETAIL.match(line.lstrip() if stripped is None else stripped)
    if detail:
        days, hours, minutes, seconds, packets_in, packets_out, bytes_in, bytes_out = detail.groups()
        age = (int(days) * 86400 if days else 0) + int(hours) * 3600 + int(minutes) * 60 + int(seconds)
        counters = (int(packets_in), int(packets_out), int(bytes_in), int(bytes_out))
    else:
        found = COUNTERS.search(line)
        if not found:
            return None
        age = AGE.search(line)
        age = sum(int(age.group(unit) or 0) * seconds for unit, seconds in AGE_UNITS) if age else None
        counters = tuple(int(value) for value in found.groups())
    # the rule that created the state (same label as in the firewall log)
    rule = sys.intern((RLABEL.search(line) or [None, ""])[1]) or None if "rlabel" in line else None
    return PfState(*header, None, None, age, *counters, rule)


# what each header line of the previous walk parsed to (None: a state the map skips). States
# outlive many samples and their header lines repeat word for word, so most are parsed once;
# the records then share their Endpoints with the previous sample's (they are never changed)
_known_headers = {}
_UNKNOWN = object()


def parse_states(output, limit=None):
    """Parse `pfctl -vv -s state` (its text, or its lines as they arrive) using the same endpoint
    fields as OPNsense's state API. Past `limit` states it stops (TooManyStates): the table can grow
    during the walk (a flood), after its size was checked."""
    global _known_headers
    known, seen = _known_headers, {}
    records = []
    header = None
    skipping = False
    with _StringPool() as addresses, _StringPool() as ports:
        for line in (output.splitlines() if isinstance(output, str) else output):
            first = line[:1]
            if first != " " and first != "\t":
                header = known.get(line, _UNKNOWN)
                if header is _UNKNOWN:
                    header = _state_header(line, addresses, ports)
                seen[line] = header
                skipping = header is None
                continue
            # dispatch on the detail line's first word: running every pattern over every line was
            # the collector's largest CPU cost
            if skipping:
                continue  # detail lines of a skipped state must not attach to the previous record
            stripped = line.lstrip()
            start = stripped[:3]
            if start == "id:":
                state_id = STATE_ID.search(stripped)
                if state_id and records and records[-1].id is None:
                    records[-1].id = "%s/%s" % state_id.groups()
            elif start == "ori" and stripped.startswith("origif:"):
                if records and records[-1].origif is None:
                    # the interface the state was created on: for NAT states, the egress (WAN, VPN, ...)
                    records[-1].origif = sys.intern(stripped.split()[1])
            elif start == "age" and header is not None and stripped.startswith("age "):
                record = _counters_record(header, line, stripped)
                if record:
                    records.append(record)
                    header = None
                    if limit is not None and len(records) > limit:
                        raise TooManyStates(len(records), limit)
    # only this walk's lines are kept: the cache never outgrows the state table
    _known_headers = seen
    return records


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


def flow_endpoints(record, local_addresses, networks=None, interface_addresses=None, primary_wan_device=None):
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
    elif nat and record["direction"] == "out" and private_ip(src) and public_ip(dst) \
            and record.get("origif") == primary_wan_device and src in (interface_addresses or {}).get(primary_wan_device, set()):
        # Outbound NAT through the configured primary WAN's RFC1918 address (upstream/double NAT).
        local = src
    elif nat and record["direction"] == "in" and private_ip(nat) and public_ip(src) \
            and record.get("origif") == primary_wan_device and nat in (interface_addresses or {}).get(primary_wan_device, set()):
        # An upstream port forward followed by this firewall's own port forward.
        local = nat
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
    # On inbound NAT, both the WAN translation and the protected target can be private behind
    # upstream NAT. PF's destination is the protected side; prefer it over the wire translation.
    sides = (record["dst"], record["nat"], record["src"]) if record.get("direction") == "in" \
        else (record["nat"], record["src"], record["dst"])
    for side in sides:
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


class StateFacts:
    """What the map reads from a state's endpoints, worked out once per state and kept while the
    state lasts: its flow (firewall, remote), inside host, who started it, its service and the
    tuple Suricata sees. Only the counters, the age and the TCP state change between samples.

    The flow tracker, the Suricata correlation and the threat history all walk the same sample;
    view() gives each of them the same answers, so none recomputes them per state.
    """

    class Facts:
        __slots__ = ("src", "dst", "nat", "origif", "rule", "pair", "inside", "lan_key", "src_is_remote",
                     "remote_started", "service_port", "service", "port_label", "target", "rule_key", "outside",
                     "inside_text", "public", "remote")

        def __init__(self, record, local_addresses, networks, interface_addresses=None, primary_wan_device=None):
            src, dst, nat = record["src"], record["dst"], record["nat"]
            self.src, self.dst, self.nat = src, dst, nat
            self.origif, self.rule = record.get("origif"), record.get("rule")
            # the inside-facing half of a NATed connection (see lan_rule_index)
            self.lan_key = None
            if self.rule and not nat and private_ip(src["address"]) and public_ip(dst["address"]):
                self.lan_key = (record["protocol"], src["address"], src["port"], dst["address"], dst["port"])
            self.inside = self.src_is_remote = self.remote_started = self.service_port = self.service = None
            self.port_label = self.target = self.rule_key = self.outside = self.inside_text = None
            self.public = self.remote = None
            self.pair = pair = flow_endpoints(record, local_addresses, networks, interface_addresses, primary_wan_device)
            if pair is None:
                return
            self.inside = inside = inside_endpoint(record, networks, local_addresses)
            self.src_is_remote = src["address"] == pair[1]
            self.remote_started, self.service_port = orientation(record, pair[1], networks, local_addresses)
            self.service = service_name(record["protocol"], self.service_port)
            self.port_label = service_port_label(record["protocol"], self.service_port)
            self.target = (remote_target(record, pair[1], pair[0], inside, self.service_port)
                           if self.remote_started else None)
            # rule_for(): the inside-facing state's rule, looked up per sample
            self.rule_key = None
            if inside:
                far = src if self.src_is_remote else dst
                self.rule_key = (record["protocol"], inside["address"], inside["port"], far["address"], far["port"])
            self.inside_text = host_port(inside["address"], inside["port"]) if inside else None
            self.outside = key = state_outside(record, pair)
            if key is not None:
                self.public, self.remote = host_port(key[1], key[2]), host_port(key[3], key[4])

        def rule_of(self, record, lan_rules):
            """rule_for() of this state in this sample."""
            if self.rule_key is not None and lan_rules:
                rule = lan_rules.get(self.rule_key)
                if rule:
                    return rule
            return record.rule

    def __init__(self):
        self.context = None
        self.known = {}

    def view(self, records, local_addresses, networks=None, interface_addresses=None, primary_wan_device=None):
        """([(record, facts)] in sample order, lan_rule_index(records)) for one sample."""
        # what the facts depend on besides the state itself (the collector replaces both, never edits them)
        context = (local_addresses, networks, interface_addresses, primary_wan_device)
        known = self.known if context == self.context else {}
        self.context = context
        fresh = {}
        views = []
        lan_rules = {}
        facts_of = StateFacts.Facts
        with _StringPool() as strings:
            for record in records:
                state_id = record.id
                facts = known.get(state_id)
                # the same state (and the same parsed header line: lines that differ never share Endpoints)
                if facts is None or facts.src is not record.src or facts.dst is not record.dst \
                        or facts.nat is not record.nat or facts.origif != record.origif or facts.rule != record.rule:
                    facts = facts_of(record, local_addresses, networks, interface_addresses, primary_wan_device)
                    facts.port_label = strings.share(facts.port_label)
                    facts.inside_text = strings.share(facts.inside_text)
                    facts.public = strings.share(facts.public)
                    facts.remote = strings.share(facts.remote)
                    facts.target = strings.share(facts.target)
                if state_id is not None:
                    fresh[state_id] = facts
                if facts.lan_key is not None:
                    lan_rules[facts.lan_key] = facts.rule
                views.append((record, facts))
        self.known = fresh
        return views, lan_rules


class TooManyStates(RuntimeError):
    """Reference parser fixture exceeded its explicit bound."""

    def __init__(self, count, limit):
        super().__init__(f"{count} states (limit {limit})")
        self.count, self.limit = count, limit


def remote_target(record, remote, local, inside, service_port):
    """The target of a state the remote side started.

    A reply state (the remote is not the source) is keyed by the server's own port; otherwise
    by the port the remote aimed at, which for a port forward is the inside host's port.
    """
    if record["src"]["address"] != remote:
        port = service_port
    else:
        port = (inside or record["dst"])["port"]
    return connection_target(record["protocol"], inside["address"] if inside else local, port)


def __getattr__(name):
    """Expose retained production PF helpers without copying them into the oracle."""
    return getattr(shared, name)
