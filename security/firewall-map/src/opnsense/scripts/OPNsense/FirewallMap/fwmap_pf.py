#!/usr/local/bin/python3

"""PF state table, ruleset and interface parsing for Firewall Map+."""

import ipaddress
import re
import subprocess
import xml.etree.ElementTree as ElementTree

from fwmap_common import CONFIG_XML, PFCTL, RULES_DEBUG, private_ipv4, public_ipv4


IFCONFIG = "/sbin/ifconfig"
COUNTERS = re.compile(r"(?P<packets_in>\d+):(?P<packets_out>\d+) pkts,\s+(?P<bytes_in>\d+):(?P<bytes_out>\d+) bytes")
AGE = re.compile(r"\bage (?:(?P<days>\d+)d)?(?P<h>\d+):(?P<m>\d+):(?P<s>\d+)")
RLABEL = re.compile(r"\brlabel ([^,\s]+)")
STATE_ID = re.compile(r"\bid: (?P<id>[0-9a-f]+) creatorid: (?P<creator>[0-9a-f]+)")
ENDPOINT = re.compile(r"^(?P<address>.+?)(?::(?P<port>\d+))?$")


def endpoint(value):
    """Split a PF endpoint while keeping address parsing deliberately IPv4-only."""
    value = value.strip("()")
    # fast path for the common "a.b.c.d:port" / "a.b.c.d" forms (no regex: this runs per state)
    if value.count(":") <= 1:
        address, _, port = value.partition(":")
        if address and (not port or port.isdigit()):
            return {"address": address, "port": port or None}
    match = ENDPOINT.match(value)
    if not match:
        return {"address": None, "port": None}
    return {"address": match.group("address"), "port": match.group("port")}


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
    if not translated and not public_ipv4(left["address"]) and not public_ipv4(right["address"]):
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
            int(age.group("days") or 0) * 86400 + int(age.group("h")) * 3600
            + int(age.group("m")) * 60 + int(age.group("s"))
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


def flow_endpoints(record, local_addresses):
    """Return (firewall public address, remote address) or None for non-map traffic.

    NAT states carry the firewall's public address explicitly; other states are kept
    only when one endpoint is a public address configured on this firewall.
    """
    src = record["src"]["address"]
    dst = record["dst"]["address"]
    nat = record["nat"]["address"] if record["nat"] else None
    if nat and public_ipv4(nat):
        local = nat
    elif src in local_addresses:
        local = src
    elif dst in local_addresses:
        local = dst
    elif nat and private_ipv4(src) and public_ipv4(dst) and local_addresses:
        # outbound NAT to a tunnel address (e.g. a WireGuard or IPsec egress): draw it from the
        # firewall's own location, the egress interface tells which path it took
        local = min(local_addresses)
        return local, dst
    else:
        return None
    remote = dst if local == src else src
    if not public_ipv4(remote) or remote == local or remote in local_addresses:
        return None
    return local, remote


def inside_endpoint(record):
    """The LAN endpoint behind a NAT state (the private one among source, destination and NAT)."""
    for side in (record["nat"], record["src"], record["dst"]):
        if side and private_ipv4(side["address"]):
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
        if private_ipv4(src["address"]) and public_ipv4(dst["address"]):
            index[(record["protocol"], src["address"], src["port"], dst["address"], dst["port"])] = rule
    return index


def rule_for(record, pair, lan_rules):
    inside = inside_endpoint(record)
    if inside and lan_rules:
        far = record["src"] if record["src"]["address"] == pair[1] else record["dst"]
        rule = lan_rules.get((record["protocol"], inside["address"], inside["port"], far["address"], far["port"]))
        if rule:
            return rule
    return record.get("rule")


def orientation(record, remote):
    """(remote started it, the service's port) for one state.

    A state normally starts at its initiator. When the opening packet passed the other CARP
    node (asymmetric paths), the reply from an inside server creates an "outbound" state from a
    well-known port to an ephemeral one: that connection was really started by the remote side.
    """
    if record["src"]["address"] == remote:
        return True, record["dst"]["port"]
    # behind outbound NAT the source port that matters is the inside host's, not the translated one
    source, target = (inside_endpoint(record) or record["src"])["port"], record["dst"]["port"]
    # the client side must look ephemeral: keeps NFS (reserved port to 2049) and IKE (500 to 4500) outbound
    if (record["protocol"] in ("tcp", "udp") and source and target and source.isdigit() and target.isdigit()
            and int(source) < 1024 and int(target) >= 10000):
        return True, source
    return False, target


def interface_networks(output):
    """[(IPv4Network, device)] for every IPv4 address configured on an interface."""
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
    # most specific first, so a host matches its own subnet before a wider one
    networks.sort(key=lambda item: -item[0].prefixlen)
    return networks


def host_info():
    """Return (public IPv4 addresses on this firewall, CARP role or None, interface networks)."""
    try:
        output = subprocess.run(
            [IFCONFIG, "-a"], capture_output=True, check=False, text=True, timeout=2,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return set(), None, []
    addresses = {address for address in re.findall(r"\binet\s+(\d+(?:\.\d+){3})", output) if public_ipv4(address)}
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
        root = ElementTree.parse(config).getroot()
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
        interfaces = ElementTree.parse(path).getroot().find("interfaces")
    except (OSError, ElementTree.ParseError):
        return names
    for node in list(interfaces) if interfaces is not None else []:
        device = node.findtext("if")
        if device:
            names[device] = (node.findtext("descr") or "").strip() or node.tag.upper()
    return names


PORT_FORWARD = re.compile(
    r"^rdr (?:pass )?on (?P<iface>\S+) inet proto (?P<proto>\{[^}]*\}|\S+) from .*? to .*? port \{?(?P<ports>[\d:, ]+)\}?"
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
                if not target or not private_ipv4(target):
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
            return f'{forward["target"]}:{forward["target_port"] or port}', forward["description"]
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
    # firewall's own randomised DNS ports, is only right on the wire side
    if record["direction"] == "out":
        public = record["src"]
    else:
        public = nat if nat else record["dst"]
    if public["address"] != local:
        return None  # NAT to a tunnel address: Suricata on WAN never sees this tuple
    far = record["src"] if record["src"]["address"] == remote else record["dst"]
    if far["address"] != remote:
        return None
    return outside_key(record["protocol"], local, public["port"], remote, far["port"])


# Walking the state table costs about 2 kB of memory and 20 µs per state; above this many states
# (a flood, or a very busy firewall) the map stops sampling instead of risking the firewall's memory
MAX_SAMPLED_STATES = 100000
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


def sample_states(limit=MAX_SAMPLED_STATES):
    count = state_count()
    if count is not None and count > limit:
        raise TooManyStates(count, limit)
    result = subprocess.run(
        [PFCTL, "-vv", "-s", "state"], capture_output=True, check=False, text=True, timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError("pfctl failed")
    return parse_states(result.stdout)
