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


"""Client of the package-owned PF state collector (firewallmap-collector).

The collector speaks exactly one protocol, PROTOCOL_VERSION; the wire formats
are specified in collector/PROTOCOL.md. A collector announcing any other
protocol comes from a different package version: that is an installation
problem (CollectorIncompatible), not a transient failure, and the same binary
is never started again. A collector built for another PF state ABI than the
running kernel's is just as persistent: it is started again only when the
binary or the running kernel changed. Every response is validated completely (framing,
record order, counts, checksum) before any of it is used; anything unexpected
closes the collector, so a stream is never resynchronized. Python never
supplies elapsed time: the collector anchors each sample itself and reports a
baseline (interval < 0) when it has none.

Compatibility names: decoded event matches keep the historical keys
``bytes_in`` (traffic from the remote) and ``bytes_out`` (traffic to the
remote); flow rows use the explicit ``*_from_remote``/``*_to_remote`` names.
"""

import ipaddress
import json
import math
import os
import re
import select
import socket
import struct
import subprocess
import tempfile
import time
import zlib

from . import classification, common, evidence as evidence_facts, profiles

HELPER = "/usr/local/libexec/firewallmap-collector"
PROTOCOL_VERSION = 1
# the banner's first two fields are the same in every protocol; the rest is protocol 1's
BANNER_PROTOCOL = re.compile(rb"^FMCOLLECTOR protocol=(\d{1,9})[ \n]")
BANNER = re.compile(rb"^FMCOLLECTOR protocol=1 pf_state_version=(\d{1,10}) freebsd_version=(\d{1,10})\n$")
MAX_FRAME = 4096
# a response must complete within this; the window grows with the helper's own measured cost
READ_TIMEOUT = 20
READ_TIMEOUT_MAX = 120
READ_TIMEOUT_FACTOR = 3
PROTO_NUMBERS = {"icmp": 1, "tcp": 6, "udp": 17, "ipv6-icmp": 58, "sctp": 132}
SNAPSHOT_FLOWS = 5000
SNAPSHOT_BYTES = 10 * 1024 * 1024
SNAPSHOT_STATES = 5000
MAX_EVENT_QUERIES = 2500

# Resource budgets (collector/budget.h, PROTOCOL.md): the helper enforces the same maxima.
RANKED_FLOWS = 150
CANDIDATES_PER_KIND = 16
THREAT_REMOTES = 20000
MEMORY_MIN_MIB, MEMORY_MAX_MIB, MEMORY_AUTO_MAX_MIB = 64, 16384, 1024
MEMORY_AUTO_SHARE = 0.05
# operator context maxima: over them a sample is refused, naming the kind (never truncated)
CONTEXT_MAXIMA = {"L": 4096, "N": 8192, "A": 1024}
_FLOW_RECORD, _CANDIDATE_RECORD, _THREAT_REMOTE_RECORD, _THREAT_CANDIDATE_RECORD = 182, 100, 62, 92
_EVENT_RECORD, _CLASSIFIED_RECORD, _CLASS_SET_RECORD, _FIXED_RECORDS = 198, 40, 16, 4096
# classification (collector/classify.h): PF tables given Firewall Map meaning, one bit each
CLASS_MAX_SETS, CLASS_MAX_ADDRESSES = 64, 20000
CLASS_CATEGORIES = ("T", "C", "O")  # threat, country, operational
CLASS_STATUSES = {0: "ok", 1: "missing", 2: "too_large", 3: "unreadable"}
_TABLE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,31}$")
_GENERATION = re.compile(r"^[!-~]{1,63}$")

# FMAGG4 record kinds
HEADER, FLOW, CANDIDATE, THREAT_REMOTE, THREAT_CANDIDATE, EVENT_MATCH, TELEMETRY, CLASSIFIED, CLASS_SET = range(9)
SNAPSHOT_CANDIDATE = 10
FAILURE, FOOTER = 254, 255
# record order within a response; telemetry, then the footer, end it
_ORDER = {FLOW: 1, CANDIDATE: 2, THREAT_REMOTE: 3, THREAT_CANDIDATE: 4, EVENT_MATCH: 5, CLASSIFIED: 6,
          CLASS_SET: 7, SNAPSHOT_CANDIDATE: 8}
_SNAPSHOT_CANDIDATE = struct.Struct("!17s17sBBdQQ")
# candidate kinds
PROTOCOL, INSIDE_HOST, EGRESS_INTERFACE, SERVICE, REMOTE_TARGET, RULE_LABEL = range(1, 7)
THREAT_CANDIDATE_KINDS = (INSIDE_HOST, SERVICE, REMOTE_TARGET)
EVENT_MATCH_CURRENT, EVENT_MATCH_RECENT = 1, 2  # a state in this sample, one seen recently
EVENT_MATCH_KINDS = (EVENT_MATCH_CURRENT, EVENT_MATCH_RECENT)
OUTCOMES = {0: "sample", 1: "refused_states", 2: "refused_context", 3: "refused_memory"}
FAILURE_CLASSES = {1: "structural", 2: "internal", 3: "incompatible", 4: "resources", 5: "request"}
# FMSTATE2 omission reason bits and selection policies
OMISSION_REASONS = ((1, "encoded_bytes"), (2, "state_count"), (4, "per_flow_evidence_limit"))
SELECTION_POLICIES = {2: "bytes_desc_newest_identity_v1"}

_FLOW = struct.Struct("!I17s17sQQQIIQQQQQQQBBIIBdddddBI")
SECURITY_CLASSES = ("S0", "S1", "S2", "S3")
# why a flow may be on the map (collector/profile.h): "none" only where the collector did not
# decide (the base ranking, snapshot selections)
PRESENCES = ("none", "traffic", "probe", "mirror")
# CARP addresses a request may name (CARP rows)
CARP_ADDRESSES_MAX = 256
_TELEMETRY = struct.Struct("!IQddddd" + "Q" * 42)
_TELEMETRY_FIELDS = ("pid", "sequence", "interval", "dump_seconds", "processing_seconds", "user_cpu",
                     "system_cpu", "max_rss", "heap_bytes", "heap_peak", "heap_blocks", "heap_budget",
                     "state_limit", "preflight_states", "skipped_af_translation", "candidates_omitted",
                     "threat_remotes_omitted", "threat_candidates_omitted", "event_history_evicted",
                     "classifier_bytes", "snapshot_candidates_omitted", "regime", "next_regime", "quality_discovery", "quality_ranking",
                     "quality_attribution", "discovery_error", "flows_total", "flows_estimated",
                     "tracked_flows", "tracked_limit", "exit_threshold", "forced_limit", "forced_flows",
                     "forced_refused", "candidate_limit", "candidate_evictions", "join_limit", "join_refused",
                     "untracked_states", "promoted", "baseline_bytes", "tracked_bytes", "candidate_bytes",
                     "join_bytes", "ranking_bytes", "discovery_bytes", "recommended_interval_ms", "cadence_reason")
# why the collector recommends its sampling interval (collector/cadence.h)
CADENCE_REASONS = ("floor", "duty", "memory", "refused")
# the quality axes (collector/CONTRACTS.md), as the telemetry numbers them
REGIMES = ("exact", "bounded")
QUALITY = {"discovery": ("exact", "bounded"), "ranking": ("exact", "warming", "bounded"),
           "attribution": ("exact", "warming", "partial")}
_FOOTER = struct.Struct("!IIQQQQQQQQQQQQQQI")


class CollectorError(RuntimeError):
    """The collector was absent, incompatible, or failed its complete sample.

    failure_class names the collector's own classification (FMFAIL1) when it
    gave one: structural, internal, incompatible, resources or request.
    """

    def __init__(self, message, failure_class=None):
        super().__init__(message)
        self.failure_class = failure_class


class CollectorIncompatible(CollectorError):
    """A persistent incompatibility; reason names it:

    * "protocol": the installed collector speaks another protocol (protocol: the one it
      announced, or None when its banner names none): the package's components come from
      different versions.
    * "pf_abi": the collector speaks this protocol but was built for another PF state ABI
      than the running kernel's (each version None when it is not known).
    """

    def __init__(self, reason, protocol=PROTOCOL_VERSION, collector_pf_state_version=None,
                 running_pf_state_version=None):
        if reason == "protocol":
            announced = "an unknown protocol" if protocol is None else f"protocol {protocol}"
            message = f"the collector uses {announced}; this Firewall Map expects protocol {PROTOCOL_VERSION}"
        else:
            def known(value):
                return "unknown" if value is None else value
            message = (f"PF state ABI mismatch: the collector was built for PF state version "
                       f"{known(collector_pf_state_version)}, the running kernel uses "
                       f"{known(running_pf_state_version)}")
        super().__init__(message, "incompatible")
        self.reason = reason
        self.protocol = protocol
        self.collector_pf_state_version = collector_pf_state_version
        self.running_pf_state_version = running_pf_state_version


# the collector's own report of an ABI mismatch (collector/pf_reader.c)
_PF_ABI_MISMATCH = re.compile(r"PF state ABI version (\d+), collector built for (\d+)")


def kernel_identity():
    """The running kernel, as uname reports it (kern.osrelease and kern.version, which names
    the build): it changes only when the firewall boots another kernel."""
    info = os.uname()
    return info.release, info.version


def available(path=HELPER):
    return os.path.isfile(path) and os.access(path, os.X_OK)


def self_test(path=HELPER, timeout=READ_TIMEOUT_MAX):
    """The helper's own compatibility check (one PF dump, no aggregation): a dict with ok,
    and class/error on failure. An incompatible PF ABI has class "incompatible"."""
    if not available(path):
        return {"ok": False, "class": "unavailable", "error": "collector unavailable"}
    try:
        result = subprocess.run([path, "--selftest"], capture_output=True, text=True, timeout=timeout, check=False)
        report = json.loads(result.stdout.strip().splitlines()[-1])
    except (OSError, subprocess.TimeoutExpired, ValueError, IndexError) as error:
        return {"ok": False, "class": "unknown", "error": str(error)}
    return report if isinstance(report, dict) else {"ok": False, "class": "unknown", "error": "malformed report"}


def kernel_version():
    """The running kernel's __FreeBSD_version (kern.osreldate), or None elsewhere."""
    try:
        output = subprocess.run(["/sbin/sysctl", "-n", "kern.osreldate"], capture_output=True, text=True,
                                timeout=2, check=False).stdout
        return int(output.strip())
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def memory_budget(setting_mib=None, physical=None):
    """The helper's memory budget in bytes: the setting, or 5% of RAM capped at 1 GiB."""
    if setting_mib is not None:
        return max(MEMORY_MIN_MIB, min(MEMORY_MAX_MIB, int(setting_mib))) << 20
    if physical is None:
        try:
            physical = os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
        except (OSError, ValueError, AttributeError):
            physical = 0
    automatic = int(physical * MEMORY_AUTO_SHARE) >> 20 if physical > 0 else MEMORY_AUTO_MAX_MIB
    return max(MEMORY_MIN_MIB, min(MEMORY_AUTO_MAX_MIB, automatic)) << 20


def response_byte_limit(candidates_per_kind=CANDIDATES_PER_KIND, threat_remotes=THREAT_REMOTES,
                        queries=MAX_EVENT_QUERIES, classify=CLASS_MAX_ADDRESSES, class_sets=CLASS_MAX_SETS):
    """The largest FMAGG4 response the budgets allow (framing included); more is a helper bug."""
    flows = RANKED_FLOWS * (_FLOW_RECORD + RULE_LABEL * candidates_per_kind * _CANDIDATE_RECORD)
    threats = threat_remotes * (_THREAT_REMOTE_RECORD + len(THREAT_CANDIDATE_KINDS) * candidates_per_kind
                                * _THREAT_CANDIDATE_RECORD)
    classes = classify * _CLASSIFIED_RECORD + class_sets * _CLASS_SET_RECORD
    classes += SNAPSHOT_FLOWS * (5 + _SNAPSHOT_CANDIDATE.size)
    return 8 + flows + threats + queries * _EVENT_RECORD + classes + _FIXED_RECORDS


def _context_address(value):
    """Canonical text of a context address, or None for one that cannot matter: loopback
    and link-local addresses never take part in a retained state."""
    try:
        address = ipaddress.ip_address(str(value).split("%", 1)[0])
    except ValueError:
        return None
    if address.is_loopback or address.is_link_local:
        return None
    return str(address)


def _context_rows(local_addresses, networks, interface_addresses, primary_wan_device):
    """(rows, refusal): the request's context, deduplicated, or the first maximum it exceeds."""
    rows = classification.rows()
    local = sorted({address for address in map(_context_address, local_addresses) if address})
    seen_networks, network_rows = set(), []
    for network, device in networks:
        if network.is_loopback or network.is_link_local or (network, device) in seen_networks:
            continue
        seen_networks.add((network, device))
        network_rows.append(f"N {network.network_address} {network.prefixlen} {device}")
    assigned = sorted({(device, address) for device, addresses in interface_addresses.items()
                       for address in map(_context_address, addresses) if address})
    for kind, count in (("L", len(local)), ("N", len(network_rows)), ("A", len(assigned))):
        if count > CONTEXT_MAXIMA[kind]:
            return None, {"reason": "refused_context", "kind": kind, "actual": count,
                          "limit": CONTEXT_MAXIMA[kind]}
    rows.extend(f"L {address}" for address in local)
    rows.extend(network_rows)
    rows.extend(f"A {address} {device}" for device, address in assigned)
    if primary_wan_device:
        rows.append(f"W {primary_wan_device}")
    groups = {}
    for (protocol, port), name in common.SERVICES.items():
        number = PROTO_NUMBERS.get(protocol)
        if number is None:
            try:
                number = socket.getprotobyname(protocol)
            except OSError as error:
                raise CollectorError(f"unsupported service protocol {protocol}") from error
        groups.setdefault(name, len(groups) + 2)
        rows.append(f"S {number} {port} {groups[name]}")
    return rows, None


def _address(data):
    if len(data) != 17 or data[0] not in (4, 6):
        raise CollectorError("invalid collector address")
    if data[0] == 4:
        if any(data[5:]):
            raise CollectorError("noncanonical IPv4 address")
        return str(ipaddress.IPv4Address(data[1:5]))
    return str(ipaddress.IPv6Address(data[1:]))


def _text(data, encoding="utf-8"):
    """A NUL-padded kernel string; never fails on a byte sequence PF truncated."""
    return data.split(b"\0", 1)[0].decode(encoding, "replace")


def _read_exact(stream, size, process, deadline):
    data = bytearray()
    descriptor = stream.fileno()
    while len(data) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([descriptor], [], [], remaining)[0]:
            raise CollectorError("collector response timed out")
        part = os.read(descriptor, size - len(data))
        if not part:
            code = process.poll()
            raise CollectorError(f"collector ended before its response was complete ({code})")
        data.extend(part)
    return bytes(data)


_READ_CHUNK = 1 << 16


def _frames(stream, process, deadline, byte_limit=None, received=8):
    """(frame bytes, payload) pairs; the footer (255) is the last one yielded.

    Reads in chunks (a large threat summary is tens of thousands of frames). The helper writes
    nothing after a footer until it is sent the next request, so a byte read past it is a
    protocol violation."""
    buffer, position, descriptor = bytearray(), 0, stream.fileno()

    def need(size):
        nonlocal buffer, position
        if position > _READ_CHUNK:
            buffer, position = buffer[position:], 0
        while len(buffer) - position < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([descriptor], [], [], remaining)[0]:
                raise CollectorError("collector response timed out")
            part = os.read(descriptor, max(size - (len(buffer) - position), _READ_CHUNK))
            if not part:
                code = process.poll()
                raise CollectorError(f"collector ended before its response was complete ({code})")
            buffer.extend(part)

    while True:
        need(4)
        size = bytes(buffer[position:position + 4])
        length, = struct.unpack("!I", size)
        received += length + 4
        if not 0 < length <= MAX_FRAME:
            raise CollectorError("collector frame size")
        if byte_limit is not None and received > byte_limit:
            raise CollectorError("collector response exceeds its byte ceiling")
        need(4 + length)
        data = bytes(buffer[position + 4:position + 4 + length])
        position += 4 + length
        yield size, data
        if data[0] == FOOTER:
            if position != len(buffer):
                raise CollectorError("collector wrote past its response")
            return


def _failure(stream, process, deadline):
    size = _read_exact(stream, 4, process, deadline)
    length, = struct.unpack("!I", size)
    if not 9 <= length <= MAX_FRAME:
        raise CollectorError("malformed collector failure report")
    data = _read_exact(stream, length, process, deadline)
    if data[0] != FAILURE:
        raise CollectorError("malformed collector failure report")
    failure_class, code = struct.unpack_from("!Ii", data, 1)
    message = data[9:].decode("utf-8", "replace")
    name = FAILURE_CLASSES.get(failure_class, "unknown")
    return CollectorError(f"collector failed ({name}, errno {code}): {message}", name)


def _magic(stream, process, deadline, expected):
    magic = _read_exact(stream, 8, process, deadline)
    if magic == b"FMFAIL1\0":
        raise _failure(stream, process, deadline)
    if magic != expected:
        raise CollectorError(f"unexpected collector response {magic!r}")


def _class_rows(classification, classify):
    """(rows, categories by set ID, addresses asked about) for the request's classification."""
    rows, categories, asked = [], [], set()
    if classification is not None:
        generation, sets = classification
        if len(sets) > CLASS_MAX_SETS or (sets and not _GENERATION.match(str(generation))):
            raise CollectorError("invalid classification request")
        names = set()
        for category, name in sets:
            if category not in CLASS_CATEGORIES or not _TABLE_NAME.match(name) or name in names:
                raise CollectorError("invalid classification set")
            names.add(name)
            rows.append(f"CLASS {len(categories)} {category} {name}")
            categories.append(category)
        if sets:
            rows.append(f"CLASSGEN {generation}")
    for address in map(_context_address, classify):
        if address and address not in asked and len(asked) < CLASS_MAX_ADDRESSES:
            asked.add(address)
            rows.append(f"K {address}")
    return rows, categories, asked


def _evidence_rows(evidence):
    """EVIDENCE rows: at most THREAT_REMOTES remotes, the strongest evidence first when over
    (high-severity IDS, other IDS, then by blocked hits); the order of the rows does not matter."""
    rows = {}
    for address, (mask, blocked, alerts, severity) in evidence.items():
        address = _context_address(address)
        if address is None or not mask:
            continue
        if mask & ~evidence_facts.REQUEST_BITS or (mask, blocked, alerts, severity) != evidence_facts.facts(
                blocked, alerts, severity, bool(mask & evidence_facts.REPUTATION)):
            raise CollectorError("inconsistent evidence facts")
        rows[address] = (mask, blocked, alerts, severity)
    strongest = sorted(rows, key=lambda address: (not rows[address][0] & evidence_facts.IDS_HIGH,
                                                  not rows[address][0] & evidence_facts.IDS,
                                                  -rows[address][1], address))[:THREAT_REMOTES]
    return [f"EVIDENCE {address} {' '.join(map(str, rows[address]))}" for address in sorted(strongest)]


def _class_mask(mask, categories):
    if mask >> len(categories):
        raise CollectorError("FMAGG4 classification outside the requested sets")
    return mask


def _decode(stream, process, query_keys, require_threat_summary, flow_limit=RANKED_FLOWS, byte_limit=None,
            timeout=None, categories=(), asked=frozenset()):
    """Read one complete FMAGG4 response."""
    deadline = time.monotonic() + (timeout or READ_TIMEOUT)
    _magic(stream, process, deadline, b"FMAGG4\0\0")
    checksum, threats_present, telemetry, footer, previous_kind = 0, None, None, None, HEADER
    flows, candidates, matches = [], [], {}
    threat_remotes, threat_candidates = [], []
    classified, class_sets, remotes, snapshot = {}, [], {}, []
    for size, data in _frames(stream, process, deadline, byte_limit):
        kind = data[0]
        if kind != FOOTER:
            checksum = zlib.crc32(data, zlib.crc32(size, checksum))
        if threats_present is None:
            if kind != HEADER or len(data) != 9:
                raise CollectorError("FMAGG4 header missing")
            version, flags = struct.unpack_from("!II", data, 1)
            if version != PROTOCOL_VERSION or flags & ~1:
                raise CollectorError("FMAGG4 header version or flags")
            threats_present = bool(flags & 1)
            if require_threat_summary and not threats_present:
                raise CollectorError("FMAGG4 threat summary missing")
            continue
        if telemetry is not None and kind != FOOTER:
            raise CollectorError("FMAGG4 record after telemetry")
        rank = _ORDER.get(kind)
        if rank is not None:
            if rank < previous_kind:
                raise CollectorError("FMAGG4 record order")
            previous_kind = rank
        if kind == FLOW:
            if len(data) != 1 + _FLOW.size:
                raise CollectorError("invalid FMAGG4 flow record")
            (rank, local, remote, states, from_remote, to_remote, oldest, youngest, remote_weight, local_weight,
             first, delta_from, delta_to, delta_packets, classes, evidence_mask, security_class, blocked_hits,
             ids_alerts, ids_severity, rate_from, rate_to, packet_rate, activity, score, presence,
             attempts) = _FLOW.unpack_from(data, 1)
            if presence >= len(PRESENCES):
                raise CollectorError("invalid FMAGG4 flow presence")
            if evidence_mask & ~(evidence_facts.REQUEST_BITS | evidence_facts.THREAT_LIST) \
                    or security_class >= len(SECURITY_CLASSES) or ids_severity > 3:
                raise CollectorError("invalid FMAGG4 flow evidence")
            if rank != len(flows) or not all(math.isfinite(value) and value >= 0 for value in
                                             (rate_from, rate_to, packet_rate, activity, score)):
                raise CollectorError("invalid FMAGG4 flow rank or rate")
            flows.append({"key": (_address(local), _address(remote)), "states": states,
                          "bytes_from_remote": from_remote, "bytes_to_remote": to_remote,
                          "oldest": oldest, "youngest": youngest,
                          "remote_initiated_weight": remote_weight, "local_initiated_weight": local_weight,
                          "first": first, "delta_bytes_from_remote": delta_from,
                          "delta_bytes_to_remote": delta_to, "delta_packets": delta_packets,
                          "rate_from_remote": rate_from, "rate_to_remote": rate_to,
                          "packet_rate": packet_rate, "activity": activity, "score": score,
                          "classes": _class_mask(classes, categories),
                          # each evidence source its own fact; the class is the collector's derivation
                          "evidence": {"mask": evidence_mask, "blocked_hits": blocked_hits,
                                       "ids_alerts": ids_alerts, "ids_severity": ids_severity},
                          "security_class": SECURITY_CLASSES[security_class],
                          "presence": PRESENCES[presence], "attempts": attempts})
        elif kind == CANDIDATE:
            if len(data) < 32:
                raise CollectorError("invalid FMAGG4 candidate record")
            flow, candidate_kind, sequence, weight, association, length = struct.unpack_from("!IBQQQH", data, 1)
            if flow >= len(flows) or candidate_kind not in range(PROTOCOL, RULE_LABEL + 1) \
                    or length != len(data) - 32:
                raise CollectorError("invalid FMAGG4 candidate identity")
            candidates.append((flow, candidate_kind, sequence, weight, association, data[32:]))
        elif kind == THREAT_REMOTE:
            if not threats_present or len(data) != 58:
                raise CollectorError("invalid FMAGG4 threat remote")
            index, = struct.unpack_from("!I", data, 1)
            remote_states, local_states, transferred, classes, youngest = struct.unpack_from("!QQQQI", data, 22)
            if index != len(threat_remotes):
                raise CollectorError("FMAGG4 threat remote order")
            threat_remotes.append({"address": _address(data[5:22]), "remote_initiated_states": remote_states,
                                   "local_initiated_states": local_states, "bytes": transferred,
                                   "classes": _class_mask(classes, categories), "youngest": youngest})
        elif kind == THREAT_CANDIDATE:
            if not threats_present or len(data) < 24:
                raise CollectorError("invalid FMAGG4 threat candidate")
            remote, candidate_kind, sequence, association, length = struct.unpack_from("!IBQQH", data, 1)
            if remote >= len(threat_remotes) or candidate_kind not in THREAT_CANDIDATE_KINDS \
                    or length != len(data) - 24:
                raise CollectorError("invalid FMAGG4 threat candidate identity")
            threat_candidates.append((remote, candidate_kind, sequence, association, data[24:]))
        elif kind == EVENT_MATCH:
            key, match = _event_match(data, query_keys)
            if key in matches:
                raise CollectorError("FMAGG4 duplicate event match")
            matches[key] = match
        elif kind == CLASSIFIED:
            if len(data) != 36:
                raise CollectorError("invalid FMAGG4 classified address")
            address = _address(data[1:18])
            mask, evidence_mask, security_class, states = struct.unpack_from("!QBBQ", data, 18)
            if address not in asked or address in remotes or not (mask or evidence_mask or states) \
                    or evidence_mask & ~(evidence_facts.REQUEST_BITS | evidence_facts.THREAT_LIST) \
                    or security_class >= len(SECURITY_CLASSES) or bool(security_class) != bool(evidence_mask):
                raise CollectorError("invalid FMAGG4 classified address identity")
            remotes[address] = {"classes": _class_mask(mask, categories), "evidence": evidence_mask,
                                "security_class": SECURITY_CLASSES[security_class], "states": states}
            if mask:
                classified[address] = mask
        elif kind == SNAPSHOT_CANDIDATE:
            if len(data) != 1 + _SNAPSHOT_CANDIDATE.size or len(snapshot) >= SNAPSHOT_FLOWS:
                raise CollectorError("invalid FMAGG4 snapshot candidate")
            local, remote, evidence_mask, security_class, score, order, states = \
                _SNAPSHOT_CANDIDATE.unpack_from(data, 1)
            if evidence_mask & ~(evidence_facts.REQUEST_BITS | evidence_facts.THREAT_LIST) \
                    or security_class >= len(SECURITY_CLASSES) or bool(security_class) != bool(evidence_mask) \
                    or not (math.isfinite(score) and score >= 0):
                raise CollectorError("invalid FMAGG4 snapshot candidate")
            snapshot.append({"local": _address(local), "remote": _address(remote), "evidence": evidence_mask,
                             "security_class": SECURITY_CLASSES[security_class], "score": score, "order": order,
                             "states": states})
        elif kind == CLASS_SET:
            if len(data) != 12:
                raise CollectorError("invalid FMAGG4 classification set")
            set_id, category, status, entries = struct.unpack_from("!BBBQ", data, 1)
            if set_id != len(class_sets) or set_id >= len(categories) or chr(category) != categories[set_id] \
                    or status not in CLASS_STATUSES or (status and entries):
                raise CollectorError("invalid FMAGG4 classification set identity")
            class_sets.append({"id": set_id, "category": categories[set_id], "status": CLASS_STATUSES[status],
                               "entries": entries})
        elif kind == TELEMETRY:
            if len(data) != 1 + _TELEMETRY.size:
                raise CollectorError("invalid FMAGG4 telemetry")
            telemetry = dict(zip(_TELEMETRY_FIELDS, _TELEMETRY.unpack_from(data, 1)))
            if not all(math.isfinite(telemetry[name]) for name in _TELEMETRY_FIELDS[2:7]) \
                    or telemetry["regime"] >= len(REGIMES) or telemetry["next_regime"] >= len(REGIMES) \
                    or telemetry["flows_estimated"] > 1 \
                    or any(telemetry[f"quality_{axis}"] >= len(values) for axis, values in QUALITY.items()):
                raise CollectorError("invalid FMAGG4 telemetry")
        elif kind == FOOTER:
            if len(data) != 1 + _FOOTER.size:
                raise CollectorError("invalid FMAGG4 footer")
            footer = _FOOTER.unpack_from(data, 1)
        else:
            raise CollectorError("unknown FMAGG4 record")
    if threats_present is None or telemetry is None or footer is None:
        raise CollectorError("incomplete FMAGG4 response")
    (outcome, context_kind, actual, limit, seen, retained, mapped, flow_total, flows_sent, candidates_sent,
     matches_sent, remotes_sent, remote_candidates_sent, classified_sent, class_sets_sent, snapshot_sent,
     expected) = footer
    records = (flows, candidates, matches, threat_remotes, threat_candidates, remotes, class_sets, snapshot)
    if expected != checksum or outcome not in OUTCOMES \
            or (flows_sent, candidates_sent, matches_sent, remotes_sent, remote_candidates_sent, classified_sent,
                class_sets_sent, snapshot_sent) != tuple(map(len, records)) \
            or len({(item["local"], item["remote"]) for item in snapshot}) != len(snapshot) \
            or len(flows) > flow_limit or not mapped <= retained <= seen \
            or sum(flow["states"] for flow in flows) > mapped \
            or (outcome and (any(records) or threats_present)):
        raise CollectorError("FMAGG4 completion validation failed")
    refused = OUTCOMES[outcome] if outcome else None
    # a sample that skipped unsupported states is semantically incomplete; event matches say so,
    # since a skipped state could have shared their outside tuple
    skipped = {"af_translation": telemetry["skipped_af_translation"]} if telemetry["skipped_af_translation"] else {}
    for match in matches.values():
        match["sample_degraded"] = bool(skipped)
    quality = {axis: values[telemetry[f"quality_{axis}"]] for axis, values in QUALITY.items()}
    if telemetry["discovery_error"] and quality["discovery"] == "bounded":
        quality["discovery_error"] = telemetry["discovery_error"]
    return {"flows": flows, "skipped": skipped, "candidates": candidates, "matches": matches,
            "quality": quality, "regime": REGIMES[telemetry["regime"]],
            "threat_remotes": threat_remotes, "threat_candidates": threat_candidates,
            "threat_summary": threats_present, "telemetry": telemetry,
            "classified": classified, "class_sets": class_sets,
            # per requested address: set mask, evidence, the collector's security class and its PF
            # states in tracked flows (whenever one of them is set)
            "remotes": remotes,
            # a sample that opened a snapshot session: what a snapshot may capture, in priority order
            "snapshot_candidates": snapshot,
            "baseline": telemetry["interval"] < 0,
            "refused": refused and {"reason": refused, "kind": chr(context_kind) if context_kind else None,
                                    "actual": actual, "limit": limit},
            "counts": {"states": seen, "retained": retained, "mapped": mapped, "flows": flow_total,
                       "flows_estimated": bool(telemetry["flows_estimated"]),
                       "tracked_flows": telemetry["tracked_flows"],
                       "captured_flows": len(flows), "candidates": len(candidates), "matches": len(matches),
                       "threat_remotes": len(threat_remotes), "threat_candidates": len(threat_candidates)}}


def _event_match(data, query_keys):
    if len(data) != 194:
        raise CollectorError("invalid FMAGG4 event match")
    query_id, match_kind, proto = struct.unpack_from("!HBB", data, 1)
    if query_id >= len(query_keys) or match_kind not in EVENT_MATCH_KINDS:
        raise CollectorError("invalid FMAGG4 event match identity")
    public, public_port = _address(data[5:22]), struct.unpack_from("!H", data, 22)[0]
    remote, remote_port = _address(data[24:41]), struct.unpack_from("!H", data, 41)[0]
    has_inside = data[43]
    inside_port, state_id, creator = struct.unpack_from("!HQI", data, 61)
    ambiguous = data[75]
    age, from_remote, to_remote, packets_from, packets_to = struct.unpack_from("!IQQQQ", data, 76)
    remote_initiated, apparent = data[112], data[113]
    if not {has_inside, ambiguous, remote_initiated, apparent} <= {0, 1}:
        raise CollectorError("invalid FMAGG4 event flags")
    try:
        protocol = common.protocol_name(proto)
    except (OSError, ValueError) as error:
        raise CollectorError("unknown FMAGG4 event protocol") from error
    key = (protocol, public, str(public_port) if public_port else "",
           remote, str(remote_port) if remote_port else "")
    if key != query_keys[query_id]:
        raise CollectorError("FMAGG4 event tuple mismatch")
    return key, {"kind": match_kind, "inside": _address(data[44:61]) if has_inside else None,
                 "inside_port": inside_port if has_inside else None,
                 "id": state_id, "creator": creator, "ambiguous": bool(ambiguous), "age": age,
                 # compatibility names: bytes_in is from the remote, bytes_out to the remote
                 "bytes_in": from_remote, "bytes_out": to_remote,
                 "packets_from_remote": packets_from, "packets_to_remote": packets_to,
                 "remote_initiated": bool(remote_initiated),
                 # historical name of the apparent-initiator heuristic
                 "remote_started": bool(apparent),
                 "interface": _text(data[114:130], "ascii"), "rule": _text(data[130:194]) or None}


class CollectorEngine:
    """One collector process owned by the Python service; its history lives across samples.

    Every request goes through _request: a request that does not complete
    cleanly, for any reason (including an exception raised while it is in
    flight), leaves the stream in an unknown position, so the helper is closed.
    """

    def __init__(self, path=HELPER, *, profile, profile_dir=None):
        self.path = path
        # the active ranking profile (a validated lib/profiles.py profile): startup configuration,
        # written as the schema-v1 document the helper compiles once. Required, never defaulted:
        # the service always passes the resolved active profile; only tests and devel tools pass
        # None, explicitly, for the base ranking (Classic, the regression oracle)
        self.profile = profile
        self.profile_dir = profile_dir
        self.process = None
        self.snapshot_open = False
        self.snapshot_generation = None
        self.snapshot_categories = ()
        self.metadata = None
        self.starts = 0
        self.last_error = None
        self.read_timeout = READ_TIMEOUT
        self.binary = None  # the identity of the binary the running process was started from
        # a persistent incompatibility: (binary identity, kernel identity or None when any kernel
        # gives the same answer, the CollectorIncompatible arguments)
        self.incompatible = None

    def _identity(self):
        try:
            info = os.stat(self.path)
        except OSError:
            return None
        return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns

    def _start(self):
        if not available(self.path):
            raise CollectorError("collector unavailable")
        identity = self._identity()
        if self.incompatible is not None:
            binary, kernel, arguments = self.incompatible
            if binary == identity and (kernel is None or kernel == kernel_identity()):
                # the same binary (and kernel): running it again would give the same answer
                raise CollectorIncompatible(**arguments)
            self.incompatible = None
        self.binary = identity
        try:
            startup = self._startup_file()
            try:
                arguments = [self.path] + (["--profile", startup] if startup else [])
                self.process = subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                                bufsize=0)
                self.starts += 1
                banner = bytearray()
                deadline = time.monotonic() + READ_TIMEOUT
                while not banner.endswith(b"\n") and len(banner) < 128:
                    banner += _read_exact(self.process.stdout, 1, self.process, deadline)
            finally:
                # the helper compiles the profile before its banner: the file is not needed after
                if startup:
                    os.unlink(startup)
            match = BANNER.match(bytes(banner))
            if not match:
                announced = BANNER_PROTOCOL.match(bytes(banner))
                protocol = int(announced.group(1)) if announced else None
                if protocol == PROTOCOL_VERSION:
                    raise CollectorError("malformed collector banner")
                self.incompatible = identity, None, {"reason": "protocol", "protocol": protocol}
                raise CollectorIncompatible(**self.incompatible[2])
            self.metadata = {"pid": self.process.pid, "protocol": PROTOCOL_VERSION,
                             "pf_state_version": int(match.group(1)), "freebsd_version": int(match.group(2))}
        except (OSError, CollectorError) as error:
            self.close()
            if isinstance(error, CollectorError):
                raise
            raise CollectorError("could not start the collector") from error

    def _request(self, text, decoder):
        if self.process is None or self.process.poll() is not None:
            raise CollectorError("collector is not running")
        try:
            self.process.stdin.write(text.encode("ascii"))
            self.process.stdin.flush()
            return decoder(self.process.stdout, self.process)
        except BaseException as error:
            # framing is unknown: never reuse this helper
            self.close()
            if isinstance(error, CollectorError) and error.failure_class == "incompatible":
                # the collector cannot read this kernel's PF states: persistent for this binary
                # and this running kernel
                reported = _PF_ABI_MISMATCH.search(str(error))
                arguments = {"reason": "pf_abi", "collector_pf_state_version": (self.metadata or {}).get(
                    "pf_state_version"), "running_pf_state_version": int(reported.group(1)) if reported else None}
                self.incompatible = self.binary, kernel_identity(), arguments
                error = CollectorIncompatible(**arguments)
            if isinstance(error, CollectorError):
                self.last_error = str(error)
                raise error
            if isinstance(error, (OSError, UnicodeError, ValueError, struct.error)):
                self.last_error = f"collector request failed: {error}"
                raise CollectorError(self.last_error) from error
            raise

    def sample(self, local_addresses, networks, interface_addresses, primary_wan_device,
               threat_summary=False, event_queries=(), snapshot=False, memory=None, evidence=None,
               correlation=True, classification=None, classify=(), carp_backup=(), mirror=False):
        """One complete sample. memory: the budget in bytes (default: automatic); evidence:
        {remote: lib.evidence facts} (sent every sample: the ranking, forced tracking and the
        threat summary use them); correlation: whether anything consumes
        IDS/block tuple matching (it is skipped otherwise); classification: (generation token,
        [(category, PF table)...]) in set-ID order, the helper re-reading the tables only when
        either changes; classify: addresses whose set masks the response carries. The flows come
        ranked by the profile the helper was started with (set_profile)."""
        rows, refused = _context_rows(local_addresses, networks, interface_addresses, primary_wan_device)
        if refused:
            # Python's own check; the helper would refuse the same request
            return {"flows": [], "candidates": [], "matches": {}, "threat_remotes": [], "threat_candidates": [],
                    "classified": {}, "class_sets": [], "remotes": {}, "snapshot_candidates": [],
                    "threat_summary": False, "telemetry": None, "baseline": False, "refused": refused,
                    "counts": {"states": 0, "retained": 0, "mapped": 0, "flows": 0, "captured_flows": 0,
                               "candidates": 0, "matches": 0, "threat_remotes": 0, "threat_candidates": 0},
                    "helper": dict(self.metadata or {}, starts=self.starts)}
        if self.process is None or self.process.poll() is not None:
            self.close()
            self._start()
        rows.append(f"BUDGET {memory or memory_budget()} {CANDIDATES_PER_KIND} {THREAT_REMOTES}")
        rows.append(f"CORRELATION {int(bool(correlation or event_queries))}")
        # the CARP addresses held as BACKUP: their flows are the master's (pfsync), mirrored on the
        # map or left out
        rows.append(f"MIRROR {int(bool(mirror))}")
        rows.extend(f"CARP {address}" for address in sorted(carp_backup)[:CARP_ADDRESSES_MAX])
        if threat_summary:
            rows.append("THREATS")
        rows.extend(_evidence_rows(evidence or {}))
        if snapshot:
            rows.append("SNAPSHOT")
        class_rows, categories, asked = _class_rows(classification, classify)
        rows.extend(class_rows)
        query_keys = []
        for protocol, public, public_port, remote, remote_port in event_queries[:MAX_EVENT_QUERIES]:
            number = PROTO_NUMBERS.get(protocol)
            if number is None:
                try:
                    number = socket.getprotobyname(protocol)
                except OSError:
                    continue
            query_keys.append((protocol, public, str(public_port or ""), remote, str(remote_port or "")))
            rows.append(f"Q {len(query_keys) - 1} {number} {public} {int(public_port or 0)} "
                        f"{remote} {int(remote_port or 0)}")
        text = "FMCONF2\n%sRUN\n" % "".join(row + "\n" for row in rows)
        limit = response_byte_limit(queries=len(query_keys), classify=len(asked), class_sets=len(categories))

        def decode(stream, process):
            decoded = _decode(stream, process, query_keys, threat_summary, byte_limit=limit,
                              timeout=self.read_timeout, categories=categories, asked=asked)
            # a sample reports every requested set's status
            if not decoded["refused"] and len(decoded["class_sets"]) != len(categories):
                raise CollectorError("FMAGG4 classification sets incomplete")
            return decoded
        result = self._request(text, decode)
        telemetry = result["telemetry"]
        # the next response may take as long as this one did, with a margin
        self.read_timeout = min(READ_TIMEOUT_MAX, max(READ_TIMEOUT, READ_TIMEOUT_FACTOR * (
            telemetry["dump_seconds"] + telemetry["processing_seconds"])))
        self.snapshot_open = snapshot and not result["refused"]
        # snapshot selections carry the flows' masks of this sample's classification
        self.snapshot_categories = categories
        self.snapshot_generation = result["telemetry"]["sequence"] if self.snapshot_open else None
        result["helper"] = dict(self.metadata or {}, starts=self.starts)
        return result

    def _startup_file(self):
        """The active profile's startup document in a private file (0600), or None."""
        if self.profile is None:
            return None
        directory = self.profile_dir or (common.RUN_DIR if os.path.isdir(common.RUN_DIR) else None)
        descriptor, path = tempfile.mkstemp(prefix="collector-profile-", suffix=".json", dir=directory)
        with os.fdopen(descriptor, "w") as handle:
            handle.write(profiles.startup_text(self.profile))
        return path

    @staticmethod
    def _profile_key(profile):
        return None if profile is None else (profile["uuid"], profiles.fingerprint(profile))

    def set_profile(self, profile):
        """The active ranking profile (validated). Another UUID or another definition of the active
        one (its fingerprint) closes the helper, which compiled the old one at startup: the next
        sample starts one with the new profile (a baseline). The same UUID and definition again
        (a rename, or an edit of another profile) changes nothing."""
        changed = self._profile_key(profile) != self._profile_key(self.profile)
        self.profile = profile
        if changed:
            self.close()
        return changed

    def snapshot_selection(self, identities):
        text = f"FMSNAP1 SELECT {self.snapshot_generation} {len(identities)}\n"
        text += _identity_rows(identities)
        result = self._request(text, lambda stream, process: _decode(
            stream, process, (), False, flow_limit=SNAPSHOT_FLOWS, byte_limit=SNAPSHOT_BYTES,
            timeout=self.read_timeout, categories=self.snapshot_categories))
        if [row["key"] for row in result["flows"]] != [tuple(item[:2]) for item in identities]:
            self.close()
            raise CollectorError("collector snapshot selection identity mismatch")
        return result

    def snapshot_detail(self, identities, byte_limit, state_limit=SNAPSHOT_STATES):
        if not 0 <= byte_limit <= SNAPSHOT_BYTES or not 0 < state_limit <= SNAPSHOT_STATES:
            raise CollectorError("invalid collector snapshot detail budget")
        text = f"FMSNAP1 DETAIL {self.snapshot_generation} {byte_limit} {state_limit} {len(identities)}\n"
        text += _identity_rows(identities)
        generation = self.snapshot_generation
        self.snapshot_open = False  # the session ends with this command, whatever its outcome
        return self._request(text, lambda stream, process: _decode_detail(
            stream, process, identities, generation, byte_limit, state_limit, self.read_timeout))

    def snapshot_cancel(self):
        """End an open session; a helper that cannot take the command is closed."""
        if self.process is None or not self.snapshot_open:
            self.snapshot_open = False
            return
        self.snapshot_open = False
        try:
            self.process.stdin.write(b"FMSNAP1 CANCEL\n")
            self.process.stdin.flush()
        except OSError:
            self.close()

    def close(self):
        self.snapshot_open = False
        self.snapshot_generation = None
        process, self.process = self.process, None
        if process is None:
            return
        try:
            process.stdin.close()
        except OSError:
            pass
        try:
            process.wait(timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            process.kill()
            process.wait()
        finally:
            process.stdout.close()


def _identity_rows(identities):
    if len(identities) > SNAPSHOT_FLOWS:
        raise CollectorError("too many collector snapshot identities")
    seen, rows = set(), []
    for local, remote, incident in identities:
        pair = (str(ipaddress.ip_address(local)), str(ipaddress.ip_address(remote)))
        if pair in seen or incident not in (True, False):
            raise CollectorError("duplicate/invalid collector snapshot identity")
        seen.add(pair)
        rows.append(f"F {pair[0]} {pair[1]} {int(incident)}\n")
    return "".join(rows) + "RUN\n"


def _snapshot_frames(stream, process, magic, byte_limit, timeout=None):
    deadline = time.monotonic() + (timeout or READ_TIMEOUT)
    _magic(stream, process, deadline, magic)
    checksum = 0
    for size, data in _frames(stream, process, deadline, byte_limit):
        if data[0] != FOOTER:
            checksum = zlib.crc32(data, zlib.crc32(size, checksum))
        yield data, checksum


_FLOW_TOTALS = struct.Struct("!IQQQQQQQQB")
_DETAIL_FOOTER = struct.Struct("!QQQQIIQIddd")


def _omission_reasons(bits):
    return [name for bit, name in OMISSION_REASONS if bits & bit]


def _decode_detail(stream, process, identities, generation, byte_limit, state_limit, timeout=None):
    started, rows, seen, actual_bytes, totals = False, {}, set(), 0, {}
    captured_by_flow = [0] * len(identities)
    # JSON rows dominate the stream; allow fixed framing, totals and completion overhead.
    ceiling = byte_limit + state_limit * 9 + len(identities) * (_FLOW_TOTALS.size + 5) + 128
    for data, checksum in _snapshot_frames(stream, process, b"FMSTATE2", ceiling, timeout):
        if data[0] == 0 and not started and len(data) == 13:
            version, received_generation = struct.unpack("!IQ", data[1:])
            if version != PROTOCOL_VERSION or received_generation != generation:
                raise CollectorError("collector snapshot detail generation/version")
            started = True
        elif data[0] == 1 and started and not totals and len(data) > 5:
            flow_id, = struct.unpack("!I", data[1:5])
            if flow_id >= len(identities) or len(seen) >= state_limit:
                raise CollectorError("collector snapshot state association/limit")
            row = json.loads(data[5:])
            local, remote, _incident = identities[flow_id]
            if not isinstance(row, dict) or row.get("flow") != {"origin": local, "dest": remote}:
                raise CollectorError("collector snapshot flow mismatch")
            identity = row.get("id"), row.get("creatorid")
            invalid_identity = not all(isinstance(value, str) for value in identity)
            if not invalid_identity:
                invalid_identity = (len(identity[0]) != 16 or len(identity[1]) != 8 or identity in seen)
            if invalid_identity:
                raise CollectorError("collector snapshot PF identity")
            try:
                int(identity[0], 16), int(identity[1], 16)
            except ValueError as error:
                raise CollectorError("collector snapshot PF identity") from error
            actual_bytes += len(json.dumps(row, separators=(",", ":"))) + len(remote) + 8
            if actual_bytes > byte_limit:
                raise CollectorError("collector snapshot encoded evidence ceiling")
            seen.add(identity)
            captured_by_flow[flow_id] += 1
            rows.setdefault(remote, []).append(row)
        elif data[0] == 2 and started and len(data) == 1 + _FLOW_TOTALS.size:
            (flow_id, matching, captured, from_remote, to_remote, packets_from, packets_to, sample_matching,
             quota, reasons) = _FLOW_TOTALS.unpack_from(data, 1)
            if flow_id != len(totals) or flow_id >= len(identities) or captured != captured_by_flow[flow_id] \
                    or captured > min(matching, quota) or reasons & ~7 \
                    or bool(matching - captured) != bool(reasons):
                raise CollectorError("collector snapshot flow totals")
            local, remote, required = identities[flow_id]
            totals[flow_id] = {"origin": local, "dest": remote, "required": required, "matching": matching,
                               "matching_at_sample": sample_matching, "quota": quota,
                               "captured": captured, "omitted": matching - captured,
                               "complete": matching == captured,
                               "bytes_from_remote": from_remote, "bytes_to_remote": to_remote,
                               "packets_from_remote": packets_from, "packets_to_remote": packets_to,
                               "omission_reasons": _omission_reasons(reasons)}
        elif data[0] == FOOTER and started and len(data) == 1 + _DETAIL_FOOTER.size:
            (traversed, observed, included, encoded, reasons, policy, skipped, expected, sample, start,
             end) = _DETAIL_FOOTER.unpack_from(data, 1)
            flows = [totals[n] for n in range(len(totals))]
            valid = expected == checksum and len(totals) == len(identities)
            valid = valid and included == len(seen) == sum(flow["captured"] for flow in flows)
            valid = valid and observed == sum(flow["matching"] for flow in flows) and observed <= traversed
            valid = valid and actual_bytes <= encoded <= byte_limit
            valid = valid and bool(observed - included) == bool(reasons) and not reasons & ~7
            valid = valid and policy in SELECTION_POLICIES
            # wall-clock times are reported, not ordered: the clock may step between them
            valid = valid and all(math.isfinite(t) and t > 0 for t in (sample, start, end))
            if not valid:
                raise CollectorError("collector snapshot detail completion")
            required = [flow for flow in flows if flow["required"]]
            return rows, {
                "scope": "retained_logical_flows", "available": observed, "captured": included,
                "omitted": observed - included, "complete": observed == included,
                "truncated": observed != included,
                "required_evidence_complete": all(flow["complete"] for flow in required),
                "total_limit": state_limit, "encoded_limit": byte_limit, "encoded_bytes": encoded,
                "omission_reasons": _omission_reasons(reasons),
                "selection_policy": SELECTION_POLICIES[policy], "skipped_states": skipped,
                "flows": flows, "traversed": traversed, "generation": generation,
                "sample_started_at": sample, "detail_started_at": start, "detail_completed_at": end,
                "atomic": False, "population": "detail_traversal",
            }
        else:
            raise CollectorError("collector snapshot detail record")
    raise CollectorError("incomplete collector snapshot detail")
