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


"""Client of the package-owned native PF engine (firewallmap-native).

The wire formats are specified in native/PROTOCOL.md. Every response is
validated completely (framing, record order, counts, checksum) before any of
it is used; anything unexpected closes the helper, so a stream is never
resynchronized. Python never supplies elapsed time: the helper anchors each
sample itself and reports a baseline (interval < 0) when it has none.

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
import time
import zlib

from . import classification, common

HELPER = "/usr/local/libexec/firewallmap-native"
BANNER = re.compile(rb"^FMNATIVE5 pf_state_version=(\d+) freebsd_version=(\d+)\n$")
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

# Resource budgets (native/budget.h, PROTOCOL.md): the helper enforces the same maxima.
RANKED_FLOWS = 150
CANDIDATES_PER_KIND = 16
THREAT_REMOTES = 20000
MEMORY_MIN_MIB, MEMORY_MAX_MIB, MEMORY_AUTO_MAX_MIB = 64, 16384, 1024
MEMORY_AUTO_SHARE = 0.05
# operator context maxima: over them a sample is refused, naming the kind (never truncated)
CONTEXT_MAXIMA = {"L": 4096, "N": 8192, "A": 1024}
_FLOW_RECORD, _CANDIDATE_RECORD, _THREAT_REMOTE_RECORD, _THREAT_CANDIDATE_RECORD = 163, 100, 54, 92
_EVENT_RECORD, _FIXED_RECORDS = 198, 4096

# FMAGG4 record kinds
HEADER, FLOW, CANDIDATE, THREAT_REMOTE, THREAT_CANDIDATE, EVENT_MATCH, TELEMETRY = range(7)
FAILURE, FOOTER = 254, 255
# candidate kinds
PROTOCOL, INSIDE_HOST, EGRESS_INTERFACE, SERVICE, REMOTE_TARGET, RULE_LABEL = range(1, 7)
THREAT_CANDIDATE_KINDS = (INSIDE_HOST, SERVICE, REMOTE_TARGET)
EVENT_MATCH_KINDS = (1, 2)  # current state, recently seen state
OUTCOMES = {0: "sample", 1: "refused_states", 2: "refused_context", 3: "refused_memory"}
FAILURE_CLASSES = {1: "structural", 2: "internal", 3: "incompatible", 4: "resources", 5: "request"}
# FMSTATE2 omission reason bits and selection policies
OMISSION_REASONS = ((1, "encoded_bytes"), (2, "state_count"), (4, "flow_quota"))
SELECTION_POLICIES = {1: "arrival_incident_first_v1"}

_FLOW = struct.Struct("!I17s17sQQQIIQQQQQQddddd")
_TELEMETRY = struct.Struct("!IQdddddQQQQQQQQQQQQ")
_TELEMETRY_FIELDS = ("pid", "sequence", "interval", "dump_seconds", "processing_seconds", "user_cpu",
                     "system_cpu", "max_rss", "heap_bytes", "heap_peak", "heap_blocks", "heap_budget",
                     "state_limit", "preflight_states", "skipped_af_translation", "candidates_omitted",
                     "threat_remotes_omitted", "threat_candidates_omitted", "event_history_evicted")
_FOOTER = struct.Struct("!IIQQQQQQQQQQQI")


class NativeError(RuntimeError):
    """The native helper was absent, incompatible, or failed its complete sample.

    failure_class names the helper's own classification (FMFAIL1) when it gave
    one: structural, internal, incompatible, resources or request.
    """

    def __init__(self, message, failure_class=None):
        super().__init__(message)
        self.failure_class = failure_class


def available(path=HELPER):
    return os.path.isfile(path) and os.access(path, os.X_OK)


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
                        queries=MAX_EVENT_QUERIES):
    """The largest FMAGG4 response the budgets allow (framing included); more is a helper bug."""
    flows = RANKED_FLOWS * (_FLOW_RECORD + RULE_LABEL * candidates_per_kind * _CANDIDATE_RECORD)
    threats = threat_remotes * (_THREAT_REMOTE_RECORD + len(THREAT_CANDIDATE_KINDS) * candidates_per_kind
                                * _THREAT_CANDIDATE_RECORD)
    return 8 + flows + threats + queries * _EVENT_RECORD + _FIXED_RECORDS


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
                raise NativeError(f"unsupported service protocol {protocol}") from error
        groups.setdefault(name, len(groups) + 2)
        rows.append(f"S {number} {port} {groups[name]}")
    return rows, None


def _address(data):
    if len(data) != 17 or data[0] not in (4, 6):
        raise NativeError("invalid native address")
    if data[0] == 4:
        if any(data[5:]):
            raise NativeError("noncanonical IPv4 address")
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
            raise NativeError("native helper response timed out")
        part = os.read(descriptor, size - len(data))
        if not part:
            code = process.poll()
            raise NativeError(f"native helper ended before its response was complete ({code})")
        data.extend(part)
    return bytes(data)


def _frames(stream, process, deadline, byte_limit=None, received=8):
    """(frame bytes, payload) pairs; the footer (255) is the last one yielded."""
    while True:
        size = _read_exact(stream, 4, process, deadline)
        length, = struct.unpack("!I", size)
        received += length + 4
        if not 0 < length <= MAX_FRAME:
            raise NativeError("native frame size")
        if byte_limit is not None and received > byte_limit:
            raise NativeError("native response exceeds its byte ceiling")
        data = _read_exact(stream, length, process, deadline)
        yield size, data
        if data[0] == FOOTER:
            return


def _failure(stream, process, deadline):
    size = _read_exact(stream, 4, process, deadline)
    length, = struct.unpack("!I", size)
    if not 9 <= length <= MAX_FRAME:
        raise NativeError("malformed native failure report")
    data = _read_exact(stream, length, process, deadline)
    if data[0] != FAILURE:
        raise NativeError("malformed native failure report")
    failure_class, code = struct.unpack_from("!Ii", data, 1)
    message = data[9:].decode("utf-8", "replace")
    name = FAILURE_CLASSES.get(failure_class, "unknown")
    return NativeError(f"native helper failed ({name}, errno {code}): {message}", name)


def _magic(stream, process, deadline, expected):
    magic = _read_exact(stream, 8, process, deadline)
    if magic == b"FMFAIL1\0":
        raise _failure(stream, process, deadline)
    if magic != expected:
        raise NativeError("native helper protocol version mismatch")


def _decode(stream, process, query_keys, require_threat_summary, flow_limit=RANKED_FLOWS, byte_limit=None,
            timeout=None):
    """Read one complete FMAGG4 response."""
    deadline = time.monotonic() + (timeout or READ_TIMEOUT)
    _magic(stream, process, deadline, b"FMAGG4\0\0")
    checksum, threats_present, telemetry, footer, previous_kind = 0, None, None, None, HEADER
    flows, candidates, matches = [], [], {}
    threat_remotes, threat_candidates = [], []
    for size, data in _frames(stream, process, deadline, byte_limit):
        kind = data[0]
        if kind != FOOTER:
            checksum = zlib.crc32(data, zlib.crc32(size, checksum))
        if threats_present is None:
            if kind != HEADER or len(data) != 9:
                raise NativeError("FMAGG4 header missing")
            version, flags = struct.unpack_from("!II", data, 1)
            if version != 4 or flags & ~1:
                raise NativeError("FMAGG4 header version or flags")
            threats_present = bool(flags & 1)
            if require_threat_summary and not threats_present:
                raise NativeError("FMAGG4 threat summary missing")
            continue
        if telemetry is not None and kind != FOOTER:
            raise NativeError("FMAGG4 record after telemetry")
        if kind in (FLOW, CANDIDATE, THREAT_REMOTE, THREAT_CANDIDATE, EVENT_MATCH) and kind < previous_kind:
            raise NativeError("FMAGG4 record order")
        if kind != FOOTER:
            previous_kind = max(previous_kind, kind)
        if kind == FLOW:
            if len(data) != 1 + _FLOW.size:
                raise NativeError("invalid FMAGG4 flow record")
            (rank, local, remote, states, from_remote, to_remote, oldest, youngest, remote_weight, local_weight,
             first, delta_from, delta_to, delta_packets, rate_from, rate_to, packet_rate, activity,
             score) = _FLOW.unpack_from(data, 1)
            if rank != len(flows) or not all(math.isfinite(value) and value >= 0 for value in
                                             (rate_from, rate_to, packet_rate, activity, score)):
                raise NativeError("invalid FMAGG4 flow rank or rate")
            flows.append({"key": (_address(local), _address(remote)), "states": states,
                          "bytes_from_remote": from_remote, "bytes_to_remote": to_remote,
                          "oldest": oldest, "youngest": youngest,
                          "remote_initiated_weight": remote_weight, "local_initiated_weight": local_weight,
                          "first": first, "delta_bytes_from_remote": delta_from,
                          "delta_bytes_to_remote": delta_to, "delta_packets": delta_packets,
                          "rate_from_remote": rate_from, "rate_to_remote": rate_to,
                          "packet_rate": packet_rate, "activity": activity, "score": score})
        elif kind == CANDIDATE:
            if len(data) < 32:
                raise NativeError("invalid FMAGG4 candidate record")
            flow, candidate_kind, sequence, weight, association, length = struct.unpack_from("!IBQQQH", data, 1)
            if flow >= len(flows) or candidate_kind not in range(PROTOCOL, RULE_LABEL + 1) \
                    or length != len(data) - 32:
                raise NativeError("invalid FMAGG4 candidate identity")
            candidates.append((flow, candidate_kind, sequence, weight, association, data[32:]))
        elif kind == THREAT_REMOTE:
            if not threats_present or len(data) != 50:
                raise NativeError("invalid FMAGG4 threat remote")
            index, = struct.unpack_from("!I", data, 1)
            remote_states, local_states, transferred, youngest = struct.unpack_from("!QQQI", data, 22)
            if index != len(threat_remotes):
                raise NativeError("FMAGG4 threat remote order")
            threat_remotes.append({"address": _address(data[5:22]), "remote_initiated_states": remote_states,
                                   "local_initiated_states": local_states, "bytes": transferred,
                                   "youngest": youngest})
        elif kind == THREAT_CANDIDATE:
            if not threats_present or len(data) < 24:
                raise NativeError("invalid FMAGG4 threat candidate")
            remote, candidate_kind, sequence, association, length = struct.unpack_from("!IBQQH", data, 1)
            if remote >= len(threat_remotes) or candidate_kind not in THREAT_CANDIDATE_KINDS \
                    or length != len(data) - 24:
                raise NativeError("invalid FMAGG4 threat candidate identity")
            threat_candidates.append((remote, candidate_kind, sequence, association, data[24:]))
        elif kind == EVENT_MATCH:
            key, match = _event_match(data, query_keys)
            if key in matches:
                raise NativeError("FMAGG4 duplicate event match")
            matches[key] = match
        elif kind == TELEMETRY:
            if len(data) != 1 + _TELEMETRY.size:
                raise NativeError("invalid FMAGG4 telemetry")
            telemetry = dict(zip(_TELEMETRY_FIELDS, _TELEMETRY.unpack_from(data, 1)))
            if not all(math.isfinite(telemetry[name]) for name in _TELEMETRY_FIELDS[2:7]):
                raise NativeError("invalid FMAGG4 telemetry")
        elif kind == FOOTER:
            if len(data) != 1 + _FOOTER.size:
                raise NativeError("invalid FMAGG4 footer")
            footer = _FOOTER.unpack_from(data, 1)
        else:
            raise NativeError("unknown FMAGG4 record")
    if threats_present is None or telemetry is None or footer is None:
        raise NativeError("incomplete FMAGG4 response")
    (outcome, context_kind, actual, limit, seen, retained, mapped, flow_total, flows_sent, candidates_sent,
     matches_sent, remotes_sent, remote_candidates_sent, expected) = footer
    records = (flows, candidates, matches, threat_remotes, threat_candidates)
    if expected != checksum or outcome not in OUTCOMES \
            or (flows_sent, candidates_sent, matches_sent, remotes_sent, remote_candidates_sent) \
            != tuple(map(len, records)) \
            or len(flows) > flow_limit or not mapped <= retained <= seen \
            or sum(flow["states"] for flow in flows) > mapped \
            or (outcome and (any(records) or threats_present)):
        raise NativeError("FMAGG4 completion validation failed")
    refused = OUTCOMES[outcome] if outcome else None
    return {"flows": flows, "candidates": candidates, "matches": matches,
            "threat_remotes": threat_remotes, "threat_candidates": threat_candidates,
            "threat_summary": threats_present, "telemetry": telemetry,
            "baseline": telemetry["interval"] < 0,
            "refused": refused and {"reason": refused, "kind": chr(context_kind) if context_kind else None,
                                    "actual": actual, "limit": limit},
            "counts": {"states": seen, "retained": retained, "mapped": mapped, "flows": flow_total,
                       "captured_flows": len(flows), "candidates": len(candidates), "matches": len(matches),
                       "threat_remotes": len(threat_remotes), "threat_candidates": len(threat_candidates)}}


def _event_match(data, query_keys):
    if len(data) != 194:
        raise NativeError("invalid FMAGG4 event match")
    query_id, match_kind, proto = struct.unpack_from("!HBB", data, 1)
    if query_id >= len(query_keys) or match_kind not in EVENT_MATCH_KINDS:
        raise NativeError("invalid FMAGG4 event match identity")
    public, public_port = _address(data[5:22]), struct.unpack_from("!H", data, 22)[0]
    remote, remote_port = _address(data[24:41]), struct.unpack_from("!H", data, 41)[0]
    has_inside = data[43]
    inside_port, state_id, creator = struct.unpack_from("!HQI", data, 61)
    ambiguous = data[75]
    age, from_remote, to_remote, packets_from, packets_to = struct.unpack_from("!IQQQQ", data, 76)
    remote_initiated, apparent = data[112], data[113]
    if not {has_inside, ambiguous, remote_initiated, apparent} <= {0, 1}:
        raise NativeError("invalid FMAGG4 event flags")
    try:
        protocol = common.protocol_name(proto)
    except (OSError, ValueError) as error:
        raise NativeError("unknown FMAGG4 event protocol") from error
    key = (protocol, public, str(public_port) if public_port else "",
           remote, str(remote_port) if remote_port else "")
    if key != query_keys[query_id]:
        raise NativeError("FMAGG4 event tuple mismatch")
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


class NativeEngine:
    """One collector-owned helper process; its native history lives across samples.

    Every request goes through _request: a request that does not complete
    cleanly, for any reason (including an exception raised while it is in
    flight), leaves the stream in an unknown position, so the helper is closed.
    """

    def __init__(self, path=HELPER):
        self.path = path
        self.process = None
        self.snapshot_open = False
        self.snapshot_generation = None
        self.metadata = None
        self.starts = 0
        self.last_error = None
        self.read_timeout = READ_TIMEOUT

    def _start(self):
        if not available(self.path):
            raise NativeError("native helper unavailable")
        try:
            self.process = subprocess.Popen([self.path], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                            bufsize=0)
            self.starts += 1
            banner = bytearray()
            deadline = time.monotonic() + READ_TIMEOUT
            while not banner.endswith(b"\n") and len(banner) < 128:
                banner += _read_exact(self.process.stdout, 1, self.process, deadline)
            match = BANNER.match(bytes(banner))
            if not match:
                raise NativeError("native helper capability mismatch")
            self.metadata = {"pid": self.process.pid, "pf_state_version": int(match.group(1)),
                             "freebsd_version": int(match.group(2))}
        except (OSError, NativeError) as error:
            self.close()
            if isinstance(error, NativeError):
                raise
            raise NativeError("could not start native helper") from error

    def _request(self, text, decoder):
        if self.process is None or self.process.poll() is not None:
            raise NativeError("native helper is not running")
        try:
            self.process.stdin.write(text.encode("ascii"))
            self.process.stdin.flush()
            return decoder(self.process.stdout, self.process)
        except BaseException as error:
            # framing is unknown: never reuse this helper
            self.close()
            if isinstance(error, NativeError):
                self.last_error = str(error)
                raise
            if isinstance(error, (OSError, UnicodeError, ValueError, struct.error)):
                self.last_error = f"native helper request failed: {error}"
                raise NativeError(self.last_error) from error
            raise

    def sample(self, local_addresses, networks, interface_addresses, primary_wan_device,
               threat_summary=False, event_queries=(), snapshot=False, memory=None, evidence=(),
               correlation=True):
        """One complete sample. memory: the budget in bytes (default: automatic); evidence:
        remotes the threat summary must keep first; correlation: whether anything consumes
        IDS/block tuple matching (it is skipped otherwise)."""
        rows, refused = _context_rows(local_addresses, networks, interface_addresses, primary_wan_device)
        if refused:
            # Python's own check; the helper would refuse the same request
            return {"flows": [], "candidates": [], "matches": {}, "threat_remotes": [], "threat_candidates": [],
                    "threat_summary": False, "telemetry": None, "baseline": False, "refused": refused,
                    "counts": {"states": 0, "retained": 0, "mapped": 0, "flows": 0, "captured_flows": 0,
                               "candidates": 0, "matches": 0, "threat_remotes": 0, "threat_candidates": 0},
                    "helper": dict(self.metadata or {}, starts=self.starts)}
        if self.process is None or self.process.poll() is not None:
            self.close()
            self._start()
        rows.append(f"BUDGET {memory or memory_budget()} {CANDIDATES_PER_KIND} {THREAT_REMOTES}")
        rows.append(f"CORRELATION {int(bool(correlation or event_queries))}")
        if threat_summary:
            rows.append("THREATS")
            evidence_rows = sorted({address for address in map(_context_address, evidence) if address})
            rows.extend(f"EVIDENCE {address}" for address in evidence_rows[:THREAT_REMOTES])
        if snapshot:
            rows.append("SNAPSHOT")
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
        limit = response_byte_limit(queries=len(query_keys))
        result = self._request(text, lambda stream, process: _decode(stream, process, query_keys,
                                                                     threat_summary, byte_limit=limit,
                                                                     timeout=self.read_timeout))
        telemetry = result["telemetry"]
        # the next response may take as long as this one did, with a margin
        self.read_timeout = min(READ_TIMEOUT_MAX, max(READ_TIMEOUT, READ_TIMEOUT_FACTOR * (
            telemetry["dump_seconds"] + telemetry["processing_seconds"])))
        self.snapshot_open = snapshot and not result["refused"]
        self.snapshot_generation = result["telemetry"]["sequence"] if self.snapshot_open else None
        result["helper"] = dict(self.metadata or {}, starts=self.starts)
        return result

    def snapshot_pages(self):
        """Bounded identity/score pages, not raw states or per-flow candidate lists."""
        offset, active = 0, None
        while True:
            page = self._request(f"FMSNAP1 PAGE {offset}\n",
                                 lambda stream, process: _decode_page(stream, process, self.read_timeout))
            changed = page["offset"] != offset or page["generation"] != self.snapshot_generation
            changed = changed or (active is not None and page["active"] != active)
            if changed:
                self.close()
                raise NativeError("native snapshot page generation/offset changed")
            active = page["active"]
            yield page["flows"]
            offset += len(page["flows"])
            if offset == active:
                return

    def snapshot_selection(self, identities):
        text = f"FMSNAP1 SELECT {self.snapshot_generation} {len(identities)}\n"
        text += _identity_rows(identities)
        result = self._request(text, lambda stream, process: _decode(
            stream, process, (), False, flow_limit=SNAPSHOT_FLOWS, byte_limit=SNAPSHOT_BYTES,
            timeout=self.read_timeout))
        if [row["key"] for row in result["flows"]] != [tuple(item[:2]) for item in identities]:
            self.close()
            raise NativeError("native snapshot selection identity mismatch")
        return result

    def snapshot_detail(self, identities, byte_limit, state_limit=SNAPSHOT_STATES):
        if not 0 <= byte_limit <= SNAPSHOT_BYTES or not 0 < state_limit <= SNAPSHOT_STATES:
            raise NativeError("invalid native snapshot detail budget")
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
        raise NativeError("too many native snapshot identities")
    seen, rows = set(), []
    for local, remote, incident in identities:
        pair = (str(ipaddress.ip_address(local)), str(ipaddress.ip_address(remote)))
        if pair in seen or incident not in (True, False):
            raise NativeError("duplicate/invalid native snapshot identity")
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


def _decode_page(stream, process, timeout=None):
    header, flows, seen = None, [], set()
    for data, checksum in _snapshot_frames(stream, process, b"FMPAGE1\0", 16384, timeout):
        if data[0] == 0 and header is None and len(data) == 33:
            version, generation, active, offset, count = struct.unpack("!IQQQI", data[1:])
            if version != 1 or not 0 <= count <= 150 or not offset + count <= active:
                raise NativeError("native snapshot page header")
            header = generation, active, offset, count
        elif data[0] == 1 and header is not None and len(data) == 51:
            pair = _address(data[1:18]), _address(data[18:35])
            score, order = struct.unpack("!dQ", data[35:])
            if pair in seen or not math.isfinite(score) or score < 0 or len(flows) >= header[3]:
                raise NativeError("native snapshot page flow")
            seen.add(pair)
            flows.append((*pair, score, order))
        elif data[0] == FOOTER and header is not None and len(data) == 5:
            if struct.unpack("!I", data[1:])[0] != checksum or len(flows) != header[3] or (
                    not flows and header[2] != header[1]):
                raise NativeError("native snapshot page completion")
            return dict(generation=header[0], active=header[1], offset=header[2], flows=flows)
        else:
            raise NativeError("native snapshot page record")
    raise NativeError("incomplete native snapshot page")


_FLOW_TOTALS = struct.Struct("!IQQQQQQB")
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
            if version != 2 or received_generation != generation:
                raise NativeError("native snapshot detail generation/version")
            started = True
        elif data[0] == 1 and started and not totals and len(data) > 5:
            flow_id, = struct.unpack("!I", data[1:5])
            if flow_id >= len(identities) or len(seen) >= state_limit:
                raise NativeError("native snapshot state association/limit")
            row = json.loads(data[5:])
            local, remote, _incident = identities[flow_id]
            if not isinstance(row, dict) or row.get("flow") != {"origin": local, "dest": remote}:
                raise NativeError("native snapshot flow mismatch")
            identity = row.get("id"), row.get("creatorid")
            invalid_identity = not all(isinstance(value, str) for value in identity)
            if not invalid_identity:
                invalid_identity = (len(identity[0]) != 16 or len(identity[1]) != 8 or identity in seen)
            if invalid_identity:
                raise NativeError("native snapshot PF identity")
            try:
                int(identity[0], 16), int(identity[1], 16)
            except ValueError as error:
                raise NativeError("native snapshot PF identity") from error
            actual_bytes += len(json.dumps(row, separators=(",", ":"))) + len(remote) + 8
            if actual_bytes > byte_limit:
                raise NativeError("native snapshot encoded evidence ceiling")
            seen.add(identity)
            captured_by_flow[flow_id] += 1
            rows.setdefault(remote, []).append(row)
        elif data[0] == 2 and started and len(data) == 1 + _FLOW_TOTALS.size:
            (flow_id, matching, captured, from_remote, to_remote, packets_from, packets_to,
             reasons) = _FLOW_TOTALS.unpack_from(data, 1)
            if flow_id != len(totals) or flow_id >= len(identities) or captured != captured_by_flow[flow_id] \
                    or captured > matching or reasons & ~7 or bool(matching - captured) != bool(reasons):
                raise NativeError("native snapshot flow totals")
            local, remote, required = identities[flow_id]
            totals[flow_id] = {"origin": local, "dest": remote, "required": required, "matching": matching,
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
                raise NativeError("native snapshot detail completion")
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
            raise NativeError("native snapshot detail record")
    raise NativeError("incomplete native snapshot detail")
