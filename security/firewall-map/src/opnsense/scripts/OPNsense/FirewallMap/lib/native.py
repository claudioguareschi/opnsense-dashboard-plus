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

"""Focused adapter for the package-owned native PF aggregation helper."""

import ipaddress
import json
import math
import os
import select
import shutil
import socket
import struct
import subprocess
import zlib

from . import common

HELPER = "/usr/local/libexec/firewallmap-native"
CAPABILITY = b"FMNATIVE4\n"
MAX_FRAME = 4096
READ_TIMEOUT = 20
PROTO_NUMBERS = {"icmp": 1, "tcp": 6, "udp": 17, "ipv6-icmp": 58, "sctp": 132}
SNAPSHOT_FLOWS = 5000
SNAPSHOT_BYTES = 10 * 1024 * 1024
SNAPSHOT_STATES = 5000


class NativeError(RuntimeError):
    """The native helper was absent, incompatible, or failed its complete sample."""


def available(path=HELPER):
    return os.path.isfile(path) and os.access(path, os.X_OK)


def _classification_rows():
    rows = []
    boundaries4 = set()
    for version, cls in ((4, ipaddress.IPv4Address), (6, ipaddress.IPv6Address)):
        maximum = 1 << (32 if version == 4 else 128)
        bounds = {0, maximum}
        for value in vars(cls._constants).values():
            for item in value if isinstance(value, (tuple, list)) else (value,):
                if isinstance(item, (ipaddress.IPv4Network, ipaddress.IPv6Network)) and item.version == version:
                    bounds.update((int(item.network_address), int(item.broadcast_address) + 1))
        if version == 4:
            bounds.update((int(common.CGNAT.network_address), int(common.CGNAT.broadcast_address) + 1))
            boundaries4 = bounds
        else:
            mapped = int(ipaddress.IPv6Address("::ffff:0:0"))
            bounds.update(mapped + n for n in boundaries4)
        ordered = sorted(bounds)
        for low, stop in zip(ordered, ordered[1:]):
            flags = []
            for n in (low, (low + stop - 1) // 2, stop - 1):
                address = str(cls(n))
                flags.append(int(common.public_ip(address)) | int(common.private_ip(address)) * 2)
            if len(set(flags)) != 1:
                raise NativeError("address classification range is not uniform")
            rows.append(f"R {cls(low)} {cls(stop - 1)} {flags[0]}")
    return rows


def _context_rows(local_addresses, networks, interface_addresses, primary_wan_device):
    rows = _classification_rows()
    rows.extend(f"L {address}" for address in sorted(local_addresses))
    rows.extend(f"N {network.network_address} {network.prefixlen} {device}"
                for network, device in networks)
    rows.extend(f"A {address} {device}" for device, addresses in interface_addresses.items()
                for address in sorted(addresses))
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
    return rows


def _address(data):
    if len(data) != 17 or data[0] not in (4, 6):
        raise NativeError("invalid FMAGG3 address")
    if data[0] == 4:
        if any(data[5:]):
            raise NativeError("noncanonical IPv4 address")
        return str(ipaddress.IPv4Address(data[1:5]))
    return str(ipaddress.IPv6Address(data[1:]))


def _read_exact(stream, size, process, deadline):
    data = bytearray()
    descriptor = stream.fileno()
    while len(data) < size:
        remaining = deadline - __import__("time").monotonic()
        if remaining <= 0 or not select.select([descriptor], [], [], remaining)[0]:
            raise NativeError("native helper response timed out")
        part = os.read(descriptor, size - len(data))
        if not part:
            code = process.poll()
            raise NativeError(f"native helper ended before sample completion ({code})")
        data.extend(part)
    return bytes(data)


def _decode(stream, process, query_keys, require_threat_summary, flow_limit=150, byte_limit=None):
    import time

    deadline = time.monotonic() + READ_TIMEOUT
    if _read_exact(stream, 8, process, deadline) != b"FMAGG3\0\0":
        raise NativeError("native helper protocol version mismatch")
    checksum = 0
    flows, candidates, matches = [], [], {}
    threat_remotes, threat_candidates = [], []
    started = False
    capabilities = 0
    counts = None
    received = 8
    while True:
        size = _read_exact(stream, 4, process, deadline)
        length, = struct.unpack("!I", size)
        if length > MAX_FRAME:
            raise NativeError("oversized FMAGG3 record")
        received += length + 4
        if byte_limit is not None and received > byte_limit:
            raise NativeError("snapshot aggregate response exceeds safety ceiling")
        data = _read_exact(stream, length, process, deadline)
        if not length:
            raise NativeError("unexpected empty FMAGG3 frame")
        kind = data[0]
        if kind != 255:
            checksum = zlib.crc32(size, checksum)
            checksum = zlib.crc32(data, checksum)
        if kind == 0:
            if started or len(data) != 9 or struct.unpack_from("!I", data, 1)[0] != 3:
                raise NativeError("FMAGG3 capability mismatch")
            flags, = struct.unpack_from("!I", data, 5)
            if flags not in (5, 7):
                raise NativeError("FMAGG3 required capabilities missing")
            if require_threat_summary and not flags & 2:
                raise NativeError("FMAGG3 threat summary capability missing")
            capabilities = flags
            started = True
        elif not started:
            raise NativeError("FMAGG3 missing capability record")
        elif kind == 1:
            if len(data) != 159:
                raise NativeError("invalid FMAGG3 flow record")
            index, = struct.unpack_from("!I", data, 1)
            if index != len(flows):
                raise NativeError("FMAGG2 flow order mismatch")
            local, remote = _address(data[5:22]), _address(data[22:39])
            states, toward, away, oldest = struct.unpack_from("!QQQI", data, 39)
            youngest, remote_started, local_started, first = struct.unpack_from("!IQQQ", data, 67)
            delta_toward, delta_away, packets = struct.unpack_from("!QQQ", data, 95)
            rate_in, rate_out, packet_rate, activity, score = struct.unpack_from("!ddddd", data, 119)
            flows.append({"key": (local, remote), "states": states, "bytes_toward": toward,
                          "bytes_away": away, "oldest": oldest, "youngest": youngest,
                          "remote_started": remote_started,
                          "local_started": local_started, "first": first, "toward": delta_toward,
                          "away": delta_away, "packets": packets, "rate_in": rate_in,
                          "rate_out": rate_out, "packet_rate": packet_rate,
                          "activity": activity, "score": score})
        elif kind == 2:
            if len(data) < 32:
                raise NativeError("invalid FMAGG3 candidate record")
            flow, candidate_kind, sequence, weight, association, value_length = struct.unpack_from(
                "!IBQQQH", data, 1)
            if flow >= len(flows) or candidate_kind not in range(1, 7) or value_length != len(data) - 32:
                raise NativeError("invalid FMAGG3 candidate identity")
            candidates.append((flow, candidate_kind, sequence, weight, association, data[32:]))
        elif kind == 3:
            if not capabilities & 2 or len(data) != 50:
                raise NativeError("invalid FMAGG3 remote summary")
            index, = struct.unpack_from("!I", data, 1)
            address = _address(data[5:22])
            inbound, outbound, transferred, youngest = struct.unpack_from("!QQQI", data, 22)
            if index != len(threat_remotes):
                raise NativeError("FMAGG3 remote order mismatch")
            threat_remotes.append({"address": address, "inbound": inbound, "outbound": outbound,
                                   "bytes": transferred, "youngest": youngest,
                                   "targets": [], "inside": [], "services": [], "service_ports": {}})
        elif kind == 4:
            if not capabilities & 2 or len(data) < 24:
                raise NativeError("invalid FMAGG3 remote candidate")
            remote, candidate_kind, sequence, association, value_length = struct.unpack_from("!IBQQH", data, 1)
            if remote >= len(threat_remotes) or candidate_kind not in (2, 4, 5) \
                    or value_length != len(data) - 24:
                raise NativeError("invalid FMAGG3 remote candidate identity")
            threat_candidates.append((remote, candidate_kind, sequence, association, data[24:]))
        elif kind == 5:
            if not capabilities & 4 or len(data) != 177:
                raise NativeError("invalid FMAGG3 event match")
            query_id, = struct.unpack_from("!H", data, 1)
            match_kind, proto = data[3], data[4]
            if query_id >= len(query_keys) or match_kind not in (1, 2):
                raise NativeError("invalid FMAGG3 event match identity")
            public, public_port = _address(data[5:22]), struct.unpack_from("!H", data, 22)[0]
            remote, remote_port = _address(data[24:41]), struct.unpack_from("!H", data, 41)[0]
            has_inside = data[43]
            if has_inside not in (0, 1):
                raise NativeError("invalid FMAGG3 inside flag")
            inside = _address(data[44:61]) if has_inside else None
            inside_port = struct.unpack_from("!H", data, 61)[0]
            state_id, creator = struct.unpack_from("!QI", data, 63)
            ambiguous = data[75]
            age = struct.unpack_from("!I", data, 76)[0]
            bytes_in, bytes_out = struct.unpack_from("!QQ", data, 80)
            remote_started = data[96]
            if ambiguous not in (0, 1) or remote_started not in (0, 1):
                raise NativeError("invalid FMAGG3 event flags")
            interface = data[97:113].split(b"\0", 1)[0].decode("ascii")
            rule = data[113:177].split(b"\0", 1)[0].decode("utf-8")
            try:
                protocol = common.protocol_name(proto)
            except (OSError, ValueError) as error:
                raise NativeError("unknown FMAGG3 event protocol") from error
            key = (protocol, public, str(public_port) if public_port else "",
                   remote, str(remote_port) if remote_port else "")
            if key != query_keys[query_id] or key in matches:
                raise NativeError("FMAGG3 event tuple mismatch or duplicate")
            matches[key] = {"kind": match_kind, "inside": inside,
                            "inside_port": inside_port if has_inside else None,
                            "id": state_id, "creator": creator, "ambiguous": bool(ambiguous),
                            "age": age, "bytes_in": bytes_in, "bytes_out": bytes_out,
                            "remote_started": bool(remote_started), "interface": interface,
                            "rule": rule or None}
        elif kind == 255:
            if len(data) != 81:
                raise NativeError("invalid FMAGG3 completion record")
            total, retained, mapped, flow_total, flow_count, candidate_count, match_count, remote_count, \
                remote_candidate_count, expected = struct.unpack("!QQQQQQQQQQ", data[1:])
            if expected != checksum or flow_count != len(flows) or candidate_count != len(candidates) \
                    or match_count != len(matches) or remote_count != len(threat_remotes) \
                    or remote_candidate_count != len(threat_candidates) \
                    or sum(f["states"] for f in flows) > mapped \
                    or not flow_count <= flow_limit or not mapped <= retained <= total:
                raise NativeError("FMAGG3 completion validation failed")
            counts = {"states": total, "retained": retained, "mapped": mapped,
                      "flows": flow_total, "captured_flows": flow_count,
                      "candidates": candidate_count, "matches": match_count,
                      "threat_remotes": remote_count, "threat_candidates": remote_candidate_count}
            break
        else:
            raise NativeError("unknown FMAGG3 record")
    if (not capabilities & 2 and (counts["threat_remotes"] or counts["threat_candidates"])):
        raise NativeError("FMAGG3 threat summary capability mismatch")
    return {"flows": flows, "candidates": candidates, "matches": matches,
            "threat_remotes": threat_remotes, "threat_candidates": threat_candidates,
            "threat_summary": bool(capabilities & 2), "counts": counts}


class NativeEngine:
    """One collector-owned helper process; its native history lives across samples."""

    def __init__(self, path=HELPER):
        self.path = path
        self.process = None
        self.snapshot_open = False

    def _start(self):
        if not available(self.path):
            raise NativeError("native helper unavailable")
        try:
            self.process = subprocess.Popen([self.path], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                            bufsize=0)
            import time
            deadline = time.monotonic() + READ_TIMEOUT
            if _read_exact(self.process.stdout, len(CAPABILITY), self.process, deadline) != CAPABILITY:
                raise NativeError("native helper capability mismatch")
        except (OSError, NativeError) as error:
            self.close()
            if isinstance(error, NativeError):
                raise
            raise NativeError("could not start native helper") from error

    def sample(self, local_addresses, networks, interface_addresses, primary_wan_device, elapsed,
               threat_summary=False, event_queries=(), snapshot=False):
        if self.process is None or self.process.poll() is not None:
            self._start()
        rows = _context_rows(local_addresses, networks, interface_addresses, primary_wan_device)
        if threat_summary:
            rows.append("T 1")
        if snapshot:
            rows.append("B 1")
        query_keys = []
        for protocol, public, public_port, remote, remote_port in event_queries[:2500]:
            number = PROTO_NUMBERS.get(protocol)
            if number is None:
                try:
                    number = socket.getprotobyname(protocol)
                except OSError:
                    continue
            query_keys.append((protocol, public, str(public_port or ""), remote, str(remote_port or "")))
            rows.append(f"Q {len(query_keys) - 1} {number} {public} {int(public_port or 0)} "
                        f"{remote} {int(remote_port or 0)}")
        text = "FMCONF1\nE %.9f\n%sRUN\n" % (elapsed, "".join(row + "\n" for row in rows))
        try:
            self.process.stdin.write(text.encode("ascii"))
            self.process.stdin.flush()
            result = _decode(self.process.stdout, self.process, query_keys, threat_summary)
            self.snapshot_open = snapshot
            return result
        except (OSError, UnicodeError, ValueError, struct.error, NativeError) as error:
            self.close()
            if isinstance(error, NativeError):
                raise
            raise NativeError("native helper request failed") from error

    def _snapshot_request(self, text, decoder):
        if self.process is None or self.process.poll() is not None:
            raise NativeError("native snapshot session unavailable")
        try:
            self.process.stdin.write(text.encode("ascii"))
            self.process.stdin.flush()
            return decoder(self.process.stdout, self.process)
        except (OSError, UnicodeError, ValueError, struct.error, NativeError) as error:
            self.close()
            if isinstance(error, NativeError):
                raise
            raise NativeError("native snapshot request failed") from error

    def snapshot_pages(self):
        """Bounded identity/score pages, not raw states or per-flow candidate lists."""
        offset, generation, active = 0, None, None
        while True:
            page = self._snapshot_request(f"FMSNAP1 PAGE {offset}\n", _decode_page)
            changed = page["offset"] != offset
            if generation is not None:
                changed = changed or page["generation"] != generation
                changed = changed or page["active"] != active
            if changed:
                self.close()
                raise NativeError("native snapshot page generation/offset changed")
            generation, active = page["generation"], page["active"]
            self.snapshot_generation = generation
            yield page["flows"]
            offset += len(page["flows"])
            if offset == active:
                return

    def snapshot_selection(self, identities):
        text = f"FMSNAP1 SELECT {self.snapshot_generation} {len(identities)}\n"
        text += _identity_rows(identities)
        result = self._snapshot_request(text, lambda stream, process: _decode(
            stream, process, (), False, flow_limit=SNAPSHOT_FLOWS, byte_limit=SNAPSHOT_BYTES))
        if [row["key"] for row in result["flows"]] != [tuple(item[:2]) for item in identities]:
            self.close()
            raise NativeError("native snapshot selection identity mismatch")
        return result

    def snapshot_detail(self, identities, byte_limit, state_limit=SNAPSHOT_STATES):
        if not 0 <= byte_limit <= SNAPSHOT_BYTES or not 0 < state_limit <= SNAPSHOT_STATES:
            raise NativeError("invalid native snapshot detail budget")
        text = f"FMSNAP1 DETAIL {self.snapshot_generation} {byte_limit} {state_limit} {len(identities)}\n"
        text += _identity_rows(identities)
        result = self._snapshot_request(text, lambda stream, process: _decode_detail(
            stream, process, identities, self.snapshot_generation, byte_limit, state_limit))
        self.snapshot_open = False
        return result

    def snapshot_cancel(self):
        if self.process is not None and self.snapshot_open:
            try:
                self.process.stdin.write(b"FMSNAP1 CANCEL\n")
                self.process.stdin.flush()
                self.snapshot_open = False
            except OSError:
                self.close()

    def close(self):
        self.snapshot_open = False
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


def _snapshot_frames(stream, process, magic, byte_limit):
    import time

    deadline = time.monotonic() + READ_TIMEOUT
    if _read_exact(stream, 8, process, deadline) != magic:
        raise NativeError("native snapshot protocol version mismatch")
    checksum, received = 0, 8
    while True:
        size = _read_exact(stream, 4, process, deadline)
        length, = struct.unpack("!I", size)
        received += length + 4
        if not 0 < length <= MAX_FRAME or received > byte_limit:
            raise NativeError("native snapshot frame/byte limit")
        data = _read_exact(stream, length, process, deadline)
        if data[0] == 255:
            yield data, checksum
            return
        checksum = zlib.crc32(size, checksum)
        checksum = zlib.crc32(data, checksum)
        yield data, checksum


def _decode_page(stream, process):
    header, flows, seen = None, [], set()
    for data, checksum in _snapshot_frames(stream, process, b"FMPAGE1\0", 16384):
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
        elif data[0] == 255 and header is not None and len(data) == 5:
            if struct.unpack("!I", data[1:])[0] != checksum or len(flows) != header[3] or (
                    not flows and header[2] != header[1]):
                raise NativeError("native snapshot page completion")
            return dict(generation=header[0], active=header[1], offset=header[2], flows=flows)
        else:
            raise NativeError("native snapshot page record")
    raise NativeError("incomplete native snapshot page")


def _decode_detail(stream, process, identities, generation, byte_limit, state_limit):
    started, rows, seen, actual_bytes = False, {}, set(), 0
    # JSON rows dominate the stream; allow fixed framing/completion overhead.
    for data, checksum in _snapshot_frames(stream, process, b"FMSTATE1", byte_limit + state_limit * 9 + 128):
        if data[0] == 0 and not started and len(data) == 13:
            version, received_generation = struct.unpack("!IQ", data[1:])
            if version != 1 or received_generation != generation:
                raise NativeError("native snapshot detail generation/version")
            started = True
        elif data[0] == 1 and started and len(data) > 5:
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
            rows.setdefault(remote, []).append(row)
        elif data[0] == 255 and started and len(data) == 65:
            traversed, observed, included, encoded, reasons, expected, sample, start, end = struct.unpack(
                "!QQQQIIddd", data[1:])
            valid_counts = included <= observed <= traversed
            valid_size = actual_bytes <= encoded <= byte_limit
            valid_reasons = bool(observed - included) == bool(reasons) and not reasons & ~3
            valid_times = all(math.isfinite(t) and t > 0 for t in (sample, start, end))
            valid_order = sample <= start <= end
            valid_footer = expected == checksum
            valid_footer = valid_footer and included == len(seen)
            valid_footer = valid_footer and valid_counts and valid_size
            valid_footer = valid_footer and valid_reasons and valid_times and valid_order
            if not valid_footer:
                raise NativeError("native snapshot detail completion")
            omission_reasons = []
            if reasons & 1:
                omission_reasons.append("encoded_bytes")
            if reasons & 2:
                omission_reasons.append("state_count")
            return rows, {
                "scope": "retained_logical_flows", "available": observed, "captured": included,
                "omitted": observed - included, "complete": observed == included,
                "truncated": observed != included, "total_limit": state_limit, "encoded_limit": byte_limit,
                "encoded_bytes": encoded,
                "omission_reasons": omission_reasons,
                "traversed": traversed, "generation": generation,
                "sample_started_at": sample, "detail_started_at": start, "detail_completed_at": end,
                "atomic": False, "population": "detail_traversal",
            }
        else:
            raise NativeError("native snapshot detail record")
    raise NativeError("incomplete native snapshot detail")
