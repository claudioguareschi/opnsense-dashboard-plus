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
import os
import select
import shutil
import socket
import struct
import subprocess
import zlib

from . import common

HELPER = "/usr/local/libexec/firewallmap-native"
CAPABILITY = b"FMNATIVE3\n"
MAX_FRAME = 4096
READ_TIMEOUT = 20
PROTO_NUMBERS = {"icmp": 1, "tcp": 6, "udp": 17, "ipv6-icmp": 58, "sctp": 132}


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


def _decode(stream, process, query_keys, require_threat_summary):
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
    while True:
        size = _read_exact(stream, 4, process, deadline)
        length, = struct.unpack("!I", size)
        if length > MAX_FRAME:
            raise NativeError("oversized FMAGG3 record")
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
                    or not flow_count <= 150 or not mapped <= retained <= total:
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
               threat_summary=False, event_queries=()):
        if self.process is None or self.process.poll() is not None:
            self._start()
        rows = _context_rows(local_addresses, networks, interface_addresses, primary_wan_device)
        if threat_summary:
            rows.append("T 1")
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
            return _decode(self.process.stdout, self.process, query_keys, threat_summary)
        except (OSError, UnicodeError, ValueError, struct.error, NativeError) as error:
            self.close()
            if isinstance(error, NativeError):
                raise
            raise NativeError("native helper request failed") from error

    def close(self):
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
