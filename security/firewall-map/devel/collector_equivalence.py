#!/usr/bin/env python3
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

"""Development-only equivalence harness; never imports adaptive working edits.

collector_equivalence.py --src CLEAN_SCRIPTS --helper ./collector_sample --dir TEMP_DIR
Modes: context (ifconfig), live (one read-only dump), synthetic (saved fixture),
compare (same captured states), decode (aggregate-only memory measurement).
No repeated live loops, traffic generation, collector construction or installs.
"""

import argparse
import ipaddress
import json
import random
import re
import struct
import subprocess
import sys
import time
import tracemalloc
import zlib
import resource
from pathlib import Path

PROTO = {1: 'icmp', 6: 'tcp', 17: 'udp', 58: 'ipv6-icmp', 132: 'sctp', 47: 'gre', 50: 'esp', 51: 'ah', 2: 'igmp'}
with Path('/etc/protocols').open() as protocols:
    for line in protocols:
        parts = line.split('#', 1)[0].split()
        if len(parts) >= 2 and parts[1].isdigit():
            PROTO.setdefault(int(parts[1]), parts[0])


def address_bytes(value):
    ip = ipaddress.ip_address(value)
    return bytes([ip.version]) + ip.packed.ljust(16, b'\0')


def address(data):
    if len(data) != 17 or data[0] not in (4, 6):
        raise ValueError('invalid address')
    if data[0] == 4 and any(data[5:]):
        raise ValueError('noncanonical IPv4 padding')
    return str(ipaddress.ip_address(data[1:5] if data[0] == 4 else data[1:]))


def frame(data):
    return struct.pack('!I', len(data)) + data


def frames(path, magic):
    with path.open('rb') as f:
        if f.read(8) != magic:
            raise ValueError('magic/version')
        while size := f.read(4):
            if len(size) != 4:
                raise ValueError('truncated length')
            n, = struct.unpack('!I', size)
            if n > 4096:
                raise ValueError('oversized frame')
            data = f.read(n)
            if len(data) != n:
                raise ValueError('truncated record')
            yield size, data
            if not n:
                footer = f.read(8)
                if len(footer) != 8 or f.read(1):
                    raise ValueError('fixture completion')
                yield b'', footer
                return


def decoded_states(path):
    count = 0
    done = False
    for size, b in frames(path, b'FMPFS2\0\0'):
        if not size:
            if struct.unpack('!Q', b)[0] != count:
                raise ValueError('fixture state count')
            done = True
            continue
        if not b:
            continue
        if len(b) < 171:
            raise ValueError('short state')
        sid, creator, direction = struct.unpack_from('!QIB', b)
        iface, orig = (b[o:o + 16].split(b'\0', 1)[0].decode('ascii') for o in (13, 29))
        age, bi, bo, pi, po, ps, pd = struct.unpack_from('!IQQQQBB', b, 45)
        pos, keys = 83, []
        for _ in range(2):
            proto = b[pos]
            pos += 1
            ends = []
            for _ in range(2):
                ends.append((address(b[pos:pos + 17]), struct.unpack_from('!H', b, pos + 17)[0]))
                pos += 19
            keys.append((proto, ends))
        expire, rule = struct.unpack_from('!II', b, pos)
        pos += 8
        length, = struct.unpack_from('!H', b, pos)
        pos += 2
        if pos + length != len(b):
            raise ValueError('state label length')
        label = b[pos:].decode('utf-8')
        count += 1
        yield {'id': sid, 'creator': creator, 'direction': direction, 'iface': iface, 'orig': orig,
               'age': age, 'expire': expire, 'rule': rule, 'bytes': (bi, bo), 'packets': (pi, po),
               'peer': (ps, pd), 'keys': keys, 'label': label}
    if not done:
        raise ValueError('fixture missing completion')


def encode_state(s):
    b = struct.pack('!QIB', s['id'], s['creator'], s['direction'])
    b += s['iface'].encode().ljust(16, b'\0') + s['orig'].encode().ljust(16, b'\0')
    b += struct.pack('!IQQQQBB', s['age'], *s['bytes'], *s['packets'], *s['peer'])
    for proto, ends in s['keys']:
        b += bytes([proto])
        for ip, port in ends:
            b += address_bytes(ip) + struct.pack('!H', port)
    b += struct.pack('!II', s.get('expire', 30), s.get('rule', 123))
    label = s['label'].encode()
    return b + struct.pack('!H', len(label)) + label


def state_text(s):
    """Same-family subset of OPNsense pf_print_state.c, not endpoint policy.

    Reader validation separately checks actual pfctl output by state identity.
    Cross-family translation is explicitly rejected, never guessed.
    """
    proto = PROTO.get(s['keys'][0][0], str(s['keys'][0][0]))
    wire, stack = (list(k[1]) for k in s['keys'])
    if ipaddress.ip_address(wire[0][0]).version != ipaddress.ip_address(stack[0][0]).version:
        raise ValueError('cross-family fixture')
    outgoing = s['direction'] == 2
    nk, sk = (wire, stack) if outgoing else (stack, wire)
    if proto in ('icmp', 'ipv6-icmp'):
        sk[0 if outgoing else 1] = (sk[0 if outgoing else 1][0], nk[0 if outgoing else 1][1])

    def host(e):
        ip, port = e
        return ip + (f'[{port}]' if ':' in ip else f':{port}') if port else ip

    left = host(nk[1]) + (f' ({host(sk[1])})' if nk[1] != sk[1] else '')
    right = host(nk[0]) + (f' ({host(sk[0])})' if nk[0] != sk[0] else '')
    peers = s['peer'] if outgoing else s['peer'][::-1]
    if proto == 'tcp':
        names = ('CLOSED', 'LISTEN', 'SYN_SENT', 'SYN_RECEIVED', 'ESTABLISHED', 'CLOSE_WAIT',
                 'FIN_WAIT_1', 'CLOSING', 'LAST_ACK', 'FIN_WAIT_2', 'TIME_WAIT')
        status = ':'.join(names[p] if p < len(names) else str(p) for p in peers)
    elif proto not in ('icmp', 'ipv6-icmp', 'sctp') and max(peers) < 3:
        status = ':'.join(('NO_TRAFFIC', 'SINGLE', 'MULTIPLE')[p] for p in peers)
    else:
        status = ':'.join(map(str, peers))
    age = s['age']
    label = f", rlabel {s['label']}" if s['label'] else ''
    return (f"{s['iface']} {proto} {left} {'->' if outgoing else '<-'} {right} {status}\n"
            f"   age {age // 3600:02}:{age // 60 % 60:02}:{age % 60:02}, expires in 00:00:00, "
            f"{s['packets'][0]}:{s['packets'][1]} pkts, {s['bytes'][0]}:{s['bytes'][1]} bytes{label}\n"
            f"   id: {s['id']:016x} creatorid: {s['creator']:08x}\n   origif: {s['orig']}\n")


def classification_rows(common):
    """Export the target Python's policy as intervals, including mapped IPv4.

    Private ipaddress constants are development-only, not a production API.
    Every policy interval is checked at its endpoints and midpoint.
    """
    rows = []
    boundaries4 = set()
    for version, cls in ((4, ipaddress.IPv4Address), (6, ipaddress.IPv6Address)):
        maximum = 1 << (32 if version == 4 else 128)
        bounds = {0, maximum}
        for v in vars(cls._constants).values():
            for item in v if isinstance(v, (tuple, list)) else (v,):
                if isinstance(item, (ipaddress.IPv4Network, ipaddress.IPv6Network)) and item.version == version:
                    bounds.update((int(item.network_address), int(item.broadcast_address) + 1))
        if version == 4:
            bounds.update((int(common.CGNAT.network_address), int(common.CGNAT.broadcast_address) + 1))
            boundaries4 = bounds
        else:
            base = int(ipaddress.IPv6Address('::ffff:0:0'))
            bounds.update(base + n for n in boundaries4)
        ordered = sorted(bounds)
        for lo, stop in zip(ordered, ordered[1:]):
            values = []
            for n in (lo, (lo + stop - 1) // 2, stop - 1):
                ip = str(cls(n))
                values.append(int(common.public_ip(ip)) | int(common.private_ip(ip)) * 2)
            if len(set(values)) != 1:
                raise ValueError('classification interval not uniform')
            rows.append(f'R {cls(lo)} {cls(stop - 1)} {values[0]}')
    return rows


def make_context(path, common, local, networks, assigned, wan):
    rows = classification_rows(common)
    rows += [f'L {a}' for a in sorted(local)]
    rows += [f'N {n.network_address} {n.prefixlen} {d}' for n, d in networks]
    rows += [f'A {a} {d}' for d, values in assigned.items() for a in sorted(values)]
    if wan:
        rows.append(f'W {wan}')
    groups = {}
    for (proto, port), name in common.SERVICES.items():
        groups.setdefault(name, len(groups) + 2)
        number = next(k for k, v in PROTO.items() if v == proto)
        rows.append(f'S {number} {port} {groups[name]}')
    path.write_text('\n'.join(rows) + '\n')
    return {'local': sorted(local), 'networks': [(str(n), d) for n, d in networks],
            'assigned': {d: sorted(v) for d, v in assigned.items()}, 'wan': wan}


def read_aggregates(path, common):
    result, counts, correlations = {}, {}, {}
    checksum, complete, started, has_deltas = 0, False, False, False
    candidate_count = correlation_count = 0
    magic = path.read_bytes()[:8]
    if magic not in (b'FMAGG1\0\0', b'FMAGG2\0\0'):
        raise ValueError('aggregate magic/version')
    for size, b in frames(path, magic):
        if complete or not b:
            raise ValueError('trailing/empty aggregate record')
        if b[0] != 255:
            checksum = zlib.crc32(size + b, checksum)
        if b[0] == 0:
            expected = (1, 7) if magic == b'FMAGG1\0\0' else (2, 15)
            if started or len(b) != 9 or struct.unpack('!II', b[1:]) != expected:
                if magic != b'FMAGG2\0\0' or len(b) != 9 or struct.unpack('!I', b[1:5]) != (2,):
                    raise ValueError('capabilities/version')
                flags, = struct.unpack('!I', b[5:])
                if flags not in (47, 63):
                    raise ValueError('capabilities/flags')
                has_deltas = bool(flags & 16)
            started = True
        elif not started:
            raise ValueError('missing capabilities')
        elif b[0] == 1:
            flow_length = 91 if magic == b'FMAGG1\0\0' else 119 if has_deltas else 95
            if len(b) != flow_length:
                raise ValueError('flow length')
            fid, = struct.unpack_from('!I', b, 1)
            if fid != len(result):
                raise ValueError('flow order/identity')
            key = (address(b[5:22]), address(b[22:39]))
            states, toward, away, age = struct.unpack_from('!QQQI', b, 39)
            if magic == b'FMAGG2\0\0':
                youngest, remote, local, first = struct.unpack_from('!IQQQ', b, 67)
            else:
                youngest, remote, local, first = age, *struct.unpack_from('!QQQ', b, 67)
            if has_deltas:
                dtoward, daway, packets = struct.unpack_from('!QQQ', b, 95 if magic == b'FMAGG2\0\0' else 91)
            else:
                dtoward = daway = packets = 0
            result[fid] = {'key': key, 'states': states, 'bytes_toward': toward, 'bytes_away': away,
                           'oldest': age, 'youngest': youngest, 'remote_started': remote,
                           'local_started': local, 'first': first,
                           'toward': dtoward, 'away': daway, 'packets': packets}
            counts[fid] = []
        elif b[0] == 2:
            if len(b) < 32:
                raise ValueError('candidate length')
            fid, kind, seq, weight, value, length = struct.unpack_from('!IBQQQH', b, 1)
            if fid not in counts or kind not in range(1, 7) or length != len(b) - 32:
                raise ValueError('candidate identity/length')
            counts[fid].append((seq, kind, b[32:], weight, value))
            candidate_count += 1
        elif b[0] == 3:
            if magic != b'FMAGG2\0\0' or len(b) != 174:
                raise ValueError('correlation record length/version')
            proto = b[1]
            public = address(b[2:19])
            public_port, = struct.unpack_from('!H', b, 19)
            remote = address(b[21:38])
            remote_port, = struct.unpack_from('!H', b, 38)
            has_inside = b[40]
            inside = address(b[41:58]) if has_inside else None
            inside_port, = struct.unpack_from('!H', b, 58)
            state_id, creator = struct.unpack_from('!QI', b, 60)
            ambiguous = b[72]
            age = struct.unpack_from('!I', b, 73)[0]
            # oriented by the PF initiator: from/to the remote (reference.DIVERGENCES)
            bytes_in, bytes_out = struct.unpack_from('!QQ', b, 77)
            remote_started = b[93]
            interface = b[94:110].split(b'\0', 1)[0].decode('ascii')
            rule = b[110:174].split(b'\0', 1)[0].decode('utf-8')
            key = (proto, public, str(public_port) if public_port else '',
                   remote, str(remote_port) if remote_port else '')
            if key in correlations or has_inside not in (0, 1) or ambiguous not in (0, 1):
                raise ValueError('correlation key/flags')
            correlations[key] = {'inside': inside, 'inside_port': inside_port if has_inside else None,
                                 'id': state_id, 'creator': creator, 'ambiguous': bool(ambiguous),
                                 'age': age, 'bytes_in': bytes_in, 'bytes_out': bytes_out,
                                 'remote_started': bool(remote_started), 'interface': interface,
                                 'rule': rule or None}
            correlation_count += 1
        elif b[0] == 255:
            if len(b) != (49 if magic == b'FMAGG1\0\0' else 57):
                raise ValueError('completion length')
            if magic == b'FMAGG2\0\0':
                total, retained, mapped, flows, candidates, correlations_expected, expected = struct.unpack('!QQQQQQQ', b[1:])
            else:
                total, retained, mapped, flows, candidates, expected = struct.unpack('!QQQQQQ', b[1:])
                correlations_expected = 0
            if expected != checksum or flows != len(result) or candidates != candidate_count:
                raise ValueError('completion checksum/counts')
            if correlations_expected != correlation_count:
                raise ValueError('completion correlation count')
            if mapped != sum(r['states'] for r in result.values()) or not mapped <= retained <= total:
                raise ValueError('state counts')
            complete = True
        else:
            raise ValueError('unknown record')
    if not complete:
        raise ValueError('missing successful completion')
    normalized = []
    for fid, r in result.items():
        r.pop('first')
        if not has_deltas:
            r.update(toward=0, away=0, packets=0)
        r.update(protocols=set(), services={}, inside={}, egress={}, targets={}, ports={}, rules={})
        for seq, kind, b, weight, value in sorted(counts[fid], key=lambda c: c[0]):
            if kind == 1:
                if len(b) != 1:
                    raise ValueError('protocol')
                r['protocols'].add(PROTO.get(b[0], str(b[0])))
                continue
            field = {2: 'inside', 3: 'egress', 4: 'services', 5: 'targets', 6: 'rules'}[kind]
            if kind == 2:
                key = address(b)
            elif kind == 4:
                if len(b) != 7:
                    raise ValueError('service')
                proto = PROTO.get(value >> 16, str(value >> 16))
                port = str(value & 65535) if value & 65535 else None
                key = common.service_name(proto, port)
                r['ports'].setdefault(key, common.service_port_label(proto, port))
            elif kind == 5:
                if len(b) != 20:
                    raise ValueError('target')
                proto = PROTO.get(b[0], str(b[0]))
                port, = struct.unpack_from('!H', b, 18)
                key = common.connection_target(proto, address(b[1:18]), str(port) if port else None)
            else:
                key = b.decode('utf-8' if kind == 6 else 'ascii')
            r[field][key] = r[field].get(key, 0) + weight
        normalized.append(normalize(r))
    return normalized, {'states': total, 'retained': retained, 'mapped': mapped, 'flows': flows,
                        'candidates': candidates, 'correlations': correlation_count}, correlations


def normalize(r):
    # The retired Python engine did not retain the collector-only youngest-state age.
    return {k: sorted(v) if k == 'protocols' else list(v.items()) if isinstance(v, dict) else v
            for k, v in r.items() if k != 'youngest'}


def synthetic(path):
    states = []

    def add(src, dst, inside=None, direction=2, label='', orig='wan0', proto=6, age=100, peer=(4, 4), wire_target=None):
        if direction == 2:
            wire, stack = [dst, src], [dst, inside or src]
        else:
            wire, stack = [src, wire_target or dst], [src, dst]
        states.append({'id': len(states) + 1, 'creator': 0x1234, 'direction': direction, 'iface': 'all',
                       'orig': orig, 'age': age, 'bytes': (100 + len(states), 200 + len(states)),
                       'packets': (2, 3), 'peer': peer, 'keys': [(proto, wire), (proto, stack)], 'label': label})

    add(('8.8.4.4', 40000), ('9.9.9.9', 443), ('192.168.1.10', 50000), label='nat')
    add(('8.8.4.4', 40001), ('9.9.9.9', 443), ('192.168.1.11', 50001), label='nat')
    add(('192.168.1.10', 50000), ('9.9.9.9', 443), direction=1, label='lan-old', orig='lan0')
    add(('192.168.1.10', 50000), ('9.9.9.9', 443), direction=1, label='lan-new', orig='lan0')
    add(('9.9.9.9', 55000), ('192.168.1.20', 443), direction=1, wire_target=('8.8.4.4', 8443), label='forward')
    add(('8.8.4.4', 443), ('9.9.9.9', 55000), ('192.168.1.20', 443), label='ha-reply')
    add(('8.8.4.4', 53000), ('1.1.1.1', 53), proto=17, peer=(1, 2), label='dns')
    add(('8.8.4.4', 53001), ('1.1.1.1', 53), proto=6, label='dns')
    add(('8.8.4.4', 53002), ('1.1.1.1', 443), proto=6)
    add(('8.8.4.4', 0), ('9.9.9.9', 55000), label='zero-port')
    add(('2600:1::10', 50000), ('2606:4700::1111', 443), orig='wan0', label='routed-v6')
    add(('2001:4860::8888', 50000), ('2606:4700::1111', 443), label='firewall-v6')
    add(('192.168.0.2', 40000), ('9.9.9.9', 443), ('192.168.1.10', 50000), label='double-nat')
    add(('9.9.9.9', 50000), ('192.168.1.20', 443), direction=1, wire_target=('192.168.0.2', 8443), label='double-forward')
    add(('10.0.0.2', 40000), ('9.9.9.9', 443), ('192.168.1.30', 50000), orig='tunnel0', label='tunnel')
    add(('8.8.4.4', 123), ('1.1.1.1', 0), proto=1, peer=(0, 0), label='icmp')
    add(('8.8.4.4', 124), ('1.1.1.1', 0), ('192.168.1.40', 7), proto=1, peer=(0, 0), label='nat-icmp')
    add(('192.168.1.40', 7), ('1.1.1.1', 0), direction=1, orig='lan0', proto=1, peer=(0, 0), label='lan-icmp')
    add(('2001:4860::8888', 123), ('2606:4700::1111', 0), proto=58, peer=(0, 0), label='icmp6')
    add(('192.168.1.2', 50000), ('192.168.1.3', 443), label='internal')
    with path.open('wb') as f:
        f.write(b'FMPFS2\0\0')
        for s in states:
            f.write(frame(encode_state(s)))
        f.write(frame(b'') + struct.pack('!Q', len(states)))


def compare(directory, pf, collector, common):
    ctx = json.loads((directory / 'context.json').read_text())
    local = set(ctx['local'])
    networks = [(ipaddress.ip_network(n), d) for n, d in ctx['networks']]
    assigned = {d: set(v) for d, v in ctx['assigned'].items()}
    start = time.perf_counter()
    text = ''.join(state_text(s) for s in decoded_states(directory / 'captured.bin'))
    formatting = time.perf_counter() - start
    start = time.perf_counter()
    records = pf.parse_states(text)
    parsing = time.perf_counter() - start
    facts = pf.StateFacts()
    start = time.perf_counter()
    sample = facts.view(records, local, networks, assigned, ctx['wan'])
    facts_time = time.perf_counter() - start
    start = time.perf_counter()
    totals, _ = collector.FlowTracker()._totals(records, local, None, networks, sample, assigned, ctx['wan'])
    totals_time = time.perf_counter() - start
    reference = [normalize({'key': key, **dict(value)}) for key, value in totals.items()]
    actual, counts, correlation_rows = read_aggregates(directory / 'aggregates.bin', common)
    if len(reference) != len(actual):
        raise AssertionError(f'flow count mismatch: {len(reference)} != {len(actual)}')
    for index, (expected, observed) in enumerate(zip(reference, actual)):
        if expected != observed:
            differences = {k: {'python': expected.get(k), 'collector': observed.get(k)}
                           for k in expected.keys() | observed.keys() if expected.get(k) != observed.get(k)}
            raise AssertionError(json.dumps({'flow_index': index, 'differences': differences}, indent=2))
    print(json.dumps({'equivalence': 'exact', **counts, 'format_fixture_ms': formatting * 1000,
                      'parse_ms': parsing * 1000, 'facts_ms': facts_time * 1000, 'totals_ms': totals_time * 1000}))


def aggregate_integrity(directory, common):
    original = (directory / 'aggregates.bin').read_bytes()
    path = directory / 'invalid-aggregate.bin'
    corrupted = bytearray(original)
    corrupted[min(90, len(corrupted) - 1)] ^= 1
    for name, value in [('missing_footer', original[:-61]), ('truncated_footer', original[:-1]),
                        ('corrupt_record', bytes(corrupted)), ('trailing_bytes', original + b'x')]:
        path.write_bytes(value)
        try:
            read_aggregates(path, common)
        except (ValueError, UnicodeDecodeError, struct.error):
            continue
        raise AssertionError(f'aggregate integrity accepted {name}')
    print(json.dumps({'aggregate_integrity': '4 rejection cases passed'}))


def ordering_checks(directory, helper, pf, collector, common):
    original = list(decoded_states(directory / 'captured.bin'))
    for index in range(4):
        sample = directory / f'order-{index}'
        sample.mkdir(exist_ok=True)
        (sample / 'context.txt').write_bytes((directory / 'context.txt').read_bytes())
        (sample / 'context.json').write_bytes((directory / 'context.json').read_bytes())
        states = list(original) if index < 3 else []
        random.Random(index).shuffle(states)
        with (sample / 'captured.bin').open('wb') as f:
            f.write(b'FMPFS2\0\0')
            for s in states:
                f.write(frame(encode_state(s)))
            f.write(frame(b'') + struct.pack('!Q', len(states)))
        subprocess.run([str(helper.resolve()), 'fixture', str(sample / 'context.txt'),
                        str(sample / 'aggregates.bin'), str(sample / 'captured.bin')], check=True)
        compare(sample, pf, collector, common)
        aggregate_integrity(sample, common)


def reader_checks(directory, helper, pf):
    states = list(decoded_states(directory / 'reader-captured.bin'))
    text = (directory / 'reader-pfctl.txt').read_text()
    blocks = re.split(r'(?=^[^ \t])', text, flags=re.M)
    by_id = {}
    for block in blocks:
        match = pf.STATE_ID.search(block)
        if match:
            by_id[(int(match['id'], 16), int(match['creator'], 16))] = block
    checked, mismatches, changed, categories = [], [], [], set()
    # Bounded diagnostics; favor labels and translations, plus IPv6.
    ordered = sorted(states, key=lambda s: (not bool(s['label']), s['keys'][0] == s['keys'][1]))
    for s in ordered:
        if len(checked) == 16:
            break
        block = by_id.get((s['id'], s['creator']))
        if block is None:
            continue
        expected_header = state_text(s).splitlines()[0].split()
        actual_header = block.splitlines()[0].split()
        # pfctl names ICMPv6 peer states like other protocols' (NO_TRAFFIC, SINGLE, MULTIPLE) when
        # pf_print_state.c is built without INET6 (OPNsense's pfctl is), else prints the numbers:
        # either rendering of the same decoded peers is the same state
        if s['keys'][0][0] == 58 and max(s['peer']) < 3 and actual_header[-1:] != expected_header[-1:]:
            peers = s['peer'] if s['direction'] == 2 else s['peer'][::-1]
            named = ':'.join(('NO_TRAFFIC', 'SINGLE', 'MULTIPLE')[p] for p in peers)
            if actual_header[-1:] == [named]:
                expected_header = expected_header[:-1] + [named]
        record = pf.parse_states(block)
        if not record:
            continue  # production intentionally skips internal/multicast-only headers
        record = record[0]
        category = (bool(s['label']), s['keys'][0] != s['keys'][1], s['direction'],
                    s['keys'][0][0], ipaddress.ip_address(s['keys'][0][1][0][0]).version)
        if category in categories:
            continue
        categories.add(category)
        numeric = re.search(r'\brule (\d+)', block)
        numeric = int(numeric[1]) if numeric else 0xffffffff
        expires = re.search(r'expires in (\d+):(\d+):(\d+)', block)
        expiry = sum(int(v) * unit for v, unit in zip(expires.groups(), (3600, 60, 1)))
        identity_fields = {'header/keys/direction/protocol': (expected_header, actual_header),
                           'interface': (s['iface'], record.interface), 'original_interface': (s['orig'], record.origif),
                           'id/creator': (f"{s['id']:016x}/{s['creator']:08x}", record.id),
                           'numeric_rule': (s['rule'], numeric), 'rule_label': (s['label'] or None, record.rule)}
        differences = {k: v for k, v in identity_fields.items() if v[0] != v[1]}
        if differences:
            mismatches.append({'id': record.id, 'differences': differences})
        moving = {'bytes': (s['bytes'], (record.bytes_in, record.bytes_out)),
                  'packets': (s['packets'], (record.packets_in, record.packets_out)),
                  'age': (s['age'], record.age), 'expire': (s['expire'], expiry)}
        delta = {k: v for k, v in moving.items() if v[0] != v[1]}
        if delta:
            changed.append({'id': record.id, 'between_exports': delta})
        checked.append({'id': record.id, 'labeled': bool(s['label']),
                        'nat': s['keys'][0] != s['keys'][1], 'direction': s['direction'],
                        'protocol': s['keys'][0][0], 'af': ipaddress.ip_address(s['keys'][0][1][0][0]).version})
    print(json.dumps({'reader_comparison': checked, 'identity_mismatches': mismatches,
                      'moving_fields_changed': changed}, indent=2))
    if mismatches or len(checked) < 4 or not any(s['labeled'] for s in checked):
        raise AssertionError('reader semantic verification failed or insufficient labeled states')
    wire = (directory / 'reader-wire.bin').read_bytes()
    seq, family = struct.unpack_from('!II', wire, 8)
    datagrams, pos = [], 16
    while pos < len(wire):
        n, = struct.unpack_from('!I', wire, pos)
        pos += 4
        datagrams.append(wire[pos:pos + n])
        pos += n
    first = next(d for d in datagrams if struct.unpack_from('<H', d, 4)[0] == family)

    def message(kind, payload, flags=2, sequence=seq):
        return struct.pack('<IHHII', 16 + len(payload), kind, flags, sequence, 0) + payload

    done = message(3, struct.pack('<i', 0))
    first_length, = struct.unpack_from('<I', first)
    first = first[:first_length]

    def state_attr_change(kind, operation):
        data = bytearray(first)
        p = 20
        while p < len(data):
            length, attr = struct.unpack_from('<HH', data, p)
            if attr & 0x3fff == kind:
                if operation == 'remove':
                    del data[p:p + ((length + 3) & ~3)]
                    struct.pack_into('<I', data, 0, len(data))
                elif operation == 'short':
                    struct.pack_into('<H', data, p, 3)
                elif operation == 'string':
                    data[p + length - 1] = 65
                elif operation == 'version':
                    struct.pack_into('<Q', data, p + 4, 0xffff)
                elif operation == 'port':
                    nested = p + 4
                    while nested < p + length:
                        nested_len, nested_type = struct.unpack_from('<HH', data, nested)
                        if nested_type & 0x3fff == 3:
                            struct.pack_into('<H', data, nested, 7)
                            break
                        nested += (nested_len + 3) & ~3
                elif operation == 'duplicate':
                    struct.pack_into('<H', data, p + 2, 1)
                return bytes(data)
            p += (length + 3) & ~3
        raise AssertionError('required fault attribute absent')

    cases = {'valid_empty': ([done], True), 'valid_capture': (datagrams, True),
             'missing_done': ([first], False), 'ack_without_done': ([message(2, struct.pack('<i', 0) + bytes(16))], False),
             'kernel_error': ([message(2, struct.pack('<i', -13) + bytes(16))], False),
             'done_error': ([message(3, struct.pack('<i', 12))], False),
             'malformed_state': ([state_attr_change(1, 'short'), done], False),
             'missing_rule_label': ([state_attr_change(40, 'remove'), done], False),
             'unterminated_rule_label': ([state_attr_change(40, 'string'), done], False),
             'malformed_after_valid': ([first, state_attr_change(1, 'short'), done], False),
             'bad_key_port_size': ([state_attr_change(5, 'port'), done], False),
             'duplicate_id': ([state_attr_change(40, 'duplicate'), done], False),
             'wrong_state_abi': ([state_attr_change(28, 'version'), done], False),
             'truncated_datagram': ([first[:-1]], False),
             'dump_interrupted': ([message(family, first[16:], flags=0x12), done], False),
             'wrong_sequence': ([message(family, first[16:], sequence=seq + 1), done], False),
             'short_header': ([b'bad'], False), 'short_done': ([message(3, b'')], False),
             'after_done': ([done, first], False)}
    results = []
    for name, (parts, success) in cases.items():
        path = directory / f'fault-{name}.bin'
        path.write_bytes(wire[:16] + b''.join(frame(d) for d in parts))
        output = directory / 'fault-output.bin'
        run = subprocess.run([str(helper.resolve()), 'wire', '-', '-', str(output), str(path)],
                             capture_output=True, text=True)
        if (run.returncode == 0) != success:
            raise AssertionError(f'{name}: {run.returncode} {run.stderr}')
        try:
            list(decoded_states(output))
            complete = True
        except ValueError:
            complete = False
        if complete != success:
            raise AssertionError(f'{name}: completion incorrectly accepted')
        results.append({'case': name, 'exit': run.returncode, 'complete': complete,
                        'error': run.stderr.splitlines()[0] if not success else None})
    print(json.dumps({'multipart_fault_tests': results}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('context', 'live', 'synthetic', 'compare', 'decode', 'reference', 'readercheck', 'ordering'))
    parser.add_argument('--src', type=Path, required=True)
    parser.add_argument('--helper', type=Path, required=True)
    parser.add_argument('--dir', type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.src.resolve()))
    from lib import common
    from reference import pf
    directory = args.dir
    directory.mkdir(exist_ok=True)
    if args.mode == 'readercheck':
        reader_checks(directory, args.helper, pf)
        return
    if args.mode == 'decode':
        start = time.perf_counter()
        result, counts, _ = read_aggregates(directory / 'aggregates.bin', common)
        decode_ms = (time.perf_counter() - start) * 1000
        del result
        tracemalloc.start()
        result, counts, _ = read_aggregates(directory / 'aggregates.bin', common)
        current, peak = tracemalloc.get_traced_memory()
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if sys.platform == 'darwin':
            rss /= 1024
        print(json.dumps({**counts, 'decode_ms': decode_ms,
                          'python_retained_bytes': current, 'python_peak_allocated_bytes': peak,
                          'process_peak_rss_kib': rss, 'aggregate_bytes': (directory / 'aggregates.bin').stat().st_size,
                          'objects': len(result)}))
        return
    if args.mode == 'reference':
        from reference import tracker as collector
        values = json.loads((directory / 'context.json').read_text())
        local = set(values['local'])
        networks = [(ipaddress.ip_network(n), d) for n, d in values['networks']]
        assigned = {d: set(v) for d, v in values['assigned'].items()}
        text = ''.join(state_text(s) for s in decoded_states(directory / 'captured.bin'))
        tracemalloc.start()
        records = pf.parse_states(text)
        facts = pf.StateFacts()
        sample = facts.view(records, local, networks, assigned, values['wan'])
        totals, counters = collector.FlowTracker()._totals(records, local, None, networks, sample, assigned, values['wan'])
        current, peak = tracemalloc.get_traced_memory()
        print(json.dumps({'records': len(records), 'facts': len(sample[0]), 'flows': len(totals), 'counter_entries': len(counters),
                          'python_retained_bytes': current, 'python_peak_allocated_bytes': peak,
                          'process_peak_rss_kib': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}))
        return
    if args.mode in ('context', 'synthetic'):
        if args.mode == 'synthetic':
            local = {'8.8.4.4', '8.8.4.10', '2001:4860::8888'}
            networks = [(ipaddress.ip_network(n), d) for n, d in
                        [('192.168.1.0/24', 'lan0'), ('2600:1::/64', 'lan0'), ('8.8.4.0/24', 'wan0')]]
            assigned = {'wan0': {'192.168.0.2', *local}}
            wan = 'wan0'
            synthetic(directory / 'captured.bin')
        else:
            from lib.config import topology
            local, _, networks, assigned = pf.host_info()
            wan = topology()['primary_wan_device']
        values = make_context(directory / 'context.txt', common, local, networks, assigned, wan)
        (directory / 'context.json').write_text(json.dumps(values))
        if args.mode == 'context':
            print(json.dumps({'policy_rows': len(classification_rows(common)), 'local_count': len(local), 'networks': len(networks)}))
            return
    if args.mode in ('live', 'synthetic'):
        mode = 'live' if args.mode == 'live' else 'fixture'
        subprocess.run([str(args.helper.resolve()), mode, str(directory / 'context.txt'),
                        str(directory / 'aggregates.bin'), str(directory / 'captured.bin')], check=True)
    from reference import tracker as collector
    if args.mode == 'ordering':
        ordering_checks(directory, args.helper, pf, collector, common)
        return
    compare(directory, pf, collector, common)
    aggregate_integrity(directory, common)


if __name__ == '__main__':
    main()
