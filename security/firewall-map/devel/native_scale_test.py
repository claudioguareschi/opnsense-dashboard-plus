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

"""Offline 10k/70k/200k native aggregation sanity measurements."""

import argparse
import ipaddress
import json
import struct
import subprocess
import sys
import zlib
from pathlib import Path

import native_equivalence as oracle


def write_fixture(path, count, unique_flows):
    local = '8.8.4.4'
    with path.open('wb') as output:
        output.write(b'FMPFS2\0\0')
        for index in range(count):
            remote_id = index if unique_flows else index % 100
            remote = str(ipaddress.IPv4Address(0x0b000001 + remote_id))
            row = struct.pack('!QIB', index + 1, 0x1234, 2)
            row += b'all'.ljust(16, b'\0') + b'wan0'.ljust(16, b'\0')
            row += struct.pack('!IQQQQBB', 10, index + 100, index + 200,
                               index + 1, index + 2, 4, 4)
            for _ in range(2):
                row += b'\x06'
                for address, port in ((remote, 443), (local, 40000)):
                    row += oracle.address_bytes(address) + struct.pack('!H', port)
            row += struct.pack('!IIH', 30, 123, 0)
            output.write(oracle.frame(row))
        output.write(oracle.frame(b'') + struct.pack('!Q', count))


def verify_output(path):
    counts = {'flows': 0, 'candidates': 0, 'correlations': 0}
    checksum = 0
    with path.open('rb') as output:
        if output.read(8) != b'FMAGG2\0\0':
            raise ValueError('aggregate format version')
        while True:
            size = output.read(4)
            if len(size) != 4:
                raise ValueError('aggregate lacks completion record')
            length, = struct.unpack('!I', size)
            record = output.read(length)
            if len(record) != length or not record:
                raise ValueError('invalid aggregate frame')
            kind = record[0]
            if kind == 255:
                if length != 57:
                    raise ValueError('completion record size')
                total, retained, mapped, flows, candidates, correlations, expected = \
                    struct.unpack('!QQQQQQQ', record[1:])
                observed = tuple(counts[key] for key in ('flows', 'candidates', 'correlations'))
                if (flows, candidates, correlations) != observed or expected != checksum:
                    raise ValueError('completion counts/checksum')
                if not total == retained == mapped or output.read(1):
                    raise ValueError('completion state counts/trailing data')
                counts['states'] = total
                return counts
            checksum = zlib.crc32(size + record, checksum)
            if kind == 0:
                if length != 9 or struct.unpack('!II', record[1:]) != (2, 47):
                    raise ValueError('capability record')
            elif kind == 1:
                counts['flows'] += 1
            elif kind == 2:
                counts['candidates'] += 1
            elif kind == 3:
                counts['correlations'] += 1
            else:
                raise ValueError('unknown aggregate record')


def run(directory, helper, common):
    local = {'8.8.4.4', '8.8.4.10', '2001:4860::8888'}
    networks = [(ipaddress.ip_network('192.168.1.0/24'), 'lan0'),
                (ipaddress.ip_network('2600:1::/64'), 'lan0'),
                (ipaddress.ip_network('8.8.4.0/24'), 'wan0')]
    assigned = {'wan0': {'192.168.0.2', *local}}
    context = directory / 'scale-context.txt'
    oracle.make_context(context, common, local, networks, assigned, 'wan0')
    results = []
    for count in (10000, 70000, 200000):
        for unique in (False, True):
            case = 'high_cardinality' if unique else 'normal'
            fixture = directory / f'scale-{count}-{case}.bin'
            aggregate = directory / f'scale-{count}-{case}.agg'
            write_fixture(fixture, count, unique)
            result = subprocess.run([str(helper.resolve()), 'fixture', str(context),
                                     str(aggregate), str(fixture)],
                                    capture_output=True, text=True, check=True)
            metrics = {}
            for field in result.stderr.split():
                if '=' in field:
                    key, value = field.split('=', 1)
                    metrics[key] = float(value) if '.' in value else int(value)
            counts = verify_output(aggregate)
            expected_flows = count if unique else min(count, 100)
            if counts['states'] != count or counts['flows'] != expected_flows:
                raise AssertionError(f'{count} states, {case}: {counts}')
            results.append({'states': count, 'case': case,
                            'elapsed_ms': metrics['elapsed_ms'],
                            'peak_rss_kib': metrics['peak_rss_kib'],
                            'flows': counts['flows'],
                            'output_bytes': aggregate.stat().st_size})
            fixture.unlink()
            aggregate.unlink()
    print(json.dumps(results, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--src', type=Path, required=True)
    parser.add_argument('--helper', type=Path, required=True)
    parser.add_argument('--dir', type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.src.resolve()))
    from lib import common
    args.dir.mkdir(exist_ok=True)
    run(args.dir, args.helper, common)


if __name__ == '__main__':
    main()
