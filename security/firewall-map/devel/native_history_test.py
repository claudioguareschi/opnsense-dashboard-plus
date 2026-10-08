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

"""Compare native multi-sample history and correlation with Firewall Map."""

import argparse
import ipaddress
import json
import struct
import subprocess
import sys
from pathlib import Path

import native_equivalence as oracle


def write_sample(path, states):
    with path.open('wb') as output:
        output.write(b'FMPFS2\0\0')
        for state in states:
            output.write(oracle.frame(oracle.encode_state(state)))
        output.write(oracle.frame(b'') + struct.pack('!Q', len(states)))


def history_test(directory, helper, pf, collector, common):
    local = {'8.8.4.4', '8.8.4.10', '2001:4860::8888'}
    networks = [(ipaddress.ip_network(n), d) for n, d in
                [('192.168.1.0/24', 'lan0'), ('2600:1::/64', 'lan0'), ('8.8.4.0/24', 'wan0')]]
    assigned = {'wan0': {'192.168.0.2', *local}}
    context_path = directory / 'history-context.txt'
    oracle.make_context(context_path, common, local, networks, assigned, 'wan0')
    base_path = directory / 'history-base.bin'
    oracle.synthetic(base_path)
    initial = list(oracle.decoded_states(base_path))
    records = pf.parse_states(''.join(oracle.state_text(s) for s in initial))
    views, _ = pf.StateFacts().view(records, local, networks, assigned, 'wan0')
    mapped_ids = {record.id for record, facts in views if facts.pair is not None}
    mapped = [s for s in initial if f"{s['id']:016x}/{s['creator']:08x}" in mapped_ids]
    if len(mapped) < 6:
        raise AssertionError('history fixture lacks mapped states')

    first = [dict(s) for s in mapped[:5]]
    second = [dict(s) for s in first[:3]]
    second[0]['bytes'] = tuple(v + d for v, d in zip(second[0]['bytes'], (100, 200)))
    second[0]['packets'] = tuple(v + d for v, d in zip(second[0]['packets'], (4, 6)))
    second[1]['bytes'] = second[1]['packets'] = (0, 0)
    second[2]['bytes'] = tuple(v + 10 for v in second[2]['bytes'])
    second[2]['packets'] = tuple(v + 2 for v in second[2]['packets'])
    new_state = dict(mapped[5])
    new_state['age'] = 1
    second.append(new_state)
    same_id_new_creator = dict(first[0])
    same_id_new_creator['creator'] += 1
    same_id_new_creator['age'] = 100
    same_id_new_creator['bytes'] = (5000, 6000)
    second.append(same_id_new_creator)
    third = [dict(s) for s in second[:3]]
    third[0]['bytes'] = tuple(v + d for v, d in zip(third[0]['bytes'], (70, 30)))
    third[0]['packets'] = tuple(v + d for v, d in zip(third[0]['packets'], (3, 1)))
    reappeared = dict(first[3])
    reappeared['age'] = 100
    third.append(reappeared)
    fourth = [dict(s) for s in third]
    fourth[0]['bytes'] = fourth[0]['packets'] = (2, 1)
    samples = [first, second, third, fourth]
    sample_paths = []
    for index, sample in enumerate(samples):
        sample_path = directory / f'history-{index}.bin'
        write_sample(sample_path, sample)
        sample_paths.append(sample_path)

    prefix = directory / 'history-result'
    command = [str(helper.resolve()), 'sequence', str(context_path), str(prefix)]
    for index, sample_path in enumerate(sample_paths):
        command.extend((str(sample_path), '-1' if index == 0 else '2'))
    subprocess.run(command, check=True)

    tracker = collector.FlowTracker()
    flow_counts = []
    for index, sample in enumerate(samples):
        records = pf.parse_states(''.join(oracle.state_text(s) for s in sample))
        state_view = pf.StateFacts().view(records, local, networks, assigned, 'wan0')
        totals, tracker.counters = tracker._totals(
            records, local, None if index == 0 else 2, networks, state_view,
            assigned, 'wan0')
        expected = [oracle.normalize({'key': key, **dict(value)})
                    for key, value in totals.items()]
        actual, _, _ = oracle.read_aggregates(directory / f'history-result.{index}', common)
        if actual != expected:
            for flow_index, (want, got) in enumerate(zip(expected, actual)):
                differences = {key: (want.get(key), got.get(key))
                               for key in want.keys() | got.keys()
                               if want.get(key) != got.get(key)}
                if differences:
                    raise AssertionError(f'sample {index}, flow {flow_index}: {differences}')
            raise AssertionError(f'sample {index}: flow count differs')
        flow_counts.append(len(actual))
    print(json.dumps({'history_equivalence': 'exact', 'samples': len(samples),
                      'flow_counts': flow_counts}))


def correlation_test(directory, helper, pf, common):
    states = list(oracle.decoded_states(directory / 'history-base.bin'))
    duplicate = dict(states[0])
    duplicate['id'] = 0x900001
    duplicate['keys'] = [(proto, list(ends)) for proto, ends in duplicate['keys']]
    duplicate['keys'][1][1][1] = ('192.168.1.99', 50999)
    states.append(duplicate)
    sample_path = directory / 'correlation-duplicate.bin'
    write_sample(sample_path, states)
    output = directory / 'correlation-duplicate.agg'
    subprocess.run([str(helper.resolve()), 'fixture', str(directory / 'history-context.txt'),
                    str(output), str(sample_path)], check=True)
    _, _, actual = oracle.read_aggregates(output, common)

    local = {'8.8.4.4', '8.8.4.10', '2001:4860::8888'}
    networks = [(ipaddress.ip_network(n), d) for n, d in
                [('192.168.1.0/24', 'lan0'), ('2600:1::/64', 'lan0'), ('8.8.4.0/24', 'wan0')]]
    assigned = {'wan0': {'192.168.0.2', *local}}
    records = pf.parse_states(''.join(oracle.state_text(s) for s in states))
    views, _ = pf.StateFacts().view(records, local, networks, assigned, 'wan0')
    expected, ambiguous = {}, set()
    protocol_number = {name: number for number, name in oracle.PROTO.items()}
    for record, facts in views:
        if facts.pair is None or facts.outside is None:
            continue
        proto, public, public_port, remote, remote_port = facts.outside
        key = (protocol_number[proto], public, public_port, remote, remote_port)
        identity, creator = (int(part, 16) for part in record.id.split('/'))
        inside = facts.inside
        value = {'inside': inside.address if inside else None,
                 'inside_port': int(inside.port) if inside else None,
                 'id': identity, 'creator': creator, 'ambiguous': False}
        previous = expected.get(key)
        if previous and (previous['inside'], previous['inside_port']) != (
                value['inside'], value['inside_port']):
            ambiguous.add(key)
        expected[key] = value
    for key in ambiguous:
        expected[key]['ambiguous'] = True
    comparable = {key: {field: value[field] for field in expected[key]}
                  for key, value in actual.items() if key in expected}
    if set(actual) != set(expected) or comparable != expected:
        raise AssertionError('native outside-tuple index differs from Python')
    if not any(row['ambiguous'] for row in actual.values()):
        raise AssertionError('duplicate outside tuple did not set ambiguity')
    print(json.dumps({'correlation_equivalence': 'exact', 'keys': len(actual),
                      'ambiguous_duplicate': True, 'last_duplicate_wins': True}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--src', type=Path, required=True)
    parser.add_argument('--helper', type=Path, required=True)
    parser.add_argument('--dir', type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.src.resolve()))
    from lib import common
    from reference import pf
    from reference import tracker as collector
    args.dir.mkdir(exist_ok=True)
    history_test(args.dir, args.helper, pf, collector, common)
    correlation_test(args.dir, args.helper, pf, common)


if __name__ == '__main__':
    main()
