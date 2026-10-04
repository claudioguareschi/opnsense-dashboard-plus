/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

import assert from 'node:assert/strict';
import {test} from 'node:test';
import {blockSummary, flowSummary, idsOutcome, outcome} from '../src/summaries.js';

test('one verdict for flagged and stopped traffic everywhere', () => {
  assert.equal(outcome({flagged: true, stopped: false}), 'danger');
  assert.equal(outcome({flagged: true, stopped: true}), 'contained');
  assert.equal(outcome({flagged: false, stopped: true}), 'blocked');
  assert.equal(outcome({flagged: false, stopped: false}), 'ok');
});

test('an IDS connection is flagged by a severe alert or a threat list, stopped by a block or an IPS drop', () => {
  assert.equal(idsOutcome({severity: 1, kind: 'current'}), 'danger');
  assert.equal(idsOutcome({severity: 3, lists: ['Spamhaus DROP'], kind: 'current'}), 'danger');
  assert.equal(idsOutcome({severity: 3, kind: 'current'}), 'ok');
  assert.equal(idsOutcome({severity: 2, kind: 'blocked'}), 'contained');
  assert.equal(idsOutcome({severity: 3, kind: 'current', ips_dropped: true}), 'blocked');
});

test('sentences are whole phrases: rule, interface, services and targets', () => {
  const block = {source: '198.51.100.7', hits: 4, window_minutes: 10, services: [{name: 'SSH', port: '22/tcp'}, {name: 'Telnet', port: '23/tcp'}]};
  assert.equal(blockSummary(block),
    '198.51.100.7 tried SSH (22/tcp) and Telnet (23/tcp) on this firewall: blocked 4× in the last 10 min.');
  assert.equal(blockSummary({...block, rule: 'Default deny', interface: 'WAN', port_count: 5}),
    '198.51.100.7 tried SSH (22/tcp), Telnet (23/tcp) and 3 other ports on this firewall: blocked 4× in the last 10 min by "Default deny" on WAN.');
  assert.equal(blockSummary({...block, interface: 'WAN', services: []}),
    '198.51.100.7 tried a connection on this firewall: blocked 4× in the last 10 min on WAN.');
  const flow = {initiated: 'remote', targets: [{ip: '192.168.1.10', name: 'nas', service: 'HTTPS', port: 443}, {ip: '192.168.1.11'}]};
  assert.deepEqual(flowSummary(flow, {ip: '203.0.113.5'}),
    ['203.0.113.5 reached nas (192.168.1.10) (and 1 other target) on HTTPS (443/tcp) through a port forward.']);
  const local = {initiated: 'local', inside: [{ip: '192.168.1.20'}], services: ['HTTPS', 'HTTP'], service_ports: {HTTPS: '443/tcp'}};
  assert.deepEqual(flowSummary(local, {ip: '203.0.113.5'}), ['192.168.1.20 opened HTTPS (443/tcp) and 1 other service to 203.0.113.5.']);
});
