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

// the page's modules read their translations from the page; none are needed here. Flags are looked
// up in the page's stylesheets: there are none here.
globalThis.window = globalThis.window || {};
globalThis.document = globalThis.document || {querySelector: () => null};
const {groupTalkers} = await import('../page/talkers.js');

const LOCATIONS = [{id: '203.0.113.5', country: 'Example', country_code: 'EX', asn: 64500, as_org: 'Example AS'}];

test('a host seen only in connection attempts nothing answered is unanswered', () => {
  // a scanner's SYNs to a port forward whose host is off create states (probe flows) and an inside
  // host that never existed on the wire (#20); a host with any flow carrying data is answered
  const summary = {locations: LOCATIONS, flows: [
    {origin: '198.51.100.2', dest: '203.0.113.5', rate: 0, presence: 'probe', attempts: 12, inside: [{ip: '10.0.0.9'}]},
    {origin: '198.51.100.2', dest: '203.0.113.5', rate: 0, presence: 'probe', attempts: 30, inside: [{ip: '10.0.0.2'}]},
    {origin: '198.51.100.2', dest: '203.0.113.5', rate: 500, inside: [{ip: '10.0.0.2', name: 'desk'}]},
  ]};
  const hosts = new Map(groupTalkers(summary).hosts.map((row) => [row.ip, row]));
  assert.equal(hosts.get('10.0.0.9').unanswered, true);
  assert.equal(hosts.get('10.0.0.2').unanswered, false);
  assert.equal(hosts.get('10.0.0.2').flows, 2);
});
