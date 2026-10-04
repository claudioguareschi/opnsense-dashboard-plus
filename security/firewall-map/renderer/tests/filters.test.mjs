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

// the page's modules read their translations from the page; none are needed here
globalThis.window = globalThis.window || {};
const {state, resetFilters} = await import('../page/context.js');
const {filtered} = await import('../page/filters.js');

const summary = {
  status: 'ok',
  locations: [{id: '192.0.2.1', local: true}, {id: '203.0.113.1', country: 'Germany', asn: 64500}, {id: '198.51.100.1', country: 'Japan'}],
  flows: [
    {origin: '192.0.2.1', dest: '203.0.113.1', services: ['HTTPS'], inside: [{ip: '10.0.0.5', interface: 'LAN'}]},
    {origin: '192.0.2.1', dest: '198.51.100.1', services: ['DNS'], threat: true, inside: [{ip: '10.0.0.6', interface: 'IOT'}]},
  ],
  blocks: [{source: '203.0.113.50', country: 'Germany', hits: 5}],
  alerts: [],
  ids_flows: [],
};

test('every filter narrows the flows, and blocked sources only where they apply', () => {
  state.settings = {blocks: true};
  resetFilters();
  assert.equal(filtered(summary).flows.length, 2);
  assert.equal(filtered(summary).blocks.length, 1);
  state.filters.country = 'Japan';
  assert.deepEqual(filtered(summary).flows.map((item) => item.dest), ['198.51.100.1']);
  assert.equal(filtered(summary).blocks.length, 0);
  resetFilters();
  state.filters.iface = 'LAN';
  assert.deepEqual(filtered(summary).flows.map((item) => item.dest), ['203.0.113.1']);
  // a blocked source has no inside interface
  assert.equal(filtered(summary).blocks.length, 0);
  resetFilters();
  state.filters.traffic = 'blocked';
  assert.equal(filtered(summary).flows.length, 0);
  assert.equal(filtered(summary).blocks.length, 1);
  state.filters.traffic = 'threats';
  assert.deepEqual(filtered(summary).flows.map((item) => item.dest), ['198.51.100.1']);
});

test('only places that are drawn stay in the locations', () => {
  state.settings = {blocks: true};
  resetFilters();
  state.filters.country = 'Germany';
  const ids = filtered(summary).locations.map((location) => location.id);
  assert.deepEqual(ids.sort(), ['192.0.2.1', '203.0.113.1']);
});
