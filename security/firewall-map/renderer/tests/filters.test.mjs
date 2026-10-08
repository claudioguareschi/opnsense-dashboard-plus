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
const {filtered, insideHostMatches} = await import('../page/filters.js');
const {T} = await import('../page/context.js');
const {captureText} = await import('../page/snapshots.js');

test('snapshot coverage distinguishes legacy, fallback, complete and truncated detail', () => {
  Object.assign(T, {
    snapshot_unknown: 'Detail completeness unknown', snapshot_complete: 'Complete detail within capture scope',
    snapshot_truncated: 'Truncated detail', snapshot_captured_flows: '{captured} flows captured of {available} available',
    snapshot_omitted_geo: '{count} additional flows without geographic data',
    snapshot_captured_states: '{captured} of {available} matching PF rows saved across captured remotes',
  });
  assert.equal(captureText({full: true}), T.snapshot_unknown);
  assert.equal(captureText({capture: {version: 1, detail_status: 'unknown'}}), T.snapshot_unknown);
  assert.equal(captureText({capture: {version: 2}}), T.snapshot_unknown);
  assert.equal(captureText({capture: {version: 1}}), T.snapshot_unknown);
  assert.equal(captureText({capture: {version: 1, detail_status: 'complete', flows: {captured: 5, available: 5}}}),
    'Complete detail within capture scope · 5 flows captured of 5 available');
  assert.equal(captureText({capture: {version: 1, detail_status: 'truncated',
    flows: {captured: 5000, available: 200000, omitted_geo: 7},
    states: {captured: 5000, available: 50000, truncated: true}}}),
  'Truncated detail · 5000 flows captured of 200000 available · 7 additional flows without geographic data'
    + ' · 5000 of 50000 matching PF rows saved across captured remotes');
});

test('a version 2 capture says what it chose among and whether the ranking was bounded', () => {
  Object.assign(T, {snapshot_population: 'from {count} flows', snapshot_ranking_bounded: 'ranking was bounded'});
  assert.equal(captureText({capture: {version: 2, detail_status: 'complete', flows: {captured: 40, available: 40},
    context: {flows_total: 250000, flows_estimated: true, quality: {ranking: 'bounded'}}}}),
  `Complete detail within capture scope · 40 flows captured of 40 available · from ≈${(250000).toLocaleString()} flows`
    + ' · ranking was bounded');
  assert.equal(captureText({capture: {version: 2, detail_status: 'complete', flows: {captured: 3, available: 3},
    context: {flows_total: 12, flows_estimated: false, quality: {ranking: 'exact'}}}}),
  'Complete detail within capture scope · 3 flows captured of 3 available · from 12 flows');
});

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

test('host filters match regular and IDS host representations', () => {
  assert.equal(insideHostMatches({ip: '10.0.0.5'}, '10.0.0.5'), true);
  assert.equal(insideHostMatches('10.0.0.5:443', '10.0.0.5'), true);
  assert.equal(insideHostMatches('[2001:db8::5]:443', '2001:db8::5'), true);
  assert.equal(insideHostMatches('[2001:db8::6]:443', '2001:db8::5'), false);
  assert.equal(insideHostMatches('10.0.0.6:443', '10.0.0.5'), false);
  assert.equal(insideHostMatches({ip: '10.0.0.6'}, '10.0.0.5'), false);
});
