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
import {buildArcs} from '../src/arcs.js';
import {Fader} from '../src/fader.js';
import {DEFAULT_OPTIONS, parseSettings} from '../src/options.js';

// the page's modules read their translations from the page; none are needed here
globalThis.window = globalThis.window || {};
const {state, resetFilters} = await import('../page/context.js');
const {filtered} = await import('../page/filters.js');

// The map draws the flows the collector sent: how many is the collector's (--flows), never a number
// the browser knows. Summaries of `count` flows to distinct places, so none share an arch.
const home = {id: '192.0.2.1', lat: 33.75, lon: -84.39, local: true};
function summary(count, first = 0) {
  const locations = [home];
  const flows = [];
  for (let n = first; n < first + count; n++) {
    const id = `198.18.${n >> 8}.${n & 255}`;
    locations.push({id, lat: -60 + (n % 50) * 2.6, lon: -170 + Math.floor(n / 50) * 3.4, country: n % 2 ? 'Japan' : 'Brazil'});
    flows.push({origin: home.id, dest: id, rate: 1000 + n, rate_in: 800, rate_out: 200, activity: 1,
      initiated: 'local', services: ['HTTPS'], egress: 'WAN', country: n % 2 ? 'Japan' : 'Brazil'});
  }
  return {locations, flows};
}

test('every flow the collector sent is drawn: no limit at 150 or anywhere else', () => {
  for (const count of [0, 1, 37, 149, 150, 151, 500, 1000]) {
    const arcs = buildArcs(summary(count), DEFAULT_OPTIONS);
    assert.equal(arcs.length, count, `${count} flows`);
    assert.equal(new Set(arcs.map((arc) => arc.key)).size, count, 'one arch per flow, none twice');
  }
});

test('the map options carry no arc limit, whatever a dashboard stored before', () => {
  assert.equal('maxArcs' in DEFAULT_OPTIONS, false);
  assert.equal('maxArcs' in parseSettings({max_arcs: '50'}), false);
  assert.equal(buildArcs(summary(151), parseSettings({max_arcs: '50'})).length, 151);
});

test('a growing and a shrinking response: arches follow the count, lanes carry over, nothing stale', () => {
  const fader = new Fader((arc) => arc.key);
  let previousLanes = new Map();
  let now = 0;
  const draw = (count) => {
    const arcs = fader.update(buildArcs(summary(count), {...DEFAULT_OPTIONS, previousLanes}), now);
    previousLanes = new Map([...fader.entries.values()].map((entry) => [entry.item.key, entry.item.lane]));
    return arcs;
  };
  assert.equal(draw(150).length, 150);
  now += 5000;
  assert.equal(draw(500).length, 500);
  now += 5000;
  // the 450 that left fade out, then are gone: only the 50 remain
  const shrinking = draw(50);
  assert.equal(shrinking.filter((arc) => !arc.fading).length, 50);
  now += 5000;
  const settled = draw(50);
  assert.equal(settled.length, 50);
  assert.equal(fader.entries.size, 50);
  now += 5000;
  // an empty response: what was drawn fades out, then nothing is left
  assert.ok(draw(0).every((arc) => arc.fading));
  now += 5000;
  assert.deepEqual(draw(0), []);
  assert.equal(fader.entries.size, 0);
});

test('filters work on any number of flows', () => {
  state.settings = {blocks: true};
  resetFilters();
  for (const count of [151, 1000]) {
    const data = summary(count);
    assert.equal(filtered(data).flows.length, count);
    state.filters.country = 'Japan';
    const japan = filtered(data);
    assert.equal(japan.flows.length, Math.floor(count / 2));
    assert.equal(buildArcs(japan, DEFAULT_OPTIONS).length, Math.floor(count / 2));
    resetFilters();
  }
});

test('a thousand flows build in well under a frame budget per refresh', () => {
  const data = summary(1000);
  const started = performance.now();
  for (let n = 0; n < 20; n++) {
    buildArcs(data, DEFAULT_OPTIONS);
  }
  const each = (performance.now() - started) / 20;
  assert.ok(each < 50, `${each.toFixed(1)} ms per build`);
});
