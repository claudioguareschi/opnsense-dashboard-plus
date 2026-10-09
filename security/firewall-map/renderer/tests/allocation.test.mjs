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
import {createRequire} from 'node:module';
import fs from 'node:fs';
import {test} from 'node:test';

// the settings page's script (plain, no bundle): the bars' rules, without a page
const require = createRequire(import.meta.url);
const A = require('../../src/opnsense/www/js/firewall-map-allocation.js');

// Security visibility: General is what S1 + S2 + S3 leave of 100
const SECURITY = [{derived: true}, {}, {}, {}];
const WEIGHTS = Array.from({length: 8}, () => ({}));
const security = (s1, s2, s3, loaded) => A.evaluate(SECURITY, [null, s1, s2, s3], loaded);

test('the security bar: General is derived and the four always total 100', () => {
  assert.deepEqual(security('15', '20', '30'), {values: [35, 15, 20, 30], total: 100, valid: true, bad: false, over: 0});
  // under 100 is fine: General takes the rest
  assert.deepEqual(security('0', '0', '0').values, [100, 0, 0, 0]);
  // over 100: General is 0 and the editor says by how much
  const over = security('40', '40', '25');
  assert.deepEqual([over.valid, over.over, over.values[0]], [false, 5, 0]);
});

test('a boundary moves points only between its two neighbours', () => {
  const start = [35, 15, 20, 30];
  // General | S1 +5 toward S1 means General grows: the brief's example, then S1 | S2
  assert.deepEqual(A.move(start, 0, 5), [40, 10, 20, 30]);
  assert.deepEqual(A.move(A.move(start, 0, 5), 1, 5), [40, 15, 15, 30]);
  assert.deepEqual(A.move(start, 2, 5), [35, 15, 25, 25]);
  for (const k of [0, 1, 2]) {
    for (const delta of [-7, -1, 1, 7]) {
      const next = A.move(start, k, delta);
      assert.equal(next.reduce((a, b) => a + b), 100);
      next.forEach((value, index) => {
        if (index !== k && index !== k + 1) assert.equal(value, start[index], `segment ${index} untouched`);
      });
    }
  }
});

test('a boundary stops at 0 on either side and repeats exactly', () => {
  assert.deepEqual(A.move([35, 15, 20, 30], 1, 99), [35, 35, 0, 30]);
  assert.deepEqual(A.move([35, 15, 20, 30], 1, -99), [35, 0, 35, 30]);
  assert.deepEqual(A.move([100, 0, 0, 0], 0, 5), [100, 0, 0, 0]);
  assert.deepEqual(A.move([100, 0, 0, 0], 0, -5), [95, 5, 0, 0]);
  let values = [35, 15, 20, 30];
  for (let n = 0; n < 50; n++) values = A.move(values, 2, n % 2 ? -3 : 3);
  assert.deepEqual(values, [35, 15, 20, 30], 'back and forth: no drift');
});

test('the ranking bar: the Security profile, Total data at 0, every boundary', () => {
  const securityProfile = ['5', '5', '10', '15', '0', '20', '15', '30'];
  const state = A.evaluate(WEIGHTS, securityProfile);
  assert.deepEqual([state.valid, state.total], [true, 100]);
  for (let k = 0; k < 7; k++) {
    const next = A.move(state.values, k, 3);
    assert.equal(next.reduce((a, b) => a + b), 100);
    assert.deepEqual(next.filter((_, index) => index !== k && index !== k + 1),
      state.values.filter((_, index) => index !== k && index !== k + 1));
  }
  // Threat reputation | IDS alerts +5: the brief's example
  assert.deepEqual(A.move(state.values, 6, 5).slice(6), [20, 25]);
  // Total data is 0: it can only grow from either side
  assert.deepEqual(A.move(state.values, 4, 2).slice(3, 6), [15, 2, 18]);
  assert.deepEqual(A.move(state.values, 3, -2).slice(3, 5), [13, 2]);
});

test('typed entries: whole points 0-100, the total shown, nothing redistributed', () => {
  for (const bad of ['-1', '101', 'abc', '', '12.5', '1e2', ' ', '5%']) {
    assert.equal(A.parse(bad), null, JSON.stringify(bad));
  }
  assert.equal(A.parse(' 7 '), 7);
  const under = A.evaluate(WEIGHTS, ['5', '5', '10', '15', '0', '20', '15', '23']);
  assert.deepEqual([under.valid, under.total, under.over], [false, 93, -7]);
  const over = A.evaluate(WEIGHTS, ['5', '5', '10', '15', '0', '20', '15', '36']);
  assert.deepEqual([over.valid, over.total, over.over], [false, 106, 6]);
  const empty = A.evaluate(WEIGHTS, ['5', '5', '10', '15', '', '20', '15', '30']);
  assert.deepEqual([empty.valid, empty.bad], [false, true]);
});

test('whole values only: decimals are refused, like the model', () => {
  for (const bad of ['12.5', '0.5', '100.0', '7.']) {
    assert.equal(A.parse(bad), null, bad);
  }
  const state = A.evaluate(WEIGHTS, ['12.5', '87.5', '0', '0', '0', '0', '0', '0']);
  assert.deepEqual([state.valid, state.bad], [false, true]);
});

test('drags and keys move whole points', () => {
  const values = [35, 15, 20, 30];
  // a 600 px bar: 6 px per point. The boundary at 35 taken and moved 31 px right: 5 points
  assert.equal(A.dragDelta(35, 35, 31, 6), 5);
  // later in the same drag the boundary is already at 40: only the rest is asked for
  assert.equal(A.dragDelta(35, 40, 31, 6), 0);
  assert.equal(A.dragDelta(35, 40, -2, 6), -5);
  // a scale fixed at the press: a 0% slot appearing or vanishing on the way changes nothing
  assert.equal(A.dragDelta(35, 36, 18, 6), 2);
  // never past the bar's ends
  assert.equal(A.dragDelta(35, 35, 9999, 6), 65);
  assert.equal(A.dragDelta(35, 35, -9999, 6), -35);
  assert.equal(A.keyDelta('ArrowRight', false, values, 1), 1);
  assert.equal(A.keyDelta('ArrowLeft', false, values, 1), -1);
  assert.equal(A.keyDelta('ArrowLeft', true, values, 1), -5);
  assert.equal(A.keyDelta('Home', false, values, 1), -15);
  assert.equal(A.keyDelta('End', false, values, 1), 20);
  assert.equal(A.keyDelta('Enter', false, values, 1), null);
});

test('a 0% segment has a slot of its own: every boundary apart, the shares exact', () => {
  // Bandwidth: the last three weights are 0
  const plan = A.layout([55, 15, 5, 5, 20, 0, 0, 0]);
  assert.equal(plan.zeros, 3);
  // the five shares give up 3 slots of room in proportion; the zero segments are one slot each
  assert.deepEqual(plan.segments.map((segment) => segment.zero), [false, false, false, false, false, true, true, true]);
  assert.deepEqual(plan.segments.slice(5).map((segment) => segment.px), [14, 14, 14]);
  const total = (unit) => plan.segments.reduce((sum, segment) => sum + (unit === '%' ? segment.percent : segment.px), 0);
  assert.equal(total('%'), 100);
  assert.ok(Math.abs(total('px')) < 1e-6, 'the slots are paid for exactly');
  // the last three boundaries all sit at 100%, each a slot apart
  const ends = plan.boundaries.slice(4).map((b) => [b.percent, b.px]);
  assert.deepEqual(ends, [[100, -42], [100, -28], [100, -14]]);
  // without zeros there is nothing to make room for
  assert.deepEqual(A.layout([35, 15, 20, 30]).boundaries.map((b) => [b.percent, b.px]), [[35, 0], [50, 0], [70, 0]]);
  assert.deepEqual(A.widths([35, 15, 20, 30]), [35, 15, 20, 30]);
  // fields that do not add up are drawn scaled, while the editor reports the total
  assert.deepEqual(A.widths([50, 50, 50, 50]), [25, 25, 25, 25]);
});

test('the settings page script parses (one scope: no name declared twice)', async () => {
  const {Script} = await import('node:vm');
  const page = fs.readFileSync(new URL('../../src/opnsense/mvc/app/views/OPNsense/FirewallMap/settings.volt', import.meta.url), 'utf8');
  const scripts = [...page.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((match) => match[1]);
  assert.ok(scripts.length);
  // Volt fills {{ ... }} with JSON values on the firewall: any literal stands in for them here
  for (const script of scripts) {
    assert.doesNotThrow(() => new Script(script.replace(/\{\{[\s\S]*?\}\}/g, '0')));
  }
});

test('the profile dialog: the new names, sections and the editor script', () => {
  const dialog = fs.readFileSync(new URL('../../src/opnsense/mvc/app/controllers/OPNsense/FirewallMap/forms/dialogProfile.xml',
    import.meta.url), 'utf8');
  for (const label of ['Security visibility', 'Ranking priorities', 'Data rate', 'Packet rate', 'Connections', 'Connection rate',
    'Total data', 'Blocked activity', 'Threat reputation', 'IDS alerts', 'Security interest (S1)', 'Elevated security (S2)',
    'High-priority security (S3)']) {
    assert.ok(dialog.includes(`<label>${label}</label>`), label);
  }
  assert.ok(!dialog.includes('general ranking pool'));
  const page = fs.readFileSync(new URL('../../src/opnsense/mvc/app/views/OPNsense/FirewallMap/settings.volt', import.meta.url), 'utf8');
  assert.ok(page.includes('/ui/js/firewall-map-allocation.js?v='));
  assert.ok(!/maximum (protected )?allocation/i.test(page), 'the shares are minimums, never caps');
});
