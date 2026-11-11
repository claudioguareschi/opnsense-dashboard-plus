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
import {buildArcs, marchingPulses, pulses} from '../src/arcs.js';
import {DEFAULT_OPTIONS} from '../src/options.js';

const home = {id: '192.0.2.1', lat: 33.75, lon: -84.39, local: true};
const place = (id, lat, lon) => ({id, lat, lon});
const flow = (dest, extra = {}) => ({origin: home.id, dest, rate: 1000, rateIn: 800, rateOut: 200, rate_in: 800, rate_out: 200,
  activity: 1, initiated: 'local', services: ['HTTPS'], egress: 'WAN', ...extra});

test('addresses at the same coordinates share one arc carrying their combined traffic', () => {
  const data = {
    locations: [home, place('203.0.113.1', 50.11, 8.68), place('203.0.113.2', 50.11, 8.68), place('198.51.100.1', 35.68, 139.69)],
    flows: [flow('203.0.113.1'), flow('203.0.113.2'), flow('198.51.100.1')],
  };
  const arcs = buildArcs(data, DEFAULT_OPTIONS);
  assert.equal(arcs.length, 2);
  const frankfurt = arcs.find((arc) => arc.members.length === 2);
  assert.ok(frankfurt, 'the two Frankfurt addresses share an arc');
});

test('one firewall\'s IPv4 and IPv6 flows to one place share an arc, never one under the other', () => {
  // the IPv6 address is placed at the IPv4 location (one house): its arcs start at the same spot
  const home6 = {id: '2001:db8::1', lat: home.lat, lon: home.lon, local: true};
  const elsewhere6 = {id: '2001:db8::2', lat: 40.71, lon: -74.0, local: true};
  const data = {
    locations: [home, home6, elsewhere6, place('203.0.113.1', 50.11, 8.68), place('2001:db8:f::1', 50.11, 8.68)],
    flows: [flow('203.0.113.1'), flow('2001:db8:f::1', {origin: home6.id})],
  };
  const arcs = buildArcs(data, DEFAULT_OPTIONS);
  assert.equal(arcs.length, 1);
  assert.deepEqual(arcs[0].members.map((member) => member.dest), ['203.0.113.1', '2001:db8:f::1']);
  // an IPv6 house placed elsewhere draws its own arc from there
  data.flows[1] = flow('2001:db8:f::1', {origin: elsewhere6.id});
  const apart = buildArcs(data, DEFAULT_OPTIONS);
  assert.equal(apart.length, 2);
  assert.notDeepEqual(apart[0].path, apart[1].path);
});

test('a connection Suricata alerted on keeps an arc of its own', () => {
  const data = {
    locations: [home, place('203.0.113.1', 50.11, 8.68), place('203.0.113.2', 50.11, 8.68)],
    flows: [flow('203.0.113.1'), flow('203.0.113.2', {ids_flow: {key: 'tcp|203.0.113.2|443'}})],
  };
  assert.equal(buildArcs(data, DEFAULT_OPTIONS).length, 2);
});

test('flows without a known location draw nothing', () => {
  assert.deepEqual(buildArcs({locations: [home], flows: [flow('203.0.113.9')]}, DEFAULT_OPTIONS), []);
});

test('a mirrored arc (CARP backup) carries a closely spaced pair of dots at one fixed pace', () => {
  const data = {
    locations: [home, place('203.0.113.1', 50.11, 8.68), place('198.51.100.1', 35.68, 139.69)],
    flows: [flow('203.0.113.1', {presence: 'mirror', rate: 0, rateIn: 0, rateOut: 0, rate_in: 0, rate_out: 0,
      activity: 0, initiated: 'remote'}), flow('198.51.100.1')],
  };
  const arcs = buildArcs(data, DEFAULT_OPTIONS);
  const mirror = arcs.find((arc) => arc.presence === 'mirror');
  // no counters to fade with or to set a direction: it stays, and follows who opened it
  assert.equal(mirror.activity, 1);
  assert.equal(mirror.direction, 'in');
  const dots = pulses(arcs).filter((item) => item.arc === mirror);
  assert.equal(dots.length, 2);
  assert.ok(dots.every((dot) => dot.period === dots[0].period && dot.reverse));
  assert.ok(Math.abs(dots[1].phase - dots[0].phase) < 0.05);
  // a traffic arc keeps its rate-driven pulse, and a saved snapshot marches one row per direction
  assert.equal(pulses(arcs).filter((item) => item.arc !== mirror).length, 1);
  assert.equal(marchingPulses([mirror]).length, 6);
});

test('connections take the shortest path around the globe and do not shoot over the poles', () => {
  const sfHome = {id: '192.0.2.1', lat: 37.77, lon: -122.42, local: true};
  const tokyo = place('198.51.100.1', 35.68, 139.69);
  const data = {
    locations: [sfHome, tokyo],
    flows: [flow(tokyo.id)],
  };
  const arcs = buildArcs(data, DEFAULT_OPTIONS);
  assert.equal(arcs.length, 1);
  const path = arcs[0].path;
  // Span must be the shortest route across the Pacific (~98 degrees), not eastwards across the Atlantic (~262 degrees)
  const [startLon] = path[0];
  const [endLon] = path[path.length - 1];
  const lonSpan = Math.abs(endLon - startLon);
  assert.ok(lonSpan <= 180, `longitudinal span ${lonSpan} should be <= 180`);
  // All latitudes must remain bounded and not arch over the North Pole
  for (const [, lat] of path) {
    assert.ok(lat < 70, `latitude ${lat} should remain below 70 degrees N`);
    assert.ok(lat > -60, `latitude ${lat} should remain above 60 degrees S`);
  }
});
