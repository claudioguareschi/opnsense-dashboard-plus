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
import fs from 'node:fs';
import {test} from 'node:test';
import {problemText, statusParts, waitText} from '../src/host.js';

// the widget and the map page pass these translations (Metadata/FirewallMap.xml) as the text table
const xml = fs.readFileSync(new URL('../../src/opnsense/www/js/widgets/Metadata/FirewallMap.xml', import.meta.url), 'utf8');
const translation = (key) => xml.match(new RegExp(`<${key}>([^<]*)</${key}>`))[1];
const TEXT = {unavailable: translation('data_unavailable'), collector_incompatible: translation('collector_incompatible'),
  collector_incompatible_pf: translation('collector_incompatible_pf')};

test('an incompatible collector names the package problem, not generic unavailability', () => {
  const protocol = problemText({status: 'collector_incompatible', reason: 'protocol', protocol: 2,
    expected_protocol: 1}, TEXT);
  assert.equal(protocol, 'Firewall Map collector incompatible — The Firewall Map application and its state collector '
    + 'use incompatible protocols. Reinstall or upgrade the Firewall Map package so both components come from the '
    + 'same version.');
  assert.equal(problemText({status: 'collector_incompatible', reason: 'protocol', protocol: null}, TEXT), protocol);
  const abi = problemText({status: 'collector_incompatible', reason: 'pf_abi', protocol: 1}, TEXT);
  assert.equal(abi, TEXT.collector_incompatible_pf);
  assert.match(abi, /^Firewall Map collector incompatible — /);
  for (const reason of ['protocol', 'pf_abi']) {
    assert.notEqual(problemText({status: 'collector_incompatible', reason}, TEXT), TEXT.unavailable);
  }
  // other problems are unchanged
  assert.equal(problemText({status: 'failed'}, TEXT), TEXT.unavailable);
  assert.equal(problemText({status: 'ok'}, TEXT), null);
});

test('the status line names the one active ranking profile and an honest bounded ranking', () => {
  const text = {active_flows_one: '{count} active flow', active_flows_many: '{count} active flows', no_flows: 'No flows',
    map_profile: translation('map_profile'), map_ranking_bounded: translation('map_ranking_bounded'),
    map_ranking_warming: translation('map_ranking_warming')};
  const shown = {flows: [{}, {}]};
  const summary = {ranking_profile: {uuid: 'u', name: 'Mail <Security>', fingerprint: 'f'}, tracked_flows: 120000,
    tracked_flows_estimated: true, quality: {ranking: 'bounded'}};
  assert.deepEqual(statusParts(summary, shown, {}, text),
    ['2 active flows', 'Mail &#60;Security&#62; ranking', `the top-ranked of ≈${(120000).toLocaleString()} flows`]);
  // a document without a profile (an older collector) says nothing about one
  assert.deepEqual(statusParts({quality: {ranking: 'exact'}}, shown, {}, text), ['2 active flows']);
});

test('one wait state: waiting summaries are not problems, and say why the map waits', () => {
  const text = {starting: 'Warming up…', unavailable: 'unavailable',
    map_waiting_restart: translation('map_waiting_restart'), map_waiting_profile: translation('map_waiting_profile')};
  const profile = {uuid: 'u', name: 'Mail <Security>', fingerprint: 'f', builtin: false};
  assert.equal(waitText({status: 'waiting', reason: 'start'}, text), text.starting);
  assert.equal(waitText({status: 'waiting', reason: 'restart', ranking_profile: profile}, text), text.map_waiting_restart);
  assert.equal(waitText({status: 'waiting', reason: 'profile', ranking_profile: profile}, text),
    'Applying the Mail <Security> ranking profile: the map resumes with its first ranked sample');
  for (const reason of ['start', 'restart', 'profile']) {
    assert.equal(problemText({status: 'waiting', reason, ranking_profile: profile}, text), null);
  }
  assert.equal(waitText({status: 'ok'}, text), null);
  assert.equal(waitText(undefined, text), null);
});

test('a stretched refresh interval is said on the status line; the 2-second default is not', () => {
  const text = {active_flows_one: '{count} active flow', active_flows_many: '{count} active flows', no_flows: 'No flows',
    map_interval: translation('map_interval')};
  const shown = {flows: [{}]};
  assert.deepEqual(statusParts({interval: 2}, shown, {}, text), ['1 active flow']);
  assert.deepEqual(statusParts({interval: 12}, shown, {}, text), ['1 active flow', 'refreshed every 12 s']);
});

test('the status line wraps only between its parts, each keeping its separator', async () => {
  const {statusLine} = await import('../src/host.js');
  assert.equal(statusLine(['50 active flows', '', '7 blocked sources', null, 'Balanced ranking']),
    '<span style="white-space: nowrap;">50 active flows ·</span> '
    + '<span style="white-space: nowrap;">7 blocked sources ·</span> '
    + '<span style="white-space: nowrap;">Balanced ranking</span>');
  assert.equal(statusLine([]), '');
});
