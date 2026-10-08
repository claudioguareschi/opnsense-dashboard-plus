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
import {DEFAULT_OPTIONS, parseSettings, summaryParams, summaryQuery} from '../src/options.js';

test('unset options take the defaults', () => {
  const settings = parseSettings({});
  assert.equal(settings.heavyTop, DEFAULT_OPTIONS.heavyTop);
  assert.equal(settings.blockMin, DEFAULT_OPTIONS.blockMin);
  assert.equal(settings.labels, true);
  assert.equal(settings.hostnames, false);
  assert.equal(settings.follow, false);
});

test('the dialog values ("0", "1", numbers as text) become settings', () => {
  const settings = parseSettings({heavy_top: '8', labels: '0', hostnames: '1', block_min: '0', follow: '1'});
  assert.equal(settings.heavyTop, 8);
  assert.equal(settings.labels, false);
  assert.equal(settings.hostnames, true);
  // a threshold of 0 would show every single blocked packet: it falls back to the default
  assert.equal(settings.blockMin, DEFAULT_OPTIONS.blockMin);
  assert.equal(settings.follow, true);
});

test('the live data request carries the threshold and the reverse DNS choice', () => {
  assert.deepEqual(summaryParams({blockMin: 5, hostnames: true}), {blocks_min: 5, hostnames: 1});
  assert.deepEqual(summaryParams({blockMin: 2}), {blocks_min: 2});
  assert.equal(summaryQuery({blockMin: 5, hostnames: true}), '?blocks_min=5&hostnames=1');
});

test('nothing a viewer sends selects the ranking', () => {
  // a stored widget option from a development build is ignored, and no request carries one
  assert.equal('focus' in parseSettings({focus: 'security'}), false);
  assert.deepEqual(summaryParams({blockMin: 3, focus: 'security', hostnames: true}), {blocks_min: 3, hostnames: 1});
  assert.equal(summaryQuery({blockMin: 3, focus: 'balanced'}), '?blocks_min=3');
});
