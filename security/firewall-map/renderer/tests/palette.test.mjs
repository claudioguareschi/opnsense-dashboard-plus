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
import {palette, statusColors} from '../src/palette.js';

// OPNsense's shipped themes (opnsense, opnsense-dark, opnsense-auto): text-success, -warning, -danger
const OPNSENSE = {success: [155, 210, 117], warning: [240, 173, 78], danger: [240, 80, 80]};
const LIGHT = {dark: false, background: [255, 255, 255], ...OPNSENSE};
const DARK = {dark: true, background: [30, 30, 30], ...OPNSENSE};

const hueOf = ([r, g, b]) => {
  const max = Math.max(r, g, b);
  const range = max - Math.min(r, g, b);
  const sector = max === r ? ((g - b) / range) % 6 : max === g ? (b - r) / range + 2 : (r - g) / range + 4;
  return (sector * 60 + 360) % 360;
};

test('the status colors are the theme\'s own success, warning and danger, made to stand out', () => {
  for (const theme of [LIGHT, DARK]) {
    const colors = statusColors(theme);
    // the same hues OPNsense shows (only lightened or darkened for contrast)
    for (const [key, source] of [['ok', 'success'], ['contained', 'warning'], ['danger', 'danger']]) {
      assert.ok(Math.abs(hueOf(colors[key]) - hueOf(theme[source])) < 6, `${key} keeps the theme hue`);
    }
    const map = palette(theme);
    assert.deepEqual([map.ok, map.contained, map.danger], [colors.ok, colors.contained, colors.danger]);
  }
  // on a dark background the theme colors already stand out: used as they are
  assert.deepEqual(statusColors(DARK), {ok: OPNSENSE.success, contained: OPNSENSE.warning, danger: OPNSENSE.danger});
});

test('a theme whose status colors are too alike, or that has no danger color, keeps the fixed set', () => {
  const fixed = statusColors({dark: true, background: [30, 30, 30]});
  assert.deepEqual(statusColors({...DARK, warning: [240, 95, 70]}), fixed);
  assert.deepEqual(statusColors({...DARK, danger: undefined}), fixed);
  assert.deepEqual(palette({dark: true, background: [30, 30, 30]}).danger, fixed.danger);
  assert.notDeepEqual(statusColors({dark: false, background: [255, 255, 255]}), fixed);
});
