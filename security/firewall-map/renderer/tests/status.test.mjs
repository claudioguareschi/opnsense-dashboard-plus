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
import {problemText} from '../src/host.js';

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
