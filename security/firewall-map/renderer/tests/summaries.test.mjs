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
import {idsOutcome, outcome} from '../src/summaries.js';

test('one verdict for flagged and stopped traffic everywhere', () => {
  assert.equal(outcome({flagged: true, stopped: false}), 'danger');
  assert.equal(outcome({flagged: true, stopped: true}), 'contained');
  assert.equal(outcome({flagged: false, stopped: true}), 'blocked');
  assert.equal(outcome({flagged: false, stopped: false}), 'ok');
});

test('an IDS connection is flagged by a severe alert or a threat list, stopped by a block or an IPS drop', () => {
  assert.equal(idsOutcome({severity: 1, kind: 'current'}), 'danger');
  assert.equal(idsOutcome({severity: 3, lists: ['Spamhaus DROP'], kind: 'current'}), 'danger');
  assert.equal(idsOutcome({severity: 3, kind: 'current'}), 'ok');
  assert.equal(idsOutcome({severity: 2, kind: 'blocked'}), 'contained');
  assert.equal(idsOutcome({severity: 3, kind: 'current', ips_dropped: true}), 'blocked');
});
