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
import {hostPort, privateAddress, protocolLabel, splitHostPort} from '../src/format.js';

test('host and port in both address families', () => {

  assert.equal(hostPort('192.0.2.1', '443'), '192.0.2.1:443');
  assert.equal(hostPort('2001:db8::1', '443'), '[2001:db8::1]:443');
  assert.deepEqual(splitHostPort('[2001:db8::1]:443'), ['2001:db8::1', '443']);
  assert.deepEqual(splitHostPort('2001:db8::1'), ['2001:db8::1', '']);
  assert.equal(privateAddress('fd12:3456::1'), true);
  assert.equal(privateAddress('fe80::1%igb1'), true);
  assert.equal(privateAddress('2606:4700:4700::1111'), false);
});

test('a missing protocol shows blank, not an error', () => {
  assert.equal(protocolLabel('tcp'), 'TCP');
  assert.equal(protocolLabel(undefined), '');
});
