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
import {endpointMembers, indexFlowsByDestination, retainVisibleEndpointFlows} from '../src/endpoint-flows.js';

test('endpoint hover never substitutes another IP at the same coordinates', () => {
  const oldEndpoint = {id: '203.0.113.10', lat: 40.4168, lon: -3.7038};
  const currentEndpoint = {id: '198.51.100.20', lat: 40.4168, lon: -3.7038};
  const currentFlow = {dest: currentEndpoint.id, rate: 10};
  const index = indexFlowsByDestination({locations: [currentEndpoint], flows: [currentFlow]});

  assert.deepEqual(endpointMembers(index, oldEndpoint), []);
  assert.deepEqual(endpointMembers(index, currentEndpoint), [currentFlow]);
});

test('fading endpoints retain their last flow details until they disappear', () => {
  const oldEndpoint = {id: '203.0.113.10', lat: 40.4168, lon: -3.7038, fading: true};
  const currentEndpoint = {id: '198.51.100.20', lat: 40.4168, lon: -3.7038};
  const oldFlow = {dest: oldEndpoint.id, rate: 20};
  const currentFlow = {dest: currentEndpoint.id, rate: 10};
  const previous = indexFlowsByDestination({locations: [oldEndpoint], flows: [oldFlow]});
  const current = indexFlowsByDestination({locations: [currentEndpoint], flows: [currentFlow]});

  const retained = retainVisibleEndpointFlows(current, previous, [oldEndpoint, currentEndpoint]);

  assert.deepEqual(endpointMembers(retained, oldEndpoint), [oldFlow]);
  assert.deepEqual(endpointMembers(retained, currentEndpoint), [currentFlow]);
});
