/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
 * All rights reserved.
 */

import assert from 'node:assert/strict';
import {test} from 'node:test';
import {endpointMembers, indexFlowsByDestination} from '../src/endpoint-flows.js';

test('endpoint hover never substitutes another IP at the same coordinates', () => {
  const oldEndpoint = {id: '203.0.113.10', lat: 40.4168, lon: -3.7038};
  const currentEndpoint = {id: '198.51.100.20', lat: 40.4168, lon: -3.7038};
  const currentFlow = {dest: currentEndpoint.id, rate: 10};
  const index = indexFlowsByDestination({locations: [currentEndpoint], flows: [currentFlow]});

  assert.deepEqual(endpointMembers(index, oldEndpoint), []);
  assert.deepEqual(endpointMembers(index, currentEndpoint), [currentFlow]);
});
