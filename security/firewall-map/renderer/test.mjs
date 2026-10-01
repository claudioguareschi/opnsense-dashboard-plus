import assert from 'node:assert/strict';
import {hostPort, privateAddress, splitHostPort} from './src/format.js';

assert.equal(hostPort('192.0.2.1', '443'), '192.0.2.1:443');
assert.equal(hostPort('2001:db8::1', '443'), '[2001:db8::1]:443');
assert.deepEqual(splitHostPort('[2001:db8::1]:443'), ['2001:db8::1', '443']);
assert.deepEqual(splitHostPort('2001:db8::1'), ['2001:db8::1', '']);
assert.equal(privateAddress('fd12:3456::1'), true);
assert.equal(privateAddress('fe80::1%igb1'), true);
assert.equal(privateAddress('2606:4700:4700::1111'), false);
