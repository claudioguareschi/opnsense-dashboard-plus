import assert from 'node:assert/strict';
import {test} from 'node:test';
import {Fader} from '../src/fader.js';

test('clearing a fader removes stale items after a filter change', () => {
  const fader = new Fader((item) => item.id);
  const old = {id: 'host-b'};
  fader.update([old], 0);
  fader.clear();
  assert.deepEqual(fader.update([{id: 'host-a'}], 100).map((item) => item.id), ['host-a']);
  assert.equal(fader.entries.has('host-b'), false);
});
