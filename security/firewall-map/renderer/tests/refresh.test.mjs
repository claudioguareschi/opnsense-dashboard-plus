import assert from 'node:assert/strict';
import fs from 'node:fs';
import {test} from 'node:test';
import {
  createRefreshGate, createRefreshLoop, refreshDelay, REFRESH_APPLIED_KEY, REFRESH_CEILING_MS, REFRESH_FLOOR_MS,
  REFRESH_KEEPALIVE_MS, REFRESH_MARGIN_MS,
} from '../src/refresh.js';
import * as host from '../src/host.js';

const ok = (interval, age = 0) => ({status: 'ok', interval, age});

test('A: the next request is due when the service samples next', () => {
  // at the floor: 2 s (a fresh document asks again just after the next sample, never before 2 s)
  assert.deepEqual(refreshDelay(ok(2)), {delay: 2500, interval: 2, reason: 'adaptive'});
  assert.equal(refreshDelay(ok(2, 1.5)).delay, REFRESH_FLOOR_MS);
  // in the middle: the remaining interval after the document's age, plus the margin
  assert.deepEqual(refreshDelay(ok(12, 4)), {delay: 8000 + REFRESH_MARGIN_MS, interval: 12, reason: 'adaptive'});
  assert.equal(refreshDelay(ok(60)).delay, 60000 + REFRESH_MARGIN_MS);
  // at the ceiling (300 s): never longer than the keep-alive, or the service would stop sampling
  assert.equal(refreshDelay(ok(300)).delay, REFRESH_KEEPALIVE_MS);
  assert.equal(refreshDelay(ok(300)).reason, 'adaptive');
  // overdue (a slow sample): the floor, never a tight loop
  assert.equal(refreshDelay(ok(30, 45)).delay, REFRESH_FLOOR_MS);
});

test('B: anything unusable falls back to the 2-second cadence', () => {
  for (const interval of [undefined, null, NaN, Infinity, -Infinity, -5, 0, 1.999, 300.001, 1e9, '5', {}, [], true]) {
    const next = refreshDelay({status: 'ok', interval, age: 0});
    assert.deepEqual(next, {delay: REFRESH_FLOOR_MS, interval: null, reason: 'invalid'}, String(interval));
  }
  // an impossible age is ignored (a whole interval), never a negative or NaN delay
  for (const age of [undefined, null, NaN, -3, '2', Infinity]) {
    assert.equal(refreshDelay({status: 'ok', interval: 10, age}).delay, 10000 + REFRESH_MARGIN_MS, String(age));
  }
  // no ranked sample (a wait after a restart, a refusal, no database) or no document at all
  for (const status of ['waiting', 'too_many_states', 'no_database', 'collector_incompatible']) {
    assert.deepEqual(refreshDelay({status, interval: 60}), {delay: REFRESH_FLOOR_MS, interval: null, reason: 'status'});
  }
  for (const summary of [null, undefined, 'text', 42]) {
    assert.deepEqual(refreshDelay(summary), {delay: REFRESH_FLOOR_MS, interval: null, reason: 'failed'});
  }
  // the exact bounds are accepted
  assert.equal(refreshDelay(ok(REFRESH_FLOOR_MS / 1000)).reason, 'adaptive');
  assert.equal(refreshDelay(ok(REFRESH_CEILING_MS / 1000)).reason, 'adaptive');
});

/** Manual timers and requests the test resolves itself. */
function harness() {
  const timers = new Map();
  let next = 1;
  const requests = [];
  let hidden = false;
  const decisions = [];
  const loop = createRefreshLoop({
    request: () => new Promise((resolve, reject) => requests.push({resolve, reject})),
    isHidden: () => hidden,
    onSchedule: (decision) => decisions.push(decision),
    setTimer: (fn, delay) => {
      const id = next++;
      timers.set(id, {fn, delay});
      return id;
    },
    clearTimer: (id) => timers.delete(id),
  });
  const settle = () => new Promise((resolve) => setImmediate(resolve));
  return {
    loop, timers, requests, decisions, settle,
    setHidden: (value) => {
      hidden = value;
    },
    /** Fires the one pending timer (there must be exactly one). */
    fire() {
      assert.equal(timers.size, 1, 'exactly one timer');
      const [[id, timer]] = timers;
      timers.delete(id);
      timer.fn();
      return timer.delay;
    },
  };
}

test('F: a slow request is never overlapped; the next one is scheduled only after it', async () => {
  const h = harness();
  h.loop.start();
  assert.equal(h.requests.length, 1);
  assert.equal(h.timers.size, 0);
  // a showing-again or an extra start while it is under way changes nothing
  h.loop.visible();
  h.loop.start();
  assert.equal(h.requests.length, 1);
  h.requests[0].resolve(ok(10, 0));
  await h.settle();
  assert.equal(h.timers.size, 1);
  assert.equal(h.fire(), 10000 + REFRESH_MARGIN_MS);
  assert.equal(h.requests.length, 2);
  assert.equal(h.timers.size, 0);
});

test('C: a restarted collector\'s documents carry the base interval: the cadence follows at once', async () => {
  // the service uses only the running collector's recommendation (sampling_interval); the
  // browser takes each document's interval as it comes, so a long one before a restart does not
  // survive the first document after it
  const h = harness();
  h.loop.start();
  h.requests[0].resolve(ok(60, 0));
  await h.settle();
  assert.equal(h.fire(), 60000 + REFRESH_MARGIN_MS);
  h.requests[1].resolve({status: 'waiting', reason: 'restart', interval: 2});
  await h.settle();
  assert.equal(h.fire(), REFRESH_FLOOR_MS);
  h.requests[2].resolve(ok(2, 0.3));
  await h.settle();
  assert.equal(h.decisions.at(-1).reason, 'adaptive');
  assert.equal(h.decisions.at(-1).delay, 2200);
});

test('D/E: an Apply during a request: asked again, and the old document cannot set the cadence', async () => {
  const h = harness();
  h.loop.start();
  h.loop.refreshNow();   // Apply while the first request is under way
  h.loop.refreshNow();   // a rapid second Apply
  assert.equal(h.requests.length, 1, 'no second request while one is under way');
  h.requests[0].resolve(ok(60, 0));   // its document predates the Apply
  await h.settle();
  assert.deepEqual(h.decisions.at(-1), {delay: REFRESH_FLOOR_MS, interval: null, reason: 'superseded'});
  assert.equal(h.fire(), REFRESH_FLOOR_MS);
  h.requests[1].resolve(ok(20, 0));
  await h.settle();
  assert.equal(h.decisions.at(-1).delay, 20000 + REFRESH_MARGIN_MS);
  // an Apply while idle cancels the long timer and asks at once: still one timer, one request
  h.loop.refreshNow();
  assert.equal(h.timers.size, 0);
  assert.equal(h.requests.length, 3);
  h.requests[2].resolve(ok(20, 0));
  await h.settle();
  assert.equal(h.timers.size, 1);
});

test('G: a failure retries at the floor, not in a tight loop, and recovers', async () => {
  const h = harness();
  h.loop.start();
  h.requests[0].reject(new Error('HTTP 502'));
  await h.settle();
  assert.deepEqual(h.decisions.at(-1), {delay: REFRESH_FLOOR_MS, interval: null, reason: 'failed'});
  assert.equal(h.fire(), REFRESH_FLOOR_MS);
  h.requests[1].resolve(null);   // a malformed answer
  await h.settle();
  assert.equal(h.fire(), REFRESH_FLOOR_MS);
  h.requests[2].resolve(ok(8, 0));
  await h.settle();
  assert.equal(h.fire(), 8000 + REFRESH_MARGIN_MS);
});

test('H: hidden, nothing is asked; shown again, at once and only once', async () => {
  const h = harness();
  h.loop.start();
  h.requests[0].resolve(ok(60, 0));
  await h.settle();
  assert.equal(h.timers.size, 1);
  // hidden: the long timer fires and asks nothing, and no new one is armed
  h.setHidden(true);
  h.fire();
  assert.equal(h.requests.length, 1);
  assert.equal(h.timers.size, 0);
  // shown again: at once
  h.setHidden(false);
  h.loop.visible();
  h.loop.visible();
  assert.equal(h.requests.length, 2);
  // hidden during a request: nothing is armed when it ends
  h.setHidden(true);
  h.requests[1].resolve(ok(10, 0));
  await h.settle();
  assert.equal(h.timers.size, 0);
  // shown while a long timer is pending: the stale timer is replaced, not doubled
  h.setHidden(false);
  h.loop.visible();
  h.requests[2].resolve(ok(60, 0));
  await h.settle();
  assert.equal(h.timers.size, 1);
  h.loop.visible();
  assert.equal(h.timers.size, 0);
  assert.equal(h.requests.length, 4);
});

test('starting again never adds a second loop', async () => {
  const h = harness();
  h.loop.start();
  h.requests[0].resolve(ok(30, 0));
  await h.settle();
  assert.equal(h.timers.size, 1);
  h.loop.start();   // with a timer pending: replaced, not doubled
  assert.equal(h.timers.size, 0);
  assert.equal(h.requests.length, 2);
  h.requests[1].resolve(ok(30, 0));
  await h.settle();
  assert.equal(h.timers.size, 1);
});

test('a stopped loop arms nothing more, even when a request ends afterwards', async () => {
  const h = harness();
  h.loop.start();
  h.loop.stop();
  h.requests[0].resolve(ok(2, 0));
  await h.settle();
  assert.equal(h.timers.size, 0);
  h.loop.visible();
  h.loop.refreshNow();
  assert.equal(h.requests.length, 1);
});

test('the widget gate: due ticks only, one request at a time, Apply and showing again', () => {
  const gate = createRefreshGate({tickMs: 2000});
  const first = gate.begin(0);
  assert.ok(first);
  assert.equal(gate.begin(10), null, 'one request at a time');
  assert.equal(gate.done(first, 100, ok(10, 0)).delay, 10000 + REFRESH_MARGIN_MS);
  // core ticks every 2 s: skipped until due (half a tick early is enough)
  for (const now of [2100, 4100, 6100, 8100]) {
    assert.equal(gate.begin(now), null, `tick at ${now}`);
  }
  const second = gate.begin(10100);
  assert.ok(second, 'the tick at the due time passes');
  // a 2-second delay never skips a tick that arrives slightly early
  gate.done(second, 10200, ok(2, 0.5));
  assert.ok(gate.begin(12100));
  gate.done({generation: gate.state().generation}, 12200, ok(30, 0));
  // Apply during a request: its document cannot set the cadence; the next tick asks
  const third = gate.begin(50000);
  gate.refreshNow();
  assert.deepEqual(gate.done(third, 50100, ok(120, 0)), {delay: REFRESH_FLOOR_MS, interval: null, reason: 'superseded'});
  assert.ok(gate.begin(51200));
  gate.done({generation: gate.state().generation}, 51300, ok(120, 0));
  assert.equal(gate.begin(53300), null);
  gate.visible();
  assert.ok(gate.begin(53300), 'shown again: the next tick asks');
  // a failure: the floor
  assert.equal(gate.done(null, 53400, null).reason, 'superseded');
});

test('the shared host exports the refresh helpers to the widget', () => {
  assert.equal(host.refreshDelay, refreshDelay);
  assert.equal(host.createRefreshGate, createRefreshGate);
  assert.equal(host.REFRESH_APPLIED_KEY, REFRESH_APPLIED_KEY);
});

test('the settings page announces an Apply under the key the maps listen to', () => {
  const settings = fs.readFileSync(new URL('../../src/opnsense/mvc/app/views/OPNsense/FirewallMap/settings.volt',
    import.meta.url), 'utf8');
  assert.ok(settings.includes(`localStorage.setItem('${REFRESH_APPLIED_KEY}'`));
});
