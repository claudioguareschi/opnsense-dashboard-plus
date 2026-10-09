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

/* Map refresh (adaptive refresh): when to ask for the map again.
 *
 * The collector recommends how often to sample (it sees what a sample costs); the service
 * samples at that interval within the administrator's bounds and writes it into every map
 * document as `interval`. It uses only the running collector's own recommendation: one from a
 * collector that has since restarted (a new profile, an Apply, a failure) is never used, so its
 * documents carry the safe base interval until the new collector has measured itself. The
 * browser runs no load control of its own: it asks again when the next sample is due, using the
 * document's `age` (seconds since the service wrote it, measured on the firewall), so no clock
 * is compared across machines. Anything it cannot use falls back to the 2-second cadence. */

/** The shortest interval: the collector's floor and the settings' minimum (seconds 2). */
export const REFRESH_FLOOR_MS = 2000;
/** The longest interval the settings allow (interval_max up to 300 s). */
export const REFRESH_CEILING_MS = 300000;
/** The service stops sampling for the map once nobody has asked for 300 s: ask at least twice in that window. */
export const REFRESH_KEEPALIVE_MS = 150000;
/** Asked a little after the sample is due, so the new one is there. */
export const REFRESH_MARGIN_MS = 500;
/** localStorage key the settings page bumps on Apply: open maps in other tabs refresh at once. */
export const REFRESH_APPLIED_KEY = 'firewall-map.applied';

const finite = (value) => typeof value === 'number' && Number.isFinite(value);

/**
 * The delay before the next request after `summary` (the map document, or null when the request
 * failed): {delay (ms), interval (s or null), reason}. Reasons: 'adaptive' (the document's
 * interval, timed from its age), 'status' (no ranked sample: a wait, a refusal, no database),
 * 'invalid' (a missing or impossible interval) and 'failed' (no document) use the floor.
 */
export function refreshDelay(summary) {
  if (!summary || typeof summary !== 'object') {
    return {delay: REFRESH_FLOOR_MS, interval: null, reason: 'failed'};
  }
  if (summary.status !== 'ok') {
    return {delay: REFRESH_FLOOR_MS, interval: null, reason: 'status'};
  }
  const interval = summary.interval;
  if (!finite(interval) || interval * 1000 < REFRESH_FLOOR_MS || interval * 1000 > REFRESH_CEILING_MS) {
    return {delay: REFRESH_FLOOR_MS, interval: null, reason: 'invalid'};
  }
  const intervalMs = interval * 1000;
  // an unknown or impossible age: assume the document is new and wait a whole interval
  const ageMs = finite(summary.age) && summary.age >= 0 ? summary.age * 1000 : 0;
  const due = intervalMs - ageMs + REFRESH_MARGIN_MS;
  // overdue (a slow sample): ask again at the floor, never faster
  const delay = Math.min(Math.max(due, REFRESH_FLOOR_MS), intervalMs + REFRESH_MARGIN_MS, REFRESH_KEEPALIVE_MS);
  return {delay: Math.round(delay), interval, reason: 'adaptive'};
}

/**
 * The page's refresh loop: one request at a time, the next one scheduled only when the last has
 * finished (a slow firewall never gets requests stacked or overlapping), nothing while the page
 * is hidden, at once when it is shown again. `request()` resolves with the map document after
 * the page has used it (or rejects); `refreshNow()` (an Apply elsewhere) asks at once and makes
 * a request already under way unable to set the cadence: its document predates the change.
 * `onSchedule(next)` reports each decision (diagnostics). The timers are injectable for tests.
 */
export function createRefreshLoop({request, isHidden = () => false, onSchedule = () => {},
                                   setTimer = setTimeout, clearTimer = clearTimeout}) {
  let refreshTimer = null;
  let refreshInFlight = false;
  let generation = 0;
  let stopped = false;

  const schedule = (next) => {
    onSchedule(next);
    if (!stopped && !isHidden()) {
      refreshTimer = setTimer(tick, next.delay);
    }
  };
  async function tick() {
    refreshTimer = null;
    if (stopped || refreshInFlight || isHidden()) {
      return;
    }
    refreshInFlight = true;
    const asked = generation;
    let summary = null;
    try {
      summary = await request();
    } catch (_) {
      summary = null;
    } finally {
      refreshInFlight = false;
    }
    schedule(asked === generation ? refreshDelay(summary)
      : {delay: REFRESH_FLOOR_MS, interval: null, reason: 'superseded'});
  }
  const restart = () => {
    if (refreshTimer !== null) {
      clearTimer(refreshTimer);
      refreshTimer = null;
    }
    if (!refreshInFlight) {
      tick();
    }
  };
  return {
    /** Starts (or restarts) the loop; calling it again never adds a second one. */
    start: restart,
    /** Shown again: ask now instead of waiting out a long timer (a request under way finishes first). */
    visible() {
      if (!isHidden()) {
        restart();
      }
    },
    refreshNow() {
      generation += 1;
      restart();
    },
    stop() {
      stopped = true;
      if (refreshTimer !== null) {
        clearTimer(refreshTimer);
        refreshTimer = null;
      }
    },
    /** For tests and diagnostics. */
    state: () => ({timer: refreshTimer !== null, inFlight: refreshInFlight, generation, stopped}),
  };
}

/**
 * The widget's gate: the dashboard ticks every widget on a fixed interval (2 s), so the widget
 * cannot schedule its own requests; it lets a tick through only once the next request is due.
 * `begin(now)` returns a token (or null: not due, or one already under way), `done(token, now,
 * summary)` sets when the next is due, `refreshNow()` lets the next tick through and makes a
 * request under way unable to set the cadence. Ticks may arrive a little early: half a tick of
 * tolerance keeps a 2-second delay from skipping one.
 */
export function createRefreshGate({tickMs = REFRESH_FLOOR_MS} = {}) {
  let dueAt = 0;
  let inFlight = false;
  let generation = 0;
  let last = null;
  return {
    begin(now) {
      if (inFlight || now < dueAt) {
        return null;
      }
      inFlight = true;
      return {generation};
    },
    done(token, now, summary) {
      inFlight = false;
      last = token && token.generation === generation ? refreshDelay(summary)
        : {delay: REFRESH_FLOOR_MS, interval: null, reason: 'superseded'};
      dueAt = now + last.delay - tickMs / 2;
      return last;
    },
    refreshNow() {
      generation += 1;
      dueAt = 0;
    },
    /** Shown again: the next tick asks. */
    visible() {
      dueAt = 0;
    },
    state: () => ({dueAt, inFlight, generation, last}),
  };
}
