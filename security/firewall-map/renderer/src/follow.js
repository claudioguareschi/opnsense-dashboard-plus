/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschi@gmail.com>
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

/*
 * "Follow traffic": keep the view framed on the live arcs.
 *
 * The flight is animated here, frame by frame, rather than with a deck.gl view transition:
 * those end through callbacks read from props that every interim view state replaces, and a
 * transition started before deck has laid out its first frame can be dropped, which left
 * this code believing the map had moved when it had not.
 */
import {FlyToInterpolator, WebMercatorViewport} from '@deck.gl/core';

// padding is this share of the map's shorter side; the view never zooms in further than this
// past the whole-world view, and it only tightens after the traffic has used less of the view for
// a while (it widens at once when something falls outside)
const FOLLOW_PADDING = 0.12;
const FOLLOW_MAX_ZOOM_STEPS = 3.5;
// the view frames every arc seen over this window: a flow that comes and goes keeps its room
// for a while instead of pulling the map in and out
const FOLLOW_WINDOW_MS = 10000;
// re-frame only for a real change: this much zoom, or the centre moving this share of the view
const FOLLOW_MIN_ZOOM_CHANGE = 0.25;
const FOLLOW_MIN_SHIFT = 0.15;
// a slow, gently eased flight (deck's default fly-to starts and stops abruptly)
const FOLLOW_FLY = {speed: 0.7, curve: 1.2};
const FOLLOW_MIN_FLY_MS = 1400;
const FOLLOW_MAX_FLY_MS = 3200;
const easeInOutCubic = (t) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);

function union(boxes) {
  return boxes.reduce((a, b) => [Math.min(a[0], b[0]), Math.min(a[1], b[1]), Math.max(a[2], b[2]), Math.max(a[3], b[3])]);
}

/**
 * map: {container, getView(), setView(view), landed(), arcs()} from the renderer.
 * options: {follow, followResumeMs, onFollowChange} from create().
 */
export function createFollow(map, options = {}) {
  let follow = Boolean(options.follow);
  let held = false;
  let hovering = false;
  let flying = false;
  let flightFrame = null;
  let resumeTimer = null;
  // what live arcs covered at each check over the last FOLLOW_WINDOW_MS
  let seen = [];
  // a re-frame asked for (toggle, filter, first data) that runs at the next chance
  let pendingFit = false;
  const stopHovering = () => {
    hovering = false;
  };
  map.container.addEventListener('pointerleave', stopHovering);

  function padding(width, height) {
    const pad = Math.round(Math.min(width, height) * FOLLOW_PADDING);
    // a little more on the top, where the legend and the zoom buttons float over the map
    return {top: Math.round(pad * 1.4), bottom: pad, left: pad, right: pad};
  }

  /** [west, south, east, north] of every live allowed or IDS arc (the whole curve), or null. */
  function liveBounds() {
    let west = Infinity; let east = -Infinity; let south = Infinity; let north = -Infinity;
    for (const arc of map.arcs()) {
      // not arcs fading out, nor an IDS connection that has already closed
      if (arc.fading || (arc.ids && !arc.ids.active)) {
        continue;
      }
      for (const [lon, lat] of arc.path) {
        west = Math.min(west, lon); east = Math.max(east, lon);
        south = Math.min(south, lat); north = Math.max(north, lat);
      }
    }
    return west === Infinity ? null : [west, Math.max(south, -75), east, Math.min(north, 80)];
  }

  function target(width, height, bounds) {
    const view = map.getView();
    if (!bounds || width < 50 || height < 50) {
      return null;
    }
    const maxZoom = Math.min(view.maxZoom, view.minZoom + FOLLOW_MAX_ZOOM_STEPS);
    try {
      const fitted = new WebMercatorViewport({width, height}).fitBounds([[bounds[0], bounds[1]], [bounds[2], bounds[3]]],
        {padding: padding(width, height), maxZoom});
      return {longitude: fitted.longitude, latitude: fitted.latitude, zoom: Math.max(view.minZoom, Math.min(maxZoom, fitted.zoom))};
    } catch (_) {
      return null;  // padding larger than a tiny map
    }
  }

  function cancelFlight() {
    if (flightFrame !== null) {
      cancelAnimationFrame(flightFrame);
      flightFrame = null;
    }
    flying = false;
  }

  function flyTo(destination, width, height) {
    cancelFlight();
    const view = map.getView();
    const interpolator = new FlyToInterpolator(FOLLOW_FLY);
    const start = {longitude: view.longitude, latitude: view.latitude, zoom: view.zoom, width, height};
    const end = {...destination, width, height};
    // getDuration only computes a duration when asked for 'auto'; otherwise it returns the end
    // props' transitionDuration, which was undefined and made every flight NaN
    const natural = interpolator.getDuration(start, {...end, transitionDuration: 'auto'});
    const length = Number.isFinite(natural) ? Math.max(FOLLOW_MIN_FLY_MS, Math.min(FOLLOW_MAX_FLY_MS, natural)) : FOLLOW_MIN_FLY_MS;
    const began = performance.now();
    flying = true;
    const step = (now) => {
      const t = Math.min(1, Math.max(0, (now - began) / length));
      const at = interpolator.interpolateProps(start, end, easeInOutCubic(t));
      // never hand deck a broken view: land on the target if the curve gives anything odd
      const good = [at.longitude, at.latitude, at.zoom].every(Number.isFinite);
      map.setView({...map.getView(), ...(good ? {longitude: at.longitude, latitude: at.latitude, zoom: at.zoom} : destination)});
      if (t < 1) {
        flightFrame = requestAnimationFrame(step);
      } else {
        flightFrame = null;
        flying = false;
        map.landed();
      }
    };
    flightFrame = requestAnimationFrame(step);
  }

  /**
   * Called on every data refresh (and on toggle, filter change, resize). The target frames the
   * union of what live arcs covered over the last FOLLOW_WINDOW_MS, so it widens the moment a
   * new arc appears and tightens once a departed one has been gone for the window.
   */
  function update(immediately = false) {
    const now = performance.now();
    const bounds = liveBounds();
    if (immediately) {
      // a new question (toggle, filter): frame what is there now, forget the old window
      seen = [];
    }
    if (bounds) {
      seen.push({time: now, bounds});
    }
    seen = seen.filter((entry) => now - entry.time <= FOLLOW_WINDOW_MS);
    pendingFit = pendingFit || immediately;
    if (!follow || held || hovering || flying || !seen.length) {
      return;
    }
    const width = map.container.clientWidth;
    const height = map.container.clientHeight;
    const destination = target(width, height, union(seen.map((entry) => entry.bounds)));
    if (!destination) {
      return;
    }
    const view = map.getView();
    const current = new WebMercatorViewport({...view, width, height});
    const [tx, ty] = current.project([destination.longitude, destination.latitude]);
    const shifted = Math.abs(tx - width / 2) > width * FOLLOW_MIN_SHIFT || Math.abs(ty - height / 2) > height * FOLLOW_MIN_SHIFT;
    const rezoom = Math.abs(destination.zoom - view.zoom) > FOLLOW_MIN_ZOOM_CHANGE;
    if (pendingFit || shifted || rezoom) {
      pendingFit = false;
      flyTo(destination, width, height);
    }
  }

  return {
    update,
    cancelFlight,
    get flying() {
      return flying;
    },
    get follow() {
      return follow;
    },
    /** Follow traffic holds still only while something is under the pointer. */
    setHovering(on) {
      hovering = on;
    },
    set(on) {
      const was = follow;
      follow = Boolean(on);
      return was;
    },
    /** A new map size needs a new frame, but keeps what the window has seen. */
    resized() {
      pendingFit = true;
      update();
    },
    /** The user moved the map by hand. */
    userMoved() {
      cancelFlight();
      if (!follow) {
        return;
      }
      if (options.followResumeMs) {
        // the dashboard widget has no toggle: pause, and pick up again once the user leaves it be
        clearTimeout(resumeTimer);
        held = true;
        resumeTimer = setTimeout(() => {
          held = false;
          update(true);
        }, options.followResumeMs);
        return;
      }
      follow = false;
      options.onFollowChange?.(false);
    },
    diagnostics() {
      const view = map.getView();
      return {follow, held, hovering, flying, pendingFit, window: seen.length,
        view: {longitude: view.longitude, latitude: view.latitude, zoom: view.zoom},
        target: target(map.container.clientWidth, map.container.clientHeight, liveBounds())};
    },
    destroy() {
      clearTimeout(resumeTimer);
      cancelFlight();
      map.container.removeEventListener('pointerleave', stopHovering);
    },
  };
}
