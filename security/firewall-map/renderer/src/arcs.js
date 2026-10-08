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

/* Geometry of the map's arcs: flows, blocked sources and Suricata connections, and their pulses. */
import {DEFAULT_OPTIONS} from './options.js';
import {serviceCategory} from './palette.js';
import {idsOutcome} from './summaries.js';

const ARC_SAMPLES = 32;
// blocked traffic: pulses race into the firewall
const BLOCK_PULSE_PERIOD = 1.1;
const HEAVY_TOP_MIN_RATE = 10000;
// pulse speed maps log10(bytes/s) onto this range: ~1 B/s crawls, ~10 MB/s races
const FASTEST_LOG_RATE = 7;
// a direction counts as "both ways" when the smaller side carries at least this share
const BIDIRECTIONAL_SHARE = 0.25;
/** How long the arc of a closed connection Suricata alerted on stays, fading out (see the collector's Correlator). */
export const IDS_ARC_FADE_SECONDS = 60;

export function mercatorY(latitude) {
  return (180 / Math.PI) * Math.log(Math.tan(Math.PI / 4 + (latitude * Math.PI) / 360));
}

function latitudeFromMercator(y) {
  return (360 / Math.PI) * Math.atan(Math.exp((y * Math.PI) / 180)) - 90;
}

function hash(text) {
  let value = 0;
  for (let index = 0; index < text.length; index++) {
    value = (value * 31 + text.charCodeAt(index)) | 0;
  }
  return (value >>> 0) / 4294967296;
}

/**
 * Curved flow paths that do not sit on top of each other: flows ending near the same place
 * (GeoLite often maps many addresses to one city or country centroid) get alternating,
 * increasingly deep bends, so each one stays visible as its own arch.
 */
export function buildArcs(data, options = DEFAULT_OPTIONS) {
  const locations = new Map((data.locations || []).map((location) => [location.id, location]));
  // Addresses GeoLite places at identical coordinates can't be told apart on the map, so they
  // share one arch carrying their combined rate.
  const merged = new Map();
  for (const item of data.flows || []) {
    const origin = locations.get(item.origin);
    const dest = locations.get(item.dest);
    if (!origin || !dest) {
      continue;
    }
    // a connection Suricata alerted on is never merged: it gets an arc of its own
    const key = item.ids_flow ? `${item.origin}>ids:${item.ids_flow.key}` : `${item.origin}>${dest.lat},${dest.lon}`;
    const rate = item.rate ?? item.count ?? 0;
    const rateIn = item.rate_in ?? rate;
    const rateOut = item.rate_out ?? 0;
    const entry = merged.get(key);
    if (entry) {
      entry.flow.rate += rate;
      entry.flow.rateIn += rateIn;
      entry.flow.rateOut += rateOut;
      entry.flow.activity = Math.max(entry.flow.activity, item.activity ?? 1);
      entry.members.push(item);
    } else {
      merged.set(key, {
        key,
        flow: {origin: item.origin, dest: item.dest, rate, rateIn, rateOut, activity: item.activity ?? 1},
        origin,
        dest,
        members: [item],
      });
    }
  }
  // IDS connections first so the arc limit never hides them
  const flows = [...merged.values()]
    .sort((a, b) => (b.members[0].ids_flow ? 1 : 0) - (a.members[0].ids_flow ? 1 : 0) || b.flow.rate - a.flow.rate)
    .slice(0, options.maxArcs);
  // lanes stay put across refreshes: an arch keeps its bend while it lives, new arches take the
  // first free lane of their cell, so nothing jumps when rankings change
  const cellOf = ({flow, dest}) => `${flow.origin}|${Math.round(dest.lat * 2)}|${Math.round(dest.lon * 2)}`;
  const previous = options.previousLanes || new Map();
  const taken = new Map();
  const laneOf = new Map();
  for (const entry of flows) {
    const lane = previous.get(entry.key);
    const used = taken.get(cellOf(entry)) || new Set();
    if (lane !== undefined && !used.has(lane)) {
      used.add(lane);
      taken.set(cellOf(entry), used);
      laneOf.set(entry.key, lane);
    }
  }
  for (const entry of flows) {
    if (!laneOf.has(entry.key)) {
      const used = taken.get(cellOf(entry)) || new Set();
      let lane = 0;
      while (used.has(lane)) {
        lane++;
      }
      used.add(lane);
      taken.set(cellOf(entry), used);
      laneOf.set(entry.key, lane);
    }
  }
  const arcs = [];
  flows.forEach(({key, flow, origin, dest, members}, index) => {
    const x0 = origin.lon;
    const y0 = mercatorY(origin.lat);
    const x1 = dest.lon;
    const y1 = mercatorY(dest.lat);
    const dx = x1 - x0;
    const dy = y1 - y0;
    const length = Math.hypot(dx, dy);
    if (length < 0.3) {
      return;
    }
    const lane = laneOf.get(key);
    // unit normal, oriented so the first lane bows towards the pole side of the map
    let nx = -dy / length;
    let ny = dx / length;
    if (ny < 0) {
      nx = -nx;
      ny = -ny;
    }
    const side = lane % 2 === 0 ? 1 : -1;
    const bend = Math.max(length * (0.2 + 0.12 * Math.floor(lane / 2)), 1.2 + lane * 0.6) * side;
    const cx = (x0 + x1) / 2 + nx * bend;
    const cy = (y0 + y1) / 2 + ny * bend;
    const path = [];
    for (let step = 0; step <= ARC_SAMPLES; step++) {
      const t = step / ARC_SAMPLES;
      const u = 1 - t;
      const x = u * u * x0 + 2 * u * t * cx + t * t * x1;
      const y = u * u * y0 + 2 * u * t * cy + t * t * y1;
      path.push([x, latitudeFromMercator(y)]);
    }
    const {rate, rateIn, rateOut} = flow;
    // mirrored: the CARP master's connections, synchronized without traffic counters; probe:
    // connection attempts without data (an arc is either only when all its flows are)
    const presence = ['mirror', 'probe'].find((kind) => members.every((member) => member.presence === kind)) || 'traffic';
    // a mirrored arc has no traffic to fade with: it stays as long as the master has the states
    const activity = presence === 'mirror' ? 1 : flow.activity;
    const total = rateIn + rateOut;
    const inShare = total > 0 ? rateIn / total : 1;
    let direction = 'both';
    if (presence === 'mirror') {
      // no byte counters: the pulses follow who opened the connections
      const opened = initiatedBy(members);
      direction = opened === 'remote' ? 'in' : opened === 'local' ? 'out' : 'both';
    } else if (inShare >= 1 - BIDIRECTIONAL_SHARE) {
      direction = 'in';
    } else if (inShare <= BIDIRECTIONAL_SHARE) {
      direction = 'out';
    }
    const strength = Math.min(1, Math.log10(1 + rate) / FASTEST_LOG_RATE);
    const busiest = members.reduce((top, member) => ((member.rate ?? 0) > (top.rate ?? 0) ? member : top), members[0]);
    arcs.push({
      key,
      lane,
      path,
      heavy: (index < options.heavyTop && rate >= HEAVY_TOP_MIN_RATE) || rate >= options.heavyRate,
      rate,
      rateIn,
      rateOut,
      dest,
      members,
      // color follows the dominant direction; pulses show both when traffic flows both ways
      toward: inShare >= 0.5,
      service: serviceCategory(busiest?.services?.[0]),
      egress: busiest?.egress || 'Unknown',
      threat: members.some((member) => member.threat),
      contained: !members.some((member) => member.threat) && members.some((member) => member.contained),
      ids: members[0].ids_flow || null,
      initiated: initiatedBy(members),
      presence,
      direction,
      activity,
      period: 6 - 5.2 * strength,
      phase: hash(`${flow.origin}>${flow.dest}`),
    });
  });
  return arcs;
}

/** Who opened the connections of an arch: 'remote', 'local' or 'both'. */
function initiatedBy(members) {
  const sides = new Set(members.map((flow) => flow.initiated || 'local'));
  return sides.size === 1 ? [...sides][0] : 'both';
}

/** A gently bent path from a blocked source into the firewall (bends the other way from flows). */
function blockPath(source, target) {
  const x0 = source.lon;
  const y0 = mercatorY(source.lat);
  const x1 = target.lon;
  const y1 = mercatorY(target.lat);
  const length = Math.hypot(x1 - x0, y1 - y0) || 1;
  let nx = -(y1 - y0) / length;
  let ny = (x1 - x0) / length;
  if (ny > 0) {
    nx = -nx;
    ny = -ny;
  }
  const bend = Math.max(length * 0.18, 1);
  const cx = (x0 + x1) / 2 + nx * bend;
  const cy = (y0 + y1) / 2 + ny * bend;
  const path = [];
  for (let step = 0; step <= ARC_SAMPLES; step++) {
    const t = step / ARC_SAMPLES;
    const u = 1 - t;
    path.push([u * u * x0 + 2 * u * t * cx + t * t * x1, latitudeFromMercator(u * u * y0 + 2 * u * t * cy + t * t * y1)]);
  }
  return path;
}

export function buildBlocks(data) {
  const locations = new Map((data.locations || []).map((location) => [location.id, location]));
  return (data.blocks || [])
    .map((block) => {
      const target = locations.get(block.target) || (data.locations || []).find((location) => location.local);
      return target ? {
        ...block,
        path: blockPath(block, target),
        period: BLOCK_PULSE_PERIOD,
        phase: hash(block.source),
      } : null;
    })
    .filter(Boolean);
}

/** How visible a correlated connection's arc is: full while open, then fading out over a minute. */
function idsArcActivity(flow) {
  if (flow.active) {
    return 1;
  }
  const closed = flow.closed_seconds ?? flow.last_seconds ?? IDS_ARC_FADE_SECONDS;
  return Math.max(0, 0.45 * (1 - closed / IDS_ARC_FADE_SECONDS));
}

export function idsArcData(data) {
  // the endpoint keeps its IDS ring for the alert window; only the arc goes away
  const flows = (data.ids_flows || []).filter((flow) => flow.kind !== 'blocked' && idsArcActivity(flow) > 0).map((flow) => ({
    origin: flow.origin,
    dest: flow.dest,
    rate: flow.active ? 1 : 0,
    rate_in: flow.remote_started ? 1 : 0,
    rate_out: flow.remote_started ? 0 : 1,
    activity: idsArcActivity(flow),
    initiated: flow.remote_started ? 'remote' : 'local',
    threat: idsOutcome(flow) === 'danger',
    contained: idsOutcome(flow) === 'contained',
    ids_flow: flow,
  }));
  const known = new Set((data.locations || []).map((location) => location.id));
  const locations = (data.ids_flows || []).filter((flow) => !known.has(flow.dest)).map((flow) => ({
    id: flow.dest, name: flow.city || flow.country || flow.dest, city: flow.city, country: flow.country,
    country_code: flow.country_code, lat: flow.lat, lon: flow.lon, asn: flow.asn, as_org: flow.as_org,
  }));
  return {flows, locations};
}

/**
 * Keep every pulse where it is when new data arrives. A pulse's place on its arc is
 * (seconds / period + phase) mod 1, and the period follows the arc's rate, which changes with
 * every refresh: without this, a new period moved every dot at once (the jerk every 2 seconds).
 * Each arc still carried over gets the phase that puts its pulse exactly where it was, and from
 * there it moves at its new speed.
 */
export function continuePhases(previous, arcs, seconds) {
  for (const arc of arcs) {
    const before = previous.get(arc.key);
    if (before && before !== arc && before.period !== arc.period) {
      const at = seconds / before.period + before.phase;
      arc.phase = ((at - seconds / arc.period) % 1 + 1) % 1;
    } else if (before && before !== arc) {
      arc.phase = before.phase;
    }
  }
  return arcs;
}

// radius, in screen pixels, of the circle around the firewall's house icon that arches, pulses
// and endpoints stay out of, just enough to keep the 15px icon uncovered
export const HOME_CLEARANCE = 10;

/** Map units (degrees of longitude, and mercatorY) per screen pixel at a deck.gl zoom. */
export function unitsPerPixel(zoom) {
  return 360 / (512 * 2 ** zoom);
}

/** The point at a fractional sample index along a sampled path. */
function pointAt(path, t) {
  const index = Math.min(Math.floor(t), path.length - 2);
  const fraction = t - index;
  const [ax, ay] = path[index];
  const [bx, by] = path[index + 1];
  return [ax + (bx - ax) * fraction, ay + (by - ay) * fraction];
}

/** How many samples in from one end the path leaves the clear circles around the homes. */
function exitIndex(path, homes, radius, fromEnd) {
  const last = path.length - 1;
  const nearest = (index) => {
    const [x, lat] = path[fromEnd ? last - index : index];
    const y = mercatorY(lat);
    return Math.min(...homes.map(([homeX, homeY]) => Math.hypot(x - homeX, y - homeY)));
  };
  let inside = nearest(0);
  if (inside >= radius) {
    return 0;
  }
  for (let index = 1; index <= last; index++) {
    const distance = nearest(index);
    if (distance >= radius) {
      return index - 1 + Math.max(0, Math.min(1, (radius - inside) / (distance - inside || 1)));
    }
    inside = distance;
  }
  return last;
}

/**
 * The part of a path drawn on screen: the ends stop a fixed number of pixels short of any home
 * (the firewall's own locations, given as [lon, mercatorY]), so the house icons stay clear of
 * arches and pulses at every zoom. The result has as many samples as the path, so
 * pulsePosition works on it unchanged; null when the whole arch lies inside the clear circles
 * (a place right next to home at this zoom).
 */
export function clearOfHomes(path, homes, radius) {
  const last = path.length - 1;
  if (!homes.length) {
    return path;
  }
  const from = exitIndex(path, homes, radius, false);
  const to = last - exitIndex(path, homes, radius, true);
  if (from === 0 && to === last) {
    return path;
  }
  if (to - from < 0.5) {
    return null;
  }
  const shown = [];
  for (let step = 0; step <= last; step++) {
    shown.push(pointAt(path, from + ((to - from) * step) / last));
  }
  return shown;
}

export function pulsePosition(arc, seconds, reverse, period = arc.period, phase = arc.phase) {
  const path = arc.shown || arc.path;
  let t = (seconds / period + phase) % 1;
  if (reverse) {
    t = 1 - t;
  }
  return pointAt(path, t * ARC_SAMPLES);
}

// a mirrored arc (CARP backup): a closely spaced pair of dots at one fixed pace, since there are
// no traffic counters to set a speed
const MIRROR_PERIOD = 4;
const MIRROR_GAP = 0.035;

// a saved snapshot: evenly spaced dots marching at one pace, so a frozen map never looks live
const MARCH_DOTS = 6;
const MARCH_PERIOD = 7;

/** Equally spaced marching dots for every arc of a saved snapshot, in the traffic's direction. */
export function marchingPulses(arcs) {
  const items = [];
  // one marching row per direction, whatever the live pattern (a mirrored pair is one)
  for (const item of pulses(arcs).filter((pulse) => !pulse.pair)) {
    for (let dot = 0; dot < MARCH_DOTS; dot++) {
      items.push({...item, period: MARCH_PERIOD, phase: dot / MARCH_DOTS, march: true});
    }
  }
  return items;
}

/** Pulses run away from the firewall (arc origin) for outbound traffic and towards it for inbound. */
export function pulses(arcs) {
  const items = [];
  for (const arc of arcs) {
    if (arc.ids && !arc.ids.active) {
      continue;  // a closed connection carries no traffic
    }
    const sides = [];
    if (arc.direction !== 'in') {
      sides.push({arc, reverse: false, toward: false});
    }
    if (arc.direction !== 'out') {
      sides.push({arc, reverse: true, toward: true});
    }
    for (const side of sides) {
      if (arc.presence === 'mirror') {
        items.push({...side, period: MIRROR_PERIOD, phase: arc.phase},
          {...side, period: MIRROR_PERIOD, phase: arc.phase + MIRROR_GAP, pair: true});
      } else {
        items.push(side);
      }
    }
  }
  return items;
}
