/* Geometry of the map's arcs: flows, blocked sources and Suricata connections, and their pulses. */
import {DEFAULT_OPTIONS} from './options.js';
import {serviceCategory} from './palette.js';
import {idsOutcome} from './summaries.js';

export const ARC_SAMPLES = 32;
// blocked traffic: pulses race into the firewall
const BLOCK_PULSE_PERIOD = 1.1;
const HEAVY_TOP_MIN_RATE = 10000;
// pulse speed maps log10(bytes/s) onto this range: ~1 B/s crawls, ~10 MB/s races
const FASTEST_LOG_RATE = 7;
// a direction counts as "both ways" when the smaller side carries at least this share
const BIDIRECTIONAL_SHARE = 0.25;
/** The arc and map entries for connections Suricata alerted on (see the collector's Correlator). */
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
    const activity = flow.activity;
    const total = rateIn + rateOut;
    const inShare = total > 0 ? rateIn / total : 1;
    let direction = 'both';
    if (inShare >= 1 - BIDIRECTIONAL_SHARE) {
      direction = 'in';
    } else if (inShare <= BIDIRECTIONAL_SHARE) {
      direction = 'out';
    }
    const strength = Math.min(1, Math.log10(1 + rate) / FASTEST_LOG_RATE);
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
      // colour follows the dominant direction; pulses show both when traffic flows both ways
      toward: inShare >= 0.5,
      service: serviceCategory(members.slice().sort((a, b) => (b.rate ?? 0) - (a.rate ?? 0))[0]?.services?.[0]),
      egress: members.slice().sort((a, b) => (b.rate ?? 0) - (a.rate ?? 0))[0]?.egress || 'Unknown',
      threat: members.some((member) => member.threat),
      contained: !members.some((member) => member.threat) && members.some((member) => member.contained),
      ids: members[0].ids_flow || null,
      initiated: initiatedBy(members),
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
export function idsArcActivity(flow) {
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

export function pulsePosition(arc, seconds, reverse) {
  let t = (seconds / arc.period + arc.phase) % 1;
  if (reverse) {
    t = 1 - t;
  }
  t *= ARC_SAMPLES;
  const index = Math.min(Math.floor(t), ARC_SAMPLES - 1);
  const fraction = t - index;
  const [ax, ay] = arc.path[index];
  const [bx, by] = arc.path[index + 1];
  return [ax + (bx - ax) * fraction, ay + (by - ay) * fraction];
}

/** Pulses run away from the firewall (arc origin) for outbound traffic and towards it for inbound. */
export function pulses(arcs) {
  const items = [];
  for (const arc of arcs) {
    if (arc.ids && !arc.ids.active) {
      continue;  // a closed connection carries no traffic
    }
    if (arc.direction !== 'in') {
      items.push({arc, reverse: false, toward: false});
    }
    if (arc.direction !== 'out') {
      items.push({arc, reverse: true, toward: true});
    }
  }
  return items;
}
