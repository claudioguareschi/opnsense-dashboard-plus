/* Firewall Map+ renderer. Bundled locally from deck.gl. */
import {Deck, MapView, WebMercatorViewport} from '@deck.gl/core';
import {GeoJsonLayer, PathLayer, ScatterplotLayer, TextLayer} from '@deck.gl/layers';
import worldData from './world.json';

// Antarctica only adds empty space below the flows.
const world = {...worldData, features: worldData.features.filter((feature) => feature.id !== 'ATA')};

const ARC_SAMPLES = 32;
const LINK_WIDTH = 1.5;
const HEAVY_WIDTH = 3;
// heavy talkers: the busiest few links (if above a floor), or anything above a byte rate
const DEFAULT_OPTIONS = {
  heavyTop: 5, heavyRate: 1000000, maxArcs: 120, labels: true, asn: true, blocks: true, colorMode: 'initiator',
};
// blocked traffic: pulses race into the firewall; threats also throb at their source
const BLOCK_PULSE_PERIOD = 1.1;
const THREAT_THROB_PERIOD = 0.9;
const HEAVY_TOP_MIN_RATE = 10000;
// city labels appear once the map is zoomed this far past the fitted world view
const LABEL_ZOOM_STEP = 1.2;
const MAX_LABELS = 40;
const LABEL_FONT_SIZE = 11;
// approximate glyph width for placing labels before they are drawn
const LABEL_CHAR_WIDTH = 6.2;
const LABEL_PADDING = 3;
// pulse speed maps log10(bytes/s) onto this range: ~1 B/s crawls, ~10 MB/s races
const FASTEST_LOG_RATE = 7;
// a direction counts as "both ways" when the smaller side carries at least this share
const BIDIRECTIONAL_SHARE = 0.25;
const FRAME_INTERVAL = 1000 / 30;

function mercatorY(latitude) {
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

const INITIATOR_LABELS = {
  local: 'Started inside',
  remote: 'Started outside',
  both: 'Started from both sides',
};

function duration(seconds) {
  if (!seconds || seconds < 60) {
    return null;
  }
  if (seconds < 5400) {
    return `${Math.round(seconds / 60)} min`;
  }
  if (seconds < 172800) {
    return `${Math.round(seconds / 3600)} h`;
  }
  return `${Math.round(seconds / 86400)} days`;
}

/** 'HTTPS (443/tcp)', 'port 9443/tcp' or 'ICMP'. */
function serviceLabel(name, port) {
  const raw = /^(TCP|UDP)\/(\d+)$/.exec(name || '');
  if (raw) {
    return `port ${raw[2]}/${raw[1].toLowerCase()}`;
  }
  return port ? `${plain(name)} (${port})` : plain(name || 'traffic');
}

function hostLabel(host) {
  return host.name ? `${plain(host.name)} (${host.ip})` : host.ip;
}

/**
 * One plain-language sentence per direction of a flow, built only from what the collector saw:
 * who opened it, the service and port, the other side's name, network and country, how long.
 * `remote` is {ip, hostname, org, country}; the caller escapes the result.
 */
export function flowSummary(flow, remote) {
  const place = [remote.org, remote.country].filter(Boolean).map(plain).join(', ');
  const other = `${remote.hostname ? plain(remote.hostname) : remote.ip}${place ? ` (${place})` : ''}`;
  const open = duration(flow.age);
  const sentences = [];
  const services = flow.services || [];
  const ports = flow.service_ports || {};
  if (flow.initiated === 'remote' || flow.initiated === 'both') {
    const targets = flow.targets || [];
    const target = targets[0];
    let where = 'this firewall';
    let service = serviceLabel(services[0], ports[services[0]]);
    if (target) {
      where = target.firewall || target.name === 'firewall' ? 'this firewall' : hostLabel(target);
      const port = target.port ? `${target.port}/${target.protocol || 'tcp'}` : null;
      service = serviceLabel(target.service, port);
    }
    const more = targets.length > 1 ? ` (and ${targets.length - 1} other target${targets.length > 2 ? 's' : ''})` : '';
    const forwarded = target && !(target.firewall || target.name === 'firewall') ? ' through a port forward' : '';
    sentences.push(`${other} reached ${where} on ${service}${more}${forwarded}${open ? `, open for ${open}` : ''}.`);
  }
  if (flow.initiated !== 'remote') {
    const inside = flow.inside || [];
    const who = inside.length
      ? `${hostLabel(inside[0])}${inside.length > 1 ? ` and ${inside.length - 1} other host${inside.length > 2 ? 's' : ''}` : ''}`
      : 'This firewall';
    const name = services[0] || '';
    const service = serviceLabel(name, ports[name]);
    const more = services.length > 1 ? ` and ${services.length - 1} other service${services.length > 2 ? 's' : ''}` : '';
    let sentence;
    if (/^DNS/.test(name)) {
      sentence = `${who} queried ${service}${more} at ${other}`;
    } else if (name === 'NTP') {
      sentence = `${who} synced time with ${other} over ${service}${more}`;
    } else if (/^(SMTP|SMTPS|Submission)$/.test(name)) {
      sentence = `${who} delivered mail to ${other} over ${service}${more}`;
    } else if (name === 'ICMP') {
      sentence = `${who} pinged ${other}`;
    } else {
      sentence = `${who} opened ${service}${more} to ${other}`;
    }
    sentences.push(`${sentence}${open && name !== 'ICMP' ? `, open for ${open}` : ''}.`);
  }
  return sentences;
}

/** The same kind of sentence for a source the firewall blocked (from the filter log). */
export function blockSummary(block, showAsn = true) {
  const place = [showAsn ? block.as_org : null, block.country].filter(Boolean).map(plain).join(', ');
  const services = (block.services || []).slice(0, 2).map((service) => serviceLabel(service.name, service.port));
  const others = Math.max(0, (block.port_count || services.length) - services.length);
  const tried = services.length
    ? `${services.join(services.length > 1 && !others ? ' and ' : ', ')}${others ? ` and ${others} other port${others > 1 ? 's' : ''}` : ''}`
    : 'a connection';
  const hits = block.hits ?? block.hits_per_minute;
  const since = duration(block.seconds);
  const rule = block.rule ? ` by "${plain(block.rule)}"` : '';
  const where = block.interface ? ` on ${plain(block.interface)}` : '';
  return `${block.source}${place ? ` (${place})` : ''} tried ${tried} on this firewall: blocked ${hits}× `
    + `in the last ${block.window_minutes ?? 1} min${rule}${where}${since ? `, first seen ${since} ago` : ''}.`;
}

// arches, blocked sources and endpoints fade in and out instead of popping
const FADE_IN_MS = 800;

/** A colour with its alpha scaled by a fade opacity. */
function faded(color, opacity) {
  return opacity >= 1 ? color : [color[0], color[1], color[2], Math.round((color[3] ?? 255) * opacity)];
}
const FADE_OUT_MS = 1600;

/** Tracks when each keyed item appeared or vanished; vanished items linger while fading out. */
class Fader {
  constructor(keyOf) {
    this.keyOf = keyOf;
    this.entries = new Map();
  }

  opacityOf(entry, now) {
    const fadeIn = Math.min(1, (now - entry.born) / FADE_IN_MS);
    const fadeOut = entry.gone === null ? 1 : Math.max(0, 1 - (now - entry.gone) / FADE_OUT_MS);
    return Math.max(0, fadeIn * fadeOut);
  }

  update(items, now) {
    const next = new Map();
    const result = [];
    for (const item of items) {
      const key = this.keyOf(item);
      if (next.has(key)) {
        continue;
      }
      const previous = this.entries.get(key);
      let born = now;
      if (previous) {
        // coming back while fading out resumes from the current opacity
        born = previous.gone === null ? previous.born : now - this.opacityOf(previous, now) * FADE_IN_MS;
      }
      const entry = {item, born, gone: null};
      item.fade = entry;
      next.set(key, entry);
      result.push(item);
    }
    for (const [key, entry] of this.entries) {
      if (next.has(key)) {
        continue;
      }
      if (entry.gone === null) {
        entry.gone = now;
      }
      if (this.opacityOf(entry, now) > 0) {
        entry.item.fading = true;
        next.set(key, entry);
        result.push(entry.item);
      }
    }
    this.entries = next;
    return result;
  }

  opacity(item, now) {
    return item.fade ? this.opacityOf(item.fade, now) : 1;
  }

  animating(now) {
    for (const entry of this.entries.values()) {
      if (entry.gone !== null || now - entry.born < FADE_IN_MS) {
        return true;
      }
    }
    return false;
  }
}

function formatRate(bytes) {
  const units = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
  let value = bytes;
  let unit = 0;
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1000;
    unit++;
  }
  return `${value >= 100 || unit === 0 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`;
}

// OPNsense HTML-escapes &, < and > in API responses (e.g. "AT&amp;T"); undo that before display
function plain(text) {
  return String(text ?? '').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
}

function escapeHtml(text) {
  return plain(text).replace(/[&<>"']/g, (char) => `&#${char.charCodeAt(0)};`);
}

// categories for "colour by service"; each flow uses its busiest service
const SERVICE_CATEGORIES = [
  ['Web', /^(HTTPS?|HTTP alt|HTTPS alt)$/],
  ['QUIC', /^QUIC$/],
  ['DNS', /^DNS/],
  ['NTP', /^NTP$/],
  ['VPN', /^(OpenVPN|WireGuard|IKE|IPsec NAT-T)$/],
  ['Mail', /^(SMTP|SMTPS|Submission|IMAP|IMAPS|POP3S)$/],
  ['Remote access', /^(SSH|RDP)$/],
  ['Push / STUN', /(Push|STUN)/],
];
// colour-blind friendly categorical colours, none of them close to the crimson used for threats
const CATEGORY_COLORS = [
  [0, 114, 178], [230, 159, 0], [0, 158, 115], [204, 121, 167],
  [86, 180, 233], [140, 109, 49], [27, 158, 158], [120, 94, 240], [150, 150, 150],
];

export function serviceCategory(service) {
  if (!service) {
    return 'Other';
  }
  const match = SERVICE_CATEGORIES.find(([, pattern]) => pattern.test(service));
  return match ? match[0] : 'Other';
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

/**
 * Suricata's view of an address in one line per signature, worst first:
 * 'Suricata: ET SCAN Potential SSH Scan (severity 2), 3× in the last hour, latest 2 min ago'.
 */
export function idsSummary(ids) {
  if (!ids || !ids.count) {
    return [];
  }
  const latest = duration(ids.last_seconds) || 'moments';
  const lines = (ids.signatures || []).map((item, index) =>
    `Suricata: ${plain(item.signature)} (severity ${item.severity}${item.category ? `, ${plain(item.category)}` : ''})`
    + `, ${item.count}×${index === 0 ? ` in the last ${ids.minutes >= 60 ? `${Math.round(ids.minutes / 60)} h` : `${ids.minutes} min`}, latest ${latest} ago` : ''}`);
  const shown = (ids.signatures || []).reduce((sum, item) => sum + item.count, 0);
  if (ids.count > shown) {
    lines.push(`and ${ids.count - shown} more alert${ids.count - shown > 1 ? 's' : ''}`);
  }
  return lines;
}

/* ------------------------------------------------------------------ hover cards */

// The same visual grammar as the page's details panel: title and place, a verdict pill, one block
// per address (host, network, the plain-language sentence, IDS lines), and a muted footer.
const TT_ICONS = {
  check: '<path d="M20 6 9 17l-5-5"/>',
  ban: '<circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/>',
  flag: '<path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><path d="M4 22v-7"/>',
  alert: '<circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/>',
  server: '<rect x="3" y="3" width="18" height="7" rx="1.5"/><rect x="3" y="14" width="18" height="7" rx="1.5"/><path d="M7 6.5h.01M7 17.5h.01"/>',
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
};

function ttIcon(name) {
  return `<svg class="fmt-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${TT_ICONS[name]}</svg>`;
}

const TT_STYLE = `
.fmt{font-size:12px;line-height:1.4;padding:10px 12px;min-width:220px}
.fmt-head{display:flex;align-items:flex-start;gap:10px}
.fmt-head>div:first-child{flex:1;min-width:0}
.fmt-title{font-weight:600;font-size:13.5px;line-height:1.25}
.fmt-sub{opacity:.7;font-size:11.5px;margin-top:1px}
.fmt-pill{display:inline-flex;align-items:center;gap:3px;white-space:nowrap;font-weight:600;font-size:11px;padding:1px 8px;border-radius:10px}
.fmt-ok{background:rgb(40,150,70);color:#fff}.fmt-danger{background:rgb(196,18,48);color:#fff}
.fmt-blocked{background:rgb(80,80,80);color:#fff}.fmt-muted{background:rgba(128,128,128,.22)}
.fmt-lists{margin-top:6px;display:flex;flex-wrap:wrap;gap:3px}
.fmt-chip{font-size:10.5px;font-weight:600;padding:0 6px;border-radius:3px;color:rgb(196,18,48);border:1px solid rgba(196,18,48,.45)}
.fmt-addr{margin-top:8px;padding-top:7px;border-top:1px solid rgba(128,128,128,.2)}
.fmt-host{display:flex;align-items:center;gap:6px;font-weight:600}
.fmt-host .fmt-ic{color:rgb(30,110,215);width:14px;height:14px}
.fmt-meta{opacity:.7;font-size:11.5px;margin-left:20px}
.fmt-say{margin:3px 0 0 20px}
.fmt-say.fmt-bad{color:rgb(196,18,48);font-weight:600}
.fmt-ids{margin:3px 0 0 20px;font-size:11.5px;color:rgb(200,110,0);display:flex;gap:5px}
.fmt-ids.fmt-bad{color:rgb(196,18,48);font-weight:600}
.fmt-ids .fmt-ic{margin-top:2px}
.fmt-more{margin:6px 0 0 20px;opacity:.7;font-size:11.5px}
.fmt-foot{margin-top:8px;padding-top:6px;border-top:1px solid rgba(128,128,128,.2);opacity:.75;font-size:11.5px;display:flex;flex-wrap:wrap;gap:2px 12px}
.fmt-ic{width:12px;height:12px;flex:none;vertical-align:-2px}
.fmt-flag.flag-icon{width:16px;height:12px;background-size:cover;border-radius:2px;margin-right:4px;vertical-align:-1px;box-shadow:0 0 0 1px rgba(0,0,0,.1)}
`;

function ensureTooltipStyle() {
  if (!document.getElementById('fwmap-tooltip-style')) {
    const style = document.createElement('style');
    style.id = 'fwmap-tooltip-style';
    style.textContent = TT_STYLE;
    document.head.appendChild(style);
  }
}

function ttFlag(code) {
  // flag images only where the page loads OPNsense's flag stylesheet (the full-size map)
  return /^[A-Za-z]{2}$/.test(code || '') && document.querySelector('link[href*="flag-icon"]')
    ? `<span class="flag-icon flag-icon-${code.toLowerCase()} fmt-flag"></span>` : '';
}

function ttPill(kind, text, icon) {
  return `<span class="fmt-pill fmt-${kind}">${icon ? ttIcon(icon) : ''}${escapeHtml(text)}</span>`;
}

function ttHead(title, sub, pill) {
  return `<div class="fmt-head"><div><div class="fmt-title">${escapeHtml(title)}</div>`
    + `${sub ? `<div class="fmt-sub">${sub}</div>` : ''}</div>${pill}</div>`;
}

function ttLists(lists) {
  return (lists || []).length
    ? `<div class="fmt-lists">${lists.map((name) => `<span class="fmt-chip">${escapeHtml(plain(name).replace(/^FWMAP_/, '').replace(/_/g, ' '))}</span>`).join('')}</div>` : '';
}

function ttIds(ids) {
  const bad = ids && ids.severity <= 2;
  return idsSummary(ids).map((line) => `<div class="fmt-ids${bad ? ' fmt-bad' : ''}">${ttIcon('flag')}<span>${escapeHtml(line.replace(/^Suricata: /, ''))}</span></div>`).join('');
}

function ttAddress(icon, name, meta, sentences, bad, ids) {
  return `<div class="fmt-addr"><div class="fmt-host">${ttIcon(icon)}<span>${escapeHtml(name)}</span></div>`
    + `${meta ? `<div class="fmt-meta">${escapeHtml(meta)}</div>` : ''}`
    + sentences.map((sentence) => `<div class="fmt-say${bad ? ' fmt-bad' : ''}">${escapeHtml(sentence)}</div>`).join('')
    + ttIds(ids) + '</div>';
}

function ttPlace(item) {
  const text = [item.city || item.region, item.country].filter(Boolean).map(plain).join(', ');
  const approximate = !item.city && item.accuracy_km ? ` (± ${item.accuracy_km} km)` : '';
  return text ? `${ttFlag(item.country_code)}${escapeHtml(text + approximate)}` : '';
}

/** Hover card for an endpoint (all flows to that place) or a single arch. */
function describe(place, members, locations, hostnames = {}, showAsn = true) {
  const rateIn = members.reduce((sum, flow) => sum + (flow.rate_in ?? 0), 0);
  const rateOut = members.reduce((sum, flow) => sum + (flow.rate_out ?? 0), 0);
  const services = [...new Set(members.flatMap((flow) => flow.services || []))].slice(0, 4);
  const egress = [...new Set(members.map((flow) => flow.egress).filter(Boolean))];
  const lists = [...new Set(members.flatMap((flow) => flow.lists || []))];
  const sorted = members.slice().sort((a, b) => (b.rate ?? 0) - (a.rate ?? 0));
  const addresses = sorted.slice(0, 4).map((flow) => {
    const location = locations.get(flow.dest);
    const hostname = hostnames?.[flow.dest];
    const org = showAsn && location?.asn ? `AS${location.asn} ${plain(location.as_org || '')}` : '';
    const remote = {ip: flow.dest, hostname, org: showAsn ? location?.as_org : null, country: location?.country};
    return ttAddress('server', hostname || flow.dest, [hostname ? flow.dest : '', org].filter(Boolean).join(' · '),
      flowSummary(flow, remote), flow.threat, flow.ids);
  });
  const title = [place.city || place.region, place.country].filter(Boolean).join(', ') || place.name || place.id;
  const flagged = lists.length > 0;
  const more = members.length > 4 ? `<div class="fmt-more">+${members.length - 4} more address${members.length - 4 > 1 ? 'es' : ''} here</div>` : '';
  const foot = [`↓ ${formatRate(rateIn)}  ↑ ${formatRate(rateOut)}`, egress.length ? `via ${egress.map(plain).join(', ')}` : '',
    services.join(', ')].filter(Boolean).map((part) => `<span>${escapeHtml(part)}</span>`).join('');
  return `<div class="fmt">${ttHead(title, members.length > 1 ? escapeHtml(`${members.length} addresses`) : ttPlace(place),
      flagged ? ttPill('danger', 'Allowed · flagged', 'alert') : ttPill('ok', 'Allowed', 'check'))}
    ${ttLists(lists)}${addresses.join('')}${more}<div class="fmt-foot">${foot}</div></div>`;
}

/** The arc and map entries for connections Suricata alerted on (see the collector's Correlator). */
export function idsArcData(data) {
  const flows = (data.ids_flows || []).filter((flow) => flow.kind !== 'blocked').map((flow) => ({
    origin: flow.origin,
    dest: flow.dest,
    rate: flow.active ? 1 : 0,
    rate_in: flow.remote_started ? 1 : 0,
    rate_out: flow.remote_started ? 0 : 1,
    activity: flow.active ? 1 : 0.45,
    initiated: flow.remote_started ? 'remote' : 'local',
    threat: flow.severity <= 2 || (flow.lists || []).length > 0,
    ids_flow: flow,
  }));
  const known = new Set((data.locations || []).map((location) => location.id));
  const locations = (data.ids_flows || []).filter((flow) => !known.has(flow.dest)).map((flow) => ({
    id: flow.dest, name: flow.city || flow.country || flow.dest, city: flow.city, country: flow.country,
    country_code: flow.country_code, lat: flow.lat, lon: flow.lon, asn: flow.asn, as_org: flow.as_org,
  }));
  return {flows, locations};
}

function bytesText(bytes) {
  return formatRate(bytes || 0).replace('/s', '');
}

/** One-line description of a correlated connection for the hover card. */
export function idsFlowSummary(flow) {
  const inside = flow.inside_host?.name ? `${plain(flow.inside_host.name)} (${flow.inside})` : (flow.inside || 'this firewall');
  const who = flow.remote_started ? `${flow.remote} → ${inside}` : `${inside} → ${flow.remote}`;
  const state = flow.active ? `open for ${duration(flow.age) || 'moments'}` : 'closed';
  return `${who} ${flow.protocol.toUpperCase()} · ${state} · ↓ ${bytesText(flow.bytes_in)} ↑ ${bytesText(flow.bytes_out)}`;
}

function describeIdsFlow(flow, showAsn) {
  const serious = flow.severity <= 2;
  const signatures = flow.groups.flatMap((group) => group.signatures);
  const ids = {count: flow.count, severity: flow.severity, signatures, minutes: 60, last_seconds: flow.last_seconds};
  const org = showAsn && flow.asn ? `AS${flow.asn} ${plain(flow.as_org || '')}` : '';
  return `<div class="fmt">${ttHead(flow.city || flow.country || flow.dest, ttPlace(flow),
      serious ? ttPill('danger', 'Allowed · flagged', 'alert') : ttPill('ok', 'Allowed', 'check'))}
    ${ttLists(flow.lists)}
    ${ttAddress('server', flow.remote, org, [idsFlowSummary(flow)], serious, ids)}
    <div class="fmt-foot"><span>${escapeHtml(`Suricata alerted on this connection${flow.ips_dropped ? ' · dropped by IPS' : ''}`)}</span>
      ${flow.rule ? `<span>${escapeHtml(`rule: ${plain(flow.rule)}`)}</span>` : ''}</div></div>`;
}

/** Hover card for an address Suricata alerted on that has no arc right now. */
function describeAlert(alert, showAsn) {
  const org = showAsn && alert.asn ? `AS${alert.asn} ${plain(alert.as_org || '')}` : '';
  return `<div class="fmt">${ttHead(alert.city || alert.country || alert.source, ttPlace(alert), ttPill('muted', 'Seen by Suricata', 'flag'))}
    ${ttLists(alert.lists)}
    ${ttAddress('server', alert.source, org, [], false, alert.ids)}
    <div class="fmt-foot"><span>No connection is open right now</span></div></div>`;
}

/** Hover card for a blocked source. */
function describeBlock(block, showAsn) {
  const org = showAsn && block.asn ? `AS${block.asn} ${plain(block.as_org || '')}` : '';
  const bad = block.threat || (block.lists || []).length > 0;
  return `<div class="fmt">${ttHead(block.city || block.country || block.source, ttPlace(block), ttPill('blocked', 'Blocked', 'ban'))}
    ${ttLists(block.lists)}
    ${ttAddress('server', block.source, org, [blockSummary(block, showAsn)], bad, block.ids)}
    <div class="fmt-foot"><span>${escapeHtml(`${block.hits_per_minute} in the last minute${block.threat ? ' · hammering' : ''}`)}</span></div></div>`;
}

function pulsePosition(arc, seconds, reverse) {
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
function pulses(arcs) {
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

// Mercator world is 512px wide at zoom 0; this centre keeps inhabited land in view.
const WORLD_TILE = 512;
const VIEW_LATITUDE = 34;
const VIEW_LONGITUDE = 12;

const DEFAULT_THEME = {
  dark: true,
  background: [7, 17, 31],
  text: [169, 200, 217],
  accent: [45, 212, 191],
  success: [76, 175, 80],
};

function rgb(color, alpha = 255) {
  return [color[0], color[1], color[2], alpha];
}

function mix(a, b, amount) {
  return a.map((value, index) => Math.round(value + (b[index] - value) * amount));
}

const ORANGE = [240, 140, 0];

/** Map palette derived from the dashboard theme so the widget blends in. */
export function palette(theme = DEFAULT_THEME) {
  const {dark, background, text, accent, success} = {...DEFAULT_THEME, ...theme};
  const shade = (color, amount) => mix(color, dark ? [255, 255, 255] : text, amount);
  return {
    dark,
    land: rgb(mix(background, accent, dark ? 0.12 : 0.07)),
    border: rgb(mix(background, mix(accent, text, 0.5), dark ? 0.45 : 0.35)),
    // towards the firewall uses the theme accent, away from it the theme's success green
    toward: {link: mix(background, accent, 0.7), heavy: shade(accent, 0.2), pulse: shade(accent, 0.15)},
    away: {link: mix(background, success, 0.7), heavy: shade(success, 0.2), pulse: shade(success, 0.15)},
    // a clear orange for connections started outside: the theme accent can be close to the threat crimson
    inbound: {link: mix(background, ORANGE, 0.75), heavy: mix(ORANGE, dark ? [255, 255, 255] : [0, 0, 0], 0.08), pulse: ORANGE},
    neutral: {link: mix(background, [150, 150, 150], 0.7), heavy: [128, 128, 128], pulse: [120, 120, 120]},
    endpoint: rgb(mix(accent, text, 0.2), 220),
    // a crimson distinct from the theme accent, reserved for blocked traffic and threats
    block: dark ? [255, 77, 109] : [196, 18, 48],
    label: rgb(mix(text, background, 0.15), 230),
    tooltip: {
      background: `rgb(${background.join(',')})`,
      text: `rgb(${text.join(',')})`,
      border: `rgba(${accent.join(',')},0.35)`,
    },
    background: rgb(background),
  };
}

/**
 * Read the dashboard theme's own colours (OPNsense themes don't expose CSS variables): the
 * background behind the map, body text, the link colour (theme accent) and the success green.
 */
export function readTheme(element) {
  const parse = (value) => {
    const match = /rgba?\(([^)]+)\)/.exec(value || '');
    if (!match) {
      return null;
    }
    const [r, g, b, a = 1] = match[1].split(',').map((part) => parseFloat(part));
    return a === 0 ? null : [r, g, b];
  };
  let background = null;
  for (let node = element?.parentElement; node && !background; node = node.parentElement) {
    background = parse(getComputedStyle(node).backgroundColor);
  }
  background = background || [255, 255, 255];
  const text = parse(getComputedStyle(element).color) || [55, 55, 54];
  const probeColor = (probe) => {
    element.appendChild(probe);
    const color = parse(getComputedStyle(probe).color);
    probe.remove();
    return color;
  };
  const link = document.createElement('a');
  link.href = '#';
  const accent = probeColor(link) || [192, 62, 20];
  const success = document.createElement('span');
  success.className = 'text-success';
  const green = probeColor(success) || [76, 175, 80];
  const luminance = (0.2126 * background[0] + 0.7152 * background[1] + 0.0722 * background[2]) / 255;
  return {dark: luminance < 0.5, background, text, accent, success: green};
}

function fitZoom(width) {
  // a not-yet-laid-out container reports 0; fall back to a typical widget width
  return Math.log2((width > 100 ? width : 480) / WORLD_TILE);
}

export function createFirewallMap(container, options = {}) {
  let colors = palette(options.theme);
  let settings = {...DEFAULT_OPTIONS, ...(options.settings || {})};
  let locationIndex = new Map();
  let flowsByDest = new Map();
  let lastData = {locations: [], flows: []};
  const initialZoom = fitZoom(container.clientWidth);
  let viewState = {longitude: VIEW_LONGITUDE, latitude: VIEW_LATITUDE, zoom: initialZoom, minZoom: initialZoom, maxZoom: 6};

  const deck = new Deck({
    parent: container,
    views: new MapView({repeat: false}),
    viewState,
    onViewStateChange: ({viewState: next}) => {
      const labelsWereVisible = viewState.zoom >= viewState.minZoom + LABEL_ZOOM_STEP;
      viewState = {...next, minZoom: viewState.minZoom, maxZoom: viewState.maxZoom};
      deck.setProps({viewState});
      if (labelsWereVisible || viewState.zoom >= viewState.minZoom + LABEL_ZOOM_STEP) {
        // labels are placed in screen space, so re-place them as the map moves
        labelLayer = buildLabelLayer();
        deck.setProps({layers: compose()});
      }
    },
    controller: {scrollZoom: {smooth: true}, dragRotate: false, touchRotate: false},
    useDevicePixels: true,
    // arcs are 1.5px wide: pick within a few pixels so clicks and hovers land reliably
    pickingRadius: 6,
    // arrow pointer so endpoints and arches can be hovered; the hand only while dragging
    getCursor: ({isDragging, isHovering}) => isDragging ? 'grabbing' : (isHovering ? 'pointer' : 'default'),
    onHover: (info) => showTooltip(info),
    onClick: (info) => {
      if (options.onSelect && info.object && info.layer) {
        options.onSelect(selection(info.object, info.layer.id));
      }
    },
    layers: [],
  });
  // Exposed for in-browser diagnostics of the live widget.
  container.firewallMapDeck = deck;

  // Hover cards live on <body> (fixed position) so they are never clipped by the widget
  const tooltip = document.createElement('div');
  tooltip.style.cssText = 'position:fixed;z-index:2000;pointer-events:none;display:none;'
    + 'border-radius:6px;max-width:360px;box-shadow:0 4px 16px rgba(0,0,0,.14);';
  ensureTooltipStyle();
  document.body.appendChild(tooltip);

  /** What was clicked, in a form the page can act on (addresses, inside hosts, country). */
  function selection(object, layerId) {
    if (layerId === 'firewall-map-blocks' || layerId === 'firewall-map-block-sources') {
      return {kind: 'blocked', addresses: [object.source], country: object.country, countryCode: object.country_code,
        title: object.city || object.country, block: object};
    }
    if (layerId === 'firewall-map-alerts') {
      return {kind: 'alert', addresses: [object.source], country: object.country, countryCode: object.country_code,
        title: object.city || object.country, alert: object};
    }
    if ((layerId === 'firewall-map-arcs' || layerId === 'firewall-map-ids-markers') && (object.ids || object.arc?.ids)) {
      const flow = object.ids || object.arc.ids;
      return {kind: 'idsflow', addresses: [flow.dest], country: flow.country, countryCode: flow.country_code,
        title: flow.city || flow.country, idsFlow: flow, members: object.members || object.arc.members};
    }
    if (layerId === 'firewall-map-arcs') {
      return {kind: 'flow', addresses: object.members.map((member) => member.dest), country: object.dest.country,
        countryCode: object.dest.country_code, title: object.dest.city || object.dest.region || object.dest.country,
        members: object.members};
    }
    if (layerId === 'firewall-map-endpoints' && !object.local && !(flowsByDest.get(`${object.lat},${object.lon}`) || []).length) {
      // an endpoint that only exists because of Suricata: its own connection, or its alert history
      const flow = (lastData.ids_flows || []).find((item) => item.dest === object.id);
      if (flow) {
        return {kind: 'idsflow', addresses: [flow.dest], country: flow.country, countryCode: flow.country_code,
          title: flow.city || flow.country, idsFlow: flow, members: []};
      }
      const alert = (lastData.alerts || []).find((item) => item.source === object.id);
      return {kind: 'alert', addresses: [object.id], country: object.country, countryCode: object.country_code,
        title: object.city || object.country, alert: alert || {source: object.id, lists: []}};
    }
    if (layerId === 'firewall-map-endpoints' && !object.local) {
      const members = flowsByDest.get(`${object.lat},${object.lon}`) || [];
      return {kind: 'flow', addresses: members.map((member) => member.dest), country: object.country,
        countryCode: object.country_code, title: object.city || object.region || object.country, members};
    }
    return null;
  }

  function tooltipHtml(object, layer) {
    if (!object || !layer) {
      return null;
    }
    if (layer.id === 'firewall-map-endpoints' && object.local) {
      const own = (lastData.flows || []).filter((flow) => flow.origin === object.id);
      const rateIn = own.reduce((sum, flow) => sum + (flow.rate_in ?? 0), 0);
      const rateOut = own.reduce((sum, flow) => sum + (flow.rate_out ?? 0), 0);
      return `<div class="fmt">${ttHead('This firewall', escapeHtml(object.id), '')}
        <div class="fmt-foot"><span>${escapeHtml(`${own.length} active links`)}</span><span>${escapeHtml(`↓ ${formatRate(rateIn)}  ↑ ${formatRate(rateOut)}`)}</span></div></div>`;
    }
    if (layer.id === 'firewall-map-endpoints') {
      return describe(object, flowsByDest.get(`${object.lat},${object.lon}`) || [], locationIndex, lastData.hostnames, settings.asn);
    }
    if (layer.id === 'firewall-map-blocks' || layer.id === 'firewall-map-block-sources') {
      return describeBlock(object, settings.asn);
    }
    if (layer.id === 'firewall-map-alerts') {
      return describeAlert(object, settings.asn);
    }
    if ((layer.id === 'firewall-map-arcs' || layer.id === 'firewall-map-ids-markers') && (object.ids || object.arc?.ids)) {
      return describeIdsFlow(object.ids || object.arc.ids, settings.asn);
    }
    if (layer.id === 'firewall-map-arcs') {
      return describe(object.dest, object.members, locationIndex, lastData.hostnames, settings.asn);
    }
    return null;
  }

  function showTooltip({object, layer, x, y}) {
    const html = tooltipHtml(object, layer);
    if (!html) {
      tooltip.style.display = 'none';
      return;
    }
    tooltip.innerHTML = html;
    tooltip.style.background = colors.tooltip.background;
    tooltip.style.color = colors.tooltip.text;
    tooltip.style.border = `1px solid ${colors.tooltip.border}`;
    tooltip.style.display = 'block';
    // next to the pointer, flipped to the other side when it would leave the window
    const bounds = container.getBoundingClientRect();
    const width = tooltip.offsetWidth;
    const height = tooltip.offsetHeight;
    let left = bounds.left + x + 14;
    let top = bounds.top + y + 14;
    if (left + width > window.innerWidth - 4) {
      left = bounds.left + x - width - 14;
    }
    if (top + height > window.innerHeight - 4) {
      top = bounds.top + y - height - 14;
    }
    tooltip.style.left = `${Math.max(4, left)}px`;
    tooltip.style.top = `${Math.max(4, top)}px`;
  }

  const hideTooltip = () => {
    tooltip.style.display = 'none';
  };
  container.addEventListener('mouseleave', hideTooltip);

  let arcs = [];
  let baseLayers = [];
  let labelLayer = null;
  let labelCandidates = [];
  let frame = null;
  let lastFrame = 0;
  const started = performance.now();

  let pulseItems = [];
  let blockArcs = [];
  let locationsShown = [];
  const arcFader = new Fader((arc) => arc.key);
  const blockFader = new Fader((block) => block.source);
  const endpointFader = new Fader((location) => location.id);
  const alertFader = new Fader((alert) => alert.source);
  let idsHistory = new Set();
  let alertPoints = [];
  let frameNow = performance.now();
  let fadeKey = 'steady';
  // stable colour per category across refreshes (first seen keeps its colour)
  const categoryColors = new Map();
  let categoryKey = '';

  function categoryOf(arc) {
    return settings.colorMode === 'egress' ? arc.egress : arc.service;
  }

  function categorical() {
    return settings.colorMode === 'egress' || settings.colorMode === 'service';
  }

  function categoryColor(name) {
    if (!categoryColors.has(name)) {
      categoryColors.set(name, CATEGORY_COLORS[categoryColors.size % CATEGORY_COLORS.length]);
      categoryKey = [...categoryColors.keys()].join('|');
    }
    return categoryColors.get(name);
  }

  function arcColor(arc) {
    return faded(arcBaseColor(arc), arcFader.opacity(arc, frameNow));
  }

  function arcBaseColor(arc) {
    const alpha = Math.round((arc.heavy ? 150 : 70) + 105 * arc.activity);
    if (arc.threat) {
      // a permitted flow to a listed address
      return rgb(colors.block, Math.max(alpha, 170));
    }
    if (categorical()) {
      const base = baseColor(arc);
      return rgb(arc.heavy ? mix(base, colors.dark ? [255, 255, 255] : [0, 0, 0], 0.2) : mix(colors.background.slice(0, 3), base, 0.8), alpha);
    }
    const scheme = settings.colorMode === 'initiator' ? initiatorScheme(arc.initiated) : arc.toward ? colors.toward : colors.away;
    return rgb(arc.heavy ? scheme.heavy : scheme.link, alpha);
  }

  function pulseColor(item) {
    return faded(pulseBaseColor(item), arcFader.opacity(item.arc, frameNow));
  }

  function pulseBaseColor(item) {
    const alpha = Math.round(110 + 145 * item.arc.activity);
    if (item.arc.threat) {
      return rgb(colors.block, alpha);
    }
    if (categorical()) {
      return rgb(baseColor(item.arc), alpha);
    }
    // by who connected, pulses keep the arc's colour; their movement shows which way the data goes
    const scheme = settings.colorMode === 'initiator' ? initiatorScheme(item.arc.initiated) : item.toward ? colors.toward : colors.away;
    return rgb(scheme.pulse, alpha);
  }

  // green: started inside the network; orange (theme accent): started from outside
  function initiatorScheme(side) {
    return side === 'remote' ? colors.inbound : side === 'local' ? colors.away : colors.neutral;
  }

  function baseColor(arc) {
    return categoryColor(categoryOf(arc));
  }

  function legend() {
    if (settings.colorMode === 'initiator') {
      // always show inside and outside, so the meaning of green and orange is never a guess
      const present = new Set(['local', 'remote', ...arcs.filter((arc) => !arc.fading).map((arc) => arc.initiated)]);
      return [
        ...['local', 'remote', 'both'].filter((side) => present.has(side))
          .map((side) => ({label: INITIATOR_LABELS[side], color: initiatorScheme(side).heavy})),
        {label: 'Blocked / listed', color: colors.block},
      ];
    }
    if (!categorical()) {
      return [
        {label: 'Toward the firewall', color: colors.toward.heavy},
        {label: 'Away from the firewall', color: colors.away.heavy},
        {label: 'Blocked / listed', color: colors.block},
      ];
    }
    const present = [...new Set(arcs.filter((arc) => !arc.fading).map(categoryOf))];
    present.sort((a, b) => (a === 'Other' ? 1 : b === 'Other' ? -1 : a.localeCompare(b)));
    return [
      ...present.map((label) => ({label, color: categoryColor(label)})),
      {label: 'Blocked / listed', color: colors.block},
    ];
  }

  function pulseLayer(seconds) {
    return new ScatterplotLayer({
      id: 'firewall-map-pulses',
      data: pulseItems,
      getPosition: (item) => pulsePosition(item.arc, seconds, item.reverse),
      getRadius: (item) => item.arc.heavy ? 3.4 : 2.4,
      radiusUnits: 'pixels',
      getFillColor: (item) => pulseColor(item),
      updateTriggers: {getPosition: seconds, getFillColor: [colors.toward.pulse, colors.away.pulse, colors.inbound.pulse, settings.colorMode, categoryKey]},
    });
  }

  function blockPulseLayers(seconds) {
    const active = blockArcs.filter((block) => block.activity > 0);
    return [
      new ScatterplotLayer({
        id: 'firewall-map-block-pulses',
        data: active,
        getPosition: (block) => pulsePosition(block, seconds, false),
        getRadius: (block) => block.threat ? 3.6 : 2.6,
        radiusUnits: 'pixels',
        getFillColor: (block) => rgb(colors.block, Math.round((80 + 175 * block.activity) * blockFader.opacity(block, frameNow))),
        updateTriggers: {getPosition: seconds, getFillColor: colors.block},
      }),
      new ScatterplotLayer({
        id: 'firewall-map-threats',
        data: blockArcs.filter((block) => block.threat),
        getPosition: (block) => [block.lon, block.lat],
        // a throbbing halo around sources hammering the firewall
        getRadius: () => 6 + 6 * ((seconds / THREAT_THROB_PERIOD) % 1),
        radiusUnits: 'pixels',
        stroked: true,
        filled: false,
        lineWidthUnits: 'pixels',
        getLineWidth: 1.5,
        getLineColor: () => rgb(colors.block, Math.round(220 * (1 - (seconds / THREAT_THROB_PERIOD) % 1))),
        updateTriggers: {getRadius: seconds, getLineColor: [seconds, colors.block]},
      }),
    ];
  }

  function draw(now) {
    frame = null;
    if (!deck) {
      return;
    }
    if (now - lastFrame >= FRAME_INTERVAL) {
      lastFrame = now;
      deck.setProps({layers: compose(now)});
    }
    if (arcs.length || blockArcs.length || animating(now)) {
      frame = requestAnimationFrame(draw);
    }
  }

  // one label per place, busiest places first
  function labels(data) {
    const seen = new Map();
    for (const flow of data.flows || []) {
      const location = locationIndex.get(flow.dest);
      const text = location?.city || location?.region || location?.country;
      if (!text) {
        continue;
      }
      const key = `${location.lat},${location.lon}`;
      const current = seen.get(key);
      seen.set(key, {text, lat: location.lat, lon: location.lon, rate: (current?.rate || 0) + (flow.rate || 0)});
    }
    return [...seen.values()].sort((a, b) => b.rate - a.rate).slice(0, MAX_LABELS);
  }

  /**
   * Greedy screen-space placement: busiest places first, each label tries above, below,
   * right and left of its point and is dropped when every spot overlaps a placed label.
   */
  function placeLabels(candidates) {
    const width = container.clientWidth;
    const height = container.clientHeight;
    if (!width || !height) {
      return [];
    }
    const viewport = new WebMercatorViewport({...viewState, width, height});
    const placed = [];
    const boxes = [];
    for (const label of candidates) {
      const [px, py] = viewport.project([label.lon, label.lat]);
      const w = label.text.length * LABEL_CHAR_WIDTH + 2 * LABEL_PADDING;
      const h = LABEL_FONT_SIZE + 2 * LABEL_PADDING;
      const spots = [[0, -(h / 2 + 5)], [0, h / 2 + 5], [w / 2 + 6, 0], [-(w / 2 + 6), 0]];
      for (const [dx, dy] of spots) {
        const box = [px + dx - w / 2, py + dy - h / 2, px + dx + w / 2, py + dy + h / 2];
        const inside = box[0] >= 0 && box[1] >= 0 && box[2] <= width && box[3] <= height;
        const clear = boxes.every((other) => box[2] <= other[0] || box[0] >= other[2] || box[3] <= other[1] || box[1] >= other[3]);
        if (inside && clear) {
          boxes.push(box);
          placed.push({...label, offset: [dx, dy]});
          break;
        }
      }
    }
    return placed;
  }

  function buildLabelLayer() {
    const visible = settings.labels && viewState.zoom >= viewState.minZoom + LABEL_ZOOM_STEP;
    return new TextLayer({
      id: 'firewall-map-labels',
      data: visible ? placeLabels(labelCandidates) : [],
      visible,
      getPosition: (label) => [label.lon, label.lat],
      getText: (label) => plain(label.text),
      getSize: LABEL_FONT_SIZE,
      getColor: colors.label,
      getPixelOffset: (label) => label.offset,
      fontFamily: getComputedStyle(container).fontFamily || 'sans-serif',
      outlineWidth: 3,
      outlineColor: colors.background,
      fontSettings: {sdf: true},
      characterSet: 'auto',
      updateTriggers: {getColor: colors.label},
    });
  }

  function fadingLayers() {
    return [
      new PathLayer({
        id: 'firewall-map-arcs',
        data: arcs,
        getPath: (arc) => arc.path,
        getWidth: (arc) => arc.heavy ? HEAVY_WIDTH : LINK_WIDTH,
        widthUnits: 'pixels',
        capRounded: true,
        jointRounded: true,
        pickable: true,
        widthMinPixels: 1,
        getColor: (arc) => arcColor(arc),
        updateTriggers: {getColor: [colors.toward.link, colors.away.link, colors.inbound.link, settings.colorMode, categoryKey, fadeKey]},
      }),
      new PathLayer({
        id: 'firewall-map-blocks',
        data: blockArcs,
        getPath: (block) => block.path,
        getWidth: (block) => block.threat ? 2.4 : 1.4,
        widthUnits: 'pixels',
        capRounded: true,
        jointRounded: true,
        pickable: true,
        // bright while hits arrive, then a faint trace that can still be hovered
        getColor: (block) => rgb(colors.block, Math.round((35 + 185 * block.activity) * blockFader.opacity(block, frameNow))),
        updateTriggers: {getColor: [colors.block, fadeKey]},
      }),
      new ScatterplotLayer({
        id: 'firewall-map-block-sources',
        data: blockArcs,
        getPosition: (block) => [block.lon, block.lat],
        getRadius: (block) => block.threat ? 3.5 : 2.5,
        radiusUnits: 'pixels',
        pickable: true,
        getFillColor: (block) => rgb(colors.block, Math.round((90 + 165 * block.activity) * blockFader.opacity(block, frameNow))),
        updateTriggers: {getFillColor: [colors.block, fadeKey]},
      }),
      new ScatterplotLayer({
        id: 'firewall-map-ids-rings',
        data: locationsShown.filter((location) => idsHistory.has(location.id)),
        getPosition: (location) => [location.lon, location.lat],
        getRadius: 6,
        radiusUnits: 'pixels',
        stroked: true,
        filled: false,
        lineWidthUnits: 'pixels',
        getLineWidth: 1.5,
        getLineColor: (location) => faded([230, 140, 0, 230], endpointFader.opacity(location, frameNow)),
        pickable: false,
        updateTriggers: {getLineColor: fadeKey},
      }),
      new ScatterplotLayer({
        // detection marker at the middle of an IDS connection's own arc
        id: 'firewall-map-ids-markers',
        data: arcs.filter((arc) => arc.ids).map((arc) => ({arc, position: arc.path[Math.floor(arc.path.length / 2)]})),
        getPosition: (item) => item.position,
        getRadius: 5,
        radiusUnits: 'pixels',
        stroked: true,
        filled: true,
        getFillColor: (item) => faded(rgb(colors.background.slice(0, 3), 240), arcFader.opacity(item.arc, frameNow)),
        getLineColor: (item) => faded(item.arc.ids.severity <= 2 ? rgb(colors.block) : [230, 140, 0, 255], arcFader.opacity(item.arc, frameNow)),
        lineWidthUnits: 'pixels',
        getLineWidth: 2.5,
        pickable: true,
        updateTriggers: {getFillColor: [colors.background, fadeKey], getLineColor: [colors.block, fadeKey]},
      }),
      new TextLayer({
        id: 'firewall-map-ids-marks',
        data: arcs.filter((arc) => arc.ids).map((arc) => ({arc, position: arc.path[Math.floor(arc.path.length / 2)]})),
        getPosition: (item) => item.position,
        getText: () => '!',
        getSize: 10,
        getColor: (item) => faded(item.arc.ids.severity <= 2 ? rgb(colors.block) : [230, 140, 0, 255], arcFader.opacity(item.arc, frameNow)),
        fontWeight: 700,
        characterSet: ['!'],
        pickable: false,
        updateTriggers: {getColor: [colors.block, fadeKey]},
      }),
      new ScatterplotLayer({
        // addresses Suricata alerted on with no arc right now: a hollow marker in the alert colour
        id: 'firewall-map-alerts',
        data: alertPoints,
        getPosition: (alert) => [alert.lon, alert.lat],
        getRadius: 4.5,
        radiusUnits: 'pixels',
        stroked: true,
        filled: true,
        getFillColor: (alert) => faded(rgb(colors.background.slice(0, 3), 220), alertFader.opacity(alert, frameNow)),
        getLineColor: (alert) => faded(alert.ids?.severity <= 2 ? rgb(colors.block) : [230, 140, 0, 255], alertFader.opacity(alert, frameNow)),
        lineWidthUnits: 'pixels',
        getLineWidth: 2,
        pickable: true,
        updateTriggers: {getFillColor: [colors.background, fadeKey], getLineColor: [colors.block, fadeKey]},
      }),
      new ScatterplotLayer({
        id: 'firewall-map-endpoints',
        data: locationsShown,
        getPosition: (location) => [location.lon, location.lat],
        getRadius: (location) => location.local ? 5 : 2.5,
        radiusUnits: 'pixels',
        stroked: true,
        filled: true,
        getFillColor: (location) => faded(location.local ? colors.background : colors.endpoint, endpointFader.opacity(location, frameNow)),
        getLineColor: (location) => faded(colors.endpoint, endpointFader.opacity(location, frameNow)),
        lineWidthUnits: 'pixels',
        getLineWidth: (location) => location.local ? 2 : 0,
        pickable: true,
        radiusMinPixels: 2.5,
        updateTriggers: {getFillColor: [colors.endpoint, fadeKey], getLineColor: [colors.endpoint, fadeKey]},
      }),
    ];
  }

  function animating(now) {
    return arcFader.animating(now) || blockFader.animating(now) || endpointFader.animating(now) || alertFader.animating(now);
  }

  function compose(now = performance.now()) {
    const seconds = (now - started) / 1000;
    frameNow = now;
    // colours are recomputed every frame only while something is fading
    fadeKey = animating(now) ? now : 'steady';
    return [...baseLayers, ...fadingLayers(), pulseLayer(seconds), ...blockPulseLayers(seconds), labelLayer].filter(Boolean);
  }

  function layers(data) {
    const now = performance.now();
    const previousLanes = new Map([...arcFader.entries.values()].map((entry) => [entry.item.key, entry.item.lane]));
    const ids = idsArcData(data);
    const arcData = {...data, flows: [...(data.flows || []), ...ids.flows], locations: [...(data.locations || []), ...ids.locations]};
    arcs = arcFader.update(buildArcs(arcData, {...settings, previousLanes}), now);
    // endpoints with recent Suricata history get a ring (history, not proof about the current traffic)
    idsHistory = new Set([
      ...(data.flows || []).filter((flow) => flow.ids).map((flow) => flow.dest),
      ...(data.ids_flows || []).map((flow) => flow.dest),
    ]);
    pulseItems = pulses(arcs);
    blockArcs = blockFader.update(settings.blocks ? buildBlocks(data) : [], now);
    locationsShown = endpointFader.update(arcData.locations, now);
    alertPoints = alertFader.update(data.alerts || [], now);
    locationIndex = new Map((data.locations || []).map((location) => [location.id, location]));
    flowsByDest = new Map();
    for (const flow of data.flows || []) {
      const dest = locationIndex.get(flow.dest);
      if (dest) {
        const key = `${dest.lat},${dest.lon}`;
        flowsByDest.set(key, [...(flowsByDest.get(key) || []), flow]);
      }
    }
    baseLayers = [
      new GeoJsonLayer({
        id: 'firewall-map-world',
        data: world,
        filled: true,
        stroked: true,
        getFillColor: colors.land,
        getLineColor: colors.border,
        lineWidthMinPixels: 0.6,
        pickable: false,
        updateTriggers: {getFillColor: colors.land, getLineColor: colors.border},
      }),
    ];
    labelCandidates = labels(data);
    labelLayer = buildLabelLayer();
    const layerList = compose();
    if ((arcs.length || blockArcs.length || animating(performance.now())) && frame === null) {
      frame = requestAnimationFrame(draw);
    }
    return layerList;
  }

  return {
    render(data) {
      lastData = data;
      deck.setProps({layers: layers(data)});
    },
    legend,
    setSettings(next) {
      settings = {...DEFAULT_OPTIONS, ...next};
      deck.setProps({layers: layers(lastData)});
    },
    setTheme(theme) {
      colors = palette(theme);
      deck.setProps({layers: layers(lastData)});
    },
    /** Zoom by `steps` (positive in, negative out) around the centre; `fit` shows the whole world. */
    zoom(steps) {
      const zoom = Math.max(viewState.minZoom, Math.min(viewState.maxZoom, viewState.zoom + steps));
      viewState = {...viewState, zoom, transitionDuration: 250};
      deck.setProps({viewState});
      labelLayer = buildLabelLayer();
      deck.setProps({layers: compose()});
    },
    fit() {
      viewState = {...viewState, longitude: VIEW_LONGITUDE, latitude: VIEW_LATITUDE, zoom: viewState.minZoom, transitionDuration: 300};
      deck.setProps({viewState});
      labelLayer = buildLabelLayer();
      deck.setProps({layers: compose()});
    },
    resize() {
      // keep the whole world fitted to the widget width as it is resized
      const zoom = fitZoom(container.clientWidth);
      const fitted = viewState.zoom <= viewState.minZoom + 0.01;
      viewState = {...viewState, minZoom: zoom, zoom: fitted ? zoom : Math.max(zoom, viewState.zoom)};
      deck.setProps({viewState});
      labelLayer = buildLabelLayer();
      deck.setProps({layers: compose()});
      deck.redraw(true);
    },
    destroy() {
      if (frame !== null) {
        cancelAnimationFrame(frame);
        frame = null;
      }
      container.removeEventListener('mouseleave', hideTooltip);
      tooltip.remove();
      deck.finalize();
    },
  };
}

// The IIFE build assigns this module namespace to the global FirewallMapRenderer.
export {createFirewallMap as create};
