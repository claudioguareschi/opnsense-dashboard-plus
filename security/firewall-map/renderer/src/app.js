/* Firewall Map+ renderer. Bundled locally from deck.gl. */
import {Deck, MapView} from '@deck.gl/core';
import {GeoJsonLayer, PathLayer, ScatterplotLayer, TextLayer} from '@deck.gl/layers';
import worldData from './world.json';

// Antarctica only adds empty space below the flows.
const world = {...worldData, features: worldData.features.filter((feature) => feature.id !== 'ATA')};

const ARC_SAMPLES = 32;
const LINK_WIDTH = 1.5;
const HEAVY_WIDTH = 3;
// heavy talkers: the busiest few links (if above a floor), or anything above a byte rate
const DEFAULT_OPTIONS = {heavyTop: 5, heavyRate: 1000000, maxArcs: 120, labels: true};
const HEAVY_TOP_MIN_RATE = 10000;
// city labels appear once the map is zoomed this far past the fitted world view
const LABEL_ZOOM_STEP = 1.2;
const MAX_LABELS = 40;
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
    const key = `${item.origin}>${dest.lat},${dest.lon}`;
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
        flow: {origin: item.origin, dest: item.dest, rate, rateIn, rateOut, activity: item.activity ?? 1},
        origin,
        dest,
        members: [item],
      });
    }
  }
  const flows = [...merged.values()].sort((a, b) => b.flow.rate - a.flow.rate).slice(0, options.maxArcs);
  const lanes = new Map();
  const arcs = [];
  flows.forEach(({flow, origin, dest, members}, index) => {
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
    const cell = `${flow.origin}|${Math.round(dest.lat * 2)}|${Math.round(dest.lon * 2)}`;
    const lane = lanes.get(cell) || 0;
    lanes.set(cell, lane + 1);
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
      key: `${flow.origin}>${flow.dest}`,
      path,
      heavy: (index < options.heavyTop && rate >= HEAVY_TOP_MIN_RATE) || rate >= options.heavyRate,
      rate,
      rateIn,
      rateOut,
      dest,
      members,
      // colour follows the dominant direction; pulses show both when traffic flows both ways
      toward: inShare >= 0.5,
      direction,
      activity,
      period: 6 - 5.2 * strength,
      phase: hash(`${flow.origin}>${flow.dest}`),
    });
  });
  return arcs;
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

function escapeHtml(text) {
  return String(text ?? '').replace(/[&<>"']/g, (char) => `&#${char.charCodeAt(0)};`);
}

/** Hover card for an endpoint (all flows to that place) or a single arch. */
function describe(place, members, locations) {
  const rateIn = members.reduce((sum, flow) => sum + (flow.rate_in ?? 0), 0);
  const rateOut = members.reduce((sum, flow) => sum + (flow.rate_out ?? 0), 0);
  const services = [...new Set(members.flatMap((flow) => flow.services || []))].slice(0, 5);
  const addresses = members
    .slice()
    .sort((a, b) => (b.rate ?? 0) - (a.rate ?? 0))
    .slice(0, 6)
    .map((flow) => {
      const location = locations.get(flow.dest);
      const asn = location?.asn ? ` · AS${location.asn} ${escapeHtml(location.as_org || '')}` : '';
      return `<div>${escapeHtml(flow.dest)}${asn}</div>`;
    });
  const more = members.length > 6 ? `<div>+${members.length - 6} more</div>` : '';
  const title = [place.city || place.region, place.country].filter(Boolean).join(', ') || place.name || place.id;
  // GeoLite places region- or country-level matches at a representative point; say how rough it is
  const approximate = !place.city && place.accuracy_km ? ` <span style="opacity:.7">(± ${place.accuracy_km} km)</span>` : '';
  return `
    <div style="font-weight:600;margin-bottom:2px">${escapeHtml(title)}${approximate}</div>
    ${addresses.join('')}${more}
    <div style="margin-top:4px">↓ ${formatRate(rateIn)} &nbsp; ↑ ${formatRate(rateOut)}</div>
    ${services.length ? `<div>${services.map(escapeHtml).join(', ')}</div>` : ''}
  `;
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
    endpoint: rgb(mix(accent, text, 0.2), 220),
    label: rgb(mix(text, background, 0.15), 230),
    tooltip: {
      background: `rgb(${background.join(',')})`,
      text: `rgb(${text.join(',')})`,
      border: `rgba(${accent.join(',')},0.35)`,
    },
    background: rgb(background),
  };
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
      if (labelsWereVisible !== viewState.zoom >= viewState.minZoom + LABEL_ZOOM_STEP) {
        deck.setProps({layers: layers(lastData)});
      }
    },
    controller: {scrollZoom: {smooth: true}, dragRotate: false, touchRotate: false},
    useDevicePixels: true,
    // arrow pointer so endpoints and arches can be hovered; the hand only while dragging
    getCursor: ({isDragging, isHovering}) => isDragging ? 'grabbing' : (isHovering ? 'pointer' : 'default'),
    getTooltip: ({object, layer}) => {
      if (!object || !layer) {
        return null;
      }
      let html = null;
      if (layer.id === 'firewall-map-endpoints' && object.local) {
        const own = (lastData.flows || []).filter((flow) => flow.origin === object.id);
        const rateIn = own.reduce((sum, flow) => sum + (flow.rate_in ?? 0), 0);
        const rateOut = own.reduce((sum, flow) => sum + (flow.rate_out ?? 0), 0);
        html = `<div style="font-weight:600;margin-bottom:2px">${escapeHtml(object.id)}</div>
          <div>${own.length} active links</div>
          <div style="margin-top:4px">↓ ${formatRate(rateIn)} &nbsp; ↑ ${formatRate(rateOut)}</div>`;
      } else if (layer.id === 'firewall-map-endpoints') {
        html = describe(object, flowsByDest.get(`${object.lat},${object.lon}`) || [], locationIndex);
      } else if (layer.id === 'firewall-map-arcs') {
        html = describe(object.dest, object.members, locationIndex);
      }
      return html && {
        html,
        style: {
          background: colors.tooltip.background,
          color: colors.tooltip.text,
          border: `1px solid ${colors.tooltip.border}`,
          borderRadius: '4px',
          padding: '6px 8px',
          fontSize: '12px',
          lineHeight: '1.35',
          boxShadow: '0 2px 8px rgba(0,0,0,.15)',
          maxWidth: '320px',
        },
      };
    },
    layers: [],
  });
  // Exposed for in-browser diagnostics of the live widget.
  container.firewallMapDeck = deck;

  let arcs = [];
  let baseLayers = [];
  let frame = null;
  let lastFrame = 0;
  const started = performance.now();

  let pulseItems = [];

  function pulseLayer(seconds) {
    return new ScatterplotLayer({
      id: 'firewall-map-pulses',
      data: pulseItems,
      getPosition: (item) => pulsePosition(item.arc, seconds, item.reverse),
      getRadius: (item) => item.arc.heavy ? 3.4 : 2.4,
      radiusUnits: 'pixels',
      getFillColor: (item) => rgb((item.toward ? colors.toward : colors.away).pulse, Math.round(110 + 145 * item.arc.activity)),
      updateTriggers: {getPosition: seconds, getFillColor: [colors.toward.pulse, colors.away.pulse]},
    });
  }

  function draw(now) {
    frame = null;
    if (!deck) {
      return;
    }
    if (now - lastFrame >= FRAME_INTERVAL) {
      lastFrame = now;
      deck.setProps({layers: [...baseLayers, pulseLayer((now - started) / 1000)]});
    }
    if (arcs.length) {
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

  function layers(data) {
    arcs = buildArcs(data, settings);
    pulseItems = pulses(arcs);
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
        getColor: (arc) => {
          const scheme = arc.toward ? colors.toward : colors.away;
          return rgb(arc.heavy ? scheme.heavy : scheme.link, Math.round((arc.heavy ? 150 : 70) + 105 * arc.activity));
        },
        updateTriggers: {getColor: [colors.toward.link, colors.away.link]},
      }),
      new ScatterplotLayer({
        id: 'firewall-map-endpoints',
        data: data.locations || [],
        getPosition: (location) => [location.lon, location.lat],
        getRadius: (location) => location.local ? 5 : 2.5,
        radiusUnits: 'pixels',
        stroked: true,
        filled: true,
        getFillColor: (location) => location.local ? colors.background : colors.endpoint,
        getLineColor: colors.endpoint,
        lineWidthUnits: 'pixels',
        getLineWidth: (location) => location.local ? 2 : 0,
        pickable: true,
        radiusMinPixels: 2.5,
        updateTriggers: {getFillColor: colors.endpoint, getLineColor: colors.endpoint},
      }),
      new TextLayer({
        id: 'firewall-map-labels',
        data: labels(data),
        visible: settings.labels && viewState.zoom >= viewState.minZoom + LABEL_ZOOM_STEP,
        getPosition: (label) => [label.lon, label.lat],
        getText: (label) => label.text,
        getSize: 11,
        getColor: colors.label,
        getPixelOffset: [0, -9],
        fontFamily: getComputedStyle(container).fontFamily || 'sans-serif',
        outlineWidth: 3,
        outlineColor: colors.background,
        fontSettings: {sdf: true},
        characterSet: 'auto',
        updateTriggers: {getColor: colors.label},
      }),
    ];
    const layerList = [...baseLayers, pulseLayer((performance.now() - started) / 1000)];
    if (arcs.length && frame === null) {
      frame = requestAnimationFrame(draw);
    }
    return layerList;
  }

  return {
    render(data) {
      lastData = data;
      deck.setProps({layers: layers(data)});
    },
    setSettings(next) {
      settings = {...DEFAULT_OPTIONS, ...next};
      deck.setProps({layers: layers(lastData)});
    },
    setTheme(theme) {
      colors = palette(theme);
      deck.setProps({layers: layers(lastData)});
    },
    resize() {
      // keep the whole world fitted to the widget width as it is resized
      const zoom = fitZoom(container.clientWidth);
      const fitted = viewState.zoom <= viewState.minZoom + 0.01;
      viewState = {...viewState, minZoom: zoom, zoom: fitted ? zoom : Math.max(zoom, viewState.zoom)};
      deck.setProps({viewState});
      deck.redraw(true);
    },
    destroy() {
      if (frame !== null) {
        cancelAnimationFrame(frame);
        frame = null;
      }
      deck.finalize();
    },
  };
}

// The IIFE build assigns this module namespace to the global FirewallMapRenderer.
export {createFirewallMap as create};
