/* Firewall Map+ renderer. Bundled locally from deck.gl. */
import {Deck, MapView} from '@deck.gl/core';
import {GeoJsonLayer, PathLayer, ScatterplotLayer} from '@deck.gl/layers';
import worldData from './world.json';

// Antarctica only adds empty space below the flows.
const world = {...worldData, features: worldData.features.filter((feature) => feature.id !== 'ATA')};

const ARC_SAMPLES = 32;
const LINK_WIDTH = 1.5;
const HEAVY_WIDTH = 3;
// heavy talkers: the busiest few links, or anything above this byte rate
const HEAVY_TOP = 5;
const HEAVY_TOP_MIN_RATE = 10000;
const HEAVY_RATE = 1000000;
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
export function buildArcs(data) {
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
    } else {
      merged.set(key, {
        flow: {origin: item.origin, dest: item.dest, rate, rateIn, rateOut, activity: item.activity ?? 1},
        origin,
        dest,
      });
    }
  }
  const flows = [...merged.values()].sort((a, b) => b.flow.rate - a.flow.rate);
  const lanes = new Map();
  const arcs = [];
  flows.forEach(({flow, origin, dest}, index) => {
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
      heavy: (index < HEAVY_TOP && rate >= HEAVY_TOP_MIN_RATE) || rate >= HEAVY_RATE,
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
    background: rgb(background),
  };
}

function fitZoom(width) {
  // a not-yet-laid-out container reports 0; fall back to a typical widget width
  return Math.log2((width > 100 ? width : 480) / WORLD_TILE);
}

export function createFirewallMap(container, options = {}) {
  let colors = palette(options.theme);
  let lastData = {locations: [], flows: []};
  const initialZoom = fitZoom(container.clientWidth);
  let viewState = {longitude: VIEW_LONGITUDE, latitude: VIEW_LATITUDE, zoom: initialZoom, minZoom: initialZoom, maxZoom: 6};

  const deck = new Deck({
    parent: container,
    views: new MapView({repeat: false}),
    viewState,
    onViewStateChange: ({viewState: next}) => {
      viewState = {...next, minZoom: viewState.minZoom, maxZoom: viewState.maxZoom};
      deck.setProps({viewState});
    },
    controller: {scrollZoom: {smooth: true}, dragRotate: false, touchRotate: false},
    useDevicePixels: true,
    getCursor: ({isDragging}) => isDragging ? 'grabbing' : 'grab',
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

  function layers(data) {
    arcs = buildArcs(data);
    pulseItems = pulses(arcs);
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
        updateTriggers: {getFillColor: colors.endpoint, getLineColor: colors.endpoint},
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
