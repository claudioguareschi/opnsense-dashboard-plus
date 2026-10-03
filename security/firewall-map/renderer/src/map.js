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

/* The deck.gl map: layers for arcs, blocked sources, IDS markers and labels, fades and pulses. */
import {Deck, MapView, WebMercatorViewport} from '@deck.gl/core';
import {GeoJsonLayer, IconLayer, PathLayer, ScatterplotLayer, TextLayer} from '@deck.gl/layers';
import {IDS_ARC_FADE_SECONDS, buildArcs, continuePhases, buildBlocks, clearOfHomes, HOME_CLEARANCE, idsArcData, marchingPulses, mercatorY, pulsePosition, pulses, unitsPerPixel} from './arcs.js';
import {createFollow} from './follow.js';
import {plain} from './format.js';
import {DEFAULT_OPTIONS} from './options.js';
import {CATEGORY_COLORS, mix, palette, rgb} from './palette.js';
import {alertOutcome, idsOutcome, outcome} from './summaries.js';
import {textTable} from './text.js';
import {cards, createTooltip} from './tooltips.js';
import worldData from './world.json';

// Antarctica only adds empty space below the flows.
const world = {...worldData, features: worldData.features.filter((feature) => feature.id !== 'ATA')};

const LINK_WIDTH = 1.5;
const HEAVY_WIDTH = 3;
// threats throb at their source
const THREAT_THROB_PERIOD = 0.9;
// city labels appear once the map is zoomed this far past the fitted world view
const LABEL_ZOOM_STEP = 1.2;
const MAX_LABELS = 40;
// places considered for a label, busiest first (most are off screen when zoomed in)
const MAX_LABEL_CANDIDATES = 600;
const LABEL_FONT_SIZE = 11;
// approximate glyph width for placing labels before they are drawn
const LABEL_CHAR_WIDTH = 6.2;
const LABEL_PADDING = 3;
const FRAME_INTERVAL = 1000 / 30;

// arches, blocked sources and endpoints fade in and out instead of popping
const FADE_IN_MS = 800;

/** A color with its alpha scaled by a fade opacity. */
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

// the firewall's own location: an outline house, tinted by the layer (mask), so it is not
// mistaken for the hollow rings that mark flagged addresses. Drawn on a canvas because the
// OPNsense content policy does not let deck.gl fetch a data: URL.
let homeAtlas = null;
function homeIconAtlas() {
  if (!homeAtlas) {
    const canvas = document.createElement('canvas');
    canvas.width = canvas.height = 48;
    const context = canvas.getContext('2d');
    context.scale(2, 2);
    context.strokeStyle = '#000';
    context.lineWidth = 2.2;
    context.lineCap = context.lineJoin = 'round';
    context.stroke(new Path2D('M3 10.5 12 3l9 7.5M5.5 8.5V21h13V8.5M10 21v-6h4v6'));
    homeAtlas = canvas;
  }
  return homeAtlas;
}
const HOME_LAYER = 'firewall-map-home';
const HOME_ICON_MAPPING = {home: {x: 0, y: 0, width: 48, height: 48, anchorY: 24, mask: true}};

// Mercator world is 512px wide at zoom 0. The whole-world view is centered on longitude 0, so the
// world fills the map edge to edge instead of leaving a strip on one side; this latitude keeps
// inhabited land in view.
const WORLD_TILE = 512;
const VIEW_LATITUDE = 34;

function fitZoom(width) {
  // a not-yet-laid-out container reports 0; fall back to a typical widget width
  return Math.log2((width > 100 ? width : 480) / WORLD_TILE);
}

/**
 * options: {theme, settings, text, onSelect(selection), onFollowChange(on), followResumeMs}.
 * `text` is the caller's translation table (see text.js); `settings` as parseSettings() returns.
 */
export function createFirewallMap(container, options = {}) {
  let colors = palette(options.theme);
  let settings = {...DEFAULT_OPTIONS, ...(options.settings || {})};
  const text = textTable(options.text);
  const card = cards(text);
  let locationIndex = new Map();
  let flowsByDest = new Map();
  let lastData = {locations: [], flows: []};
  const initialZoom = fitZoom(container.clientWidth);
  let viewState = {longitude: 0, latitude: VIEW_LATITUDE, zoom: initialZoom, minZoom: initialZoom, maxZoom: 6};
  const follow = createFollow({
    container,
    getView: () => viewState,
    setView: (next) => {
      viewState = next;
      deck.setProps({viewState});
    },
    // labels are placed for the final view only
    landed: () => relabel(),
    arcs: () => arcs,
  }, {...options, follow: settings.follow});

  // deck.gl's own frame statistics (GPU memory, frame cost), kept for diagnostics() once a second
  let deckMetrics = {};
  const deck = new Deck({
    parent: container,
    _onMetrics: (metrics) => {
      deckMetrics = {...metrics};
    },
    views: new MapView({repeat: false}),
    viewState,
    onViewStateChange: ({viewState: next, interactionState}) => {
      if (interactionState && (interactionState.isDragging || interactionState.isPanning || interactionState.isZooming)) {
        follow.userMoved();
      }
      const labelsWereVisible = viewState.zoom >= viewState.minZoom + LABEL_ZOOM_STEP;
      viewState = {...next, minZoom: viewState.minZoom, maxZoom: viewState.maxZoom};
      deck.setProps({viewState});
      if (!follow.flying && (labelsWereVisible || viewState.zoom >= viewState.minZoom + LABEL_ZOOM_STEP)) {
        // labels are placed in screen space, so re-place them as the map moves
        relabel();
      }
    },
    controller: {scrollZoom: {smooth: true}, dragRotate: false, touchRotate: false},
    useDevicePixels: true,
    // arcs are 1.5px wide: pick within a few pixels so clicks and hovers land reliably, but not so
    // far that an empty-looking spot answers
    pickingRadius: 5,
    // arrow pointer so endpoints and arches can be hovered; the hand only while dragging
    getCursor: ({isDragging, isHovering}) => isDragging ? 'grabbing' : (isHovering ? 'pointer' : 'default'),
    onHover: (info) => {
      // follow traffic holds still only while something is under the pointer, not whenever
      // the mouse happens to rest on the map
      follow.setHovering(Boolean(info.object));
      tooltip.show(tooltipHtml(info.object, info.layer), info.x, info.y, colors);
    },
    onClick: (info) => {
      if (options.onSelect && info.object && info.layer) {
        options.onSelect(selection(info.object, info.layer.id));
      }
    },
    layers: [],
  });
  // Exposed for in-browser diagnostics of the live widget.
  container.firewallMapDeck = deck;
  // The browser can take the GPU away (memory pressure, sleep, a driver reset). The map cannot
  // repaint without it, so the host is told and builds a new renderer; preventDefault lets the
  // browser hand the context back. The events do not bubble: listen while they travel down.
  let contextLosses = 0;
  const onContextLost = (event) => {
    event.preventDefault();
    contextLosses += 1;
    options.onContextLost?.();
  };
  container.addEventListener('webglcontextlost', onContextLost, true);
  container.firewallMapFollow = () => follow.diagnostics();
  const tooltip = createTooltip(container);

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
    if ((layer.id === 'firewall-map-endpoints' || layer.id === HOME_LAYER) && object.local) {
      return card.firewall(object, (lastData.flows || []).filter((flow) => flow.origin === object.id));
    }
    if (layer.id === 'firewall-map-endpoints') {
      return card.flows(object, flowsByDest.get(`${object.lat},${object.lon}`) || [], locationIndex, lastData.hostnames, settings.asn);
    }
    if (layer.id === 'firewall-map-blocks' || layer.id === 'firewall-map-block-sources') {
      return card.block(object, settings.asn);
    }
    if (layer.id === 'firewall-map-alerts') {
      return card.alert(object, settings.asn);
    }
    if ((layer.id === 'firewall-map-arcs' || layer.id === 'firewall-map-ids-markers') && (object.ids || object.arc?.ids)) {
      return card.idsFlow(object.ids || object.arc.ids, settings.asn);
    }
    if (layer.id === 'firewall-map-arcs') {
      return card.flows(object.dest, object.members, locationIndex, lastData.hostnames, settings.asn);
    }
    return null;
  }

  function relabel() {
    labelLayer = buildLabelLayer();
    deck.setProps({layers: compose()});
  }

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
  let idsHistory = new Map();
  let alertPoints = [];
  let frameNow = performance.now();
  let dataTime = performance.now();
  // a saved snapshot on screen: time stands still, so closed IDS connections do not fade
  let frozen = false;
  let fadeKey = 'steady';
  // the zoom (to 1/20 of a step) the arch ends were last cleared of the house icon for
  let clearKey = null;
  let cleared = {};
  let arcsDrawn = [];
  let blocksDrawn = [];
  let endpointsDrawn = [];
  let homesDrawn = [];
  // stable color per category across refreshes (first seen keeps its color)
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
    return faded(arcBaseColor(arc), arcOpacity(arc));
  }

  /** How far a closed IDS connection's arc has faded, counting on from the last refresh. */
  function idsLinger(arc) {
    if (!arc.ids || arc.ids.active) {
      return 1;
    }
    const closed = (arc.ids.closed_seconds ?? arc.ids.last_seconds ?? 0) + (frozen ? 0 : (frameNow - dataTime) / 1000);
    return Math.max(0, 1 - closed / IDS_ARC_FADE_SECONDS);
  }

  function arcOpacity(arc) {
    return arcFader.opacity(arc, frameNow) * idsLinger(arc);
  }

  function arcBaseColor(arc) {
    // an idle connection is still a state on the firewall (and may be the one a snapshot was taken
    // for): it stays plainly visible wherever it can be hovered, busier ones only get stronger
    const alpha = Math.round((arc.heavy ? 170 : 140) + (arc.heavy ? 85 : 115) * arc.activity);
    if (arc.threat) {
      // flagged traffic the firewall let through
      return rgb(colors.danger, Math.max(alpha, 170));
    }
    if (arc.contained) {
      return rgb(colors.contained, Math.max(alpha, 170));
    }
    if (categorical()) {
      const base = baseColor(arc);
      return rgb(arc.heavy ? mix(base, colors.dark ? [255, 255, 255] : [0, 0, 0], 0.2) : mix(colors.background.slice(0, 3), base, 0.8), alpha);
    }
    const scheme = settings.colorMode === 'initiator' ? initiatorScheme(arc.initiated) : arc.toward ? colors.toward : colors.away;
    return rgb(arc.heavy ? scheme.heavy : scheme.link, alpha);
  }

  function pulseColor(item) {
    return faded(pulseBaseColor(item), arcOpacity(item.arc));
  }

  function pulseBaseColor(item) {
    const alpha = Math.round(110 + 145 * item.arc.activity);
    if (item.arc.threat) {
      return rgb(colors.danger, alpha);
    }
    if (item.arc.contained) {
      return rgb(colors.contained, alpha);
    }
    if (categorical()) {
      return rgb(baseColor(item.arc), alpha);
    }
    // by who connected, pulses keep the arc's color; their movement shows which way the data goes
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
          .map((side) => ({label: text[`map_started_${side === 'local' ? 'inside' : side === 'remote' ? 'outside' : 'both'}`], color: initiatorScheme(side).heavy})),
        ...outcomeLegend(),
      ];
    }
    if (!categorical()) {
      return [
        {label: text.map_toward, color: colors.toward.heavy},
        {label: text.map_away, color: colors.away.heavy},
        ...outcomeLegend(),
      ];
    }
    const present = [...new Set(arcs.filter((arc) => !arc.fading).map(categoryOf))];
    present.sort((a, b) => (a === 'Other' ? 1 : b === 'Other' ? -1 : a.localeCompare(b)));
    return [
      ...present.map((label) => ({label, color: categoryColor(label)})),
      ...outcomeLegend(),
    ];
  }

  function outcomeLegend() {
    return [
      {label: text.map_blocked, color: colors.blocked},
      {label: text.map_flagged_blocked, color: colors.contained},
      {label: text.map_flagged_allowed, color: colors.danger},
    ];
  }

  function blockColor(block) {
    return (block.lists || []).length ? colors.contained : colors.blocked;
  }

  function outcomeColor(kind) {
    return {danger: colors.danger, contained: colors.contained, blocked: colors.blocked, ok: colors.blocked}[kind];
  }

  function pulseLayer(seconds) {
    return new ScatterplotLayer({
      id: 'firewall-map-pulses',
      data: pulseItems.filter((item) => drawn(item.arc)),
      getPosition: (item) => pulsePosition(item.arc, seconds, item.reverse, item.period, item.phase),
      getRadius: (item) => item.march ? (item.arc.heavy ? 2.6 : 1.9) : item.arc.heavy ? 3.4 : 2.4,
      radiusUnits: 'pixels',
      getFillColor: (item) => pulseColor(item),
      updateTriggers: {getPosition: seconds, getFillColor: [colors.toward.pulse, colors.away.pulse, colors.inbound.pulse, settings.colorMode, categoryKey]},
    });
  }

  function blockPulseLayers(seconds) {
    const active = blockArcs.filter((block) => block.activity > 0 && drawn(block));
    return [
      new ScatterplotLayer({
        id: 'firewall-map-block-pulses',
        data: active,
        getPosition: (block) => pulsePosition(block, seconds, false),
        getRadius: (block) => block.threat ? 3.6 : 2.6,
        radiusUnits: 'pixels',
        getFillColor: (block) => rgb(blockColor(block), Math.round((80 + 175 * block.activity) * blockFader.opacity(block, frameNow))),
        updateTriggers: {getPosition: seconds, getFillColor: [colors.blocked, colors.contained]},
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
        getLineColor: (block) => rgb(blockColor(block), Math.round(220 * (1 - (seconds / THREAT_THROB_PERIOD) % 1))),
        updateTriggers: {getRadius: seconds, getLineColor: [seconds, colors.blocked, colors.contained]},
      }),
    ];
  }

  let framesComposed = 0;
  let composeMs = 0;
  function draw(now) {
    frame = null;
    if (now - lastFrame >= FRAME_INTERVAL) {
      lastFrame = now;
      const start = performance.now();
      deck.setProps({layers: compose(now)});
      framesComposed += 1;
      composeMs += performance.now() - start;
    }
    if (arcs.length || blockArcs.length || animating(now)) {
      frame = requestAnimationFrame(draw);
    }
  }

  // one label per place, busiest places first
  // one label per place: busiest allowed traffic first, then blocked sources and alerts by hits
  function labels(data) {
    const seen = new Map();
    const add = (place, rank, weight) => {
      const text = place?.city || place?.region || place?.country;
      if (!text || !Number.isFinite(place.lat) || !Number.isFinite(place.lon)) {
        return;
      }
      const key = `${place.lat},${place.lon}`;
      const current = seen.get(key);
      if (!current || rank < current.rank) {
        seen.set(key, {text, lat: place.lat, lon: place.lon, rank, weight});
      } else if (rank === current.rank) {
        current.weight += weight;
      }
    };
    for (const flow of data.flows || []) {
      add(locationIndex.get(flow.dest), 0, flow.rate || 0);
    }
    if (settings.blocks) {
      (data.blocks || []).forEach((block) => add(block, 1, block.hits || 0));
    }
    (data.alerts || []).forEach((alert) => add(alert, 1, alert.count || 1));
    return [...seen.values()].sort((a, b) => a.rank - b.rank || b.weight - a.weight).slice(0, MAX_LABEL_CANDIDATES);
  }

  /**
   * Greedy screen-space placement: busiest places first, each label tries above, below,
   * right and left of its point and is dropped when every spot overlaps a placed label or a
   * house. Only places on screen count towards MAX_LABELS, and places hidden inside a house's
   * circle get none.
   */
  function placeLabels(candidates) {
    const width = container.clientWidth;
    const height = container.clientHeight;
    if (!width || !height) {
      return [];
    }
    const viewport = new WebMercatorViewport({...viewState, width, height});
    const placed = [];
    // labels keep out of the clear circle around each house
    const homePixels = homesDrawn.map((home) => viewport.project([home.lon, home.lat]));
    const boxes = homePixels.map(([x, y]) => [x - HOME_CLEARANCE, y - HOME_CLEARANCE, x + HOME_CLEARANCE, y + HOME_CLEARANCE]);
    for (const label of candidates) {
      if (placed.length >= MAX_LABELS) {
        break;
      }
      const [px, py] = viewport.project([label.lon, label.lat]);
      if (px < 0 || py < 0 || px > width || py > height ||
          homePixels.some(([x, y]) => Math.hypot(px - x, py - y) < HOME_CLEARANCE)) {
        continue;
      }
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
        data: arcsDrawn,
        getPath: (arc) => arc.shown || arc.path,
        getWidth: (arc) => arc.heavy ? HEAVY_WIDTH : LINK_WIDTH,
        widthUnits: 'pixels',
        capRounded: true,
        jointRounded: true,
        pickable: true,
        widthMinPixels: 1,
        getColor: (arc) => arcColor(arc),
        updateTriggers: {getColor: [colors.toward.link, colors.away.link, colors.inbound.link, settings.colorMode, categoryKey, fadeKey], getPath: clearKey},
      }),
      new PathLayer({
        id: 'firewall-map-blocks',
        data: blocksDrawn,
        getPath: (block) => block.shown || block.path,
        getWidth: (block) => block.threat ? 2.4 : 1.4,
        widthUnits: 'pixels',
        capRounded: true,
        jointRounded: true,
        pickable: true,
        // bright while hits arrive, then a faint trace that can still be hovered
        getColor: (block) => rgb(blockColor(block), Math.round((35 + 185 * block.activity) * blockFader.opacity(block, frameNow))),
        updateTriggers: {getColor: [colors.blocked, colors.contained, fadeKey], getPath: clearKey},
      }),
      new ScatterplotLayer({
        id: 'firewall-map-block-sources',
        data: blockArcs,
        getPosition: (block) => [block.lon, block.lat],
        getRadius: (block) => block.threat ? 3.5 : 2.5,
        radiusUnits: 'pixels',
        pickable: true,
        getFillColor: (block) => rgb(blockColor(block), Math.round((90 + 165 * block.activity) * blockFader.opacity(block, frameNow))),
        updateTriggers: {getFillColor: [colors.blocked, colors.contained, fadeKey]},
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
        getLineColor: (location) => faded(rgb(outcomeColor(idsHistory.get(location.id)), 230), endpointFader.opacity(location, frameNow)),
        pickable: false,
        updateTriggers: {getLineColor: [colors.danger, colors.contained, fadeKey]},
      }),
      new ScatterplotLayer({
        // detection marker at the middle of an IDS connection's own arc
        id: 'firewall-map-ids-markers',
        data: arcs.filter((arc) => arc.ids && drawn(arc)).map((arc) => ({arc, position: arc.path[Math.floor(arc.path.length / 2)]})),
        getPosition: (item) => item.position,
        getRadius: 5,
        radiusUnits: 'pixels',
        stroked: true,
        filled: true,
        getFillColor: (item) => faded(rgb(colors.background.slice(0, 3), 240), arcOpacity(item.arc)),
        getLineColor: (item) => faded(rgb(outcomeColor(idsOutcome(item.arc.ids))), arcOpacity(item.arc)),
        lineWidthUnits: 'pixels',
        getLineWidth: 2.5,
        pickable: true,
        updateTriggers: {getFillColor: [colors.background, fadeKey], getLineColor: [colors.danger, colors.contained, fadeKey]},
      }),
      new TextLayer({
        id: 'firewall-map-ids-marks',
        data: arcs.filter((arc) => arc.ids && drawn(arc)).map((arc) => ({arc, position: arc.path[Math.floor(arc.path.length / 2)]})),
        getPosition: (item) => item.position,
        getText: () => '!',
        getSize: 10,
        getColor: (item) => faded(rgb(outcomeColor(idsOutcome(item.arc.ids))), arcOpacity(item.arc)),
        fontWeight: 700,
        characterSet: ['!'],
        pickable: false,
        updateTriggers: {getColor: [colors.danger, colors.contained, fadeKey]},
      }),
      new ScatterplotLayer({
        // addresses Suricata alerted on with no arc right now: a hollow marker in the alert color
        id: 'firewall-map-alerts',
        data: alertPoints,
        getPosition: (alert) => [alert.lon, alert.lat],
        getRadius: 4.5,
        radiusUnits: 'pixels',
        stroked: true,
        filled: true,
        getFillColor: (alert) => faded(rgb(colors.background.slice(0, 3), 220), alertFader.opacity(alert, frameNow)),
        getLineColor: (alert) => faded(rgb(outcomeColor(alertOutcome(alert))), alertFader.opacity(alert, frameNow)),
        lineWidthUnits: 'pixels',
        getLineWidth: 2,
        pickable: true,
        updateTriggers: {getFillColor: [colors.background, fadeKey], getLineColor: [colors.contained, fadeKey]},
      }),
      new ScatterplotLayer({
        id: 'firewall-map-endpoints',
        data: endpointsDrawn,
        getPosition: (location) => [location.lon, location.lat],
        getRadius: 2.5,
        radiusUnits: 'pixels',
        stroked: false,
        filled: true,
        getFillColor: (location) => faded(colors.endpoint, endpointFader.opacity(location, frameNow)),
        pickable: true,
        radiusMinPixels: 2.5,
        updateTriggers: {getFillColor: [colors.endpoint, fadeKey]},
      }),
    ];
  }

  // the firewall's own location, drawn above the arches and pulses, which keep out of a clear
  // circle around it (see clearHome); the whole icon square is pickable for the firewall card
  function homeLayers() {
    return [
      new IconLayer({
        id: HOME_LAYER,
        data: homesDrawn,
        getPosition: (location) => [location.lon, location.lat],
        iconAtlas: homeIconAtlas(),
        iconMapping: HOME_ICON_MAPPING,
        getIcon: () => 'home',
        getSize: 15,
        sizeUnits: 'pixels',
        alphaCutoff: 0,
        getColor: (location) => faded(colors.endpoint, endpointFader.opacity(location, frameNow)),
        pickable: true,
        updateTriggers: {getColor: [colors.endpoint, fadeKey]},
      }),
    ];
  }

  // arches and pulses stop short of the house icon by a fixed number of pixels, and endpoints
  // inside that circle are not drawn, so the cleared part follows the zoom; new items are
  // cleared on their first frame
  function clearHome() {
    const key = Math.round(viewState.zoom * 20);
    if (key === clearKey && cleared.arcs === arcs && cleared.blocks === blockArcs && cleared.locations === locationsShown) {
      return;
    }
    const radius = HOME_CLEARANCE * unitsPerPixel(key / 20);
    clearKey = key;
    cleared = {arcs, blocks: blockArcs, locations: locationsShown};
    // a firewall can have several home locations (one per WAN address); ones closer together
    // than the circle share one house
    const locals = locationsShown.filter((location) => location.local);
    const homes = locals.map((home) => [home.lon, mercatorY(home.lat)]);
    const within = ([x, y], points) => points.some(([homeX, homeY]) => Math.hypot(x - homeX, y - homeY) < radius);
    const drawnPoints = [];
    homesDrawn = [];
    locals.forEach((home, index) => {
      if (!within(homes[index], drawnPoints)) {
        drawnPoints.push(homes[index]);
        homesDrawn.push(home);
      }
    });
    for (const item of [...arcs, ...blockArcs]) {
      item.shown = clearOfHomes(item.path, homes, radius);
    }
    const nearHome = (location) => within([location.lon, mercatorY(location.lat)], homes);
    // new arrays only when something changed, so deck.gl keeps its geometry between frames
    arcsDrawn = arcs.filter(drawn);
    blocksDrawn = blockArcs.filter(drawn);
    endpointsDrawn = locationsShown.filter((location) => !location.local && !nearHome(location));
  }

  function drawn(item) {
    return item.shown !== null;
  }

  function animating(now) {
    return arcFader.animating(now) || blockFader.animating(now) || endpointFader.animating(now) || alertFader.animating(now) ||
      arcs.some((arc) => arc.ids && !arc.ids.active);
  }

  function compose(now = performance.now()) {
    const seconds = (now - started) / 1000;
    frameNow = now;
    // colors are recomputed every frame only while something is fading
    fadeKey = animating(now) ? now : 'steady';
    clearHome();
    return [...baseLayers, ...fadingLayers(), pulseLayer(seconds), ...blockPulseLayers(seconds), ...homeLayers(), labelLayer].filter(Boolean);
  }

  function layers(data) {
    const now = performance.now();
    const previousLanes = new Map([...arcFader.entries.values()].map((entry) => [entry.item.key, entry.item.lane]));
    dataTime = now;
    const ids = idsArcData(data);
    const arcData = {...data, flows: [...(data.flows || []), ...ids.flows], locations: [...(data.locations || []), ...ids.locations]};
    // pulses carry on from where they are, at the arc's new speed (see continuePhases)
    const previousArcs = new Map(arcs.map((arc) => [arc.key, arc]));
    arcs = arcFader.update(continuePhases(previousArcs, buildArcs(arcData, {...settings, previousLanes}), (now - started) / 1000), now);
    // endpoints with recent Suricata history get a ring (history, not proof about the current traffic)
    // colored by the worst outcome there: red if flagged traffic got through, amber if it was stopped
    const rank = {blocked: 0, ok: 0, contained: 1, danger: 2};
    idsHistory = new Map();
    const note = (dest, kind) => {
      if (!idsHistory.has(dest) || rank[kind] > rank[idsHistory.get(dest)]) {
        idsHistory.set(dest, kind);
      }
    };
    (data.flows || []).filter((flow) => flow.ids).forEach((flow) => note(flow.dest, outcome({flagged: flow.ids.severity <= 2, stopped: false})));
    (data.ids_flows || []).forEach((flow) => note(flow.dest, idsOutcome(flow)));
    pulseItems = frozen ? marchingPulses(arcs) : pulses(arcs);
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
    clearHome();  // labels are placed around the houses of this data
    labelLayer = buildLabelLayer();
    const layerList = compose();
    if ((arcs.length || blockArcs.length || animating(performance.now())) && frame === null) {
      frame = requestAnimationFrame(draw);
    }
    return layerList;
  }

  function settle() {
    // the end of a button zoom (deck transition): drop the transition props
    const {transitionDuration, transitionInterpolator, transitionEasing, onTransitionEnd, onTransitionInterrupt, ...rest} = viewState;
    viewState = rest;
    relabel();
  }

  function moveTo(changes, milliseconds) {
    follow.userMoved();
    viewState = {...viewState, ...changes, transitionDuration: milliseconds, transitionInterpolator: undefined,
      onTransitionEnd: settle, onTransitionInterrupt: settle};
    deck.setProps({viewState});
    relabel();
  }

  return {
    render(data) {
      lastData = data;
      deck.setProps({layers: layers(data)});
      follow.update();
    },
    /** Keep the view on the traffic; turning it on flies there at once. */
    setFollow(on) {
      follow.set(on);
      follow.update(true);
    },
    /** A saved snapshot (true) or live traffic: a snapshot's arcs carry evenly spaced marching dots, nothing ages. */
    setFrozen(on) {
      frozen = Boolean(on);
      pulseItems = frozen ? marchingPulses(arcs) : pulses(arcs);
    },
    /** Re-frame now (after a filter change) rather than waiting for the traffic to settle. */
    refit() {
      follow.update(true);
    },
    legend,
    setSettings(next) {
      settings = {...DEFAULT_OPTIONS, ...next};
      const wasFollowing = next && 'follow' in next ? follow.set(next.follow) : follow.follow;
      deck.setProps({layers: layers(lastData)});
      follow.update(follow.follow && !wasFollowing);
    },
    setTheme(theme) {
      colors = palette(theme);
      deck.setProps({layers: layers(lastData)});
    },
    /** Zoom by `steps` (positive in, negative out) around the center. */
    zoom(steps) {
      moveTo({zoom: Math.max(viewState.minZoom, Math.min(viewState.maxZoom, viewState.zoom + steps))}, 250);
    },
    /** The whole world, edge to edge. */
    fit() {
      moveTo({longitude: 0, latitude: VIEW_LATITUDE, zoom: viewState.minZoom}, 300);
    },
    resize() {
      // keep the whole world fitted to the map's width as it is resized
      const zoom = fitZoom(container.clientWidth);
      const fitted = viewState.zoom <= viewState.minZoom + 0.01;
      viewState = {...viewState, minZoom: zoom, zoom: fitted ? zoom : Math.max(zoom, viewState.zoom),
        ...(fitted ? {longitude: 0} : {})};
      deck.setProps({viewState});
      relabel();
      deck.redraw(true);
      follow.resized();
    },
    /** For the page's ?debug=1 panel: frame rate, frame cost, GPU memory and what is on the map. */
    diagnostics() {
      const metrics = deckMetrics;
      const result = {fps: metrics.fps, cpuPerFrame: metrics.cpuTimePerFrame, gpuPerFrame: metrics.gpuTimePerFrame,
        gpuMemory: metrics.gpuMemory, framesComposed, composeMs, animating: frame !== null,
        arcs: arcs.length, blocks: blockArcs.length, pulses: pulseItems.length, contextLosses};
      framesComposed = 0;
      composeMs = 0;
      return result;
    },
    destroy() {
      container.removeEventListener('webglcontextlost', onContextLost, true);
      if (frame !== null) {
        cancelAnimationFrame(frame);
        frame = null;
      }
      follow.destroy();
      tooltip.destroy();
      deck.finalize();
    },
  };
}
