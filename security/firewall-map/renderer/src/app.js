/* Firewall Map+ renderer. Bundled locally from Flowmap.gl and deck.gl. */
import {Deck, MapView} from '@deck.gl/core';
import {GeoJsonLayer, ScatterplotLayer} from '@deck.gl/layers';
import {FlowmapLayer} from '@flowmap.gl/layers';
import worldData from './world.json';

// Antarctica only adds empty space below the flows.
const world = {...worldData, features: worldData.features.filter((feature) => feature.id !== 'ATA')};

const ACCESSORS = {
  getLocationId: (location) => location.id,
  getLocationLat: (location) => location.lat,
  getLocationLon: (location) => location.lon,
  getLocationName: (location) => location.name,
  getFlowOriginId: (flow) => flow.origin,
  getFlowDestId: (flow) => flow.dest,
  // Byte rates span several orders of magnitude (one stream vs. many keep-alives); a log
  // scale keeps small flows visible, and idle flows shrink as the collector fades them out.
  getFlowMagnitude: (flow) => Math.max(0.05, Math.log10(1 + (flow.rate ?? flow.count)) * (flow.activity ?? 1)),
};

// Mercator world is 512px wide at zoom 0; this centre keeps inhabited land in view.
const WORLD_TILE = 512;
const VIEW_LATITUDE = 34;
const VIEW_LONGITUDE = 12;

const DEFAULT_THEME = {
  dark: true,
  background: [7, 17, 31],
  text: [169, 200, 217],
  accent: [45, 212, 191],
};

function rgb(color, alpha = 255) {
  return [color[0], color[1], color[2], alpha];
}

function mix(a, b, amount) {
  return a.map((value, index) => Math.round(value + (b[index] - value) * amount));
}

function hex(color) {
  return `#${color.map((value) => value.toString(16).padStart(2, '0')).join('')}`;
}

/** Map palette derived from the dashboard theme so the widget blends in. */
export function palette(theme = DEFAULT_THEME) {
  const {dark, background, text, accent} = {...DEFAULT_THEME, ...theme};
  return {
    dark,
    land: rgb(mix(background, accent, dark ? 0.12 : 0.07)),
    border: rgb(mix(background, mix(accent, text, 0.5), dark ? 0.45 : 0.35)),
    flows: [0.35, 0.6, 0.8, 1].map((amount) => hex(mix(background, accent, amount))),
    endpoint: rgb(accent, 220),
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

  // Wheel zoom only with Ctrl/Cmd so scrolling the dashboard is never captured by the map.
  const onWheel = (event) => {
    if (!event.ctrlKey && !event.metaKey) {
      event.stopPropagation();
    }
  };
  container.addEventListener('wheel', onWheel, {capture: true});

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

  function layers(data) {
    return [
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
      new FlowmapLayer({
        id: 'firewall-map-flows',
        data: {locations: data.locations || [], flows: data.flows || []},
        ...ACCESSORS,
        darkMode: colors.dark,
        colorScheme: colors.flows,
        flowLinesRenderingMode: 'animated-straight',
        fadeEnabled: true,
        fadeOpacityEnabled: true,
        fadeAmount: 35,
        locationsEnabled: false,
        locationTotalsEnabled: false,
        locationLabelsEnabled: false,
        adaptiveScalesEnabled: true,
        clusteringEnabled: false,
        flowLineThicknessScale: 1,
        maxTopFlowsDisplayNum: options.maxFlows || 120,
        pickable: true,
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
      container.removeEventListener('wheel', onWheel, {capture: true});
      deck.finalize();
    },
  };
}

// The IIFE build assigns this module namespace to the global FirewallMapRenderer.
export {createFirewallMap as create};
