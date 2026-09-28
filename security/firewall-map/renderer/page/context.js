/*
 * Shared by the map page's modules: the translated strings (from the page template as
 * window.FirewallMapPageText) and the page state.
 */
import {textTable} from '../src/text.js';

export const T = window.FirewallMapPageText || {};
// the renderer's sentences (flow summaries, IDS lines) in the page's language
export const TEXT = textTable(T);

export const POLL_MS = 2000;
export const WATCHLIST = 'FWMAP_Watchlist';
// list names the collector reports (fwmap_blocklists)
export const ABUSEIPDB_BLACKLIST_LIST = 'AbuseIPDB blacklist';
export const ABUSEIPDB_LOOKUP_LIST = 'AbuseIPDB (looked up)';
// investigations are kept for this many addresses, the oldest dropped first
export const MAX_INVESTIGATIONS = 50;
export const MAX_ABUSE_SCORES = 500;

export const state = {
  renderer: null,
  snapshot: null,
  settings: null,
  // the plugin settings (null for users who may not read them)
  pluginSettings: null,
  filters: {traffic: 'all', service: '', iface: '', host: '', country: '', asn: ''},
  colorMode: 'initiator',
  talkerTab: 'hosts',
  talkerRows: [],
  history: new Map(),
  isAdmin: false,
  selection: null,
  detailsAddress: null,
  renderedSelection: null,
  renderedAddress: null,
  investigations: new Map(),
  abuseScores: new Map(),
  abuseChecking: new Set(),
  abuseConfigured: false,
  queueExpanded: new Set(),
  follow: false,
  layout: {},
  updatedAt: null,
};

/** The page's own filters, as the reset button leaves them. */
export function resetFilters() {
  state.filters = {traffic: 'all', service: '', iface: '', host: '', country: '', asn: ''};
}
