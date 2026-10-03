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
