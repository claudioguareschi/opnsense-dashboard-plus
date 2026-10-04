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
 * Full-size Firewall Map+ page: filters, color modes with legend, top talkers and investigation
 * actions around the shared renderer (firewall-map-renderer.js, the global FirewallMapRenderer).
 * Built with vite.page.config.js into src/opnsense/www/js/firewall-map-page.js.
 */
import {escapeHtml} from '../src/format.js';
import {parseSettings, summaryQuery} from '../src/options.js';
import {addCountry, addToAlias, killStates, markThreat, showStates} from './actions.js';
import {getJSON} from './api.js';
import {POLL_MS, resetFilters, state, T} from './context.js';
import {renderDetails} from './details.js';
import {filtered} from './filters.js';
import {checkAbuse, investigate} from './investigate.js';
import {bindSplitters, readFollow, setFollow, watchSideWidth} from './layout.js';
import {refreshQueueCount, showQueue} from './queue.js';
import {backToLive, bindSnapshots, renderSnapshotList, showSavedStates, takenText} from './snapshots.js';
import {renderTalkers, talkerActive, talkers, talkersFromLast} from './talkers.js';
import {bindChips, syncChips, updateLegend, updateToolbar} from './toolbar.js';

const host = () => window.FirewallMapRenderer.host;

/** Suricata counts in the status line, each a one-click filter; connections and address history apart. */
function idsLinks(summary) {
  const idsFlows = (summary.ids_flows || []).filter((flow) => flow.kind !== 'blocked').length;
  const idsAddresses = new Set([...(summary.alerts || []).map((alert) => alert.source),
    ...(summary.flows || []).filter((flow) => flow.ids).map((flow) => flow.dest),
    ...(summary.blocks || []).filter((block) => block.ids).map((block) => block.source)]).size;
  const link = (filter, text) => `<a href="#" class="fwmap-status-ids${state.filters.traffic === filter ? ' active' : ''}" `
    + `data-filter="${filter}" aria-pressed="${state.filters.traffic === filter}">${escapeHtml(text)}</a>`;
  const links = [];
  if (idsFlows) {
    links.push(link('ids_flows', `${idsFlows} ${idsFlows === 1 ? T.ids_flow : T.ids_flows}`));
  }
  if (idsAddresses) {
    links.push(link('ids_addresses', `${idsAddresses} ${idsAddresses === 1 ? T.ids_address : T.ids_addresses}`));
  }
  return links;
}

function statusLine(summary, shown) {
  const parts = host().statusParts(summary, shown, state.settings, T);
  // the Suricata links sit before the CARP note, which stays last
  const carp = summary.carp === 'backup' ? parts.pop() : null;
  $('#fwmap-status').html([...parts, ...idsLinks(summary), carp].filter(Boolean).join(' · '));
  if (state.mode === 'live') {
    state.updatedAt = Date.now();
  }
  updatedLine();
}

function updatedLine() {
  if (state.mode === 'snapshot' && state.frozen) {
    $('#fwmap-updated').html(`${escapeHtml(T.captured)} ${escapeHtml(takenText(state.frozen.meta))} <i class="fwmap-live frozen"></i>`);
    return;
  }
  if (!state.updatedAt) {
    return;
  }
  const seconds = Math.max(0, Math.round((Date.now() - state.updatedAt) / 1000));
  $('#fwmap-updated').html(`${escapeHtml(T.last_updated)} ${escapeHtml(seconds)} s ${escapeHtml(T.ago)} `
    + `<i class="fwmap-live${seconds > 10 ? ' stale' : ''}"></i>`);
}

function refresh() {
  const summary = state.data;
  if (!summary || summary.status !== 'ok') {
    return;
  }
  const shown = filtered(summary);
  state.renderer.render(shown);
  updateToolbar(summary);
  updateLegend();
  statusLine(summary, shown);
  $('#fwmap-credit').html(host().creditHtml(summary.provider));
}

/**
 * The geolocation card over an empty map (downloading, failed, key missing), or the small note when
 * only network names are missing; re-rendered only when it changes, so Retry stays pressed.
 */
function showGeo(summary) {
  const html = summary ? host().geoCardHtml(summary, T, {admin: state.isAdmin}) || host().geoNoteHtml(summary, T, state.geoNoteDismissed) : '';
  const $slot = $('#fwmap-geo');
  if ($slot.data('html') !== html) {
    $slot.html(html).data('html', html);
    host().tickCountdowns();
  }
}

/** One request at a time, never stacked on a slow firewall; nothing while the page is hidden. */
function poll(query) {
  let timer = null;
  // a request is on its way: showing the page again then must not start a second loop
  let running = false;
  const tick = async () => {
    timer = null;
    if (document.hidden) {
      return;
    }
    running = true;
    try {
      const summary = await getJSON(`/api/firewallmap/flow/summary${query}`);
      const problem = host().problemText(summary, T);
      showGeo(state.mode === 'live' ? summary : null);
      if (problem && state.mode === 'live') {
        // no database or no sample: an empty map, not the last picture
        if (summary.status === 'no_database' || summary.status === 'too_many_states') {
          state.renderer.render({flows: [], locations: []});
        }
        // the geolocation card says it on the map itself
        $('#fwmap-status').text(summary.status === 'no_database' ? '' : problem);
      } else {
        state.live = summary;
        // the sparklines keep their history in snapshot mode too
        const groups = talkers(summary);
        if (state.mode === 'live') {
          state.data = summary;
          renderTabs(groups);
          refresh();
        }
      }
    } catch (error) {
      console.error('Firewall Map+: flow update failed', error);
      if (state.mode === 'live') {
        $('#fwmap-status').text(T.unavailable);
      }
    } finally {
      running = false;
    }
    if (!document.hidden) {
      timer = setTimeout(tick, POLL_MS);
    }
  };
  // shown again: poll at once instead of waiting out an interval
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && timer === null && !running) {
      tick();
      refreshQueueCount();
    }
  });
  tick();
}

/** The side panel's current tab: top talkers from `groups`, or the saved snapshots. */
function renderTabs(groups) {
  const snapshots = state.talkerTab === 'snapshots';
  // snapshots and IDS alerts have a fixed order (newest first; connections, then severity)
  $('#fwmap-talker-sort').closest('.bootstrap-select').toggle(!snapshots && state.talkerTab !== 'ids');
  if (snapshots) {
    renderSnapshotList();
  } else if (groups) {
    renderTalkers(groups);
  }
}

/** Switch the side panel to `tab` (as a click on it would). */
function setTab(tab) {
  state.talkerTab = tab;
  $('#fwmap-talkers .nav li').removeClass('active').find('a').attr('aria-selected', 'false');
  $(`#fwmap-talkers .nav a[data-tab="${tab}"]`).attr('aria-selected', 'true').parent().addClass('active');
  renderTabs(state.data ? talkersFromLast() : null);
}

function selectTalker(row) {
  if (row?.select) {
    // IDS tab: open the details of that address or connection
    state.selection = row.select;
    state.detailsAddress = row.key;
    renderDetails();
  } else if (row?.filter) {
    // a second click on the active row removes its filter
    const active = talkerActive(row);
    for (const [key, value] of Object.entries(row.filter)) {
      state.filters[key] = active ? '' : value;
    }
    refresh();
  }
}

function bindFilters() {
  const bind = (selector, key) => $(selector).on('change', function () {
    state.filters[key] = $(this).val();
    refresh();
    // a new filter is a new question: frame its answer straight away when following
    state.renderer.refit();
  });
  bind('#fwmap-filter-traffic', 'traffic');
  bind('#fwmap-filter-service', 'service');
  bind('#fwmap-filter-iface', 'iface');
  bind('#fwmap-filter-host', 'host');
  bind('#fwmap-filter-country', 'country');
  bindChips();
  $('#fwmap-filter-asn a').on('click', (event) => {
    event.preventDefault();
    state.filters.asn = '';
    refresh();
    syncChips();
  });
  $('#fwmap-color').on('change', function () {
    state.colorMode = $(this).val();
    state.renderer.setSettings({...state.settings, colorMode: state.colorMode, follow: state.follow});
    refresh();
  });
  $('#fwmap-reset').on('click', () => {
    resetFilters();
    $('#fwmap-filter-traffic').val('all');
    refresh();
    syncChips();
  });
  // the IDS counters in the status line filter the map; a second click shows everything again
  $('#fwmap-status').on('click', '.fwmap-status-ids', function (event) {
    event.preventDefault();
    const filter = String($(this).data('filter'));
    $('#fwmap-filter-traffic').val(state.filters.traffic === filter ? 'all' : filter).trigger('change');
  });
}

function bindTalkers() {
  const rowOf = (element) => (state.talkerRows || [])[$(element).closest('.fwmap-talker').data('index')];
  // delegated: the rows are redrawn every poll, a click must survive that
  $('#fwmap-talkers-list')
    .on('mousedown', '.fwmap-talker:not(.fwmap-snap-row)', function (event) {
      event.preventDefault();
      selectTalker(rowOf(this));
    })
    .on('keydown', '.fwmap-talker:not(.fwmap-snap-row)', function (event) {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        const index = $(this).data('index');
        selectTalker(rowOf(this));
        // the list is redrawn: keep the keyboard on the same row
        $(`#fwmap-talkers-list .fwmap-talker[data-index="${index}"]`).trigger('focus');
      }
    });
  $('#fwmap-talker-search, #fwmap-talker-sort').on('input change', () => {
    renderTabs(state.data ? talkersFromLast() : null);
  });
  $('#fwmap-talkers .nav a').on('click', function (event) {
    event.preventDefault();
    setTab($(this).data('tab'));
  });
}

function bindDetails() {
  const on = (selector, handler) => $('#fwmap-details').on('click', selector, function (event) {
    event.preventDefault();
    handler($(this));
  });
  const address = ($element) => String($element.data('address'));
  on('#fwmap-details-close', () => {
    state.selection = null;
    renderDetails();
  });
  on('.fwmap-copy', ($element) => navigator.clipboard?.writeText(address($element)));
  // in snapshot mode "States" are the ones saved with it; "Current states" asks the firewall now
  on('.fwmap-states', ($element) => (state.mode === 'snapshot' ? showSavedStates(address($element)) : showStates(address($element))));
  on('.fwmap-states-now', ($element) => showStates(address($element)));
  on('.fwmap-kill', ($element) => killStates(address($element)));
  on('.fwmap-alias', ($element) => addToAlias(address($element)));
  on('.fwmap-mark', ($element) => markThreat(address($element)));
  on('.fwmap-country', ($element) => addCountry(String($element.data('code'))));
  on('.fwmap-abuse-check', ($element) => checkAbuse(address($element), renderDetails));
  on('.fwmap-investigate', ($element) => investigate(address($element), renderDetails));
  on('.fwmap-pick', ($element) => {
    state.detailsAddress = address($element);
    renderDetails();
  });
}

function bindControls() {
  bindFilters();
  bindTalkers();
  bindDetails();
  $('#fwmap-review').on('click', () => showQueue());
  setInterval(updatedLine, 1000);
  $('#fwmap-zoom').on('click', 'button', function () {
    const step = $(this).data('zoom');
    if (step === 'follow') {
      setFollow(!state.follow);
    } else if (step === 'fit') {
      state.renderer.fit();
    } else {
      state.renderer.zoom(Number(step));
    }
  });
}

/** This user's map options, as the dashboard widget stores them. */
async function loadSettings() {
  let config = {};
  try {
    const dashboard = await getJSON('/api/core/dashboard/getDashboard');
    config = (dashboard.dashboard?.widgets || []).find((widget) => widget.id === 'firewallmap')?.widget || {};
  } catch (error) {
    console.error('Firewall Map+: dashboard settings unavailable', error);
  }
  state.settings = {...parseSettings(config), colorMode: state.colorMode};
  // investigation actions are offered to administrators (who can read the plugin status)
  try {
    state.pluginStatus = await getJSON('/api/firewallmap/settings/status');
    state.isAdmin = true;
    state.abuseConfigured = Boolean(state.pluginStatus.abuseipdb_configured);
  } catch (_) {
    state.pluginStatus = null;
    state.isAdmin = false;
  }
}

function createRenderer() {
  const $map = $('#fwmap-map');
  const theme = window.FirewallMapRenderer.readTheme($map[0]);
  host().applyTheme($map[0], theme, {
    grid: document.getElementById('fwmap-grid'),
    overlays: [document.getElementById('fwmap-status'), document.getElementById('fwmap-legend')],
    // the side panel, the zoom buttons and the Threats dialog (outside the layout) share the palette
    root: document.body,
  });
  state.follow = readFollow();
  const container = document.getElementById('fwmap-canvas');
  state.renderer = window.FirewallMapRenderer.create(container, {
    theme,
    settings: {...state.settings, follow: state.follow},
    text: T,
    onSelect: (selection) => {
      state.selection = selection;
      renderDetails();
    },
    // moving the map by hand ends follow mode, as in a navigation app
    onFollowChange: (on) => setFollow(on, false),
    onContextLost: () => recoverRenderer(),
  });
  setFollow(state.follow);
  $(container).children('canvas').css({left: 0, top: 0});
}

// a browser that keeps taking the GPU away is not fought: after this many resets in RESET_WINDOW_MS
// the map stops and asks for a reload
const MAX_RESETS = 3;
const RESET_WINDOW_MS = 120000;
const REBUILD_MS = 2000;
let resets = [];
let rebuilding = null;

/** The WebGL context was lost: say so, then build a new renderer (a new canvas, a new context). */
function recoverRenderer() {
  state.contextLosses = (state.contextLosses || 0) + 1;
  const now = Date.now();
  resets = resets.filter((time) => now - time < RESET_WINDOW_MS).concat(now);
  if (rebuilding) {
    return;
  }
  if (resets.length > MAX_RESETS) {
    $('#fwmap-status').text(T.webgl_failed);
    return;
  }
  $('#fwmap-status').text(T.webgl_lost);
  rebuilding = setTimeout(() => {
    rebuilding = null;
    try {
      state.renderer.destroy();
    } catch (_) {
      // the old context is gone; nothing left to release
    }
    $('#fwmap-canvas').empty();
    createRenderer();
    if (state.mode === 'snapshot') {
      state.renderer.setFrozen(true);
      state.renderer.setFollow(false);
    }
    refresh();
  }, REBUILD_MS);
}

$(async () => {
  if (!window.FirewallMapRenderer?.host.hasWebGL()) {
    $('#fwmap-status').text(T.webgl);
    return;
  }
  await loadSettings();
  try {
    createRenderer();
  } catch (error) {
    console.error('Firewall Map+: renderer initialization failed', error);
    $('#fwmap-status').text(`${T.renderer_failed}: ${error?.message || error}`);
    return;
  }
  bindControls();
  bindSplitters();
  watchSideWidth();
  $('#fwmap-review').toggle(state.isAdmin);
  if (state.isAdmin) {
    refreshQueueCount();
    setInterval(refreshQueueCount, 60000);
  }
  renderDetails();
  bindSnapshots({refresh, renderDetails, setTab, setFollow: (on) => setFollow(on)});
  $('#fwmap-geo').on('click', '.fwmap-geo-note-close', () => {
    state.geoNoteDismissed = host().geoNoteKey(state.live);
    showGeo(state.mode === 'live' ? state.live : null);
  });
  $(window).on('resize', () => state.renderer.resize());
  // Escape leaves a snapshot
  $(document).on('keydown', (event) => {
    if (event.key === 'Escape' && state.mode === 'snapshot' && !$('.modal.in').length) {
      backToLive();
    }
  });
  poll(summaryQuery(state.settings));
  // ?debug=1: the diagnostics panel, a separate script that only development packages install
  if (new URLSearchParams(window.location.search).get('debug') === '1' && window.FirewallMapDiagnostics) {
    window.FirewallMapDiagnostics.start({renderer: () => state.renderer, mode: () => state.mode, contextLosses: () => state.contextLosses});
  }
});
