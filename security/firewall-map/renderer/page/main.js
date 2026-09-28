/*
 * Full-size Firewall Map+ page: filters, colour modes with legend, top talkers and investigation
 * actions around the shared renderer (firewall-map-renderer.js, the global FirewallMapRenderer).
 * Built with vite.page.config.js into src/opnsense/www/js/firewall-map-page.js.
 */
import {escapeHtml} from '../src/format.js';
import {parseSettings, snapshotQuery} from '../src/options.js';
import {addCountry, addToAlias, killStates, markThreat, showStates} from './actions.js';
import {getJSON} from './api.js';
import {POLL_MS, resetFilters, state, T} from './context.js';
import {renderDetails} from './details.js';
import {filtered} from './filters.js';
import {checkAbuse, investigate} from './investigate.js';
import {bindSplitters, readFollow, setFollow, watchSideWidth} from './layout.js';
import {refreshQueueCount, showQueue} from './queue.js';
import {renderTalkers, talkerActive, talkers, talkersFromLast} from './talkers.js';
import {updateLegend, updateToolbar} from './toolbar.js';

const host = () => window.FirewallMapRenderer.host;

/** Suricata counts in the status line, each a one-click filter; connections and address history apart. */
function idsLinks(snapshot) {
  const idsFlows = (snapshot.ids_flows || []).filter((flow) => flow.kind !== 'blocked').length;
  const idsAddresses = new Set([...(snapshot.alerts || []).map((alert) => alert.source),
    ...(snapshot.flows || []).filter((flow) => flow.ids).map((flow) => flow.dest),
    ...(snapshot.blocks || []).filter((block) => block.ids).map((block) => block.source)]).size;
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

function statusLine(snapshot, shown) {
  const parts = host().statusParts(snapshot, shown, state.settings, T);
  // the Suricata links sit before the CARP note, which stays last
  const carp = snapshot.carp === 'backup' ? parts.pop() : null;
  $('#fwmap-status').html([...parts, ...idsLinks(snapshot), carp].filter(Boolean).join(' · '));
  state.updatedAt = Date.now();
  updatedLine();
}

function updatedLine() {
  if (!state.updatedAt) {
    return;
  }
  const seconds = Math.max(0, Math.round((Date.now() - state.updatedAt) / 1000));
  $('#fwmap-updated').html(`${escapeHtml(T.last_updated)} ${escapeHtml(seconds)} s ${escapeHtml(T.ago)} `
    + `<i class="fwmap-live${seconds > 10 ? ' stale' : ''}"></i>`);
}

function refresh() {
  const snapshot = state.snapshot;
  if (!snapshot || snapshot.status !== 'ok') {
    return;
  }
  const shown = filtered(snapshot);
  state.renderer.render(shown);
  updateToolbar(snapshot);
  updateLegend();
  statusLine(snapshot, shown);
  $('#fwmap-credit').html(host().creditHtml(snapshot.provider));
}

/** One request at a time, never stacked on a slow firewall; nothing while the page is hidden. */
function poll(query) {
  let timer = null;
  const tick = async () => {
    timer = null;
    if (document.hidden) {
      return;
    }
    try {
      const snapshot = await getJSON(`/api/firewallmap/flow/snapshot${query}`);
      const problem = host().problemText(snapshot, T);
      if (problem) {
        if (snapshot.status === 'no_database') {
          state.renderer.render({flows: [], locations: []});
        }
        $('#fwmap-status').text(problem);
      } else {
        state.snapshot = snapshot;
        renderTalkers(talkers(snapshot));
        refresh();
      }
    } catch (error) {
      console.error('Firewall Map+: flow update failed', error);
      $('#fwmap-status').text(T.unavailable);
    }
    if (!document.hidden) {
      timer = setTimeout(tick, POLL_MS);
    }
  };
  // shown again: poll at once instead of waiting out an interval
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && timer === null) {
      tick();
      refreshQueueCount();
    }
  });
  tick();
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
  $('#fwmap-filter-asn a').on('click', (event) => {
    event.preventDefault();
    state.filters.asn = '';
    refresh();
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
    .on('mousedown', '.fwmap-talker', function (event) {
      event.preventDefault();
      selectTalker(rowOf(this));
    })
    .on('keydown', '.fwmap-talker', function (event) {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        const index = $(this).data('index');
        selectTalker(rowOf(this));
        // the list is redrawn: keep the keyboard on the same row
        $(`#fwmap-talkers-list .fwmap-talker[data-index="${index}"]`).trigger('focus');
      }
    });
  $('#fwmap-talker-search, #fwmap-talker-sort').on('input change', () => {
    if (state.snapshot) {
      renderTalkers(talkersFromLast());
    }
  });
  $('#fwmap-talkers .nav a').on('click', function (event) {
    event.preventDefault();
    state.talkerTab = $(this).data('tab');
    $('#fwmap-talkers .nav li').removeClass('active').find('a').attr('aria-selected', 'false');
    $(this).attr('aria-selected', 'true').parent().addClass('active');
    if (state.snapshot) {
      renderTalkers(talkersFromLast());
    }
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
  on('.fwmap-states', ($element) => showStates(address($element)));
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
  // investigation actions are offered to administrators (who can read the plugin settings)
  try {
    state.pluginSettings = await getJSON('/api/firewallmap/settings/get');
    state.isAdmin = Boolean(state.pluginSettings.provider);
    state.abuseConfigured = Boolean(state.pluginSettings.abuseipdb_configured);
  } catch (_) {
    state.pluginSettings = null;
    state.isAdmin = false;
  }
}

function createRenderer() {
  const $map = $('#fwmap-map');
  const theme = window.FirewallMapRenderer.readTheme($map[0]);
  host().applyTheme($map[0], theme, {
    grid: document.getElementById('fwmap-grid'),
    overlays: [document.getElementById('fwmap-status'), document.getElementById('fwmap-legend')],
    // the side panel, the zoom buttons and the review queue dialog (outside the layout) share the palette
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
  });
  setFollow(state.follow);
  $(container).children('canvas').css({left: 0, top: 0});
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
    console.error('Firewall Map+: renderer initialisation failed', error);
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
  $(window).on('resize', () => state.renderer.resize());
  poll(snapshotQuery(state.settings));
});
