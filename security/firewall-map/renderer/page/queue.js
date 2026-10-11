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

/* Threat history: flagged traffic organized by what the firewall or IPS actually did. */
import {escapeHtml, fill, flagHtml, formatBytes, hostPort, listLabel, plain, privateAddress, protocolLabel, splitHostPort} from '../src/format.js';
import {flowSummary} from '../src/summaries.js';
import {addAddressToAlias, chooseAlias, killStates, showStates} from './actions.js';
import {confirmAction, getJSON, notifyFailure, postJSON} from './api.js';
import {state, T, TEXT} from './context.js';
import {remoteOf} from './details.js';
import {ic} from './icons.js';
import {investigate, investigationPanel} from './investigate.js';
import {ago, agoText, idsLines, pill} from './parts.js';

const VIEWS = ['passed', 'firewall_blocked', 'ips_dropped', 'all', 'reviewed', 'dismissed'];
const QUEUE_PAGE = 100;

// inside host names from the live map, for addresses recorded in the queue
function insideNames(extra = {}) {
  const names = new Map(Object.entries(extra));
  for (const flow of state.data?.flows || []) {
    for (const host of [...(flow.inside || []), ...(flow.targets || [])]) {
      if (host.name && host.ip) {
        names.set(host.ip, host.name);
      }
    }
  }
  return names;
}

function queueItem(row, names) {
  const insideAddresses = new Set(row.inside || []);
  // the same sentence as on the map, rebuilt from what the queue recorded
  const ports = row.service_ports || {};
  const serviceFor = (protocol, port) => Object.keys(ports).find((name) => ports[name] === `${port}/${protocol}`)
    || (port ? `${protocolLabel(protocol)}/${port}` : 'ICMP');
  const disposition = ['passed', 'firewall_blocked', 'ips_dropped'].includes(row.disposition) ? row.disposition : 'passed';
  // the per-connection snapshot the collector took from PF (and Suricata) for this address. The
  // card leads with a connection that shows the disposition: an address that got through once and
  // was blocked later is filed under Passed, so its headline is the connection that passed.
  const wanted = {passed: 'pass', firewall_blocked: 'block'}[disposition];
  const conns = [...(row.connections || [])].sort((a, b) => (b.decision === wanted) - (a.decision === wanted));
  const lead = conns[0];
  const leadTarget = lead && lead.remote_started ? (() => {
    const [ip, port] = splitHostPort(lead.inside || lead.public || '');
    return `${lead.protocol}|${ip}|${port}`;
  })() : null;
  const targets = [...(row.targets || [])].sort((a, b) => (b === leadTarget) - (a === leadTarget)).map((target) => {
    const [protocol, ip, port] = String(target).split('|');
    const firewall = !privateAddress(ip) && !insideAddresses.has(ip);
    return {ip, port, protocol, name: firewall ? 'firewall' : names.get(ip), firewall,
      service: (row.target_services || {})[target] || serviceFor(protocol, port)};
  });
  const pseudo = {
    initiated: row.inbound && row.outbound ? 'both' : row.inbound ? 'remote' : 'local',
    targets,
    inside: (row.inside || []).map((ip) => ({ip, name: names.get(ip)})),
    services: row.services || [],
    service_ports: ports,
  };
  // what was recorded with the entry, completed by the live map
  const live = remoteOf(row.address);
  const saved = row.remote || {};
  const remote = {
    ip: row.address,
    hostname: saved.hostname || live.hostname,
    org: state.settings.asn ? (saved.org || live.org) : null,
    country: saved.country || live.country,
  };
  const lines = flowSummary(pseudo, remote, TEXT).map(escapeHtml);
  const address = escapeHtml(row.address);
  const status = ['new', 'reviewed', 'blocked', 'dismissed'].includes(row.status) ? row.status : 'new';
  const inbound = pseudo.initiated !== 'local';
  // the local side: the port-forward target, the inside host, or the firewall itself
  const target = targets[0];
  const inside = pseudo.inside[0];
  let localIcon = 'shield-halved';
  let localName = T.this_firewall_title;
  let localLines = [];
  let otherTargets = '';
  let service = row.services?.[0] ? `${row.services[0]}${ports[row.services[0]] ? ` · ${ports[row.services[0]].split('/').reverse().join('/').toUpperCase()}` : ''}` : '';
  if (inbound && target) {
    service = `${target.service}${target.port ? ` · ${protocolLabel(target.protocol)}/${target.port}` : ''}`;
    if (!target.firewall) {
      localIcon = 'server';
      localName = target.name || target.ip;
      localLines = [target.name ? target.ip : '', T.port_forward];
    } else {
      // one of the firewall's own public addresses (a WAN address or VIP): say which interface
      const via = (row.connections || []).find((item) => item.interface && splitHostPort(item.public || '')[0] === target.ip);
      localLines = [via ? `${target.ip} · ${via.interface}` : target.ip];
    }
    if (targets.length > 1) {
      otherTargets = `+ ${targets.length - 1} ${targets.length > 2 ? T.other_targets : T.other_target}`;
    }
  } else if (!inbound && inside) {
    localIcon = 'laptop';
    localName = inside.name || inside.ip;
    localLines = [inside.name ? inside.ip : ''];
    if (pseudo.inside.length > 1) {
      localLines.push(`+ ${pseudo.inside.length - 1} ${T.other_hosts}`);
    }
  }
  const cc = saved.country_code || live.country_code || countryCodeOf(remote.country);
  if (lead && lead.inside && !inbound) {
    const [leadIp] = splitHostPort(lead.inside);
    localIcon = 'laptop';
    localName = lead.inside_name || names.get(leadIp) || leadIp;
    localLines = [lead.inside, conns.length > 1 ? `+ ${conns.length - 1} ${conns.length > 2 ? T.more_connections : T.more_connection}` : ''];
  }
  const rule = lead ? lead.rule || conns.find((item) => item.decision === lead.decision && item.rule)?.rule : null;
  // the firewall's decision and Suricata's action side by side, whatever the source of the record
  const decision = (item) => [
    item.decision === 'pass' ? pill('success', T.fw_passed) : item.decision === 'block' ? pill('default', T.fw_blocked)
      : `<span class="text-muted">${escapeHtml(T.fw_not_seen)}</span>`,
    item.ips_dropped ? pill('warning', T.ips_dropped_short) : '',
  ].filter(Boolean).join(' ');
  const connTable = conns.length ? `<table class="table table-condensed fwmap-q-conns"><thead><tr><th>${escapeHtml(T.connection_col)}</th><th>${escapeHtml(T.decision)}</th><th>${escapeHtml(T.rule)}</th>`
    + `<th>${escapeHtml(T.interface)}</th><th>${escapeHtml(T.transferred)}</th><th>${escapeHtml(T.started)}</th><th>IDS</th></tr></thead><tbody>`
    + conns.map((item) => {
      const insideText = `${item.inside_name ? `${item.inside_name} ` : ''}${item.inside || T.this_firewall}`;
      const path = item.remote_started ? `${item.remote} → ${insideText}` : `${insideText} → ${item.remote}`;
      const ids = (item.ids || []).map((sig) => `<div class="${sig.severity <= 2 ? 'text-danger fwmap-ids-high' : 'fwmap-ids'}">${ic('flag')} ${escapeHtml(sig.signature)} ×${escapeHtml(sig.count)}</div>`
        + (sig.query ? `<div class="text-muted">${escapeHtml(T.query)}: ${escapeHtml(sig.query)}</div>` : '')).join('');
      return `<tr><td><div>${escapeHtml(path)} <span class="text-muted">${escapeHtml(protocolLabel(item.protocol))}</span></div>`
        + `<div class="text-muted">${escapeHtml(T.via)} ${escapeHtml(item.public || '')}${item.open ? '' : ` · ${escapeHtml(T.closed)}`}</div></td>`
        + `<td>${decision(item)}</td><td>${escapeHtml(item.rule || '—')}</td><td>${escapeHtml(item.interface || '—')}</td>`
        + `<td>↓ ${escapeHtml(formatBytes(item.bytes_in || 0))} ↑ ${escapeHtml(formatBytes(item.bytes_out || 0))}</td>`
        + `<td>${item.started ? escapeHtml(agoText(item.started)) : '—'}</td><td>${ids || '<span class="text-muted">—</span>'}</td></tr>`;
    }).join('') + '</tbody></table>' : '';
  const org = saved.org || live.org;
  // the lists stand out while the entry waits for review
  const chips = (row.lists || []).map((name) => pill(status === 'new' ? 'danger' : 'default', listLabel(name))).join(' ');
  const expanded = state.queueExpanded.has(row.address);
  const card = state.investigations.get(row.address);
  const btn = (cls, icon, label, extra = '') =>
    `<button type="button" class="btn btn-default ${cls}" ${extra}>${ic(icon)} ${escapeHtml(label)}</button>`;
  const link = (href, icon, label) =>
    `<a class="btn btn-default" href="${href}" target="_blank" rel="noopener noreferrer">${ic(icon)} ${escapeHtml(label)}</a>`;
  const review = status === 'new'
    ? btn('fwmap-q-status', 'check', T.mark_reviewed, 'data-status="reviewed"')
    : btn('fwmap-q-status', 'rotate-left', T.reopen, 'data-status="new"');
  const dispositionColor = {passed: 'danger', firewall_blocked: 'default', ips_dropped: 'warning'}[disposition];
  return `<div class="panel panel-default fwmap-q-item fwmap-q-${status}" data-address="${address}" data-status="${status}">
    <div class="panel-body">
    <div class="fwmap-q-top">
      <div class="fwmap-q-who">
        <div class="fwmap-q-ipline"><span class="fwmap-q-ip">${address}</span>
          ${pill(dispositionColor, T[`disposition_${disposition}`])}
          ${status !== 'new' ? `<span class="text-muted text-uppercase small">${escapeHtml(T[`status_${status}`])}</span>` : ''}</div>
        ${remote.hostname ? `<div class="text-muted fwmap-q-hostname" title="${escapeHtml(remote.hostname)}">${escapeHtml(remote.hostname)}</div>` : ''}
        ${org || remote.country ? `<div class="fwmap-q-org">${escapeHtml(org || '')}${org && remote.country ? ' · ' : ''}${remote.country ? `${flagHtml(cc)}${escapeHtml(remote.country)}` : ''}</div>` : ''}
        ${chips ? `<div class="fwmap-q-chips">${chips}</div>` : ''}
      </div>
      <div class="fwmap-q-flow">
        <div class="fwmap-q-diagram">
          ${ic('globe', 'fa-2x text-muted')}
          <div class="fwmap-q-link">
            <div>${escapeHtml(service)}</div>
            <div class="fwmap-q-arrow ${inbound ? 'fwmap-q-arrow-in' : 'fwmap-q-arrow-out'}"></div>
            ${pill('default', inbound ? `↘ ${T.inbound}` : `↖ ${T.outbound}`)}
          </div>
          ${ic(localIcon, 'fa-2x text-muted')}
          <div class="fwmap-q-local"><div class="fwmap-q-local-name">${escapeHtml(localName)}</div>
            ${localLines.filter(Boolean).map((line, index) => `<div class="${index ? 'text-muted' : ''}">${escapeHtml(line)}</div>`).join('')}
            ${otherTargets ? `<a href="#" class="fwmap-q-expand text-muted" aria-expanded="${expanded}">${escapeHtml(otherTargets)}</a>` : ''}</div>
        </div>
        <ul class="list-inline text-muted fwmap-q-meta">
          <li>${ic('calendar')} ${escapeHtml(fill(T.first_seen_ago, {time: ago(row.first_seen)}))}</li>
          <li>${ic('chart-column')} ${escapeHtml(row.samples)} ${escapeHtml(row.samples === 1 ? T.sample : T.samples)}</li>
          <li>${ic('right-left')} ${escapeHtml(T.peak)} ${escapeHtml(formatBytes(row.peak_bytes || 0))}</li>
          ${rule ? `<li title="${escapeHtml(T.rule)}">${ic('shield-halved')} ${escapeHtml(rule)}</li>` : ''}
        </ul>
        ${idsLines(row.ids, TEXT)}
      </div>
      <div class="text-muted fwmap-q-when">
        <span title="${escapeHtml(new Date(row.last_seen * 1000).toLocaleString())}">${ic('clock')} ${escapeHtml(agoText(row.last_seen))}</span>
        <a href="#" class="fwmap-q-expand" title="${escapeHtml(T.more_details)}" aria-label="${escapeHtml(T.more_details)}" aria-expanded="${expanded}">${ic(expanded ? 'chevron-down' : 'chevron-right')}</a>
      </div>
    </div>
    ${row.seen_after_block ? `<div class="text-danger fwmap-q-warning">${ic('circle-exclamation')} ${escapeHtml(T.seen_after_block)}</div>` : ''}
    ${expanded ? `<div class="well well-sm fwmap-q-more">${lines.map((line) => `<div>${line}</div>`).join('')}
      ${targets.length > 1 ? `<div class="text-muted">${escapeHtml(T.targets_seen)}: ${targets.map((item) => escapeHtml(
        `${item.firewall ? T.this_firewall : item.name || item.ip} (${hostPort(item.ip, item.port)}${item.service ? `, ${item.service}` : ''})`)).join(' · ')}</div>` : ''}
      ${(row.services || []).length ? `<div class="text-muted">${escapeHtml(T.services_seen)}: ${(row.services || []).map(escapeHtml).join(', ')}</div>` : ''}
      ${connTable || `<div class="text-muted">${escapeHtml(T.no_snapshot)}</div>`}</div>` : ''}
    ${row.note ? `<div class="well well-sm fwmap-q-note">${escapeHtml(row.note)}</div>` : ''}
    ${card ? investigationPanel(card) : ''}
    </div>
    <div class="panel-footer clearfix">
      <div class="btn-toolbar pull-left">
        <div class="btn-group btn-group-sm"><button type="button" class="btn btn-primary fwmap-q-investigate">${ic('magnifying-glass')} ${escapeHtml(T.investigate)}</button></div>
        <div class="btn-group btn-group-sm">
          ${state.can.states ? btn('fwmap-q-states', 'list', T.show_states) : ''}
          ${link(`https://bgp.he.net/ip/${encodeURIComponent(row.address)}`, 'globe', T.whois)}
          ${link(`https://www.abuseipdb.com/check/${encodeURIComponent(row.address)}`, 'arrow-up-right-from-square', 'AbuseIPDB')}
        </div>
      </div>
      <div class="btn-toolbar pull-right">
        <div class="btn-group btn-group-sm">
          ${review}
          ${status !== 'dismissed' ? btn('fwmap-q-status', 'eye-slash', T.dismiss, 'data-status="dismissed"') : ''}
        </div>
        <div class="btn-group btn-group-sm">
          ${state.can.aliases ? `<button type="button" class="btn btn-danger fwmap-q-block">${ic('ban')} ${escapeHtml(T.block)}</button>` : ''}
          <button type="button" class="btn ${state.can.aliases ? 'btn-danger' : 'btn-default'} dropdown-toggle" data-toggle="dropdown" aria-haspopup="true" aria-label="${escapeHtml(T.more)}">${state.can.aliases ? '' : `${escapeHtml(T.more)} `}<span class="caret"></span></button>
          <ul class="dropdown-menu dropdown-menu-right">
            <li><a href="#" class="fwmap-q-edit-note">${ic('pen')} ${escapeHtml(T.edit_note)}</a></li>
            ${state.can.kill ? `<li><a href="#" class="fwmap-q-kill">${ic('trash-can')} ${escapeHtml(T.kill_states)}</a></li>` : ''}
          </ul>
        </div>
      </div>
    </div>
  </div>`;
}


/** Country name to code from the live map (older queue entries only stored the name). */
function countryCodeOf(name) {
  const match = (state.data?.locations || []).find((location) => location.country === name && location.country_code);
  return match ? match.country_code : '';
}

export async function refreshQueueCount() {
  // a hidden page does not poll; the count is refreshed when it is shown again
  if (document.hidden) {
    return;
  }
  try {
    const result = await getJSON('/api/firewallmap/threats/list/counts');
    $('#fwmap-review-count').text(result.counts?.passed || '');
  } catch (_) {
    $('#fwmap-review-count').text('');
  }
}

async function setThreat(address, status, note) {
  const payload = {address, status};
  if (note !== undefined) {
    payload.note = note;
  }
  const result = await postJSON('/api/firewallmap/threats/set', payload);
  if (result.result !== 'saved') {
    throw new Error(result.error || T.action_failed);
  }
}

function blacklistStatus(plugin) {
  const status = plugin.abuseipdb_blacklist || {};
  let text = T.blacklist_no_key;
  if (plugin.abuseipdb_configured) {
    text = status.updated
      ? `${Number(status.count).toLocaleString()} ${T.blacklist_addresses}, ${T.updated} ${new Date(status.updated * 1000).toLocaleString([], {dateStyle: 'medium', timeStyle: 'short'})}`
      : T.blacklist_pending;
    if (status.error) {
      text += ` (${T.blacklist_error}: ${plain(status.error)})`;
    }
  }
  return $('<div class="text-muted"></div>').attr('title', T.blacklist)
    .append(`${ic('layer-group')} `)
    .append($('<span></span>').text(`${T.blacklist_short}: ${text}`));
}

/** The Threats dialog. The server pages and searches it: history can hold thousands of entries. */
export async function showQueue() {
  // seq: only the answer to the latest request is drawn (quick tab switches, typing)
  const view = {status: 'passed', rows: [], total: 0, counts: {}, names: {}, query: '', seq: 0};
  const $body = $('<div></div>');
  const status = state.pluginStatus || {};
  const $record = $(`<div class="checkbox fwmap-q-record"><label title="${escapeHtml(T.record_threats_hint)}"><input type="checkbox"> ${escapeHtml(T.record_threats)}</label></div>`);
  $record.find('input').prop('checked', status.record_threats !== '0').on('change', async function () {
    const value = this.checked ? '1' : '0';
    try {
      // the plugin setting (also at Reporting: Firewall Map: Settings), saved and applied
      const saved = await postJSON('/api/firewallmap/settings/set', {firewallmap: {general: {record_threats: value}}});
      if (saved.result !== 'saved') {
        throw new Error(Object.values(saved.validations || {}).flat().join(' ') || saved.result);
      }
    } catch (error) {
      this.checked = value !== '1';
      notifyFailure(error);
      return;
    }
    if (state.pluginStatus) {
      state.pluginStatus.record_threats = value;
    }
    // the setting is saved; applying it can still fail (an FWMAP_* alias name taken): say so
    try {
      const applied = await postJSON('/api/firewallmap/service/reconfigure', {});
      if (applied.status !== 'ok') {
        throw new Error(applied.status_msg || applied.status);
      }
    } catch (error) {
      notifyFailure(error);
    }
  });
  const $tabs = $(`<ul class="nav nav-pills fwmap-q-tabs" role="tablist" aria-label="${escapeHtml(T.review_queue)}"></ul>`);
  const $bulk = $('<div class="btn-group btn-group-sm fwmap-q-bulkbar"></div>');
  const $search = $(`<input type="search" class="form-control" placeholder="${escapeHtml(T.queue_search)}" aria-label="${escapeHtml(T.queue_search)}">`);
  const $list = $('<div class="fwmap-q-list" aria-live="polite"></div>');
  const $searchBox = $(`<div class="input-group input-group-sm fwmap-q-searchbox"><span class="input-group-addon">${ic('magnifying-glass')}</span></div>`).append($search);
  $body.append($('<div class="fwmap-q-toolbar"></div>').append($tabs, $bulk), $searchBox, $list);

  const emptyText = () => (view.query ? T.queue_no_match : T[`queue_empty_${view.status}`] || T.queue_empty);

  const render = () => {
    $tabs.html(VIEWS.map((status) => `<li class="${status === view.status ? 'active' : ''}" role="presentation">`
      + `<a href="#" role="tab" aria-selected="${status === view.status}" data-status="${status}">${escapeHtml(T[`status_${status}`])}`
      + `${view.counts[status] ? ` <span class="badge">${escapeHtml(view.counts[status])}</span>` : ''}</a></li>`).join(''));
    const names = insideNames(view.names);
    $list.html(view.rows.length ? view.rows.map((row) => queueItem(row, names)).join('')
      + (view.total > view.rows.length ? `<div class="text-center fwmap-q-moreitems"><button type="button" class="btn btn-default btn-sm fwmap-q-showmore">`
        + `${escapeHtml(fill(T.show_more, {count: Math.min(QUEUE_PAGE, view.total - view.rows.length)}))}</button>`
        + ` <span class="text-muted">${escapeHtml(fill(T.showing, {shown: view.rows.length, total: view.total}))}</span></div>` : '')
      : `<div class="text-muted text-center fwmap-q-empty">${ic('check')} ${escapeHtml(emptyText())}</div>`);
    // bulk actions for the tab: dismissing is reversible, deleting asks first. With a search, they
    // act on what the search shows and say so.
    const count = view.query ? view.total : view.counts[view.status] || 0;
    const bulk = [];
    if (['passed', 'firewall_blocked', 'ips_dropped'].includes(view.status) && count) {
      const label = view.query ? T.dismiss_shown : T.dismiss_all;
      bulk.push(`<button type="button" class="btn btn-default fwmap-q-bulk" data-to="dismissed">${ic('eye-slash')} ${escapeHtml(fill(label, {count}))}</button>`);
    }
    if ((view.status === 'dismissed' || view.status === 'reviewed') && count) {
      const label = view.query ? T.delete_shown : T.delete_all;
      bulk.push(`<button type="button" class="btn btn-default fwmap-q-purge">${ic('trash-can')} ${escapeHtml(fill(label, {count}))}</button>`);
    }
    $bulk.html(bulk.join(''));
  };

  const url = (offset, limit) => `/api/firewallmap/threats/list/${view.status}?offset=${offset}&limit=${limit}`
    + (view.query ? `&q=${encodeURIComponent(view.query)}` : '');
  /** First page of the current tab and search; `more` appends the next page instead. */
  const load = async (more = false) => {
    const seq = ++view.seq;
    try {
      const result = await getJSON(more ? url(view.rows.length, QUEUE_PAGE) : url(0, Math.max(QUEUE_PAGE, view.rows.length)));
      if (seq !== view.seq) {
        return;  // a newer request (another tab, more typing) owns the list now
      }
      view.rows = more ? view.rows.concat(result.rows || []) : result.rows || [];
      view.total = result.total ?? view.rows.length;
      view.counts = result.counts || {};
      view.names = result.names || {};
      $('.fwmap-q-newcount b').text(view.counts.passed || 0);
      $('#fwmap-review-count').text(view.counts.passed || '');
    } catch (error) {
      if (seq === view.seq) {
        notifyFailure(error);
      }
    }
    if (seq === view.seq) {
      render();
    }
  };
  const act = async (work) => {
    try {
      await work();
    } catch (error) {
      notifyFailure(error);
    }
    load();
  };
  const addressOf = (element) => String($(element).closest('.fwmap-q-item').data('address'));
  const rowOf = (address) => view.rows.find((row) => row.address === address) || {};
  let typing = null;
  $search.on('input', () => {
    clearTimeout(typing);
    typing = setTimeout(() => {
      view.query = String($search.val() || '').trim();
      view.rows = [];
      load();
    }, 250);
  });

  $bulk.on('click', '.fwmap-q-bulk', function () {
    const to = String($(this).data('to'));
    const count = view.query ? view.total : view.counts[view.status] || 0;
    const message = view.query ? T.dismiss_shown_confirm : T.dismiss_all_confirm;
    confirmAction(fill(message, {count}), () => act(async () => {
      const result = await postJSON('/api/firewallmap/threats/bulk', {from: view.status, to, query: view.query});
      if (result.result !== 'saved') {
        throw new Error(result.error || T.action_failed);
      }
    }));
  }).on('click', '.fwmap-q-purge', function () {
    const count = view.query ? view.total : view.counts[view.status] || 0;
    confirmAction(fill(T.delete_all_confirm, {count, status: T[`status_${view.status}`]}), () => act(async () => {
      const result = await postJSON('/api/firewallmap/threats/purge', {status: view.status, query: view.query});
      if (result.result !== 'deleted') {
        throw new Error(result.error || T.action_failed);
      }
    }));
  });
  $tabs.on('click', 'a', function (event) {
    event.preventDefault();
    view.status = String($(this).data('status'));
    view.rows = [];
    load();
  });
  $list
    .on('click', '.fwmap-q-status', function () {
      const address = addressOf(this);
      act(() => setThreat(address, String($(this).data('status'))));
    })
    .on('click', '.fwmap-q-showmore', () => load(true))
    .on('click', '.fwmap-q-expand', function (event) {
      event.preventDefault();
      const address = addressOf(this);
      if (state.queueExpanded.has(address)) {
        state.queueExpanded.delete(address);
      } else {
        state.queueExpanded.add(address);
      }
      render();
    })
    .on('click', '.fwmap-q-edit-note', function (event) {
      event.preventDefault();
      const address = addressOf(this);
      // the server keeps 2400 bytes; 800 characters fit in any script
      const $text = $('<textarea class="form-control" rows="4" maxlength="800"></textarea>')
        .attr('aria-label', `${T.note_title} ${address}`).val(plain(rowOf(address).note || ''));
      BootstrapDialog.show({
        title: escapeHtml(`${T.note_title} ${address}`), message: $text,
        buttons: [
          {label: T.cancel, action: (dialog) => dialog.close()},
          {label: T.save, cssClass: 'btn-primary', action: (dialog) => {
            dialog.close();
            act(() => setThreat(address, rowOf(address).status || 'new', String($text.val())));
          }},
        ],
      });
    })
    .on('click', '.fwmap-q-block', function () {
      const address = addressOf(this);
      chooseAlias(['host', 'hosts', 'network', 'networks'], escapeHtml(`${T.block_title}: ${address}`), (name) => {
        confirmAction(`${T.add_confirm} ${address} → ${name}? ${T.block_hint}`, () => act(async () => {
          await addAddressToAlias(name, address);
          const note = [plain(rowOf(address).note || ''), `→ ${name} (${new Date().toLocaleString()})`].filter(Boolean).join('\n');
          await setThreat(address, 'blocked', note);
        }));
      });
    })
    .on('click', '.fwmap-q-investigate, .fwmap-inv-retry', (event) => {
      event.preventDefault();
      investigate(addressOf(event.currentTarget), render);
    })
    .on('click', '.fwmap-q-states', function (event) {
      event.preventDefault();
      showStates(addressOf(this));
    })
    .on('click', '.fwmap-q-kill', function (event) {
      event.preventDefault();
      killStates(addressOf(this));
    });

  // what the queue is and where its data comes from, out of the way of the entries
  const $footer = $('<div class="pull-left text-left fwmap-q-footer"></div>').append($record).append(blacklistStatus(status));
  BootstrapDialog.show({
    title: `${ic('list-check')} ${escapeHtml(T.review_queue)} <span class="fwmap-pill fwmap-pill-danger fwmap-q-newcount"><b></b> ${escapeHtml(T.passed_attention)}</span>`
      + `<div class="small text-muted">${escapeHtml(T.review_intro)}</div>`,
    type: BootstrapDialog.TYPE_DEFAULT, size: BootstrapDialog.SIZE_WIDE, message: $body, cssClass: 'fwmap-q-dialog',
    buttons: [{label: T.close, action: (dialog) => dialog.close()}],
    onshown: (dialog) => {
      dialog.getModalFooter().prepend($footer);
      // the list can load before the header exists
      $('.fwmap-q-newcount b').text(view.counts.passed ?? '');
    },
    onhidden: () => refreshQueueCount(),
  });
  load();
}
