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

/* The side panel's top talkers: hosts, countries, networks and IDS addresses, with sparklines. */
import {escapeHtml, flagHtml, formatRate, plain} from '../src/format.js';
import {state, T} from './context.js';
import {locationsById} from './filters.js';
import {ic} from './icons.js';

const HISTORY_POINTS = 60;
const TALKER_ROWS = 20;
/** "VLAN10_MGMT" reads as "MGMT (VLAN10)"; the configured name stays in the tooltip. */
function shortInterface(name) {
  const match = /^VLAN(\d+)[_ -]+(.+)$/i.exec(plain(name || ''));
  return match ? `${match[2]} (VLAN${match[1]})` : plain(name || '');
}

/** Top talkers by host, country and network, plus the addresses Suricata alerted on. */
function groupTalkers(snapshot) {
  const locations = locationsById(snapshot);
  const groups = {hosts: new Map(), countries: new Map(), networks: new Map(), ids: new Map()};
  const add = (group, key, fields, rate) => {
    const entry = groups[group].get(key) || {key, rate: 0, flows: 0, ...fields};
    entry.rate += rate;
    entry.flows += 1;
    groups[group].set(key, entry);
  };
  for (const flow of snapshot.flows || []) {
    const rate = flow.rate || 0;
    const dest = locations.get(flow.dest) || {};
    for (const inside of (flow.inside || []).slice(0, 1)) {
      add('hosts', inside.ip, {label: inside.name || inside.ip, ip: inside.ip, iface: inside.interface,
        icon: 'laptop', filter: {host: inside.ip}}, rate);
    }
    if (dest.country) {
      add('countries', dest.country, {label: plain(dest.country), flag: flagHtml(dest.country_code),
        icon: 'fa-flag-o', filter: {country: dest.country}}, rate);
    }
    if (dest.asn) {
      add('networks', String(dest.asn), {label: plain(dest.as_org || `AS${dest.asn}`), sub: `AS${dest.asn}`,
        icon: 'network', filter: {asn: String(dest.asn)}}, rate);
    }
  }
  // IDS: correlated connections first, then addresses with alert history
  const idsEntry = (address, ids, count, severity, select, connection) => {
    const current = groups.ids.get(address);
    if (current && (current.connection || !connection)) {
      return;
    }
    const top = ids?.signatures?.[0] || ids?.groups?.[0]?.signatures?.[0];
    groups.ids.set(address, {key: address, label: address, sub: top ? plain(top.signature) : '', severity,
      count, connection, icon: connection ? 'fa-exclamation-circle' : 'fa-flag', rate: 0, select});
  };
  for (const flow of snapshot.ids_flows || []) {
    if (flow.kind !== 'blocked') {
      idsEntry(flow.dest, flow, flow.count, flow.severity, {kind: 'idsflow', addresses: [flow.dest], idsFlow: flow,
        country: flow.country, countryCode: flow.country_code, title: flow.city || flow.country}, true);
    }
  }
  for (const flow of snapshot.flows || []) {
    if (flow.ids) {
      const dest = locations.get(flow.dest) || {};
      idsEntry(flow.dest, flow.ids, flow.ids.count, flow.ids.severity, {kind: 'flow', addresses: [flow.dest], members: [flow],
        country: dest.country, countryCode: dest.country_code, title: dest.city || dest.country}, false);
    }
  }
  for (const block of snapshot.blocks || []) {
    if (block.ids) {
      idsEntry(block.source, block.ids, block.ids.count, block.ids.severity, {kind: 'blocked', addresses: [block.source],
        block, country: block.country, countryCode: block.country_code, title: block.city || block.country}, false);
    }
  }
  for (const alert of snapshot.alerts || []) {
    idsEntry(alert.source, alert.ids, alert.ids?.count || 0, alert.ids?.severity || 3, {kind: 'alert', addresses: [alert.source],
      alert, country: alert.country, countryCode: alert.country_code, title: alert.city || alert.country}, false);
  }
  const result = {};
  for (const [group, entries] of Object.entries(groups)) {
    result[group] = [...entries.values()].sort(group === 'ids'
      ? (a, b) => (b.connection - a.connection) || (a.severity - b.severity) || (b.count - a.count)
      : (a, b) => b.rate - a.rate);
  }
  return result;
}

export function talkers(snapshot) {
  const result = groupTalkers(snapshot);
  for (const [group, entries] of Object.entries(result)) {
    if (group === 'ids') {
      continue;
    }
    for (const entry of entries) {
      const key = `${group}:${entry.key}`;
      const series = state.history.get(key) || [];
      series.push(entry.rate);
      if (series.length > HISTORY_POINTS) {
        series.shift();
      }
      state.history.set(key, series);
      entry.series = series;
    }
  }
  // forget series that have gone quiet, so memory stays bounded
  for (const [key, series] of state.history) {
    const [group, id] = key.split(/:(.*)/s);
    if (!(result[group] || []).some((entry) => entry.key === id)) {
      series.push(0);
      if (series.length > HISTORY_POINTS) {
        series.shift();
      }
      if (series.every((value) => value === 0)) {
        state.history.delete(key);
      }
    }
  }
  return result;
}

/** A small filled area chart; the newest point sits at the right edge. */
function sparkline(canvas, series) {
  const ratio = window.devicePixelRatio || 1;
  const width = canvas.clientWidth || 64;
  const height = canvas.clientHeight || 22;
  canvas.width = Math.round(width * ratio);
  canvas.height = Math.round(height * ratio);
  const context = canvas.getContext('2d');
  // the theme accent, as the page's palette sets it (see host.applyTheme)
  const color = getComputedStyle(canvas).getPropertyValue('--fwmap-accent').trim() || 'rgb(192, 62, 20)';
  context.setTransform(ratio, 0, 0, ratio, 0, 0);
  context.clearRect(0, 0, width, height);
  if (!series || series.length < 2) {
    return;
  }
  const max = Math.max(...series, 1);
  // a short history is spread over the whole width instead of a sliver at the right edge
  const points = series.map((value, index) => [(index / (series.length - 1)) * width,
    height - 1 - (value / max) * (height - 3)]);
  context.beginPath();
  points.forEach(([x, y], index) => (index ? context.lineTo(x, y) : context.moveTo(x, y)));
  context.lineTo(points[points.length - 1][0], height);
  context.lineTo(points[0][0], height);
  context.closePath();
  context.fillStyle = color;
  context.globalAlpha = 0.18;
  context.fill();
  context.globalAlpha = 1;
  context.beginPath();
  points.forEach(([x, y], index) => (index ? context.lineTo(x, y) : context.moveTo(x, y)));
  context.strokeStyle = color;
  context.lineWidth = 1.2;
  context.stroke();
}

export function talkerActive(row) {
  return row.filter && Object.entries(row.filter).every(([key, value]) => state.filters[key] === value);
}

export function renderTalkers(groups) {
  const ids = state.talkerTab === 'ids';
  // the IDS tab lists alerts, not traffic: its order is fixed (connections, then severity)
  $('#fwmap-talker-sort').toggle(!ids);
  const needle = String($('#fwmap-talker-search').val() || '').trim().toLowerCase();
  const sort = $('#fwmap-talker-sort').val() || 'rate';
  let rows = (groups[state.talkerTab] || []).slice();
  if (needle) {
    rows = rows.filter((row) => [row.label, row.ip, row.iface, row.sub, row.key].filter(Boolean)
      .some((text) => String(text).toLowerCase().includes(needle)));
  }
  if (!ids && sort === 'flows') {
    rows.sort((a, b) => b.flows - a.flows || b.rate - a.rate);
  } else if (sort === 'name') {
    rows.sort((a, b) => String(a.label).localeCompare(String(b.label)));
  }
  rows = rows.slice(0, TALKER_ROWS);
  const $list = $('#fwmap-talkers-list');
  if (!rows.length) {
    $list.html(`<div class="text-muted fwmap-empty">${escapeHtml(ids ? T.no_ids_talkers : T.no_talkers)}</div>`);
    state.talkerRows = [];
    return;
  }
  $list.html(rows.map((row, index) => {
    const sub = row.ip ? `${escapeHtml(row.ip)}${row.iface ? ` · <span title="${escapeHtml(row.iface)}">${escapeHtml(shortInterface(row.iface))}</span>` : ''}`
      : escapeHtml(row.sub || '');
    const chart = ids ? '<span></span>' : '<canvas></canvas>';
    const value = ids
      ? `<span class="fwmap-talker-count ${row.severity <= 2 ? 'fwmap-ids-high' : 'fwmap-ids'}">${escapeHtml(row.count)} ${escapeHtml(T.alerts_short)}</span>`
      : `<span class="fwmap-talker-rate">${escapeHtml(formatRate(row.rate))}</span>`;
    const extra = ids
      ? `<span class="fwmap-talker-flows">${escapeHtml(T.severity)} ${escapeHtml(row.severity)}</span>`
      : `<span class="fwmap-talker-flows">${escapeHtml(row.flows)} ${escapeHtml(row.flows === 1 ? T.flow_one : T.flow_many)}</span>`;
    const active = talkerActive(row);
    // a button for keyboards too: Enter or Space acts like a click (see bindControls)
    return `<div class="fwmap-talker${active ? ' active' : ''}" data-index="${index}" role="button" tabindex="0"
        ${ids ? '' : `aria-pressed="${active}"`} title="${escapeHtml(ids ? T.select_hint : T.filter_hint)}">
      <span class="fwmap-talker-icon">${row.flag || `${ic(row.icon)}`}</span>
      <span class="fwmap-talker-text"><span class="fwmap-talker-label">${escapeHtml(row.label)}</span>
        <span class="fwmap-talker-sub">${sub}</span></span>
      ${chart}${value}${extra}
    </div>`;
  }).join(''));
  state.talkerRows = rows;
  $list.find('.fwmap-talker canvas').each(function () {
    sparkline(this, rows[$(this).closest('.fwmap-talker').data('index')].series);
  });
}

// re-rank the current tab from the last snapshot without adding a history point
export function talkersFromLast() {
  const groups = groupTalkers(state.snapshot);
  for (const [group, entries] of Object.entries(groups)) {
    for (const entry of entries) {
      // a saved snapshot has no history of its own: no sparkline rather than today's
      entry.series = state.mode === 'snapshot' ? null : state.history.get(`${group}:${entry.key}`);
    }
  }
  return groups;
}
