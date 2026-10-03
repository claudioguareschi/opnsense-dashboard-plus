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

/* The details panel for what was clicked on the map or in the IDS list. */
import {escapeHtml, flagHtml, formatBytes, formatRate, hostPort, listLabel, plain, splitHostPort} from '../src/format.js';
import {idsOutcome} from '../src/summaries.js';
import {ABUSEIPDB_BLACKLIST_LIST, ABUSEIPDB_LOOKUP_LIST, state, T} from './context.js';
import {ic} from './icons.js';
import {ago, bigPill, card, endBox, pill, place, rows, serviceParts, spanText} from './parts.js';

// Investigate scrolls its card into view slowly enough to follow
const REVEAL_MS = 900;

/** What the map knows about a remote address: hostname, network, country. */
export function remoteOf(address) {
  const location = (state.snapshot?.locations || []).find((item) => item.id === address) || {};
  return {
    ip: address,
    hostname: state.snapshot?.hostnames?.[address],
    org: state.settings.asn ? location.as_org : null,
    country: location.country,
    country_code: location.country_code,
  };
}

function reputationCard(item) {
  const listed = new Set(item.lists || []);
  const lists = [...new Set([...(state.snapshot?.threat_lists || []), ...listed])];
  const address = item.address;
  const score = item.abuseipdb ?? state.abuseScores.get(address);
  // already on the downloaded AbuseIPDB blacklist: that row says it all, no lookup to offer
  const blacklisted = listed.has(ABUSEIPDB_BLACKLIST_LIST);
  const known = score !== null && score !== undefined;
  let abuse;
  if (state.abuseChecking.has(address)) {
    abuse = `<span class="fwmap-muted">${escapeHtml(T.checking)}</span>`;
  } else if (!known) {
    // a lookup is one click away when the firewall has an AbuseIPDB key
    abuse = state.isAdmin && state.abuseConfigured
      ? `<a href="#" class="fwmap-abuse-check" data-address="${escapeHtml(address)}">${ic('search')} ${escapeHtml(T.check_now)}</a>`
      : `<span class="fwmap-muted" title="${escapeHtml(T.abuseipdb_hint)}">${escapeHtml(T.no_key)}</span>`;
  } else {
    abuse = score >= 75 ? pill('danger', `${score}%`) : score >= 25 ? pill('warning', `${score}%`) : pill('ok', T.clean, 'fa-check');
  }
  // listed stands out in red; everything else reads as a quiet green "not listed"
  const notListed = `<span class="fwmap-not-listed">${ic('check')} ${escapeHtml(T.not_listed_short)}</span>`;
  const left = rows([
    ['AbuseIPDB', blacklisted && !known ? '' : abuse],
    ...lists.filter((name) => name !== ABUSEIPDB_LOOKUP_LIST).map((name) =>
      [listLabel(name), listed.has(name) ? pill('danger', T.listed, 'fa-ban') : notListed]),
  ]);
  const right = rows([
    ['ASN', item.asn ? escapeHtml(`AS${item.asn}`) : ''],
    [T.organization, escapeHtml(plain(item.as_org || ''))],
    [T.country, item.country ? `${flagHtml(item.country_code)} ${escapeHtml(plain(item.country))}` : ''],
  ]);
  return card('fa-database', T.sec_reputation, `<div class="fwmap-two">${left}${right}</div>`,
    state.isAdmin ? {cls: 'fwmap-investigate', address, title: T.investigate} : null);
}

function idsCard(ids, groups) {
  const signatures = groups ? groups.flatMap((group) => group.signatures)
    : (ids?.signatures || []).map((item) => ({...item, last: null}));
  if (!signatures.length) {
    return card('fa-search', T.sec_ids_long, `<div class="fwmap-empty-note">${ic('check', 'fwmap-ok-ic')}
      <div><div>${escapeHtml(T.no_ids)}</div><div class="fwmap-muted">${escapeHtml(T.no_ids_sub)}</div></div></div>`,
    {href: '/ui/ids#alerts', title: T.open_ids});
  }
  const scope = groups ? T.ids_on_connection : T.ids_on_address;
  return card('fa-search', T.sec_ids_long, `<div class="fwmap-card-note">${escapeHtml(scope)}</div>`
    + signatures.map((item) => `<div class="fwmap-sig">
        <div class="${item.severity <= 2 ? 'fwmap-ids-high' : 'fwmap-ids'}">${ic('flag')} ${escapeHtml(item.signature)}</div>
        <div class="text-muted">${escapeHtml(T.severity)} ${escapeHtml(item.severity)}${item.category ? ` · ${escapeHtml(item.category)}` : ''}${item.sid ? ` · SID ${escapeHtml(item.sid)}` : ''}
          · ${escapeHtml(item.count)}×${item.last ? ` · ${escapeHtml(new Date(item.last * 1000).toLocaleTimeString())}` : ''}${item.action === 'blocked' ? ` · <b>${escapeHtml(T.ips_dropped)}</b>` : ''}</div>
      </div>`).join(''), {href: '/ui/ids#alerts', title: T.open_ids});
}

function firewallBox(sub) {
  return endBox('fa-shield', T.this_firewall_title, [sub]);
}

function localOrigin() {
  return (state.snapshot?.locations || []).find((entry) => entry.local)?.id || '';
}

function rateText(rateIn, rateOut, format = formatRate) {
  return `↓ ${escapeHtml(format(rateIn || 0))} ↑ ${escapeHtml(format(rateOut || 0))}`;
}

function flowModel(flow, context) {
  const {remoteBox, item, address} = context;
  const outbound = flow.initiated !== 'remote';
  const inside = (flow.inside || [])[0];
  const target = (flow.targets || [])[0];
  const name = (flow.services || [])[0];
  const service = serviceParts(target && !outbound ? target.service : name,
    target && !outbound && target.port ? `${target.port}/${target.protocol || 'tcp'}` : (flow.service_ports || {})[name]);
  const localBox = outbound
    ? (inside ? endBox('laptop', inside.name || inside.ip, [inside.name ? inside.ip : '', inside.interface]) : firewallBox(localOrigin()))
    : (target && !target.firewall ? endBox('laptop', target.name || target.ip, [target.name ? target.ip : '', target.interface])
      : firewallBox(localOrigin()));
  const flagged = (flow.lists || []).length > 0;
  return {
    verdict: flagged ? bigPill('danger', T.allowed_flagged, 'fa-exclamation-triangle') : bigPill('ok', T.allowed, 'fa-check'),
    sub: outbound ? T.started_inside_long : T.started_outside_long,
    diagram: {from: outbound ? localBox : remoteBox, service, rate: rateText(flow.rate_in, flow.rate_out),
      to: outbound ? remoteBox : localBox, blocked: false},
    connection: rows([
      [T.protocol, escapeHtml(`${service.name}${service.port ? ` (${service.port.split('/')[0]})` : ''}`)],
      [T.remote_port, outbound && service.port ? escapeHtml(service.port.split('/')[1]) : ''],
      [T.other_services, (flow.services || []).slice(1).map(escapeHtml).join(', ')],
      [T.state, (flow.activity || 0) > 0 ? pill('ok', T.active, 'fa-check') : pill('muted', T.idle)],
      [T.started, flow.age ? escapeHtml(`${ago(Date.now() / 1000 - flow.age)} ${T.ago}`) : ''],
      [T.transferred, flow.transferred ? rateText(flow.transferred[0], flow.transferred[1], formatBytes) : ''],
      [T.current_rate, rateText(flow.rate_in, flow.rate_out)],
      [T.duration, flow.age ? escapeHtml(spanText(flow.age)) : ''],
      [T.connections, escapeHtml(flow.states)],
    ]),
    firewall: rows([
      [T.decision, pill('ok', T.allowed, 'fa-check')],
      [T.interface, escapeHtml(inside?.interface || target?.interface || flow.egress || '')],
      [T.rule, escapeHtml(flow.rule || '')],
      [T.egress, escapeHtml(flow.egress || '')],
      ['NAT', inside && outbound ? escapeHtml(`${T.yes} (${inside.ip} → ${flow.origin})`)
        : target && !target.firewall ? escapeHtml(`${T.port_forward} (${flow.origin} → ${hostPort(target.ip, target.port)})`) : escapeHtml(T.no)],
    ]),
    ids: idsCard(flow.ids, null),
    reputation: reputationCard({...item, address, lists: flow.lists, abuseipdb: flow.abuseipdb}),
  };
}

function idsFlowModel(ids, context) {
  const {remoteBox, item, address} = context;
  const inside = ids.inside_host;
  const insideBox = inside ? endBox('laptop', inside.name || inside.ip, [inside.name ? ids.inside : '', inside.interface])
    : firewallBox(ids.public);
  // "[2001:db8::1]:443" or "192.0.2.1:443": the port is the last part, not the first colon's
  const [, port] = splitHostPort(ids.remote);
  const [publicAddress] = splitHostPort(ids.public);
  const [insideAddress] = splitHostPort(ids.inside);
  const service = {name: ids.protocol.toUpperCase(), port: port ? `${ids.protocol.toUpperCase()}/${port}` : ''};
  const serious = ids.severity <= 2 || (ids.lists || []).length > 0;
  const verdicts = {
    ok: bigPill('ok', T.allowed, 'fa-check'),
    danger: bigPill('danger', T.allowed_flagged, 'fa-exclamation-triangle'),
    blocked: bigPill('blocked', ids.ips_dropped ? T.ips_dropped_title : T.blocked, 'fa-ban'),
    contained: bigPill('contained', ids.ips_dropped ? T.ips_dropped_flagged : T.blocked_flagged, 'fa-ban'),
  };
  return {
    verdict: verdicts[idsOutcome(ids)],
    sub: ids.remote_started ? T.started_outside_long : T.started_inside_long,
    diagram: {from: ids.remote_started ? remoteBox : insideBox, service, rate: rateText(ids.bytes_in, ids.bytes_out, formatBytes),
      to: ids.remote_started ? insideBox : remoteBox, blocked: false},
    connection: rows([
      [T.protocol, escapeHtml(ids.protocol.toUpperCase())],
      [T.inside_side, escapeHtml(ids.inside || T.this_firewall)],
      [T.via, escapeHtml(ids.public)],
      [T.remote_side, escapeHtml(ids.remote)],
      [T.state, ids.active ? pill('ok', T.active, 'fa-check') : pill('muted', T.closed)],
      [T.started, ids.age ? escapeHtml(`${ago(Date.now() / 1000 - ids.age)} ${T.ago}`) : ''],
      [T.transferred, rateText(ids.bytes_in, ids.bytes_out, formatBytes)],
    ]),
    firewall: rows([
      [T.decision, pill('ok', T.allowed, 'fa-check')],
      [T.interface, escapeHtml(ids.interface || '')],
      [T.rule, escapeHtml(ids.rule || '')],
      ['NAT', ids.inside && insideAddress !== publicAddress ? escapeHtml(`${T.yes} (${ids.inside} → ${ids.public})`) : escapeHtml(T.no)],
      ['IPS', ids.ips_dropped ? pill(serious ? 'contained' : 'blocked', T.ips_dropped) : ''],
    ]),
    ids: idsCard(null, ids.groups),
    reputation: reputationCard({...item, address}),
  };
}

function blockModel(block, context) {
  const {remoteBox, item, address} = context;
  const service = serviceParts(block.services?.[0]?.name, block.services?.[0]?.port);
  const flagged = (block.lists || []).length > 0;
  return {
    verdict: flagged ? bigPill('contained', T.blocked_flagged, 'fa-ban') : bigPill('blocked', T.blocked, 'fa-ban'),
    sub: T.blocked_attempts,
    diagram: {from: remoteBox, service, rate: `${escapeHtml(block.hits)}× ${escapeHtml(T.in_minutes.replace('%s', block.window_minutes))}`,
      to: endBox('fa-shield', T.this_firewall_title, [block.target, block.interface]), blocked: true},
    connection: rows([
      [T.tried, (block.services || []).map((entry) => {
        const parts = serviceParts(entry.name, entry.port);
        return `${escapeHtml(parts.name)} <span class="fwmap-muted">${escapeHtml(parts.port)}</span> ×${escapeHtml(entry.hits)}`;
      }).join('<br>')],
      [T.other_ports, block.port_count > (block.services || []).length ? escapeHtml(block.port_count - block.services.length) : ''],
      [T.attempts, escapeHtml(`${block.hits} · ${block.hits_per_minute}/min`)],
      [T.first_seen, block.seconds ? escapeHtml(`${ago(Date.now() / 1000 - block.seconds)} ${T.ago}`) : ''],
    ]),
    firewall: rows([
      [T.decision, pill('blocked', T.blocked, 'fa-ban')],
      [T.interface, escapeHtml(block.interface || '')],
      [T.rule, escapeHtml(block.rule || '')],
      [T.target, escapeHtml(block.target || '')],
    ]),
    ids: idsCard(block.ids, null),
    reputation: reputationCard({...item, address}),
  };
}

function alertModel(alert, context) {
  const {item, address} = context;
  // flagged but with no connection known to have got through: amber, as on the map
  const flagged = alert?.ids?.severity <= 2 || (alert?.lists || []).length;
  return {
    verdict: flagged ? bigPill('contained', `${T.ids_only} · ${T.flagged}`, 'fa-flag') : bigPill('muted', T.ids_only, 'fa-flag'),
    sub: T.ids_only_sub,
    diagram: null,
    connection: `<div class="text-muted">${escapeHtml(T.no_connection)}</div>`,
    firewall: `<div class="text-muted">${escapeHtml(T.no_connection)}</div>`,
    ids: idsCard(alert?.ids, null),
    reputation: reputationCard({...item, address}),
  };
}

/** Everything the panel shows for one remote address of the selection. */
function detailsModel(selection, address) {
  const flow = selection.kind === 'flow' ? (selection.members || []).find((member) => member.dest === address) : null;
  const block = selection.kind === 'blocked' ? selection.block : null;
  const alert = selection.kind === 'alert' ? selection.alert : null;
  const ids = selection.kind === 'idsflow' ? selection.idsFlow : null;
  const location = (state.snapshot?.locations || []).find((entry) => entry.id === address) || {};
  const source = block || alert || ids || {};
  const item = {...location, ...source, country_code: source.country_code || location.country_code};
  const hostname = state.snapshot?.hostnames?.[address];
  const remote = {
    title: hostname || address, hostname, place: place(item), cc: item.country_code,
    org: state.settings.asn ? plain(item.as_org || '') : '',
  };
  const context = {item, address, remoteBox: endBox('fa-server', remote.title, [hostname ? address : '', remote.place])};
  const model = flow ? flowModel(flow, context) : ids ? idsFlowModel(ids, context)
    : block ? blockModel(block, context) : alertModel(alert, context);
  return {...model, remote};
}

function actionBar(address, countryCode) {
  const more = [
    `<li><a href="https://bgp.he.net/ip/${encodeURIComponent(address)}" target="_blank" rel="noopener noreferrer"><i class="fa fa-globe"></i> ${escapeHtml(T.whois)}</a></li>`,
    `<li><a href="https://www.abuseipdb.com/check/${encodeURIComponent(address)}" target="_blank" rel="noopener noreferrer"><i class="fa fa-external-link"></i> AbuseIPDB</a></li>`,
    `<li><a href="#" class="fwmap-copy" data-address="${escapeHtml(address)}"><i class="fa fa-clipboard"></i> ${escapeHtml(T.copy)}</a></li>`,
  ];
  if (state.isAdmin) {
    more.push('<li role="separator" class="divider"></li>',
      `<li><a href="#" class="fwmap-alias" data-address="${escapeHtml(address)}"><i class="fa fa-list-ul"></i> ${escapeHtml(T.add_to_alias)}</a></li>`,
      `<li><a href="#" class="fwmap-mark" data-address="${escapeHtml(address)}"><i class="fa fa-flag"></i> ${escapeHtml(T.mark_threat)}</a></li>`);
    if (countryCode) {
      more.push(`<li><a href="#" class="fwmap-country" data-code="${escapeHtml(countryCode)}"><i class="fa fa-map-marker"></i> ${escapeHtml(T.add_country)} (${escapeHtml(countryCode)})</a></li>`);
    }
  }
  const investigate = state.isAdmin
    ? `<button type="button" class="btn btn-primary fwmap-investigate" data-address="${escapeHtml(address)}">${ic('external')} ${escapeHtml(T.investigate)}</button>` : '';
  // a snapshot shows the states saved with it (to everyone who may see the snapshot) and the
  // current ones; killing states belongs to the live map
  const states = state.mode === 'snapshot' ? `
    <button type="button" class="btn btn-default fwmap-states" data-address="${escapeHtml(address)}">${ic('list')} ${escapeHtml(T.states_at)} ${escapeHtml(capturedTime())}</button>
    ${state.isAdmin ? `<button type="button" class="btn btn-default fwmap-states-now" data-address="${escapeHtml(address)}">${ic('clock')} ${escapeHtml(T.current_states)}</button>` : ''}`
    : state.isAdmin ? `
    <button type="button" class="btn btn-default fwmap-states" data-address="${escapeHtml(address)}">${ic('list')} ${escapeHtml(T.show_states)}</button>
    <button type="button" class="btn btn-default fwmap-kill" data-address="${escapeHtml(address)}">${ic('trash')} ${escapeHtml(T.kill_states)}</button>` : '';
  const admin = investigate + states;
  return `<div class="fwmap-actions">${admin}
    <div class="btn-group dropup"><button type="button" class="btn btn-default dropdown-toggle" data-toggle="dropdown" aria-haspopup="true">${escapeHtml(T.more)} <span class="caret"></span></button>
    <ul class="dropdown-menu dropdown-menu-right">${more.join('')}</ul></div></div>`;
}

/** "16:42" of the snapshot on screen. */
function capturedTime() {
  return new Date((state.frozen?.meta?.taken || 0) * 1000).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'});
}

function diagramHtml(diagram) {
  if (!diagram) {
    return '';
  }
  return `<div class="fwmap-diagram">${diagram.from}
    <div class="fwmap-link${diagram.blocked ? ' fwmap-link-blocked' : ''}"><div class="fwmap-link-service">${escapeHtml(diagram.service.name)}</div>
      <div class="fwmap-link-port">${escapeHtml(diagram.service.port)}</div>
      <div class="fwmap-link-arrow">${diagram.blocked ? ic('ban') : ''}</div>
      <div class="fwmap-link-rate">${diagram.rate}</div></div>
    ${diagram.to}</div>`;
}

export function renderDetails() {
  const selection = state.selection;
  const $details = $('#fwmap-details');
  const addresses = selection ? [...new Set(selection.addresses)].filter(Boolean) : [];
  if (!addresses.length) {
    $details.html(`<div class="text-muted fwmap-empty">${escapeHtml(T.click_hint)}</div>`);
    return;
  }
  if (!addresses.includes(state.detailsAddress)) {
    state.detailsAddress = addresses[0];
  }
  const address = state.detailsAddress;
  const model = detailsModel(selection, address);
  const picker = addresses.length > 1 ? `<div class="fwmap-picker"><span class="text-muted">${escapeHtml(addresses.length)} ${escapeHtml(T.remote_addresses_here)}</span>`
    + addresses.slice(0, 12).map((entry) => `<a href="#" class="fwmap-pick${entry === address ? ' active' : ''}" data-address="${escapeHtml(entry)}"`
      + `${entry === address ? ' aria-current="true"' : ''}>${escapeHtml(entry)}</a>`).join('')
    + '</div>' : '';
  const investigation = state.investigations.get(address);
  // re-rendering the same address (a lookup finishing, a check) keeps the reader's scroll position
  const same = state.renderedSelection === selection && state.renderedAddress === address;
  const scrollTop = same ? ($details.find('.fwmap-d-scroll').scrollTop() || 0) : 0;
  state.renderedSelection = selection;
  state.renderedAddress = address;
  $details.html(`
    <div class="fwmap-d-scroll">
      <div class="fwmap-d-head">
        ${ic('globe', 'fwmap-d-icon')}
        <div class="fwmap-d-title">
          <div class="fwmap-d-name">${escapeHtml(model.remote.title)}</div>
          <div class="fwmap-d-line">${model.remote.hostname ? `<b>${escapeHtml(address)}</b>` : ''}
            ${model.remote.place ? `<span>${model.remote.cc ? `${flagHtml(model.remote.cc)} ` : ''}${escapeHtml(model.remote.place)}</span>` : ''}</div>
          ${model.remote.org ? `<div class="fwmap-d-line">${escapeHtml(model.remote.org)}</div>` : ''}
        </div>
        <div class="fwmap-d-verdict">${model.verdict}<div class="fwmap-d-verdict-sub">${escapeHtml(model.sub)}</div></div>
        <a href="#" id="fwmap-details-close" title="${escapeHtml(T.close)}" aria-label="${escapeHtml(T.close)}">${ic('x')}</a>
      </div>
      ${state.mode === 'snapshot' ? `<div class="fwmap-snap-notice">${ic('camera')} ${escapeHtml(T.as_captured)} ${escapeHtml(capturedTime())} · ${escapeHtml(T.may_have_closed)}</div>` : ''}
      ${picker}
      ${diagramHtml(model.diagram)}
      <div class="fwmap-cards">
        ${card('fa-bar-chart', T.sec_connection, model.connection, state.isAdmin || state.mode === 'snapshot' ? {cls: 'fwmap-states', address, title: T.show_states} : null)}
        ${card('fa-shield', T.sec_firewall, model.firewall, {href: '/ui/diagnostics/firewall/log', title: T.open_log})}
        ${model.ids}
        ${model.reputation}
      </div>
      ${investigation ? `<div class="fwmap-investigation">${investigation}</div>` : ''}
    </div>
    ${actionBar(address, selection.countryCode)}
  `);
  if (scrollTop) {
    $details.find('.fwmap-d-scroll').scrollTop(scrollTop);
  }
  // Investigate: one slow scroll that brings the lookup's card to the top of the panel. The card
  // keeps at least the panel's height, so it can reach the top and the data arriving mid-scroll
  // (a re-render) neither stops the scroll nor makes it jump.
  const scroller = $details.find('.fwmap-d-scroll')[0];
  const lookupCard = $details.find('.fwmap-investigation')[0];
  const now = performance.now();
  if (state.revealInvestigation === address) {
    state.revealing = {address, until: now + REVEAL_MS};
  }
  const revealing = state.revealing?.address === address && now < state.revealing.until;
  if (scroller && lookupCard && state.revealing?.address === address) {
    lookupCard.style.minHeight = `${Math.max(0, scroller.clientHeight - 16)}px`;
  }
  if (scroller && lookupCard && revealing) {
    const top = scroller.scrollTop + lookupCard.getBoundingClientRect().top - scroller.getBoundingClientRect().top - 8;
    $(scroller).stop().animate({scrollTop: top}, Math.max(0, state.revealing.until - now), 'swing');
  }
}
