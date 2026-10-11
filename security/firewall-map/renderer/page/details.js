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
import {escapeHtml, fill, flagHtml, formatBytes, formatRate, hostPort, listLabel, plain, protocolLabel, splitHostPort} from '../src/format.js';
import {idsOutcome} from '../src/summaries.js';
import {ABUSEIPDB_BLACKLIST_LIST, ABUSEIPDB_LOOKUP_LIST, state, T} from './context.js';
import {ic} from './icons.js';
import {investigationPanel} from './investigate.js';
import {agoText, bigPill, card, endBox, pill, place, rows, serviceParts, spanText} from './parts.js';

// Investigate scrolls its card into view slowly enough to follow
const REVEAL_MS = 900;

/** What the map knows about a remote address: hostname, network, country. */
export function remoteOf(address) {
  const location = (state.data?.locations || []).find((item) => item.id === address) || {};
  return {
    ip: address,
    hostname: state.data?.hostnames?.[address],
    org: state.settings.asn ? location.as_org : null,
    country: location.country,
    country_code: location.country_code,
  };
}

function reputationCard(item) {
  const listed = new Set(item.lists || []);
  const lists = [...new Set([...(state.data?.threat_lists || []), ...listed])];
  const address = item.address;
  const score = item.abuseipdb ?? state.abuseScores.get(address);
  // already on the downloaded AbuseIPDB blacklist: that row says it all, no lookup to offer
  const blacklisted = listed.has(ABUSEIPDB_BLACKLIST_LIST);
  const known = score !== null && score !== undefined;
  let abuse;
  if (state.abuseChecking.has(address)) {
    abuse = `<span class="text-muted">${escapeHtml(T.checking)}</span>`;
  } else if (!known) {
    // a lookup is one click away when the firewall has an AbuseIPDB key
    abuse = state.can.manage && state.abuseConfigured
      ? `<a href="#" class="fwmap-abuse-check" data-address="${escapeHtml(address)}">${ic('magnifying-glass')} ${escapeHtml(T.check_now)}</a>`
      : `<span class="text-muted" title="${escapeHtml(T.abuseipdb_hint)}">${escapeHtml(T.no_key)}</span>`;
  } else {
    abuse = score >= 75 ? pill('danger', `${score}%`) : score >= 25 ? pill('warning', `${score}%`) : pill('success', T.clean, 'check');
  }
  // listed stands out in red; everything else reads as a quiet green "not listed"
  const notListed = `<span class="text-success text-nowrap">${ic('check')} ${escapeHtml(T.not_listed_short)}</span>`;
  const left = rows([
    ['AbuseIPDB', blacklisted && !known ? '' : abuse],
    ...lists.filter((name) => name !== ABUSEIPDB_LOOKUP_LIST).map((name) =>
      [listLabel(name), listed.has(name) ? pill('danger', T.listed, 'ban') : notListed]),
  ]);
  const right = rows([
    ['ASN', item.asn ? escapeHtml(`AS${item.asn}`) : ''],
    [T.organization, escapeHtml(plain(item.as_org || ''))],
    [T.country, item.country ? `${flagHtml(item.country_code)} ${escapeHtml(plain(item.country))}` : ''],
    // PF membership, shown apart from the geolocation it may disagree with
    [T.pf_sets, (item.sets || []).map((set) => `<span class="fwmap-pill fwmap-pill-default" title="${escapeHtml(
      set.category === 'country' ? T.set_country : T.set_operational)}">${escapeHtml(set.name)}</span>`).join(' ')],
  ]);
  return card('layer-group', T.sec_reputation, `<div class="fwmap-two">${left}${right}</div>`,
    state.can.manage ? {cls: 'fwmap-investigate', address, title: T.investigate} : null);
}

function idsCard(ids, groups) {
  const signatures = groups ? groups.flatMap((group) => group.signatures)
    : (ids?.signatures || []).map((item) => ({...item, last: null}));
  if (!signatures.length) {
    return card('magnifying-glass', T.sec_ids_long, `<div class="text-success">${ic('check')} ${escapeHtml(T.no_ids)}</div>
      <div class="text-muted">${escapeHtml(T.no_ids_sub)}</div>`,
    {href: '/ui/ids#alerts', title: T.open_ids});
  }
  const scope = groups ? T.ids_on_connection : T.ids_on_address;
  return card('magnifying-glass', T.sec_ids_long, `<div class="help-block">${escapeHtml(scope)}</div>`
    + signatures.map((item) => `<div class="fwmap-sig">
        <div class="${item.severity <= 2 ? 'text-danger fwmap-ids-high' : 'fwmap-ids'}">${ic('flag')} ${escapeHtml(item.signature)}</div>
        <div class="text-muted">${escapeHtml(T.severity)} ${escapeHtml(item.severity)}${item.category ? ` · ${escapeHtml(item.category)}` : ''}${item.sid ? ` · SID ${escapeHtml(item.sid)}` : ''}
          · ${escapeHtml(item.count)}×${item.last ? ` · ${escapeHtml(new Date(item.last * 1000).toLocaleTimeString())}` : ''}${item.action === 'blocked' ? ` · <b>${escapeHtml(T.ips_dropped)}</b>` : ''}</div>
      </div>`).join(''), {href: '/ui/ids#alerts', title: T.open_ids});
}

function firewallBox(sub) {
  return endBox('shield-halved', T.this_firewall_title, [sub]);
}

function localOrigin() {
  return (state.data?.locations || []).find((entry) => entry.local)?.id || '';
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
    verdict: flagged ? bigPill('danger', T.allowed_flagged, 'triangle-exclamation') : bigPill('success', T.allowed, 'check'),
    // a mirrored connection or a probe says so first: neither carries data here
    sub: flow.presence === 'mirror' ? T.mirror_sub
      : flow.presence === 'probe' ? fill(T.probe_sub, {count: Number(flow.attempts || 0).toLocaleString()})
        : outbound ? T.started_inside_long : T.started_outside_long,
    diagram: {from: outbound ? localBox : remoteBox, service, rate: rateText(flow.rate_in, flow.rate_out),
      to: outbound ? remoteBox : localBox, blocked: false},
    connection: rows([
      [T.protocol, escapeHtml(`${service.name}${service.port ? ` (${service.port.split('/')[0]})` : ''}`)],
      [T.remote_port, outbound && service.port ? escapeHtml(service.port.split('/')[1]) : ''],
      [T.other_services, (flow.services || []).slice(1).map(escapeHtml).join(', ')],
      [T.state, (flow.activity || 0) > 0 ? pill('success', T.active, 'check') : pill('default', T.idle, 'dot')],
      [T.started, flow.age ? escapeHtml(agoText(Date.now() / 1000 - flow.age)) : ''],
      [T.transferred, flow.transferred ? rateText(flow.transferred[0], flow.transferred[1], formatBytes) : ''],
      [T.current_rate, rateText(flow.rate_in, flow.rate_out)],
      [T.duration, flow.age ? escapeHtml(spanText(flow.age)) : ''],
      [T.connections, escapeHtml(flow.states)],
    ]),
    firewall: rows([
      [T.decision, pill('success', T.allowed, 'check')],
      [T.interface, escapeHtml(inside?.interface || target?.interface || flow.egress || '')],
      [T.rule, escapeHtml(flow.rule || '')],
      [T.egress, escapeHtml(flow.egress || '')],
      ['NAT', inside && outbound ? escapeHtml(`${T.yes} (${inside.ip} → ${flow.origin})`)
        : target && !target.firewall ? escapeHtml(`${T.port_forward} (${flow.origin} → ${hostPort(target.ip, target.port)})`) : escapeHtml(T.no)],
    ]),
    ids: idsCard(flow.ids, null),
    reputation: reputationCard({...item, address, lists: flow.lists, abuseipdb: flow.abuseipdb, sets: flow.sets}),
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
  const service = {name: protocolLabel(ids.protocol), port: port ? `${protocolLabel(ids.protocol)}/${port}` : ''};
  const serious = ids.severity <= 2 || (ids.lists || []).length > 0;
  const verdicts = {
    ok: bigPill('success', T.allowed, 'check'),
    danger: bigPill('danger', T.allowed_flagged, 'triangle-exclamation'),
    blocked: bigPill('default', ids.ips_dropped ? T.ips_dropped_title : T.blocked, 'ban'),
    contained: bigPill('warning', ids.ips_dropped ? T.ips_dropped_flagged : T.blocked_flagged, 'ban'),
  };
  return {
    verdict: verdicts[idsOutcome(ids)],
    sub: ids.remote_started ? T.started_outside_long : T.started_inside_long,
    diagram: {from: ids.remote_started ? remoteBox : insideBox, service, rate: rateText(ids.bytes_in, ids.bytes_out, formatBytes),
      to: ids.remote_started ? insideBox : remoteBox, blocked: false},
    connection: rows([
      [T.protocol, escapeHtml(protocolLabel(ids.protocol))],
      [T.inside_side, escapeHtml(ids.inside || T.this_firewall)],
      [T.via, escapeHtml(ids.public)],
      [T.remote_side, escapeHtml(ids.remote)],
      [T.state, ids.active ? pill('success', T.active, 'check') : pill('default', T.closed, 'dot')],
      [T.started, ids.age ? escapeHtml(agoText(Date.now() / 1000 - ids.age)) : ''],
      [T.transferred, rateText(ids.bytes_in, ids.bytes_out, formatBytes)],
    ]),
    firewall: rows([
      [T.decision, pill('success', T.allowed, 'check')],
      [T.interface, escapeHtml(ids.interface || '')],
      [T.rule, escapeHtml(ids.rule || '')],
      ['NAT', ids.inside && insideAddress !== publicAddress ? escapeHtml(`${T.yes} (${ids.inside} → ${ids.public})`) : escapeHtml(T.no)],
      ['IPS', ids.ips_dropped ? pill(serious ? 'warning' : 'default', T.ips_dropped) : ''],
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
    verdict: flagged ? bigPill('warning', T.blocked_flagged, 'ban') : bigPill('default', T.blocked, 'ban'),
    sub: T.blocked_attempts,
    diagram: {from: remoteBox, service, rate: `${escapeHtml(block.hits)}× ${escapeHtml(fill(T.in_minutes, {minutes: block.window_minutes}))}`,
      to: endBox('shield-halved', T.this_firewall_title, [block.target, block.interface]), blocked: true},
    connection: rows([
      [T.tried, (block.services || []).map((entry) => {
        const parts = serviceParts(entry.name, entry.port);
        return `${escapeHtml(parts.name)} <span class="text-muted">${escapeHtml(parts.port)}</span> ×${escapeHtml(entry.hits)}`;
      }).join('<br>')],
      [T.other_ports, block.port_count > (block.services || []).length ? escapeHtml(block.port_count - block.services.length) : ''],
      [T.block_attempts, escapeHtml(`${block.hits} · ${block.hits_per_minute}/min`)],
      [T.first_seen, block.seconds ? escapeHtml(agoText(Date.now() / 1000 - block.seconds)) : ''],
    ]),
    firewall: rows([
      [T.decision, pill('default', T.blocked, 'ban')],
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
    verdict: flagged ? bigPill('warning', `${T.ids_only} · ${T.flagged}`, 'flag') : bigPill('default', T.ids_only, 'flag'),
    sub: T.ids_only_sub,
    diagram: null,
    connection: `<div class="text-muted">${escapeHtml(T.no_connection)}</div>`,
    firewall: `<div class="text-muted">${escapeHtml(T.no_connection)}</div>`,
    ids: idsCard(alert?.ids, null),
    reputation: reputationCard({...item, address}),
  };
}

/** Everything the panel shows for one remote address of the selection. */
function detailsModel(selection, address, owner) {
  // a LAN host and the firewall itself can both talk to one address: one flow each (owner)
  const flow = selection.kind === 'flow' ? (selection.members || []).find((member) => member.dest === address
    && (owner === undefined || (member.owner ?? null) === owner)) : null;
  const block = selection.kind === 'blocked' ? selection.block : null;
  const alert = selection.kind === 'alert' ? selection.alert : null;
  const ids = selection.kind === 'idsflow' ? selection.idsFlow : null;
  const location = (state.data?.locations || []).find((entry) => entry.id === address) || {};
  const source = block || alert || ids || {};
  const item = {...location, ...source, country_code: source.country_code || location.country_code};
  const hostname = state.data?.hostnames?.[address];
  const remote = {
    title: hostname || address, hostname, place: place(item), cc: item.country_code,
    org: state.settings.asn ? plain(item.as_org || '') : '',
  };
  const context = {item, address, remoteBox: endBox('server', remote.title, [hostname ? address : '', remote.place])};
  const model = flow ? flowModel(flow, context) : ids ? idsFlowModel(ids, context)
    : block ? blockModel(block, context) : alertModel(alert, context);
  return {...model, remote};
}

function actionBar(address, countryCode) {
  const item = (cls, icon, label, extra = '') => `<li><a href="#" class="${cls}" ${extra}>${ic(icon)} ${escapeHtml(label)}</a></li>`;
  const more = [
    `<li><a href="https://bgp.he.net/ip/${encodeURIComponent(address)}" target="_blank" rel="noopener noreferrer">${ic('globe')} ${escapeHtml(T.whois)}</a></li>`,
    `<li><a href="https://www.abuseipdb.com/check/${encodeURIComponent(address)}" target="_blank" rel="noopener noreferrer">${ic('arrow-up-right-from-square')} AbuseIPDB</a></li>`,
    item('fwmap-copy', 'clipboard', T.copy, `data-address="${escapeHtml(address)}"`),
  ];
  if (state.can.aliases) {
    more.push('<li role="separator" class="divider"></li>',
      item('fwmap-alias', 'list', T.add_to_alias, `data-address="${escapeHtml(address)}"`),
      item('fwmap-mark', 'flag', T.mark_threat, `data-address="${escapeHtml(address)}"`));
    if (countryCode) {
      more.push(item('fwmap-country', 'location-dot', `${T.add_country} (${countryCode})`, `data-code="${escapeHtml(countryCode)}"`));
    }
  }
  const button = (cls, icon, label, color = 'default') =>
    `<button type="button" class="btn btn-${color} ${cls}" data-address="${escapeHtml(address)}">${ic(icon)} ${escapeHtml(label)}</button>`;
  const investigate = state.can.manage ? `<div class="btn-group btn-group-sm">${button('fwmap-investigate', 'magnifying-glass', T.investigate, 'primary')}</div>` : '';
  // a snapshot shows saved states only with the native Show States capability, and the
  // current ones; killing states belongs to the live map
  const states = state.mode === 'snapshot' && state.can.states
    ? [button('fwmap-states', 'list', `${T.states_at} ${capturedTime()}`), button('fwmap-states-now', 'clock', T.current_states)]
    : state.mode === 'snapshot' ? []
      : [state.can.states ? button('fwmap-states', 'list', T.show_states) : '', state.can.kill ? button('fwmap-kill', 'trash-can', T.kill_states) : ''];
  const group = states.filter(Boolean).length ? `<div class="btn-group btn-group-sm">${states.join('')}</div>` : '';
  return `<div class="btn-toolbar fwmap-actions">${investigate}${group}
    <div class="btn-group btn-group-sm dropup pull-right"><button type="button" class="btn btn-default dropdown-toggle" data-toggle="dropdown" aria-haspopup="true">${escapeHtml(T.more)} <span class="caret"></span></button>
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
    <div class="fwmap-link"><div class="fwmap-link-service">${escapeHtml(diagram.service.name)}</div>
      <div class="fwmap-link-port">${escapeHtml(diagram.service.port)}</div>
      <div class="fwmap-link-arrow">${diagram.blocked ? ic('ban', 'text-danger') : ''}</div>
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
  const here = selection.kind === 'flow' ? (selection.members || []).filter((member) => member.dest === address) : [];
  const owners = here.map((member) => member.owner ?? null);
  if (!owners.includes(state.detailsOwner)) {
    state.detailsOwner = owners.length ? owners[0] : undefined;
  }
  const model = detailsModel(selection, address, state.detailsOwner);
  // several flows to this address: who each belongs to, the inside host or this firewall
  const ownerPicker = here.length > 1 ? `<div class="fwmap-picker"><span class="text-muted">${escapeHtml(here.length)} ${escapeHtml(T.connections_here)}</span>`
    + here.map((member) => {
      const owner = member.owner ?? null;
      const label = owner ? (member.inside?.[0]?.name || owner) : T.this_firewall_title;
      const active = owner === state.detailsOwner;
      return `<a href="#" class="fwmap-pick-owner${active ? ' active' : ''}" data-owner="${escapeHtml(owner || '')}"`
        + `${active ? ' aria-current="true"' : ''}>${escapeHtml(label)}</a>`;
    }).join('') + '</div>' : '';
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
        ${ic('globe', 'text-muted fwmap-d-icon')}
        <div class="fwmap-d-title">
          <div class="fwmap-d-name">${escapeHtml(model.remote.title)}</div>
          <div class="fwmap-d-line">${model.remote.hostname ? `<b>${escapeHtml(address)}</b>` : ''}
            ${model.remote.place ? `<span>${model.remote.cc ? `${flagHtml(model.remote.cc)} ` : ''}${escapeHtml(model.remote.place)}</span>` : ''}</div>
          ${model.remote.org ? `<div class="fwmap-d-line">${escapeHtml(model.remote.org)}</div>` : ''}
        </div>
        <div class="fwmap-d-verdict">${model.verdict}<div class="fwmap-d-verdict-sub">${escapeHtml(model.sub)}</div></div>
        <button type="button" class="close" id="fwmap-details-close" title="${escapeHtml(T.close)}" aria-label="${escapeHtml(T.close)}"><span aria-hidden="true">&times;</span></button>
      </div>
      ${state.mode === 'snapshot' ? `<div class="alert alert-warning fwmap-snap-notice">${ic('camera')} ${escapeHtml(fill(T.as_captured_at, {time: capturedTime()}))} · ${escapeHtml(T.may_have_closed)}</div>` : ''}
      ${picker}
      ${ownerPicker}
      ${diagramHtml(model.diagram)}
      <div class="fwmap-cards">
        ${card('chart-column', T.sec_connection, model.connection, state.can.states ? {cls: 'fwmap-states', address, title: T.show_states} : null)}
        ${card('shield-halved', T.sec_firewall, model.firewall, {href: '/ui/diagnostics/firewall/log', title: T.open_log})}
        ${model.ids}
        ${model.reputation}
      </div>
      ${investigation ? investigationPanel(investigation) : ''}
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
