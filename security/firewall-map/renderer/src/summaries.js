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

/* Plain-language sentences about flows, blocks and Suricata alerts, and the outcome legend. */
import {fill, formatBytes, plain, plural, protocolLabel} from './format.js';
import {DEFAULT_TEXT} from './text.js';

export function duration(seconds, text = DEFAULT_TEXT) {
  if (!seconds || seconds < 60) {
    return null;
  }
  if (seconds < 5400) {
    return fill(text.map_minutes, {count: Math.round(seconds / 60)});
  }
  if (seconds < 172800) {
    return fill(text.map_hours, {count: Math.round(seconds / 3600)});
  }
  return fill(text.map_days, {count: Math.round(seconds / 86400)});
}

/** 'HTTPS (443/tcp)', 'port 9443/tcp' or 'ICMP'. */
function serviceLabel(name, port, text) {
  const raw = /^(TCP|UDP)\/(\d+)$/.exec(name || '');
  if (raw) {
    return fill(text.map_port, {port: `${raw[2]}/${raw[1].toLowerCase()}`});
  }
  return port ? `${plain(name)} (${port})` : plain(name || text.map_traffic);
}

function hostLabel(host) {
  return host.name ? `${plain(host.name)} (${host.ip})` : host.ip;
}

function isFirewall(target) {
  return target.firewall || target.name === 'firewall';
}

function remoteReached(flow, other, open, text) {
  const services = flow.services || [];
  const ports = flow.service_ports || {};
  const targets = flow.targets || [];
  const target = targets[0];
  let where = text.map_this_firewall;
  let service = serviceLabel(services[0], ports[services[0]], text);
  if (target) {
    where = isFirewall(target) ? text.map_this_firewall : hostLabel(target);
    const port = target.port ? `${target.port}/${target.protocol || 'tcp'}` : null;
    service = serviceLabel(target.service, port, text);
  }
  if (targets.length > 1) {
    where = plural(text, 'map_other_targets', targets.length - 1, {target: where});
  }
  return fill(target && !isFirewall(target) ? text.map_reached_forward : text.map_reached, {
    other, where, service,
    open: open ? fill(text.map_open_for, {duration: open}) : '',
  });
}

function localOpened(flow, other, open, text) {
  const services = flow.services || [];
  const ports = flow.service_ports || {};
  const inside = flow.inside || [];
  const who = inside.length
    ? (inside.length > 1 ? plural(text, 'map_other_hosts', inside.length - 1, {host: hostLabel(inside[0])}) : hostLabel(inside[0]))
    : text.map_this_firewall_title;
  const name = services[0] || '';
  const service = serviceLabel(name, ports[name], text);
  const values = {
    who, other,
    service: services.length > 1 ? plural(text, 'map_other_services', services.length - 1, {service}) : service,
  };
  let sentence;
  if (/^DNS/.test(name)) {
    sentence = fill(text.map_queried, values);
  } else if (name === 'NTP') {
    sentence = fill(text.map_synced, values);
  } else if (/^(SMTP|SMTPS|Submission)$/.test(name)) {
    sentence = fill(text.map_mailed, values);
  } else if (name === 'ICMP') {
    sentence = fill(text.map_pinged, values);
  } else {
    sentence = fill(text.map_opened, values);
  }
  return `${sentence}${open && name !== 'ICMP' ? fill(text.map_open_for, {duration: open}) : ''}.`;
}

/**
 * One plain-language sentence per direction of a flow, built only from what the collector saw:
 * who opened it, the service and port, the other side's name, network and country, how long.
 * `remote` is {ip, hostname, org, country}; the caller escapes the result.
 */
export function flowSummary(flow, remote, text = DEFAULT_TEXT) {
  const place = [remote.org, remote.country].filter(Boolean).map(plain).join(', ');
  const other = `${remote.hostname ? plain(remote.hostname) : remote.ip}${place ? ` (${place})` : ''}`;
  const open = duration(flow.age, text);
  const sentences = [];
  if (flow.initiated === 'remote' || flow.initiated === 'both') {
    sentences.push(remoteReached(flow, other, open, text));
  }
  if (flow.initiated !== 'remote') {
    sentences.push(localOpened(flow, other, open, text));
  }
  return sentences;
}

/** The same kind of sentence for a source the firewall blocked (from the filter log). */
export function blockSummary(block, showAsn = true, text = DEFAULT_TEXT) {
  const place = [showAsn ? block.as_org : null, block.country].filter(Boolean).map(plain).join(', ');
  const services = (block.services || []).slice(0, 2).map((service) => serviceLabel(service.name, service.port, text));
  const others = Math.max(0, (block.port_count || services.length) - services.length);
  let tried = text.map_a_connection;
  if (others) {
    tried = plural(text, 'map_other_ports', others, {services: services.join(', ')});
  } else if (services.length > 1) {
    tried = fill(text.map_two_services, {first: services[0], second: services[1]});
  } else if (services.length) {
    tried = services[0];
  }
  const since = duration(block.seconds, text);
  const sentence = block.rule && block.interface ? 'map_block_sentence_rule_interface'
    : block.rule ? 'map_block_sentence_rule' : block.interface ? 'map_block_sentence_interface' : 'map_block_sentence';
  return fill(text[sentence], {
    source: block.source,
    place: place ? ` (${place})` : '',
    tried,
    hits: block.hits ?? block.hits_per_minute,
    minutes: block.window_minutes ?? 1,
    rule: plain(block.rule || ''),
    interface: plain(block.interface || ''),
    since: since ? fill(text.map_first_seen_ago, {duration: since}) : '',
  });
}

/**
 * Suricata's view of an address in one line per signature, worst first:
 * 'Suricata: ET SCAN Potential SSH Scan (severity 2), 3× in the last hour, latest 2 min ago'.
 * `source: false` leaves out the "Suricata:" (where an IDS icon already says it).
 */
export function idsSummary(ids, text = DEFAULT_TEXT, {source = true} = {}) {
  if (!ids || !ids.count) {
    return [];
  }
  const latest = duration(ids.last_seconds, text) || text.map_moments;
  const window = ids.minutes >= 60 ? fill(text.map_hours, {count: Math.round(ids.minutes / 60)})
    : fill(text.map_minutes, {count: ids.minutes});
  const lines = (ids.signatures || []).map((item, index) => {
    const line = fill(text.map_ids_line, {signature: plain(item.signature), severity: item.severity,
      category: item.category ? `, ${plain(item.category)}` : ''})
      + (index === 0 ? fill(text.map_ids_first, {count: item.count, window, latest}) : fill(text.map_ids_count, {count: item.count}));
    return source ? fill(text.map_ids_source, {line}) : line;
  });
  const shown = (ids.signatures || []).reduce((sum, item) => sum + item.count, 0);
  if (ids.count > shown) {
    lines.push(plural(text, 'map_more_alerts', ids.count - shown));
  }
  return lines;
}

/** One-line description of a connection Suricata alerted on. */
export function idsFlowSummary(flow, text = DEFAULT_TEXT) {
  const inside = flow.inside_host?.name ? `${plain(flow.inside_host.name)} (${flow.inside})` : (flow.inside || text.map_this_firewall);
  const who = flow.remote_started ? `${flow.remote} → ${inside}` : `${inside} → ${flow.remote}`;
  const state = flow.active ? fill(text.map_open_state, {duration: duration(flow.age, text) || text.map_moments}) : text.map_closed;
  return `${who} ${protocolLabel(flow.protocol)} · ${state} · ↓ ${formatBytes(flow.bytes_in)} ↑ ${formatBytes(flow.bytes_out)}`;
}

/**
 * One color legend everywhere (badges, arcs, markers): green allowed and not flagged, gray
 * blocked and not flagged, amber flagged but stopped (firewall or IPS), red flagged and let
 * through. Flagged means a blocklist, an AbuseIPDB report or a Suricata severity 1-2 alert; the
 * collector already folds all three into an address's lists.
 */
export function outcome({flagged, stopped}) {
  if (flagged) {
    return stopped ? 'contained' : 'danger';
  }
  return stopped ? 'blocked' : 'ok';
}

/** Outcome of a connection Suricata alerted on. */
export function idsOutcome(flow) {
  const flagged = flow.severity <= 2 || (flow.lists || []).length > 0;
  return outcome({flagged, stopped: flow.kind === 'blocked' || Boolean(flow.ips_dropped)});
}

/** Outcome of an address Suricata alerted on with no connection known to have got through. */
export function alertOutcome(alert) {
  return alert.ids?.severity <= 2 || (alert.lists || []).length > 0 ? 'contained' : 'blocked';
}
