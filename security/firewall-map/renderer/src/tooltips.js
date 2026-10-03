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
 * Hover cards: the same visual grammar as the page's details panel. Title and place, a verdict
 * pill, one block per address (host, network, the plain-language sentence, IDS lines), and a
 * muted footer. Status colours come from the palette as CSS variables (see cssVariables).
 */
import {escapeHtml, fill, flagHtml, formatRate, listLabel, plain, plural} from './format.js';
import {cssVariables} from './palette.js';
import {alertOutcome, blockSummary, flowSummary, idsFlowSummary, idsOutcome, idsSummary, outcome} from './summaries.js';

const ICONS = {
  check: '<path d="M20 6 9 17l-5-5"/>',
  ban: '<circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/>',
  flag: '<path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><path d="M4 22v-7"/>',
  alert: '<circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/>',
  server: '<rect x="3" y="3" width="18" height="7" rx="1.5"/><rect x="3" y="14" width="18" height="7" rx="1.5"/><path d="M7 6.5h.01M7 17.5h.01"/>',
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
};

const STYLE = `
.fmt{font-size:12px;line-height:1.4;padding:10px 12px;min-width:220px}
.fmt-head{display:flex;align-items:flex-start;gap:10px}
.fmt-head>div:first-child{flex:1;min-width:0}
.fmt-title{font-weight:600;font-size:13.5px;line-height:1.25}
.fmt-sub{opacity:.7;font-size:11.5px;margin-top:1px}
.fmt-pill{display:inline-flex;align-items:center;gap:3px;white-space:nowrap;font-weight:600;font-size:11px;padding:1px 8px;border-radius:10px}
.fmt-ok{background:var(--fwmap-ok);color:var(--fwmap-on-ok)}.fmt-danger{background:var(--fwmap-danger);color:var(--fwmap-on-danger)}
.fmt-blocked{background:var(--fwmap-blocked);color:var(--fwmap-on-blocked)}.fmt-muted{background:rgba(128,128,128,.22)}
.fmt-contained{background:var(--fwmap-contained);color:var(--fwmap-on-contained)}
.fmt-lists{margin-top:6px;display:flex;flex-wrap:wrap;gap:3px}
.fmt-chip{font-size:10.5px;font-weight:600;padding:0 6px;border-radius:3px;color:var(--fwmap-danger);border:1px solid var(--fwmap-danger)}
.fmt-tone-contained .fmt-chip{color:var(--fwmap-contained);border-color:var(--fwmap-contained)}
.fmt-tone-blocked .fmt-chip,.fmt-tone-ok .fmt-chip{color:inherit;border-color:rgba(128,128,128,.4)}
.fmt-addr{margin-top:8px;padding-top:7px;border-top:1px solid rgba(128,128,128,.2)}
.fmt-host{display:flex;align-items:center;gap:6px;font-weight:600}
.fmt-host .fmt-ic{color:var(--fwmap-accent);width:14px;height:14px}
.fmt-meta{opacity:.7;font-size:11.5px;margin-left:20px}
.fmt-say{margin:3px 0 0 20px}
.fmt-say.fmt-bad{font-weight:600}
.fmt-tone-danger .fmt-bad{color:var(--fwmap-danger)}
.fmt-tone-contained .fmt-bad{color:var(--fwmap-contained)}
.fmt-ids{margin:3px 0 0 20px;font-size:11.5px;opacity:.85;display:flex;gap:5px}
.fmt-ids.fmt-bad{font-weight:600;opacity:1}
.fmt-ids .fmt-ic{margin-top:2px}
.fmt-more{margin:6px 0 0 20px;opacity:.7;font-size:11.5px}
.fmt-foot{margin-top:8px;padding-top:6px;border-top:1px solid rgba(128,128,128,.2);opacity:.75;font-size:11.5px;display:flex;flex-wrap:wrap;gap:2px 12px}
.fmt-ic{width:12px;height:12px;flex:none;vertical-align:-2px}
.fmt-flag.flag-icon{width:16px;height:12px;background-size:cover;border-radius:2px;margin-right:4px;vertical-align:-1px;box-shadow:0 0 0 1px rgba(0,0,0,.1)}
`;

function ensureStyle() {
  if (!document.getElementById('fwmap-tooltip-style')) {
    const style = document.createElement('style');
    style.id = 'fwmap-tooltip-style';
    style.textContent = STYLE;
    document.head.appendChild(style);
  }
}

function icon(name) {
  return `<svg class="fmt-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${ICONS[name]}</svg>`;
}

function pill(kind, text, iconName) {
  return `<span class="fmt-pill fmt-${kind}">${iconName ? icon(iconName) : ''}${escapeHtml(text)}</span>`;
}

function head(title, sub, pillHtml) {
  return `<div class="fmt-head"><div><div class="fmt-title">${escapeHtml(title)}</div>`
    + `${sub ? `<div class="fmt-sub">${sub}</div>` : ''}</div>${pillHtml}</div>`;
}

function lists(names) {
  return (names || []).length
    ? `<div class="fmt-lists">${names.map((name) => `<span class="fmt-chip">${escapeHtml(listLabel(name))}</span>`).join('')}</div>` : '';
}

function placeOf(item) {
  const text = [item.city || item.region, item.country].filter(Boolean).map(plain).join(', ');
  const approximate = !item.city && item.accuracy_km ? ` (± ${item.accuracy_km} km)` : '';
  return text ? `${flagHtml(item.country_code, 'fmt-flag')}${escapeHtml(text + approximate)}` : '';
}

/** Hover cards for one map, written in its text table. */
export function cards(text) {
  const OUTCOME_PILLS = {
    ok: [text.map_allowed, 'check'],
    blocked: [text.map_blocked, 'ban'],
    contained: [text.map_flagged_blocked, 'ban'],
    danger: [text.map_flagged_allowed, 'alert'],
  };
  const outcomePill = (kind, label) => pill(kind, label || OUTCOME_PILLS[kind][0], OUTCOME_PILLS[kind][1]);
  const idsLines = (ids) => {
    const bad = ids && ids.severity <= 2;
    return idsSummary(ids, text).map((line) => `<div class="fmt-ids${bad ? ' fmt-bad' : ''}">${icon('flag')}`
      + `<span>${escapeHtml(line.replace(/^Suricata: /, ''))}</span></div>`).join('');
  };
  const address = (iconName, name, meta, sentences, bad, ids) =>
    `<div class="fmt-addr"><div class="fmt-host">${icon(iconName)}<span>${escapeHtml(name)}</span></div>`
    + `${meta ? `<div class="fmt-meta">${escapeHtml(meta)}</div>` : ''}`
    + sentences.map((sentence) => `<div class="fmt-say${bad ? ' fmt-bad' : ''}">${escapeHtml(sentence)}</div>`).join('')
    + idsLines(ids) + '</div>';
  const org = (item, showAsn) => (showAsn && item.asn ? `AS${item.asn} ${plain(item.as_org || '')}` : '');

  return {
    /** An endpoint (all flows to that place) or a single arch. */
    flows(place, members, locations, hostnames = {}, showAsn = true) {
      const rateIn = members.reduce((sum, flow) => sum + (flow.rate_in ?? 0), 0);
      const rateOut = members.reduce((sum, flow) => sum + (flow.rate_out ?? 0), 0);
      const services = [...new Set(members.flatMap((flow) => flow.services || []))].slice(0, 4);
      const egress = [...new Set(members.map((flow) => flow.egress).filter(Boolean))];
      const flagged = [...new Set(members.flatMap((flow) => flow.lists || []))];
      const sorted = members.slice().sort((a, b) => (b.rate ?? 0) - (a.rate ?? 0));
      const addresses = sorted.slice(0, 4).map((flow) => {
        const location = locations.get(flow.dest) || {};
        const hostname = hostnames?.[flow.dest];
        const remote = {ip: flow.dest, hostname, org: showAsn ? location.as_org : null, country: location.country};
        return address('server', hostname || flow.dest, [hostname ? flow.dest : '', org(location, showAsn)].filter(Boolean).join(' · '),
          flowSummary(flow, remote, text), flow.threat, flow.ids);
      });
      const title = [place.city || place.region, place.country].filter(Boolean).join(', ') || place.name || place.id;
      const more = members.length > 4 ? `<div class="fmt-more">${escapeHtml(plural(text, 'map_more_addresses', members.length - 4))}</div>` : '';
      const foot = [`↓ ${formatRate(rateIn)}  ↑ ${formatRate(rateOut)}`, egress.length ? fill(text.map_via, {egress: egress.map(plain).join(', ')}) : '',
        services.join(', ')].filter(Boolean).map((part) => `<span>${escapeHtml(part)}</span>`).join('');
      const tone = outcome({flagged: flagged.length > 0, stopped: false});
      return `<div class="fmt fmt-tone-${tone}">${head(title,
          members.length > 1 ? escapeHtml(plural(text, 'map_addresses', members.length)) : placeOf(place), outcomePill(tone))}
        ${lists(flagged)}${addresses.join('')}${more}<div class="fmt-foot">${foot}</div></div>`;
    },

    firewall(location, own) {
      const rateIn = own.reduce((sum, flow) => sum + (flow.rate_in ?? 0), 0);
      const rateOut = own.reduce((sum, flow) => sum + (flow.rate_out ?? 0), 0);
      return `<div class="fmt">${head(text.map_this_firewall_title, escapeHtml(location.id), '')}
        <div class="fmt-foot"><span>${escapeHtml(plural(text, 'map_active_links', own.length))}</span>`
        + `<span>${escapeHtml(`↓ ${formatRate(rateIn)}  ↑ ${formatRate(rateOut)}`)}</span></div></div>`;
    },

    idsFlow(flow, showAsn) {
      const serious = flow.severity <= 2;
      const signatures = flow.groups.flatMap((group) => group.signatures);
      const ids = {count: flow.count, severity: flow.severity, signatures, minutes: 60, last_seconds: flow.last_seconds};
      const tone = idsOutcome(flow);
      const label = flow.ips_dropped ? (serious ? text.map_ips_dropped_flagged : text.map_ips_dropped) : null;
      return `<div class="fmt fmt-tone-${tone}">${head(flow.city || flow.country || flow.dest, placeOf(flow), outcomePill(tone, label))}
        ${lists(flow.lists)}
        ${address('server', flow.remote, org(flow, showAsn), [idsFlowSummary(flow, text)], serious, ids)}
        <div class="fmt-foot"><span>${escapeHtml(flow.ips_dropped ? text.map_ids_connection_dropped : text.map_ids_connection)}</span>
          ${flow.rule ? `<span>${escapeHtml(fill(text.map_rule, {rule: plain(flow.rule)}))}</span>` : ''}</div></div>`;
    },

    /** An address Suricata alerted on that has no arc right now. */
    alert(item, showAsn) {
      const tone = alertOutcome(item);
      return `<div class="fmt fmt-tone-${tone}">${head(item.city || item.country || item.source, placeOf(item),
          pill(tone === 'contained' ? 'contained' : 'muted', tone === 'contained' ? text.map_seen_by_suricata_flagged : text.map_seen_by_suricata, 'flag'))}
        ${lists(item.lists)}
        ${address('server', item.source, org(item, showAsn), [], tone === 'contained', item.ids)}
        <div class="fmt-foot"><span>${escapeHtml(text.map_no_connection)}</span></div></div>`;
    },

    block(block, showAsn) {
      const bad = (block.lists || []).length > 0;
      const tone = outcome({flagged: bad, stopped: true});
      return `<div class="fmt fmt-tone-${tone}">${head(block.city || block.country || block.source, placeOf(block), outcomePill(tone))}
        ${lists(block.lists)}
        ${address('server', block.source, org(block, showAsn), [blockSummary(block, showAsn, text)], bad, block.ids)}
        <div class="fmt-foot"><span>${escapeHtml(fill(text.map_last_minute, {count: block.hits_per_minute}) + (block.threat ? text.map_hammering : ''))}</span></div></div>`;
    },
  };
}

/** The floating card element: on <body> (fixed position) so a widget never clips it. */
export function createTooltip(container) {
  ensureStyle();
  const element = document.createElement('div');
  element.style.cssText = 'position:fixed;z-index:2000;pointer-events:none;display:none;'
    + 'border-radius:6px;max-width:360px;box-shadow:0 4px 16px rgba(0,0,0,.14);';
  document.body.appendChild(element);
  const hide = () => {
    element.style.display = 'none';
  };
  container.addEventListener('mouseleave', hide);
  return {
    show(html, x, y, colors) {
      if (!html) {
        hide();
        return;
      }
      element.innerHTML = html;
      element.style.background = colors.tooltip.background;
      element.style.color = colors.tooltip.text;
      element.style.border = `1px solid ${colors.tooltip.border}`;
      for (const [name, value] of Object.entries(cssVariables(colors))) {
        element.style.setProperty(name, value);
      }
      element.style.display = 'block';
      // next to the pointer, flipped to the other side when it would leave the window
      const bounds = container.getBoundingClientRect();
      const width = element.offsetWidth;
      const height = element.offsetHeight;
      let left = bounds.left + x + 14;
      let top = bounds.top + y + 14;
      if (left + width > window.innerWidth - 4) {
        left = bounds.left + x - width - 14;
      }
      if (top + height > window.innerHeight - 4) {
        top = bounds.top + y - height - 14;
      }
      element.style.left = `${Math.max(4, left)}px`;
      element.style.top = `${Math.max(4, top)}px`;
    },
    hide,
    destroy() {
      container.removeEventListener('mouseleave', hide);
      element.remove();
    },
  };
}
