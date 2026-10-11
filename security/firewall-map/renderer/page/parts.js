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

/* Building blocks of the details panel and Threats. */
import {escapeHtml, fill, plain} from '../src/format.js';
import {idsSummary} from '../src/summaries.js';
import {T, TEXT} from './context.js';
import {ic} from './icons.js';

/**
 * A status pill, tinted like the Dashboard Plus state pills: `color` (success, danger, warning or
 * default) picks the theme's state color for the fill, border and icon, and the label mixes it with
 * the text color. `icon` is a Font Awesome name, or 'dot' for a plain state. `big` is the details
 * panel's verdict.
 */
export function pill(color, text, icon, big = false) {
  const mark = icon === 'dot' ? '<span class="fwmap-pill-dot" aria-hidden="true"></span>' : icon ? ic(icon) : '';
  return `<span class="fwmap-pill fwmap-pill-${color}${big ? ' fwmap-pill-lg' : ''}">${mark}${escapeHtml(text)}</span>`;
}

export function bigPill(color, text, icon) {
  return pill(color, text, icon, true);
}

/** A label/value table; rows with no value are left out. Values are HTML. */
export function rows(items, className = 'fwmap-kv') {
  return `<table class="table table-condensed ${className}">${items.filter(([, value]) => value !== null && value !== undefined && value !== '')
    .map(([label, value]) => `<tr><th>${escapeHtml(label)}</th><td>${value}</td></tr>`).join('')}</table>`;
}

export function place(item) {
  return [item.city, item.country].filter(Boolean).map(plain).join(', ');
}

/** One box of the connection diagram: a host on either end. */
export function endBox(icon, name, lines) {
  return `<div class="well well-sm fwmap-end">${ic(icon, 'text-primary fwmap-end-ic')}<div class="fwmap-end-name">${escapeHtml(name)}</div>`
    + lines.filter(Boolean).map((line) => `<div class="fwmap-end-sub">${escapeHtml(line)}</div>`).join('') + '</div>';
}

/**
 * A panel of the details panel: icon, title and a chevron that opens the related view. A table
 * body sits flush in the panel, anything else in its body.
 */
export function card(icon, title, body, action) {
  const chevron = action ? `<a href="${action.href || '#'}" class="pull-right fwmap-card-go ${action.cls || ''}"${action.href ? ' target="_blank" rel="noopener"' : ''}`
    + `${action.address ? ` data-address="${escapeHtml(action.address)}"` : ''} title="${escapeHtml(action.title)}" aria-label="${escapeHtml(action.title)}">${ic('chevron-right')}</a>` : '';
  return `<section class="panel panel-default fwmap-card"><div class="panel-heading">${chevron}${ic(icon)} <b>${escapeHtml(title)}</b></div>`
    + (body.startsWith('<table') ? body : `<div class="panel-body">${body}</div>`) + '</section>';
}

export function serviceParts(name, port) {
  const raw = /^(TCP|UDP)\/(\d+)$/.exec(name || '');
  if (raw) {
    // an unnamed port: say so once instead of "TCP 10512 · TCP/10512"
    return {name: `${T.port_word} ${raw[2]}`, port: `${raw[1]}/${raw[2]}`};
  }
  const [number, protocol] = String(port || '').split('/');
  return {name: plain(name || '—'), port: number ? `${(protocol || '').toUpperCase()}/${number}` : ''};
}

/** Suricata's alerts for an address, worst signature first. */
export function idsLines(ids, text) {
  if (!ids) {
    return '';
  }
  const cls = ids.severity <= 2 ? 'fwmap-ids text-danger fwmap-ids-high' : 'fwmap-ids';
  return idsSummary(ids, text).map((line) => `<div class="${cls}">${ic('flag')} ${escapeHtml(line)}</div>`).join('');
}

const unit = (key, count) => fill(TEXT[key], {count});

/** "3 min", "2 h", "5 days" since an epoch time. */
export function ago(seconds) {
  const age = Math.max(0, Date.now() / 1000 - seconds);
  if (age < 90) {
    return unit('map_seconds', Math.round(age));
  }
  if (age < 5400) {
    return unit('map_minutes', Math.round(age / 60));
  }
  if (age < 129600) {
    return unit('map_hours', Math.round(age / 3600));
  }
  return unit('map_days', Math.round(age / 86400));
}

/** "3 min ago" for an epoch time. */
export function agoText(seconds) {
  return fill(T.time_ago, {time: ago(seconds)});
}

/** 8040 seconds read "2 h 14 min". */
export function spanText(seconds) {
  const minutes = Math.floor(seconds / 60);
  if (minutes < 1) {
    return unit('map_seconds', Math.round(seconds));
  }
  if (minutes < 60) {
    return unit('map_minutes', minutes);
  }
  const days = Math.floor(minutes / 1440);
  const hours = Math.floor((minutes % 1440) / 60);
  return days ? `${unit('map_days', days)} ${unit('map_hours', hours)}` : `${unit('map_hours', hours)} ${unit('map_minutes', minutes % 60)}`;
}
