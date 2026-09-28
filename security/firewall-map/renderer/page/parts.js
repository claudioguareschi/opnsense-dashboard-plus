/* Building blocks of the details panel and the review queue. */
import {escapeHtml, plain} from '../src/format.js';
import {idsSummary} from '../src/summaries.js';
import {T} from './context.js';
import {ic} from './icons.js';

/** A status pill; `big` is the verdict pill at the top of the details panel. */
export function pill(kind, text, icon, big = false) {
  const base = big ? 'fwmap-vpill' : 'fwmap-pill';
  return `<span class="${base} ${base}-${kind}">${icon ? `${ic(icon)} ` : ''}${escapeHtml(text)}</span>`;
}

export function bigPill(kind, text, icon) {
  return pill(kind, text, icon, true);
}

/** A label/value table; rows with no value are left out. Values are HTML. */
export function rows(items, className = 'fwmap-kv') {
  return `<table class="${className}">${items.filter(([, value]) => value !== null && value !== undefined && value !== '')
    .map(([label, value]) => `<tr><th>${escapeHtml(label)}</th><td>${value}</td></tr>`).join('')}</table>`;
}

export function place(item) {
  return [item.city, item.country].filter(Boolean).map(plain).join(', ');
}

/** One box of the connection diagram: a host on either end. */
export function endBox(icon, name, lines) {
  return `<div class="fwmap-end">${ic(icon)}<div class="fwmap-end-name">${escapeHtml(name)}</div>`
    + lines.filter(Boolean).map((line) => `<div class="fwmap-end-sub">${escapeHtml(line)}</div>`).join('') + '</div>';
}

/** A card of the details panel: icon, title and a chevron that opens the related view. */
export function card(icon, title, body, action) {
  const chevron = action ? `<a href="${action.href || '#'}" class="fwmap-card-go ${action.cls || ''}"${action.href ? ' target="_blank" rel="noopener"' : ''}`
    + `${action.address ? ` data-address="${escapeHtml(action.address)}"` : ''} title="${escapeHtml(action.title)}" aria-label="${escapeHtml(action.title)}">${ic('chevron')}</a>` : '';
  return `<section class="fwmap-card"><div class="fwmap-card-head">${ic(icon, 'fwmap-card-ic')}<span>${escapeHtml(title)}</span>${chevron}</div>`
    + `<div class="fwmap-card-body">${body}</div></section>`;
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
  const cls = ids.severity <= 2 ? 'fwmap-ids fwmap-ids-high' : 'fwmap-ids';
  return idsSummary(ids, text).map((line) => `<div class="${cls}">${ic('flag')} ${escapeHtml(line)}</div>`).join('');
}

/** "3 min", "2 h", "5 d" since an epoch time. */
export function ago(seconds) {
  const age = Math.max(0, Date.now() / 1000 - seconds);
  if (age < 90) {
    return `${Math.round(age)} s`;
  }
  if (age < 5400) {
    return `${Math.round(age / 60)} min`;
  }
  if (age < 129600) {
    return `${Math.round(age / 3600)} h`;
  }
  return `${Math.round(age / 86400)} d`;
}

/** 8040 seconds read "2 h 14 min". */
export function spanText(seconds) {
  const minutes = Math.floor(seconds / 60);
  if (minutes < 1) {
    return `${Math.round(seconds)} s`;
  }
  if (minutes < 60) {
    return `${minutes} min`;
  }
  const days = Math.floor(minutes / 1440);
  const hours = Math.floor((minutes % 1440) / 60);
  return days ? `${days} d ${hours} h` : `${hours} h ${minutes % 60} min`;
}
