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
 * What the dashboard widget and the map page share around the renderer: theme application,
 * WebGL detection, the status line and the DB-IP credit. Exported as FirewallMapRenderer.host.
 */
import {escapeHtml, fill, formatBytes, plain, plural} from './format.js';
import {cssVariables, palette, readTheme} from './palette.js';
import {textTable} from './text.js';

export function hasWebGL() {
  try {
    const canvas = document.createElement('canvas');
    return Boolean(canvas.getContext('webgl2') || canvas.getContext('webgl'));
  } catch (_) {
    return false;
  }
}

/**
 * Color a map frame from the theme: its surface and border, the background grid, the text of
 * any overlays, and the palette's CSS variables on `root` (for pills, cards and the queue).
 */
export function applyTheme(frame, theme, {grid = null, overlays = [], root = frame} = {}) {
  const rgba = (color, alpha) => `rgba(${color.join(', ')}, ${alpha})`;
  frame.style.background = `rgb(${theme.background.join(', ')})`;
  frame.style.boxShadow = `inset 0 0 0 1px ${rgba(theme.accent, theme.dark ? 0.3 : 0.18)}`;
  if (grid) {
    const line = rgba(theme.text, theme.dark ? 0.07 : 0.05);
    grid.style.backgroundImage = `linear-gradient(${line} 1px, transparent 1px), linear-gradient(90deg, ${line} 1px, transparent 1px)`;
  }
  for (const overlay of overlays) {
    overlay.style.color = rgba(theme.text, 0.8);
  }
  for (const [name, value] of Object.entries(cssVariables(palette(theme)))) {
    root.style.setProperty(name, value);
  }
}

export {readTheme};

/**
 * The camera's flash over a map frame: a short warm wash in the theme's warning color (set by
 * applyTheme as --fwmap-frozen), so taking a snapshot is felt without a dialog.
 */
export function flash(frame) {
  const veil = document.createElement('div');
  veil.setAttribute('aria-hidden', 'true');
  Object.assign(veil.style, {
    position: 'absolute', inset: '0', zIndex: '5', pointerEvents: 'none', borderRadius: 'inherit',
    background: 'var(--fwmap-frozen-soft, rgba(255, 220, 160, .25))',
    boxShadow: 'inset 0 0 0 3px var(--fwmap-frozen, #e0a030)',
  });
  frame.appendChild(veil);
  const done = () => veil.remove();
  if (veil.animate) {
    veil.animate([{opacity: 0}, {opacity: 1, offset: 0.15}, {opacity: 0}], {duration: 650, easing: 'ease-out'}).onfinish = done;
  } else {
    setTimeout(done, 650);
  }
}

/**
 * A small notice at the bottom of a map frame (built from trusted HTML), gone after `ms`.
 * Returns the element, so a caller can bind its links.
 */
export function toast(frame, html, ms = 6000) {
  frame.querySelectorAll('.fwmap-toast').forEach((old) => old.remove());
  const note = document.createElement('div');
  note.className = 'fwmap-toast';
  note.setAttribute('role', 'status');
  Object.assign(note.style, {
    position: 'absolute', left: '50%', bottom: '44px', transform: 'translateX(-50%)', zIndex: '6',
    display: 'flex', alignItems: 'center', gap: '10px', maxWidth: 'calc(100% - 24px)', whiteSpace: 'nowrap',
    padding: '8px 10px 8px 14px', borderRadius: '10px', fontSize: '.92em',
    background: 'var(--fwmap-panel, #fff)', color: 'var(--fwmap-text, inherit)',
    border: '1px solid rgba(128, 128, 128, .35)', boxShadow: '0 6px 20px rgba(0, 0, 0, .25)',
  });
  note.innerHTML = html;
  frame.appendChild(note);
  setTimeout(() => note.remove(), ms);
  return note;
}

/**
 * The status line under a map, as HTML-escaped parts: flows, blocked sources, threats that got
 * through, CARP backup. `text` holds active_flows_one/_many, blocked_sources_one/_many,
 * below_threshold, listed_flows_one/_many, no_flows and carp_backup.
 */
export function statusParts(summary, shown, settings, text) {
  const parts = [];
  const count = shown.flows.length;
  parts.push(escapeHtml(count ? plural(text, 'active_flows', count) : text.no_flows));
  if (settings.blocks) {
    const blocked = (shown.blocks || []).length;
    const below = summary.blocks_below || 0;
    if (blocked || below) {
      parts.push(escapeHtml(plural(text, 'blocked_sources', blocked)));
      if (below) {
        parts.push(escapeHtml(plural(text, 'below_threshold', below)));
      }
    }
  }
  const threats = shown.flows.filter((flow) => flow.threat).length;
  if (threats && text.listed_flows_many) {
    parts.push(escapeHtml(plural(text, 'listed_flows', threats)));
  }
  if (summary.carp === 'backup') {
    parts.push(escapeHtml(text.carp_backup));
  }
  return parts;
}

/** DB-IP Lite is CC BY 4.0: credit it while it is the source. */
export function creditHtml(provider) {
  return provider === 'dbip' ? '<a href="https://db-ip.com" target="_blank" rel="noopener">IP Geolocation by DB-IP</a>' : '';
}

/** The status text for a summary that is not "ok" (starting, no database, failed), or null. */
export function problemText(summary, text) {
  if (summary.status === 'starting') {
    return text.starting;
  }
  if (summary.status === 'too_many_states') {
    return fill(text.too_many_states, {count: Number(summary.count).toLocaleString(), limit: Number(summary.limit).toLocaleString()});
  }
  if (summary.status === 'no_database') {
    return summary.reason === 'maxmind_key_missing' ? text.key_missing
      : summary.error ? `${text.database_failed}: ${plain(summary.error)}` : text.downloading;
  }
  return summary.status !== 'ok' ? text.unavailable : null;
}

/* The geolocation database card: shown over an empty map while the database downloads (a
 * progress bar) or after a download failed (what went wrong in plain words, a countdown to the
 * next automatic try and, for administrators, Retry now). Shared by the map page and the widget,
 * so its styles are added once here rather than in each. */

const PROVIDERS = {maxmind: 'MaxMind', maxmind_paid: 'MaxMind', dbip: 'DB-IP'};
const GEO_STYLES = `
.fwmap-geo-card { position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); z-index: 6; width: min(440px, calc(100% - 24px));
  padding: 16px 18px; border-radius: 10px; font-size: .92em; line-height: 1.4; text-align: left; background: var(--fwmap-panel, #fff);
  color: var(--fwmap-text, inherit); border: 1px solid rgba(128, 128, 128, .35); box-shadow: 0 6px 20px rgba(0, 0, 0, .18); }
.fwmap-geo-card .fwmap-geo-title { font-weight: 600; font-size: 1.05em; margin-bottom: 8px; display: flex; align-items: center; gap: 8px; }
.fwmap-geo-card .fwmap-geo-title .fa { opacity: .8; }
.fwmap-geo-card.fwmap-geo-failed .fwmap-geo-title .fa { color: var(--fwmap-contained, #d4a020); opacity: 1; }
.fwmap-geo-card p { margin: 0 0 8px; }
.fwmap-geo-card .progress { height: 14px; margin: 4px 0 6px; }
.fwmap-geo-card .fwmap-geo-sub { font-size: .9em; opacity: .7; }
.fwmap-geo-card .fwmap-geo-details { font-size: .85em; opacity: .6; word-break: break-word; margin-bottom: 10px; }
.fwmap-geo-card .fwmap-geo-actions { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
.fwmap-geo-countdown { font-variant-numeric: tabular-nums; }
.fwmap-geo-note { position: absolute; left: 50%; bottom: 44px; transform: translateX(-50%); z-index: 5; max-width: calc(100% - 24px);
  display: flex; align-items: center; gap: 8px; padding: 5px 6px 5px 10px; border-radius: 8px; font-size: .85em;
  background: var(--fwmap-panel, #fff); color: var(--fwmap-text, inherit); border: 1px solid rgba(128, 128, 128, .3);
  box-shadow: 0 2px 8px rgba(0, 0, 0, .12); }
.fwmap-geo-note .fa-triangle-exclamation { color: var(--fwmap-contained, #d4a020); }
.fwmap-geo-note span { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.fwmap-geo-note button { border: 0; background: transparent; color: inherit; opacity: .6; padding: 0 4px; }
`;

// the firewall's clock against the browser's, from the last status seen (for the countdowns)
let skew = 0;

function installGeo() {
  if (document.getElementById('fwmap-geo-styles')) {
    return;
  }
  const style = document.createElement('style');
  style.id = 'fwmap-geo-styles';
  style.textContent = GEO_STYLES;
  document.head.appendChild(style);
  // one ticker for every countdown on the page
  setInterval(tickCountdowns, 1000);
  // Retry now, wherever a card is (bound once, delegated)
  document.addEventListener('click', (event) => {
    const button = event.target.closest?.('.fwmap-geo-retry');
    if (!button || button.disabled) {
      return;
    }
    button.disabled = true;
    button.textContent = button.dataset.busy;
    window.jQuery.ajax({url: '/api/firewallmap/settings/retry_geodb', type: 'POST', dataType: 'json', contentType: 'application/json', data: '{}'})
      .fail(() => {
        button.disabled = false;
        button.textContent = button.dataset.label;
      });
  });
}

function countdownText(element) {
  const left = Math.max(0, Math.round(Number(element.dataset.at) - (Date.now() / 1000 - skew)));
  if (!left) {
    return element.dataset.retrying;
  }
  const time = `${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}`;
  return fill(element.dataset.template, {time});
}

/** Fill in the countdowns now (right after a card was inserted) rather than at the next tick. */
export function tickCountdowns() {
  document.querySelectorAll('.fwmap-geo-countdown').forEach((element) => {
    element.textContent = countdownText(element);
  });
}

function countdownHtml(geo, t) {
  if (!geo.retry_at) {
    return '';
  }
  return `<span class="fwmap-geo-countdown" data-at="${escapeHtml(geo.retry_at)}" data-template="${escapeHtml(t.geo_retry_in)}"`
    + ` data-retrying="${escapeHtml(t.geo_retrying)}"></span>`;
}

/** Each distinct problem once, in plain words. */
function explanations(geo, t) {
  const provider = PROVIDERS[geo.provider] || 'MaxMind';
  const codes = [...new Set((geo.errors || []).map((error) => error.code || 'other'))];
  return codes.map((code) => fill(t[`geo_err_${code}`] || t.geo_err_other, {provider}));
}

function geoCard(kind, icon, title, body) {
  return `<div class="fwmap-geo-card fwmap-geo-${kind}" role="status"><div class="fwmap-geo-title">`
    + `<i class="fa fa-fw ${icon}" aria-hidden="true"></i>${escapeHtml(title)}</div>${body}</div>`;
}

/**
 * The card for a map that has no geolocation database, or '' when the map has one. Its HTML only
 * changes when what it shows changes, so a caller can skip re-rendering an unchanged card (and
 * keep a pressed Retry button pressed).
 */
export function geoCardHtml(summary, text, {admin = false} = {}) {
  if (summary?.status !== 'no_database') {
    return '';
  }
  installGeo();
  const t = textTable(text);
  const geo = summary.geodb || {state: 'idle'};
  if (geo.now) {
    skew = Date.now() / 1000 - geo.now;
  }
  if (summary.reason === 'maxmind_key_missing') {
    // the status-line message starts with what the title already says ("…is needed: add it…")
    const advice = t.key_missing.includes(': ') ? t.key_missing.slice(t.key_missing.indexOf(': ') + 2) : t.key_missing;
    return geoCard('key', 'fa-key', t.geo_key_title, `<p>${escapeHtml(advice.charAt(0).toUpperCase() + advice.slice(1))}.</p>`);
  }
  if (geo.state === 'failed') {
    const retry = admin ? `<button type="button" class="btn btn-primary btn-sm fwmap-geo-retry" data-label="${escapeHtml(t.geo_retry_now)}"`
      + ` data-busy="${escapeHtml(t.geo_retrying)}">${escapeHtml(t.geo_retry_now)}</button>` : '';
    return geoCard('failed', 'fa-triangle-exclamation', t.geo_failed_title,
      explanations(geo, t).map((line) => `<p>${escapeHtml(line)}</p>`).join('')
      + `<div class="fwmap-geo-details">${(geo.errors || []).map((error) => escapeHtml(error.message || '')).join('<br>')}</div>`
      + `<div class="fwmap-geo-actions"><span class="fwmap-geo-sub">${countdownHtml(geo, t)}</span>${retry}</div>`);
  }
  if (geo.state === 'downloading' && geo.total) {
    const percent = Math.min(100, Math.round((geo.done / geo.total) * 100));
    return geoCard('downloading', 'fa-globe', t.geo_downloading_title,
      `<div class="fwmap-geo-sub">${escapeHtml(geo.edition || '')}</div>`
      + `<div class="progress"><div class="progress-bar" role="progressbar" aria-valuenow="${percent}" aria-valuemin="0" aria-valuemax="100"`
      + ` style="width: ${percent}%;">${percent}%</div></div>`
      + `<div class="fwmap-geo-sub">${escapeHtml(fill(t.geo_progress, {done: formatBytes(geo.done), total: formatBytes(geo.total)}))} · ${escapeHtml(t.geo_fills_in)}</div>`);
  }
  // starting, or a provider that does not say how big the file is: a moving bar
  const done = geo.state === 'downloading' && geo.done ? `${escapeHtml(geo.edition || '')} · ${escapeHtml(formatBytes(geo.done))}` : escapeHtml(t.geo_preparing);
  return geoCard('downloading', 'fa-globe', t.geo_downloading_title,
    '<div class="progress"><div class="progress-bar progress-bar-striped active" role="progressbar" style="width: 100%;"></div></div>'
    + `<div class="fwmap-geo-sub">${done} · ${escapeHtml(t.geo_fills_in)}</div>`);
}

/**
 * The small note for a map that works but whose AS database failed (network names missing), or
 * '' when there is none. `dismissed` is the key of a note the viewer closed.
 */
export function geoNoteHtml(summary, text, dismissed = null) {
  const geo = summary?.geodb;
  if (summary?.status !== 'ok' || geo?.state !== 'failed' || geoNoteKey(summary) === dismissed) {
    return '';
  }
  installGeo();
  const t = textTable(text);
  if (geo.now) {
    skew = Date.now() / 1000 - geo.now;
  }
  const why = explanations(geo, t).join(' ');
  // DB-IP standing in for MaxMind, only the AS database missing, or an update that failed while
  // the previous database keeps working
  const what = geo.fallback ? fill(t.geo_fallback, {provider: PROVIDERS[geo.fallback] || geo.fallback})
    : (geo.errors || []).every((error) => error.kind === 'asn') ? t.geo_partial : t.geo_stale;
  return `<div class="fwmap-geo-note" role="status" title="${escapeHtml(why)}"><i class="fa fa-triangle-exclamation" aria-hidden="true"></i>`
    + `<span>${escapeHtml(what)} · ${countdownHtml(geo, t)}</span>`
    + `<button type="button" class="fwmap-geo-note-close" aria-label="${escapeHtml(t.close || 'Close')}">&times;</button></div>`;
}

/** Which failure a note is about: closing it hides that failure, not the next one. */
export function geoNoteKey(summary) {
  return (summary?.geodb?.errors || []).map((error) => `${error.edition}:${error.code}`).join('|');
}
