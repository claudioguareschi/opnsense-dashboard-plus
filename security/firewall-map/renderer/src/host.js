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
import {escapeHtml, fill, plain, plural} from './format.js';
import {cssVariables, palette, readTheme} from './palette.js';

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
export function statusParts(snapshot, shown, settings, text) {
  const parts = [];
  const count = shown.flows.length;
  parts.push(escapeHtml(count ? plural(text, 'active_flows', count) : text.no_flows));
  if (settings.blocks) {
    const blocked = (shown.blocks || []).length;
    const below = snapshot.blocks_below || 0;
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
  if (snapshot.carp === 'backup') {
    parts.push(escapeHtml(text.carp_backup));
  }
  return parts;
}

/** DB-IP Lite is CC BY 4.0: credit it while it is the source. */
export function creditHtml(provider) {
  return provider === 'dbip' ? '<a href="https://db-ip.com" target="_blank" rel="noopener">IP Geolocation by DB-IP</a>' : '';
}

/** The status text for a snapshot that is not "ok" (starting, no database, failed), or null. */
export function problemText(snapshot, text) {
  if (snapshot.status === 'starting') {
    return text.starting;
  }
  if (snapshot.status === 'too_many_states') {
    return fill(text.too_many_states, {count: Number(snapshot.count).toLocaleString(), limit: Number(snapshot.limit).toLocaleString()});
  }
  if (snapshot.status === 'no_database') {
    return snapshot.reason === 'maxmind_key_missing' ? text.key_missing
      : snapshot.error ? `${text.database_failed}: ${plain(snapshot.error)}` : text.downloading;
  }
  return snapshot.status !== 'ok' ? text.unavailable : null;
}
