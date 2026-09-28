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
 * Colour a map frame from the theme: its surface and border, the background grid, the text of
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
