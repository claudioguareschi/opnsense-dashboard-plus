/* Text helpers shared by the renderer, the map page and the dashboard widget. */

// OPNsense HTML-escapes &, < and > in API responses (e.g. "AT&amp;T"), and its translations
// escape quotes; undo that before display (escapeHtml escapes again for HTML)
export function plain(text) {
  return String(text ?? '').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
    .replace(/&#0?39;/g, "'").replace(/&amp;/g, '&');
}

export function escapeHtml(text) {
  return plain(text).replace(/[&<>"']/g, (char) => `&#${char.charCodeAt(0)};`);
}

/** "{count} flows" with values filled in; a missing value leaves its placeholder empty. */
export function fill(template, values = {}) {
  return String(template ?? '').replace(/\{(\w+)\}/g, (_, key) => (values[key] ?? ''));
}

/** The singular or plural form of a text table entry: key_one / key_many (or key / key_many). */
export function plural(text, key, count, values = {}) {
  const template = count === 1 ? (text[`${key}_one`] ?? text[key]) : (text[`${key}_many`] ?? text[key]);
  return fill(template, {count, ...values});
}

export function formatRate(bytes) {
  const units = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
  let value = bytes || 0;
  let unit = 0;
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1000;
    unit++;
  }
  return `${value >= 100 || unit === 0 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`;
}

export function formatBytes(bytes) {
  return formatRate(bytes || 0).replace('/s', '');
}

/** "FWMAP_Spamhaus_DROP" reads as "Spamhaus DROP". */
export function listLabel(name) {
  return plain(name).replace(/^FWMAP_/, '').replace(/_/g, ' ');
}

/** A rectangular flag from OPNsense's flag-icon stylesheet, where the page loads it. */
export function flagHtml(code, className = 'fwmap-flag') {
  return /^[A-Za-z]{2}$/.test(code || '') && document.querySelector('link[href*="flag-icon"]')
    ? `<span class="flag-icon flag-icon-${code.toLowerCase()} ${className}"></span>` : '';
}

/** [address, port] from "192.0.2.1:443", "[2001:db8::1]:443" or a bare address. */
export function splitHostPort(text) {
  const value = String(text ?? '');
  const bracketed = /^\[([^\]]+)\](?::(\d+))?$/.exec(value);
  if (bracketed) {
    return [bracketed[1], bracketed[2] || ''];
  }
  const match = /^([^:]+):(\d+)$/.exec(value);
  return match ? [match[1], match[2]] : [value, ''];
}
