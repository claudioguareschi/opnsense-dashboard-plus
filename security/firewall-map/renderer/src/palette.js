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

/* Colors: the map palette derived from the OPNsense theme, and service categories. */

const DEFAULT_THEME = {
  dark: true,
  background: [7, 17, 31],
  text: [169, 200, 217],
  accent: [45, 212, 191],
  success: [76, 175, 80],
  warning: [240, 173, 78],
};

export function rgb(color, alpha = 255) {
  return [color[0], color[1], color[2], alpha];
}

export function mix(a, b, amount) {
  return a.map((value, index) => Math.round(value + (b[index] - value) * amount));
}

const ORANGE = [240, 140, 0];

/** Perceived brightness of an [r, g, b] color, 0 to 1 (Rec. 709 weights, no gamma): a quick light/dark test. */
function brightness(color) {
  return (0.2126 * color[0] + 0.7152 * color[1] + 0.0722 * color[2]) / 255;
}

/** WCAG relative luminance of an [r, g, b] color (gamma-corrected), for contrast ratios. */
function relativeLuminance(color) {
  const channel = (value) => {
    const c = value / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(color[0]) + 0.7152 * channel(color[1]) + 0.0722 * channel(color[2]);
}

function contrast(a, b) {
  const [light, dark] = [relativeLuminance(a), relativeLuminance(b)].sort((x, y) => y - x);
  return (light + 0.05) / (dark + 0.05);
}

/**
 * The theme's color pushed away from the background until it stands out by `ratio` (WCAG
 * contrast for graphics and large text is 3:1): lighter on dark themes, darker on light ones.
 */
function standOut(color, background, dark, ratio = 3) {
  const target = dark ? [255, 255, 255] : [0, 0, 0];
  let result = color.slice(0, 3);
  for (let step = 1; step <= 10 && contrast(result, background) < ratio; step += 1) {
    result = mix(color.slice(0, 3), target, step / 10);
  }
  return result;
}

/** Map palette derived from the dashboard theme so the widget blends in. */
export function palette(theme = DEFAULT_THEME) {
  const {dark, background, text, accent, success, warning} = {...DEFAULT_THEME, ...theme};
  const shade = (color, amount) => mix(color, dark ? [255, 255, 255] : text, amount);
  return {
    dark,
    accent,
    text,
    land: rgb(mix(background, accent, dark ? 0.12 : 0.07)),
    border: rgb(mix(background, mix(accent, text, 0.5), dark ? 0.45 : 0.35)),
    // towards the firewall uses the theme accent, away from it the theme's success green
    toward: {link: mix(background, accent, 0.7), heavy: shade(accent, 0.2), pulse: shade(accent, 0.15)},
    away: {link: mix(background, success, 0.7), heavy: shade(success, 0.2), pulse: shade(success, 0.15)},
    // a clear orange for connections started outside: the theme accent can be close to the threat crimson
    inbound: {link: mix(background, ORANGE, 0.75), heavy: mix(ORANGE, dark ? [255, 255, 255] : [0, 0, 0], 0.08), pulse: ORANGE},
    neutral: {link: mix(background, [150, 150, 150], 0.7), heavy: [128, 128, 128], pulse: [120, 120, 120]},
    endpoint: rgb(mix(accent, text, 0.2), 220),
    // the outcome legend: crimson for flagged traffic that got through, amber for flagged traffic
    // that was stopped, gray for ordinary blocks, green for ordinary allowed traffic (see outcome())
    danger: dark ? [255, 77, 109] : [196, 18, 48],
    contained: dark ? [245, 200, 60] : [222, 168, 0],
    blocked: dark ? [165, 165, 165] : [125, 125, 125],
    ok: dark ? [90, 190, 110] : [40, 150, 70],
    // a saved snapshot on screen: the theme's warning color, made to stand out on its background
    frozen: standOut(warning, background, dark),
    label: rgb(mix(text, background, 0.15), 230),
    tooltip: {
      background: `rgb(${background.join(',')})`,
      text: `rgb(${text.join(',')})`,
      border: `rgba(${accent.join(',')},0.35)`,
    },
    background: rgb(background),
  };
}

/**
 * The palette as CSS custom properties, so the page, Threats and the hover cards use
 * the same status colors as the map, in light and dark themes alike.
 */
export function cssVariables(colors) {
  const color = (value) => `rgb(${value.slice(0, 3).join(', ')})`;
  // readable text on a solid status color
  const on = (value) => (brightness(value) > 0.6 ? 'rgb(40, 30, 0)' : '#fff');
  return {
    '--fwmap-accent': color(colors.accent),
    '--fwmap-on-accent': on(colors.accent),
    '--fwmap-text': color(colors.text),
    '--fwmap-panel': color(colors.background),
    '--fwmap-danger': color(colors.danger),
    '--fwmap-on-danger': on(colors.danger),
    '--fwmap-contained': color(colors.contained),
    '--fwmap-on-contained': on(colors.contained),
    '--fwmap-blocked': color(colors.blocked),
    '--fwmap-on-blocked': on(colors.blocked),
    '--fwmap-ok': color(colors.ok),
    '--fwmap-on-ok': on(colors.ok),
    '--fwmap-frozen': color(colors.frozen),
    '--fwmap-on-frozen': on(colors.frozen),
    // a wash of it for banners and selected rows, readable with the theme's own text color
    '--fwmap-frozen-soft': `rgba(${colors.frozen.join(', ')}, ${colors.dark ? 0.16 : 0.14})`,
  };
}

/**
 * Read the dashboard theme's own colors (OPNsense themes don't expose CSS variables): the
 * background behind the map, body text, the link color (theme accent), the success green and the
 * warning color (saved snapshots).
 */
export function readTheme(element) {
  const parse = (value) => {
    const match = /rgba?\(([^)]+)\)/.exec(value || '');
    if (!match) {
      return null;
    }
    const [r, g, b, a = 1] = match[1].split(',').map((part) => parseFloat(part));
    return a === 0 ? null : [r, g, b];
  };
  let background = null;
  for (let node = element?.parentElement; node && !background; node = node.parentElement) {
    background = parse(getComputedStyle(node).backgroundColor);
  }
  background = background || [255, 255, 255];
  const text = parse(getComputedStyle(element).color) || [55, 55, 54];
  const probeColor = (probe) => {
    element.appendChild(probe);
    const color = parse(getComputedStyle(probe).color);
    probe.remove();
    return color;
  };
  const link = document.createElement('a');
  link.href = '#';
  const accent = probeColor(link) || [192, 62, 20];
  const success = document.createElement('span');
  success.className = 'text-success';
  const green = probeColor(success) || [76, 175, 80];
  const warning = document.createElement('span');
  warning.className = 'text-warning';
  const amber = probeColor(warning) || [240, 173, 78];
  return {dark: brightness(background) < 0.5, background, text, accent, success: green, warning: amber};
}

// categories for "color by service"; each flow uses its busiest service
const SERVICE_CATEGORIES = [
  ['Web', /^(HTTPS?|HTTP alt|HTTPS alt)$/],
  ['QUIC', /^QUIC$/],
  ['DNS', /^DNS/],
  ['NTP', /^NTP$/],
  ['VPN', /^(OpenVPN|WireGuard|IKE|IPsec NAT-T)$/],
  ['Mail', /^(SMTP|SMTPS|Submission|IMAP|IMAPS|POP3S)$/],
  ['Remote access', /^(SSH|RDP)$/],
  ['Push / STUN', /(Push|STUN)/],
];
// color-blind friendly categorical colors, none of them close to the crimson used for threats
export const CATEGORY_COLORS = [
  [0, 114, 178], [230, 159, 0], [0, 158, 115], [204, 121, 167],
  [86, 180, 233], [140, 109, 49], [27, 158, 158], [120, 94, 240], [150, 150, 150],
];

/** A category's name as shown (legend, filter): translated, while the English name stays the key. */
export function categoryLabel(name, text) {
  return text?.[`map_category_${String(name).toLowerCase().replace(/[^a-z]+/g, '_')}`] || name;
}

export function serviceCategory(service) {
  if (!service) {
    return 'Other';
  }
  const match = SERVICE_CATEGORIES.find(([, pattern]) => pattern.test(service));
  return match ? match[0] : 'Other';
}
