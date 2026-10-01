/* Colours: the map palette derived from the OPNsense theme, and service categories. */

const DEFAULT_THEME = {
  dark: true,
  background: [7, 17, 31],
  text: [169, 200, 217],
  accent: [45, 212, 191],
  success: [76, 175, 80],
};

export function rgb(color, alpha = 255) {
  return [color[0], color[1], color[2], alpha];
}

export function mix(a, b, amount) {
  return a.map((value, index) => Math.round(value + (b[index] - value) * amount));
}

const ORANGE = [240, 140, 0];

/** Map palette derived from the dashboard theme so the widget blends in. */
export function palette(theme = DEFAULT_THEME) {
  const {dark, background, text, accent, success} = {...DEFAULT_THEME, ...theme};
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
    // that was stopped, grey for ordinary blocks, green for ordinary allowed traffic (see outcome())
    danger: dark ? [255, 77, 109] : [196, 18, 48],
    contained: dark ? [245, 200, 60] : [222, 168, 0],
    blocked: dark ? [165, 165, 165] : [125, 125, 125],
    ok: dark ? [90, 190, 110] : [40, 150, 70],
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
 * the same status colours as the map, in light and dark themes alike.
 */
export function cssVariables(colors) {
  const color = (value) => `rgb(${value.slice(0, 3).join(', ')})`;
  // readable text on a solid status colour
  const on = (value) => ((0.2126 * value[0] + 0.7152 * value[1] + 0.0722 * value[2]) / 255 > 0.6 ? 'rgb(40, 30, 0)' : '#fff');
  return {
    '--fwmap-accent': color(colors.accent),
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
  };
}

/**
 * Read the dashboard theme's own colours (OPNsense themes don't expose CSS variables): the
 * background behind the map, body text, the link colour (theme accent) and the success green.
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
  const luminance = (0.2126 * background[0] + 0.7152 * background[1] + 0.0722 * background[2]) / 255;
  return {dark: luminance < 0.5, background, text, accent, success: green};
}

// categories for "colour by service"; each flow uses its busiest service
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
// colour-blind friendly categorical colours, none of them close to the crimson used for threats
export const CATEGORY_COLORS = [
  [0, 114, 178], [230, 159, 0], [0, 158, 115], [204, 121, 167],
  [86, 180, 233], [140, 109, 49], [27, 158, 158], [120, 94, 240], [150, 150, 150],
];

export function serviceCategory(service) {
  if (!service) {
    return 'Other';
  }
  const match = SERVICE_CATEGORIES.find(([, pattern]) => pattern.test(service));
  return match ? match[0] : 'Other';
}
