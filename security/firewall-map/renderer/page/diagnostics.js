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
 * The diagnostics panel (?debug=1 on the page URL): frame rate, frame cost, memory, GPU memory,
 * poll latency and WebGL context losses, with ten-minute plots, to watch the map for leaks and
 * load over a long session. A separate script, shipped in development packages only: the page
 * calls start() when it is installed and asked for. It sees the page through `page` (the
 * renderer, the mode, the WebGL reset count) and brings its own styles.
 */
const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'})[c]);
let page = {renderer: () => null, mode: () => '', contextLosses: () => 0};

const SAMPLE_MS = 1000;
const KEEP = 600;
const POLL_PATH = '/api/firewallmap/flow/summary';

const samples = [];
const polls = [];
let longTasks = 0;
let started = 0;

function observe() {
  try {
    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        if (entry.name.includes(POLL_PATH)) {
          polls.push({ms: entry.duration, bytes: entry.encodedBodySize || entry.transferSize || 0});
        }
      }
    }).observe({type: 'resource', buffered: false});
  } catch (_) {
    // resource timing unavailable: the poll row stays empty
  }
  try {
    // Chromium only: main-thread work over 50 ms
    new PerformanceObserver((list) => {
      longTasks += list.getEntries().length;
    }).observe({type: 'longtask', buffered: false});
  } catch (_) {
    longTasks = null;
  }
}

function sample() {
  const map = page.renderer()?.diagnostics?.() || {};
  const recent = polls.splice(0);
  const heap = performance.memory?.usedJSHeapSize;
  const point = {
    t: Math.round((Date.now() - started) / 1000),
    fps: map.animating ? map.framesComposed / (SAMPLE_MS / 1000) : 0,
    // deck.gl's measured CPU time per drawn frame; before its first report, our own layer building
    frameMs: map.cpuPerFrame || (map.framesComposed ? map.composeMs / map.framesComposed : 0),
    heapMb: heap ? heap / 1048576 : null,
    gpuMb: map.gpuMemory ? map.gpuMemory / 1048576 : null,
    nodes: document.getElementsByTagName('*').length,
    pollMs: recent.length ? Math.max(...recent.map((entry) => entry.ms)) : null,
    pollKb: recent.length ? recent[recent.length - 1].bytes / 1024 : null,
    arcs: map.arcs, blocks: map.blocks, pulses: map.pulses,
    contextLosses: page.contextLosses() || 0,
    longTasks,
    mode: page.mode(),
    hidden: document.hidden,
    // adaptive refresh: the last decision of the live map's refresh loop (src/refresh.js)
    refresh: page.refresh?.() || null,
  };
  samples.push(point);
  if (samples.length > KEEP) {
    samples.shift();
  }
  return point;
}

/** "4.5 s (interval 5 s, adaptive)" or "2 s (fallback: status)". */
function refreshText(refresh) {
  if (!refresh) {
    return 'n/a';
  }
  const delay = `${(refresh.delay / 1000).toFixed(1)} s`;
  return refresh.reason === 'adaptive' ? `${delay} (interval ${refresh.interval} s, adaptive)`
    : `${delay} (fallback: ${refresh.reason})`;
}

function cssColor(name, fallback) {
  const value = getComputedStyle(document.getElementById('fwmap-map')).getPropertyValue(name).trim();
  return value || fallback;
}

/** A sparkline of `key` over the kept samples, with its latest value and the range. */
function plot(canvas, key, color) {
  const values = samples.map((point) => point[key]).filter((value) => typeof value === 'number');
  const ratio = window.devicePixelRatio || 1;
  const width = canvas.clientWidth;
  const height = canvas.clientHeight;
  if (canvas.width !== width * ratio) {
    canvas.width = width * ratio;
    canvas.height = height * ratio;
  }
  const context = canvas.getContext('2d');
  context.setTransform(ratio, 0, 0, ratio, 0, 0);
  context.clearRect(0, 0, width, height);
  if (values.length < 2) {
    return '';
  }
  const low = Math.min(...values);
  const high = Math.max(...values);
  const span = high - low || 1;
  context.strokeStyle = color;
  context.lineWidth = 1.2;
  context.beginPath();
  // the newest sample at the right edge; the window grows from one minute to ten
  const slots = Math.min(KEEP, Math.max(60, values.length)) - 1;
  values.forEach((value, index) => {
    const x = width - ((values.length - 1 - index) / slots) * width;
    const y = height - 2 - ((value - low) / span) * (height - 4);
    if (index) {
      context.lineTo(x, y);
    } else {
      context.moveTo(x, y);
    }
  });
  context.stroke();
  return `${low.toFixed(low < 10 ? 1 : 0)}–${high.toFixed(high < 10 ? 1 : 0)}`;
}

const PLOTS = [
  {key: 'fps', label: 'FPS', unit: '', color: ['--fwmap-ok', '#5a9b3c']},
  {key: 'frameMs', label: 'Frame', unit: 'ms', color: ['--fwmap-accent', '#c03e14']},
  {key: 'heapMb', label: 'JS heap', unit: 'MB', color: ['--fwmap-contained', '#d4a020']},
  {key: 'gpuMb', label: 'GPU', unit: 'MB', color: ['--fwmap-blocked', '#888']},
  {key: 'pollMs', label: 'Poll', unit: 'ms', color: ['--fwmap-danger', '#b03030']},
];

function format(value, unit) {
  if (typeof value !== 'number') {
    return 'n/a';
  }
  return `${value.toFixed(value < 10 ? 1 : 0)}${unit ? ` ${unit}` : ''}`;
}

function uptime(seconds) {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return hours ? `${hours} h ${minutes} min` : `${minutes} min ${seconds % 60} s`;
}

function render(panel, point) {
  for (const item of PLOTS) {
    const row = panel.querySelector(`[data-plot="${item.key}"]`);
    if (!row) {
      continue;
    }
    const range = plot(row.querySelector('canvas'), item.key, cssColor(...item.color));
    // the latest measured value (a second without a poll keeps showing the last one)
    const latest = [...samples].reverse().find((entry) => typeof entry[item.key] === 'number')?.[item.key];
    row.querySelector('.fwmap-diag-value').textContent = format(latest ?? point[item.key], item.unit);
    row.querySelector('.fwmap-diag-range').textContent = range;
  }
  const facts = [
    ['Uptime', uptime(point.t)],
    ['Arcs · blocks · dots', `${point.arcs ?? 'n/a'} · ${point.blocks ?? 'n/a'} · ${point.pulses ?? 'n/a'}`],
    ['DOM nodes', point.nodes],
    ['Poll size', format([...samples].reverse().find((entry) => typeof entry.pollKb === 'number')?.pollKb, 'KB')],
    ['Long tasks', point.longTasks ?? 'n/a'],
    ['WebGL resets', point.contextLosses],
    ['Next poll', refreshText(point.refresh)],
  ];
  panel.querySelector('.fwmap-diag-facts').innerHTML = facts
    .map(([label, value]) => `<span>${escapeHtml(label)}</span><b>${escapeHtml(value)}</b>`).join('');
}

const POSITION_KEY = 'firewallmap.diagnostics.position';

function readPosition() {
  try {
    return JSON.parse(localStorage.getItem(POSITION_KEY) || 'null');
  } catch (_) {
    return null;
  }
}

function savePosition(position) {
  try {
    localStorage.setItem(POSITION_KEY, JSON.stringify(position));
  } catch (_) {
    // storage blocked (private window): the panel just starts at its default place next time
  }
}

/** Keep the panel inside the window; without a saved place, the bottom right of the map. */
function placePanel(panel, position) {
  const map = document.getElementById('fwmap-map').getBoundingClientRect();
  const width = panel.offsetWidth;
  const height = panel.offsetHeight;
  const left = position ? position.left : map.right - width - 12;
  const top = position ? position.top : map.bottom - height - 60;
  panel.style.left = `${Math.round(Math.min(Math.max(0, left), window.innerWidth - width))}px`;
  panel.style.top = `${Math.round(Math.min(Math.max(0, top), window.innerHeight - height))}px`;
}

/** Drag by the title bar (pointer events, so mouse, pen and touch alike); double-click puts it back. */
function draggable(panel) {
  const head = panel.querySelector('.fwmap-diag-head');
  let grab = null;
  head.addEventListener('pointerdown', (event) => {
    if (event.button !== 0 || event.target.closest('button')) {
      return;
    }
    grab = {x: event.clientX - panel.offsetLeft, y: event.clientY - panel.offsetTop};
    head.setPointerCapture(event.pointerId);
    event.preventDefault();
  });
  head.addEventListener('pointermove', (event) => {
    if (grab) {
      placePanel(panel, {left: event.clientX - grab.x, top: event.clientY - grab.y});
    }
  });
  const drop = () => {
    if (grab) {
      grab = null;
      savePosition({left: panel.offsetLeft, top: panel.offsetTop});
    }
  };
  head.addEventListener('pointerup', drop);
  head.addEventListener('pointercancel', drop);
  head.addEventListener('dblclick', (event) => {
    if (!event.target.closest('button')) {
      try {
        localStorage.removeItem(POSITION_KEY);
      } catch (_) {
        // nothing saved to forget
      }
      placePanel(panel, null);
    }
  });
  // a smaller window never strands it out of reach
  window.addEventListener('resize', () => placePanel(panel, {left: panel.offsetLeft, top: panel.offsetTop}));
}

const STYLES = `#fwmap-diag { position: fixed; z-index: 1030; width: 270px; padding: 8px 10px; font-size: 11px; line-height: 1.35; border: 1px solid rgba(128, 128, 128, .3); border-radius: 6px; color: var(--fwmap-text, inherit); background: color-mix(in srgb, var(--fwmap-panel, #fff) 78%, transparent); backdrop-filter: blur(6px); -webkit-backdrop-filter: blur(6px); box-shadow: 0 2px 8px rgba(0, 0, 0, .12); font-variant-numeric: tabular-nums; } .fwmap-diag-head { display: flex; align-items: center; gap: 6px; margin: -8px -10px 4px; padding: 6px 10px 4px; cursor: move; touch-action: none; user-select: none; -webkit-user-select: none; } .fwmap-diag-note { opacity: .65; font-size: 10px; margin-bottom: 4px; } .fwmap-diag-head b { flex: 1; } .fwmap-diag-plot { display: grid; grid-template-columns: 48px 1fr 54px; grid-template-rows: auto auto; column-gap: 6px; align-items: center; margin-bottom: 3px; } .fwmap-diag-plot > span { opacity: .7; grid-row: span 2; } .fwmap-diag-plot canvas { width: 100%; height: 22px; grid-row: span 2; } .fwmap-diag-value { text-align: right; } .fwmap-diag-range { text-align: right; opacity: .6; font-size: 10px; } .fwmap-diag-facts { display: grid; grid-template-columns: 1fr auto; gap: 1px 8px; margin-top: 6px; padding-top: 6px; border-top: 1px solid rgba(128, 128, 128, .25); } .fwmap-diag-facts span { opacity: .7; }`;

/** Show the panel and start sampling; the page calls this when ?debug=1 is on the URL. */
export function start(hooks) {
  page = {...page, ...hooks};
  const style = document.createElement('style');
  style.textContent = STYLES;
  document.head.appendChild(style);
  started = Date.now();
  observe();
  const panel = document.createElement('div');
  panel.id = 'fwmap-diag';
  panel.innerHTML = `<div class="fwmap-diag-head"><b>Diagnostics</b>
      <button type="button" class="btn btn-default btn-xs fwmap-diag-copy" title="Copy the samples as JSON">Copy</button>
      <button type="button" class="btn btn-default btn-xs fwmap-diag-close" title="Hide until the page is reloaded">&times;</button></div>`
    + PLOTS.map((item) => `<div class="fwmap-diag-plot" data-plot="${item.key}"><span>${escapeHtml(item.label)}</span>`
      + '<canvas></canvas><b class="fwmap-diag-value"></b><small class="fwmap-diag-range"></small></div>').join('')
    + '<div class="fwmap-diag-facts"></div>';
  // fixed to the window, so it can be dragged anywhere on the page
  document.body.appendChild(panel);
  if (!performance.memory) {
    // only Chromium reports the JS heap to a page; Safari and Firefox keep it to their own inspectors
    panel.querySelector('[data-plot="heapMb"]').remove();
    panel.querySelector('.fwmap-diag-head').insertAdjacentHTML('afterend',
      '<div class="fwmap-diag-note">JS heap: not reported by this browser (Safari: Web Inspector › Timelines › Memory)</div>');
  }
  placePanel(panel, readPosition());
  draggable(panel);
  const timer = setInterval(() => render(panel, sample()), SAMPLE_MS);
  panel.querySelector('.fwmap-diag-close').addEventListener('click', () => {
    clearInterval(timer);
    panel.remove();
  });
  panel.querySelector('.fwmap-diag-copy').addEventListener('click', () => {
    navigator.clipboard?.writeText(JSON.stringify({userAgent: navigator.userAgent, samples}));
  });
}
