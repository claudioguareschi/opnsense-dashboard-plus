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
 * Saved snapshots on the map page: the camera, the Live | Snapshots switch, snapshot mode (frame,
 * banner, timeline) and the Snapshots tab. A snapshot is a whole map document saved on the
 * firewall; showing one feeds it to the renderer instead of the live document, which keeps
 * being polled underneath so going back to live is instant.
 */
import {escapeHtml, fill, formatBytes, hostPort, plural} from '../src/format.js';
import {confirmAction, getJSON, notifyFailure, postJSON} from './api.js';
import {state, T} from './context.js';
import {ic} from './icons.js';
import {pill} from './parts.js';
import {readStorage, writeStorage} from './storage.js';

const TIMELINE_KEY = 'firewallmap.timeline';
// the page's hooks into main.js (set by bindSnapshots), so this module needs no circular import
let hooks = {refresh: () => {}, renderTabs: () => {}, renderDetails: () => {}, setTab: () => {}, setFollow: () => {}};

let timelineOpen = readStorage(TIMELINE_KEY) === '1';

/** "Fri 3 Oct, 16:42:10" in the browser's language. */
export function takenText(meta, withDate = true) {
  const date = new Date((meta?.taken || 0) * 1000);
  const time = date.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit', second: '2-digit'});
  if (!withDate) {
    return time;
  }
  const today = new Date().toDateString() === date.toDateString();
  const day = today ? T.today : date.toLocaleDateString([], {weekday: 'short', day: 'numeric', month: 'short'});
  return `${day}, ${time}`;
}

function countsText(meta) {
  const flows = escapeHtml(plural(T, 'snapshot_flows', meta.flows || 0));
  const flagged = meta.flagged ? ` · ${pill('danger', plural(T, 'snapshot_flagged', meta.flagged))}` : '';
  return `${flows}${flagged} · <span class="text-muted">${escapeHtml(captureText(meta))}</span>`;
}

/** Coverage is separate from legacy full/partial: old captures have unknown completeness. */
export function captureText(meta) {
  const capture = meta.capture;
  // version 1 (selected from every flow) and 2 (evidence, then the ranked flows) read alike
  if (!capture || ![1, 2].includes(capture.version) || !['complete', 'truncated'].includes(capture.detail_status)) {
    return T.snapshot_unknown;
  }
  const parts = [capture.detail_status === 'truncated' ? T.snapshot_truncated : T.snapshot_complete];
  const flows = capture.flows || {};
  if (flows.available != null) {
    parts.push(fill(T.snapshot_captured_flows, {captured: flows.captured, available: flows.available}));
  }
  if (flows.omitted_geo) {
    parts.push(fill(T.snapshot_omitted_geo, {count: flows.omitted_geo}));
  }
  const states = capture.states || {};
  if (states.truncated) {
    parts.push(fill(T.snapshot_captured_states, {captured: states.captured, available: states.available}));
  }
  // what the capture was taken from: the flows it chose among, and a bounded ranking said plainly
  const context = capture.context || {};
  if (context.flows_total != null && T.snapshot_population) {
    const total = Number(context.flows_total).toLocaleString();
    parts.push(fill(T.snapshot_population, {count: (context.flows_estimated ? '≈' : '') + total}));
  }
  if (context.quality?.ranking === 'bounded' && T.snapshot_ranking_bounded) {
    parts.push(T.snapshot_ranking_bounded);
  }
  return parts.join(' · ');
}

async function loadSnapshots() {
  try {
    const result = await getJSON('/api/firewallmap/snapshots/list');
    state.snapshots = result.snapshots || [];
    state.snapshotsKept = {keep: result.keep || 50, keep_days: result.keep_days || 30};
  } catch (error) {
    console.error('Firewall Map+: snapshot list unavailable', error);
    state.snapshots = [];
  }
  if (state.frozen && !state.snapshots.some((meta) => meta.id === state.frozen.meta.id)) {
    // deleted elsewhere: keep showing it, the list simply no longer has it
    state.snapshots = [state.frozen.meta, ...state.snapshots];
  }
  renderChrome();
}

/** The camera: a flash, a saved snapshot, a note that offers to open it. Nothing to fill in. */
async function takeSnapshot() {
  const frame = document.getElementById('fwmap-map');
  window.FirewallMapRenderer.host.flash(frame);
  const $button = $('#fwmap-camera').prop('disabled', true);
  try {
    const result = await postJSON('/api/firewallmap/snapshots/save', {});
    if (result.result !== 'saved') {
      throw new Error(result.error || result.result);
    }
    const meta = result.snapshot;
    const note = window.FirewallMapRenderer.host.toast(frame,
      `${ic('check', 'text-success')}<span><b>${escapeHtml(T.snapshot_saved)}</b> `
      + `<span class="text-muted">· ${escapeHtml(takenText(meta, false))} · ${countsText(meta)}</span></span>`
      + `<button type="button" class="btn btn-primary btn-xs fwmap-toast-open">${escapeHtml(T.snapshot_view)}</button>`);
    $(note).find('.fwmap-toast-open').on('click', () => {
      note.remove();
      openSnapshot(meta.id);
    });
    await loadSnapshots();
  } catch (error) {
    if (error?.message === 'too_soon') {
      // someone (maybe this viewer) took one seconds ago: that one already shows this moment
      window.FirewallMapRenderer.host.toast(frame, `<span>${escapeHtml(T.snapshot_too_soon)}</span>`);
    } else {
      notifyFailure(error);
    }
  } finally {
    $button.prop('disabled', false);
  }
}

async function openSnapshot(id) {
  try {
    const result = await getJSON(`/api/firewallmap/snapshots/get/${encodeURIComponent(id)}?blocks_min=${state.settings?.blockMin ?? 3}`);
    if (result.result !== 'ok') {
      throw new Error(result.error || result.result);
    }
    enterSnapshotMode(result.snapshot, result.data);
  } catch (error) {
    notifyFailure(error);
  }
}

function enterSnapshotMode(meta, data) {
  timelineDay = dayKey(meta);
  if (state.mode !== 'snapshot') {
    state.tabBeforeSnapshots = state.talkerTab;
  }
  state.mode = 'snapshot';
  state.frozen = {meta, data};
  state.data = data;
  state.selection = null;
  state.renderer.setFrozen(true);
  // a frozen map does not follow anything; the live choice is kept for later
  state.renderer.setFollow(false);
  hooks.setTab('snapshots');
  hooks.refresh();
  hooks.renderDetails();
  renderChrome();
}

export function backToLive() {
  if (state.mode === 'live') {
    return;
  }
  state.mode = 'live';
  state.frozen = null;
  state.selection = null;
  state.renderer.setFrozen(false);
  state.data = state.live;
  hooks.setTab(state.tabBeforeSnapshots && state.tabBeforeSnapshots !== 'snapshots' ? state.tabBeforeSnapshots : 'hosts');
  state.tabBeforeSnapshots = null;
  hooks.setFollow(state.follow);
  if (state.data) {
    hooks.refresh();
  }
  hooks.renderDetails();
  renderChrome();
}

/** The header switch: Snapshots opens the newest one (or the one already on screen). */
function chooseMode(mode) {
  if (mode === 'live') {
    backToLive();
  } else if (state.mode !== 'snapshot' && state.snapshots.length) {
    openSnapshot(state.snapshots[0].id);
  }
}

function editNote() {
  const meta = state.frozen?.meta;
  if (!meta) {
    return;
  }
  const $input = $('<textarea class="form-control" rows="3" maxlength="500"></textarea>').val(meta.note || '')
    .attr('aria-label', T.snapshot_note);
  BootstrapDialog.show({
    title: escapeHtml(`${T.snapshot_note} · ${takenText(meta)}`),
    message: $('<div></div>').append($input),
    onshown: () => $input.trigger('focus'),
    buttons: [
      {label: T.cancel, action: (dialog) => dialog.close()},
      {label: T.save, cssClass: 'btn-primary', action: async (dialog) => {
        dialog.close();
        try {
          const result = await postJSON(`/api/firewallmap/snapshots/note/${encodeURIComponent(meta.id)}`, {note: String($input.val() || '')});
          if (result.result !== 'saved') {
            throw new Error(result.error || result.result);
          }
          state.frozen.meta = result.snapshot;
          await loadSnapshots();
        } catch (error) {
          notifyFailure(error);
        }
      }},
    ],
  });
}

function download() {
  const frozen = state.frozen;
  if (!frozen) {
    return;
  }
  const blob = new Blob([JSON.stringify({snapshot: frozen.meta, data: frozen.data}, null, 1)], {type: 'application/json'});
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = `firewall-map-${frozen.meta.id}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

function remove() {
  const meta = state.frozen?.meta;
  if (!meta) {
    return;
  }
  confirmAction(`${T.snapshot_delete_confirm} ${takenText(meta)}?`, async () => {
    try {
      const result = await postJSON(`/api/firewallmap/snapshot_admin/delete/${encodeURIComponent(meta.id)}`, {});
      if (result.result !== 'deleted') {
        throw new Error(result.error || result.result);
      }
      const index = state.snapshots.findIndex((item) => item.id === meta.id);
      state.frozen = null;
      await loadSnapshots();
      const next = state.snapshots[Math.min(Math.max(index, 0), state.snapshots.length - 1)];
      if (next) {
        openSnapshot(next.id);
      } else {
        backToLive();
      }
    } catch (error) {
      notifyFailure(error);
    }
  });
}

/** Step to the next older (+1) or newer (-1) snapshot. */
function step(direction) {
  const index = state.snapshots.findIndex((meta) => meta.id === state.frozen?.meta.id);
  const next = state.snapshots[index + direction];
  if (next) {
    openSnapshot(next.id);
  }
}

function renderBanner() {
  const $banner = $('#fwmap-banner');
  const frozen = state.frozen;
  if (state.mode !== 'snapshot' || !frozen) {
    $banner.hide().empty();
    return;
  }
  const meta = frozen.meta;
  const note = meta.note ? ` · <span class="fwmap-snap-note">“${escapeHtml(meta.note)}”</span>` : '';
  const partial = meta.partial ? ` · <span class="text-muted" title="${escapeHtml(T.snapshot_partial_hint)}">${escapeHtml(T.snapshot_partial)}</span>` : '';
  $banner.html(`
    ${ic('camera', 'fwmap-banner-ic')}
    <span class="fwmap-banner-text"><b>${escapeHtml(T.snapshot)} · ${escapeHtml(takenText(meta))}</b>${meta.user ? ` <span class="fwmap-banner-counts">· ${escapeHtml(T.snapshot_by)} ${escapeHtml(meta.user)}</span>` : ''}${note}
      <span class="fwmap-banner-counts">· ${countsText(meta)}${partial}</span></span>
    <span class="fwmap-banner-actions">
      <button type="button" class="btn btn-default btn-sm fwmap-snap-note-btn">${ic('pen')} ${escapeHtml(meta.note ? T.snapshot_edit_note : T.snapshot_add_note)}</button>
      <button type="button" class="btn btn-default btn-sm fwmap-snap-download" title="${escapeHtml(T.snapshot_download)}" aria-label="${escapeHtml(T.snapshot_download)}">${ic('download')}</button>
      ${state.can.manage ? `<button type="button" class="btn btn-default btn-sm fwmap-snap-delete" title="${escapeHtml(T.snapshot_delete)}" aria-label="${escapeHtml(T.snapshot_delete)}">${ic('trash-can')}</button>` : ''}
    </span>`).show();
}

// the scrubber: dots closer than this many pixels share one numbered dot
const CLUSTER_PX = 18;
// the zoomed strip a numbered dot opens keeps its dots at least this far apart
const STRIP_GAP_PX = 34;
let timelineDay = null;

function dayKey(meta) {
  return new Date((meta?.taken || 0) * 1000).toDateString();
}

function dayLabel(key) {
  const date = new Date(key);
  return new Date().toDateString() === key ? T.today : date.toLocaleDateString([], {weekday: 'short', day: 'numeric', month: 'short'});
}

/** The badge over a dot: when and by whom, what it holds, the note. */
function tipHtml(meta) {
  return `<span class="fwmap-tl-tip" role="tooltip"><b>${escapeHtml(takenText(meta))}</b>
    ${meta.user ? `<span class="text-muted">${escapeHtml(T.snapshot_by)} ${escapeHtml(meta.user)}</span>` : ''}
    <span>${countsText(meta)}</span>
    ${meta.note ? `<span class="fwmap-snap-note">“${escapeHtml(meta.note)}”</span>` : ''}</span>`;
}

/** A tick every 5 min … 6 h, whichever gives four to seven labels over `span` seconds. */
function tickStep(span) {
  const steps = [300, 600, 900, 1800, 3600, 7200, 10800, 21600];
  return steps.find((stepSeconds) => span / stepSeconds <= 7) || 21600;
}

function timeLabel(seconds) {
  return new Date(seconds * 1000).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'});
}

/** Lay out one day's snapshots on the track: numbered dots for close ones, a zoomed strip on hover. */
function layoutTrack($track, day) {
  const width = $track.width() || 300;
  const metas = day.slice().sort((a, b) => a.taken - b.taken);
  const first = metas[0].taken;
  const last = metas[metas.length - 1].taken;
  // the axis zooms to the day's snapshots, never narrower than 20 minutes
  const span = Math.max(last - first, 1200);
  const middle = (first + last) / 2;
  const start = middle - span * 0.56;
  const end = middle + span * 0.56;
  const x = (taken) => ((taken - start) / (end - start)) * width;
  const step = tickStep(end - start);
  let ticks = '';
  for (let tick = Math.ceil(start / step) * step; tick <= end; tick += step) {
    ticks += `<span class="fwmap-tl-tick" style="left:${x(tick).toFixed(1)}px">${escapeHtml(timeLabel(tick))}</span>`;
  }
  const groups = [];
  for (const meta of metas) {
    const position = x(meta.taken);
    const group = groups[groups.length - 1];
    if (group && position - group.x0 < CLUSTER_PX) {
      group.items.push(meta);
      group.x1 = position;
    } else {
      groups.push({x0: position, x1: position, items: [meta]});
    }
  }
  const currentId = state.frozen?.meta.id;
  const dots = groups.map((group) => {
    const center = (group.x0 + group.x1) / 2;
    const current = group.items.some((meta) => meta.id === currentId);
    if (group.items.length === 1) {
      const meta = group.items[0];
      return `<button type="button" class="fwmap-tl-dot${current ? ' active' : ''}${meta.flagged ? ' flagged' : ''}" data-id="${escapeHtml(meta.id)}"
        style="left:${center.toFixed(1)}px" aria-label="${escapeHtml(takenText(meta))}"${current ? ' aria-current="true"' : ''}>${tipHtml(meta)}</button>`;
    }
    // the zoomed strip: the group's own time span, its dots spread to stay pickable
    const a = group.items[0].taken;
    const b = group.items[group.items.length - 1].taken;
    const stripWidth = Math.max(180, (group.items.length - 1) * STRIP_GAP_PX + 60);
    let previous = -Infinity;
    const mini = group.items.map((meta, index) => {
      let position = 30 + (b > a ? ((meta.taken - a) / (b - a)) * (stripWidth - 60) : index * STRIP_GAP_PX);
      position = Math.max(position, previous + STRIP_GAP_PX);
      previous = position;
      const active = meta.id === currentId;
      return `<button type="button" class="fwmap-tl-mini${active ? ' active' : ''}${meta.flagged ? ' flagged' : ''}" data-id="${escapeHtml(meta.id)}"
        style="left:${position.toFixed(1)}px" aria-label="${escapeHtml(takenText(meta))}"${active ? ' aria-current="true"' : ''}>
        <span class="fwmap-tl-mini-time">${escapeHtml(takenText(meta, false))}</span>${tipHtml(meta)}</button>`;
    }).join('');
    const finalWidth = Math.max(stripWidth, previous + 30);
    return `<div class="fwmap-tl-group${current ? ' active' : ''}" tabindex="0" style="left:${center.toFixed(1)}px"
        aria-label="${escapeHtml(plural(T, 'snapshots_here', group.items.length))}">
      <span class="fwmap-tl-count">${escapeHtml(group.items.length)}</span>
      <span class="fwmap-tl-pop"><span class="fwmap-tl-strip" style="width:${finalWidth.toFixed(0)}px">${mini}</span></span></div>`;
  }).join('');
  $track.html(`<span class="fwmap-tl-line"></span>${ticks}${dots}`);
}

function renderTimeline() {
  const $timeline = $('#fwmap-timeline');
  if (state.mode !== 'snapshot' || !state.frozen) {
    $timeline.hide().empty();
    return;
  }
  const list = state.snapshots;
  const index = list.findIndex((meta) => meta.id === state.frozen.meta.id);
  const older = `<button type="button" class="fwmap-tl-step" data-step="1" title="${escapeHtml(T.snapshot_older)}" aria-label="${escapeHtml(T.snapshot_older)}"${index >= list.length - 1 ? ' disabled' : ''}>${ic('chevron-left')}</button>`;
  const newer = `<button type="button" class="fwmap-tl-step" data-step="-1" title="${escapeHtml(T.snapshot_newer)}" aria-label="${escapeHtml(T.snapshot_newer)}"${index <= 0 ? ' disabled' : ''}>${ic('chevron-right')}</button>`;
  const where = `<span class="fwmap-tl-where">${escapeHtml(takenText(state.frozen.meta, false))} <span class="text-muted">· ${escapeHtml(list.length - index)}/${escapeHtml(list.length)}</span></span>`;
  if (!timelineOpen) {
    $timeline.removeClass('open').html(`
      <button type="button" class="fwmap-tl-toggle" aria-expanded="false" title="${escapeHtml(T.timeline_expand)}">${ic('clock')} ${escapeHtml(T.timeline)}</button>
      ${older}${where}${newer}`).show();
    return;
  }
  // one day at a time: the snapshot on screen picks it, the day buttons move through the others
  const days = [...new Set(list.map(dayKey))].sort((a, b) => new Date(a) - new Date(b));
  if (!timelineDay || !days.includes(timelineDay)) {
    timelineDay = dayKey(state.frozen.meta);
  }
  const dayIndex = days.indexOf(timelineDay);
  const dayButton = (stepValue, icon, label, disabled) => `<button type="button" class="fwmap-tl-day-step" data-day-step="${stepValue}"
    title="${escapeHtml(label)}" aria-label="${escapeHtml(label)}"${disabled ? ' disabled' : ''}>${ic(icon)}</button>`;
  $timeline.addClass('open').html(`
    <button type="button" class="fwmap-tl-toggle" aria-expanded="true" title="${escapeHtml(T.timeline_collapse)}" aria-label="${escapeHtml(T.timeline_collapse)}">${ic('clock')}</button>
    <span class="fwmap-tl-day">${dayButton(-1, 'chevron-left', T.timeline_previous_day, dayIndex <= 0)}
      <span class="fwmap-tl-day-label">${escapeHtml(dayLabel(timelineDay))}</span>
      ${dayButton(1, 'chevron-right', T.timeline_next_day, dayIndex >= days.length - 1)}</span>
    <span class="fwmap-tl-track"></span>
    ${older}${where}${newer}`).show();
  layoutTrack($timeline.find('.fwmap-tl-track'), list.filter((meta) => dayKey(meta) === timelineDay));
}

/** The Snapshots tab of the side panel. */
export function renderSnapshotList() {
  const $list = $('#fwmap-talkers-list');
  const needle = String($('#fwmap-talker-search').val() || '').trim().toLowerCase();
  let rows = state.snapshots;
  if (needle) {
    rows = rows.filter((meta) => [meta.note, meta.user, takenText(meta)].filter(Boolean)
      .some((text) => String(text).toLowerCase().includes(needle)));
  }
  if (!rows.length) {
    $list.html(`<div class="text-muted fwmap-empty">${escapeHtml(needle ? T.queue_no_match : T.no_snapshots)}</div>`);
    return;
  }
  const kept = `<p class="help-block">${escapeHtml(fill(T.snapshots_kept, {count: state.snapshotsKept.keep, days: state.snapshotsKept.keep_days}))}</p>`;
  $list.html(`${kept}<div class="list-group">${rows.map((meta) => {
    const current = meta.id === state.frozen?.meta.id;
    return `<a href="#" role="button" class="list-group-item fwmap-snap-row${current ? ' active' : ''}" data-id="${escapeHtml(meta.id)}"
        aria-pressed="${current}" title="${escapeHtml(T.snapshot_show)}">
      <span class="badge">${escapeHtml(formatBytes(meta.size || 0))}</span>
      <h5 class="list-group-item-heading">${ic('camera')} ${escapeHtml(takenText(meta))}${meta.user ? ` <small>${escapeHtml(T.snapshot_by)} ${escapeHtml(meta.user)}</small>` : ''}</h5>
      <div class="list-group-item-text">${countsText(meta)}${meta.partial ? ` <span title="${escapeHtml(T.snapshot_partial_hint)}">${pill('warning', T.snapshot_partial)}</span>` : ''}
        ${meta.note ? `<div><em>“${escapeHtml(meta.note)}”</em></div>` : ''}</div>
    </a>`;
  }).join('')}</div>`);
}

/** The header switch, the camera, the frame, banner and timeline, and the tab if it is open. */
function renderChrome() {
  const snapshot = state.mode === 'snapshot';
  $('#fwmap-map').toggleClass('fwmap-frozen', snapshot);
  $('#fwmap-mode-live').toggleClass('active', !snapshot).attr('aria-pressed', String(!snapshot));
  $('#fwmap-mode-snapshots').toggleClass('active', snapshot).attr('aria-pressed', String(snapshot))
    .prop('disabled', !snapshot && !state.snapshots.length)
    .attr('title', state.snapshots.length ? T.snapshots : T.no_snapshots);
  $('#fwmap-snapshot-count').text(state.snapshots.length || '');
  $('#fwmap-camera, #fwmap-follow').toggle(!snapshot);
  renderBanner();
  renderTimeline();
  if (state.talkerTab === 'snapshots') {
    renderSnapshotList();
  }
}

/** The States dialog for a saved snapshot: the PF states as they were when it was taken. */
export function showSavedStates(address) {
  if (!state.can.states) return;
  const rows = state.frozen?.data?.states?.[address] || [];
  const body = rows.map((row) => `<tr><td>${escapeHtml(row.interface || '')}</td><td>${escapeHtml(row.proto || '')}</td>`
    + `<td>${escapeHtml(hostPort(row.src_addr, row.src_port))}</td><td>${escapeHtml(hostPort(row.dst_addr, row.dst_port))}</td>`
    + `<td>${escapeHtml(row.nat || '')}</td><td>${escapeHtml(row.state || '')}</td><td>${escapeHtml(formatBytes(row.bytes || 0))}</td></tr>`).join('');
  BootstrapDialog.show({
    title: escapeHtml(`${T.states_for} ${address} · ${takenText(state.frozen?.meta)}`), size: BootstrapDialog.SIZE_WIDE,
    message: `${state.frozen?.data?.capture?.states?.truncated ? `<div class="alert alert-warning">${escapeHtml(captureText(state.frozen.meta))}</div>` : ''}` + (body
      ? `<table class="table table-condensed table-striped"><thead><tr><th>${escapeHtml(T.interface)}</th><th>${escapeHtml(T.protocol)}</th>`
        + `<th>${escapeHtml(T.source)}</th><th>${escapeHtml(T.destination)}</th><th>NAT</th><th>${escapeHtml(T.state)}</th><th>${escapeHtml(T.bytes)}</th></tr></thead>`
        + `<tbody>${body}</tbody></table>`
      : escapeHtml(state.frozen?.data?.full ? T.no_states : T.snapshot_no_states)),
    buttons: [{label: T.close, action: (dialog) => dialog.close()}],
  });
}

export function bindSnapshots(pageHooks) {
  hooks = {...hooks, ...pageHooks};
  $('#fwmap-camera').on('click', () => takeSnapshot());
  $('#fwmap-mode').on('click', 'button', function () {
    chooseMode($(this).data('mode'));
  });
  $('#fwmap-banner')
    .on('click', '.fwmap-snap-note-btn', () => editNote())
    .on('click', '.fwmap-snap-download', () => download())
    .on('click', '.fwmap-snap-delete', () => remove());
  $('#fwmap-timeline')
    .on('click', '.fwmap-tl-toggle', () => {
      timelineOpen = !timelineOpen;
      writeStorage(TIMELINE_KEY, timelineOpen ? '1' : '0');
      renderTimeline();
    })
    .on('click', '.fwmap-tl-step', function () {
      step(Number($(this).data('step')));
    })
    .on('click', '.fwmap-tl-dot, .fwmap-tl-mini', function () {
      openSnapshot(String($(this).data('id')));
    })
    .on('click', '.fwmap-tl-day-step', function () {
      const days = [...new Set(state.snapshots.map(dayKey))].sort((a, b) => new Date(a) - new Date(b));
      timelineDay = days[days.indexOf(timelineDay) + Number($(this).data('day-step'))] || timelineDay;
      renderTimeline();
    });
  $('#fwmap-talkers-list')
    .on('mousedown', '.fwmap-snap-row', function (event) {
      event.preventDefault();
      openSnapshot(String($(this).data('id')));
    })
    // the row is a link for Bootstrap's list styling; it opens on mousedown and goes nowhere
    .on('click', '.fwmap-snap-row', (event) => event.preventDefault())
    .on('keydown', '.fwmap-snap-row', function (event) {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        openSnapshot(String($(this).data('id')));
      }
    });
  // the scrubber's layout depends on the map's width (window, splitters)
  if (window.ResizeObserver) {
    let frame = null;
    new ResizeObserver(() => {
      if (timelineOpen && state.mode === 'snapshot' && frame === null) {
        frame = requestAnimationFrame(() => {
          frame = null;
          renderTimeline();
        });
      }
    }).observe(document.getElementById('fwmap-map'));
  }
  // a link from the dashboard widget's "Open in full map"
  const match = /(?:^#|&)snapshot=(\d{8}T\d{6}Z-[0-9a-f]{4})/.exec(window.location.hash);
  loadSnapshots().then(() => {
    if (match) {
      openSnapshot(match[1]);
      history.replaceState(null, '', window.location.pathname + window.location.search);
    }
  });
}
