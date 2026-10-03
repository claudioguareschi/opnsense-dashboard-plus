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
import {escapeHtml, formatBytes, hostPort, plural} from '../src/format.js';
import {confirmAction, getJSON, notifyFailure, postJSON} from './api.js';
import {state, T} from './context.js';
import {ic} from './icons.js';

const TIMELINE_KEY = 'firewallmap.timeline';
// the page's hooks into main.js (set by bindSnapshots), so this module needs no circular import
let hooks = {refresh: () => {}, renderTabs: () => {}, renderDetails: () => {}, setTab: () => {}, setFollow: () => {}};

function storage(key, value) {
  try {
    if (value === undefined) {
      return window.localStorage.getItem(key);
    }
    window.localStorage.setItem(key, value);
  } catch (_) {
    // private windows or blocked storage: the choice lasts for this page only
  }
  return null;
}

let timelineOpen = storage(TIMELINE_KEY) === '1';

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

function shortTime(meta) {
  return new Date((meta?.taken || 0) * 1000).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'});
}

function countsText(meta) {
  const parts = [plural(T, 'snapshot_flows', meta.flows || 0)];
  if (meta.flagged) {
    parts.push(`<span class="fwmap-snap-flagged">${escapeHtml(plural(T, 'snapshot_flagged', meta.flagged))}</span>`);
  }
  return parts.map((part, index) => (index ? part : escapeHtml(part))).join(' · ');
}

export async function loadSnapshots() {
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
export async function takeSnapshot() {
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
      `${ic('check', 'fwmap-toast-ok')}<span><b>${escapeHtml(T.snapshot_saved)}</b> `
      + `<span class="fwmap-muted">· ${escapeHtml(takenText(meta, false))} · ${countsText(meta)}</span></span>`
      + `<button type="button" class="btn btn-primary btn-xs fwmap-toast-open">${escapeHtml(T.snapshot_open)}</button>`);
    $(note).find('.fwmap-toast-open').on('click', () => {
      note.remove();
      openSnapshot(meta.id);
    });
    await loadSnapshots();
  } catch (error) {
    notifyFailure(error);
  } finally {
    $button.prop('disabled', false);
  }
}

export async function openSnapshot(id) {
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
  if (state.mode !== 'snapshot') {
    state.tabBeforeSnapshots = state.talkerTab;
  }
  state.mode = 'snapshot';
  state.frozen = {meta, data};
  state.snapshot = data;
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
  state.snapshot = state.live;
  hooks.setTab(state.tabBeforeSnapshots && state.tabBeforeSnapshots !== 'snapshots' ? state.tabBeforeSnapshots : 'hosts');
  state.tabBeforeSnapshots = null;
  hooks.setFollow(state.follow);
  if (state.snapshot) {
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
  const partial = meta.partial ? ` · <span class="fwmap-muted" title="${escapeHtml(T.snapshot_partial_hint)}">${escapeHtml(T.snapshot_partial)}</span>` : '';
  $banner.html(`
    ${ic('camera', 'fwmap-banner-ic')}
    <span class="fwmap-banner-text"><b>${escapeHtml(T.snapshot)} · ${escapeHtml(takenText(meta))}</b>${note}
      <span class="fwmap-banner-counts">· ${countsText(meta)}${meta.user ? ` · ${escapeHtml(T.snapshot_by)} ${escapeHtml(meta.user)}` : ''}${partial}</span></span>
    <span class="fwmap-banner-actions">
      <button type="button" class="btn btn-default btn-sm fwmap-snap-note-btn">${ic('edit')} ${escapeHtml(meta.note ? T.snapshot_edit_note : T.snapshot_add_note)}</button>
      <button type="button" class="btn btn-default btn-sm fwmap-snap-download" title="${escapeHtml(T.snapshot_download)}" aria-label="${escapeHtml(T.snapshot_download)}">${ic('download')}</button>
      ${state.isAdmin ? `<button type="button" class="btn btn-default btn-sm fwmap-snap-delete" title="${escapeHtml(T.snapshot_delete)}" aria-label="${escapeHtml(T.snapshot_delete)}">${ic('trash')}</button>` : ''}
      <button type="button" class="btn btn-sm fwmap-snap-live"><i class="fwmap-live"></i> ${escapeHtml(T.back_to_live)}</button>
    </span>`).show();
}

function chipHtml(meta) {
  const current = meta.id === state.frozen?.meta.id;
  return `<button type="button" class="fwmap-snap-chip${current ? ' active' : ''}" data-id="${escapeHtml(meta.id)}"${current ? ' aria-current="true"' : ''}>
    <span class="fwmap-snap-chip-time">${escapeHtml(takenText(meta))}</span>
    <span class="fwmap-snap-chip-sub">${countsText(meta)}${meta.note ? ` · ${escapeHtml(T.snapshot_has_note)}` : ''}</span></button>`;
}

function renderTimeline() {
  const $timeline = $('#fwmap-timeline');
  if (state.mode !== 'snapshot' || !state.frozen) {
    $timeline.hide().empty();
    return;
  }
  const list = state.snapshots;
  const index = list.findIndex((meta) => meta.id === state.frozen.meta.id);
  // newest on the right, as time reads
  const ordered = list.slice().reverse();
  const older = `<button type="button" class="fwmap-tl-step" data-step="1" title="${escapeHtml(T.snapshot_older)}" aria-label="${escapeHtml(T.snapshot_older)}"${index >= list.length - 1 ? ' disabled' : ''}>${ic('chevron-left')}</button>`;
  const newer = `<button type="button" class="fwmap-tl-step" data-step="-1" title="${escapeHtml(T.snapshot_newer)}" aria-label="${escapeHtml(T.snapshot_newer)}"${index <= 0 ? ' disabled' : ''}>${ic('chevron')}</button>`;
  if (!timelineOpen) {
    $timeline.removeClass('open').html(`
      <button type="button" class="fwmap-tl-toggle" aria-expanded="false" title="${escapeHtml(T.timeline_expand)}">${ic('clock')} ${escapeHtml(T.timeline)}</button>
      ${older}<span class="fwmap-tl-where">${escapeHtml(shortTime(state.frozen.meta))} <span class="fwmap-muted">· ${escapeHtml(list.length - index)} / ${escapeHtml(list.length)}</span></span>${newer}`).show();
    return;
  }
  $timeline.addClass('open').html(`
    <div class="fwmap-tl-head"><span>${ic('clock')} ${escapeHtml(T.timeline)} <span class="fwmap-muted">· ${escapeHtml(list.length)} / ${escapeHtml(state.snapshotsKept.keep)}</span></span>
      <button type="button" class="fwmap-tl-toggle" aria-expanded="true" title="${escapeHtml(T.timeline_collapse)}" aria-label="${escapeHtml(T.timeline_collapse)}">${ic('chevron-down')}</button></div>
    <div class="fwmap-tl-strip">${older}<div class="fwmap-tl-chips">${ordered.map(chipHtml).join('')}</div>${newer}</div>`).show();
  const $chips = $timeline.find('.fwmap-tl-chips');
  const $active = $chips.find('.fwmap-snap-chip.active');
  if ($active.length) {
    $chips.scrollLeft($active[0].offsetLeft - $chips.width() / 2 + $active.outerWidth() / 2);
  }
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
  const kept = `<div class="fwmap-snap-kept fwmap-muted">${escapeHtml(T.snapshots_kept.replace('%s', state.snapshotsKept.keep).replace('%d', state.snapshotsKept.keep_days))}</div>`;
  $list.html(kept + rows.map((meta) => {
    const current = meta.id === state.frozen?.meta.id;
    return `<div class="fwmap-talker fwmap-snap-row${current ? ' active' : ''}" role="button" tabindex="0" data-id="${escapeHtml(meta.id)}"
        aria-pressed="${current}" title="${escapeHtml(T.snapshot_show)}">
      <span class="fwmap-talker-icon">${ic('camera')}</span>
      <span class="fwmap-talker-text"><span class="fwmap-talker-label">${escapeHtml(takenText(meta))}</span>
        <span class="fwmap-talker-sub">${countsText(meta)}${meta.user ? ` · ${escapeHtml(T.snapshot_by)} ${escapeHtml(meta.user)}` : ''}</span>
        ${meta.note ? `<span class="fwmap-talker-sub fwmap-snap-note">“${escapeHtml(meta.note)}”</span>` : ''}</span>
      <span class="fwmap-snap-size">${escapeHtml(formatBytes(meta.size || 0))}</span>
    </div>`;
  }).join(''));
}

/** The header switch, the camera, the frame, banner and timeline, and the tab if it is open. */
export function renderChrome() {
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
  const rows = state.frozen?.data?.states?.[address] || [];
  const body = rows.map((row) => `<tr><td>${escapeHtml(row.interface || '')}</td><td>${escapeHtml(row.proto || '')}</td>`
    + `<td>${escapeHtml(hostPort(row.src_addr, row.src_port))}</td><td>${escapeHtml(hostPort(row.dst_addr, row.dst_port))}</td>`
    + `<td>${escapeHtml(row.nat || '')}</td><td>${escapeHtml(row.state || '')}</td><td>${escapeHtml(formatBytes(row.bytes || 0))}</td></tr>`).join('');
  BootstrapDialog.show({
    title: escapeHtml(`${T.states_for} ${address} · ${takenText(state.frozen?.meta)}`), size: BootstrapDialog.SIZE_WIDE,
    message: body
      ? `<table class="table table-condensed table-striped"><thead><tr><th>${escapeHtml(T.interface)}</th><th>${escapeHtml(T.protocol)}</th>`
        + `<th>${escapeHtml(T.source)}</th><th>${escapeHtml(T.destination)}</th><th>NAT</th><th>${escapeHtml(T.state)}</th><th>${escapeHtml(T.bytes)}</th></tr></thead>`
        + `<tbody>${body}</tbody></table>`
      : escapeHtml(state.frozen?.data?.full ? T.no_states : T.snapshot_no_states),
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
    .on('click', '.fwmap-snap-delete', () => remove())
    .on('click', '.fwmap-snap-live', () => backToLive());
  $('#fwmap-timeline')
    .on('click', '.fwmap-tl-toggle', () => {
      timelineOpen = !timelineOpen;
      storage(TIMELINE_KEY, timelineOpen ? '1' : '0');
      renderTimeline();
    })
    .on('click', '.fwmap-tl-step', function () {
      step(Number($(this).data('step')));
    })
    .on('click', '.fwmap-snap-chip', function () {
      openSnapshot(String($(this).data('id')));
    });
  $('#fwmap-talkers-list')
    .on('mousedown', '.fwmap-snap-row', function (event) {
      event.preventDefault();
      openSnapshot(String($(this).data('id')));
    })
    .on('keydown', '.fwmap-snap-row', function (event) {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        openSnapshot(String($(this).data('id')));
      }
    });
  // a link from the dashboard widget's "Open in full map"
  const match = /(?:^#|&)snapshot=(\d{8}T\d{6}Z-[0-9a-f]{4})/.exec(window.location.hash);
  loadSnapshots().then(() => {
    if (match) {
      openSnapshot(match[1]);
      history.replaceState(null, '', window.location.pathname + window.location.search);
    }
  });
}

