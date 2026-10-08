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

/* The toolbar's filter chips and the map legend. */
import {escapeHtml, plain} from '../src/format.js';
import {categoryLabel} from '../src/palette.js';
import {state, T, TEXT} from './context.js';
import {flowService, locationsById} from './filters.js';
import {readStorage, writeStorage} from './storage.js';

/** Rebuild a filter's options (bootstrap-select), never while its list is open. */
function fillSelect($select, values, current, allLabel) {
  const options = [`<option value="">${escapeHtml(allLabel)}</option>`]
    .concat([...values].sort((a, b) => String(a.label).localeCompare(String(b.label)))
      .map((item) => `<option value="${escapeHtml(item.value)}">${escapeHtml(item.label)}</option>`));
  if (current && ![...values].some((item) => String(item.value) === current)) {
    // keep a chosen value even while it has no live traffic
    options.push(`<option value="${escapeHtml(current)}">${escapeHtml(current)}</option>`);
  }
  const html = options.join('');
  const open = $select.parent().hasClass('open');
  if ($select.data('html') !== html && !open) {
    $select.html(html).data('html', html);
    withIcons($select);
    $select.selectpicker('refresh');
  }
  // The native value and Bootstrap Select's button are separate states.  Polling can rebuild the
  // option list while a host is selected, so restore both once its menu is closed.
  if (!open) {
    $select.val(current);
    $select.selectpicker('val', current);
  }
}

/** The filter's icon on every option, so bootstrap-select shows it on the button. */
function withIcons($select) {
  const icon = $select.closest('.fwmap-filter').data('icon');
  if (icon) {
    $select.find('option').attr('data-icon', icon);
  }
}

/* The viewer's Focus (a Flow Ranking Profile key), kept in this browser. */
const FOCUS_KEY = 'fwmap-focus';
export function readFocus() {
  return readStorage(FOCUS_KEY) || '';
}

/** The Focus selector: the profiles the collector ranks for, the one this view shows selected. */
export function updateFocus(summary, onChange) {
  const profiles = summary.profiles || [];
  const $wrap = $('#fwmap-focus-wrap');
  $wrap.toggle(profiles.length > 1);
  if (profiles.length < 2) {
    return;
  }
  const $select = $('#fwmap-focus');
  const html = profiles.map((profile) => `<option value="${escapeHtml(profile.key)}" data-icon="fa-fw fa-crosshairs"`
    + ` title="${escapeHtml(`${T.focus || 'Focus'}: ${profile.name}`)}"`
    + `>${escapeHtml(profile.name)}</option>`).join('');
  const open = $select.parent().hasClass('open');
  if ($select.data('html') !== html && !open) {
    $select.html(html).data('html', html);
    $select.selectpicker('refresh');
    $select.off('changed.bs.select').on('changed.bs.select', () => {
      const key = $select.val() || '';
      writeStorage(FOCUS_KEY, key);
      onChange(key);
    });
  }
  if (!open && summary.focus && $select.val() !== summary.focus) {
    $select.selectpicker('val', summary.focus);
  }
  const current = profiles.find((profile) => profile.key === summary.focus);
  $wrap.attr('title', current ? current.description : '');
}

export function updateToolbar(summary) {
  const locations = locationsById(summary);
  const services = new Map();
  const ifaces = new Map();
  const hosts = new Map();
  const countries = new Map();
  for (const flow of summary.flows || []) {
    const service = flowService(flow);
    services.set(service, {value: service, label: categoryLabel(service, TEXT)});
    for (const inside of flow.inside || []) {
      if (inside.interface) {
        ifaces.set(inside.interface, {value: inside.interface, label: inside.interface});
      }
      hosts.set(inside.ip, {value: inside.ip, label: inside.name ? `${inside.name} (${inside.ip})` : inside.ip});
    }
    const country = locations.get(flow.dest)?.country;
    if (country) {
      countries.set(country, {value: country, label: plain(country)});
    }
  }
  for (const name of summary.interfaces || []) {
    ifaces.set(name, {value: name, label: name});
  }
  for (const block of summary.blocks || []) {
    if (block.country) {
      countries.set(block.country, {value: block.country, label: plain(block.country)});
    }
  }
  fillSelect($('#fwmap-filter-service'), services.values(), state.filters.service, T.all_services);
  fillSelect($('#fwmap-filter-iface'), ifaces.values(), state.filters.iface, T.all_interfaces);
  fillSelect($('#fwmap-filter-host'), hosts.values(), state.filters.host, T.all_hosts);
  fillSelect($('#fwmap-filter-country'), countries.values(), state.filters.country, T.all_countries);
  const asnActive = state.filters.asn !== '';
  $('#fwmap-filter-asn').toggleClass('shown', asnActive).find('.fwmap-asn-label > span').text(asnActive ? `AS${state.filters.asn}` : '');
  syncChips();
}

/** A chosen filter turns primary and shows its clear button; reset appears once two are set. */
export function syncChips() {
  let active = state.filters.asn ? 1 : 0;
  $('.fwmap-filter').each(function () {
    const $select = $(this).find('select.selectpicker');
    const on = !['', 'all'].includes($select.val() || '');
    if ($(this).hasClass('active') !== on || !$(this).data('styled')) {
      $(this).toggleClass('active', on).data('styled', true);
      $select.selectpicker('setStyle', on ? 'btn-primary btn-sm' : 'btn-default btn-sm');
    }
    // every poll comes here: redraw the button only when what it shows changed
    const shown = `${$select.val()}|${$select.data('html') || ''}`;
    if ($select.data('rendered') !== shown) {
      $select.data('rendered', shown).selectpicker('render');
    }
    active += on ? 1 : 0;
  });
  $('#fwmap-reset').toggle(active >= 2);
  // folding measures every chip (forced layouts): only when the chips or the room changed
  const layout = `${document.getElementById('fwmap-chips')?.clientWidth}|${$('.fwmap-filter select.selectpicker')
    .map((_, select) => $(select).data('rendered')).get().join('|')}|${active}`;
  if (layout !== lastLayout) {
    lastLayout = layout;
    foldChips();
  }
}

let lastLayout = null;

/** Filters that do not fit on the row move, from the right, into the "Filters" menu. */
function foldChips() {
  const row = document.getElementById('fwmap-chips');
  const wrap = document.getElementById('fwmap-more-wrap');
  const menu = document.getElementById('fwmap-more-menu');
  // never move a filter whose list is open
  if (!row || row.offsetParent === null || $('.fwmap-filter .bootstrap-select.open').length) {
    return;
  }
  // document order is the filters' own order, wherever they are now
  const groups = [...document.querySelectorAll('.fwmap-filter')];
  for (const group of groups) {
    row.insertBefore(group, document.getElementById('fwmap-filter-asn'));
  }
  wrap.style.display = 'none';
  if (row.scrollWidth > row.clientWidth + 1) {
    wrap.style.display = '';
    // traffic, the main filter, always stays on the row
    for (let index = groups.length - 1; index > 0 && row.scrollWidth > row.clientWidth + 1; index--) {
      menu.insertBefore(groups[index], menu.firstChild);
    }
  } else {
    closeMore();
  }
  const folded = groups.filter((group) => group.parentNode === menu && group.classList.contains('active')).length;
  $('#fwmap-more-count').text(folded || '');
}

function closeMore() {
  $('#fwmap-more-wrap').removeClass('open');
  $('#fwmap-more').attr('aria-expanded', 'false');
}

/** bootstrap-select on the filters and the legend's color scheme, clear buttons, the "Filters" menu. */
export function bindChips() {
  $('.fwmap-filter select.selectpicker').each(function () {
    withIcons($(this));
  });
  // bootstrap-select may already have built its buttons on page load (its data-api), before
  // the icons were set: refresh so they show from the start, not only after the first data
  $('#fwmap-toolbar .selectpicker, #fwmap-color').selectpicker().selectpicker('refresh');
  $('#fwmap-chips').on('click', '.fwmap-filter .fwmap-filter-clear', function (event) {
    event.preventDefault();
    const group = $(this).closest('.fwmap-filter');
    group.find('select').val(group.data('filter') === 'traffic' ? 'all' : '').trigger('change');
  });
  $('#fwmap-more').on('click', (event) => {
    event.stopPropagation();
    const open = !$('#fwmap-more-wrap').hasClass('open');
    $('#fwmap-more-wrap').toggleClass('open', open);
    $('#fwmap-more').attr('aria-expanded', String(open));
  });
  $(document).on('mousedown', (event) => {
    if (!$(event.target).closest('#fwmap-more-wrap').length) {
      closeMore();
    }
  });
  $('#fwmap-toolbar').on('change', 'select', () => syncChips());
  if (window.ResizeObserver) {
    new ResizeObserver(() => foldChips()).observe(document.getElementById('fwmap-toolbar'));
  }
  syncChips();
}

export function updateLegend() {
  const items = state.renderer.legend();
  $('#fwmap-legend-items').html(items.map((item) =>
    `<span class="fwmap-legend-item"><i style="background:rgb(${item.color.slice(0, 3).join(',')})"></i>`
    + `${escapeHtml(item.label)}</span>`).join('')
    + `<span class="fwmap-legend-item"><i class="fwmap-legend-ring"></i>${escapeHtml(T.ids_alert)}</span>`);
}
