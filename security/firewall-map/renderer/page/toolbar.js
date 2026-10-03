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
import {state, T} from './context.js';
import {flowService, locationsById} from './filters.js';

function fillSelect($select, values, current, allLabel) {
  const options = [`<option value="">${escapeHtml(allLabel)}</option>`]
    .concat([...values].sort((a, b) => String(a.label).localeCompare(String(b.label)))
      .map((item) => `<option value="${escapeHtml(item.value)}">${escapeHtml(item.label)}</option>`));
  if (current && ![...values].some((item) => String(item.value) === current)) {
    // keep a chosen value even while it has no live traffic
    options.push(`<option value="${escapeHtml(current)}">${escapeHtml(current)}</option>`);
  }
  const html = options.join('');
  // never rebuild a dropdown the user is working with
  if ($select.data('html') !== html && document.activeElement !== $select[0]) {
    $select.html(html).data('html', html);
  }
  $select.val(current);
}

export function updateToolbar(snapshot) {
  const locations = locationsById(snapshot);
  const services = new Map();
  const ifaces = new Map();
  const hosts = new Map();
  const countries = new Map();
  for (const flow of snapshot.flows || []) {
    const service = flowService(flow);
    services.set(service, {value: service, label: service});
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
  for (const block of snapshot.blocks || []) {
    if (block.country) {
      countries.set(block.country, {value: block.country, label: plain(block.country)});
    }
  }
  fillSelect($('#fwmap-filter-service'), services.values(), state.filters.service, T.all_services);
  fillSelect($('#fwmap-filter-iface'), ifaces.values(), state.filters.iface, T.all_interfaces);
  fillSelect($('#fwmap-filter-host'), hosts.values(), state.filters.host, T.all_hosts);
  fillSelect($('#fwmap-filter-country'), countries.values(), state.filters.country, T.all_countries);
  const asnActive = state.filters.asn !== '';
  $('#fwmap-filter-asn').toggleClass('shown', asnActive).find('span').text(asnActive ? `AS${state.filters.asn}` : '');
  syncChips();
}

let measure;

/** A select is as wide as the option it shows, so a chip never carries empty space. */
function fitSelect(select) {
  if (select.closest('#fwmap-more-menu')) {
    select.style.width = '';
    return;
  }
  const style = getComputedStyle(select);
  measure = measure || document.createElement('canvas').getContext('2d');
  measure.font = `${style.fontWeight} ${style.fontSize} ${style.fontFamily}`;
  const text = select.options[select.selectedIndex]?.text || '';
  select.style.width = `${Math.ceil(measure.measureText(text).width + parseFloat(style.paddingRight || 0) + 4)}px`;
}

/** Chosen filters fill with the accent colour; the reset button appears once two are set. */
export function syncChips() {
  let active = state.filters.asn ? 1 : 0;
  let folded = 0;
  $('.fwmap-chip[data-filter]').each(function () {
    const select = $(this).find('select')[0];
    const on = !['', 'all'].includes(select.value || '');
    $(this).toggleClass('active', on);
    active += on ? 1 : 0;
    folded += on && this.closest('#fwmap-more-menu') ? 1 : 0;
    fitSelect(select);
  });
  $('#fwmap-reset').toggle(active >= 2);
  $('#fwmap-more-count').text(folded || '');
  foldChips();
  $('#fwmap-legend .fwmap-legend-mode select').each(function () {
    fitSelect(this);
  });
}

/** Chips that do not fit on the row move, from the right, into the "Filters" menu. */
function foldChips() {
  const row = document.getElementById('fwmap-chips');
  const wrap = document.getElementById('fwmap-more-wrap');
  const menu = document.getElementById('fwmap-more-menu');
  if (!row || row.offsetParent === null || row.contains(document.activeElement) && document.activeElement.tagName === 'SELECT') {
    return;
  }
  // document order is the chips' own order, wherever they are now
  const chips = [...document.querySelectorAll('.fwmap-chip[data-filter]')];
  const wasFolded = chips.some((chip) => chip.parentNode === menu);
  for (const chip of chips) {
    row.insertBefore(chip, document.getElementById('fwmap-filter-asn'));
  }
  wrap.style.display = 'none';
  if (row.scrollWidth > row.clientWidth + 1) {
    wrap.style.display = '';
    // the traffic chip, the main filter, always stays on the row
    for (let index = chips.length - 1; index > 0 && row.scrollWidth > row.clientWidth + 1; index--) {
      menu.insertBefore(chips[index], menu.firstChild);
    }
  } else {
    wrap.classList.remove('open');
  }
  if (wasFolded !== chips.some((chip) => chip.parentNode === menu)) {
    chips.forEach((chip) => fitSelect(chip.querySelector('select')));
  }
  const folded = chips.filter((chip) => chip.parentNode === menu && chip.classList.contains('active')).length;
  $('#fwmap-more-count').text(folded || '');
}

/** Clear buttons on chosen chips, the "Filters" menu, and refolding as the row resizes. */
export function bindChips() {
  $('#fwmap-toolbar').on('click', '.fwmap-chip[data-filter] .fwmap-chip-clear', function (event) {
    event.preventDefault();
    event.stopPropagation();
    const chip = $(this).closest('.fwmap-chip');
    chip.find('select').val(chip.data('filter') === 'traffic' ? 'all' : '').trigger('change');
  });
  $('#fwmap-more').on('click', (event) => {
    event.stopPropagation();
    const open = !$('#fwmap-more-wrap').hasClass('open');
    $('#fwmap-more-wrap').toggleClass('open', open);
    $('#fwmap-more').attr('aria-expanded', String(open));
  });
  $(document).on('mousedown', (event) => {
    if (!$(event.target).closest('#fwmap-more-wrap').length) {
      $('#fwmap-more-wrap').removeClass('open');
      $('#fwmap-more').attr('aria-expanded', 'false');
    }
  });
  $('#fwmap-toolbar').on('change', 'select', () => syncChips());
  $('#fwmap-color').on('change', function () {
    fitSelect(this);
  });
  if (window.ResizeObserver) {
    new ResizeObserver(() => syncChips()).observe(document.getElementById('fwmap-toolbar'));
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
