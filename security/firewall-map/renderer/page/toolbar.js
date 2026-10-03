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

/* The toolbar's filter dropdowns and the map legend. */
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
  $('#fwmap-filter-asn').toggle(asnActive).find('span').text(asnActive ? `AS${state.filters.asn}` : '');
}

export function updateLegend() {
  const items = state.renderer.legend();
  $('#fwmap-legend').html(items.map((item) =>
    `<span class="fwmap-legend-item"><i style="background:rgb(${item.color.slice(0, 3).join(',')})"></i>`
    + `${escapeHtml(item.label)}</span>`).join('')
    + `<span class="fwmap-legend-item"><i class="fwmap-legend-ring"></i>${escapeHtml(T.ids_alert)}</span>`);
}
