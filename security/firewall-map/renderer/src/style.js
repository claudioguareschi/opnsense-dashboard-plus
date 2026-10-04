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
 * How the map is colored: arcs and pulses by the chosen mode (inbound/outbound, download/upload,
 * egress, service) or by verdict, blocked sources, the legend, and the pulse layers. Reads the
 * map's current state through `view` (see createFirewallMap).
 */
import {ScatterplotLayer} from '@deck.gl/layers';
import {IDS_ARC_FADE_SECONDS, pulsePosition} from './arcs.js';
import {faded} from './fader.js';
import {CATEGORY_COLORS, categoryLabel, mix, rgb} from './palette.js';

// a blocked source hammering the firewall throbs this often (seconds)
const THREAT_THROB_PERIOD = 0.9;

export function createStyle(view) {
  const categoryColors = new Map();
  let categoryKey = '';

  function categoryOf(arc) {
    return view.settings.colorMode === 'egress' ? arc.egress : arc.service;
  }

  function categorical() {
    return view.settings.colorMode === 'egress' || view.settings.colorMode === 'service';
  }

  function categoryColor(name) {
    if (!categoryColors.has(name)) {
      categoryColors.set(name, CATEGORY_COLORS[categoryColors.size % CATEGORY_COLORS.length]);
      categoryKey = [...categoryColors.keys()].join('|');
    }
    return categoryColors.get(name);
  }

  function arcColor(arc) {
    return faded(arcBaseColor(arc), arcOpacity(arc));
  }

  /** How far a closed IDS connection's arc has faded, counting on from the last refresh. */
  function idsLinger(arc) {
    if (!arc.ids || arc.ids.active) {
      return 1;
    }
    const closed = (arc.ids.closed_seconds ?? arc.ids.last_seconds ?? 0) + (view.frozen ? 0 : (view.frameNow - view.dataTime) / 1000);
    return Math.max(0, 1 - closed / IDS_ARC_FADE_SECONDS);
  }

  function arcOpacity(arc) {
    return view.arcFader.opacity(arc, view.frameNow) * idsLinger(arc);
  }

  function arcBaseColor(arc) {
    // an idle connection is still a state on the firewall (and may be the one a snapshot was taken
    // for): it stays plainly visible wherever it can be hovered, busier ones only get stronger
    const alpha = Math.round((arc.heavy ? 170 : 140) + (arc.heavy ? 85 : 115) * arc.activity);
    if (arc.threat) {
      // flagged traffic the firewall let through
      return rgb(view.colors.danger, Math.max(alpha, 170));
    }
    if (arc.contained) {
      return rgb(view.colors.contained, Math.max(alpha, 170));
    }
    if (categorical()) {
      const base = baseColor(arc);
      return rgb(arc.heavy ? mix(base, view.colors.dark ? [255, 255, 255] : [0, 0, 0], 0.2) : mix(view.colors.background.slice(0, 3), base, 0.8), alpha);
    }
    const scheme = view.settings.colorMode === 'initiator' ? initiatorScheme(arc.initiated) : arc.toward ? view.colors.toward : view.colors.away;
    return rgb(arc.heavy ? scheme.heavy : scheme.link, alpha);
  }

  function pulseColor(item) {
    return faded(pulseBaseColor(item), arcOpacity(item.arc));
  }

  function pulseBaseColor(item) {
    const alpha = Math.round(110 + 145 * item.arc.activity);
    if (item.arc.threat) {
      return rgb(view.colors.danger, alpha);
    }
    if (item.arc.contained) {
      return rgb(view.colors.contained, alpha);
    }
    if (categorical()) {
      return rgb(baseColor(item.arc), alpha);
    }
    // by who connected, pulses keep the arc's color; their movement shows which way the data goes
    const scheme = view.settings.colorMode === 'initiator' ? initiatorScheme(item.arc.initiated) : item.toward ? view.colors.toward : view.colors.away;
    return rgb(scheme.pulse, alpha);
  }

  // green: started inside the network; orange (theme accent): started from outside
  function initiatorScheme(side) {
    return side === 'remote' ? view.colors.inbound : side === 'local' ? view.colors.away : view.colors.neutral;
  }

  function baseColor(arc) {
    return categoryColor(categoryOf(arc));
  }

  function legend() {
    if (view.settings.colorMode === 'initiator') {
      // always show inside and outside, so the meaning of green and orange is never a guess
      const present = new Set(['local', 'remote', ...view.arcs.filter((arc) => !arc.fading).map((arc) => arc.initiated)]);
      return [
        ...['local', 'remote', 'both'].filter((side) => present.has(side))
          .map((side) => ({label: view.text[`map_started_${side === 'local' ? 'inside' : side === 'remote' ? 'outside' : 'both'}`], color: initiatorScheme(side).heavy})),
        ...outcomeLegend(),
      ];
    }
    if (!categorical()) {
      return [
        {label: view.text.map_toward, color: view.colors.toward.heavy},
        {label: view.text.map_away, color: view.colors.away.heavy},
        ...outcomeLegend(),
      ];
    }
    const present = [...new Set(view.arcs.filter((arc) => !arc.fading).map(categoryOf))];
    present.sort((a, b) => (a === 'Other' ? 1 : b === 'Other' ? -1 : a.localeCompare(b)));
    return [
      ...present.map((name) => ({label: view.settings.colorMode === 'service' ? categoryLabel(name, view.text) : name, color: categoryColor(name)})),
      ...outcomeLegend(),
    ];
  }

  function outcomeLegend() {
    return [
      {label: view.text.map_blocked, color: view.colors.blocked},
      {label: view.text.map_flagged_blocked, color: view.colors.contained},
      {label: view.text.map_flagged_allowed, color: view.colors.danger},
    ];
  }

  function blockColor(block) {
    return (block.lists || []).length ? view.colors.contained : view.colors.blocked;
  }

  function outcomeColor(kind) {
    return {danger: view.colors.danger, contained: view.colors.contained, blocked: view.colors.blocked, ok: view.colors.blocked}[kind];
  }

  function pulseLayer(seconds) {
    return new ScatterplotLayer({
      id: 'firewall-map-pulses',
      data: view.pulseItems.filter((item) => view.drawn(item.arc)),
      getPosition: (item) => pulsePosition(item.arc, seconds, item.reverse, item.period, item.phase),
      getRadius: (item) => item.march ? (item.arc.heavy ? 2.6 : 1.9) : item.arc.heavy ? 3.4 : 2.4,
      radiusUnits: 'pixels',
      getFillColor: (item) => pulseColor(item),
      updateTriggers: {getPosition: seconds, getFillColor: [view.colors.toward.pulse, view.colors.away.pulse, view.colors.inbound.pulse, view.settings.colorMode, categoryKey]},
    });
  }

  function blockPulseLayers(seconds) {
    const active = view.blockArcs.filter((block) => block.activity > 0 && view.drawn(block));
    return [
      new ScatterplotLayer({
        id: 'firewall-map-block-pulses',
        data: active,
        getPosition: (block) => pulsePosition(block, seconds, false),
        getRadius: (block) => block.threat ? 3.6 : 2.6,
        radiusUnits: 'pixels',
        getFillColor: (block) => rgb(blockColor(block), Math.round((80 + 175 * block.activity) * view.blockFader.opacity(block, view.frameNow))),
        updateTriggers: {getPosition: seconds, getFillColor: [view.colors.blocked, view.colors.contained]},
      }),
      new ScatterplotLayer({
        id: 'firewall-map-threats',
        data: view.blockArcs.filter((block) => block.threat),
        getPosition: (block) => [block.lon, block.lat],
        // a throbbing halo around sources hammering the firewall
        getRadius: () => 6 + 6 * ((seconds / THREAT_THROB_PERIOD) % 1),
        radiusUnits: 'pixels',
        stroked: true,
        filled: false,
        lineWidthUnits: 'pixels',
        getLineWidth: 1.5,
        getLineColor: (block) => rgb(blockColor(block), Math.round(220 * (1 - (seconds / THREAT_THROB_PERIOD) % 1))),
        updateTriggers: {getRadius: seconds, getLineColor: [seconds, view.colors.blocked, view.colors.contained]},
      }),
    ];
  }

  return {
    categoryKey: () => categoryKey,
    categoryOf, categorical, categoryColor, arcColor, idsLinger, arcOpacity, arcBaseColor, pulseColor, pulseBaseColor, initiatorScheme, baseColor, legend, outcomeLegend, blockColor, outcomeColor, pulseLayer, blockPulseLayers,
  };
}
