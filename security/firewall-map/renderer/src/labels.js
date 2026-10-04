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

/* Place names on the map: one label per place, busiest first, placed in screen space so they
 * never overlap each other or a house. Reads the map's current state through `view`. */
import {WebMercatorViewport} from '@deck.gl/core';
import {TextLayer} from '@deck.gl/layers';
import {HOME_CLEARANCE} from './arcs.js';
import {plain} from './format.js';

// city labels appear once the map is zoomed this far past the fitted world view
export const LABEL_ZOOM_STEP = 1.2;
const MAX_LABELS = 40;
// places considered for a label, busiest first (most are off screen when zoomed in)
const MAX_LABEL_CANDIDATES = 600;
const LABEL_FONT_SIZE = 11;
// approximate glyph width for placing labels before they are drawn
const LABEL_CHAR_WIDTH = 6.2;
const LABEL_PADDING = 3;

export function createLabels(view) {
  // one label per place, busiest places first
  // one label per place: busiest allowed traffic first, then blocked sources and alerts by hits
  function labels(data) {
    const seen = new Map();
    const add = (place, rank, weight) => {
      const text = place?.city || place?.region || place?.country;
      if (!text || !Number.isFinite(place.lat) || !Number.isFinite(place.lon)) {
        return;
      }
      const key = `${place.lat},${place.lon}`;
      const current = seen.get(key);
      if (!current || rank < current.rank) {
        seen.set(key, {text, lat: place.lat, lon: place.lon, rank, weight});
      } else if (rank === current.rank) {
        current.weight += weight;
      }
    };
    for (const flow of data.flows || []) {
      add(view.locationIndex.get(flow.dest), 0, flow.rate || 0);
    }
    if (view.settings.blocks) {
      (data.blocks || []).forEach((block) => add(block, 1, block.hits || 0));
    }
    (data.alerts || []).forEach((alert) => add(alert, 1, alert.count || 1));
    return [...seen.values()].sort((a, b) => a.rank - b.rank || b.weight - a.weight).slice(0, MAX_LABEL_CANDIDATES);
  }

  /**
   * Greedy screen-space placement: busiest places first, each label tries above, below,
   * right and left of its point and is dropped when every spot overlaps a placed label or a
   * house. Only places on screen count towards MAX_LABELS, and places hidden inside a house's
   * circle get none.
   */
  function placeLabels(candidates) {
    const width = view.container.clientWidth;
    const height = view.container.clientHeight;
    if (!width || !height) {
      return [];
    }
    const viewport = new WebMercatorViewport({...view.viewState, width, height});
    const placed = [];
    // labels keep out of the clear circle around each house
    const homePixels = view.homesDrawn.map((home) => viewport.project([home.lon, home.lat]));
    const boxes = homePixels.map(([x, y]) => [x - HOME_CLEARANCE, y - HOME_CLEARANCE, x + HOME_CLEARANCE, y + HOME_CLEARANCE]);
    for (const label of candidates) {
      if (placed.length >= MAX_LABELS) {
        break;
      }
      const [px, py] = viewport.project([label.lon, label.lat]);
      if (px < 0 || py < 0 || px > width || py > height ||
          homePixels.some(([x, y]) => Math.hypot(px - x, py - y) < HOME_CLEARANCE)) {
        continue;
      }
      const w = label.text.length * LABEL_CHAR_WIDTH + 2 * LABEL_PADDING;
      const h = LABEL_FONT_SIZE + 2 * LABEL_PADDING;
      const spots = [[0, -(h / 2 + 5)], [0, h / 2 + 5], [w / 2 + 6, 0], [-(w / 2 + 6), 0]];
      for (const [dx, dy] of spots) {
        const box = [px + dx - w / 2, py + dy - h / 2, px + dx + w / 2, py + dy + h / 2];
        const inside = box[0] >= 0 && box[1] >= 0 && box[2] <= width && box[3] <= height;
        const clear = boxes.every((other) => box[2] <= other[0] || box[0] >= other[2] || box[3] <= other[1] || box[1] >= other[3]);
        if (inside && clear) {
          boxes.push(box);
          placed.push({...label, offset: [dx, dy]});
          break;
        }
      }
    }
    return placed;
  }

  function buildLabelLayer() {
    const visible = view.settings.labels && view.viewState.zoom >= view.viewState.minZoom + LABEL_ZOOM_STEP;
    return new TextLayer({
      id: 'firewall-map-labels',
      data: visible ? placeLabels(view.labelCandidates) : [],
      visible,
      getPosition: (label) => [label.lon, label.lat],
      getText: (label) => plain(label.text),
      getSize: LABEL_FONT_SIZE,
      getColor: view.colors.label,
      getPixelOffset: (label) => label.offset,
      fontFamily: getComputedStyle(view.container).fontFamily || 'sans-serif',
      outlineWidth: 3,
      outlineColor: view.colors.background,
      fontSettings: {sdf: true},
      characterSet: 'auto',
      updateTriggers: {getColor: view.colors.label},
    });
  }

  return {labels, buildLabelLayer};
}
