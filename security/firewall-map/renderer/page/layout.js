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

/* The page layout: resizable panels (remembered per browser) and the follow-traffic toggle. */
import {state, T} from './context.js';
import {readStorage, writeStorage} from './storage.js';

const LAYOUT_KEY = 'firewallmap.layout';
const FOLLOW_KEY = 'firewallmap.follow';
// arrow keys move a splitter by this many pixels (side panel) or this share (the two side boxes)
const KEY_STEP_PX = 24;
const KEY_STEP_SHARE = 0.05;

/**
 * Follow traffic: the choice made on this page wins; until one is made, the dashboard widget's
 * "Follow traffic" option decides, so the two never disagree silently.
 */
export function readFollow() {
  const stored = readStorage(FOLLOW_KEY);
  return stored === null ? Boolean(state.settings?.follow) : stored === '1';
}

export function setFollow(on, tellRenderer = true) {
  state.follow = Boolean(on);
  $('#fwmap-follow').toggleClass('active', state.follow).attr('aria-pressed', String(state.follow));
  writeStorage(FOLLOW_KEY, state.follow ? '1' : '0');
  if (tellRenderer) {
    state.renderer?.setFollow(state.follow);
  }
}

function readLayout() {
  try {
    return JSON.parse(readStorage(LAYOUT_KEY) || '{}') || {};
  } catch (_) {
    return {};
  }
}

function applyLayout(layout) {
  const $side = $('#fwmap-side');
  if (layout.side) {
    $side.css({width: `${layout.side}px`, flex: `0 0 ${layout.side}px`});
  } else {
    $side.css({width: '', flex: ''});
  }
  const share = layout.talkers || 0.5;
  $('#fwmap-talkers').css('flex', `${share} 1 0`);
  $('#fwmap-details-box').css('flex', `${1 - share} 1 0`);
  $('#fwmap-split-side').attr('aria-valuenow', Math.round($side.outerWidth() || 0));
  $('#fwmap-split-details').attr('aria-valuenow', Math.round(share * 100));
}

function commit() {
  applyLayout(state.layout);
  writeStorage(LAYOUT_KEY, JSON.stringify(state.layout));
  state.renderer?.resize();
}

/**
 * A splitter: pointer drag (the map redraws once per frame), arrow keys, double-click or Home
 * to reset. `moveTo(event)` and `step(delta)` change state.layout; `reset()` forgets the size.
 */
function splitter($handle, {moveTo, step, reset}) {
  let frame = null;
  const onMove = (event) => {
    moveTo(event);
    applyLayout(state.layout);
    if (frame === null) {
      frame = requestAnimationFrame(() => {
        frame = null;
        state.renderer?.resize();
      });
    }
  };
  const onUp = () => {
    document.removeEventListener('pointermove', onMove);
    document.removeEventListener('pointerup', onUp);
    document.removeEventListener('pointercancel', onUp);
    $handle.removeClass('fwmap-dragging');
    $('body').removeClass('fwmap-resizing');
    commit();
  };
  $handle.attr({tabindex: '0', role: 'separator', 'aria-label': T.resize_hint || $handle.attr('title')})
    .on('pointerdown', (event) => {
      event.preventDefault();
      // listen on the document so a fast drag that leaves the thin handle keeps working
      document.addEventListener('pointermove', onMove);
      document.addEventListener('pointerup', onUp);
      document.addEventListener('pointercancel', onUp);
      $handle.addClass('fwmap-dragging');
      $('body').addClass('fwmap-resizing');
    })
    .on('dblclick', () => {
      reset();
      commit();
    })
    .on('keydown', (event) => {
      const keys = {ArrowLeft: -1, ArrowUp: -1, ArrowRight: 1, ArrowDown: 1};
      if (event.key in keys) {
        event.preventDefault();
        step(keys[event.key]);
        commit();
      } else if (event.key === 'Home') {
        event.preventDefault();
        reset();
        commit();
      }
    });
}

export function bindSplitters() {
  state.layout = readLayout();
  applyLayout(state.layout);
  const sideBounds = () => $('#fwmap-layout')[0].getBoundingClientRect();
  const clampSide = (width) => Math.max(220, Math.min(width, Math.round(sideBounds().width * 0.6)));
  splitter($('#fwmap-split-side').attr('aria-orientation', 'vertical'), {
    // the side panel is right of the map: its width is what lies right of the pointer
    moveTo: (event) => {
      state.layout.side = clampSide(Math.round(sideBounds().right - event.clientX - 6));
    },
    // moving the splitter right makes the side panel narrower
    step: (direction) => {
      state.layout.side = clampSide(($('#fwmap-side').outerWidth() || 0) - direction * KEY_STEP_PX);
    },
    reset: () => {
      delete state.layout.side;
    },
  });
  const clampShare = (share) => Math.max(0.15, Math.min(share, 0.85));
  splitter($('#fwmap-split-details').attr('aria-orientation', 'horizontal'), {
    moveTo: (event) => {
      const bounds = $('#fwmap-side')[0].getBoundingClientRect();
      state.layout.talkers = clampShare((event.clientY - bounds.top) / bounds.height);
    },
    step: (direction) => {
      state.layout.talkers = clampShare((state.layout.talkers || 0.5) + direction * KEY_STEP_SHARE);
    },
    reset: () => {
      delete state.layout.talkers;
    },
  });
}

/** Drop the least important talker column when the side panel is narrow. */
export function watchSideWidth() {
  const side = document.getElementById('fwmap-side');
  const update = () => side.classList.toggle('fwmap-narrow', side.clientWidth < 470);
  if (window.ResizeObserver) {
    new ResizeObserver(update).observe(side);
  }
  update();
}
