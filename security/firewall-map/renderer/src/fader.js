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

/* Fading: arcs, blocked sources and endpoints fade in and out instead of popping. */

// arches, blocked sources and endpoints fade in and out instead of popping
export const FADE_IN_MS = 800;

/** A color with its alpha scaled by a fade opacity. */
export function faded(color, opacity) {
  return opacity >= 1 ? color : [color[0], color[1], color[2], Math.round((color[3] ?? 255) * opacity)];
}
export const FADE_OUT_MS = 1600;

/** Tracks when each keyed item appeared or vanished; vanished items linger while fading out. */
export class Fader {
  constructor(keyOf) {
    this.keyOf = keyOf;
    this.entries = new Map();
  }

  opacityOf(entry, now) {
    const fadeIn = Math.min(1, (now - entry.born) / FADE_IN_MS);
    const fadeOut = entry.gone === null ? 1 : Math.max(0, 1 - (now - entry.gone) / FADE_OUT_MS);
    return Math.max(0, fadeIn * fadeOut);
  }

  update(items, now) {
    const next = new Map();
    const result = [];
    for (const item of items) {
      const key = this.keyOf(item);
      if (next.has(key)) {
        continue;
      }
      const previous = this.entries.get(key);
      let born = now;
      if (previous) {
        // coming back while fading out resumes from the current opacity
        born = previous.gone === null ? previous.born : now - this.opacityOf(previous, now) * FADE_IN_MS;
      }
      const entry = {item, born, gone: null};
      item.fade = entry;
      next.set(key, entry);
      result.push(item);
    }
    for (const [key, entry] of this.entries) {
      if (next.has(key)) {
        continue;
      }
      if (entry.gone === null) {
        entry.gone = now;
      }
      if (this.opacityOf(entry, now) > 0) {
        entry.item.fading = true;
        next.set(key, entry);
        result.push(entry.item);
      }
    }
    this.entries = next;
    return result;
  }

  opacity(item, now) {
    return item.fade ? this.opacityOf(item.fade, now) : 1;
  }

  animating(now) {
    for (const entry of this.entries.values()) {
      if (entry.gone !== null || now - entry.born < FADE_IN_MS) {
        return true;
      }
    }
    return false;
  }
}
