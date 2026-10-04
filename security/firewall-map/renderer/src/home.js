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

// the firewall's own location: an outline house, tinted by the layer (mask), so it is not
// mistaken for the hollow rings that mark flagged addresses. Drawn on a canvas because the
// OPNsense content policy does not let deck.gl fetch a data: URL.
let homeAtlas = null;
export function homeIconAtlas() {
  if (!homeAtlas) {
    const canvas = document.createElement('canvas');
    canvas.width = canvas.height = 48;
    const context = canvas.getContext('2d');
    context.scale(2, 2);
    context.strokeStyle = '#000';
    context.lineWidth = 2.2;
    context.lineCap = context.lineJoin = 'round';
    context.stroke(new Path2D('M3 10.5 12 3l9 7.5M5.5 8.5V21h13V8.5M10 21v-6h4v6'));
    homeAtlas = canvas;
  }
  return homeAtlas;
}
export const HOME_LAYER = 'firewall-map-home';
export const HOME_ICON_MAPPING = {home: {x: 0, y: 0, width: 48, height: 48, anchorY: 24, mask: true}};
