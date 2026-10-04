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
 * The per-user map options: one set of defaults for the dashboard widget and the map page, and
 * one parser for the values the dashboard stores (strings from the options dialog).
 */
export const DEFAULT_OPTIONS = {
  heavyTop: 5, heavyRate: 1000000, maxArcs: 100, labels: true, hostnames: false, asn: true, blocks: true,
  blockMin: 3, colorMode: 'initiator', follow: false,
};

/** The options dialog's values ("5", "0", "1") as renderer settings, defaults for anything unset. */
export function parseSettings(config = {}) {
  const number = (value, fallback) => {
    const parsed = parseInt(value, 10);
    return Number.isFinite(parsed) ? parsed : fallback;
  };
  return {
    heavyTop: number(config.heavy_top, DEFAULT_OPTIONS.heavyTop),
    heavyRate: number(config.heavy_rate, DEFAULT_OPTIONS.heavyRate),
    maxArcs: number(config.max_arcs, DEFAULT_OPTIONS.maxArcs),
    labels: config.labels !== '0',
    hostnames: config.hostnames === '1',
    asn: config.asn !== '0',
    blocks: config.blocks !== '0',
    blockMin: number(config.block_min, DEFAULT_OPTIONS.blockMin) || DEFAULT_OPTIONS.blockMin,
    follow: config.follow === '1',
  };
}

/** The live data request's parameters: the viewer's block threshold and reverse DNS choice. */
export function snapshotParams(settings) {
  return {blocks_min: settings.blockMin ?? DEFAULT_OPTIONS.blockMin, ...(settings.hostnames ? {hostnames: 1} : {})};
}

/** The same as a query string, for a request that does not build it itself (the page). */
export function snapshotQuery(settings) {
  return `?blocks_min=${settings.blockMin ?? DEFAULT_OPTIONS.blockMin}${settings.hostnames ? '&hostnames=1' : ''}`;
}
