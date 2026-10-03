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

/* Firewall Map+ renderer. Bundled locally from deck.gl; the IIFE build assigns this module's
 * exports to the global FirewallMapRenderer. */
import * as host from './host.js';
import {createFirewallMap} from './map.js';

export {createFirewallMap as create, host};
export {DEFAULT_OPTIONS, parseSettings, snapshotParams, snapshotQuery} from './options.js';
export {palette, readTheme, serviceCategory} from './palette.js';
export {DEFAULT_TEXT} from './text.js';
export {escapeHtml, fill, flagHtml, formatBytes, formatRate, listLabel, plain, plural, splitHostPort} from './format.js';
export {alertOutcome, blockSummary, flowSummary, idsOutcome, idsSummary, outcome} from './summaries.js';
export {buildArcs, buildBlocks, idsArcActivity, idsArcData} from './arcs.js';
