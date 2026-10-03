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

/* What the map shows: the snapshot narrowed by the toolbar filters. */
import {serviceCategory} from '../src/palette.js';
import {state} from './context.js';

export function locationsById(snapshot) {
  return new Map((snapshot.locations || []).map((location) => [location.id, location]));
}

export function flowService(flow) {
  return serviceCategory((flow.services || [])[0]);
}

function flowMatches(flow, locations) {
  const f = state.filters;
  const dest = locations.get(flow.dest) || {};
  if (f.traffic === 'blocked') {
    return false;
  }
  if (f.traffic === 'threats' && !flow.threat) {
    return false;
  }
  if (f.traffic === 'ids' && !flow.ids) {
    return false;
  }
  if (f.traffic === 'ids_flows' || (f.traffic === 'ids_addresses' && !flow.ids)) {
    return false;
  }
  if (f.service && flowService(flow) !== f.service) {
    return false;
  }
  if (f.iface && !(flow.inside || []).some((inside) => inside.interface === f.iface)) {
    return false;
  }
  if (f.host && !(flow.inside || []).some((inside) => inside.ip === f.host)) {
    return false;
  }
  if (f.country && dest.country !== f.country) {
    return false;
  }
  if (f.asn && String(dest.asn || '') !== f.asn) {
    return false;
  }
  return true;
}

function blockMatches(block) {
  const f = state.filters;
  if (f.traffic === 'permitted') {
    return false;
  }
  // "threats" means flagged traffic that got through; blocked sources have their own view
  if (f.traffic === 'threats') {
    return false;
  }
  if (f.traffic === 'ids' && !block.ids) {
    return false;
  }
  if (f.traffic === 'ids_flows' || (f.traffic === 'ids_addresses' && !block.ids)) {
    return false;
  }
  // blocked sources have no service category or inside host
  if (f.service || f.iface || f.host) {
    return false;
  }
  if (f.country && block.country !== f.country) {
    return false;
  }
  if (f.asn && String(block.asn || '') !== f.asn) {
    return false;
  }
  return true;
}

function idsFlowMatches(flow) {
  const f = state.filters;
  if (f.traffic === 'blocked' || (f.traffic === 'threats' && flow.severity > 2 && !(flow.lists || []).length)) {
    return false;
  }
  if (f.host && !(flow.inside || '').startsWith(`${f.host}:`) && flow.inside !== f.host) {
    return false;
  }
  if (f.service || f.iface) {
    return false;
  }
  if (f.country && flow.country !== f.country) {
    return false;
  }
  return !(f.asn && String(flow.asn || '') !== f.asn);
}

function alertMatches(alert) {
  const f = state.filters;
  if (f.service || f.iface || f.host) {
    return false;
  }
  if (f.country && alert.country !== f.country) {
    return false;
  }
  return !(f.asn && String(alert.asn || '') !== f.asn);
}

export function filtered(snapshot) {
  const locations = locationsById(snapshot);
  const flows = (snapshot.flows || []).filter((flow) => flowMatches(flow, locations));
  const blocks = state.settings.blocks ? (snapshot.blocks || []).filter(blockMatches) : [];
  // alerting addresses without an arc: shown with everything, or when looking at IDS alerts
  const alerts = ['', 'all', 'ids', 'ids_addresses'].includes(state.filters.traffic || '') ? (snapshot.alerts || []).filter(alertMatches) : [];
  const used = new Set(flows.flatMap((flow) => [flow.origin, flow.dest]));
  return {
    ...snapshot,
    flows,
    blocks,
    alerts,
    ids_flows: (snapshot.ids_flows || []).filter(idsFlowMatches),
    locations: (snapshot.locations || []).filter((location) => location.local || used.has(location.id)),
  };
}
