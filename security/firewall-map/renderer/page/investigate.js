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

/* Investigations: registry, routing and AbuseIPDB lookups for one address. */
import {escapeHtml} from '../src/format.js';
import {errorText, getJSON, notify} from './api.js';
import {MAX_ABUSE_SCORES, MAX_INVESTIGATIONS, state, T} from './context.js';
import {rows} from './parts.js';

function scoreBadge(score) {
  const kind = score >= 75 ? 'danger' : score >= 25 ? 'warning' : score > 0 ? 'contained' : 'ok';
  return `<span class="fwmap-pill fwmap-pill-${kind}">${escapeHtml(score)}%</span>`;
}

export function investigationCard(result) {
  if (result.status !== 'ok') {
    return `<div class="text-danger">${escapeHtml(result.error || T.action_failed)}</div>`;
  }
  const section = (title, data, body) => `<div class="fwmap-inv-section"><div class="fwmap-inv-title">${escapeHtml(title)}</div>`
    + (data?.error ? `<div class="text-muted">${escapeHtml(T.lookup_failed)}: ${escapeHtml(data.error)}</div>` : body) + '</div>';
  const table = (items) => rows(items, 'fwmap-inv-table');
  const rdap = result.rdap || {};
  const ripe = result.ripestat || {};
  const abuse = result.abuseipdb;
  let html = section(T.registry, rdap, table([
    [T.owner, escapeHtml(rdap.owner || rdap.name)],
    [T.network, escapeHtml([rdap.name, rdap.handle].filter(Boolean).join(' · '))],
    [T.range, escapeHtml(rdap.range)],
    [T.country, escapeHtml(rdap.country)],
    [T.abuse_contact, rdap.abuse_email ? `<a href="mailto:${escapeHtml(rdap.abuse_email)}">${escapeHtml(rdap.abuse_email)}</a>` : ''],
    [T.registered, escapeHtml([rdap.registered, rdap.updated && `${T.updated} ${rdap.updated}`].filter(Boolean).join(' · '))],
  ]));
  html += section(T.routing, ripe, table([
    [T.prefix, escapeHtml(ripe.prefix)],
    [T.origin_as, (ripe.asns || []).map((item) => escapeHtml(`AS${item.asn} ${item.holder || ''}`)).join('<br>')],
    [T.announced, ripe.announced === undefined ? '' : escapeHtml(ripe.announced ? T.yes : T.no)],
  ]));
  if (abuse) {
    html += section('AbuseIPDB', abuse, table([
      [T.confidence, abuse.score === undefined ? '' : scoreBadge(abuse.score)],
      [T.reports, abuse.reports === undefined ? '' : escapeHtml(`${abuse.reports} (${abuse.reporters ?? 0} ${T.reporters})`)],
      [T.last_reported, escapeHtml(abuse.last_reported)],
      [T.usage, escapeHtml([abuse.usage, abuse.tor ? 'Tor' : null].filter(Boolean).join(' · '))],
      ['ISP', escapeHtml([abuse.isp, abuse.domain].filter(Boolean).join(' · '))],
    ]));
  } else if (!result.abuseipdb_configured) {
    html += `<div class="text-muted fwmap-inv-section">${escapeHtml(T.abuseipdb_hint)}</div>`;
  }
  return html;
}

/** Keep a card for the most recent addresses only. */
function remember(address, html) {
  state.investigations.delete(address);
  state.investigations.set(address, html);
  while (state.investigations.size > MAX_INVESTIGATIONS) {
    state.investigations.delete(state.investigations.keys().next().value);
  }
}

function noteScore(result, address) {
  if (result.abuseipdb && typeof result.abuseipdb.score === 'number') {
    state.abuseScores.delete(address);
    state.abuseScores.set(address, result.abuseipdb.score);
    // the page may stay open for weeks: keep the most recent verdicts only
    while (state.abuseScores.size > MAX_ABUSE_SCORES) {
      state.abuseScores.delete(state.abuseScores.keys().next().value);
    }
  }
}

// a lookup that fails outright (the firewall busy, a registry slow to answer) is tried again once
const RETRY_MS = 1500;

function failureCard(address, text) {
  return `<div class="text-danger">${escapeHtml(T.action_failed)}: ${escapeHtml(text)}</div>`
    + `<button type="button" class="btn btn-default btn-xs fwmap-investigate fwmap-inv-retry" data-address="${escapeHtml(address)}">`
    + `<i class="fa fa-rotate-right"></i> ${escapeHtml(T.retry)}</button>`;
}

async function lookup(address) {
  let failure = null;
  for (let attempt = 0; attempt < 2; attempt++) {
    if (attempt) {
      await new Promise((resolve) => setTimeout(resolve, RETRY_MS));
    }
    try {
      const result = await getJSON(`/api/firewallmap/investigate/address/${encodeURIComponent(address)}`);
      if (result.status === 'ok') {
        return {result};
      }
      failure = result.error || T.lookup_failed;
    } catch (error) {
      failure = errorText(error);
    }
  }
  return {failure};
}

/** The full lookup for an address; `rerender` redraws whatever shows the card, scrolled to it. */
export async function investigate(address, rerender) {
  // one slow scroll to the card when the lookup starts; the data then fills in where the eye already is
  state.revealInvestigation = address;
  remember(address, `<div class="fwmap-inv-loading"><i class="fa fa-spinner fa-spin"></i> ${escapeHtml(T.looking_up)}</div>`);
  rerender();
  state.revealInvestigation = null;
  const {result, failure} = await lookup(address);
  if (result) {
    remember(address, investigationCard(result));
    noteScore(result, address);
  } else {
    remember(address, failureCard(address, failure));
  }
  rerender();
}

/** AbuseIPDB alone, from the Reputation card: the verdict fills in without opening the full investigation. */
export async function checkAbuse(address, rerender) {
  state.abuseChecking.add(address);
  rerender();
  try {
    const result = await getJSON(`/api/firewallmap/investigate/address/${encodeURIComponent(address)}`);
    noteScore(result, address);
    if (!state.abuseScores.has(address)) {
      notify(`AbuseIPDB: ${result.abuseipdb?.error || result.error || T.lookup_failed}`, BootstrapDialog.TYPE_WARNING);
    }
  } catch (error) {
    notify(`${T.action_failed}: ${errorText(error)}`, BootstrapDialog.TYPE_DANGER);
  }
  state.abuseChecking.delete(address);
  rerender();
}
