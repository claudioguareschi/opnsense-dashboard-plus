/* Investigations: registry, routing and AbuseIPDB lookups for one address. */
import {escapeHtml} from '../src/format.js';
import {errorText, getJSON, notify} from './api.js';
import {MAX_INVESTIGATIONS, state, T} from './context.js';
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
    state.abuseScores.set(address, result.abuseipdb.score);
  }
}

/** The full lookup for an address; `rerender` redraws whatever shows the card. */
export async function investigate(address, rerender) {
  remember(address, `<div class="text-muted"><i class="fa fa-spinner fa-spin"></i> ${escapeHtml(T.looking_up)}</div>`);
  rerender();
  try {
    const result = await getJSON(`/api/firewallmap/investigate/address/${encodeURIComponent(address)}`);
    remember(address, investigationCard(result));
    noteScore(result, address);
  } catch (error) {
    remember(address, `<div class="text-danger">${escapeHtml(T.action_failed)}: ${escapeHtml(errorText(error))}</div>`);
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
