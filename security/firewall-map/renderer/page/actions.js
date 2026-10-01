/* Actions on an address: states, aliases, the watchlist, GeoIP countries. They change the firewall. */
import {escapeHtml, hostPort, plain} from '../src/format.js';
import {confirmAction, errorText, getJSON, notify, notifyFailure, postJSON} from './api.js';
import {T, WATCHLIST} from './context.js';

export async function showStates(address) {
  try {
    const result = await postJSON('/api/diagnostics/firewall/query_states', {searchPhrase: address, rowCount: 100, current: 1});
    const count = (result.rows || []).length;
    const rows = (result.rows || []).map((row) => `<tr><td>${escapeHtml(row.interface)}</td><td>${escapeHtml(row.proto)}</td>`
      + `<td>${escapeHtml(hostPort(row.src_addr, row.src_port))}</td><td>${escapeHtml(hostPort(row.dst_addr, row.dst_port))}</td>`
      + `<td>${escapeHtml(row.state)}</td><td>${escapeHtml(row.bytes ?? '')}</td></tr>`).join('');
    BootstrapDialog.show({
      title: escapeHtml(`${T.states_for} ${address}`), size: BootstrapDialog.SIZE_WIDE,
      message: rows
        ? `<table class="table table-condensed table-striped"><thead><tr><th>${escapeHtml(T.interface)}</th><th>${escapeHtml(T.protocol)}</th>`
          + `<th>${escapeHtml(T.source)}</th><th>${escapeHtml(T.destination)}</th><th>${escapeHtml(T.state)}</th><th>${escapeHtml(T.bytes)}</th></tr></thead>`
          + `<tbody>${rows}</tbody></table>${result.total > count ? `<div class="text-muted">${escapeHtml(T.more_states)}</div>` : ''}`
        : escapeHtml(T.no_states),
      buttons: [{label: T.close, action: (dialog) => dialog.close()}],
    });
  } catch (error) {
    notifyFailure(error);
  }
}

export function killStates(address) {
  confirmAction(`${T.kill_confirm} ${address}? ${T.kill_scope}`, async () => {
    try {
      const result = await postJSON('/api/diagnostics/firewall/kill_states', {filter: address});
      notify(result.result === 'ok' ? `${T.killed} ${result.dropped_states}` : T.action_failed,
        result.result === 'ok' ? BootstrapDialog.TYPE_SUCCESS : BootstrapDialog.TYPE_DANGER);
    } catch (error) {
      notifyFailure(error);
    }
  });
}

async function aliasRows(types) {
  const result = await postJSON('/api/firewall/alias/search_item', {current: 1, rowCount: -1});
  return (result.rows || []).filter((row) => types.includes(String(row.type).toLowerCase().split(' ')[0])
    || types.includes(String(row.type).toLowerCase()));
}

/** Pick an alias of one of `types`; onChoose(name, uuid). */
export async function chooseAlias(types, title, onChoose) {
  let rows = [];
  try {
    rows = await aliasRows(types);
  } catch (error) {
    notifyFailure(error);
    return;
  }
  if (!rows.length) {
    notify(T.no_aliases);
    return;
  }
  const $select = $('<select class="form-control"></select>').attr('aria-label', T.add_to_alias).html(rows.map((row) =>
    `<option value="${escapeHtml(row.uuid)}" data-name="${escapeHtml(row.name)}">${escapeHtml(row.name)} (${escapeHtml(row.type)})</option>`).join(''));
  BootstrapDialog.show({
    title, message: $('<div></div>').append($select),
    buttons: [
      {label: T.cancel, action: (dialog) => dialog.close()},
      {label: T.confirm, cssClass: 'btn-primary', action: (dialog) => {
        const $option = $select.find(':selected');
        dialog.close();
        onChoose(plain($option.data('name')), $option.val());
      }},
    ],
  });
}

/** Add one address to a named alias; throws with the firewall's message when it is refused. */
export async function addAddressToAlias(name, address) {
  const result = await postJSON(`/api/firewall/alias_util/add/${encodeURIComponent(name)}`, {address});
  if (result.status !== 'done') {
    throw new Error(result.status_msg || result.status);
  }
}

export function addToAlias(address) {
  chooseAlias(['host', 'hosts', 'network', 'networks', 'external'], escapeHtml(`${T.add_to_alias}: ${address}`), (name) => {
    confirmAction(`${T.add_confirm} ${address} → ${name}?`, async () => {
      try {
        await addAddressToAlias(name, address);
        notify(`${address} → ${name}`, BootstrapDialog.TYPE_SUCCESS);
      } catch (error) {
        notifyFailure(error);
      }
    });
  });
}

// a plain host alias; it only marks traffic on the map until the operator uses it in a rule
export function markThreat(address) {
  confirmAction(`${T.mark_confirm} ${address} ${T.mark_scope}`, async () => {
    try {
      const found = await postJSON('/api/firewall/alias/search_item', {current: 1, rowCount: -1, searchPhrase: WATCHLIST});
      if (!(found.rows || []).some((row) => plain(row.name) === WATCHLIST)) {
        const saved = await postJSON('/api/firewall/alias/add_item', {alias: {
          enabled: '1', name: WATCHLIST, type: 'host', content: address,
          description: 'Firewall Map+ watchlist: addresses marked as threats (no rules use it unless you add one)',
        }});
        if (saved.result !== 'saved') {
          throw new Error(JSON.stringify(saved.validations || saved));
        }
        await postJSON('/api/firewall/alias/reconfigure', {});
      } else {
        await addAddressToAlias(WATCHLIST, address);
      }
      notify(`${address} → ${WATCHLIST}. ${T.marked}`, BootstrapDialog.TYPE_SUCCESS);
    } catch (error) {
      notifyFailure(error);
    }
  });
}

export function addCountry(code) {
  chooseAlias(['geoip', 'geoip (ip in country)'], escapeHtml(`${T.add_country} (${code})`), (name, uuid) => {
    confirmAction(`${T.add_confirm} ${code} → ${name}?`, async () => {
      try {
        const current = await getJSON(`/api/firewall/alias/get_item/${encodeURIComponent(uuid)}`);
        const content = current.alias?.content || {};
        const codes = Object.entries(content).filter(([, option]) => option.selected).map(([value]) => value);
        if (!codes.includes(code)) {
          codes.push(code);
        }
        const saved = await postJSON(`/api/firewall/alias/set_item/${encodeURIComponent(uuid)}`, {alias: {content: codes.join('\n')}});
        if (saved.result !== 'saved') {
          throw new Error(JSON.stringify(saved.validations || saved));
        }
        await postJSON('/api/firewall/alias/reconfigure', {});
        notify(`${code} → ${name}`, BootstrapDialog.TYPE_SUCCESS);
      } catch (error) {
        notify(`${T.action_failed}: ${errorText(error)}`, BootstrapDialog.TYPE_DANGER);
      }
    });
  });
}
