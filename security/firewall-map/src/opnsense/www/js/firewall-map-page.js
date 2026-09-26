/*
 * Copyright (C) 2026 Claudio Guareschi
 * All rights reserved.
 *
 * Full-size Firewall Map+ page: filters, colour modes with legend, top talkers and
 * investigation actions around the shared renderer (firewall-map-renderer.js).
 * Strings come from the page template as window.FirewallMapPageText.
 */

(function () {
    'use strict';

    const T = window.FirewallMapPageText || {};
    const POLL_MS = 2000;
    const HISTORY_POINTS = 60;
    const TALKER_ROWS = 12;

    // OPNsense HTML-escapes &, < and > in API responses; undo that, then escape for display
    const plain = (text) => String(text ?? '').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
    const esc = (text) => plain(text).replace(/[&<>"']/g, (char) => `&#${char.charCodeAt(0)};`);

    function formatRate(bytes) {
        const units = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
        let value = bytes || 0;
        let unit = 0;
        while (value >= 1000 && unit < units.length - 1) {
            value /= 1000;
            unit++;
        }
        return `${value >= 100 || unit === 0 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`;
    }

    function postJSON(url, payload) {
        return $.ajax({
            url, type: 'POST', dataType: 'json', contentType: 'application/json',
            data: JSON.stringify(payload || {}),
        });
    }

    const state = {
        renderer: null,
        snapshot: null,
        settings: null,
        filters: {traffic: 'all', service: '', iface: '', host: '', country: '', asn: ''},
        colorMode: 'direction',
        talkerTab: 'hosts',
        history: new Map(),
        isAdmin: false,
        selection: null,
        investigations: new Map(),
    };

    /* ---------------------------------------------------------------- filtering */

    function locationsById(snapshot) {
        return new Map((snapshot.locations || []).map((location) => [location.id, location]));
    }

    function flowService(flow) {
        return FirewallMapRenderer.serviceCategory((flow.services || [])[0]);
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
        if (f.traffic === 'threats' && !(block.threat || (block.lists || []).length)) {
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

    function filtered(snapshot) {
        const locations = locationsById(snapshot);
        const flows = (snapshot.flows || []).filter((flow) => flowMatches(flow, locations));
        const blocks = state.settings.blocks ? (snapshot.blocks || []).filter(blockMatches) : [];
        const used = new Set(flows.flatMap((flow) => [flow.origin, flow.dest]));
        return {
            ...snapshot,
            flows,
            blocks,
            locations: (snapshot.locations || []).filter((location) => location.local || used.has(location.id)),
        };
    }

    /* ---------------------------------------------------------------- toolbar */

    function fillSelect($select, values, current, allLabel) {
        const options = [`<option value="">${esc(allLabel)}</option>`]
            .concat([...values].sort((a, b) => String(a.label).localeCompare(String(b.label)))
                .map((item) => `<option value="${esc(item.value)}">${esc(item.label)}</option>`));
        if (current && ![...values].some((item) => String(item.value) === current)) {
            // keep a chosen value even while it has no live traffic
            options.push(`<option value="${esc(current)}">${esc(current)}</option>`);
        }
        const html = options.join('');
        // never rebuild a dropdown the user is working with
        if ($select.data('html') !== html && document.activeElement !== $select[0]) {
            $select.html(html).data('html', html);
        }
        $select.val(current);
    }

    function updateToolbar(snapshot) {
        const locations = locationsById(snapshot);
        const services = new Map();
        const ifaces = new Map();
        const hosts = new Map();
        const countries = new Map();
        for (const flow of snapshot.flows || []) {
            const service = flowService(flow);
            services.set(service, {value: service, label: service});
            for (const inside of flow.inside || []) {
                if (inside.interface) {
                    ifaces.set(inside.interface, {value: inside.interface, label: inside.interface});
                }
                hosts.set(inside.ip, {value: inside.ip, label: inside.name ? `${inside.name} (${inside.ip})` : inside.ip});
            }
            const country = locations.get(flow.dest)?.country;
            if (country) {
                countries.set(country, {value: country, label: plain(country)});
            }
        }
        for (const block of snapshot.blocks || []) {
            if (block.country) {
                countries.set(block.country, {value: block.country, label: plain(block.country)});
            }
        }
        fillSelect($('#fwmap-filter-service'), services.values(), state.filters.service, T.all_services);
        fillSelect($('#fwmap-filter-iface'), ifaces.values(), state.filters.iface, T.all_interfaces);
        fillSelect($('#fwmap-filter-host'), hosts.values(), state.filters.host, T.all_hosts);
        fillSelect($('#fwmap-filter-country'), countries.values(), state.filters.country, T.all_countries);
        const asnActive = state.filters.asn !== '';
        $('#fwmap-filter-asn').toggle(asnActive).find('span').text(asnActive ? `AS${state.filters.asn}` : '');
    }

    function updateLegend() {
        const items = state.renderer.legend();
        $('#fwmap-legend').html(items.map((item) =>
            `<span class="fwmap-legend-item"><i style="background:rgb(${item.color.slice(0, 3).join(',')})"></i>`
            + `${esc(item.label)}</span>`).join(''));
    }

    /* ---------------------------------------------------------------- top talkers */

    function talkers(snapshot) {
        const locations = locationsById(snapshot);
        const groups = {hosts: new Map(), countries: new Map(), networks: new Map()};
        const add = (group, key, label, sub, rate, filter) => {
            const entry = groups[group].get(key) || {key, label, sub, rate: 0, filter};
            entry.rate += rate;
            groups[group].set(key, entry);
        };
        for (const flow of snapshot.flows || []) {
            const rate = flow.rate || 0;
            const inside = (flow.inside || [])[0];
            if (inside) {
                add('hosts', inside.ip, inside.name || inside.ip, inside.name ? `${inside.ip} · ${inside.interface || ''}` : inside.interface,
                    rate, {host: inside.ip});
            }
            const dest = locations.get(flow.dest) || {};
            if (dest.country) {
                add('countries', dest.country, plain(dest.country), '', rate, {country: dest.country});
            }
            if (dest.asn) {
                add('networks', String(dest.asn), plain(dest.as_org || `AS${dest.asn}`), `AS${dest.asn}`, rate, {asn: String(dest.asn)});
            }
        }
        const result = {};
        for (const [group, entries] of Object.entries(groups)) {
            result[group] = [...entries.values()].sort((a, b) => b.rate - a.rate);
            for (const entry of result[group]) {
                const key = `${group}:${entry.key}`;
                const series = state.history.get(key) || [];
                series.push(entry.rate);
                if (series.length > HISTORY_POINTS) {
                    series.shift();
                }
                state.history.set(key, series);
                entry.series = series;
            }
        }
        // forget series that have gone quiet, so memory stays bounded
        for (const [key, series] of state.history) {
            const [group, id] = key.split(/:(.*)/s);
            if (!groups[group]?.has(id)) {
                series.push(0);
                if (series.length > HISTORY_POINTS) {
                    series.shift();
                }
                if (series.every((value) => value === 0)) {
                    state.history.delete(key);
                }
            }
        }
        return result;
    }

    function sparkline(canvas, series, color) {
        const context = canvas.getContext('2d');
        const {width, height} = canvas;
        context.clearRect(0, 0, width, height);
        if (!series || series.length < 2) {
            return;
        }
        const max = Math.max(...series, 1);
        context.strokeStyle = color;
        context.lineWidth = 1.2;
        context.beginPath();
        // newest point at the right edge, so a short history grows from the right
        const offset = HISTORY_POINTS - series.length;
        series.forEach((value, index) => {
            const x = ((offset + index) / (HISTORY_POINTS - 1)) * width;
            const y = height - 1 - (value / max) * (height - 2);
            index ? context.lineTo(x, y) : context.moveTo(x, y);
        });
        context.stroke();
    }

    function renderTalkers(groups) {
        const rows = (groups[state.talkerTab] || []).slice(0, TALKER_ROWS);
        const $list = $('#fwmap-talkers-list');
        if (!rows.length) {
            $list.html(`<div class="text-muted fwmap-empty">${esc(T.no_talkers)}</div>`);
            return;
        }
        $list.html(rows.map((row, index) => `
            <div class="fwmap-talker" data-index="${index}" title="${esc(T.filter_hint)}">
                <div class="fwmap-talker-text">
                    <div class="fwmap-talker-label">${esc(row.label)}</div>
                    ${row.sub ? `<div class="fwmap-talker-sub">${esc(row.sub)}</div>` : ''}
                </div>
                <canvas width="70" height="22"></canvas>
                <div class="fwmap-talker-rate">${formatRate(row.rate)}</div>
            </div>`).join(''));
        const accent = getComputedStyle(document.querySelector('#fwmap-talkers a') || document.body).color;
        state.talkerRows = rows;
        $list.find('.fwmap-talker').each(function () {
            sparkline($(this).find('canvas')[0], rows[$(this).data('index')].series, accent);
        });
    }

    /* ---------------------------------------------------------------- details and actions */

    function addressRow(address) {
        const links = [
            `<a href="#" class="fwmap-copy" data-address="${esc(address)}">${esc(T.copy)}</a>`,
            `<a href="https://bgp.he.net/ip/${encodeURIComponent(address)}" target="_blank" rel="noopener noreferrer">${esc(T.whois)}</a>`,
            `<a href="https://www.abuseipdb.com/check/${encodeURIComponent(address)}" target="_blank" rel="noopener noreferrer">AbuseIPDB</a>`,
        ];
        const admin = state.isAdmin ? [
            `<a href="#" class="fwmap-investigate" data-address="${esc(address)}"><b>${esc(T.investigate)}</b></a>`,
            `<a href="#" class="fwmap-states" data-address="${esc(address)}">${esc(T.show_states)}</a>`,
            `<a href="#" class="fwmap-kill" data-address="${esc(address)}">${esc(T.kill_states)}</a>`,
            `<a href="#" class="fwmap-alias" data-address="${esc(address)}">${esc(T.add_to_alias)}</a>`,
        ] : [];
        const card = state.investigations.get(address);
        return `<div class="fwmap-address"><b>${esc(address)}</b><div class="fwmap-links">${links.concat(admin).join(' · ')}</div>`
            + (card ? `<div class="fwmap-investigation">${card}</div>` : '') + '</div>';
    }

    /* ---------------------------------------------------------------- investigation card */

    function field(label, value) {
        return value === null || value === undefined || value === ''
            ? '' : `<tr><th>${esc(label)}</th><td>${value}</td></tr>`;
    }

    function scoreBadge(score) {
        const color = score >= 75 ? '#c41230' : score >= 25 ? '#e67e22' : score > 0 ? '#d4a017' : '#2e8b57';
        return `<span class="fwmap-score" style="background:${color}">${esc(score)}%</span>`;
    }

    function investigationCard(result) {
        if (result.status !== 'ok') {
            return `<div class="text-danger">${esc(result.error || T.action_failed)}</div>`;
        }
        const section = (title, data, rows) => `<div class="fwmap-inv-section"><div class="fwmap-inv-title">${esc(title)}</div>`
            + (data?.error ? `<div class="text-muted">${esc(T.lookup_failed)}: ${esc(data.error)}</div>`
                : `<table class="fwmap-inv-table">${rows}</table>`) + '</div>';
        const rdap = result.rdap || {};
        const ripe = result.ripestat || {};
        const abuse = result.abuseipdb;
        const abuseEmail = rdap.abuse_email
            ? `<a href="mailto:${esc(rdap.abuse_email)}">${esc(rdap.abuse_email)}</a>` : null;
        let html = section(T.registry, rdap,
            field(T.owner, esc(rdap.owner || rdap.name))
            + field(T.network, esc([rdap.name, rdap.handle].filter(Boolean).join(' · ')))
            + field(T.range, esc(rdap.range))
            + field(T.country, esc(rdap.country))
            + field(T.abuse_contact, abuseEmail)
            + field(T.registered, esc([rdap.registered, rdap.updated && `${T.updated} ${rdap.updated}`].filter(Boolean).join(' · '))));
        html += section(T.routing, ripe,
            field(T.prefix, esc(ripe.prefix))
            + field(T.origin_as, (ripe.asns || []).map((item) => esc(`AS${item.asn} ${item.holder || ''}`)).join('<br>'))
            + field(T.announced, ripe.announced === undefined ? null : esc(ripe.announced ? T.yes : T.no)));
        if (abuse) {
            html += section('AbuseIPDB', abuse,
                field(T.confidence, abuse.score === undefined ? null : scoreBadge(abuse.score))
                + field(T.reports, abuse.reports === undefined ? null : esc(`${abuse.reports} (${abuse.reporters ?? 0} ${T.reporters})`))
                + field(T.last_reported, esc(abuse.last_reported))
                + field(T.usage, esc([abuse.usage, abuse.tor ? 'Tor' : null].filter(Boolean).join(' · ')))
                + field('ISP', esc([abuse.isp, abuse.domain].filter(Boolean).join(' · '))));
        } else if (!result.abuseipdb_configured) {
            html += `<div class="text-muted fwmap-inv-section">${esc(T.abuseipdb_hint)}</div>`;
        }
        return html;
    }

    async function investigate(address) {
        state.investigations.set(address, `<div class="text-muted"><i class="fa fa-spinner fa-spin"></i> ${esc(T.looking_up)}</div>`);
        renderDetails();
        try {
            const result = await $.getJSON(`/api/firewallmap/investigate/address/${encodeURIComponent(address)}`);
            state.investigations.set(address, investigationCard(result));
        } catch (error) {
            state.investigations.set(address, `<div class="text-danger">${esc(T.action_failed)}: ${esc(error.statusText || error)}</div>`);
        }
        renderDetails();
    }

    /* ---------------------------------------------------------------- threat feeds */

    async function showFeeds() {
        let feeds = [];
        try {
            feeds = ((await $.getJSON('/api/firewallmap/settings/tables')).tables || []).filter((table) => table.curated);
        } catch (error) {
            notify(`${T.action_failed}: ${error.statusText || error}`, BootstrapDialog.TYPE_DANGER);
            return;
        }
        const $list = $('<div></div>');
        for (const feed of feeds) {
            const added = feed.installed;
            const $row = $(`<div class="fwmap-feed"><div><b>${esc(feed.label)}</b><div class="text-muted">${esc(feed.description)}</div>`
                + `<div class="text-muted" style="font-size:.85em">${esc(feed.url)}</div></div></div>`);
            const $button = $(`<button type="button" class="btn btn-sm ${added ? 'btn-default' : 'btn-primary'}"></button>`)
                .text(added ? T.feed_added : T.add_feed).prop('disabled', added);
            $button.on('click', async () => {
                $button.prop('disabled', true);
                try {
                    const saved = await postJSON('/api/firewall/alias/add_item', {alias: {
                        enabled: '1', name: feed.name, type: 'urltable', content: feed.url, updatefreq: '1',
                        description: `Firewall Map+ threat feed: ${feed.label}`,
                    }});
                    if (saved.result !== 'saved') {
                        throw new Error(JSON.stringify(saved.validations || saved));
                    }
                    await postJSON('/api/firewall/alias/reconfigure', {});
                    $button.removeClass('btn-primary').addClass('btn-default').text(T.feed_added);
                } catch (error) {
                    $button.prop('disabled', false);
                    notify(`${T.action_failed}: ${error.message || error.statusText || error}`, BootstrapDialog.TYPE_DANGER);
                }
            });
            $row.append($button);
            $list.append($row);
        }
        $list.append(`<div class="text-muted" style="margin-top:8px">${esc(T.feeds_note)}</div>`);
        BootstrapDialog.show({title: T.threat_feeds, message: $list, buttons: [{label: T.close, action: (dialog) => dialog.close()}]});
    }

    function renderDetails() {
        const selection = state.selection;
        const $details = $('#fwmap-details');
        if (!selection) {
            $details.html(`<div class="text-muted fwmap-empty">${esc(T.click_hint)}</div>`);
            return;
        }
        const addresses = [...new Set(selection.addresses)].slice(0, 8);
        const insides = [];
        for (const member of selection.members || []) {
            for (const inside of member.inside || []) {
                if (!insides.some((known) => known.ip === inside.ip)) {
                    insides.push(inside);
                }
            }
        }
        const kind = selection.kind === 'blocked' ? T.blocked_source : T.remote_endpoints;
        const lists = [...new Set([...(selection.block?.lists || []),
            ...(selection.members || []).flatMap((member) => member.lists || [])])];
        const country = state.isAdmin && selection.countryCode
            ? `<div class="fwmap-links"><a href="#" class="fwmap-country" data-code="${esc(selection.countryCode)}">`
              + `${esc(T.add_country)} (${esc(selection.countryCode)})</a></div>` : '';
        $details.html(`
            <div class="fwmap-details-head">
                <b>${esc(selection.title || '')}</b>
                <a href="#" id="fwmap-details-close" title="${esc(T.close)}">&times;</a>
            </div>
            <div class="text-muted">${esc(kind)}</div>
            ${lists.length ? `<div style="font-weight:600;color:rgb(196,18,48)">${esc(T.listed_in)} ${lists.map(esc).join(', ')}</div>` : ''}
            ${addresses.map(addressRow).join('')}
            ${insides.length ? `<div class="text-muted" style="margin-top:6px">${esc(T.inside_hosts)}</div>`
              + insides.map((inside) => `<div>${esc(inside.name || inside.ip)} <span class="text-muted">${esc([inside.ip, inside.interface].filter(Boolean).join(' · '))}</span></div>`).join('') : ''}
            ${country}
        `);
    }

    function notify(message, type) {
        BootstrapDialog.show({
            type: type || BootstrapDialog.TYPE_INFO, title: T.firewall_map, message: esc(message),
            buttons: [{label: T.close, action: (dialog) => dialog.close()}],
        });
    }

    function confirmAction(message, onConfirm) {
        BootstrapDialog.confirm({
            title: T.firewall_map, message: esc(message), type: BootstrapDialog.TYPE_WARNING,
            btnOKLabel: T.confirm, btnCancelLabel: T.cancel,
            callback: (confirmed) => confirmed && onConfirm(),
        });
    }

    async function showStates(address) {
        try {
            const result = await postJSON('/api/diagnostics/firewall/query_states', {searchPhrase: address, rowCount: 100, current: 1});
            const count = (result.rows || []).length;
            const rows = (result.rows || []).map((row) => `<tr><td>${esc(row.interface)}</td><td>${esc(row.proto)}</td>`
                + `<td>${esc(row.src_addr)}:${esc(row.src_port)}</td><td>${esc(row.dst_addr)}:${esc(row.dst_port)}</td>`
                + `<td>${esc(row.state)}</td><td>${esc(row.bytes ?? '')}</td></tr>`).join('');
            BootstrapDialog.show({
                title: esc(`${T.states_for} ${address}`), size: BootstrapDialog.SIZE_WIDE,
                message: rows
                    ? `<table class="table table-condensed table-striped"><thead><tr><th>${esc(T.interface)}</th><th>${esc(T.protocol)}</th>`
                      + `<th>${esc(T.source)}</th><th>${esc(T.destination)}</th><th>${esc(T.state)}</th><th>${esc(T.bytes)}</th></tr></thead>`
                      + `<tbody>${rows}</tbody></table>${result.total > count ? `<div class="text-muted">${esc(T.more_states)}</div>` : ''}`
                    : esc(T.no_states),
                buttons: [{label: T.close, action: (dialog) => dialog.close()}],
            });
        } catch (error) {
            notify(`${T.action_failed}: ${error.statusText || error}`, BootstrapDialog.TYPE_DANGER);
        }
    }

    function killStates(address) {
        confirmAction(`${T.kill_confirm} ${address}? ${T.kill_scope}`, async () => {
            try {
                const result = await postJSON('/api/diagnostics/firewall/kill_states', {filter: address});
                notify(result.result === 'ok' ? `${T.killed} ${result.dropped_states}` : T.action_failed,
                    result.result === 'ok' ? BootstrapDialog.TYPE_SUCCESS : BootstrapDialog.TYPE_DANGER);
            } catch (error) {
                notify(`${T.action_failed}: ${error.statusText || error}`, BootstrapDialog.TYPE_DANGER);
            }
        });
    }

    async function aliasRows(types) {
        const result = await postJSON('/api/firewall/alias/search_item', {current: 1, rowCount: -1});
        return (result.rows || []).filter((row) => types.includes(String(row.type).toLowerCase().split(' ')[0])
            || types.includes(String(row.type).toLowerCase()));
    }

    async function chooseAlias(types, title, onChoose) {
        let rows = [];
        try {
            rows = await aliasRows(types);
        } catch (error) {
            notify(`${T.action_failed}: ${error.statusText || error}`, BootstrapDialog.TYPE_DANGER);
            return;
        }
        if (!rows.length) {
            notify(T.no_aliases);
            return;
        }
        const $select = $('<select class="form-control"></select>').html(rows.map((row) =>
            `<option value="${esc(row.uuid)}" data-name="${esc(row.name)}">${esc(row.name)} (${esc(row.type)})</option>`).join(''));
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

    function addToAlias(address) {
        chooseAlias(['host', 'hosts', 'network', 'networks', 'external'], esc(`${T.add_to_alias}: ${address}`), (name) => {
            confirmAction(`${T.add_confirm} ${address} → ${name}?`, async () => {
                try {
                    const result = await postJSON(`/api/firewall/alias_util/add/${encodeURIComponent(name)}`, {address});
                    notify(result.status === 'done' ? `${address} → ${name}` : `${T.action_failed}: ${result.status_msg || result.status}`,
                        result.status === 'done' ? BootstrapDialog.TYPE_SUCCESS : BootstrapDialog.TYPE_DANGER);
                } catch (error) {
                    notify(`${T.action_failed}: ${error.statusText || error}`, BootstrapDialog.TYPE_DANGER);
                }
            });
        });
    }

    function addCountry(code) {
        chooseAlias(['geoip', 'geoip (ip in country)'], esc(`${T.add_country} (${code})`), (name, uuid) => {
            confirmAction(`${T.add_confirm} ${code} → ${name}?`, async () => {
                try {
                    const current = await $.getJSON(`/api/firewall/alias/get_item/${encodeURIComponent(uuid)}`);
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
                    notify(`${T.action_failed}: ${error.statusText || error.message || error}`, BootstrapDialog.TYPE_DANGER);
                }
            });
        });
    }

    /* ---------------------------------------------------------------- main loop */

    function statusLine(snapshot, shown) {
        const count = shown.flows.length;
        let message = count ? `${count} ${T.active_flows}` : T.no_flows;
        if (state.settings.blocks) {
            const blocked = shown.blocks.length;
            const below = snapshot.blocks_below || 0;
            if (blocked || below) {
                message += ` · ${blocked} ${T.blocked_sources}`;
                if (below) {
                    message += ` · ${below} ${T.below_threshold}`;
                }
            }
        }
        const threats = shown.flows.filter((flow) => flow.threat).length;
        if (threats) {
            message += ` · ${threats} ${T.listed_flows}`;
        }
        if (snapshot.carp === 'backup') {
            message += ` · ${T.carp_backup}`;
        }
        $('#fwmap-status').text(message);
    }

    function refresh() {
        const snapshot = state.snapshot;
        if (!snapshot || snapshot.status !== 'ok') {
            return;
        }
        const shown = filtered(snapshot);
        state.renderer.render(shown);
        updateToolbar(snapshot);
        updateLegend();
        statusLine(snapshot, shown);
        $('#fwmap-credit').html(snapshot.provider === 'dbip'
            ? '<a href="https://db-ip.com" target="_blank" rel="noopener">IP Geolocation by DB-IP</a>' : '');
    }

    async function poll(query) {
        try {
            const snapshot = await $.getJSON(`/api/firewallmap/flow/snapshot${query}`);
            if (snapshot.status === 'starting') {
                $('#fwmap-status').text(T.starting);
            } else if (snapshot.status === 'no_database') {
                state.renderer.render({flows: [], locations: []});
                $('#fwmap-status').text(snapshot.reason === 'maxmind_key_missing' ? T.key_missing
                    : snapshot.error ? `${T.database_failed}: ${snapshot.error}` : T.downloading);
            } else if (snapshot.status !== 'ok') {
                $('#fwmap-status').text(T.unavailable);
            } else {
                state.snapshot = snapshot;
                renderTalkers(talkers(snapshot));
                refresh();
            }
        } catch (error) {
            console.error('Firewall Map+: flow update failed', error);
            $('#fwmap-status').text(T.unavailable);
        }
        // one request at a time: never stack polls on a slow firewall
        setTimeout(() => poll(query), POLL_MS);
    }

    function bindControls() {
        const bind = (selector, key) => $(selector).on('change', function () {
            state.filters[key] = $(this).val();
            refresh();
        });
        bind('#fwmap-filter-traffic', 'traffic');
        bind('#fwmap-filter-service', 'service');
        bind('#fwmap-filter-iface', 'iface');
        bind('#fwmap-filter-host', 'host');
        bind('#fwmap-filter-country', 'country');
        $('#fwmap-filter-asn a').on('click', (event) => {
            event.preventDefault();
            state.filters.asn = '';
            refresh();
        });
        $('#fwmap-color').on('change', function () {
            state.colorMode = $(this).val();
            state.renderer.setSettings({...state.settings, colorMode: state.colorMode});
            refresh();
        });
        $('#fwmap-reset').on('click', () => {
            state.filters = {traffic: 'all', service: '', iface: '', host: '', country: '', asn: ''};
            $('#fwmap-filter-traffic').val('all');
            refresh();
        });
        // delegated: the rows are redrawn every poll, a click must survive that
        $('#fwmap-talkers-list').on('mousedown', '.fwmap-talker', function (event) {
            event.preventDefault();
            const row = (state.talkerRows || [])[$(this).data('index')];
            if (row) {
                Object.assign(state.filters, row.filter);
                refresh();
            }
        });
        $('#fwmap-talkers .nav a').on('click', function (event) {
            event.preventDefault();
            state.talkerTab = $(this).data('tab');
            $('#fwmap-talkers .nav li').removeClass('active');
            $(this).parent().addClass('active');
            if (state.snapshot) {
                renderTalkers(talkersFromLast());
            }
        });
        $('#fwmap-details')
            .on('click', '#fwmap-details-close', (event) => {
                event.preventDefault();
                state.selection = null;
                renderDetails();
            })
            .on('click', '.fwmap-copy', function (event) {
                event.preventDefault();
                navigator.clipboard?.writeText($(this).data('address'));
            })
            .on('click', '.fwmap-states', function (event) {
                event.preventDefault();
                showStates(String($(this).data('address')));
            })
            .on('click', '.fwmap-kill', function (event) {
                event.preventDefault();
                killStates(String($(this).data('address')));
            })
            .on('click', '.fwmap-alias', function (event) {
                event.preventDefault();
                addToAlias(String($(this).data('address')));
            })
            .on('click', '.fwmap-country', function (event) {
                event.preventDefault();
                addCountry(String($(this).data('code')));
            })
            .on('click', '.fwmap-investigate', function (event) {
                event.preventDefault();
                investigate(String($(this).data('address')));
            });
        $('#fwmap-feeds').on('click', () => showFeeds());
    }

    // re-rank the current tab from the last snapshot without adding a history point
    function talkersFromLast() {
        const snapshot = state.snapshot;
        const locations = locationsById(snapshot);
        const groups = {hosts: new Map(), countries: new Map(), networks: new Map()};
        for (const flow of snapshot.flows || []) {
            const dest = locations.get(flow.dest) || {};
            const inside = (flow.inside || [])[0];
            const entries = [
                inside && ['hosts', inside.ip, inside.name || inside.ip, inside.name ? `${inside.ip} · ${inside.interface || ''}` : inside.interface, {host: inside.ip}],
                dest.country && ['countries', dest.country, plain(dest.country), '', {country: dest.country}],
                dest.asn && ['networks', String(dest.asn), plain(dest.as_org || `AS${dest.asn}`), `AS${dest.asn}`, {asn: String(dest.asn)}],
            ].filter(Boolean);
            for (const [group, key, label, sub, filter] of entries) {
                const entry = groups[group].get(key) || {key, label, sub, rate: 0, filter, series: state.history.get(`${group}:${key}`)};
                entry.rate += flow.rate || 0;
                groups[group].set(key, entry);
            }
        }
        return Object.fromEntries(Object.entries(groups).map(([group, entries]) =>
            [group, [...entries.values()].sort((a, b) => b.rate - a.rate)]));
    }

    $(async function () {
        const $map = $('#fwmap-map');
        const canvas = document.createElement('canvas');
        if (!(canvas.getContext('webgl2') || canvas.getContext('webgl'))) {
            $('#fwmap-status').text(T.webgl);
            return;
        }

        // same per-user settings as the dashboard widget
        let config = {};
        try {
            const dashboard = await $.getJSON('/api/core/dashboard/getDashboard');
            config = (dashboard.dashboard?.widgets || []).find((widget) => widget.id === 'firewallmap')?.widget || {};
        } catch (error) {
            console.error('Firewall Map+: dashboard settings unavailable', error);
        }
        state.settings = {
            heavyTop: parseInt(config.heavy_top ?? '5', 10),
            heavyRate: parseInt(config.heavy_rate ?? '1000000', 10),
            maxArcs: parseInt(config.max_arcs ?? '150', 10),
            labels: config.labels !== '0',
            hostnames: config.hostnames === '1',
            asn: config.asn !== '0',
            blocks: config.blocks !== '0',
            blockMin: parseInt(config.block_min ?? '3', 10) || 3,
            colorMode: state.colorMode,
        };

        // investigation actions are offered to administrators (who can read the plugin settings)
        try {
            state.isAdmin = !!(await $.getJSON('/api/firewallmap/settings/get')).provider;
        } catch (_) {
            state.isAdmin = false;
        }

        try {
            const theme = FirewallMapRenderer.readTheme($map[0]);
            const rgba = (color, alpha) => `rgba(${color.join(', ')}, ${alpha})`;
            $map.css({
                background: `rgb(${theme.background.join(', ')})`,
                boxShadow: `inset 0 0 0 1px ${rgba(theme.accent, theme.dark ? 0.3 : 0.18)}`,
            });
            const line = rgba(theme.text, theme.dark ? 0.07 : 0.05);
            $('#fwmap-grid').css('background-image',
                `linear-gradient(${line} 1px, transparent 1px), linear-gradient(90deg, ${line} 1px, transparent 1px)`);
            $('#fwmap-status, #fwmap-legend').css('color', rgba(theme.text, 0.8));
            const container = document.getElementById('fwmap-canvas');
            state.renderer = FirewallMapRenderer.create(container, {
                theme,
                settings: state.settings,
                onSelect: (selection) => {
                    state.selection = selection;
                    renderDetails();
                },
            });
            $(container).children('canvas').css({left: 0, top: 0});
        } catch (error) {
            console.error('Firewall Map+: renderer initialisation failed', error);
            $('#fwmap-status').text(`${T.renderer_failed}: ${error?.message || error}`);
            return;
        }

        bindControls();
        $('#fwmap-feeds').toggle(state.isAdmin);
        renderDetails();
        $(window).on('resize', () => state.renderer.resize());
        poll(`?blocks_min=${state.settings.blockMin}${state.settings.hostnames ? '&hostnames=1' : ''}`);
    });
})();
