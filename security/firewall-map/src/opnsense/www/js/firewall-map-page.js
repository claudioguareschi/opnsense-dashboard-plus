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
    const TALKER_ROWS = 20;

    // OPNsense HTML-escapes &, < and > in API responses; undo that, then escape for display
    const plain = (text) => String(text ?? '').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
    const esc = (text) => plain(text).replace(/[&<>"']/g, (char) => `&#${char.charCodeAt(0)};`);

    const WATCHLIST = 'FWMAP_Watchlist';

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
        colorMode: 'initiator',
        talkerTab: 'hosts',
        history: new Map(),
        isAdmin: false,
        selection: null,
        investigations: new Map(),
        abuseScores: new Map(),
        abuseChecking: new Set(),
        abuseConfigured: false,
    };

    /* ---------------------------------------------------------------- icons */

    // thin outline icons as in the design mockup (Font Awesome's solid glyphs are too heavy)
    const ICON_PATHS = {
        'globe': '<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
        'laptop': '<rect x="4" y="4" width="16" height="11" rx="1.5"/><path d="M2 19h20"/>',
        'server': '<rect x="3" y="3" width="18" height="7" rx="1.5"/><rect x="3" y="14" width="18" height="7" rx="1.5"/><path d="M7 6.5h.01M7 17.5h.01M11 6.5h6M11 17.5h6"/>',
        'shield': '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
        'shield-check': '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
        'chart': '<path d="M3 3v18h18"/><path d="M8 17v-4M12 17V7M16 17v-7M20 17v-2"/>',
        'search': '<circle cx="11" cy="11" r="7"/><path d="m21 21-5-5"/>',
        'layers': '<path d="m12 2 10 5-10 5L2 7l10-5z"/><path d="m2 17 10 5 10-5"/><path d="m2 12 10 5 10-5"/>',
        'external': '<path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>',
        'list': '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
        'trash': '<path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M10 11v6M14 11v6"/>',
        'chevron': '<path d="m9 18 6-6-6-6"/>',
        'check': '<path d="M20 6 9 17l-5-5"/>',
        'x': '<path d="M18 6 6 18M6 6l12 12"/>',
        'ban': '<circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/>',
        'flag': '<path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><path d="M4 22v-7"/>',
        'alert': '<circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/>',
        'network': '<rect x="9" y="2" width="6" height="6" rx="1"/><rect x="16" y="16" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3M12 12V8"/>',
        'plus': '<path d="M12 5v14M5 12h14"/>',
        'minus': '<path d="M5 12h14"/>',
        'expand': '<path d="M8 3H5a2 2 0 0 0-2 2v3M21 8V5a2 2 0 0 0-2-2h-3M3 16v3a2 2 0 0 0 2 2h3M16 21h3a2 2 0 0 0 2-2v-3"/>',
    };
    // the Font Awesome names used across the page, mapped to the outline set
    const ICON_ALIASES = {
        'fa-globe': 'globe', 'fa-desktop': 'laptop', 'fa-laptop': 'laptop', 'fa-server': 'server', 'fa-shield': 'shield',
        'fa-bar-chart': 'chart', 'fa-search': 'search', 'fa-database': 'layers', 'fa-external-link': 'external',
        'fa-list': 'list', 'fa-trash-o': 'trash', 'fa-chevron-right': 'chevron', 'fa-check': 'check', 'fa-times': 'x',
        'fa-ban': 'ban', 'fa-flag': 'flag', 'fa-flag-o': 'flag', 'fa-exclamation-triangle': 'alert',
        'fa-exclamation-circle': 'alert', 'fa-sitemap': 'network',
    };

    function ic(name, cls = '') {
        const key = ICON_ALIASES[name] || name;
        const paths = ICON_PATHS[key];
        if (!paths) {
            return `<i class="fa ${name} ${cls}"></i>`;
        }
        return `<svg class="fwmap-ic ${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"`
            + ` stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths}</svg>`;
    }

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

    function filtered(snapshot) {
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
            + `${esc(item.label)}</span>`).join('')
            + `<span class="fwmap-legend-item"><i class="fwmap-legend-ring"></i>${esc(T.ids_alert)}</span>`);
    }

    /* ---------------------------------------------------------------- top talkers */

    /** "VLAN10_MGMT" reads as "MGMT (VLAN10)"; the configured name stays in the tooltip. */
    function shortInterface(name) {
        const match = /^VLAN(\d+)[_ -]+(.+)$/i.exec(plain(name || ''));
        return match ? `${match[2]} (VLAN${match[1]})` : plain(name || '');
    }

    /** Top talkers by host, country and network, plus the addresses Suricata alerted on. */
    function groupTalkers(snapshot) {
        const locations = locationsById(snapshot);
        const groups = {hosts: new Map(), countries: new Map(), networks: new Map(), ids: new Map()};
        const add = (group, key, fields, rate) => {
            const entry = groups[group].get(key) || {key, rate: 0, flows: 0, ...fields};
            entry.rate += rate;
            entry.flows += 1;
            groups[group].set(key, entry);
        };
        for (const flow of snapshot.flows || []) {
            const rate = flow.rate || 0;
            const dest = locations.get(flow.dest) || {};
            for (const inside of (flow.inside || []).slice(0, 1)) {
                add('hosts', inside.ip, {label: inside.name || inside.ip, ip: inside.ip, iface: inside.interface,
                    icon: 'laptop', filter: {host: inside.ip}}, rate);
            }
            if (dest.country) {
                add('countries', dest.country, {label: plain(dest.country), flag: flagOf(dest.country_code),
                    icon: 'fa-flag-o', filter: {country: dest.country}}, rate);
            }
            if (dest.asn) {
                add('networks', String(dest.asn), {label: plain(dest.as_org || `AS${dest.asn}`), sub: `AS${dest.asn}`,
                    icon: 'network', filter: {asn: String(dest.asn)}}, rate);
            }
        }
        // IDS: correlated connections first, then addresses with alert history
        const idsEntry = (address, ids, count, severity, select, connection) => {
            const current = groups.ids.get(address);
            if (current && (current.connection || !connection)) {
                return;
            }
            const top = ids?.signatures?.[0] || ids?.groups?.[0]?.signatures?.[0];
            groups.ids.set(address, {key: address, label: address, sub: top ? plain(top.signature) : '', severity,
                count, connection, icon: connection ? 'fa-exclamation-circle' : 'fa-flag', rate: 0, select});
        };
        for (const flow of snapshot.ids_flows || []) {
            if (flow.kind !== 'blocked') {
                idsEntry(flow.dest, flow, flow.count, flow.severity, {kind: 'idsflow', addresses: [flow.dest], idsFlow: flow,
                    country: flow.country, countryCode: flow.country_code, title: flow.city || flow.country}, true);
            }
        }
        for (const flow of snapshot.flows || []) {
            if (flow.ids) {
                const dest = locations.get(flow.dest) || {};
                idsEntry(flow.dest, flow.ids, flow.ids.count, flow.ids.severity, {kind: 'flow', addresses: [flow.dest], members: [flow],
                    country: dest.country, countryCode: dest.country_code, title: dest.city || dest.country}, false);
            }
        }
        for (const block of snapshot.blocks || []) {
            if (block.ids) {
                idsEntry(block.source, block.ids, block.ids.count, block.ids.severity, {kind: 'blocked', addresses: [block.source],
                    block, country: block.country, countryCode: block.country_code, title: block.city || block.country}, false);
            }
        }
        for (const alert of snapshot.alerts || []) {
            idsEntry(alert.source, alert.ids, alert.ids?.count || 0, alert.ids?.severity || 3, {kind: 'alert', addresses: [alert.source],
                alert, country: alert.country, countryCode: alert.country_code, title: alert.city || alert.country}, false);
        }
        const result = {};
        for (const [group, entries] of Object.entries(groups)) {
            result[group] = [...entries.values()].sort(group === 'ids'
                ? (a, b) => (b.connection - a.connection) || (a.severity - b.severity) || (b.count - a.count)
                : (a, b) => b.rate - a.rate);
        }
        return result;
    }

    function talkers(snapshot) {
        const result = groupTalkers(snapshot);
        for (const [group, entries] of Object.entries(result)) {
            if (group === 'ids') {
                continue;
            }
            for (const entry of entries) {
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
            if (!(result[group] || []).some((entry) => entry.key === id)) {
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

    const SPARK_COLOR = [232, 93, 40];

    /** A small filled area chart; the newest point sits at the right edge. */
    function sparkline(canvas, series) {
        const ratio = window.devicePixelRatio || 1;
        const width = canvas.clientWidth || 64;
        const height = canvas.clientHeight || 22;
        canvas.width = Math.round(width * ratio);
        canvas.height = Math.round(height * ratio);
        const context = canvas.getContext('2d');
        context.setTransform(ratio, 0, 0, ratio, 0, 0);
        context.clearRect(0, 0, width, height);
        if (!series || series.length < 2) {
            return;
        }
        const max = Math.max(...series, 1);
        // a short history is spread over the whole width instead of a sliver at the right edge
        const points = series.map((value, index) => [(index / (series.length - 1)) * width,
            height - 1 - (value / max) * (height - 3)]);
        context.beginPath();
        points.forEach(([x, y], index) => (index ? context.lineTo(x, y) : context.moveTo(x, y)));
        context.lineTo(points[points.length - 1][0], height);
        context.lineTo(points[0][0], height);
        context.closePath();
        context.fillStyle = `rgba(${SPARK_COLOR.join(',')}, .18)`;
        context.fill();
        context.beginPath();
        points.forEach(([x, y], index) => (index ? context.lineTo(x, y) : context.moveTo(x, y)));
        context.strokeStyle = `rgb(${SPARK_COLOR.join(',')})`;
        context.lineWidth = 1.2;
        context.stroke();
    }

    function talkerActive(row) {
        return row.filter && Object.entries(row.filter).every(([key, value]) => state.filters[key] === value);
    }

    function renderTalkers(groups) {
        const ids = state.talkerTab === 'ids';
        const needle = String($('#fwmap-talker-search').val() || '').trim().toLowerCase();
        const sort = $('#fwmap-talker-sort').val() || 'rate';
        let rows = (groups[state.talkerTab] || []).slice();
        if (needle) {
            rows = rows.filter((row) => [row.label, row.ip, row.iface, row.sub, row.key].filter(Boolean)
                .some((text) => String(text).toLowerCase().includes(needle)));
        }
        if (!ids && sort === 'flows') {
            rows.sort((a, b) => b.flows - a.flows || b.rate - a.rate);
        } else if (sort === 'name') {
            rows.sort((a, b) => String(a.label).localeCompare(String(b.label)));
        }
        rows = rows.slice(0, TALKER_ROWS);
        const $list = $('#fwmap-talkers-list');
        if (!rows.length) {
            $list.html(`<div class="text-muted fwmap-empty">${esc(ids ? T.no_ids_talkers : T.no_talkers)}</div>`);
            state.talkerRows = [];
            return;
        }
        $list.html(rows.map((row, index) => {
            const sub = row.ip ? `${esc(row.ip)}${row.iface ? ` · <span title="${esc(row.iface)}">${esc(shortInterface(row.iface))}</span>` : ''}`
                : esc(row.sub || '');
            const chart = ids ? '<span></span>' : '<canvas></canvas>';
            const value = ids
                ? `<span class="fwmap-talker-count ${row.severity <= 2 ? 'fwmap-ids-high' : 'fwmap-ids'}">${esc(row.count)} ${esc(T.alerts_short)}</span>`
                : `<span class="fwmap-talker-rate">${esc(formatRate(row.rate))}</span>`;
            const extra = ids
                ? `<span class="fwmap-talker-flows">${esc(T.severity)} ${esc(row.severity)}</span>`
                : `<span class="fwmap-talker-flows">${esc(row.flows)} ${esc(row.flows === 1 ? T.flow_one : T.flow_many)}</span>`;
            return `<div class="fwmap-talker${talkerActive(row) ? ' active' : ''}" data-index="${index}" title="${esc(ids ? T.select_hint : T.filter_hint)}">
                <span class="fwmap-talker-icon">${row.flag || `${ic(row.icon)}`}</span>
                <span class="fwmap-talker-text"><span class="fwmap-talker-label">${esc(row.label)}</span>
                    <span class="fwmap-talker-sub">${sub}</span></span>
                ${chart}${value}${extra}
            </div>`;
        }).join(''));
        state.talkerRows = rows;
        $list.find('.fwmap-talker canvas').each(function () {
            sparkline(this, rows[$(this).closest('.fwmap-talker').data('index')].series);
        });
    }

    /* ---------------------------------------------------------------- details and actions */

    /** What the map knows about a remote address: hostname, network, country. */
    function remoteOf(address) {
        const location = (state.snapshot?.locations || []).find((item) => item.id === address) || {};
        return {
            ip: address,
            hostname: state.snapshot?.hostnames?.[address],
            org: state.settings.asn ? location.as_org : null,
            country: location.country,
        };
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

    /** AbuseIPDB alone, from the Reputation card: the verdict fills in without opening the full investigation. */
    async function checkAbuse(address) {
        state.abuseChecking.add(address);
        renderDetails();
        try {
            const result = await $.getJSON(`/api/firewallmap/investigate/address/${encodeURIComponent(address)}`);
            if (result.abuseipdb && typeof result.abuseipdb.score === 'number') {
                state.abuseScores.set(address, result.abuseipdb.score);
            } else {
                notify(`AbuseIPDB: ${result.abuseipdb?.error || result.error || T.lookup_failed}`, BootstrapDialog.TYPE_WARNING);
            }
        } catch (error) {
            notify(`${T.action_failed}: ${error.statusText || error}`, BootstrapDialog.TYPE_DANGER);
        }
        state.abuseChecking.delete(address);
        renderDetails();
    }

    async function investigate(address) {
        state.investigations.set(address, `<div class="text-muted"><i class="fa fa-spinner fa-spin"></i> ${esc(T.looking_up)}</div>`);
        renderDetails();
        try {
            const result = await $.getJSON(`/api/firewallmap/investigate/address/${encodeURIComponent(address)}`);
            state.investigations.set(address, investigationCard(result));
            if (result.abuseipdb && typeof result.abuseipdb.score === 'number') {
                state.abuseScores.set(address, result.abuseipdb.score);
            }
        } catch (error) {
            state.investigations.set(address, `<div class="text-danger">${esc(T.action_failed)}: ${esc(error.statusText || error)}</div>`);
        }
        renderDetails();
    }

    /* ---------------------------------------------------------------- review queue */

    const STATUSES = ['new', 'reviewed', 'blocked', 'dismissed'];

    // inside host names from the live map, for addresses recorded in the queue
    function insideNames() {
        const names = new Map();
        for (const flow of state.snapshot?.flows || []) {
            for (const host of [...(flow.inside || []), ...(flow.targets || [])]) {
                if (host.name && host.ip) {
                    names.set(host.ip, host.name);
                }
            }
        }
        return names;
    }

    function ago(seconds) {
        const age = Math.max(0, Date.now() / 1000 - seconds);
        if (age < 90) {
            return `${Math.round(age)} s`;
        }
        if (age < 5400) {
            return `${Math.round(age / 60)} min`;
        }
        if (age < 129600) {
            return `${Math.round(age / 3600)} h`;
        }
        return `${Math.round(age / 86400)} d`;
    }

    /** 8040 seconds read "2 h 14 min". */
    function spanText(seconds) {
        const minutes = Math.floor(seconds / 60);
        if (minutes < 1) {
            return `${Math.round(seconds)} s`;
        }
        if (minutes < 60) {
            return `${minutes} min`;
        }
        const days = Math.floor(minutes / 1440);
        const hours = Math.floor((minutes % 1440) / 60);
        return days ? `${days} d ${hours} h` : `${hours} h ${minutes % 60} min`;
    }

    function formatBytes(bytes) {
        return formatRate(bytes).replace('/s', '');
    }

    function queueItem(row, names) {
        // the same sentence as on the map, rebuilt from what the queue recorded
        const ports = row.service_ports || {};
        const serviceFor = (protocol, port) => Object.keys(ports).find((name) => ports[name] === `${port}/${protocol}`)
            || (port ? `${String(protocol).toUpperCase()}/${port}` : 'ICMP');
        const targets = (row.targets || []).map((target) => {
            const [protocol, ip, port] = String(target).split('|');
            const firewall = !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(ip);
            return {ip, port, protocol, name: firewall ? 'firewall' : names.get(ip), firewall,
                service: (row.target_services || {})[target] || serviceFor(protocol, port)};
        });
        const pseudo = {
            initiated: row.inbound && row.outbound ? 'both' : row.inbound ? 'remote' : 'local',
            targets,
            inside: (row.inside || []).map((ip) => ({ip, name: names.get(ip)})),
            services: row.services || [],
            service_ports: ports,
        };
        // what was recorded with the entry, completed by the live map
        const live = remoteOf(row.address);
        const saved = row.remote || {};
        const remote = {
            ip: row.address,
            hostname: saved.hostname || live.hostname,
            org: state.settings.asn ? (saved.org || live.org) : null,
            country: saved.country || live.country,
        };
        const lines = FirewallMapRenderer.flowSummary(pseudo, remote).map(esc);
        const address = esc(row.address);
        const status = STATUSES.includes(row.status) ? row.status : 'new';
        const direction = pseudo.initiated === 'local'
            ? `<span class="fwmap-q-dir fwmap-q-out" title="${esc(T.outbound)}"><i class="fa fa-sign-out"></i> ${esc(T.outbound)}</span>`
            : `<span class="fwmap-q-dir fwmap-q-in" title="${esc(T.inbound)}"><i class="fa fa-sign-in"></i> ${esc(T.inbound)}</span>`;
        const button = (cls, icon, label, extra = '') =>
            `<button type="button" class="btn btn-xs ${cls}" ${extra}><i class="fa ${icon}"></i> ${esc(label)}</button>`;
        const decisions = [
            status === 'new' ? button('btn-default fwmap-q-status', 'fa-check', T.mark_reviewed, 'data-status="reviewed"') : '',
            status !== 'dismissed' ? button('btn-default fwmap-q-status', 'fa-eye-slash', T.dismiss, 'data-status="dismissed"') : '',
            status !== 'new' ? button('btn-default fwmap-q-status', 'fa-undo', T.reopen, 'data-status="new"') : '',
            button('btn-default fwmap-q-edit-note', 'fa-pencil', T.edit_note),
            button('btn-danger fwmap-q-block', 'fa-ban', T.block),
        ].join('');
        const tool = (cls, icon, label, href) => href
            ? `<a href="${href}" target="_blank" rel="noopener noreferrer" title="${esc(label)}"><i class="fa ${icon}"></i> ${esc(label)}</a>`
            : `<a href="#" class="${cls}" title="${esc(label)}"><i class="fa ${icon}"></i> ${esc(label)}</a>`;
        const tools = [
            tool('fwmap-q-investigate', 'fa-search', T.investigate),
            tool('', 'fa-globe', T.whois, `https://bgp.he.net/ip/${encodeURIComponent(row.address)}`),
            tool('', 'fa-external-link', 'AbuseIPDB', `https://www.abuseipdb.com/check/${encodeURIComponent(row.address)}`),
            tool('fwmap-q-states', 'fa-list', T.show_states),
            tool('fwmap-q-kill', 'fa-times-circle', T.kill_states),
        ].join('');
        const chips = (row.lists || []).map((name) => `<span class="fwmap-q-chip">${esc(listLabel(name))}</span>`).join('');
        const card = state.investigations.get(row.address);
        return `<div class="fwmap-q-item fwmap-q-${status}" data-address="${address}" data-status="${status}">
            <div class="fwmap-q-head">
                <span class="fwmap-q-ip">${address}</span>
                <span class="fwmap-q-status-pill">${esc(T[`status_${status}`])}</span>
                ${direction}
                <span class="fwmap-q-seen" title="${esc(new Date(row.last_seen * 1000).toLocaleString())}">
                    <i class="fa fa-clock-o"></i> ${esc(ago(row.last_seen))} ${esc(T.ago)}</span>
            </div>
            ${lines.map((line) => `<div class="fwmap-q-summary">${line}</div>`).join('')}
            ${idsLines(row.ids)}
            <div class="fwmap-q-chips">${chips}</div>
            <div class="fwmap-q-meta">
                <span title="${esc(T.first_seen)}"><i class="fa fa-calendar"></i> ${esc(T.first_seen)} ${esc(ago(row.first_seen))} ${esc(T.ago)}</span>
                <span title="${esc(T.samples)}"><i class="fa fa-bar-chart"></i> ${esc(row.samples)} ${esc(T.samples)}</span>
                <span title="${esc(T.peak)}"><i class="fa fa-exchange"></i> ${esc(T.peak)} ${esc(formatBytes(row.peak_bytes || 0))}</span>
                ${(row.services || []).length ? `<span><i class="fa fa-plug"></i> ${(row.services || []).map(esc).join(', ')}</span>` : ''}
            </div>
            ${row.seen_after_block ? `<div class="fwmap-q-warning"><i class="fa fa-exclamation-triangle"></i> ${esc(T.seen_after_block)}</div>` : ''}
            ${row.note ? `<div class="fwmap-q-note"><i class="fa fa-sticky-note-o"></i> ${esc(row.note)}</div>` : ''}
            ${card ? `<div class="fwmap-investigation">${card}</div>` : ''}
            <div class="fwmap-q-actions">
                <div class="fwmap-q-tools">${tools}</div>
                <div class="fwmap-q-decisions">${decisions}</div>
            </div>
        </div>`;
    }

    /** "FWMAP_Spamhaus_DROP" reads as "Spamhaus DROP". */
    function listLabel(name) {
        return plain(name).replace(/^FWMAP_/, '').replace(/_/g, ' ');
    }

    async function refreshQueueCount() {
        try {
            const result = await $.getJSON('/api/firewallmap/threats/list/counts');
            $('#fwmap-review-count').text(result.counts?.new || '');
        } catch (_) {
            $('#fwmap-review-count').text('');
        }
    }

    async function setThreat(address, status, note) {
        const payload = {address, status};
        if (note !== undefined) {
            payload.note = note;
        }
        const result = await postJSON('/api/firewallmap/threats/set', payload);
        if (result.result !== 'saved') {
            throw new Error(result.error || T.action_failed);
        }
    }

    async function showQueue() {
        const view = {status: 'new', rows: [], counts: {}};
        const $body = $('<div></div>');
        let settings = {};
        try {
            settings = await $.getJSON('/api/firewallmap/settings/get');
        } catch (_) {
            settings = {};
        }
        const $record = $(`<label class="fwmap-q-record" title="${esc(T.record_threats_hint)}"><input type="checkbox"> ${esc(T.record_threats)}</label>`);
        $record.find('input').prop('checked', settings.record_threats !== '0').on('change', async function () {
            try {
                await postJSON('/api/firewallmap/settings/set', {record_threats: this.checked ? '1' : '0'});
            } catch (error) {
                notify(`${T.action_failed}: ${error.statusText || error}`, BootstrapDialog.TYPE_DANGER);
            }
        });
        const $tabs = $('<ul class="nav nav-pills fwmap-q-tabs"></ul>');
        const $search = $(`<input type="search" class="form-control input-sm fwmap-q-search" placeholder="${esc(T.queue_search)}">`);
        const $list = $('<div class="fwmap-q-list"></div>');
        $body.append($('<div class="fwmap-q-toolbar"></div>').append($tabs, $search), $list);
        $search.on('input', () => render());

        const render = () => {
            $tabs.html([...STATUSES, 'all'].map((status) => `<li class="${status === view.status ? 'active' : ''}">`
                + `<a href="#" data-status="${status}">${esc(T[`status_${status}`])}`
                + `${status !== 'all' && view.counts[status] ? ` <span class="badge">${esc(view.counts[status])}</span>` : ''}</a></li>`).join(''));
            const names = insideNames();
            const needle = String($search.val() || '').trim().toLowerCase();
            const rows = needle ? view.rows.filter((row) => JSON.stringify(row).toLowerCase().includes(needle)) : view.rows;
            $list.html(rows.length ? rows.map((row) => queueItem(row, names)).join('')
                : `<div class="text-muted fwmap-empty"><i class="fa fa-check-circle"></i> ${esc(T.queue_empty)}</div>`);
        };
        const load = async () => {
            try {
                const result = await $.getJSON(`/api/firewallmap/threats/list/${view.status}`);
                view.rows = result.rows || [];
                view.counts = result.counts || {};
                $('#fwmap-review-count').text(view.counts.new || '');
            } catch (error) {
                notify(`${T.action_failed}: ${error.statusText || error}`, BootstrapDialog.TYPE_DANGER);
            }
            render();
        };
        const act = async (work) => {
            try {
                await work();
            } catch (error) {
                notify(`${T.action_failed}: ${error.message || error.statusText || error}`, BootstrapDialog.TYPE_DANGER);
            }
            load();
        };
        const addressOf = (element) => String($(element).closest('.fwmap-q-item').data('address'));
        const rowOf = (address) => view.rows.find((row) => row.address === address) || {};

        $tabs.on('click', 'a', function (event) {
            event.preventDefault();
            view.status = String($(this).data('status'));
            load();
        });
        $list
            .on('click', '.fwmap-q-status', function () {
                const address = addressOf(this);
                act(() => setThreat(address, String($(this).data('status'))));
            })
            .on('click', '.fwmap-q-edit-note', function () {
                const address = addressOf(this);
                const $text = $('<textarea class="form-control" rows="4" maxlength="1000"></textarea>').val(plain(rowOf(address).note || ''));
                BootstrapDialog.show({
                    title: esc(`${T.note_title} ${address}`), message: $text,
                    buttons: [
                        {label: T.cancel, action: (dialog) => dialog.close()},
                        {label: T.save, cssClass: 'btn-primary', action: (dialog) => {
                            dialog.close();
                            act(() => setThreat(address, rowOf(address).status || 'new', String($text.val())));
                        }},
                    ],
                });
            })
            .on('click', '.fwmap-q-block', function () {
                const address = addressOf(this);
                chooseAlias(['host', 'hosts', 'network', 'networks'], esc(`${T.block_title}: ${address}`), (name) => {
                    confirmAction(`${T.add_confirm} ${address} → ${name}? ${T.block_hint}`, () => act(async () => {
                        const result = await postJSON(`/api/firewall/alias_util/add/${encodeURIComponent(name)}`, {address});
                        if (result.status !== 'done') {
                            throw new Error(result.status_msg || result.status);
                        }
                        const note = [plain(rowOf(address).note || ''), `→ ${name} (${new Date().toLocaleString()})`].filter(Boolean).join('\n');
                        await setThreat(address, 'blocked', note);
                    }));
                });
            })
            .on('click', '.fwmap-q-investigate', async function (event) {
                event.preventDefault();
                const address = addressOf(this);
                state.investigations.set(address, `<div class="text-muted"><i class="fa fa-spinner fa-spin"></i> ${esc(T.looking_up)}</div>`);
                render();
                try {
                    state.investigations.set(address, investigationCard(
                        await $.getJSON(`/api/firewallmap/investigate/address/${encodeURIComponent(address)}`)));
                } catch (error) {
                    state.investigations.set(address, `<div class="text-danger">${esc(T.action_failed)}: ${esc(error.statusText || error)}</div>`);
                }
                render();
            })
            .on('click', '.fwmap-q-states', function (event) {
                event.preventDefault();
                showStates(addressOf(this));
            })
            .on('click', '.fwmap-q-kill', function (event) {
                event.preventDefault();
                killStates(addressOf(this));
            });

        // what the queue is and where its data comes from, out of the way of the entries
        const $footer = $('<div class="fwmap-q-footer"></div>')
            .append($record)
            .append(blacklistStatus(settings));
        BootstrapDialog.show({
            title: `<i class="fa fa-list-alt"></i> ${esc(T.review_queue)} <span class="fwmap-q-subtitle">· ${esc(T.review_intro)}</span>`,
            size: BootstrapDialog.SIZE_WIDE, message: $body, cssClass: 'fwmap-q-dialog',
            buttons: [{label: T.close, action: (dialog) => dialog.close()}],
            onshown: (dialog) => dialog.getModalFooter().prepend($footer),
            onhidden: () => refreshQueueCount(),
        });
        load();
    }

    /* ---------------------------------------------------------------- AbuseIPDB blacklist */

    function blacklistStatus(settings) {
        const status = settings.abuseipdb_blacklist || {};
        let text = T.blacklist_no_key;
        if (settings.abuseipdb_configured) {
            text = status.updated
                ? `${Number(status.count).toLocaleString()} ${T.blacklist_addresses}, ${T.updated} ${new Date(status.updated * 1000).toLocaleString([], {dateStyle: 'medium', timeStyle: 'short'})}`
                : T.blacklist_pending;
            if (status.error) {
                text += ` (${T.blacklist_error}: ${plain(status.error)})`;
            }
        }
        return $('<div class="fwmap-q-source"></div>').attr('title', T.blacklist)
            .append('<i class="fa fa-database"></i> ')
            .append($('<span></span>').text(`${T.blacklist_short}: ${text}`));
    }

    /** Suricata's alerts for an address, worst signature first. */
    function idsLines(ids) {
        if (!ids) {
            return '';
        }
        const cls = ids.severity <= 2 ? 'fwmap-ids fwmap-ids-high' : 'fwmap-ids';
        return FirewallMapRenderer.idsSummary(ids)
            .map((line) => `<div class="${cls}">${ic('flag')} ${esc(line)}</div>`).join('');
    }

    /* ---------------------------------------------------------------- details panel */

    /** A rectangular flag (OPNsense ships flag-icon-css); emoji flags render tiny or as letters. */
    function flagOf(code) {
        return /^[A-Za-z]{2}$/.test(code || '')
            ? `<span class="flag-icon flag-icon-${code.toLowerCase()} fwmap-flag"></span>` : '';
    }

    function bigPill(kind, text, icon) {
        return `<span class="fwmap-vpill fwmap-vpill-${kind}">${icon ? `${ic(icon)} ` : ''}${esc(text)}</span>`;
    }

    function pill(kind, text, icon) {
        return `<span class="fwmap-pill fwmap-pill-${kind}">${icon ? `${ic(icon)} ` : ''}${esc(text)}</span>`;
    }

    function place(item) {
        return [item.city, item.country].filter(Boolean).map(plain).join(', ');
    }

    /** One box of the connection diagram: a host on either end. */
    function endBox(icon, name, lines) {
        return `<div class="fwmap-end">${ic(icon)}<div class="fwmap-end-name">${esc(name)}</div>`
            + lines.filter(Boolean).map((line) => `<div class="fwmap-end-sub">${esc(line)}</div>`).join('') + '</div>';
    }

    /** A card of the details panel: icon, title and a chevron that opens the related view. */
    function card(icon, title, body, action) {
        const chevron = action ? `<a href="${action.href || '#'}" class="fwmap-card-go ${action.cls || ''}"${action.href ? ' target="_blank" rel="noopener"' : ''}`
            + `${action.address ? ` data-address="${esc(action.address)}"` : ''} title="${esc(action.title)}">${ic('chevron')}</a>` : '';
        return `<section class="fwmap-card"><div class="fwmap-card-head">${ic(icon, 'fwmap-card-ic')}<span>${esc(title)}</span>${chevron}</div>`
            + `<div class="fwmap-card-body">${body}</div></section>`;
    }

    function rows(items) {
        return `<table class="fwmap-kv">${items.filter(([, value]) => value !== null && value !== undefined && value !== '')
            .map(([label, value]) => `<tr><th>${esc(label)}</th><td>${value}</td></tr>`).join('')}</table>`;
    }

    function serviceParts(name, port) {
        const raw = /^(TCP|UDP)\/(\d+)$/.exec(name || '');
        if (raw) {
            // an unnamed port: say so once instead of "TCP 10512 · TCP/10512"
            return {name: `${T.port_word} ${raw[2]}`, port: `${raw[1]}/${raw[2]}`};
        }
        const [number, protocol] = String(port || '').split('/');
        return {name: plain(name || '—'), port: number ? `${(protocol || '').toUpperCase()}/${number}` : ''};
    }

    function reputationCard(item) {
        const listed = new Set(item.lists || []);
        const lists = [...new Set([...(state.snapshot?.threat_lists || []), ...listed])];
        const address = item.address;
        const known = state.abuseScores.get(address);
        const score = item.abuseipdb ?? known;
        let abuse;
        if (state.abuseChecking.has(address)) {
            abuse = `<span class="fwmap-muted">${esc(T.checking)}</span>`;
        } else if (score === null || score === undefined) {
            // a lookup is one click away when the firewall has an AbuseIPDB key
            abuse = state.isAdmin && state.abuseConfigured
                ? `<a href="#" class="fwmap-abuse-check" data-address="${esc(address)}">${ic('search')} ${esc(T.check_now)}</a>`
                : `<span class="fwmap-muted" title="${esc(T.abuseipdb_hint)}">${esc(T.no_key)}</span>`;
        } else {
            abuse = score >= 75 ? pill('danger', `${score}%`) : score >= 25 ? pill('warning', `${score}%`) : pill('ok', T.clean, 'fa-check');
        }
        // listed stands out in red; everything else reads as a quiet green "not listed"
        const notListed = `<span class="fwmap-not-listed">${ic('check')} ${esc(T.not_listed_short)}</span>`;
        const left = rows([['AbuseIPDB', abuse], ...lists.filter((name) => name !== 'AbuseIPDB (looked up)').map((name) =>
            [listLabel(name), listed.has(name) ? pill('danger', T.listed, 'fa-ban') : notListed])]);
        const right = rows([
            ['ASN', item.asn ? esc(`AS${item.asn}`) : ''],
            [T.organization, esc(plain(item.as_org || ''))],
            [T.country, item.country ? `${flagOf(item.country_code)} ${esc(plain(item.country))}` : ''],
        ]);
        return card('fa-database', T.sec_reputation, `<div class="fwmap-two">${left}${right}</div>`,
            state.isAdmin ? {cls: 'fwmap-investigate', address: item.ip || item.dest || item.source || state.detailsAddress, title: T.investigate} : null);
    }

    function idsCard(ids, groups) {
        const signatures = groups ? groups.flatMap((group) => group.signatures)
            : (ids?.signatures || []).map((item) => ({...item, last: null}));
        if (!signatures.length) {
            return card('fa-search', T.sec_ids_long, `<div class="fwmap-empty-note">${ic('check', 'fwmap-ok-ic')}
                <div><div>${esc(T.no_ids)}</div><div class="fwmap-muted">${esc(T.no_ids_sub)}</div></div></div>`,
                {href: '/ui/ids#alerts', title: T.open_ids});
        }
        const scope = groups ? T.ids_on_connection : T.ids_on_address;
        return card('fa-search', T.sec_ids_long, `<div class="fwmap-card-note">${esc(scope)}</div>`
            + signatures.map((item) => `<div class="fwmap-sig">
                <div class="${item.severity <= 2 ? 'fwmap-ids-high' : 'fwmap-ids'}">${ic('flag')} ${esc(item.signature)}</div>
                <div class="text-muted">${esc(T.severity)} ${esc(item.severity)}${item.category ? ` · ${esc(item.category)}` : ''}${item.sid ? ` · SID ${esc(item.sid)}` : ''}
                    · ${esc(item.count)}×${item.last ? ` · ${esc(new Date(item.last * 1000).toLocaleTimeString())}` : ''}${item.action === 'blocked' ? ` · <b>${esc(T.ips_dropped)}</b>` : ''}</div>
            </div>`).join(''), {href: '/ui/ids#alerts', title: T.open_ids});
    }

    /** Everything the panel shows for one remote address of the selection. */
    function detailsModel(selection, address) {
        const flow = selection.kind === 'flow' ? (selection.members || []).find((member) => member.dest === address) : null;
        const block = selection.kind === 'blocked' ? selection.block : null;
        const alert = selection.kind === 'alert' ? selection.alert : null;
        const ids = selection.kind === 'idsflow' ? selection.idsFlow : null;
        const location = (state.snapshot?.locations || []).find((item) => item.id === address) || {};
        const item = {...location, ...(block || alert || ids || {}), country_code: (block || alert || ids || {}).country_code || location.country_code};
        const hostname = state.snapshot?.hostnames?.[address];
        const remote = {
            title: hostname || address, ip: address, hostname, place: place(item), cc: item.country_code,
            org: state.settings.asn ? plain(item.as_org || '') : '',
        };
        const firewallName = T.this_firewall_title;
        const origin = (state.snapshot?.locations || []).find((entry) => entry.local)?.id || '';
        const remoteBox = endBox('fa-server', remote.title, [hostname ? address : '', [remote.place].filter(Boolean).join('')]);
        if (flow) {
            const outbound = flow.initiated !== 'remote';
            const inside = (flow.inside || [])[0];
            const target = (flow.targets || [])[0];
            const name = (flow.services || [])[0];
            const service = serviceParts(target && !outbound ? target.service : name,
                target && !outbound && target.port ? `${target.port}/${target.protocol || 'tcp'}` : (flow.service_ports || {})[name]);
            const localBox = outbound
                ? (inside ? endBox('laptop', inside.name || inside.ip, [inside.name ? inside.ip : '', inside.interface])
                    : endBox('fa-shield', firewallName, [origin]))
                : (target && !target.firewall ? endBox('laptop', target.name || target.ip, [target.name ? target.ip : '', target.interface])
                    : endBox('fa-shield', firewallName, [origin]));
            const flagged = (flow.lists || []).length > 0;
            const transferred = flow.transferred ? `↓ ${esc(formatBytes(flow.transferred[0]))} ↑ ${esc(formatBytes(flow.transferred[1]))}` : '';
            return {
                remote, address,
                verdict: flagged ? bigPill('danger', T.allowed_flagged, 'fa-exclamation-triangle') : bigPill('ok', T.allowed, 'fa-check'),
                sub: outbound ? T.started_inside_long : T.started_outside_long,
                diagram: [outbound ? localBox : remoteBox, service, `↓ ${esc(formatRate(flow.rate_in || 0))} ↑ ${esc(formatRate(flow.rate_out || 0))}`, outbound ? remoteBox : localBox, false],
                connection: rows([
                    [T.protocol, esc(`${service.name}${service.port ? ` (${service.port.split('/')[0]})` : ''}`)],
                    [T.remote_port, outbound && service.port ? esc(service.port.split('/')[1]) : ''],
                    [T.other_services, (flow.services || []).slice(1).map(esc).join(', ')],
                    [T.state, (flow.activity || 0) > 0 ? pill('ok', T.active, 'fa-check') : pill('muted', T.idle)],
                    [T.started, flow.age ? esc(`${ago(Date.now() / 1000 - flow.age)} ${T.ago}`) : ''],
                    [T.transferred, transferred],
                    [T.current_rate, `↓ ${esc(formatRate(flow.rate_in || 0))} ↑ ${esc(formatRate(flow.rate_out || 0))}`],
                    [T.duration, flow.age ? esc(spanText(flow.age)) : ''],
                    [T.connections, esc(flow.states)],
                ]),
                firewall: rows([
                    [T.decision, pill('ok', T.allowed, 'fa-check')],
                    [T.interface, esc(inside?.interface || (target && target.interface) || flow.egress || '')],
                    [T.rule, esc(flow.rule || '')],
                    [T.egress, esc(flow.egress || '')],
                    ['NAT', inside && outbound ? esc(`${T.yes} (${inside.ip} → ${flow.origin})`)
                        : target && !target.firewall ? esc(`${T.port_forward} (${flow.origin} → ${target.ip}${target.port ? `:${target.port}` : ''})`) : esc(T.no)],
                ]),
                ids: idsCard(flow.ids, null),
                reputation: reputationCard({...item, address, lists: flow.lists, abuseipdb: flow.abuseipdb}),
            };
        }
        if (ids) {
            const inside = ids.inside_host;
            const insideBox = inside ? endBox('laptop', inside.name || inside.ip, [inside.name ? ids.inside : '', inside.interface])
                : endBox('fa-shield', firewallName, [ids.public]);
            const [, port] = ids.remote.split(':');
            const service = {name: ids.protocol.toUpperCase(), port: port ? `${ids.protocol.toUpperCase()}/${port}` : ''};
            const serious = ids.severity <= 2 || (ids.lists || []).length > 0;
            return {
                remote, address,
                verdict: serious ? bigPill('danger', T.allowed_flagged, 'fa-exclamation-triangle') : bigPill('ok', T.allowed, 'fa-check'),
                sub: ids.remote_started ? T.started_outside_long : T.started_inside_long,
                diagram: [ids.remote_started ? remoteBox : insideBox, service, `↓ ${esc(formatBytes(ids.bytes_in || 0))} ↑ ${esc(formatBytes(ids.bytes_out || 0))}`, ids.remote_started ? insideBox : remoteBox, false],
                connection: rows([
                    [T.protocol, esc(ids.protocol.toUpperCase())],
                    [T.inside_side, esc(ids.inside || T.this_firewall)],
                    [T.via, esc(ids.public)],
                    [T.remote_side, esc(ids.remote)],
                    [T.state, ids.active ? pill('ok', T.active, 'fa-check') : pill('muted', T.closed)],
                    [T.started, ids.age ? esc(`${ago(Date.now() / 1000 - ids.age)} ${T.ago}`) : ''],
                    [T.transferred, `↓ ${esc(formatBytes(ids.bytes_in || 0))} ↑ ${esc(formatBytes(ids.bytes_out || 0))}`],
                ]),
                firewall: rows([
                    [T.decision, pill('ok', T.allowed, 'fa-check')],
                    [T.interface, esc(ids.interface || '')],
                    [T.rule, esc(ids.rule || '')],
                    ['NAT', ids.inside && !String(ids.inside).startsWith(ids.public.split(':')[0]) ? esc(`${T.yes} (${ids.inside} → ${ids.public})`) : esc(T.no)],
                    ['IPS', ids.ips_dropped ? pill('danger', T.ips_dropped) : ''],
                ]),
                ids: idsCard(null, ids.groups),
                reputation: reputationCard({...item, address}),
            };
        }
        if (block) {
            const service = serviceParts(block.services?.[0]?.name, block.services?.[0]?.port);
            return {
                remote, address,
                verdict: bigPill('blocked', T.blocked, 'fa-ban'),
                sub: T.blocked_attempts,
                diagram: [remoteBox, service, `${esc(block.hits)}× ${esc(T.in_minutes.replace('%s', block.window_minutes))}`, endBox('fa-shield', firewallName, [block.target, block.interface]), true],
                connection: rows([
                    [T.tried, (block.services || []).map((entry) => {
                        const parts = serviceParts(entry.name, entry.port);
                        return `${esc(parts.name)} <span class="fwmap-muted">${esc(parts.port)}</span> ×${esc(entry.hits)}`;
                    }).join('<br>')],
                    [T.other_ports, block.port_count > (block.services || []).length ? esc(block.port_count - block.services.length) : ''],
                    [T.attempts, esc(`${block.hits} · ${block.hits_per_minute}/min`)],
                    [T.first_seen, block.seconds ? esc(`${ago(Date.now() / 1000 - block.seconds)} ${T.ago}`) : ''],
                ]),
                firewall: rows([
                    [T.decision, pill('blocked', T.blocked, 'fa-ban')],
                    [T.interface, esc(block.interface || '')],
                    [T.rule, esc(block.rule || '')],
                    [T.target, esc(block.target || '')],
                ]),
                ids: idsCard(block.ids, null),
                reputation: reputationCard({...item, address}),
            };
        }
        return {
            remote, address,
            verdict: bigPill('muted', T.ids_only, 'fa-flag'),
            sub: T.ids_only_sub,
            diagram: null,
            connection: `<div class="text-muted">${esc(T.no_connection)}</div>`,
            firewall: `<div class="text-muted">${esc(T.no_connection)}</div>`,
            ids: idsCard(alert?.ids, null),
            reputation: reputationCard({...item, address}),
        };
    }

    function actionBar(address, countryCode) {
        const more = [
            `<li><a href="https://bgp.he.net/ip/${encodeURIComponent(address)}" target="_blank" rel="noopener noreferrer"><i class="fa fa-globe"></i> ${esc(T.whois)}</a></li>`,
            `<li><a href="https://www.abuseipdb.com/check/${encodeURIComponent(address)}" target="_blank" rel="noopener noreferrer"><i class="fa fa-external-link"></i> AbuseIPDB</a></li>`,
            `<li><a href="#" class="fwmap-copy" data-address="${esc(address)}"><i class="fa fa-clipboard"></i> ${esc(T.copy)}</a></li>`,
        ];
        if (state.isAdmin) {
            more.push('<li role="separator" class="divider"></li>',
                `<li><a href="#" class="fwmap-alias" data-address="${esc(address)}"><i class="fa fa-list-ul"></i> ${esc(T.add_to_alias)}</a></li>`,
                `<li><a href="#" class="fwmap-mark" data-address="${esc(address)}"><i class="fa fa-flag"></i> ${esc(T.mark_threat)}</a></li>`);
            if (countryCode) {
                more.push(`<li><a href="#" class="fwmap-country" data-code="${esc(countryCode)}"><i class="fa fa-map-marker"></i> ${esc(T.add_country)} (${esc(countryCode)})</a></li>`);
            }
        }
        const admin = state.isAdmin ? `
            <button type="button" class="btn btn-primary fwmap-investigate" data-address="${esc(address)}">${ic('external')} ${esc(T.investigate)}</button>
            <button type="button" class="btn btn-default fwmap-states" data-address="${esc(address)}">${ic('list')} ${esc(T.show_states)}</button>
            <button type="button" class="btn btn-default fwmap-kill" data-address="${esc(address)}">${ic('trash')} ${esc(T.kill_states)}</button>` : '';
        return `<div class="fwmap-actions">${admin}
            <div class="btn-group dropup"><button type="button" class="btn btn-default dropdown-toggle" data-toggle="dropdown">${esc(T.more)} <span class="caret"></span></button>
            <ul class="dropdown-menu dropdown-menu-right">${more.join('')}</ul></div></div>`;
    }

    function renderDetails() {
        const selection = state.selection;
        const $details = $('#fwmap-details');
        if (!selection) {
            $details.html(`<div class="text-muted fwmap-empty">${esc(T.click_hint)}</div>`);
            return;
        }
        const addresses = [...new Set(selection.addresses)].filter(Boolean);
        if (!addresses.length) {
            $details.html(`<div class="text-muted fwmap-empty">${esc(T.click_hint)}</div>`);
            return;
        }
        if (!addresses.includes(state.detailsAddress)) {
            state.detailsAddress = addresses[0];
        }
        const address = state.detailsAddress;
        const model = detailsModel(selection, address);
        const picker = addresses.length > 1 ? `<div class="fwmap-picker"><span class="text-muted">${esc(addresses.length)} ${esc(T.remote_addresses_here)}</span>`
            + addresses.slice(0, 12).map((entry) => `<a href="#" class="fwmap-pick${entry === address ? ' active' : ''}" data-address="${esc(entry)}">${esc(entry)}</a>`).join('')
            + '</div>' : '';
        const diagram = model.diagram ? `<div class="fwmap-diagram">${model.diagram[0]}
            <div class="fwmap-link${model.diagram[4] ? ' fwmap-link-blocked' : ''}"><div class="fwmap-link-service">${esc(model.diagram[1].name)}</div>
                <div class="fwmap-link-port">${esc(model.diagram[1].port)}</div>
                <div class="fwmap-link-arrow">${model.diagram[4] ? ic('ban') : ''}</div>
                <div class="fwmap-link-rate">${model.diagram[2]}</div></div>
            ${model.diagram[3]}</div>` : '';
        const investigation = state.investigations.get(address);
        // re-rendering the same address (a lookup finishing, a check) keeps the reader's scroll position
        const same = state.renderedSelection === selection && state.renderedAddress === address;
        const scrollTop = same ? ($details.find('.fwmap-d-scroll').scrollTop() || 0) : 0;
        state.renderedSelection = selection;
        state.renderedAddress = address;
        $details.html(`
            <div class="fwmap-d-scroll">
                <div class="fwmap-d-head">
                    ${ic('globe', 'fwmap-d-icon')}
                    <div class="fwmap-d-title">
                        <div class="fwmap-d-name">${esc(model.remote.title)}</div>
                        <div class="fwmap-d-line">${model.remote.hostname ? `<b>${esc(address)}</b>` : ''}
                            ${model.remote.place ? `<span>${model.remote.cc ? `${flagOf(model.remote.cc)} ` : ''}${esc(model.remote.place)}</span>` : ''}</div>
                        ${model.remote.org ? `<div class="fwmap-d-line">${esc(model.remote.org)}</div>` : ''}
                    </div>
                    <div class="fwmap-d-verdict">${model.verdict}<div class="fwmap-d-verdict-sub">${esc(model.sub)}</div></div>
                    <a href="#" id="fwmap-details-close" title="${esc(T.close)}">${ic('x')}</a>
                </div>
                ${picker}
                ${diagram}
                <div class="fwmap-cards">
                    ${card('fa-bar-chart', T.sec_connection, model.connection, state.isAdmin ? {cls: 'fwmap-states', address, title: T.show_states} : null)}
                    ${card('fa-shield', T.sec_firewall, model.firewall, {href: '/ui/diagnostics/firewall/log', title: T.open_log})}
                    ${model.ids}
                    ${model.reputation}
                </div>
                ${investigation ? `<div class="fwmap-investigation">${investigation}</div>` : ''}
            </div>
            ${actionBar(address, selection.countryCode)}
        `);
        if (scrollTop) {
            $details.find('.fwmap-d-scroll').scrollTop(scrollTop);
        }
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

    // a plain host alias; it only marks traffic on the map until the operator uses it in a rule
    function markThreat(address) {
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
                    const result = await postJSON(`/api/firewall/alias_util/add/${WATCHLIST}`, {address});
                    if (result.status !== 'done') {
                        throw new Error(result.status_msg || result.status);
                    }
                }
                notify(`${address} → ${WATCHLIST}. ${T.marked}`, BootstrapDialog.TYPE_SUCCESS);
            } catch (error) {
                notify(`${T.action_failed}: ${error.message || error.statusText || error}`, BootstrapDialog.TYPE_DANGER);
            }
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
        const parts = [];
        const count = shown.flows.length;
        parts.push(esc(count ? `${count} ${T.active_flows}` : T.no_flows));
        if (state.settings.blocks) {
            const blocked = shown.blocks.length;
            const below = snapshot.blocks_below || 0;
            if (blocked || below) {
                parts.push(esc(`${blocked} ${T.blocked_sources}`));
                if (below) {
                    parts.push(esc(`${below} ${T.below_threshold}`));
                }
            }
        }
        // connection evidence and address history are counted separately, each a one-click filter
        const all = snapshot;
        const idsFlows = (all.ids_flows || []).filter((flow) => flow.kind !== 'blocked').length;
        const idsAddresses = new Set([...(all.alerts || []).map((alert) => alert.source),
            ...(all.flows || []).filter((flow) => flow.ids).map((flow) => flow.dest),
            ...(all.blocks || []).filter((block) => block.ids).map((block) => block.source)]).size;
        const link = (filter, text) => `<a href="#" class="fwmap-status-ids${state.filters.traffic === filter ? ' active' : ''}" data-filter="${filter}">${esc(text)}</a>`;
        if (idsFlows) {
            parts.push(link('ids_flows', `${idsFlows} ${idsFlows === 1 ? T.ids_flow : T.ids_flows}`));
        }
        if (idsAddresses) {
            parts.push(link('ids_addresses', `${idsAddresses} ${idsAddresses === 1 ? T.ids_address : T.ids_addresses}`));
        }
        const threats = shown.flows.filter((flow) => flow.threat).length;
        if (threats) {
            parts.push(esc(`${threats} ${T.listed_flows}`));
        }
        if (snapshot.carp === 'backup') {
            parts.push(esc(T.carp_backup));
        }
        $('#fwmap-status').html(parts.join(' · '));
        state.updatedAt = Date.now();
        updatedLine();
    }

    function updatedLine() {
        if (!state.updatedAt) {
            return;
        }
        const seconds = Math.max(0, Math.round((Date.now() - state.updatedAt) / 1000));
        $('#fwmap-updated').html(`${esc(T.last_updated)} ${esc(seconds)} s ${esc(T.ago)} <i class="fwmap-live${seconds > 10 ? ' stale' : ''}"></i>`);
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
            if (row?.select) {
                // IDS tab: open the details of that address or connection
                state.selection = row.select;
                state.detailsAddress = row.key;
                renderDetails();
            } else if (row?.filter) {
                // a second click on the active row removes its filter
                const active = talkerActive(row);
                for (const [key, value] of Object.entries(row.filter)) {
                    state.filters[key] = active ? '' : value;
                }
                refresh();
            }
        });
        $('#fwmap-talker-search, #fwmap-talker-sort').on('input change', () => {
            if (state.snapshot) {
                renderTalkers(talkersFromLast());
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
            .on('click', '.fwmap-mark', function (event) {
                event.preventDefault();
                markThreat(String($(this).data('address')));
            })
            .on('click', '.fwmap-country', function (event) {
                event.preventDefault();
                addCountry(String($(this).data('code')));
            })
            .on('click', '.fwmap-abuse-check', function (event) {
                event.preventDefault();
                checkAbuse(String($(this).data('address')));
            })
            .on('click', '.fwmap-pick', function (event) {
                event.preventDefault();
                state.detailsAddress = String($(this).data('address'));
                renderDetails();
            })
            .on('click', '.fwmap-investigate', function (event) {
                event.preventDefault();
                investigate(String($(this).data('address')));
            });
        $('#fwmap-review').on('click', () => showQueue());
        // the IDS counters in the status line filter the map; a second click shows everything again
        $('#fwmap-status').on('click', '.fwmap-status-ids', function (event) {
            event.preventDefault();
            const filter = String($(this).data('filter'));
            const next = state.filters.traffic === filter ? 'all' : filter;
            $('#fwmap-filter-traffic').val(next).trigger('change');
        });
        setInterval(updatedLine, 1000);
        $('#fwmap-zoom').on('click', 'button', function () {
            const step = $(this).data('zoom');
            if (step === 'fit') {
                state.renderer.fit();
            } else {
                state.renderer.zoom(Number(step));
            }
        });
    }

    // re-rank the current tab from the last snapshot without adding a history point
    function talkersFromLast() {
        const groups = groupTalkers(state.snapshot);
        for (const [group, entries] of Object.entries(groups)) {
            for (const entry of entries) {
                entry.series = state.history.get(`${group}:${entry.key}`);
            }
        }
        return groups;
    }

    /* ---------------------------------------------------------------- resizable panels */

    const LAYOUT_KEY = 'firewallmap.layout';

    function readLayout() {
        try {
            return JSON.parse(window.localStorage.getItem(LAYOUT_KEY) || '{}') || {};
        } catch (_) {
            return {};
        }
    }

    function saveLayout(layout) {
        try {
            window.localStorage.setItem(LAYOUT_KEY, JSON.stringify(layout));
        } catch (_) {
            // private windows or blocked storage: the sizes just are not remembered
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
    }

    /** Pointer drag on a handle; `move` gets the pointer event, the map redraws once per frame. */
    function draggable($handle, move, reset) {
        let frame = null;
        const onMove = (event) => {
            move(event);
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
            saveLayout(state.layout);
            state.renderer?.resize();
        };
        $handle.on('pointerdown', (event) => {
            event.preventDefault();
            // listen on the document so a fast drag that leaves the thin handle keeps working
            document.addEventListener('pointermove', onMove);
            document.addEventListener('pointerup', onUp);
            document.addEventListener('pointercancel', onUp);
            $handle.addClass('fwmap-dragging');
            $('body').addClass('fwmap-resizing');
        }).on('dblclick', () => {
            reset();
            applyLayout(state.layout);
            saveLayout(state.layout);
            state.renderer?.resize();
        });
    }

    /** Drop the least important talker column when the side panel is narrow. */
    function watchSideWidth() {
        const side = document.getElementById('fwmap-side');
        const update = () => side.classList.toggle('fwmap-narrow', side.clientWidth < 470);
        if (window.ResizeObserver) {
            new ResizeObserver(update).observe(side);
        }
        update();
    }

    function bindSplitters() {
        state.layout = readLayout();
        applyLayout(state.layout);
        draggable($('#fwmap-split-side'), (event) => {
            const bounds = $('#fwmap-layout')[0].getBoundingClientRect();
            // the side panel is right of the map: its width is what lies right of the pointer
            const width = Math.round(bounds.right - event.clientX - 6);
            state.layout.side = Math.max(220, Math.min(width, Math.round(bounds.width * 0.6)));
            applyLayout(state.layout);
        }, () => {
            delete state.layout.side;
        });
        draggable($('#fwmap-split-details'), (event) => {
            const bounds = $('#fwmap-side')[0].getBoundingClientRect();
            const share = (event.clientY - bounds.top) / bounds.height;
            state.layout.talkers = Math.max(0.15, Math.min(share, 0.85));
            applyLayout(state.layout);
        }, () => {
            delete state.layout.talkers;
        });
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
            const pluginSettings = await $.getJSON('/api/firewallmap/settings/get');
            state.isAdmin = !!pluginSettings.provider;
            state.abuseConfigured = !!pluginSettings.abuseipdb_configured;
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
            // the side panel boxes sit on the page's own background colour
            document.getElementById('fwmap-side').style.setProperty('--fwmap-panel', `rgb(${theme.background.join(', ')})`);
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
        bindSplitters();
        watchSideWidth();
        $('#fwmap-review').toggle(state.isAdmin);
        if (state.isAdmin) {
            refreshQueueCount();
            setInterval(refreshQueueCount, 60000);
        }
        renderDetails();
        $(window).on('resize', () => state.renderer.resize());
        poll(`?blocks_min=${state.settings.blockMin}${state.settings.hostnames ? '&hostnames=1' : ''}`);
    });
})();
