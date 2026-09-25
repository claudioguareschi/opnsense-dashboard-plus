/*
 * Copyright (C) 2026 Claudio Guareschi
 * All rights reserved.
 */

export default class DashboardPlusFirewallLogs extends BaseTableWidget {
    constructor(config) {
        super(config);
        this.configurable = true;
        this.currentConfig = null;
        this.interfaceNames = {};
        this.seen = new Set();
    }

    getGridOptions() {
        return {sizeToContent: 650};
    }

    getMarkup() {
        const $container = $('<div class="dashboard-plus-firewall-logs"></div>');
        const $table = this.createTable('dashboard-plus-firewall-logs-table', {headerPosition: 'none'});
        const $header = $('<div class="flextable-header dashboard-plus-firewall-logs-header" role="row"></div>');
        [
            this.translations.action,
            this.translations.time,
            this.translations.interface,
            this.translations.source,
            this.translations.destination
        ].forEach(title => $header.append(`<div class="flex-cell" role="columnheader">${title}</div>`));
        $table.prepend($header);
        $container.append($table);
        return $container;
    }

    _escape(value) {
        return $('<div>').text(value ?? '').html();
    }

    _applyColumns() {
        const widths = ['6%', '17%', '12%', '33%', '32%'];
        $('#dashboard-plus-firewall-logs-table')
            .children('.flextable-header, .dashboard-plus-firewall-logs-row')
            .each((_, row) => {
                $(row).children('.flex-cell').each((column, cell) => {
                    const $cell = $(cell);
                    if (column === 5) {
                        $cell.css({
                            width: '94%',
                            flexBasis: '94%',
                            marginLeft: '6%',
                            marginTop: '0.25em',
                            textAlign: 'left'
                        });
                    } else {
                        $cell.css({
                            width: widths[column],
                            flexBasis: widths[column],
                            marginLeft: '',
                            marginTop: '',
                            textAlign: 'left'
                        });
                    }
                });
            });
    }

    _actionIcon(action) {
        if (action === 'pass') {
            return `<i class="fa fa-check-circle-o" style="color: #2ca02c; font-size: 1.35em;" title="${this.translations.pass}"></i>`;
        }
        if (action === 'block') {
            return `<i class="fa fa-times-circle-o" style="color: #d62728; font-size: 1.35em;" title="${this.translations.block}"></i>`;
        }
        return `<i class="fa fa-exchange" style="color: #777777;" title="${this._escape(action)}"></i>`;
    }

    _time(timestamp) {
        const value = new Date(timestamp);
        if (Number.isNaN(value.getTime())) {
            return this._escape(timestamp);
        }
        const date = new Intl.DateTimeFormat(undefined, {month: 'short', day: 'numeric'}).format(value);
        const time = new Intl.DateTimeFormat(undefined, {hour: '2-digit', minute: '2-digit', second: '2-digit'}).format(value);
        return `<div>${date}<br>${time}</div>`;
    }

    _endpoint(address, port) {
        const escapedAddress = this._escape(address || '—');
        return port ? `${escapedAddress}:<span style="color: inherit;">${this._escape(port)}</span>` : escapedAddress;
    }

    _identity(entry) {
        const interfaceName = this.interfaceNames[entry.interface] || entry.interface || '—';
        return this._escape(interfaceName);
    }

    _rule(entry) {
        const rule = entry.label || `@${entry.rulenr || '0'}`;
        const query = new URLSearchParams({field: 'rid', operator: '=', value: entry.rid || ''});
        return `<a href="/ui/diagnostics/firewall/log#${query}" target="_blank" rel="noopener noreferrer" style="font-size: 0.86em;">${this._escape(rule)}</a>`;
    }

    _matches(entry) {
        const action = this.currentConfig.actions || 'block';
        const selectedInterfaces = this.currentConfig.interfaces;
        const interfaces = Array.isArray(selectedInterfaces) && selectedInterfaces.length
            ? selectedInterfaces
            : Object.keys(this.interfaceNames);
        return (action === 'all' || entry.action === action) && interfaces.includes(entry.interface);
    }

    _clearRows() {
        $('#dashboard-plus-firewall-logs-table')
            .children('.dashboard-plus-firewall-logs-row, .dashboard-plus-firewall-logs-empty').remove();
        this.seen.clear();
    }

    _addEntry(entry, prepend = true) {
        const digest = entry.__digest__ || `${entry.__timestamp__}-${entry.interface}-${entry.src}-${entry.dst}-${entry.rid}`;
        if (!this._matches(entry) || this.seen.has(digest)) {
            return;
        }
        this.seen.add(digest);
        const $row = $('<div class="flextable-row dashboard-plus-firewall-logs-row" role="row"></div>');
        [
            this._actionIcon(entry.action),
            this._time(entry.__timestamp__),
            this._identity(entry),
            this._endpoint(entry.src, entry.srcport),
            this._endpoint(entry.dst, entry.dstport),
            this._rule(entry)
        ].forEach(value => $row.append(`<div class="flex-cell" role="cell">${value}</div>`));
        const $table = $('#dashboard-plus-firewall-logs-table');
        const $header = $table.children('.dashboard-plus-firewall-logs-header');
        prepend ? $header.after($row) : $table.append($row);

        const count = parseInt(this.currentConfig.rows, 10) || 5;
        const $rows = $table.children('.dashboard-plus-firewall-logs-row');
        if ($rows.length > count) {
            $rows.last().remove();
        }
        $table.children('.dashboard-plus-firewall-logs-empty').remove();
        this._applyColumns();
        this.config.callbacks?.updateGrid?.();
    }

    async _startLog(config) {
        this.closeEventSource();
        this.currentConfig = config;
        this._clearRows();
        const limit = parseInt(config.rows, 10) || 5;
        const recent = await this.ajaxCall(`/api/diagnostics/firewall/log?limit=${limit}`);
        (Array.isArray(recent) ? [...recent] : []).reverse().forEach(entry => this._addEntry(entry, true));
        if (!$('#dashboard-plus-firewall-logs-table').children('.dashboard-plus-firewall-logs-row').length) {
            $('#dashboard-plus-firewall-logs-table').append(
                `<div class="dashboard-plus-firewall-logs-empty" style="padding: 0.75em;">${this.translations.no_entries}</div>`
            );
        }
        this.openEventSource('/api/diagnostics/firewall/stream_log', event => {
            try {
                this._addEntry(JSON.parse(event.data));
            } catch (_) {
                // Keep the stream alive when an unrelated or malformed event arrives.
            }
        });
        this.config.callbacks?.updateGrid?.();
    }

    async onMarkupRendered() {
        $(`#${this.id}-title`).html(`<b>${this.translations.dashboard_title}</b>`);
        const [interfaceNames, config] = await Promise.all([
            this.ajaxCall('/api/diagnostics/interface/get_interface_names'),
            this.getWidgetConfig()
        ]);
        this.interfaceNames = interfaceNames || {};
        await this._startLog(config);
    }

    async onWidgetOptionsChanged(options) {
        await this._startLog(options);
    }

    async getWidgetOptions() {
        const interfaceNames = Object.keys(this.interfaceNames).length
            ? this.interfaceNames
            : await this.ajaxCall('/api/diagnostics/interface/get_interface_names');
        return {
            actions: {
                title: this.translations.actions,
                type: 'select',
                id: 'dashboard-plus-firewall-logs-actions',
                options: [
                    {value: 'all', label: this.translations.all},
                    {value: 'block', label: this.translations.block},
                    {value: 'pass', label: this.translations.pass}
                ],
                default: 'block'
            },
            interfaces: {
                title: this.translations.interfaces,
                type: 'select_multiple',
                id: 'dashboard-plus-firewall-logs-interfaces',
                options: Object.entries(interfaceNames).map(([value, label]) => ({value, label})),
                default: Object.keys(interfaceNames)
            },
            rows: {
                title: this.translations.rows,
                type: 'select',
                id: 'dashboard-plus-firewall-logs-rows',
                options: ['5', '10', '25'].map(value => ({value, label: value})),
                default: '5'
            }
        };
    }
}
