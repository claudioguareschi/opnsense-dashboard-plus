/*
 * Copyright (C) 2026 Claudio Guareschi
 * All rights reserved.
 */

const {escapeHtml, renderTitle, ensureTableStyle, DashboardPlusWidget} =
    await import(`./DashboardPlusCommon.js${new URL(import.meta.url).search}`);

export default class DashboardPlusFirewallLogs extends DashboardPlusWidget(BaseWidget) {
    constructor(config) {
        super(config);
        this.configurable = true;
        this.currentConfig = null;
        this.interfaceNames = {};
        // Digests of the rows on screen, so a stream event already loaded is not shown twice.
        this.seen = new Set();
    }

    getGridOptions() {
        return {sizeToContent: 650};
    }

    _tableId() {
        return `${this.id}-table`;
    }

    getMarkup() {
        ensureTableStyle();
        // The interface and rule go on a second line so the addresses keep room for
        // "address:port".
        return $(`
            <div class="flextable-container dashboard-plus-table" id="${this._tableId()}" role="table"
                style="--dashboard-plus-columns: auto auto minmax(0, 1fr) minmax(0, 1fr);">
                <div class="flextable-header dashboard-plus-row" role="row">
                    ${[
                        this.translations.action,
                        this.translations.time,
                        this.translations.source,
                        this.translations.destination
                    ].map(title => `<div role="columnheader">${escapeHtml(title)}</div>`).join('')}
                </div>
            </div>
        `);
    }

    _actionIcon(action) {
        if (action === 'pass') {
            return `<i class="fa fa-check-circle-o" style="color: #2ca02c; font-size: 1.35em;" title="${escapeHtml(this.translations.pass)}"></i>`;
        }
        if (action === 'block') {
            return `<i class="fa fa-times-circle-o" style="color: #d62728; font-size: 1.35em;" title="${escapeHtml(this.translations.block)}"></i>`;
        }
        return `<i class="fa fa-exchange" style="color: #777777;" title="${escapeHtml(action)}"></i>`;
    }

    /* The time of day in the column, the full date and time on hover. */
    _time(timestamp) {
        const value = new Date(timestamp);
        if (Number.isNaN(value.getTime())) {
            return escapeHtml(timestamp);
        }
        const time = new Intl.DateTimeFormat(undefined, {hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false}).format(value);
        const full = new Intl.DateTimeFormat(undefined, {dateStyle: 'medium', timeStyle: 'medium'}).format(value);
        return `<span title="${escapeHtml(full)}">${escapeHtml(time)}</span>`;
    }

    _endpoint(address, port) {
        if (!address) {
            return '—';
        }
        if (!port) {
            return escapeHtml(address);
        }
        return escapeHtml(address.includes(':') ? `[${address}]:${port}` : `${address}:${port}`);
    }

    _rule(entry) {
        const rule = entry.label || `@${entry.rulenr || '0'}`;
        const query = new URLSearchParams({field: 'rid', operator: '=', value: entry.rid || ''});
        return `<a href="/ui/diagnostics/firewall/log#${query}" target="_blank" rel="noopener noreferrer">${escapeHtml(rule)}</a>`;
    }

    _matches(entry) {
        const action = this.currentConfig.actions || 'block';
        const selected = this.currentConfig.interfaces;
        const interfaces = Array.isArray(selected) && selected.length ? selected : Object.keys(this.interfaceNames);
        return (action === 'all' || entry.action === action) && interfaces.includes(entry.interface);
    }

    _rows() {
        return $(`#${this._tableId()}`).children('.flextable-row');
    }

    _clearRows() {
        this._rows().remove();
        $(`#${this._tableId()}`).children('.dashboard-plus-logs-empty').remove();
        this.seen.clear();
    }

    _addEntry(entry) {
        const digest = entry.__digest__ || `${entry.__timestamp__}-${entry.interface}-${entry.src}-${entry.dst}-${entry.rid}`;
        if (!this._matches(entry) || this.seen.has(digest)) {
            return false;
        }
        this.seen.add(digest);
        const $row = $(`
            <div class="flextable-row dashboard-plus-row" role="row" style="align-items: start; row-gap: 0.1em;">
                <div role="cell">${this._actionIcon(entry.action)}</div>
                <div role="cell" class="dashboard-plus-nowrap" style="font-variant-numeric: tabular-nums;">${this._time(entry.__timestamp__)}</div>
                <div role="cell">${this._endpoint(entry.src, entry.srcport)}</div>
                <div role="cell">${this._endpoint(entry.dst, entry.dstport)}</div>
                <div role="cell" class="dashboard-plus-small" style="grid-column: 2 / -1;">${escapeHtml(this.interfaceNames[entry.interface] || entry.interface || '—')} · ${this._rule(entry)}</div>
            </div>
        `).attr('data-digest', digest);
        const $table = $(`#${this._tableId()}`);
        $table.children('.dashboard-plus-logs-empty').remove();
        $table.children('.flextable-header').after($row);

        const limit = parseInt(this.currentConfig.rows, 10) || 5;
        this._rows().slice(limit).each((_, row) => {
            this.seen.delete(row.dataset.digest);
            row.remove();
        });
        return true;
    }

    async _startLog(config) {
        this.closeEventSource();
        this.currentConfig = config;
        this._clearRows();
        const limit = parseInt(config.rows, 10) || 5;
        const recent = await this.ajaxCall(`/api/diagnostics/firewall/log?limit=${limit}`);
        (Array.isArray(recent) ? [...recent] : []).reverse().forEach(entry => this._addEntry(entry));
        if (!this._rows().length) {
            $(`#${this._tableId()}`).append(
                `<div class="dashboard-plus-logs-empty dashboard-plus-span" style="padding: 0.75em;">${escapeHtml(this.translations.no_entries)}</div>`
            );
        }
        this.openEventSource('/api/diagnostics/firewall/stream_log', event => {
            let entry;
            try {
                entry = JSON.parse(event.data);
            } catch (_) {
                // Keep the stream alive when an unrelated or malformed event arrives.
                return;
            }
            const count = this._rows().length;
            // Once the list is full a new row replaces the oldest; only a change in the row
            // count changes the widget's height.
            if (this._addEntry(entry) && this._rows().length !== count) {
                this.config.callbacks?.updateGrid?.();
            }
        });
        this.config.callbacks?.updateGrid?.();
    }

    async onMarkupRendered() {
        renderTitle(this);
        const [interfaceNames, config] = await Promise.all([
            this.ajaxCall('/api/diagnostics/interface/get_interface_names'),
            this.getWidgetConfig()
        ]);
        this.interfaceNames = interfaceNames || {};
        this.fitToContent();
        await this._startLog(config);
    }

    async onWidgetOptionsChanged() {
        // Read back through getWidgetConfig so an empty selection means the defaults now,
        // as it will after the dashboard reloads.
        await this._startLog(await this.getWidgetConfig());
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
