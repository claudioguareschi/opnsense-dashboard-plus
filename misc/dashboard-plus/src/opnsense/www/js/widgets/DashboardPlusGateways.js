/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
 * All rights reserved.
 */

const {escapeHtml, renderTitle, mergeOrder, makeSortable, isDragging, ensureTableStyle, DashboardPlusWidget} =
    await import(`./DashboardPlusCommon.js${new URL(import.meta.url).search}`);

const METRICS = ['rtt', 'rttd', 'loss'];

export default class DashboardPlusGateways extends DashboardPlusWidget(BaseWidget) {
    constructor(config) {
        super(config);
        this.configurable = true;
        this.cachedGateways = [];
        this.currentConfig = null;
    }

    getGridOptions() {
        return {sizeToContent: 650};
    }

    _tableId() {
        return `${this.id}-table`;
    }

    getMarkup() {
        ensureTableStyle();
        return $(`
            <div>
                <div class="flextable-container dashboard-plus-table" id="${this._tableId()}" role="table"></div>
                <div id="${this.id}-empty" style="display: none; padding: 0.75em;">
                    <a href="/ui/routing/configuration">${escapeHtml(this.translations.unconfigured)}</a>
                </div>
            </div>
        `);
    }

    async _fetchGateways() {
        const data = await this.ajaxCall('/api/routing/settings/search_gateway');
        return data.rows || [];
    }

    _statusColors(state) {
        return {
            online: {color: '#2ca02c', background: 'rgba(44, 160, 44, 0.18)'},
            offline: {color: '#d62728', background: 'rgba(214, 39, 40, 0.16)'},
            warning: {color: '#e06c00', background: 'rgba(255, 127, 14, 0.18)'}
        }[state] ?? {color: '#777777', background: 'rgba(119, 119, 119, 0.14)'};
    }

    _state(gateway) {
        if (gateway.disabled) {
            return {label: this.translations.disabled, state: 'disabled'};
        }
        // A gateway without monitoring has no RTT or loss; the API still calls it "Online".
        if (gateway.monitor_disable === '1') {
            return {label: this.translations.unmonitored, state: 'unmonitored'};
        }
        const status = String(gateway.status || '');
        const normalized = status.toLowerCase();
        const state = normalized.includes('offline') ? 'offline'
            : normalized.includes('delay') || normalized.includes('loss') ? 'warning'
            : normalized.includes('online') ? 'online' : 'unknown';
        return {label: status, state};
    }

    _fields() {
        const fields = this.currentConfig?.fields;
        return METRICS.filter(field => !Array.isArray(fields) || fields.includes(field));
    }

    _headerRow(fields) {
        const title = text => escapeHtml(this.translations[text]);
        return `<div class="flextable-header dashboard-plus-row" role="row">
            <div></div>
            <div role="columnheader">${title('gateway')}</div>
            ${fields.map(field => `<div class="dashboard-plus-number" role="columnheader">${title(field)}</div>`).join('')}
            <div role="columnheader" style="text-align: center;">${title('status')}</div>
        </div>`;
    }

    _row(gateway, fields) {
        const {label, state} = this._state(gateway);
        const colors = this._statusColors(state);
        const measured = state !== 'disabled' && state !== 'unmonitored';
        const values = {rtt: gateway.delay, rttd: gateway.stddev, loss: gateway.loss};
        const metric = value => escapeHtml(measured && value && value !== '~' ? value : '—');
        const icon = gateway.disabled
            ? `<i class="fa fa-times-circle-o" style="font-size: 1.3em; color: #777777;" title="${escapeHtml(this.translations.disabled)}"></i>`
            : `<i class="fa fa-check-circle-o" style="font-size: 1.3em;" title="${escapeHtml(this.translations.enabled)}"></i>`;
        // the default-gateway globe sits beside both lines, centered like the status icon
        const defaultMarker = gateway.defaultgw
            ? `<i class="fa fa-globe dashboard-plus-side-icon" aria-label="${escapeHtml(this.translations.default_gateway)}" title="${escapeHtml(this.translations.default_gateway)}"></i>`
            : '';
        return `<div class="flextable-row dashboard-plus-row" role="row" data-sort-id="${escapeHtml(gateway.uuid)}" draggable="true" title="${escapeHtml(this.translations.drag_to_reorder)}" style="cursor: grab;">
            <div role="cell">${icon}</div>
            <div role="cell" class="dashboard-plus-gateway-name dashboard-plus-named" style="line-height: 1.35;">
                <div>
                    <div class="dashboard-plus-ellipsis"><a href="/ui/routing/configuration#edit=${encodeURIComponent(gateway.uuid)}" target="_blank" rel="noopener noreferrer">${escapeHtml(gateway.name)}</a></div>
                    <div class="dashboard-plus-ellipsis dashboard-plus-muted dashboard-plus-small">${escapeHtml(gateway.gateway || '—')}</div>
                </div>
                ${defaultMarker}
            </div>
            ${fields.map(field => `<div role="cell" class="dashboard-plus-number dashboard-plus-small">${metric(values[field])}</div>`).join('')}
            <div role="cell" style="text-align: center;">
                <span class="dashboard-plus-pill" style="color: ${colors.color}; background: ${colors.background};">${escapeHtml(label)}</span>
            </div>
        </div>`;
    }

    _orderedGateways() {
        const order = mergeOrder(this.currentConfig.gateways, this.currentConfig.gateways ?? this.cachedGateways.map(gateway => gateway.uuid));
        const byId = new Map(this.cachedGateways.map(gateway => [gateway.uuid, gateway]));
        return order.filter(uuid => byId.has(uuid)).map(uuid => byId.get(uuid));
    }

    _render() {
        const $table = $(`#${this._tableId()}`);
        if (!this.currentConfig || isDragging($table)) {
            return;
        }
        const empty = this.cachedGateways.length === 0;
        $table.toggle(!empty);
        $(`#${this.id}-empty`).toggle(empty);
        if (empty) {
            return;
        }
        const fields = this._fields();
        $table[0].style.setProperty('--dashboard-plus-columns', `auto minmax(0, 1fr)${' auto'.repeat(fields.length)} auto`);
        $table.html(this._headerRow(fields) + this._orderedGateways().map(gateway => this._row(gateway, fields)).join(''));
    }

    async onMarkupRendered() {
        renderTitle(this);
        this.currentConfig = await this.getWidgetConfig();
        makeSortable($(`#${this._tableId()}`), {
            itemSelector: '.flextable-row[data-sort-id]',
            placeholderClass: 'flextable-row dashboard-plus-row',
            label: this.translations.drag_to_reorder,
            onReorder: order => {
                this.currentConfig.gateways = mergeOrder(order, this.currentConfig.gateways || order);
                this.setWidgetConfig(this.currentConfig);
            }
        });
        this.fitToContent();
    }

    async onWidgetTick() {
        this.cachedGateways = await this._fetchGateways();
        this._render();
    }

    async getWidgetOptions() {
        const gateways = this.cachedGateways.length ? this.cachedGateways : await this._fetchGateways();
        return {
            gateways: {
                title: this.translations.gateways,
                type: 'select_multiple',
                id: 'dashboard-plus-gateways-selection',
                options: gateways.map(gateway => ({value: gateway.uuid, label: gateway.name})),
                default: gateways.map(gateway => gateway.uuid)
            },
            fields: {
                title: this.translations.metrics,
                type: 'select_multiple',
                id: 'dashboard-plus-gateways-fields',
                options: METRICS.map(field => ({value: field, label: this.translations[field]})),
                default: METRICS
            }
        };
    }

    async onWidgetOptionsChanged() {
        const previous = this.currentConfig?.gateways;
        const config = await this.getWidgetConfig();
        // The dialog lists the selection in option order; keep the dragged order.
        config.gateways = mergeOrder(previous, config.gateways);
        this.setWidgetConfig(config);
        this.currentConfig = config;
        this._render();
    }
}
