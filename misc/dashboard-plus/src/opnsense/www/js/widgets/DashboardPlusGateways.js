/*
 * Copyright (C) 2026 Claudio Guareschi
 * All rights reserved.
 */

const {escapeHtml, renderTitle, mergeOrder, makeSortable, isDragging, sizeToContent, widthChanged} =
    await import(`./DashboardPlusCommon.js${new URL(import.meta.url).search}`);

export default class DashboardPlusGateways extends BaseTableWidget {
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
        const $container = $('<div class="dashboard-plus-gateways" style="padding: 0 0.25em;"></div>');
        const $table = this.createTable(this._tableId(), {
            headerPosition: 'top',
            headers: [
                '',
                this.translations.gateway,
                this.translations.rtt,
                this.translations.rttd,
                this.translations.loss,
                this.translations.status
            ]
        });
        $table.find('.grid-header').css('text-align', 'left');
        // A separate empty state: replacing the table's content would also drop the header
        // row that updateTable inserts rows after.
        $container.append($table, `<div id="${this.id}-empty" style="display: none; padding: 0.75em;">
            <a href="/ui/routing/configuration">${escapeHtml(this.translations.unconfigured)}</a>
        </div>`);
        return $container;
    }

    async _fetchGateways() {
        const data = await this.ajaxCall('/api/routing/settings/search_gateway');
        return data.rows || [];
    }

    _statusInfo(status) {
        const normalized = String(status || '').toLowerCase();
        if (normalized.includes('disabled')) {
            return {color: '#777777', background: 'rgba(119, 119, 119, 0.14)'};
        }
        if (normalized.includes('online')) {
            return {color: '#2ca02c', background: 'rgba(44, 160, 44, 0.20)'};
        }
        if (normalized.includes('offline')) {
            return {color: '#d62728', background: 'rgba(214, 39, 40, 0.20)'};
        }
        if (normalized.includes('delay') || normalized.includes('loss')) {
            return {color: '#ff7f0e', background: 'rgba(255, 127, 14, 0.20)'};
        }
        return {color: '#777777', background: 'rgba(119, 119, 119, 0.14)'};
    }

    _enablementIcon(disabled) {
        return disabled
            ? `<i class="fa fa-times-circle-o" style="font-size: 1.5em; color: #777777;" title="${escapeHtml(this.translations.disabled)}"></i>`
            : `<i class="fa fa-check-circle-o" style="font-size: 1.5em;" title="${escapeHtml(this.translations.enabled)}"></i>`;
    }

    _gatewayIdentity(gateway) {
        const defaultMarker = gateway.defaultgw
            ? `<i class="fa fa-globe" aria-label="${escapeHtml(this.translations.default_gateway)}" title="${escapeHtml(this.translations.default_gateway)}" style="margin-left: 0.5em;"></i>`
            : '';
        return `<div style="text-align: left; line-height: 1.35;">
            <a href="/ui/routing/configuration#edit=${encodeURIComponent(gateway.uuid)}" target="_blank" rel="noopener noreferrer">${escapeHtml(gateway.name)}</a>${defaultMarker}
            <strong style="display: block; margin-top: 0.15em;">${escapeHtml(gateway.gateway)}</strong>
        </div>`;
    }

    _statusCell(status, info) {
        return `<div style="min-height: 3.35em; display: flex; align-items: center; justify-content: flex-start;">
            <span style="min-width: 5.25em; padding: 0.45em 0.65em; border-radius: 999px; background: ${info.background}; color: ${info.color}; font-weight: 600; text-align: center;">${escapeHtml(status)}</span>
        </div>`;
    }

    _applyFieldVisibility(config) {
        const fields = config.fields || ['rtt', 'rttd', 'loss'];
        const fieldColumns = {rtt: 2, rttd: 3, loss: 4};
        const $table = $(`#${this._tableId()}`);
        $table.children('.grid-header-container, .grid-row').each((_, row) => {
            Object.entries(fieldColumns).forEach(([field, column]) => {
                $(row).children().eq(column).toggle(fields.includes(field));
            });
        });

        const columns = {
            0: '8% 62% 15% 15%',
            1: '8% 45% 18% 14% 15%',
            2: '8% 36% 17% 16% 14% 15%',
            3: '8% 31% 16% 15% 14% 16%'
        }[fields.length];
        $table.children('.grid-header-container, .grid-row').css('grid-template-columns', columns);
    }

    _orderedGateways(gateways, config) {
        const order = config.gateways || gateways.map(gateway => gateway.uuid);
        return [...gateways].filter(gateway => order.includes(gateway.uuid)).sort((left, right) =>
            order.indexOf(left.uuid) - order.indexOf(right.uuid)
        );
    }

    async onMarkupRendered() {
        renderTitle(this);
        this.currentConfig = await this.getWidgetConfig();
        this._applyFieldVisibility(this.currentConfig);
        makeSortable($(`#${this._tableId()}`), {
            itemSelector: '.grid-row',
            handleSelector: '.grid-item:nth-child(2)',
            placeholderClass: 'grid-row',
            label: this.translations.drag_to_reorder,
            onReorder: order => {
                this.currentConfig.gateways = mergeOrder(order, this.currentConfig.gateways || order);
                this.setWidgetConfig(this.currentConfig);
            }
        });
        sizeToContent(this);
    }

    _metric(gateway, unmonitored, value) {
        return escapeHtml(gateway.disabled || unmonitored || value === '~' || !value ? '—' : value);
    }

    async onWidgetTick() {
        const gateways = await this._fetchGateways();
        this.cachedGateways = gateways;
        this._render();
    }

    _render() {
        const $table = $(`#${this._tableId()}`);
        if (isDragging($table)) {
            return;
        }
        const gateways = this.cachedGateways;
        $table.toggle(gateways.length > 0);
        $(`#${this.id}-empty`).toggle(gateways.length === 0);
        if (!gateways.length) {
            return;
        }

        const orderedGateways = this._orderedGateways(gateways, this.currentConfig);
        const rows = orderedGateways.map(gateway => {
            // A gateway without monitoring has no RTT or loss; the API still calls it "Online".
            const unmonitored = !gateway.disabled && gateway.monitor_disable === '1';
            const status = gateway.disabled ? this.translations.disabled
                : unmonitored ? this.translations.unmonitored : gateway.status;
            const info = this._statusInfo(unmonitored ? 'unmonitored' : status);
            return [
                this._enablementIcon(gateway.disabled),
                this._gatewayIdentity(gateway),
                this._metric(gateway, unmonitored, gateway.delay),
                this._metric(gateway, unmonitored, gateway.stddev),
                this._metric(gateway, unmonitored, gateway.loss),
                this._statusCell(status, info)
            ];
        });
        // BaseTableWidget inserts every new row immediately after the header,
        // so feed it in reverse to retain the configured visual order.
        super.updateTable(this._tableId(), [...rows].reverse());
        $table.children('.grid-row').each((index, row) => {
            const $cells = $(row).children();
            $(row).attr('data-sort-id', orderedGateways[index].uuid);
            $cells.css('text-align', 'left');
            $cells.eq(0).css('text-align', 'center');
            $cells.eq(1).attr({draggable: 'true', title: this.translations.drag_to_reorder})
                .css('cursor', 'grab');
        });
        this._applyFieldVisibility(this.currentConfig);
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
                options: [
                    {value: 'rtt', label: this.translations.rtt},
                    {value: 'rttd', label: this.translations.rttd},
                    {value: 'loss', label: this.translations.loss}
                ],
                default: ['rtt', 'rttd', 'loss']
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

    onWidgetResize(elem, width, height) {
        const layoutChanged = super.onWidgetResize(elem, width, height);
        return widthChanged(this, width) || layoutChanged;
    }
}
