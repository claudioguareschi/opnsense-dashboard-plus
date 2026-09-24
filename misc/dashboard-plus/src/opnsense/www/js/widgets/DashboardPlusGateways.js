/*
 * Copyright (C) 2026 Claudio Guareschi
 * All rights reserved.
 */

export default class DashboardPlusGateways extends BaseTableWidget {
    constructor(config) {
        super(config);
        this.configurable = true;
        this.cachedGateways = [];
        this.currentConfig = null;
        this.configChanged = false;
    }

    getGridOptions() {
        return {sizeToContent: 650};
    }

    getMarkup() {
        const $container = $('<div class="dashboard-plus-gateways" style="padding: 0 0.25em;"></div>');
        const $table = this.createTable('dashboard-plus-gateways-table', {
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
        $container.append($table);
        return $container;
    }

    async _fetchGateways() {
        const data = await this.ajaxCall('/api/routing/settings/search_gateway');
        return data.rows || [];
    }

    _escape(value) {
        return $('<div>').text(value ?? '').html();
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
            ? `<i class="fa fa-times" style="font-size: 1.25em; color: #777777;" title="${this.translations.disabled}"></i>`
            : `<i class="fa fa-check" style="font-size: 1.25em;" title="${this.translations.enabled}"></i>`;
    }

    _gatewayIdentity(gateway) {
        const defaultMarker = gateway.defaultgw
            ? `<i class="fa fa-globe" aria-label="${this.translations.default_gateway}" title="${this.translations.default_gateway}" style="margin-left: 0.5em;"></i>`
            : '';
        return `<div style="text-align: left; line-height: 1.35;">
            <a href="/ui/routing/configuration#edit=${encodeURIComponent(gateway.uuid)}" target="_blank" rel="noopener noreferrer">${this._escape(gateway.name)}</a>${defaultMarker}
            <strong style="display: block; margin-top: 0.15em;">${this._escape(gateway.gateway)}</strong>
        </div>`;
    }

    _statusCell(status, info) {
        return `<div style="min-height: 3.35em; display: flex; align-items: center; justify-content: flex-start;">
            <span style="width: 5.25em; padding: 0.45em 0.65em; border-radius: 999px; background: ${info.background}; color: ${info.color}; font-weight: 600; text-align: center;">${this._escape(status)}</span>
        </div>`;
    }

    _applyFieldVisibility(config) {
        const fields = config.fields || ['rtt', 'rttd', 'loss'];
        const fieldColumns = {rtt: 2, rttd: 3, loss: 4};
        const $table = $('#dashboard-plus-gateways-table');
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

    _saveGatewayOrder() {
        const order = $('#dashboard-plus-gateways-table').children('.grid-row')
            .map((_, row) => $(row).data('gateway')).get();
        const selected = this.currentConfig.gateways || order;
        this.currentConfig.gateways = [
            ...order.filter(uuid => selected.includes(uuid)),
            ...selected.filter(uuid => !order.includes(uuid))
        ];
        this.setWidgetConfig(this.currentConfig);
        $('#save-grid').show();
    }

    _makeRowsSortable() {
        const $table = $('#dashboard-plus-gateways-table');
        let $draggedRow = null;
        let $placeholder = null;
        const clearDragState = () => {
            $draggedRow?.css({opacity: '', outline: ''});
            $placeholder?.remove();
            $draggedRow = null;
            $placeholder = null;
        };
        $table.on('mousedown', '.grid-row .grid-item:nth-child(2)', event => event.stopPropagation());
        $table.on('dragstart', '.grid-row .grid-item:nth-child(2)', event => {
            $draggedRow = $(event.currentTarget).closest('.grid-row');
            $draggedRow.css({opacity: 0.4, outline: '2px dashed #d94f00'});
            $placeholder = $('<div class="grid-row dashboard-plus-gateways-drop-placeholder" aria-label="Drop gateway here"></div>')
                .css({
                    height: $draggedRow.outerHeight(),
                    border: '2px dashed #d94f00',
                    background: 'rgba(217, 79, 0, 0.08)'
                });
            event.originalEvent.dataTransfer.effectAllowed = 'move';
            event.stopPropagation();
        });
        $table.on('dragover', event => {
            event.preventDefault();
            event.originalEvent.dataTransfer.dropEffect = 'move';
            const $target = $(event.target).closest('.grid-row');
            if (!$draggedRow || !$target.length || $target[0] === $draggedRow[0]) {
                return;
            }
            const halfway = $target.offset().top + ($target.outerHeight() / 2);
            event.originalEvent.clientY < halfway ? $target.before($placeholder) : $target.after($placeholder);
        });
        $table.on('drop', event => {
            event.preventDefault();
            if ($draggedRow && $placeholder?.parent().length) {
                $placeholder.replaceWith($draggedRow);
                this._saveGatewayOrder();
            }
            clearDragState();
        });
        $table.on('dragend', '.grid-row .grid-item:nth-child(2)', clearDragState);
    }

    async onMarkupRendered() {
        $(`#${this.id}-title`).html(`<b>${this.translations.dashboard_title}</b>`);
        this.currentConfig = await this.getWidgetConfig();
        this._applyFieldVisibility(this.currentConfig);
        this._makeRowsSortable();
    }

    async onWidgetTick() {
        if (this.configChanged || !this.currentConfig) {
            this.currentConfig = await this.getWidgetConfig();
            this.configChanged = false;
        }
        const gateways = await this._fetchGateways();
        this.cachedGateways = gateways;
        const config = this.currentConfig;
        if (!gateways.length) {
            $('#dashboard-plus-gateways-table').html(`<a href="/ui/routing/configuration">${this.translations.unconfigured}</a>`);
            return;
        }

        const orderedGateways = this._orderedGateways(gateways, config);
        const rows = orderedGateways.map(gateway => {
            const status = gateway.disabled ? this.translations.disabled : gateway.status;
            const info = this._statusInfo(status);
            return [
                this._enablementIcon(gateway.disabled),
                this._gatewayIdentity(gateway),
                this._escape(gateway.disabled || gateway.delay === '~' ? '—' : gateway.delay),
                this._escape(gateway.disabled || gateway.stddev === '~' ? '—' : gateway.stddev),
                this._escape(gateway.disabled || gateway.loss === '~' ? '—' : gateway.loss),
                this._statusCell(status, info)
            ];
        });
        // BaseTableWidget inserts every new row immediately after the header,
        // so feed it in reverse to retain the configured visual order.
        super.updateTable('dashboard-plus-gateways-table', [...rows].reverse());
        $('#dashboard-plus-gateways-table').children('.grid-row').each((index, row) => {
            const $cells = $(row).children();
            $(row).data('gateway', orderedGateways[index].uuid);
            $cells.css('text-align', 'left');
            $cells.eq(0).css('text-align', 'center');
            $cells.eq(1).attr({draggable: 'true', title: this.translations.drag_to_reorder})
                .css('cursor', 'grab');
        });
        this._applyFieldVisibility(config);
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

    onWidgetOptionsChanged() {
        this.configChanged = true;
    }
}
