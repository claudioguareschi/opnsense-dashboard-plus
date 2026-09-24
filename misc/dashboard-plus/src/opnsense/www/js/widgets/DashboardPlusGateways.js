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
        const $container = $('<div class="dashboard-plus-gateways"></div>');
        $container.append(this.createTable('dashboard-plus-gateways-table', {
            headerPosition: 'top',
            headers: [
                this.translations.health,
                this.translations.gateway,
                this.translations.rtt,
                this.translations.rttd,
                this.translations.loss,
                this.translations.status
            ]
        }));
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
        if (normalized.includes('online')) {
            return {color: '#2ca02c', background: 'rgba(44, 160, 44, 0.20)', icon: 'fa-check-circle'};
        }
        if (normalized.includes('offline')) {
            return {color: '#d62728', background: 'rgba(214, 39, 40, 0.20)', icon: 'fa-times-circle'};
        }
        if (normalized.includes('delay') || normalized.includes('loss')) {
            return {color: '#ff7f0e', background: 'rgba(255, 127, 14, 0.20)', icon: 'fa-exclamation-circle'};
        }
        return {color: '#777777', background: 'rgba(119, 119, 119, 0.14)', icon: 'fa-question-circle'};
    }

    _gatewayIdentity(gateway) {
        const defaultMarker = gateway.defaultgw
            ? ` <i class="fa fa-globe" aria-label="${this.translations.default_gateway}" title="${this.translations.default_gateway}"></i>`
            : '';
        return `<div style="text-align: left; line-height: 1.35;">
            <a href="/ui/routing/configuration#edit=${encodeURIComponent(gateway.uuid)}" target="_blank" rel="noopener noreferrer">${this._escape(gateway.name)}</a>${defaultMarker}
            <br><strong>${this._escape(gateway.gateway)}</strong>
        </div>`;
    }

    _statusCell(status, info) {
        return `<div style="margin: -4px; min-height: 3.35em; display: flex; align-items: center; justify-content: center; background: ${info.background}; color: ${info.color}; font-weight: 600;">${this._escape(status)}</div>`;
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

    async onMarkupRendered() {
        $(`#${this.id}-title`).html(`<b>${this.translations.dashboard_title}</b>`);
        this.currentConfig = await this.getWidgetConfig();
        this._applyFieldVisibility(this.currentConfig);
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

        const rows = this._orderedGateways(gateways, config).map(gateway => {
            const info = this._statusInfo(gateway.status);
            return [
                `<i class="fa ${info.icon}" style="font-size: 1.4em; color: ${info.color};" title="${this._escape(gateway.status)}"></i>`,
                this._gatewayIdentity(gateway),
                this._escape(gateway.delay === '~' ? '—' : gateway.delay),
                this._escape(gateway.stddev === '~' ? '—' : gateway.stddev),
                this._escape(gateway.loss === '~' ? '—' : gateway.loss),
                this._statusCell(gateway.status, info)
            ];
        });
        super.updateTable('dashboard-plus-gateways-table', rows);
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
