/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
 * All rights reserved.
 */

const {escapeHtml, renderTitle, DashboardPlusWidget} =
    await import(`./DashboardPlusCommon.js${new URL(import.meta.url).search}`);

const STYLE_ID = 'dashboard-plus-wan-health-style';

export default class DashboardPlusWanHealth extends DashboardPlusWidget(BaseWidget) {
    constructor(config) {
        super(config);
        this.configurable = true;
        this.currentConfig = {};
        this.gateways = [];
        this.error = '';
        this.refreshSeconds = 15;
        this.tickTimeout = 15;
    }

    getGridOptions() {
        return {sizeToContent: 420, minH: 4};
    }

    _elementId(name) {
        return `${this.id}-wan-health-${name}`;
    }

    _addStyle() {
        const css = `
            .dashboard-plus-wan-health {
                width: 100%;
                max-width: none;
                box-sizing: border-box;
                color: inherit;
            }
            .dashboard-plus-wan-health-header {
                display: flex;
                align-items: center;
                justify-content: space-between;
                gap: 0.8em;
                padding: 0.15em 0.4em 0.7em;
                border-bottom: 1px solid rgba(217, 79, 0, 0.28);
            }
            .dashboard-plus-wan-health-identity {
                display: flex;
                align-items: center;
                gap: 0.6em;
                min-width: 0;
            }
            .dashboard-plus-wan-health-dot {
                flex: none;
                width: 0.7em;
                height: 0.7em;
                border-radius: 50%;
                background: var(--success, #2ca02c);
                box-shadow: 0 0 0 3px rgba(44, 160, 44, 0.12);
            }
            .dashboard-plus-wan-health-dot.warning {
                background: var(--warning, #e06c00);
                box-shadow: 0 0 0 3px rgba(224, 108, 0, 0.12);
            }
            .dashboard-plus-wan-health-dot.danger {
                background: var(--danger, #d62728);
                box-shadow: 0 0 0 3px rgba(214, 39, 40, 0.12);
            }
            .dashboard-plus-wan-health-dot.muted {
                background: #777;
                box-shadow: 0 0 0 3px rgba(119, 119, 119, 0.12);
            }
            .dashboard-plus-wan-health-label {
                min-width: 0;
            }
            .dashboard-plus-wan-health-eyebrow,
            .dashboard-plus-wan-health-metric-label,
            .dashboard-plus-wan-health-section-label {
                color: currentColor;
                opacity: 0.68;
                font-size: 0.78em;
                letter-spacing: 0.02em;
            }
            .dashboard-plus-wan-health-state {
                font-size: 1.05em;
                font-weight: 600;
                white-space: nowrap;
            }
            .dashboard-plus-wan-health-default {
                max-width: 48%;
                overflow: hidden;
                text-align: right;
                text-overflow: ellipsis;
                white-space: nowrap;
                opacity: 0.78;
                font-size: 0.84em;
            }
            .dashboard-plus-wan-health-metrics {
                display: grid;
                grid-template-columns: repeat(3, minmax(0, 1fr));
                gap: 0.5em;
                padding: 0.7em 0.4em;
            }
            .dashboard-plus-wan-health-metric {
                min-width: 0;
                padding: 0.6em 0.65em;
                border: 1px solid rgba(127, 127, 127, 0.24);
                border-radius: 3px;
                background: rgba(127, 127, 127, 0.06);
            }
            .dashboard-plus-wan-health-metric-value {
                margin-top: 0.18em;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
                font-size: 1.16em;
                font-weight: 600;
                font-variant-numeric: tabular-nums;
            }
            .dashboard-plus-wan-health-metric-detail {
                margin-top: 0.12em;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
                opacity: 0.64;
                font-size: 0.76em;
            }
            .dashboard-plus-wan-health-section {
                margin: 0 0.4em;
                border-top: 1px solid rgba(127, 127, 127, 0.2);
            }
            .dashboard-plus-wan-health-section-head {
                display: flex;
                align-items: center;
                justify-content: space-between;
                gap: 0.6em;
                padding: 0.55em 0 0.35em;
            }
            .dashboard-plus-wan-health-gateways {
                display: grid;
                gap: 0.25em;
            }
            .dashboard-plus-wan-health-gateway {
                display: flex;
                align-items: center;
                gap: 0.55em;
                min-width: 0;
                padding: 0.32em 0;
            }
            .dashboard-plus-wan-health-gateway-dot {
                flex: none;
                width: 0.55em;
                height: 0.55em;
                border-radius: 50%;
                background: var(--success, #2ca02c);
            }
            .dashboard-plus-wan-health-gateway-dot.warning {
                background: var(--warning, #e06c00);
            }
            .dashboard-plus-wan-health-gateway-dot.danger {
                background: var(--danger, #d62728);
            }
            .dashboard-plus-wan-health-gateway-dot.muted {
                background: #777;
            }
            .dashboard-plus-wan-health-gateway-main {
                min-width: 0;
                flex: 1 1 auto;
            }
            .dashboard-plus-wan-health-gateway-name,
            .dashboard-plus-wan-health-gateway-address {
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
            }
            .dashboard-plus-wan-health-gateway-name {
                font-size: 0.88em;
            }
            .dashboard-plus-wan-health-gateway-address {
                opacity: 0.62;
                font-size: 0.76em;
            }
            .dashboard-plus-wan-health-gateway-metrics {
                flex: none;
                display: flex;
                gap: 0.55em;
                align-items: center;
                font-size: 0.78em;
                font-variant-numeric: tabular-nums;
                white-space: nowrap;
            }
            .dashboard-plus-wan-health-badge {
                flex: none;
                padding: 0.16em 0.48em;
                border-radius: 999px;
                font-size: 0.72em;
                white-space: nowrap;
            }
            .dashboard-plus-wan-health-badge.healthy {
                color: var(--success, #2ca02c);
                background: rgba(44, 160, 44, 0.12);
            }
            .dashboard-plus-wan-health-badge.warning {
                color: var(--warning, #e06c00);
                background: rgba(224, 108, 0, 0.12);
            }
            .dashboard-plus-wan-health-badge.danger {
                color: var(--danger, #d62728);
                background: rgba(214, 39, 40, 0.12);
            }
            .dashboard-plus-wan-health-badge.muted {
                color: #888;
                background: rgba(119, 119, 119, 0.12);
            }
            .dashboard-plus-wan-health-empty {
                padding: 0.35em 0 0.6em;
                opacity: 0.65;
                font-size: 0.82em;
            }
            .dashboard-plus-wan-health-footer {
                display: flex;
                justify-content: space-between;
                gap: 0.7em;
                padding: 0.65em 0.4em 0.15em;
                opacity: 0.68;
                font-size: 0.76em;
            }
            .dashboard-plus-wan-health-footer a {
                flex: none;
                color: #d94f00;
            }
            .dashboard-plus-wan-health-error {
                padding: 0.6em 0.4em 0.15em;
                color: var(--danger, #d62728);
                font-size: 0.8em;
            }
            @media (max-width: 28em) {
                .dashboard-plus-wan-health-gateway-metrics {
                    display: none;
                }
            }
            @media (max-width: 24em) {
                .dashboard-plus-wan-health-metrics {
                    grid-template-columns: 1fr;
                }
            }
        `;
        const existing = document.getElementById(STYLE_ID);
        if (existing) {
            $(existing).text(css);
        } else {
            $('<style>').attr('id', STYLE_ID).text(css).appendTo('head');
        }
    }

    getMarkup() {
        this._addStyle();
        return $(`
            <div id="${this._elementId('root')}" class="dashboard-plus-wan-health">
                <div class="dashboard-plus-wan-health-header">
                    <div class="dashboard-plus-wan-health-identity">
                        <span id="${this._elementId('dot')}" class="dashboard-plus-wan-health-dot muted" aria-hidden="true"></span>
                        <div class="dashboard-plus-wan-health-label">
                            <div class="dashboard-plus-wan-health-eyebrow">${escapeHtml(this.translations.connection)}</div>
                            <div id="${this._elementId('state')}" class="dashboard-plus-wan-health-state">${escapeHtml(this.translations.loading)}</div>
                        </div>
                    </div>
                    <div id="${this._elementId('default')}" class="dashboard-plus-wan-health-default">${escapeHtml(this.translations.loading)}</div>
                </div>
                <div id="${this._elementId('metrics')}" class="dashboard-plus-wan-health-metrics"></div>
                <div class="dashboard-plus-wan-health-section">
                    <div class="dashboard-plus-wan-health-section-head">
                        <span class="dashboard-plus-wan-health-section-label">${escapeHtml(this.translations.gateways)}</span>
                        <span id="${this._elementId('count')}" class="dashboard-plus-wan-health-section-label"></span>
                    </div>
                    <div id="${this._elementId('gateways')}" class="dashboard-plus-wan-health-gateways"></div>
                </div>
                <div id="${this._elementId('error')}" class="dashboard-plus-wan-health-error" style="display: none;"></div>
                <div class="dashboard-plus-wan-health-footer">
                    <span id="${this._elementId('updated')}">${escapeHtml(this.translations.waiting)}</span>
                    <a href="/ui/routing/configuration" target="_blank" rel="noopener noreferrer">${escapeHtml(this.translations.open_gateways)}</a>
                </div>
            </div>
        `);
    }

    _asNumber(value) {
        const number = Number(String(value ?? '').replace('%', '').replace('ms', '').trim());
        return Number.isFinite(number) ? number : null;
    }

    _gatewayState(gateway) {
        if (gateway.disabled) {
            return {label: this.translations.disabled, state: 'muted'};
        }
        if (String(gateway.monitor_disable) === '1') {
            return {label: this.translations.unmonitored, state: 'muted'};
        }
        const status = String(gateway.status || '').toLowerCase();
        if (status.includes('offline') || status.includes('down')) {
            return {label: this.translations.offline, state: 'danger'};
        }
        if (status.includes('delay') || status.includes('loss') || status.includes('warning')) {
            return {label: this.translations.warning, state: 'warning'};
        }
        if (status.includes('online')) {
            return {label: this.translations.online, state: 'healthy'};
        }
        return {label: this.translations.unavailable, state: 'warning'};
    }

    _wanGateways() {
        const configured = Array.isArray(this.currentConfig.gateways) ? this.currentConfig.gateways : null;
        const all = this.gateways.filter(gateway => gateway.interface === 'wan' ||
            String(gateway.interface_descr || '').toLowerCase() === 'wan');
        if (!configured) {
            return all;
        }
        const selected = new Set(configured);
        return all.filter(gateway => selected.has(gateway.uuid));
    }

    _primary(gateways) {
        return gateways.find(gateway => gateway.defaultgw && String(gateway.monitor_disable) !== '1') ||
            gateways.find(gateway => gateway.defaultgw) || gateways[0] || null;
    }

    _metric(label, value, detail) {
        return `<div class="dashboard-plus-wan-health-metric">
            <div class="dashboard-plus-wan-health-metric-label">${escapeHtml(label)}</div>
            <div class="dashboard-plus-wan-health-metric-value">${escapeHtml(value)}</div>
            <div class="dashboard-plus-wan-health-metric-detail">${escapeHtml(detail)}</div>
        </div>`;
    }

    _render() {
        const gateways = this._wanGateways();
        const primary = this._primary(gateways);
        const primaryState = primary ? this._gatewayState(primary) : {label: this.translations.unavailable, state: 'muted'};
        const monitored = gateways.filter(gateway => String(gateway.monitor_disable) !== '1' && !gateway.disabled);
        const hasFailure = monitored.some(gateway => this._gatewayState(gateway).state === 'danger');
        const hasWarning = monitored.some(gateway => this._gatewayState(gateway).state === 'warning');
        const overall = !gateways.length ? {label: this.translations.no_wan, state: 'muted'}
            : hasFailure ? {label: this.translations.offline, state: 'danger'}
                : hasWarning ? {label: this.translations.warning, state: 'warning'}
                    : primaryState;
        const dot = $(`#${this._elementId('dot')}`);
        dot.removeClass('healthy warning danger muted').addClass(overall.state);
        $(`#${this._elementId('state')}`).text(overall.label);
        $(`#${this._elementId('default')}`).text(primary ?
            `${primary.name}${primary.defaultgw ? ` · ${this.translations.default_gateway}` : ''}` : this.translations.no_wan);

        const delay = primary && String(primary.monitor_disable) !== '1' ? primary.delay : null;
        const stddev = primary && String(primary.monitor_disable) !== '1' ? primary.stddev : null;
        const loss = primary && String(primary.monitor_disable) !== '1' ? primary.loss : null;
        $(`#${this._elementId('metrics')}`).html([
            this._metric(this.translations.rtt, delay || '—', primary ? primary.gateway || '—' : this.translations.no_wan),
            this._metric(this.translations.jitter, stddev || '—', this.translations.rtt_deviation),
            this._metric(this.translations.loss, loss || '—', this.translations.packet_loss)
        ].join(''));

        $(`#${this._elementId('count')}`).text(gateways.length ? `${gateways.length} ${this.translations.selected}` : '');
        $(`#${this._elementId('gateways')}`).html(gateways.length ? gateways.map(gateway => {
            const state = this._gatewayState(gateway);
            const measured = state.state !== 'muted';
            return `<div class="dashboard-plus-wan-health-gateway">
                <span class="dashboard-plus-wan-health-gateway-dot ${state.state}" aria-hidden="true"></span>
                <div class="dashboard-plus-wan-health-gateway-main">
                    <div class="dashboard-plus-wan-health-gateway-name">${escapeHtml(gateway.name)}${gateway.interface_descr ? ` · ${escapeHtml(gateway.interface_descr)}` : ''}</div>
                    <div class="dashboard-plus-wan-health-gateway-address">${escapeHtml(gateway.gateway || '—')}</div>
                </div>
                <div class="dashboard-plus-wan-health-gateway-metrics">
                    <span>${escapeHtml(measured ? gateway.delay || '—' : '—')}</span>
                    <span>${escapeHtml(measured ? gateway.loss || '—' : '—')}</span>
                </div>
                <span class="dashboard-plus-wan-health-badge ${state.state}">${escapeHtml(state.label)}</span>
            </div>`;
        }).join('') : `<div class="dashboard-plus-wan-health-empty">${escapeHtml(this.translations.no_wan)}</div>`);

        $(`#${this._elementId('error')}`).text(this.error).toggle(Boolean(this.error));
        $(`#${this._elementId('updated')}`).text(this.error ? this.translations.fetch_failed :
            `${this.translations.updated} ${new Date().toLocaleTimeString()}`);
        this.config.callbacks?.updateGrid?.();
    }

    async _fetchGateways() {
        const data = await this.ajaxCall('/api/routing/settings/search_gateway');
        this.gateways = data?.rows || [];
    }

    _applyConfig(config = {}) {
        this.currentConfig = config;
        this.refreshSeconds = Number(config.refresh_interval) || 15;
        this.tickTimeout = this.refreshSeconds;
    }

    async onMarkupRendered() {
        renderTitle(this);
        this._applyConfig(await this.getWidgetConfig());
        try {
            await this._fetchGateways();
            this.error = '';
        } catch (error) {
            this.error = error?.message || this.translations.fetch_failed;
        }
        this._render();
        this.fitToContent();
    }

    async onWidgetTick() {
        try {
            await this._fetchGateways();
            this.error = '';
        } catch (error) {
            this.error = error?.message || this.translations.fetch_failed;
        }
        this._render();
    }

    async getWidgetOptions() {
        const gateways = this.gateways.length ? this.gateways :
            (await this.ajaxCall('/api/routing/settings/search_gateway'))?.rows || [];
        const wan = gateways.filter(gateway => gateway.interface === 'wan' ||
            String(gateway.interface_descr || '').toLowerCase() === 'wan');
        return {
            gateways: {
                title: this.translations.gateways,
                type: 'select_multiple',
                id: this._elementId('gateway-selection'),
                options: wan.map(gateway => ({value: gateway.uuid, label: gateway.name})),
                default: wan.map(gateway => gateway.uuid)
            },
            refresh_interval: {
                title: this.translations.refresh_interval,
                type: 'select',
                id: this._elementId('refresh-interval'),
                options: [
                    {value: '5', label: this.translations.seconds_5},
                    {value: '15', label: this.translations.seconds_15},
                    {value: '30', label: this.translations.seconds_30}
                ],
                default: '15'
            }
        };
    }

    async onWidgetOptionsChanged() {
        const config = await this.getWidgetConfig();
        this.setWidgetConfig(config);
        this._applyConfig(config);
        this._render();
    }
}
