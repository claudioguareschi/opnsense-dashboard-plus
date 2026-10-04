/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
 * All rights reserved.
 */

const {escapeHtml, renderTitle, DashboardPlusWidget} =
    await import(`./DashboardPlusCommon.js${new URL(import.meta.url).search}`);

const STYLE_ID = 'dashboard-plus-dns-health-style';

export default class DashboardPlusDnsHealth extends DashboardPlusWidget(BaseWidget) {
    constructor(config) {
        super(config);
        this.configurable = true;
        this.currentConfig = {};
        this.data = {status: null, stats: null, totals: null, settings: null, upstreams: []};
        this.previousSample = null;
        this.error = '';
        this.totalsError = '';
        this.totalsLoading = false;
        this.refreshSeconds = 30;
        this.tickTimeout = 30;
    }

    getGridOptions() {
        return {sizeToContent: 420, minH: 4};
    }

    _elementId(name) {
        return `${this.id}-dns-health-${name}`;
    }

    _addStyle() {
        const css = `
            .dashboard-plus-dns-health {
                width: 100%;
                max-width: none;
                box-sizing: border-box;
                color: inherit;
            }
            .dashboard-plus-dns-health-header {
                display: flex;
                align-items: center;
                justify-content: space-between;
                gap: 0.8em;
                padding: 0.15em 0.4em 0.7em;
                border-bottom: 1px solid rgba(217, 79, 0, 0.28);
            }
            .dashboard-plus-dns-health-identity {
                display: flex;
                align-items: center;
                gap: 0.6em;
                min-width: 0;
            }
            .dashboard-plus-dns-health-dot {
                flex: none;
                width: 0.7em;
                height: 0.7em;
                border-radius: 50%;
                background: currentColor;
                box-shadow: 0 0 0 3px currentColor;
                opacity: 0.8;
            }
            .dashboard-plus-dns-health-label {
                min-width: 0;
            }
            .dashboard-plus-dns-health-eyebrow,
            .dashboard-plus-dns-health-metric-label,
            .dashboard-plus-dns-health-section-label {
                color: currentColor;
                opacity: 0.68;
                font-size: 0.78em;
                letter-spacing: 0.02em;
            }
            .dashboard-plus-dns-health-state {
                font-size: 1.05em;
                font-weight: 600;
                white-space: nowrap;
            }
            .dashboard-plus-dns-health-mode {
                max-width: 48%;
                overflow: hidden;
                text-align: right;
                text-overflow: ellipsis;
                white-space: nowrap;
                opacity: 0.78;
                font-size: 0.84em;
            }
            .dashboard-plus-dns-health-metrics {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(9em, 1fr));
                gap: 0.5em;
                padding: 0.7em 0.4em;
            }
            .dashboard-plus-dns-health-metric {
                min-width: 0;
                padding: 0.6em 0.65em;
                border: 1px solid rgba(127, 127, 127, 0.24);
                border-radius: 3px;
                background: rgba(127, 127, 127, 0.06);
            }
            .dashboard-plus-dns-health-metric-value {
                margin-top: 0.18em;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
                font-size: 1.16em;
                font-weight: 600;
                font-variant-numeric: tabular-nums;
            }
            .dashboard-plus-dns-health-metric-detail {
                margin-top: 0.12em;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
                opacity: 0.64;
                font-size: 0.76em;
            }
            .dashboard-plus-dns-health-section {
                margin: 0 0.4em;
                border-top: 1px solid rgba(127, 127, 127, 0.2);
            }
            .dashboard-plus-dns-health-section-head {
                display: flex;
                align-items: center;
                justify-content: space-between;
                gap: 0.6em;
                padding: 0.55em 0 0.35em;
            }
            .dashboard-plus-dns-health-upstreams {
                display: grid;
                gap: 0.25em;
            }
            .dashboard-plus-dns-health-upstream {
                display: flex;
                align-items: center;
                gap: 0.55em;
                min-width: 0;
                padding: 0.32em 0;
            }
            .dashboard-plus-dns-health-upstream-dot {
                flex: none;
                width: 0.55em;
                height: 0.55em;
                border-radius: 50%;
                background: currentColor;
            }
            .dashboard-plus-dns-health-upstream-main {
                min-width: 0;
                flex: 1 1 auto;
            }
            .dashboard-plus-dns-health-upstream-name,
            .dashboard-plus-dns-health-upstream-server {
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
            }
            .dashboard-plus-dns-health-upstream-name {
                font-size: 0.88em;
            }
            .dashboard-plus-dns-health-upstream-server {
                opacity: 0.62;
                font-size: 0.76em;
            }
            .dashboard-plus-dns-health-badge {
                flex: none;
                font-size: 0.72em;
                white-space: nowrap;
            }
            .dashboard-plus-dns-health-empty {
                padding: 0.35em 0 0.6em;
                opacity: 0.65;
                font-size: 0.82em;
            }
            .dashboard-plus-dns-health-footer {
                display: flex;
                justify-content: space-between;
                gap: 0.7em;
                padding: 0.65em 0.4em 0.15em;
                opacity: 0.68;
                font-size: 0.76em;
            }
            .dashboard-plus-dns-health-footer a { flex: none; }
            .dashboard-plus-dns-health-error {
                padding: 0.6em 0.4em 0.15em;
                font-size: 0.8em;
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
            <div id="${this._elementId('root')}" class="dashboard-plus-dns-health">
                <div class="dashboard-plus-dns-health-header">
                    <div class="dashboard-plus-dns-health-identity">
                        <span id="${this._elementId('dot')}" class="dashboard-plus-dns-health-dot text-muted" aria-hidden="true"></span>
                        <div class="dashboard-plus-dns-health-label">
                            <div class="dashboard-plus-dns-health-eyebrow">${escapeHtml(this.translations.resolver)}</div>
                            <div id="${this._elementId('state')}" class="dashboard-plus-dns-health-state">${escapeHtml(this.translations.loading)}</div>
                        </div>
                    </div>
                    <div id="${this._elementId('mode')}" class="dashboard-plus-dns-health-mode">${escapeHtml(this.translations.loading)}</div>
                </div>
                <div id="${this._elementId('metrics')}" class="dashboard-plus-dns-health-metrics"></div>
                <div class="dashboard-plus-dns-health-section">
                    <div class="dashboard-plus-dns-health-section-head">
                        <span class="dashboard-plus-dns-health-section-label">${escapeHtml(this.translations.upstreams)}</span>
                        <span id="${this._elementId('upstream-count')}" class="dashboard-plus-dns-health-section-label"></span>
                    </div>
                    <div id="${this._elementId('upstreams')}" class="dashboard-plus-dns-health-upstreams"></div>
                </div>
                <div id="${this._elementId('error')}" class="dashboard-plus-dns-health-error" style="display: none;"></div>
                <div class="dashboard-plus-dns-health-footer">
                    <span id="${this._elementId('updated')}">${escapeHtml(this.translations.waiting)}</span>
                    <a href="/ui/unbound/overview" target="_blank" rel="noopener noreferrer">${escapeHtml(this.translations.open_unbound)}</a>
                </div>
            </div>
        `);
    }

    _asNumber(value) {
        const number = Number(value);
        return Number.isFinite(number) ? number : null;
    }

    _formatCount(value) {
        const number = this._asNumber(value);
        return number === null ? '—' : new Intl.NumberFormat().format(Math.round(number));
    }

    _formatRate(value) {
        const number = this._asNumber(value);
        return number === null ? '—' : `${number < 10 ? number.toFixed(1) : Math.round(number)}/s`;
    }

    _formatPercent(value) {
        const number = this._asNumber(value);
        return number === null ? '—' : `${number.toFixed(1)}%`;
    }

    _status() {
        const status = String(this.data.status?.status || '').toLowerCase();
        const enabled = this.data.settings?.unbound?.general?.enabled;
        if (String(enabled ?? '') === '0') {
            return {label: this.translations.disabled, state: 'muted'};
        }
        if (status === 'running') {
            return {label: this.translations.running, state: 'healthy'};
        }
        if (status === 'stopped') {
            return {label: this.translations.stopped, state: 'danger'};
        }
        return {label: this.translations.unavailable, state: 'warning'};
    }

    _mode() {
        const unbound = this.data.settings?.unbound || {};
        const forwarding = String(unbound.forwarding?.enabled ?? '') === '1';
        if (forwarding) {
            return this.translations.forwarding;
        }
        if (this._status().state === 'healthy') {
            return this.translations.recursive;
        }
        return this.translations.unavailable;
    }

    _metric(label, value, detail) {
        return `<div class="dashboard-plus-dns-health-metric">
            <div class="dashboard-plus-dns-health-metric-label">${escapeHtml(label)}</div>
            <div class="dashboard-plus-dns-health-metric-value">${escapeHtml(value)}</div>
            <div class="dashboard-plus-dns-health-metric-detail">${escapeHtml(detail)}</div>
        </div>`;
    }

    _stats() {
        const statsTotal = this.data.stats?.data?.total?.num || {};
        const totalQueries = this._asNumber(statsTotal.queries);
        const cacheHits = this._asNumber(statsTotal.cachehits);
        const cacheMisses = this._asNumber(statsTotal.cachemiss);
        const cacheTotal = cacheHits !== null && cacheMisses !== null ? cacheHits + cacheMisses : null;
        let rate = null;
        const now = Date.now();
        if (totalQueries !== null && this.previousSample) {
            const elapsed = (now - this.previousSample.at) / 1000;
            const delta = totalQueries - this.previousSample.queries;
            if (elapsed > 0 && delta >= 0) {
                rate = delta / elapsed;
            }
        }
        if (totalQueries !== null) {
            this.previousSample = {queries: totalQueries, at: now};
        }
        const blocked = this._asNumber(this.data.totals?.blocked?.total ?? this.data.totals?.blocked);
        const dnsTotal = this._asNumber(this.data.totals?.total);
        return {
            rate,
            totalQueries,
            cacheRate: cacheTotal ? cacheHits / cacheTotal * 100 : null,
            blocked,
            blockedRate: blocked !== null && dnsTotal ? blocked / dnsTotal * 100 : null,
            timeouts: this._asNumber(statsTotal.queries_timed_out)
        };
    }

    _render() {
        const status = this._status();
        const stats = this._stats();
        const dot = $(`#${this._elementId('dot')}`);
        dot.removeClass('text-success text-warning text-danger text-muted').addClass({
            healthy: 'text-success',
            warning: 'text-warning',
            danger: 'text-danger',
            muted: 'text-muted'
        }[status.state]);
        $(`#${this._elementId('state')}`).text(status.label);
        $(`#${this._elementId('mode')}`).text(this._mode());
        $(`#${this._elementId('metrics')}`).html([
            this._metric(this.translations.queries, this._formatRate(stats.rate),
                `${this._formatCount(stats.totalQueries)} ${this.translations.total}`),
            this._metric(this.translations.cache_hit, this._formatPercent(stats.cacheRate),
                this.translations.unbound_cache),
            this._metric(this.translations.blocked, this._formatCount(stats.blocked),
                stats.blockedRate === null ? this.translations.dnsbl :
                    `${this._formatPercent(stats.blockedRate)} ${this.translations.of_queries}`)
        ].join(''));

        const upstreams = this.data.upstreams || [];
        $(`#${this._elementId('upstream-count')}`).text(upstreams.length ? `${upstreams.length} ${this.translations.configured}` : '');
        $(`#${this._elementId('upstreams')}`).html(upstreams.length ? upstreams.map(upstream => `
            <div class="dashboard-plus-dns-health-upstream">
                <span class="dashboard-plus-dns-health-upstream-dot text-success" aria-hidden="true"></span>
                <div class="dashboard-plus-dns-health-upstream-main">
                    <div class="dashboard-plus-dns-health-upstream-name">${escapeHtml(upstream.description || upstream.server)}</div>
                    <div class="dashboard-plus-dns-health-upstream-server">${escapeHtml(upstream.server)}</div>
                </div>
                <span class="label label-success dashboard-plus-dns-health-badge">${escapeHtml(this.translations.configured)}</span>
            </div>`).join('') : `<div class="dashboard-plus-dns-health-empty">${escapeHtml(this.translations.no_upstreams)}</div>`);

        const displayError = this.error || this.totalsError;
        $(`#${this._elementId('error')}`).text(displayError).toggle(Boolean(displayError))
            .toggleClass('text-danger', Boolean(displayError));
        $(`#${this._elementId('updated')}`).text(displayError ? this.translations.fetch_failed :
            `${this.translations.updated} ${new Date().toLocaleTimeString()}`);
        this.config.callbacks?.updateGrid?.();
    }

    _fetchTotals() {
        return $.ajax({
            type: 'GET',
            url: '/api/unbound/overview/totals/10',
            dataType: 'json',
            contentType: 'application/json',
            timeout: 20000
        });
    }

    _refreshTotals() {
        if (this.totalsLoading) {
            return;
        }
        this.totalsLoading = true;
        this._fetchTotals().then(totals => {
            this.data.totals = totals;
            this.totalsError = '';
        }).catch(error => {
            this.totalsError = error?.statusText || this.translations.fetch_failed;
        }).finally(() => {
            this.totalsLoading = false;
            this._render();
        });
    }

    async _fetchData() {
        const responses = await Promise.allSettled([
            this.ajaxCall('/api/unbound/service/status'),
            this.ajaxCall('/api/unbound/diagnostics/stats'),
            this.ajaxCall('/api/unbound/settings/get'),
            this.ajaxCall('/api/unbound/settings/searchForward')
        ]);
        const value = (index, fallback) => responses[index].status === 'fulfilled' ? responses[index].value : fallback;
        if (responses.every(response => response.status === 'rejected')) {
            throw new Error(this.translations.fetch_failed);
        }
        this.data = {
            status: value(0, null),
            stats: value(1, null),
            totals: this.data.totals,
            settings: value(2, null),
            upstreams: value(3, {rows: []})?.rows || []
        };
        this._refreshTotals();
    }

    _applyConfig(config = {}) {
        this.currentConfig = config;
        this.refreshSeconds = Number(config.refresh_interval) || 30;
        this.tickTimeout = this.refreshSeconds;
    }

    async onMarkupRendered() {
        renderTitle(this);
        this._applyConfig(await this.getWidgetConfig());
        try {
            await this._fetchData();
            this.error = '';
        } catch (error) {
            this.error = error?.message || this.translations.fetch_failed;
        }
        this._render();
        this.fitToContent();
    }

    async onWidgetTick() {
        try {
            await this._fetchData();
            this.error = '';
        } catch (error) {
            this.error = error?.message || this.translations.fetch_failed;
        }
        this._render();
    }

    async getWidgetOptions() {
        return {
            refresh_interval: {
                title: this.translations.refresh_interval,
                type: 'select',
                id: this._elementId('refresh-interval'),
                options: [
                    {value: '15', label: this.translations.seconds_15},
                    {value: '30', label: this.translations.seconds_30},
                    {value: '60', label: this.translations.minute_1}
                ],
                default: '30'
            }
        };
    }

    async onWidgetOptionsChanged() {
        const config = await this.getWidgetConfig();
        this.setWidgetConfig(config);
        this._applyConfig(config);
    }
}
