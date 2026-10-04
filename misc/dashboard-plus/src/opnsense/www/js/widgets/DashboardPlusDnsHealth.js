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
        this.data = {status: null, stats: null, totals: null, settings: null, upstreams: [], recent: {queries: [], types: {}}};
        this.previousSample = null;
        this.error = '';
        this.totalsError = '';
        this.totalsLoading = false;
        this.loading = true;
        this.refreshSeconds = 30;
        this.tickTimeout = 30;
        this.queryChart = null;
        this.queryRateChart = null;
        this.queryRateSamples = [];
        this.queryRateTimer = null;
        this.queryRatePolling = false;
        this.recentRows = 5;
    }

    getGridOptions() {
        return {sizeToContent: 620, minW: 4, minH: 6};
    }

    _elementId(name) {
        return `${this.id}-dns-health-${name}`;
    }

    _addStyle() {
        const css = `
            .dashboard-plus-dns-health {
                width: 95%;
                margin: 0.25em auto;
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
                width: 1em;
                height: 1em;
                margin: 0 0.25em;
                background: currentColor;
                opacity: 0.8;
            }
            .dashboard-plus-dns-health-label {
                min-width: 0;
                text-align: left;
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
                text-align: left;
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
            .dashboard-plus-dns-health-metric-detail + .dashboard-plus-dns-health-metric-detail {
                margin-top: 0.08em;
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
                padding: 0 0.65em 0.65em;
                max-height: 10em;
                overflow-y: auto;
            }
            .dashboard-plus-dns-health-upstream {
                display: grid;
                grid-template-columns: auto minmax(0, 1fr) auto;
                align-items: center;
                column-gap: 0.65em;
                min-width: 0;
                padding: 0.32em 0;
            }
            .dashboard-plus-dns-health-upstream-icon {
                text-align: center;
                align-self: center;
                line-height: 1;
                opacity: 0.72;
            }
            .dashboard-plus-dns-health-upstream-name {
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
                font-size: 0.88em;
            }
            .dashboard-plus-dns-health-upstream-server {
                text-align: right;
                opacity: 0.62;
                font-size: 0.76em;
                font-variant-numeric: tabular-nums;
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
            .dashboard-plus-dns-health-panels {
                display: grid;
                grid-template-columns: repeat(2, minmax(0, 1fr));
                gap: 0.7em;
                margin: 0 0.4em;
            }
            .dashboard-plus-dns-health-panel {
                display: flex;
                flex-direction: column;
                min-width: 0;
                border: 1px solid rgba(127, 127, 127, 0.24);
                border-radius: 3px;
                padding: 0;
            }
            .dashboard-plus-dns-health-panel-head {
                margin: 0;
                padding: 0.65em 0.65em 0.45em;
                text-align: left;
                font-size: 0.86em;
                font-weight: 600;
            }
            .dashboard-plus-dns-health-types {
                display: grid;
                grid-template-columns: minmax(7em, 1fr) minmax(7em, 1fr);
                align-items: center;
                gap: 0.5em;
                flex: 1;
                padding: 0 1em 0.65em;
                box-sizing: border-box;
            }
            .dashboard-plus-dns-health-types-chart {
                width: min(100%, 10em);
                aspect-ratio: 1;
                justify-self: center;
            }
            .dashboard-plus-dns-health-types canvas {
                width: 100% !important;
                height: 100% !important;
            }
            .dashboard-plus-dns-health-rate-chart {
                height: 10em;
                position: relative;
                padding: 0 0.45em 0.55em;
            }
            .dashboard-plus-dns-health-rate-chart canvas {
                width: 100% !important;
                height: 100% !important;
            }
            .dashboard-plus-dns-health-rate-empty {
                display: flex;
                align-items: center;
                justify-content: center;
                height: 100%;
                opacity: 0.65;
                font-size: 0.82em;
            }
            .dashboard-plus-dns-health-forward-zones {
                margin: 0.7em 0.4em 0;
            }
            .dashboard-plus-dns-health-type-legend {
                display: grid;
                gap: 0.25em;
                min-width: 0;
                font-size: 0.78em;
            }
            .dashboard-plus-dns-health-type-row {
                display: grid;
                grid-template-columns: 0.8em minmax(0, 1fr) auto;
                align-items: center;
                gap: 0.35em;
            }
            .dashboard-plus-dns-health-type-color {
                width: 0.75em;
                height: 0.75em;
                border-radius: 50%;
            }
            .dashboard-plus-dns-health-recent {
                margin: 0.7em 0.4em 0;
            }
            .dashboard-plus-dns-health-recent-list {
                max-height: var(--dashboard-plus-dns-health-recent-height, 12em);
                overflow-y: auto;
                padding: 0 0.65em 0.65em;
            }
            .dashboard-plus-dns-health-recent-row {
                display: grid;
                grid-template-columns: 1.35em minmax(0, 1fr) auto auto;
                align-items: center;
                gap: 0.7em;
                padding: 0.32em 0;
                border-top: 1px solid rgba(127, 127, 127, 0.15);
                font-size: 0.82em;
            }
            .dashboard-plus-dns-health-recent-domain {
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
                text-align: left;
            }
            .dashboard-plus-dns-health-recent-meta {
                white-space: nowrap;
                opacity: 0.7;
                font-variant-numeric: tabular-nums;
            }
            .dashboard-plus-dns-health-recent-icon {
                text-align: center;
                opacity: 0.75;
            }
            @media (max-width: 28em) {
                .dashboard-plus-dns-health-panels { grid-template-columns: 1fr; }
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
                        <span id="${this._elementId('dot')}" class="dashboard-plus-dot dashboard-plus-dns-health-dot text-muted" aria-hidden="true"></span>
                        <div class="dashboard-plus-dns-health-label">
                            <div class="dashboard-plus-dns-health-eyebrow">${escapeHtml(this.translations.resolver)}</div>
                            <div id="${this._elementId('state')}" class="dashboard-plus-dns-health-state">${escapeHtml(this.translations.loading)}</div>
                        </div>
                    </div>
                    <div id="${this._elementId('mode')}" class="dashboard-plus-dns-health-mode">${escapeHtml(this.translations.loading)}</div>
                </div>
                <div id="${this._elementId('metrics')}" class="dashboard-plus-dns-health-metrics"></div>
                <div class="dashboard-plus-dns-health-panels">
                    <section class="dashboard-plus-dns-health-panel">
                        <div class="dashboard-plus-dns-health-panel-head">${escapeHtml(this.translations.query_types)}</div>
                        <div class="dashboard-plus-dns-health-types">
                            <div class="dashboard-plus-dns-health-types-chart"><canvas id="${this._elementId('types-chart')}"></canvas></div>
                            <div id="${this._elementId('types-legend')}" class="dashboard-plus-dns-health-type-legend"></div>
                        </div>
                    </section>
                    <section class="dashboard-plus-dns-health-panel">
                        <div class="dashboard-plus-dns-health-panel-head">${escapeHtml(this.translations.requests_per_second)}</div>
                        <div class="dashboard-plus-dns-health-rate-chart">
                            <canvas id="${this._elementId('rate-chart')}"></canvas>
                            <div id="${this._elementId('rate-empty')}" class="dashboard-plus-dns-health-rate-empty">${escapeHtml(this.translations.waiting)}</div>
                        </div>
                    </section>
                </div>
                <section class="dashboard-plus-dns-health-forward-zones dashboard-plus-dns-health-panel">
                    <div class="dashboard-plus-dns-health-panel-head">${escapeHtml(this.translations.upstreams)}</div>
                    <div id="${this._elementId('upstreams')}" class="dashboard-plus-dns-health-upstreams"></div>
                </section>
                <section class="dashboard-plus-dns-health-recent dashboard-plus-dns-health-panel">
                    <div class="dashboard-plus-dns-health-panel-head">${escapeHtml(this.translations.recent_external_queries)}</div>
                    <div id="${this._elementId('recent')}" class="dashboard-plus-dns-health-recent-list"></div>
                </section>
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

    _formatLookup(value) {
        const milliseconds = this._asNumber(value);
        return milliseconds === null ? '—' : `${Math.round(milliseconds)} ms`;
    }

    _formatAge(value) {
        const seconds = this._asNumber(value);
        if (seconds === null) {
            return '';
        }
        if (seconds < 60) {
            return `${Math.round(seconds)}s`;
        }
        if (seconds < 3600) {
            return `${Math.floor(seconds / 60)}m`;
        }
        return `${Math.floor(seconds / 3600)}h`;
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
            return this.translations.local_forwarding;
        }
        if (this._status().state === 'healthy') {
            return this.translations.local_recursive;
        }
        return this.translations.unavailable;
    }

    _metric(label, value, detail, secondary = '') {
        return `<div class="dashboard-plus-dns-health-metric">
            <div class="dashboard-plus-dns-health-metric-label">${escapeHtml(label)}</div>
            <div class="dashboard-plus-dns-health-metric-value">${escapeHtml(value)}</div>
            <div class="dashboard-plus-dns-health-metric-detail">${escapeHtml(detail)}</div>
            ${secondary ? `<div class="dashboard-plus-dns-health-metric-detail">${escapeHtml(secondary)}</div>` : ''}
        </div>`;
    }

    _stats() {
        const statsTotal = this.data.stats?.data?.total?.num || {};
        const totalQueries = this._asNumber(statsTotal.queries);
        const cacheHits = this._asNumber(statsTotal.cachehits);
        const cacheMisses = this._asNumber(statsTotal.cachemiss);
        const cacheTotal = cacheHits !== null && cacheMisses !== null ? cacheHits + cacheMisses : null;
        const blocked = this._asNumber(this.data.totals?.blocked?.total ?? this.data.totals?.blocked);
        const dnsTotal = this._asNumber(this.data.totals?.total);
        const recursiveSeconds = this._asNumber(this.data.stats?.data?.total?.recursion?.time?.avg);
        return {
            rate: this.queryRateSamples.at(-1)?.ratePerSecond ?? null,
            totalQueries,
            cacheHits,
            cacheMisses,
            cacheRate: cacheTotal ? cacheHits / cacheTotal * 100 : null,
            blocked,
            blockedRate: blocked !== null && dnsTotal ? blocked / dnsTotal * 100 : null,
            resolved: this._asNumber(this.data.totals?.resolved?.total),
            local: this._asNumber(this.data.totals?.local?.total),
            lookup: recursiveSeconds === null ? null : recursiveSeconds * 1000
        };
    }

    _recordQueryRate(totalQueries) {
        const now = Date.now();
        if (totalQueries !== null && this.previousSample) {
            const elapsed = (now - this.previousSample.at) / 1000;
            const delta = totalQueries - this.previousSample.queries;
            if (elapsed > 0 && delta >= 0) {
                this.queryRateSamples.push({at: now, ratePerSecond: delta / elapsed});
            }
        }
        this.queryRateSamples = this.queryRateSamples.filter(sample => sample.at >= now - 10 * 60 * 1000);
        if (totalQueries !== null) {
            this.previousSample = {queries: totalQueries, at: now};
        }
    }

    _renderQueryRate() {
        const chart = typeof Chart === 'undefined' ? null : Chart;
        const canvas = document.getElementById(this._elementId('rate-chart'));
        const $empty = $(`#${this._elementId('rate-empty')}`);
        $empty.toggle(!this.queryRateSamples.length);
        $(canvas).toggle(Boolean(this.queryRateSamples.length));
        if (!canvas || !chart || !this.queryRateSamples.length) {
            return;
        }
        const color = '#2ca02c';
        const labels = this.queryRateSamples.map(sample => new Date(sample.at).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit', second: '2-digit'}));
        const data = this.queryRateSamples.map(sample => sample.ratePerSecond);
        if (this.queryRateChart) {
            this.queryRateChart.data.labels = labels;
            this.queryRateChart.data.datasets[0].data = data;
            this.queryRateChart.update('none');
            return;
        }
        this.queryRateChart = new chart(canvas.getContext('2d'), {
            type: 'line',
            data: {
                labels,
                datasets: [{
                    label: this.translations.requests_per_second,
                    data,
                    borderColor: color,
                    backgroundColor: 'rgba(44, 160, 44, 0.16)',
                    fill: true,
                    tension: 0.22,
                    pointRadius: 0,
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {colorschemes: false, legend: {display: false}},
                scales: {
                    y: {beginAtZero: true, ticks: {maxTicksLimit: 5, callback: value => this._formatRate(value)}},
                    x: {ticks: {maxRotation: 0, autoSkip: true, maxTicksLimit: 5}}
                }
            }
        });
    }

    _renderTypes() {
        const allTypes = this.data.recent?.types && typeof this.data.recent.types === 'object' ? this.data.recent.types : {};
        const primary = ['A', 'AAAA', 'PTR', 'TXT', 'MX'];
        const entries = primary.filter(type => allTypes[type]).map(type => [type, Number(allTypes[type])]);
        const other = Object.entries(allTypes)
            .filter(([type]) => !primary.includes(type))
            .reduce((total, [, count]) => total + Number(count), 0);
        if (other) {
            entries.push(['Other', other]);
        }
        const chart = typeof Chart === 'undefined' ? null : Chart;
        // Use the same Tableau palette as the Interface Statistics and Firewall charts.
        const palette = chart?.colorschemes?.tableau?.Tableau20 ?? ['#4e79a7', '#a0cbe8', '#f28e2b', '#ffbe7d', '#59a14f', '#8cd17d'];
        const total = entries.reduce((sum, [, count]) => sum + count, 0);
        const $legend = $(`#${this._elementId('types-legend')}`);
        $legend.html(entries.length ? entries.map(([type, count], index) => `
            <div class="dashboard-plus-dns-health-type-row">
                <span class="dashboard-plus-dns-health-type-color" style="background: ${palette[index % palette.length]};"></span>
                <span class="dashboard-plus-ellipsis">${escapeHtml(type)}</span>
                <span>${this._formatPercent(total ? count / total * 100 : null)}</span>
            </div>`).join('') : `<div class="dashboard-plus-dns-health-empty">${escapeHtml(this.translations.waiting)}</div>`);

        this.queryChart?.destroy();
        this.queryChart = null;
        const canvas = document.getElementById(this._elementId('types-chart'));
        if (!canvas || !entries.length || !chart) {
            return;
        }
        this.queryChart = new chart(canvas.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: entries.map(([type]) => type),
                datasets: [{data: entries.map(([, count]) => count), backgroundColor: palette, borderColor: chart.defaults.backgroundColor}]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '62%',
                plugins: {legend: {display: false}, colorschemes: false}
            }
        });
    }

    _renderRecent() {
        const $recent = $(`#${this._elementId('recent')}`);
        const queries = Array.isArray(this.data.recent?.queries) ? this.data.recent.queries : [];
        $recent.css('--dashboard-plus-dns-health-recent-height', `${this.recentRows * 2.1}em`);
        $recent.html(this.loading ? `<div class="dashboard-plus-dns-health-empty">${escapeHtml(this.translations.waiting)}</div>` : queries.length ? queries.map(query => {
            const lookup = this._asNumber(query.lookup_ms);
            const details = [lookup === null ? '' : this._formatLookup(lookup), this._formatAge(query.age)].filter(Boolean).join(' · ') || '—';
            const isError = ['SERVFAIL', 'REFUSED'].includes(query.rcode);
            return `
            <div class="dashboard-plus-dns-health-recent-row">
                <i class="fa fa-fw fa-${isError ? 'times-circle-o text-danger' : 'globe text-primary'} dashboard-plus-dns-health-recent-icon" title="${escapeHtml(query.rcode || query.type)}" aria-hidden="true"></i>
                <span class="dashboard-plus-dns-health-recent-domain" title="${escapeHtml(query.domain)}">${escapeHtml(query.domain)}</span>
                <span class="dashboard-plus-dns-health-recent-meta">${escapeHtml(query.type)}</span>
                <span class="dashboard-plus-dns-health-recent-meta">${escapeHtml(details)}</span>
            </div>`;
        }).join('') : `<div class="dashboard-plus-dns-health-empty">${escapeHtml(this.translations.no_recent_queries)}</div>`);
    }

    _renderMetrics(stats = this._stats()) {
        $(`#${this._elementId('metrics')}`).html([
            this._metric(this.translations.queries, this._formatRate(stats.rate),
                `${this._formatCount(stats.totalQueries)} ${this.translations.total}`,
                `${this._formatCount(stats.resolved)} ${this.translations.resolved.toLowerCase()} · ${this._formatCount(stats.local)} ${this.translations.local.toLowerCase()}`),
            this._metric(this.translations.cache_hit, this._formatPercent(stats.cacheRate),
                `${this._formatCount(stats.cacheHits)} ${this.translations.cached.toLowerCase()}`,
                `${this._formatCount(stats.cacheMisses)} ${this.translations.cache_misses.toLowerCase()}`),
            this._metric(this.translations.blocked, this._formatCount(stats.blocked),
                stats.blockedRate === null ? this.translations.dnsbl :
                    `${this._formatPercent(stats.blockedRate)} ${this.translations.of_queries}`,
                `${this.translations.avg_recursive_lookup} ${this._formatLookup(stats.lookup)}`)
        ].join(''));
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
        this._renderMetrics(stats);

        const upstreams = Array.isArray(this.data.upstreams) ? this.data.upstreams : [];
        $(`#${this._elementId('upstreams')}`).html(this.loading ? `<div class="dashboard-plus-dns-health-empty">${escapeHtml(this.translations.waiting)}</div>` : upstreams.length ? upstreams.map(upstream => `
            <div class="dashboard-plus-dns-health-upstream">
                <i class="fa fa-fw fa-server dashboard-plus-dns-health-upstream-icon" title="${escapeHtml(this.translations.upstreams)}" aria-hidden="true"></i>
                <div class="dashboard-plus-dns-health-upstream-name" title="${escapeHtml(upstream.domain || upstream.description || upstream.server)}">${escapeHtml(upstream.domain || upstream.description || upstream.server)}</div>
                <div class="dashboard-plus-dns-health-upstream-server">${escapeHtml(upstream.server)}</div>
            </div>`).join('') : `<div class="dashboard-plus-dns-health-empty">${escapeHtml(this.translations.no_upstreams)}</div>`);
        this._renderTypes();
        this._renderQueryRate();
        this._renderRecent();

        const displayError = this.loading ? '' : this.error || this.totalsError;
        $(`#${this._elementId('error')}`).text(displayError).toggle(Boolean(displayError))
            .toggleClass('text-danger', Boolean(displayError));
        $(`#${this._elementId('updated')}`).text(this.loading ? this.translations.waiting : displayError ? this.translations.fetch_failed :
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

    async _pollQueryRate() {
        if (this.loading || this.queryRatePolling) {
            return;
        }
        this.queryRatePolling = true;
        try {
            this.data.stats = await this.ajaxCall('/api/unbound/diagnostics/stats');
            this._recordQueryRate(this._asNumber(this.data.stats?.data?.total?.num?.queries));
            this._renderMetrics();
            this._renderQueryRate();
        } finally {
            this.queryRatePolling = false;
        }
    }

    _startQueryRatePolling() {
        clearInterval(this.queryRateTimer);
        this.queryRateTimer = setInterval(() => {
            this._pollQueryRate().catch(() => {});
        }, 1000);
    }

    async _fetchData() {
        const responses = await Promise.allSettled([
            this.ajaxCall('/api/unbound/service/status'),
            this.ajaxCall('/api/unbound/diagnostics/stats'),
            this.ajaxCall('/api/unbound/settings/get'),
            this.ajaxCall('/api/unbound/settings/searchForward'),
            this.ajaxCall('/api/dashboardplus/dns/recent')
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
            upstreams: value(3, {rows: []})?.rows || [],
            recent: value(4, {queries: [], types: {}})
        };
        this._recordQueryRate(this._asNumber(this.data.stats?.data?.total?.num?.queries));
        this.loading = false;
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
            this.loading = false;
            this.error = error?.message || this.translations.fetch_failed;
        }
        this._render();
        this.fitToContent();
        this._startQueryRatePolling();
    }

    async onWidgetTick() {
        try {
            await this._fetchData();
            this.error = '';
        } catch (error) {
            this.loading = false;
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

    onWidgetResize(elem, width, height) {
        const layoutChanged = super.onWidgetResize(elem, width, height);
        this.queryChart?.resize();
        this.queryRateChart?.resize();
        return layoutChanged;
    }

    onWidgetClose() {
        this.queryChart?.destroy();
        this.queryRateChart?.destroy();
        clearInterval(this.queryRateTimer);
        this.queryRateTimer = null;
        super.onWidgetClose();
    }
}
