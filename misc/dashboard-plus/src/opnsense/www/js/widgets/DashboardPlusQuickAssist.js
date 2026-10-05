/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

const {renderTitle, sharedRequest, DashboardPlusWidget} =
    await import(`./DashboardPlusCommon.js${new URL(import.meta.url).search}`);

const RECENT_FAILURE_MS = 60000;
const HISTORY_MS = 60000;
const STYLE_ID = 'dashboard-plus-quickassist-style';

export default class DashboardPlusQuickAssist extends DashboardPlusWidget(BaseWidget) {
    constructor(config) {
        super(config);
        this.tickTimeout = 2;
        this.previous = null;
        this.failureTimes = [];
        this.chart = null;
        this.rateSamples = [];
    }

    getGridOptions() {
        return {sizeToContent: 500};
    }

    _id(name) {
        return `${this.id}-${name}`;
    }

    _set(name, value) {
        const element = document.getElementById(this._id(name));
        if (element) {
            element.textContent = value;
        }
    }

    _compact(value) {
        return new Intl.NumberFormat(undefined, {notation: 'compact', maximumSignificantDigits: 3}).format(value || 0);
    }

    _mhz(hz) {
        return hz > 0 ? `${Math.round(hz / 1000000)} MHz` : '—';
    }

    _serviceList(devices) {
        const services = new Set();
        devices.forEach(device => String(device.services || '').split(/[;,]/).forEach(service => {
            if (service.trim()) {
                services.add(service.trim());
            }
        }));
        return [...services].join(' + ') || '—';
    }

    _snapshot(sample) {
        const devices = Array.isArray(sample?.devices) ? sample.devices : [];
        return {
            at: Number(sample?.sampled_at) * 1000 || Date.now(),
            responses: devices.reduce((total, device) => total + (Number(device.responses) || 0), 0),
            requests: devices.reduce((total, device) => total + (Number(device.requests) || 0), 0),
            devices: new Map(devices.map(device => [String(device.unit), device]))
        };
    }

    /* Counter resets and disappearing devices establish a new baseline, never a false spike. */
    _rates(sample) {
        const current = this._snapshot(sample);
        const previous = this.previous;
        this.previous = current;
        if (!previous || current.at <= previous.at || current.devices.size < previous.devices.size) {
            return {completed: 0, requests: 0, lag: 0, outstanding: Math.max(current.requests - current.responses, 0), reset: true};
        }
        for (const [unit, device] of current.devices) {
            const old = previous.devices.get(unit);
            if (!old || Number(device.responses) < Number(old.responses) || Number(device.requests) < Number(old.requests)) {
                return {completed: 0, requests: 0, lag: 0, outstanding: Math.max(current.requests - current.responses, 0), reset: true};
            }
        }
        const seconds = (current.at - previous.at) / 1000;
        const completed = Math.max((current.responses - previous.responses) / seconds, 0);
        const requests = Math.max((current.requests - previous.requests) / seconds, 0);
        return {
            completed, requests, lag: Math.max(requests - completed, 0),
            outstanding: Math.max(current.requests - current.responses, 0), reset: false
        };
    }

    _health(sample) {
        const devices = Array.isArray(sample?.devices) ? sample.devices : [];
        const now = Number(sample?.sampled_at) * 1000 || Date.now();
        const previous = this.previous?.devices || new Map();
        let fault = !sample?.available || devices.length === 0;
        let degraded = sample?.ocf?.present && !sample?.ocf?.enabled;
        if (previous.size > devices.length) {
            fault = true;
        }
        devices.forEach(device => {
            if ((device.state && String(device.state).toLowerCase() !== 'up') ||
                    (device.heartbeat !== null && device.heartbeat !== undefined && Number(device.heartbeat) === 0)) {
                fault = true;
            }
            const old = previous.get(String(device.unit));
            if (old && Number(device.heartbeat_failed) > Number(old.heartbeat_failed)) {
                this.failureTimes.push(now);
            }
        });
        this.failureTimes = this.failureTimes.filter(time => now - time <= RECENT_FAILURE_MS);
        if (this.failureTimes.length >= 3) {
            fault = true;
        } else if (this.failureTimes.length) {
            degraded = true;
        }
        if (fault) {
            return {key: sample?.available ? 'fault' : 'unavailable', className: 'danger'};
        }
        if (degraded) {
            return {key: 'degraded', className: 'warning'};
        }
        return {key: 'active', className: 'success'};
    }

    _addStyle() {
        const css = `
            .dashboard-plus-quickassist {
                width: 95%;
                margin: 0.25em auto;
                box-sizing: border-box;
                color: inherit;
            }
            .dashboard-plus-quickassist-header {
                display: flex;
                align-items: center;
                justify-content: space-between;
                gap: 0.8em;
                padding: 0.15em 0.4em 0.7em;
                border-bottom: 1px solid rgba(217, 79, 0, 0.28);
            }
            .dashboard-plus-quickassist-identity {
                display: flex;
                align-items: center;
                min-width: 0;
                gap: 0.65em;
            }
            .dashboard-plus-quickassist-icon {
                flex: none;
                width: 1.9em;
                text-align: center;
                font-size: 1.35em;
                opacity: 0.72;
            }
            .dashboard-plus-quickassist-label { min-width: 0; text-align: left; }
            .dashboard-plus-quickassist-eyebrow,
            .dashboard-plus-quickassist-metric-label,
            .dashboard-plus-quickassist-subtitle {
                color: currentColor;
                opacity: 0.68;
                font-size: 0.78em;
                letter-spacing: 0.02em;
            }
            .dashboard-plus-quickassist-model {
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
                font-size: 1.05em;
                font-weight: 600;
            }
            .dashboard-plus-quickassist-status {
                flex: none;
                display: flex;
                align-items: center;
                gap: 0.42em;
                font-size: 0.82em;
                font-weight: 600;
                text-transform: uppercase;
                white-space: nowrap;
            }
            .dashboard-plus-quickassist-status-dot {
                width: 0.72em;
                height: 0.72em;
                border-radius: 50%;
                background: currentColor;
                opacity: 0.8;
            }
            .dashboard-plus-quickassist-section {
                margin: 0.7em 0.4em 0;
                border: 1px solid rgba(127, 127, 127, 0.24);
                border-radius: 3px;
            }
            .dashboard-plus-quickassist-section-head {
                display: flex;
                align-items: flex-start;
                justify-content: space-between;
                gap: 0.8em;
                padding: 0.65em 0.7em 0.4em;
            }
            .dashboard-plus-quickassist-section-title {
                font-size: 0.9em;
                font-weight: 600;
            }
            .dashboard-plus-quickassist-rate {
                flex: none;
                align-self: center;
                font-variant-numeric: tabular-nums;
                white-space: nowrap;
            }
            .dashboard-plus-quickassist-rate strong {
                font-size: 1.35em;
                font-weight: 600;
            }
            .dashboard-plus-quickassist-chart {
                height: 10em;
                position: relative;
                padding: 0 0.45em 0.55em;
            }
            .dashboard-plus-quickassist-chart canvas { width: 100% !important; height: 100% !important; }
            .dashboard-plus-quickassist-progress.progress {
                height: 0.75em;
                margin: 0 0.7em;
                overflow: hidden;
                background: rgba(127, 127, 127, 0.2);
                box-shadow: none;
            }
            .dashboard-plus-quickassist-progress .progress-bar { transition: width 0.2s linear; }
            .dashboard-plus-quickassist-pipeline-values {
                display: grid;
                grid-template-columns: repeat(3, minmax(0, 1fr));
                gap: 0.5em;
                padding: 0.65em 0.7em 0.7em;
                font-size: 0.8em;
            }
            .dashboard-plus-quickassist-pipeline-values > :nth-child(2) { text-align: center; }
            .dashboard-plus-quickassist-pipeline-values > :last-child { text-align: right; }
            .dashboard-plus-quickassist-pipeline-values strong { font-variant-numeric: tabular-nums; }
            .dashboard-plus-quickassist-devices {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(8.5em, 1fr));
                gap: 0.35em 0.7em;
                padding: 0 0.7em 0.7em;
            }
            .dashboard-plus-quickassist-device {
                display: grid;
                grid-template-columns: 1.4em minmax(0, 1fr);
                align-items: start;
                gap: 0.45em;
                min-width: 0;
                padding: 0.35em 0;
            }
            .dashboard-plus-quickassist-device-icon { opacity: 0.68; text-align: center; }
            .dashboard-plus-quickassist-metric-value {
                display: block;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
                font-size: 1em;
                font-weight: 600;
                font-variant-numeric: tabular-nums;
            }
            .dashboard-plus-quickassist-metric-detail {
                display: block;
                min-height: 1.2em;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
                opacity: 0.64;
                font-size: 0.76em;
            }
            .dashboard-plus-quickassist-ocf-dot {
                display: inline-block;
                width: 0.62em;
                height: 0.62em;
                margin-right: 0.35em;
                border-radius: 50%;
                background: currentColor;
                vertical-align: 0.03em;
            }
            .dashboard-plus-quickassist-error {
                padding: 0.55em 0.4em 0.05em;
                font-size: 0.8em;
            }
            @media (max-width: 25em) {
                .dashboard-plus-quickassist-pipeline-values { grid-template-columns: 1fr; }
                .dashboard-plus-quickassist-pipeline-values > :nth-child(2),
                .dashboard-plus-quickassist-pipeline-values > :last-child { text-align: left; }
            }
        `;
        const existing = document.getElementById(STYLE_ID);
        if (existing) {
            $(existing).text(css);
        } else {
            $('<style>').attr('id', STYLE_ID).text(css).appendTo('head');
        }
    }

    _markup() {
        return `<div id="${this._id('root')}" class="dashboard-plus-quickassist">
            <div class="dashboard-plus-quickassist-header">
                <div class="dashboard-plus-quickassist-identity">
                    <i class="fa fa-fw fa-microchip dashboard-plus-quickassist-icon" aria-hidden="true"></i>
                    <div class="dashboard-plus-quickassist-label"><div class="dashboard-plus-quickassist-eyebrow">${this.translations.dashboard_title}</div><div id="${this._id('model')}" class="dashboard-plus-quickassist-model">—</div></div>
                </div>
                <div id="${this._id('status')}" class="dashboard-plus-quickassist-status text-muted"><span class="dashboard-plus-quickassist-status-dot" aria-hidden="true"></span><span>—</span></div>
            </div>
            <section class="dashboard-plus-quickassist-section">
                <div class="dashboard-plus-quickassist-section-head"><div><div class="dashboard-plus-quickassist-section-title">${this.translations.qat_activity}</div><div class="dashboard-plus-quickassist-subtitle">${this.translations.requests_per_second}</div></div><div class="dashboard-plus-quickassist-rate"><strong id="${this._id('rate')}">—</strong> req/s</div></div>
                <div class="dashboard-plus-quickassist-chart"><canvas id="${this._id('chart')}"></canvas></div>
            </section>
            <section class="dashboard-plus-quickassist-section">
                <div class="dashboard-plus-quickassist-section-head"><div class="dashboard-plus-quickassist-section-title">${this.translations.qat_pipeline} <i class="fa fa-fw fa-info-circle text-muted" title="${this.translations.requests_per_second}" aria-hidden="true"></i></div></div>
                <div class="progress dashboard-plus-quickassist-progress"><div id="${this._id('completed')}" class="progress-bar progress-bar-success"></div><div id="${this._id('lag')}" class="progress-bar progress-bar-warning"></div></div>
                <div class="dashboard-plus-quickassist-pipeline-values"><span><strong id="${this._id('completed-rate')}">—</strong> ${this.translations.completed_requests}</span><span><strong id="${this._id('lag-rate')}">—</strong> ${this.translations.lag_requests}</span><span>${this.translations.outstanding} <strong id="${this._id('outstanding')}">—</strong></span></div>
            </section>
            <section class="dashboard-plus-quickassist-section">
                <div class="dashboard-plus-quickassist-section-head"><div class="dashboard-plus-quickassist-section-title">${this.translations.device_information}</div></div>
                <div class="dashboard-plus-quickassist-devices">
                    <div class="dashboard-plus-quickassist-device"><i class="fa fa-fw fa-microchip dashboard-plus-quickassist-device-icon" aria-hidden="true"></i><div><div class="dashboard-plus-quickassist-metric-label">${this.translations.qat_devices}</div><strong id="${this._id('devices')}" class="dashboard-plus-quickassist-metric-value">—</strong><span class="dashboard-plus-quickassist-metric-detail"></span></div></div>
                    <div class="dashboard-plus-quickassist-device"><i class="fa fa-fw fa-cogs dashboard-plus-quickassist-device-icon" aria-hidden="true"></i><div><div class="dashboard-plus-quickassist-metric-label">${this.translations.acceleration_engines}</div><strong id="${this._id('engines')}" class="dashboard-plus-quickassist-metric-value">—</strong><span id="${this._id('engines-detail')}" class="dashboard-plus-quickassist-metric-detail"></span></div></div>
                    <div class="dashboard-plus-quickassist-device"><i class="fa fa-fw fa-tachometer dashboard-plus-quickassist-device-icon" aria-hidden="true"></i><div><div class="dashboard-plus-quickassist-metric-label">${this.translations.clock}</div><strong id="${this._id('clock')}" class="dashboard-plus-quickassist-metric-value">—</strong><span class="dashboard-plus-quickassist-metric-detail"></span></div></div>
                    <div class="dashboard-plus-quickassist-device"><i class="fa fa-fw fa-list dashboard-plus-quickassist-device-icon" aria-hidden="true"></i><div><div class="dashboard-plus-quickassist-metric-label">${this.translations.services}</div><strong id="${this._id('services')}" class="dashboard-plus-quickassist-metric-value">—</strong><span class="dashboard-plus-quickassist-metric-detail"></span></div></div>
                    <div class="dashboard-plus-quickassist-device"><i class="fa fa-fw fa-database dashboard-plus-quickassist-device-icon" aria-hidden="true"></i><div><div class="dashboard-plus-quickassist-metric-label">${this.translations.ocf}</div><strong id="${this._id('ocf')}" class="dashboard-plus-quickassist-metric-value">—</strong><span class="dashboard-plus-quickassist-metric-detail"></span></div></div>
                </div>
            </section>
            <div id="${this._id('error')}" class="dashboard-plus-quickassist-error text-danger"></div>
        </div>`;
    }

    getMarkup() {
        this._addStyle();
        return $(this._markup());
    }

    _render(sample, rates, health, error = '') {
        const devices = Array.isArray(sample?.devices) ? sample.devices : [];
        this._set('model', devices[0]?.description || 'Intel QuickAssist');
        const status = document.getElementById(this._id('status'));
        if (status) {
            status.className = `dashboard-plus-quickassist-status text-${health.className}`;
            status.querySelector('span:last-child').textContent = this.translations[health.key];
        }
        this._set('rate', this._compact(rates.completed));
        this._set('completed-rate', this._compact(rates.completed));
        this._set('lag-rate', this._compact(rates.lag));
        this._set('outstanding', this._compact(rates.outstanding));
        const totalRate = rates.completed + rates.lag;
        const completed = totalRate ? (rates.completed / totalRate) * 100 : 100;
        const lag = totalRate ? 100 - completed : 0;
        const completedBar = document.getElementById(this._id('completed'));
        const lagBar = document.getElementById(this._id('lag'));
        if (completedBar) completedBar.style.width = `${completed}%`;
        if (lagBar) lagBar.style.width = `${lag}%`;
        const engines = devices.reduce((total, device) => total + (Number(device.ae_count) || 0), 0);
        const counts = new Set(devices.map(device => Number(device.ae_count) || 0));
        this._set('devices', String(devices.length));
        this._set('engines', `${engines} total`);
        this._set('engines-detail', counts.size === 1 && devices.length ? `${engines / devices.length} AE / device` : '');
        this._set('clock', this._mhz(Math.max(...devices.map(device => Number(device.frequency_hz) || 0), 0)));
        this._set('services', this._serviceList(devices));
        this._set('ocf', sample?.ocf?.present ? (sample.ocf.enabled ? this.translations.enabled : this.translations.disabled) : '—');
        const errorElement = document.getElementById(this._id('error'));
        if (errorElement) errorElement.textContent = error;
    }

    _recordRate(rates, at) {
        const now = at || Date.now();
        this.rateSamples.push({x: now, y: rates.completed});
        this.rateSamples = this.rateSamples.filter(sample => sample.x >= now - HISTORY_MS);
    }

    _renderChart() {
        const canvas = document.getElementById(this._id('chart'));
        if (!canvas || typeof Chart === 'undefined') return;
        if (this.chart) {
            this.chart.data.datasets[0].data = this.rateSamples;
            this.chart.update('none');
            return;
        }
        this.chart = new Chart(canvas.getContext('2d'), {
            type: 'line',
            data: {datasets: [{label: this.translations.requests_per_second, data: this.rateSamples,
                borderColor: '#2ca02c', backgroundColor: 'rgba(44, 160, 44, 0.28)', fill: true,
                pointRadius: 0, borderWidth: 2}]},
            options: {
                responsive: true, maintainAspectRatio: false, normalized: true,
                elements: {line: {fill: true, cubicInterpolationMode: 'monotone', clip: 0}},
                plugins: {colorschemes: false, legend: {display: false}, streaming: {frameRate: 30, ttl: HISTORY_MS + 10000},
                    tooltip: {callbacks: {label: context => `${this.translations.requests_per_second}: ${this._compact(context.raw.y)} req/s`}}},
                scales: {
                    y: {beginAtZero: true, ticks: {maxTicksLimit: 5, callback: value => `${this._compact(value)}/s`}},
                    x: {type: 'realtime', time: {tooltipFormat: 'HH:mm:ss', unit: 'second', displayFormats: {second: 'HH:mm:ss'}},
                        realtime: {duration: HISTORY_MS, delay: 2000}, ticks: {maxRotation: 0, autoSkip: true, maxTicksLimit: 5}}
                }
            }
        });
    }

    async _sample() {
        const result = await sharedRequest(this, '/api/dashboardplus/system/qat');
        const health = this._health(result);
        const rates = this._rates(result);
        this._recordRate(rates, Number(result.sampled_at) * 1000 || Date.now());
        this._renderChart();
        this._render(result, rates, health);
    }

    async onMarkupRendered() {
        renderTitle(this);
        try {
            await this._sample();
        } catch (error) {
            this._render({available: false, devices: [], ocf: {}}, {completed: 0, lag: 0, outstanding: 0}, {key: 'unavailable', className: 'danger'}, this.translations.fetch_failed);
        }
        this.fitToContent();
    }

    async onWidgetTick() {
        try {
            await this._sample();
        } catch (error) {
            const health = {key: 'unavailable', className: 'danger'};
            this._render({available: false, devices: [], ocf: {}}, {completed: 0, lag: 0, outstanding: 0}, health, this.translations.fetch_failed);
        }
    }

    onWidgetClose() {
        this.chart?.destroy();
        this.chart = null;
    }
}
