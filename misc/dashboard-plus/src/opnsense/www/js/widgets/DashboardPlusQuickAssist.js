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

const {renderTitle, ensureStyle, sharedRequest, DashboardPlusWidget} =
    await import(`./DashboardPlusCommon.js${new URL(import.meta.url).search}`);

const RECENT_FAILURE_MS = 60000;

export default class DashboardPlusQuickAssist extends DashboardPlusWidget(BaseWidget) {
    constructor(config) {
        super(config);
        this.tickTimeout = 2;
        this.previous = null;
        this.failureTimes = [];
        this.chart = null;
        this.responses = null;
    }

    getGridOptions() {
        return {sizeToContent: 470};
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

    _markup() {
        return `<div id="${this._id('root')}" class="dashboard-plus-quickassist">
            <div class="qat-heading"><span class="qat-chip">▣</span><div><strong>QUICKASSIST</strong><small id="${this._id('model')}">—</small></div><div id="${this._id('status')}" class="qat-status text-muted">—</div></div>
            <section class="qat-panel"><div class="qat-label">${this.translations.qat_activity}</div><div class="qat-subtitle">${this.translations.requests_per_second}</div><div class="qat-rate"><strong id="${this._id('rate')}">—</strong> req/s</div><canvas id="${this._id('chart')}" height="170"></canvas></section>
            <section class="qat-panel"><div class="qat-label">${this.translations.qat_pipeline}</div><div class="qat-pipeline"><div id="${this._id('completed')}" class="qat-completed"></div><div id="${this._id('lag')}" class="qat-lag"></div></div><div class="qat-pipeline-labels"><span><b id="${this._id('completed-rate')}">—</b> ${this.translations.completed_requests}</span><span><b id="${this._id('lag-rate')}">—</b> ${this.translations.lag_requests}</span><span>${this.translations.outstanding} <b id="${this._id('outstanding')}">—</b></span></div></section>
            <section class="qat-panel"><div class="qat-label">${this.translations.device_information}</div><div class="qat-info"><div><small>${this.translations.qat_devices}</small><b id="${this._id('devices')}">—</b></div><div><small>${this.translations.acceleration_engines}</small><b id="${this._id('engines')}">—</b></div><div><small>${this.translations.clock}</small><b id="${this._id('clock')}">—</b></div><div><small>${this.translations.services}</small><b id="${this._id('services')}">—</b></div><div><small>${this.translations.ocf}</small><b id="${this._id('ocf')}">—</b></div></div></section>
            <div id="${this._id('error')}" class="text-danger qat-error"></div>
        </div>`;
    }

    getMarkup() {
        ensureStyle();
        return $(this._markup());
    }

    _render(sample, rates, health, error = '') {
        const devices = Array.isArray(sample?.devices) ? sample.devices : [];
        this._set('model', devices[0]?.description || 'Intel QuickAssist');
        const status = document.getElementById(this._id('status'));
        if (status) {
            status.textContent = this.translations[health.key];
            status.className = `qat-status text-${health.className}`;
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
        this._set('engines', counts.size === 1 && devices.length ? `${engines} total (${engines / devices.length} / device)` : `${engines} total`);
        this._set('clock', this._mhz(Math.max(...devices.map(device => Number(device.frequency_hz) || 0), 0)));
        this._set('services', this._serviceList(devices));
        this._set('ocf', sample?.ocf?.present ? (sample.ocf.enabled ? this.translations.enabled : this.translations.disabled) : '—');
        const errorElement = document.getElementById(this._id('error'));
        if (errorElement) errorElement.textContent = error;
    }

    _createChart() {
        const canvas = document.getElementById(this._id('chart'));
        if (!canvas || typeof SmoothieChart === 'undefined') return;
        this.responses = new TimeSeries();
        this.chart = new SmoothieChart({responsive: true, minValue: 0, maxValueScale: 1.15, millisPerPixel: 120,
            grid: {strokeStyle: 'rgba(119,119,119,0.12)', verticalSections: 4, fillStyle: 'transparent'},
            labels: {fillStyle: Chart.defaults.color, fontFamily: getComputedStyle(document.body).fontFamily, precision: 0}});
        this.chart.addTimeSeries(this.responses, {lineWidth: 3, strokeStyle: '#4fc76a', fillStyle: 'rgba(79,199,106,0.18)'});
        this.chart.streamTo(canvas, 1000);
    }

    async _sample() {
        const result = await sharedRequest('/api/dashboardplus/system/qat');
        const health = this._health(result);
        const rates = this._rates(result);
        if (this.responses) this.responses.append(Number(result.sampled_at) * 1000 || Date.now(), rates.completed);
        this._render(result, rates, health);
    }

    async onMarkupRendered() {
        renderTitle(this);
        this._createChart();
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
        this.chart?.stop();
    }
}
