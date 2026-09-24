/*
 * Copyright (C) 2026 Claudio Guareschi
 * All rights reserved.
 */

export default class DashboardPlusSystemMetrics extends BaseWidget {
    constructor(config) {
        super(config);
        this.tickTimeout = 10;
        this.configurable = true;
        this.cpuSeries = null;
        this.memorySeries = null;
        this.statesSeries = null;
        this.mbufSeries = null;
        this.memoryPercent = null;
        this.charts = [];
        this.windowDuration = 60000;
        this.currentConfig = null;
    }

    getGridOptions() {
        return {sizeToContent: 420};
    }

    _createChart(canvasId, series, color, precision = 0, scale = {}) {
        const chart = new SmoothieChart({
            responsive: true,
            millisPerPixel: this._millisecondsPerPixel(canvasId),
            minValue: scale.minValue,
            maxValue: scale.maxValue,
            maxValueScale: scale.maxValueScale || 1,
            tooltip: true,
            labels: {
                fillStyle: Chart.defaults.color,
                precision,
                fontSize: 11
            },
            grid: {
                strokeStyle: 'rgba(119,119,119,0.12)',
                verticalSections: 4,
                millisPerLine: this.windowDuration / 4,
                fillStyle: 'transparent'
            }
        });
        chart.streamTo(document.getElementById(canvasId), 1000);
        chart.addTimeSeries(series, {lineWidth: 3, strokeStyle: color, fillStyle: `${color}33`});
        this.charts.push({chart, canvasId});
    }

    _millisecondsPerPixel(canvasId) {
        const width = document.getElementById(canvasId)?.clientWidth || 500;
        return this.windowDuration / width;
    }

    _applyTimeWindow(config) {
        this.windowDuration = (parseInt(config.time_window, 10) || 60) * 1000;
        this.charts.forEach(({chart, canvasId}) => {
            chart.options.millisPerPixel = this._millisecondsPerPixel(canvasId);
            chart.options.grid.millisPerLine = this.windowDuration / 4;
        });
    }

    _formatTotalMemory(mebibytes) {
        return mebibytes >= 1024
            ? `${(mebibytes / 1024).toFixed(1)} GiB`
            : `${mebibytes} MiB`;
    }

    _formatKiB(kibibytes) {
        if (kibibytes >= 1024 * 1024) {
            return `${(kibibytes / (1024 * 1024)).toFixed(1)} GiB`;
        }
        if (kibibytes >= 1024) {
            return `${(kibibytes / 1024).toFixed(1)} MiB`;
        }
        return `${kibibytes} KiB`;
    }

    getMarkup() {
        return $(`
            <div class="dashboard-plus-system-metrics" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1em; padding: 0 0.25em;">
                <section>
                    <div style="width: 95%; margin: 0 auto;">
                        <div style="display: flex; justify-content: space-between; align-items: baseline; margin: 0 0.25em;">
                            <h3 style="margin: 0;">${this.translations.cpu}</h3>
                            <span id="${this.id}-cpu-current">--</span>
                        </div>
                    </div>
                    <div id="${this.id}-cpu-load" style="font-size: 0.9em; margin: 0.25em 0;"></div>
                    <div class="canvas-container-noaspectratio" style="margin: 0 0.5em;"><canvas id="${this.id}-cpu-chart" style="width: 100%; height: 90px;"></canvas></div>
                </section>
                <section>
                    <div style="width: 95%; margin: 0 auto;">
                        <div style="display: flex; justify-content: space-between; align-items: baseline; margin: 0 0.25em;">
                            <h3 style="margin: 0;">${this.translations.memory}</h3>
                            <span id="${this.id}-memory-current">--</span>
                        </div>
                    </div>
                    <div id="${this.id}-memory-total" style="font-size: 0.9em; margin: 0.25em 0;"></div>
                    <div class="canvas-container-noaspectratio" style="margin: 0 0.5em;"><canvas id="${this.id}-memory-chart" style="width: 100%; height: 90px;"></canvas></div>
                </section>
                <section>
                    <div style="width: 95%; margin: 0 auto;">
                        <div style="display: flex; justify-content: space-between; align-items: baseline; margin: 0 0.25em;">
                            <h3 style="margin: 0;">${this.translations.states}</h3>
                            <span id="${this.id}-states-current">--</span>
                        </div>
                    </div>
                    <div id="${this.id}-states-total" style="font-size: 0.9em; margin: 0.25em 0;"></div>
                    <div class="canvas-container-noaspectratio" style="margin: 0 0.5em;"><canvas id="${this.id}-states-chart" style="width: 100%; height: 90px;"></canvas></div>
                </section>
                <section>
                    <div style="width: 95%; margin: 0 auto;">
                        <div style="display: flex; justify-content: space-between; align-items: baseline; margin: 0 0.25em;">
                            <h3 style="margin: 0;">${this.translations.mbufs}</h3>
                            <span id="${this.id}-mbufs-current">--</span>
                        </div>
                    </div>
                    <div id="${this.id}-mbufs-total" style="font-size: 0.9em; margin: 0.25em 0;"></div>
                    <div class="canvas-container-noaspectratio" style="margin: 0 0.5em;"><canvas id="${this.id}-mbufs-chart" style="width: 100%; height: 90px;"></canvas></div>
                </section>
                <section style="grid-column: 1 / -1;">
                    <div style="width: 95%; margin: 0 auto;">
                        <div style="display: flex; justify-content: space-between; align-items: baseline; margin: 0 0.25em;">
                            <h3 style="margin: 0;">${this.translations.swap}</h3>
                            <span id="${this.id}-swap-current">--</span>
                        </div>
                    </div>
                    <div style="margin: 0.25em 0.5em 0; height: 0.75em; background: rgba(119,119,119,0.12); border-radius: 0.375em; overflow: hidden;">
                        <div id="${this.id}-swap-bar" style="height: 100%; width: 0; background: #2ca02c; transition: width 0.2s ease;"></div>
                    </div>
                    <div id="${this.id}-swap-total" style="font-size: 0.9em; margin: 0.25em 0;"></div>
                </section>
            </div>
        `);
    }

    async onMarkupRendered() {
        $(`#${this.id}-title`).html(`<b>${this.translations.dashboard_title}</b>`);
        this.currentConfig = await this.getWidgetConfig();
        this._applyTimeWindow(this.currentConfig);
        this.cpuSeries = new TimeSeries();
        this.memorySeries = new TimeSeries();
        this.statesSeries = new TimeSeries();
        this.mbufSeries = new TimeSeries();
        this._createChart(
            `${this.id}-cpu-chart`, this.cpuSeries, '#d94f00', 0,
            {minValue: 0, maxValueScale: 1.15}
        );
        this._createChart(
            `${this.id}-memory-chart`, this.memorySeries, '#2ca02c', 0,
            {minValue: 0, maxValue: 100}
        );
        this._createChart(
            `${this.id}-states-chart`, this.statesSeries, '#2c7fb8', 0,
            {minValue: 0, maxValue: 100}
        );
        this._createChart(
            `${this.id}-mbufs-chart`, this.mbufSeries, '#8c6bb1', 0,
            {minValue: 0, maxValue: 100}
        );

        this.openEventSource('/api/diagnostics/cpu_usage/stream', event => {
            if (!event) {
                this.closeEventSource();
                return;
            }
            const cpu = JSON.parse(event.data).total;
            this.cpuSeries.append(Date.now(), cpu);
            if (this.memoryPercent !== null) {
                this.memorySeries.append(Date.now(), this.memoryPercent);
            }
            $(`#${this.id}-cpu-current`).text(`${cpu.toFixed(0)}%`);
        });
    }

    async getWidgetOptions() {
        return {
            time_window: {
                title: this.translations.time_window,
                type: 'select',
                id: 'dashboard-plus-system-metrics-time-window',
                options: [
                    {value: '20', label: this.translations.seconds_20},
                    {value: '60', label: this.translations.minute_1},
                    {value: '300', label: this.translations.minutes_5}
                ],
                default: '60'
            }
        };
    }

    onWidgetOptionsChanged(options) {
        this.currentConfig = options;
        this._applyTimeWindow(options);
    }

    onWidgetResize() {
        this._applyTimeWindow(this.currentConfig || {time_window: '60'});
        return true;
    }

    async onWidgetTick() {
        const [resources, time, states, mbufs, swap] = await Promise.all([
            this.ajaxCall('/api/diagnostics/system/system_resources'),
            this.ajaxCall('/api/diagnostics/system/system_time'),
            this.ajaxCall('/api/diagnostics/firewall/pf_states'),
            this.ajaxCall('/api/diagnostics/system/system_mbuf'),
            this.ajaxCall('/api/diagnostics/system/system_swap')
        ]);
        const memory = resources.memory;
        if (memory?.total !== undefined) {
            const total = parseInt(memory.total_frmt, 10);
            const used = parseInt(memory.used_frmt, 10);
            const arc = parseInt(memory.arc_frmt, 10) || 0;
            const pressureUsed = Math.max(0, used - arc);
            const percent = total > 0 ? (pressureUsed / total) * 100 : 0;
            this.memoryPercent = percent;
            this.memorySeries.append(Date.now(), percent);
            $(`#${this.id}-memory-current`).text(`${percent.toFixed(0)}%`);
            $(`#${this.id}-memory-total`).text(
                `${pressureUsed} MiB / ${this._formatTotalMemory(total)} ${this.translations.used}`
            );
        }
        $(`#${this.id}-cpu-load`).text(`${this.translations.load}: ${time.loadavg || this.translations.unavailable}`);

        const stateCurrent = parseInt(states?.current, 10);
        const stateLimit = parseInt(states?.limit, 10);
        if (Number.isFinite(stateCurrent) && Number.isFinite(stateLimit) && stateLimit > 0) {
            const percent = (stateCurrent / stateLimit) * 100;
            this.statesSeries.append(Date.now(), percent);
            $(`#${this.id}-states-current`).text(`${percent.toFixed(0)}%`);
            $(`#${this.id}-states-total`).text(`${stateCurrent.toLocaleString()} / ${stateLimit.toLocaleString()} ${this.translations.states.toLowerCase()}`);
        }

        const mbuf = mbufs?.['mbuf-statistics'];
        const mbufCurrent = parseInt(mbuf?.['mbuf-current'], 10);
        const mbufLimit = parseInt(mbuf?.['cluster-max'], 10);
        if (Number.isFinite(mbufCurrent) && Number.isFinite(mbufLimit) && mbufLimit > 0) {
            const percent = (mbufCurrent / mbufLimit) * 100;
            this.mbufSeries.append(Date.now(), percent);
            $(`#${this.id}-mbufs-current`).text(`${percent.toFixed(0)}%`);
            $(`#${this.id}-mbufs-total`).text(`${mbufCurrent.toLocaleString()} / ${mbufLimit.toLocaleString()} ${this.translations.mbufs.toLowerCase()}`);
        }

        const swapDevices = Array.isArray(swap?.swap) ? swap.swap : [];
        const swapTotal = swapDevices.reduce((total, device) => total + (parseInt(device.total, 10) || 0), 0);
        const swapUsed = swapDevices.reduce((total, device) => total + (parseInt(device.used, 10) || 0), 0);
        if (swapTotal > 0) {
            const percent = (swapUsed / swapTotal) * 100;
            const color = percent >= 80 ? '#d94f00' : percent >= 50 ? '#ff7f0e' : '#2ca02c';
            $(`#${this.id}-swap-current`).text(`${percent.toFixed(0)}%`);
            $(`#${this.id}-swap-total`).text(`${this._formatKiB(swapUsed)} / ${this._formatKiB(swapTotal)} ${this.translations.used}`);
            $(`#${this.id}-swap-bar`).css({width: `${Math.min(percent, 100)}%`, background: color});
        }
    }
}
