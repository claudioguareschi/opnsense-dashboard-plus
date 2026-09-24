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

    getMarkup() {
        return $(`
            <div class="dashboard-plus-system-metrics" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1em; padding: 0 0.25em;">
                <section>
                    <div style="display: flex; justify-content: space-between; align-items: baseline; margin: 0 2em;">
                        <h3 style="margin: 0;">${this.translations.cpu}</h3>
                        <span id="${this.id}-cpu-current">--</span>
                    </div>
                    <div id="${this.id}-cpu-load" style="font-size: 0.9em; margin: 0.25em 0;"></div>
                    <div class="canvas-container-noaspectratio" style="margin: 0 0.5em;"><canvas id="${this.id}-cpu-chart" style="width: 100%; height: 90px;"></canvas></div>
                </section>
                <section>
                    <div style="display: flex; justify-content: space-between; align-items: baseline; margin: 0 2em;">
                        <h3 style="margin: 0;">${this.translations.memory}</h3>
                        <span id="${this.id}-memory-current">--</span>
                    </div>
                    <div id="${this.id}-memory-total" style="font-size: 0.9em; margin: 0.25em 0;"></div>
                    <div class="canvas-container-noaspectratio" style="margin: 0 0.5em;"><canvas id="${this.id}-memory-chart" style="width: 100%; height: 90px;"></canvas></div>
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
        this._createChart(
            `${this.id}-cpu-chart`, this.cpuSeries, '#d94f00', 0,
            {minValue: 0, maxValueScale: 1.15}
        );
        this._createChart(
            `${this.id}-memory-chart`, this.memorySeries, '#2ca02c', 0,
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
        const [resources, time] = await Promise.all([
            this.ajaxCall('/api/diagnostics/system/system_resources'),
            this.ajaxCall('/api/diagnostics/system/system_time')
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
    }
}
