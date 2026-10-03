/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
 * All rights reserved.
 */

const {renderTitle, DashboardPlusWidget} =
    await import(`./DashboardPlusCommon.js${new URL(import.meta.url).search}`);

export default class DashboardPlusSystemMetrics extends DashboardPlusWidget(BaseWidget) {
    constructor(config) {
        super(config);
        this.tickTimeout = 10;
        this.configurable = true;
        this.cpuSeries = null;
        this.temperatureSeries = null;
        this.temperatureCelsius = null;
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
                // Match the dashboard text instead of Smoothie's default monospace.
                fontFamily: getComputedStyle(document.body).fontFamily,
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

    _compactNumber(value) {
        return new Intl.NumberFormat(undefined, {notation: 'compact', maximumSignificantDigits: 3}).format(value);
    }

    // Used and total in the unit that suits the total, e.g. "1.8 / 8.0 GiB".
    _formatKiBPair(usedKiB, totalKiB) {
        const units = [['GiB', 1024 * 1024], ['MiB', 1024], ['KiB', 1]];
        const [unit, size] = units.find(([, size]) => totalKiB >= size) || units[units.length - 1];
        const digits = size === 1 ? 0 : 1;
        return `${usedKiB > 0 ? (usedKiB / size).toFixed(digits) : 0} / ${(totalKiB / size).toFixed(digits)} ${unit}`;
    }

    _gaugeMarkup(component, label, extra = '') {
        // A 270 degree ring; the fill is the same arc drawn with a dash of the used percentage.
        const arc = 'M 23.13 76.87 A 38 38 0 1 1 76.87 76.87';
        return `
            <div data-component="${component}" id="${this.id}-${component}-gauge" style="text-align: center; min-width: 0;">
                <svg viewBox="0 0 100 92" style="width: 100%; max-width: 96px; display: block; margin: 0 auto;" role="img" aria-label="${label}">
                    <path d="${arc}" fill="none" stroke="rgba(119,119,119,0.12)" stroke-width="9" stroke-linecap="round"/>
                    <path class="gauge-fill" d="${arc}" pathLength="100" stroke-dasharray="0 100" fill="none" stroke="#2ca02c" stroke-width="9" stroke-linecap="round" style="transition: stroke-dasharray 0.2s ease;"/>
                    <text class="gauge-value" x="50" y="57" text-anchor="middle" fill="currentColor" style="font-size: 19px; font-weight: 600; font-variant-numeric: tabular-nums;">--</text>
                </svg>
                <div style="font-weight: 600; margin-top: -0.4em; white-space: nowrap;">${label}${extra}</div>
                <div class="gauge-detail" style="font-size: 0.85em; font-variant-numeric: tabular-nums; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;"></div>
            </div>`;
    }

    _setGauge(component, percent, detail, tooltip) {
        const gauge = document.getElementById(`${this.id}-${component}-gauge`);
        if (!gauge) {
            return;
        }
        const clamped = Math.max(0, Math.min(percent, 100));
        const fill = gauge.querySelector('.gauge-fill');
        fill.setAttribute('stroke-dasharray', `${clamped} 100`);
        fill.setAttribute('stroke', this._usageColor(clamped));
        gauge.querySelector('.gauge-value').textContent = `${percent.toFixed(0)}%`;
        gauge.querySelector('.gauge-detail').textContent = detail;
        gauge.title = tooltip;
    }

    // One row of gauges, or two when the row is too narrow for all of them.
    _layoutGauges() {
        const row = document.getElementById(`${this.id}-gauges`);
        if (!row) {
            return;
        }
        const visible = [...row.children].filter(gauge => gauge.style.display !== 'none').length;
        $(row).closest('section').toggle(visible > 0);
        const columns = visible > 2 && row.clientWidth < visible * 95 ? Math.ceil(visible / 2) : Math.max(visible, 1);
        row.style.gridTemplateColumns = `repeat(${columns}, 1fr)`;
    }

    _usageColor(percent) {
        return percent >= 80 ? '#d94f00' : percent >= 50 ? '#ff7f0e' : '#2ca02c';
    }

    _expandTemperatureScale(celsius) {
        const entry = this.charts.find(chart => chart.canvasId === `${this.id}-temperature-chart`);
        if (entry && celsius > entry.chart.options.maxValue) {
            entry.chart.options.maxValue = Math.ceil(celsius / 10) * 10;
        }
    }

    _componentNames() {
        return ['cpu', 'temperature', 'memory', 'states', 'mbufs', 'swap', 'filesystems'];
    }

    _applyComponentVisibility(config) {
        const components = config.components || this._componentNames();
        const markers = {
            cpu: `${this.id}-cpu-chart`,
            temperature: `${this.id}-temperature-chart`,
            memory: `${this.id}-memory-gauge`,
            states: `${this.id}-states-gauge`,
            mbufs: `${this.id}-mbufs-gauge`,
            swap: `${this.id}-swap-gauge`,
            filesystems: `${this.id}-filesystems`
        };
        Object.entries(markers).forEach(([component, marker]) => {
            $(`#${marker}`).closest('section, [data-component]').toggle(components.includes(component));
        });
        this._layoutGauges();
    }

    _renderFilesystems(devices) {
        const container = document.getElementById(`${this.id}-filesystems`);
        if (!container || !Array.isArray(devices)) {
            return;
        }
        container.replaceChildren();
        const byMountpoint = new Map();
        for (const filesystem of devices) {
            byMountpoint.set(filesystem.mountpoint, filesystem);
        }
        for (const mountpoint of ['/', '/tmp', '/var/log']) {
            const filesystem = byMountpoint.get(mountpoint);
            if (!filesystem) {
                continue;
            }
            const percent = Math.max(0, Math.min(parseFloat(filesystem.used_pct) || 0, 100));
            const row = document.createElement('div');
            row.style.cssText = 'display: grid; grid-template-columns: 28% 72%; padding: 0.35em 0; text-align: left;';
            const mount = document.createElement('span');
            mount.style.cssText = 'padding-right: 0.75em;';
            mount.textContent = filesystem.mountpoint;
            const usage = document.createElement('div');
            usage.style.paddingLeft = '0.75em';
            const bar = document.createElement('div');
            bar.style.cssText = 'height: 0.75em; background: rgba(119,119,119,0.12); border-radius: 0.375em; overflow: hidden;';
            const fill = document.createElement('div');
            fill.style.cssText = `height: 100%; width: ${percent}%; background: ${this._usageColor(percent)}; transition: width 0.2s ease;`;
            bar.append(fill);
            const details = document.createElement('div');
            details.style.cssText = 'font-size: 0.9em; margin-top: 0.15em;';
            details.textContent = `${percent.toFixed(0)}% · ${filesystem.used} / ${filesystem.blocks} (${filesystem.type})`;
            usage.append(bar, details);
            row.append(mount, usage);
            container.append(row);
        }
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
                            <h3 style="margin: 0;">${this.translations.temperature}</h3>
                            <span id="${this.id}-temperature-current">--</span>
                        </div>
                    </div>
                    <div class="canvas-container-noaspectratio" style="margin: 0 0.5em;"><canvas id="${this.id}-temperature-chart" style="width: 100%; height: 90px;"></canvas></div>
                </section>
                <section style="grid-column: 1 / -1;">
                    <div id="${this.id}-gauges" style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.5em; width: 95%; margin: 0 auto;">
                        ${this._gaugeMarkup('memory', this.translations.memory)}
                        ${this._gaugeMarkup('states', this.translations.states,
                            ` <a href="/ui/diagnostics/firewall/states" style="font-weight: normal; font-size: 0.9em;">${this.translations.show_states}</a>`)}
                        ${this._gaugeMarkup('mbufs', this.translations.mbufs)}
                        ${this._gaugeMarkup('swap', this.translations.swap)}
                    </div>
                </section>
                <section style="grid-column: 1 / -1;">
                    <div style="width: 95%; margin: 0 auto;">
                        <div style="display: flex; align-items: baseline; margin: 0 0.25em;">
                            <h3 style="margin: 0;">${this.translations.filesystems}</h3>
                        </div>
                    </div>
                    <div id="${this.id}-filesystems" style="width: 95%; margin: 0.25em auto 0;"></div>
                </section>
            </div>
        `);
    }

    async onMarkupRendered() {
        renderTitle(this);
        this.fitToContent();
        this.currentConfig = await this.getWidgetConfig();
        this._applyTimeWindow(this.currentConfig);
        this._applyComponentVisibility(this.currentConfig);
        this.cpuSeries = new TimeSeries();
        this.temperatureSeries = new TimeSeries();
        this._createChart(
            `${this.id}-cpu-chart`, this.cpuSeries, '#2ca02c', 0,
            {minValue: 0, maxValueScale: 1.15}
        );
        this._createChart(
            `${this.id}-temperature-chart`, this.temperatureSeries, '#d62728', 0,
            {minValue: 0, maxValue: 100}
        );

        // One sample per second for both series, paced by the CPU stream. The tick only
        // refreshes the latest temperature.
        this.openEventSource('/api/diagnostics/cpu_usage/stream', event => {
            const cpu = JSON.parse(event.data).total;
            this.cpuSeries.append(Date.now(), cpu);
            if (this.temperatureCelsius !== null) {
                this.temperatureSeries.append(Date.now(), this.temperatureCelsius);
            }
            $(`#${this.id}-cpu-current`).text(`${cpu.toFixed(0)}%`);
        });
    }

    async getWidgetOptions() {
        return {
            components: {
                title: this.translations.components,
                type: 'select_multiple',
                id: 'dashboard-plus-system-metrics-components',
                options: this._componentNames().map(component => ({
                    value: component,
                    label: this.translations[component]
                })),
                default: this._componentNames()
            },
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

    async onWidgetOptionsChanged() {
        // Read the options back through getWidgetConfig so an empty selection means the
        // defaults now, as it will after the dashboard reloads.
        this.currentConfig = await this.getWidgetConfig();
        this._applyTimeWindow(this.currentConfig);
        this._applyComponentVisibility(this.currentConfig);
        this.config.callbacks?.updateGrid?.();
    }

    onWidthChanged() {
        this._applyTimeWindow(this.currentConfig || {time_window: '60'});
        // Resize the backing stores now rather than on Smoothie's next frame, so the charts
        // are not drawn stretched while the column changes width.
        this.charts.forEach(({chart}) => chart.resize());
        this._layoutGauges();
    }

    onWidgetClose() {
        super.onWidgetClose();
        this.charts.forEach(({chart}) => chart.stop());
        this.charts = [];
    }

    async onWidgetTick() {
        const [resources, time, temperature, states, mbufs, swap, disks] = await Promise.all([
            this.ajaxCall('/api/diagnostics/system/system_resources'),
            this.ajaxCall('/api/diagnostics/system/system_time'),
            this.ajaxCall('/api/diagnostics/system/system_temperature'),
            this.ajaxCall('/api/diagnostics/firewall/pf_states'),
            this.ajaxCall('/api/diagnostics/system/system_mbuf'),
            this.ajaxCall('/api/diagnostics/system/system_swap'),
            this.ajaxCall('/api/diagnostics/system/system_disk')
        ]);
        const memory = resources.memory;
        if (memory?.total !== undefined) {
            const total = parseInt(memory.total_frmt, 10);
            const used = parseInt(memory.used_frmt, 10);
            const arc = parseInt(memory.arc_frmt, 10) || 0;
            const pressureUsed = Math.max(0, used - arc);
            const percent = total > 0 ? (pressureUsed / total) * 100 : 0;
            this._setGauge('memory', percent, this._formatKiBPair(pressureUsed * 1024, total * 1024),
                `${pressureUsed} MiB / ${this._formatTotalMemory(total)} ${this.translations.used}`);
        }
        $(`#${this.id}-cpu-load`).text(`${this.translations.load}: ${time.loadavg || this.translations.unavailable}`);

        const readings = Array.isArray(temperature)
            ? temperature.filter(reading => Number.isFinite(parseFloat(reading.temperature)))
            : [];
        if (readings.length > 0) {
            const hottest = readings.reduce((current, reading) =>
                parseFloat(reading.temperature) > parseFloat(current.temperature) ? reading : current
            );
            const celsius = parseFloat(hottest.temperature);
            this.temperatureCelsius = celsius;
            this._expandTemperatureScale(celsius);
            $(`#${this.id}-temperature-current`).text(`${celsius.toFixed(1)} °C`);
        } else {
            $(`#${this.id}-temperature-current`).text(this.translations.unavailable);
        }

        const stateCurrent = parseInt(states?.current, 10);
        const stateLimit = parseInt(states?.limit, 10);
        if (Number.isFinite(stateCurrent) && Number.isFinite(stateLimit) && stateLimit > 0) {
            const percent = (stateCurrent / stateLimit) * 100;
            this._setGauge('states', percent,
                `${this._compactNumber(stateCurrent)} / ${this._compactNumber(stateLimit)}`,
                `${stateCurrent.toLocaleString()} / ${stateLimit.toLocaleString()} ${this.translations.states.toLowerCase()}`);
        }

        const mbuf = mbufs?.['mbuf-statistics'];
        // Clusters in use against the cluster limit, as the core Mbuf widget reports it.
        const mbufCurrent = parseInt(mbuf?.['cluster-total'], 10);
        const mbufLimit = parseInt(mbuf?.['cluster-max'], 10);
        if (Number.isFinite(mbufCurrent) && Number.isFinite(mbufLimit) && mbufLimit > 0) {
            const percent = (mbufCurrent / mbufLimit) * 100;
            this._setGauge('mbufs', percent,
                `${this._compactNumber(mbufCurrent)} / ${this._compactNumber(mbufLimit)}`,
                `${mbufCurrent.toLocaleString()} / ${mbufLimit.toLocaleString()} ${this.translations.mbuf_clusters}`);
        }

        const swapDevices = Array.isArray(swap?.swap) ? swap.swap : [];
        const swapTotal = swapDevices.reduce((total, device) => total + (parseInt(device.total, 10) || 0), 0);
        const swapUsed = swapDevices.reduce((total, device) => total + (parseInt(device.used, 10) || 0), 0);
        if (swapTotal > 0) {
            const percent = (swapUsed / swapTotal) * 100;
            this._setGauge('swap', percent, this._formatKiBPair(swapUsed, swapTotal),
                `${this._formatKiB(swapUsed)} / ${this._formatKiB(swapTotal)} ${this.translations.used}`);
        }

        this._renderFilesystems(disks?.devices);
    }
}
