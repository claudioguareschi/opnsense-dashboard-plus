/*
 * Copyright (C) 2026 Claudio Guareschi
 * All rights reserved.
 */

export default class DashboardPlusTraffic extends BaseWidget {
    constructor(config) {
        super(config);
        this.configurable = true;
        this.charts = {};
        this.datasets = {};
        this.initialized = false;
        this.latestData = null;
        this.currentConfig = null;
        this.configChanged = false;
    }

    getGridOptions() {
        return {sizeToContent: 650};
    }

    _chartConfig(datasets) {
        return {
            type: 'line',
            data: {datasets},
            options: {
                maintainAspectRatio: false,
                responsive: true,
                normalized: true,
                elements: {line: {fill: true, cubicInterpolationMode: 'monotone', clip: 0}},
                scales: {
                    x: {
                        display: false,
                        type: 'realtime',
                        realtime: {duration: 20000, delay: 2000},
                    },
                    y: {ticks: {callback: value => this._formatBits(value)}}
                },
                plugins: {
                    legend: {display: true, position: 'top'},
                    tooltip: {
                        mode: 'nearest',
                        intersect: false,
                        callbacks: {label: context => `${context.dataset.label}: ${this._formatBits(context.raw.y)}`}
                    },
                    streaming: {frameRate: 30, ttl: 30000},
                    // Do not let the global palette replace the stable colors below.
                    colorschemes: false
                }
            }
        };
    }

    _dataset(name, direction, color, time) {
        return {
            label: name,
            borderColor: color,
            backgroundColor: this._setAlpha(color, 0.2),
            pointRadius: 0,
            borderWidth: 2,
            direction,
            lastTime: time,
            data: []
        };
    }

    async _initialize(data) {
        const config = await this.getWidgetConfig();
        const colors = Chart.colorschemes.tableau.Classic10;
        const combinedIn = [];
        const combinedOut = [];
        const $perInterface = $('#dashboard-plus-traffic-per-interface');

        Object.entries(data.interfaces).forEach(([id, intf], index) => {
            const color = colors[index % colors.length];
            combinedIn.push({...this._dataset(intf.name, 'inbytes', color, data.time), intf: id});
            combinedOut.push({...this._dataset(intf.name, 'outbytes', color, data.time), intf: id});

            const canvasId = `dashboard-plus-traffic-${id}`;
            $perInterface.append(`
                <div class="dashboard-plus-traffic-interface" data-interface="${id}">
                    <h3>${$('<div>').text(intf.name).html()}</h3>
                    <div class="canvas-container-noaspectratio"><canvas id="${canvasId}"></canvas></div>
                </div>
            `);
            this.charts[id] = new Chart($(`#${canvasId}`)[0].getContext('2d'), this._chartConfig([
                this._dataset(this.translations.trafficin, 'inbytes', '#1f77b4', data.time),
                this._dataset(this.translations.trafficout, 'outbytes', '#ff7f0e', data.time)
            ]));
        });

        this.charts.combinedIn = new Chart($('#dashboard-plus-traffic-in')[0].getContext('2d'), this._chartConfig(combinedIn));
        this.charts.combinedOut = new Chart($('#dashboard-plus-traffic-out')[0].getContext('2d'), this._chartConfig(combinedOut));
        this.initialized = true;
        this.currentConfig = config;
        this._applyConfig(config);
    }

    _applyConfig(config) {
        const combined = config.display === 'combined';
        $('#dashboard-plus-traffic-combined').toggle(combined);
        $('#dashboard-plus-traffic-per-interface').toggle(!combined);
        $('.dashboard-plus-traffic-interface').each((_, element) => {
            $(element).toggle(!combined && (config.interfaces || []).includes($(element).data('interface')));
        });
        for (const chart of [this.charts.combinedIn, this.charts.combinedOut]) {
            if (!chart) {
                continue;
            }
            chart.config.data.datasets.forEach(dataset => {
                dataset.hidden = !(config.interfaces || []).includes(dataset.intf);
            });
        }
    }

    _appendPoint(chart, intf, sample, time) {
        chart.config.data.datasets.forEach(dataset => {
            if (dataset.intf && dataset.intf !== intf) {
                return;
            }
            const elapsed = time - dataset.lastTime;
            if (elapsed > 0) {
                dataset.data.push({x: Date.now(), y: Math.round((sample[dataset.direction] / elapsed) * 8)});
            }
            dataset.lastTime = time;
        });
    }

    async _onMessage(event) {
        if (!event) {
            this.closeEventSource();
            return;
        }
        const data = JSON.parse(event.data);
        this.latestData = data;
        if (!this.initialized) {
            await this._initialize(data);
        }
        if (this.configChanged) {
            this.currentConfig = await this.getWidgetConfig();
            this._applyConfig(this.currentConfig);
            this.configChanged = false;
        }
        Object.entries(data.interfaces).forEach(([id, sample]) => {
            this._appendPoint(this.charts.combinedIn, id, sample, data.time);
            this._appendPoint(this.charts.combinedOut, id, sample, data.time);
            if (this.charts[id]) {
                this._appendPoint(this.charts[id], id, sample, data.time);
            }
        });
        Object.values(this.charts).forEach(chart => chart.update('quiet'));
    }

    getMarkup() {
        return $(
            `<div class="dashboard-plus-traffic-container">
                <div id="dashboard-plus-traffic-combined">
                    <h3>${this.translations.trafficin}</h3>
                    <div class="canvas-container-noaspectratio"><canvas id="dashboard-plus-traffic-in"></canvas></div>
                    <h3>${this.translations.trafficout}</h3>
                    <div class="canvas-container-noaspectratio"><canvas id="dashboard-plus-traffic-out"></canvas></div>
                </div>
                <div id="dashboard-plus-traffic-per-interface"></div>
            </div>`
        );
    }

    async onMarkupRendered() {
        this.openEventSource('/api/diagnostics/traffic/stream/1', this._onMessage.bind(this));
    }

    async getWidgetOptions() {
        const data = await this.ajaxCall('/api/diagnostics/traffic/interface');
        const interfaces = Object.entries(data.interfaces || {}).map(([id, intf]) => ({value: id, label: intf.name}));
        return {
            display: {
                title: this.translations.display,
                type: 'select',
                id: 'dashboard-plus-traffic-display',
                options: [
                    {value: 'per_interface', label: this.translations.per_interface},
                    {value: 'combined', label: this.translations.combined}
                ],
                default: 'per_interface'
            },
            interfaces: {
                title: this.translations.interfaces,
                type: 'select_multiple',
                id: 'dashboard-plus-traffic-interfaces',
                options: interfaces,
                default: interfaces.filter(item => ['lan', 'wan'].includes(item.value)).map(item => item.value)
            }
        };
    }

    onWidgetOptionsChanged() {
        this.configChanged = true;
    }

    onWidgetClose() {
        super.onWidgetClose();
        Object.values(this.charts).forEach(chart => chart.destroy());
    }
}
