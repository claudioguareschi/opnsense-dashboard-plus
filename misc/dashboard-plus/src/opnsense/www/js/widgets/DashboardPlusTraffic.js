/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
 * All rights reserved.
 */

const {escapeHtml, renderTitle, mergeOrder, makeSortable, formatBitRate, ensureStyle, DashboardPlusWidget} =
    await import(`./DashboardPlusCommon.js${new URL(import.meta.url).search}`);

export default class DashboardPlusTraffic extends DashboardPlusWidget(BaseWidget) {
    constructor(config) {
        super(config);
        this.configurable = true;
        this.charts = {};
        this.buildPromise = null;
        this.currentConfig = null;
        this.interfaceColors = {};
        this.windowDuration = 60000;
        this.directionColors = {
            inbytes: {line: '#2ca02c', fill: 'rgba(44, 160, 44, 0.28)'},
            outbytes: {line: '#ff7f0e', fill: 'rgba(255, 127, 14, 0.28)'}
        };
    }

    getGridOptions() {
        return {sizeToContent: 650};
    }

    _elementId(name) {
        return `${this.id}-traffic-${name}`;
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
                        display: true,
                        type: 'realtime',
                        time: {
                            tooltipFormat: 'HH:mm:ss',
                            unit: 'minute',
                            displayFormats: {minute: 'HH:mm'}
                        },
                        realtime: {duration: this.windowDuration, delay: 2000},
                    },
                    y: {ticks: {callback: value => formatBitRate(value)}}
                },
                plugins: {
                    legend: {display: false},
                    tooltip: {
                        mode: 'nearest',
                        intersect: false,
                        callbacks: {label: context => `${context.dataset.label}: ${formatBitRate(context.raw.y)}`}
                    },
                    streaming: {frameRate: 30, ttl: this.windowDuration + 10000},
                    colorschemes: false
                }
            }
        };
    }

    _dataset(label, direction, time, color = null) {
        const colors = color
            ? {borderColor: color, backgroundColor: `${color}47`}
            : {borderColor: this.directionColors[direction].line, backgroundColor: this.directionColors[direction].fill};
        return {label, ...colors, pointRadius: 0, borderWidth: 2, direction, lastTime: time, data: []};
    }

    _perInterfacePanel(id, name, canvasId) {
        const color = this.directionColors;
        return `
            <div class="dashboard-plus-traffic-interface" data-sort-id="${escapeHtml(id)}">
                <div class="dashboard-plus-inner">
                    <div class="dashboard-plus-panel-head dashboard-plus-traffic-heading dashboard-plus-grab" draggable="true" title="${escapeHtml(this.translations.drag_to_reorder)}">
                        <h3>${escapeHtml(name)}</h3>
                        <div class="dashboard-plus-legend">
                            <span><i class="dashboard-plus-dot" style="background: ${color.inbytes.line};"></i> ${escapeHtml(this.translations.in)}</span>
                            <span><i class="dashboard-plus-dot" style="background: ${color.outbytes.line};"></i> ${escapeHtml(this.translations.out)}</span>
                        </div>
                    </div>
                </div>
                <div class="canvas-container-noaspectratio dashboard-plus-chart"><canvas id="${escapeHtml(canvasId)}"></canvas></div>
            </div>`;
    }

    _renderCombinedLegend(entries) {
        const $legend = $(`#${this._elementId('combined-legend')}`).empty();
        entries.forEach(({label, color}) => {
            // the dot takes the series color of the chart
            $legend.append(`<span><i class="dashboard-plus-dot" style="background: ${color};"></i> ${escapeHtml(label)}</span>`);
        });
    }

    _destroyCharts() {
        Object.values(this.charts).forEach(chart => chart.destroy());
        this.charts = {};
    }

    /*
     * Build the charts for the selected interfaces only. Called once for the first stream
     * message and again whenever the selection changes; a rebuild starts the graphs afresh.
     */
    _build(data, config) {
        this._destroyCharts();
        const selected = mergeOrder(config.interfaces, config.interfaces).filter(id => id in data.interfaces);
        // Classic10 repeats once a firewall has more than ten interfaces. Tableau20, keyed on
        // every interface the firewall has, keeps each interface's color stable.
        const palette = Chart.colorschemes.tableau.Tableau20;
        Object.keys(data.interfaces).forEach((id, index) => {
            this.interfaceColors[id] = palette[index % palette.length];
        });

        const $perInterface = $(`#${this._elementId('per-interface')}`).empty();
        // Show the chosen view first: a chart created inside a hidden container starts at
        // zero size and only corrects itself on its next resize.
        this._showView(config);
        const combinedIn = [];
        const combinedOut = [];
        selected.forEach(id => {
            const name = data.interfaces[id].name;
            const color = this.interfaceColors[id];
            combinedIn.push({...this._dataset(name, 'inbytes', data.time, color), intf: id});
            combinedOut.push({...this._dataset(name, 'outbytes', data.time, color), intf: id});

            const canvasId = this._elementId(`interface-${this.sanitizeSelector(id)}`);
            $perInterface.append(this._perInterfacePanel(id, name, canvasId));
            const chart = new Chart(document.getElementById(canvasId).getContext('2d'), this._chartConfig([
                this._dataset(this.translations.in, 'inbytes', data.time),
                this._dataset(this.translations.out, 'outbytes', data.time)
            ]));
            chart.config.data.datasets.forEach(dataset => dataset.intf = id);
            this.charts[`interface-${id}`] = chart;
        });

        this.charts.combinedIn = new Chart(document.getElementById(this._elementId('in')).getContext('2d'), this._chartConfig(combinedIn));
        this.charts.combinedOut = new Chart(document.getElementById(this._elementId('out')).getContext('2d'), this._chartConfig(combinedOut));
        this._renderCombinedLegend(selected.map(id => ({label: data.interfaces[id].name, color: this.interfaceColors[id]})));
        this.builtSelection = selected.join('\n');
        this._applyDisplay(config);
        // The charts exist only after the first stream message; size the widget now rather
        // than on the dashboard's next tick.
        this.config.callbacks?.updateGrid?.();
    }

    _showView(config) {
        const combined = config.display === 'combined';
        $(`#${this._elementId('combined')}`).toggle(combined);
        $(`#${this._elementId('per-interface')}`).toggle(!combined);
        this._updateViewToggle(combined);
    }

    _applyDisplay(config) {
        this.windowDuration = (parseInt(config.time_window, 10) || 60) * 1000;
        this._showView(config);
        Object.values(this.charts).forEach(chart => {
            chart.options.scales.x.realtime.duration = this.windowDuration;
            chart.options.plugins.streaming.ttl = this.windowDuration + 10000;
            chart.resize();
        });
    }

    _updateViewToggle(compact) {
        const label = compact ? this.translations.expand : this.translations.compact;
        const $toggle = $(`#${this.id}-traffic-view-toggle`);
        $toggle.attr({title: label, 'aria-label': label});
        $toggle.find('i').attr('class', compact ? 'fa fa-expand fa-xs' : 'fa fa-compress fa-xs');
    }

    _toggleDisplay() {
        if (!this.currentConfig) {
            return;
        }
        this.currentConfig = {
            ...this.currentConfig,
            display: this.currentConfig.display === 'combined' ? 'per_interface' : 'combined'
        };
        // The toggle is a view setting like the options dialog: keep it with the layout.
        this.setWidgetConfig(this.currentConfig);
        $('#save-grid').show();
        this._applyDisplay(this.currentConfig);
        this.config.callbacks?.updateGrid?.();
    }

    _appendPoint(chart, intf, sample, time) {
        chart.config.data.datasets.forEach(dataset => {
            if (dataset.intf !== intf) {
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
        const data = JSON.parse(event.data);
        this.lastData = data;
        // Messages arrive every second while the first build awaits the widget config;
        // share one build so the canvases are never claimed twice.
        this.buildPromise ??= this.getWidgetConfig().then(config => {
            this.currentConfig = config;
            this._build(data, config);
        }).catch(error => {
            this.buildPromise = null;
            throw error;
        });
        await this.buildPromise;
        Object.entries(data.interfaces).forEach(([id, sample]) => {
            Object.values(this.charts).forEach(chart => this._appendPoint(chart, id, sample, data.time));
        });
        Object.values(this.charts).forEach(chart => chart.update('quiet'));
    }

    getMarkup() {
        ensureStyle();
        return $(
            `<div class="dashboard-plus-traffic">
                <div id="${this._elementId('combined')}" style="display: none;">
                    <h3>${escapeHtml(this.translations.trafficin)}</h3>
                    <div id="${this._elementId('combined-legend')}" class="dashboard-plus-legend dashboard-plus-combined-legend"></div>
                    <div class="canvas-container-noaspectratio dashboard-plus-chart dashboard-plus-combined-chart"><canvas id="${this._elementId('in')}"></canvas></div>
                    <h3>${escapeHtml(this.translations.trafficout)}</h3>
                    <div class="canvas-container-noaspectratio dashboard-plus-chart dashboard-plus-combined-chart"><canvas id="${this._elementId('out')}"></canvas></div>
                </div>
                <div id="${this._elementId('per-interface')}"></div>
            </div>`
        );
    }

    async onMarkupRendered() {
        renderTitle(this);
        const $header = $(`#${this.id}-title`).closest('.widget-header');
        // the same link icon as the dashboard's own breakout link in the header
        $header.find('.widget-header-left').append(
            `<a href="#" role="button" id="${this.id}-traffic-view-toggle" title="${escapeHtml(this.translations.compact)}" aria-label="${escapeHtml(this.translations.compact)}"><i class="fa fa-compress fa-xs"></i></a>`
        );
        $(`#${this.id}-traffic-view-toggle`).on('click', event => {
            event.preventDefault();
            event.stopPropagation();
            this._toggleDisplay();
        });
        makeSortable($(`#${this._elementId('per-interface')}`), {
            itemSelector: '.dashboard-plus-traffic-interface',
            handleSelector: '.dashboard-plus-traffic-heading',
            label: this.translations.drag_to_reorder,
            onReorder: order => {
                this.currentConfig.interfaces = mergeOrder(order, this.currentConfig.interfaces);
                this.setWidgetConfig(this.currentConfig);
            }
        });
        this.fitToContent();
        this.openEventSource('/api/diagnostics/traffic/stream/1', this._onMessage.bind(this));
    }

    onWidthChanged() {
        // Chart.js only notices a container resize on its own later; resize now so the
        // canvases follow the column when the side menu is toggled.
        Object.values(this.charts).forEach(chart => chart.resize());
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
            },
            time_window: {
                title: this.translations.time_window,
                type: 'select',
                id: 'dashboard-plus-traffic-time-window',
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
        await this.buildPromise;
        const previous = this.currentConfig?.interfaces;
        const config = await this.getWidgetConfig();
        // The dialog lists the selection in option order; keep the dragged order.
        config.interfaces = mergeOrder(previous, config.interfaces);
        this.setWidgetConfig(config);
        this.currentConfig = config;
        if (this.lastData && config.interfaces.join('\n') !== this.builtSelection) {
            this._build(this.lastData, config);
        } else {
            this._applyDisplay(config);
        }
    }

    onWidgetClose() {
        super.onWidgetClose();
        this._destroyCharts();
    }
}
