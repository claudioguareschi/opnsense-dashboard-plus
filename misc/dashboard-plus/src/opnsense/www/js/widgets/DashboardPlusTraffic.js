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
        this.windowDuration = 60000;
        this.directionColors = {
            inbytes: {line: '#2ca02c', fill: 'rgba(44, 160, 44, 0.28)'},
            outbytes: {line: '#ff7f0e', fill: 'rgba(255, 127, 14, 0.28)'}
        };
    }

    getGridOptions() {
        return {sizeToContent: 650};
    }

    _chartConfig(datasets, showLegend = true, useThemePalette = true) {
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
                    y: {ticks: {callback: value => this._formatBits(value)}}
                },
                plugins: {
                    legend: {display: showLegend, position: 'top'},
                    tooltip: {
                        mode: 'nearest',
                        intersect: false,
                        callbacks: {label: context => `${context.dataset.label}: ${this._formatBits(context.raw.y)}`}
                    },
                    streaming: {frameRate: 30, ttl: this.windowDuration + 1000},
                    // Match the stock Traffic widget and therefore the active theme.
                    colorschemes: useThemePalette ? {scheme: 'tableau.Classic10'} : false
                }
            }
        };
    }

    _dataset(name, direction, time, explicitColor = false) {
        const color = this.directionColors[direction];
        return {
            label: name,
            ...(explicitColor ? {borderColor: color.line, backgroundColor: color.fill} : {}),
            pointRadius: 0,
            borderWidth: 2,
            direction,
            lastTime: time,
            data: []
        };
    }

    _perInterfaceHeading(name) {
        const color = this.directionColors;
        return `
            <div class="dashboard-plus-traffic-heading" draggable="true" title="Drag to reorder" style="display: flex; justify-content: space-between; align-items: center; padding: 0 0.5em; cursor: grab;">
                <h3 style="margin: 0;">${$('<div>').text(name).html()}</h3>
                <div style="display: flex; gap: 1em; white-space: nowrap;">
                    <span><i style="display: inline-block; width: 0.8em; height: 0.8em; border-radius: 50%; background: ${color.inbytes.line};"></i> ${this.translations.in}</span>
                    <span><i style="display: inline-block; width: 0.8em; height: 0.8em; border-radius: 50%; background: ${color.outbytes.line};"></i> ${this.translations.out}</span>
                </div>
            </div>`;
    }

    async _initialize(data) {
        const config = await this.getWidgetConfig();
        const combinedIn = [];
        const combinedOut = [];
        const $perInterface = $('#dashboard-plus-traffic-per-interface');

        this._orderedInterfaces(data.interfaces, config).forEach(([id, intf]) => {
            combinedIn.push({...this._dataset(intf.name, 'inbytes', data.time), intf: id});
            combinedOut.push({...this._dataset(intf.name, 'outbytes', data.time), intf: id});

            const canvasId = `dashboard-plus-traffic-${id}`;
            $perInterface.append(`
                <div class="dashboard-plus-traffic-interface" data-interface="${id}">
                    ${this._perInterfaceHeading(intf.name)}
                    <div class="canvas-container-noaspectratio"><canvas id="${canvasId}"></canvas></div>
                </div>
            `);
            this.charts[id] = new Chart($(`#${canvasId}`)[0].getContext('2d'), this._chartConfig([
                this._dataset(this.translations.in, 'inbytes', data.time, true),
                this._dataset(this.translations.out, 'outbytes', data.time, true)
            ], false, false));
        });

        this.charts.combinedIn = new Chart($('#dashboard-plus-traffic-in')[0].getContext('2d'), this._chartConfig(combinedIn));
        this.charts.combinedOut = new Chart($('#dashboard-plus-traffic-out')[0].getContext('2d'), this._chartConfig(combinedOut));
        this._makeSubpanelsSortable();
        this.initialized = true;
        this.currentConfig = config;
        this._applyConfig(config);
    }

    _applyConfig(config) {
        this.windowDuration = (parseInt(config.time_window, 10) || 60) * 1000;
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
        Object.values(this.charts).forEach(chart => {
            chart.options.scales.x.realtime.duration = this.windowDuration;
            chart.options.plugins.streaming.ttl = this.windowDuration + 1000;
        });
    }

    _orderedInterfaces(interfaces, config) {
        const order = config.interfaces || [];
        return Object.entries(interfaces).sort(([left], [right]) => {
            const leftIndex = order.indexOf(left);
            const rightIndex = order.indexOf(right);
            return (leftIndex === -1 ? Number.MAX_SAFE_INTEGER : leftIndex) -
                (rightIndex === -1 ? Number.MAX_SAFE_INTEGER : rightIndex);
        });
    }

    _saveSubpanelOrder() {
        const order = $('#dashboard-plus-traffic-per-interface').children('.dashboard-plus-traffic-interface')
            .map((_, panel) => $(panel).data('interface')).get();
        const selected = this.currentConfig.interfaces || [];
        this.currentConfig.interfaces = [
            ...order.filter(id => selected.includes(id)),
            ...selected.filter(id => !order.includes(id))
        ];
        this.setWidgetConfig(this.currentConfig);
        $('#save-grid').show();
    }

    _makeSubpanelsSortable() {
        const $container = $('#dashboard-plus-traffic-per-interface');
        let draggedPanel = null;
        let $placeholder = null;
        const clearDragState = () => {
            if (draggedPanel) {
                draggedPanel.css({opacity: '', outline: ''});
            }
            $placeholder?.remove();
            $placeholder = null;
            draggedPanel = null;
        };
        $container.on('mousedown', '.dashboard-plus-traffic-heading', event => event.stopPropagation());
        $container.on('dragstart', '.dashboard-plus-traffic-heading', event => {
            draggedPanel = $(event.currentTarget).closest('.dashboard-plus-traffic-interface');
            draggedPanel.css({opacity: 0.4, outline: '2px dashed #d94f00'});
            $placeholder = $('<div class="dashboard-plus-traffic-drop-placeholder" aria-label="Drop graph here"></div>')
                .css({
                    height: draggedPanel.outerHeight(),
                    margin: '0.5em 0',
                    border: '2px dashed #d94f00',
                    background: 'rgba(217, 79, 0, 0.08)'
                });
            event.originalEvent.dataTransfer.effectAllowed = 'move';
            event.stopPropagation();
        });
        $container.on('dragover', '.dashboard-plus-traffic-interface', event => {
            event.preventDefault();
            event.originalEvent.dataTransfer.dropEffect = 'move';
            const $target = $(event.currentTarget);
            if (!draggedPanel || draggedPanel[0] === $target[0]) {
                return;
            }
            const halfway = $target.offset().top + ($target.outerHeight() / 2);
            event.originalEvent.clientY < halfway ? $target.before($placeholder) : $target.after($placeholder);
        });
        $container.on('drop', '.dashboard-plus-traffic-interface', event => {
            event.preventDefault();
            if (draggedPanel && $placeholder?.parent().length) {
                $placeholder.replaceWith(draggedPanel);
                this._saveSubpanelOrder();
            }
            clearDragState();
        });
        $container.on('dragend', '.dashboard-plus-traffic-heading', clearDragState);
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

    onWidgetOptionsChanged() {
        this.configChanged = true;
    }

    onWidgetClose() {
        super.onWidgetClose();
        Object.values(this.charts).forEach(chart => chart.destroy());
    }
}
