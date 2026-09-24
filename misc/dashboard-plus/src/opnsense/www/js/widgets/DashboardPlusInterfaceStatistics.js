/*
 * Copyright (C) 2026 Claudio Guareschi
 * All rights reserved.
 */

export default class DashboardPlusInterfaceStatistics extends BaseTableWidget {
    constructor(config) {
        super(config);
        this.configurable = true;
        this.chart = null;
        this.configChanged = false;
        this.currentConfig = null;
    }

    getGridOptions() {
        return {sizeToContent: 650};
    }

    getMarkup() {
        const $container = $('<div class="dashboard-plus-interface-statistics"></div>');
        $container.append(`
            <div id="dashboard-plus-interface-statistics-chart" class="dashboard-plus-interface-statistics-chart-container">
                <div class="canvas-container">
                    <canvas id="dashboard-plus-interface-statistics-canvas" style="display: inline-block"></canvas>
                </div>
            </div>
        `);
        $container.append(this.createTable('dashboard-plus-interface-statistics-table', {
            headerPosition: 'top',
            headers: [
                this.translations.interface,
                this.translations.bytes,
                this.translations.packets,
                this.translations.errors,
                this.translations.collisions
            ]
        }));
        return $container;
    }

    _pair(first, second) {
        return `<small>${this.translations.in}: ${first}<br>${this.translations.out}: ${second}</small>`;
    }

    _applyConfig(config) {
        const showGraph = config.display === 'graph' || config.display === 'both';
        const showTable = config.display === 'table' || config.display === 'both';
        $('#dashboard-plus-interface-statistics-chart').toggle(showGraph);
        $('#dashboard-plus-interface-statistics-table').toggle(showTable);
        this._applyFieldVisibility(config);
    }

    _applyFieldVisibility(config) {
        const visibleFields = config.fields || ['bytes', 'packets', 'errors', 'collisions'];
        const fieldColumns = {bytes: 1, packets: 2, errors: 3, collisions: 4};
        const $table = $('#dashboard-plus-interface-statistics-table');
        $table.children('.grid-header-container, .grid-row').each((_, row) => {
            Object.entries(fieldColumns).forEach(([field, column]) => {
                $(row).children().eq(column).toggle(visibleFields.includes(field));
            });
        });
    }

    _clearTable() {
        const id = 'dashboard-plus-interface-statistics-table';
        $(`#${id}`).children('.grid-row').remove();
        this.tables[id].data = [];
    }

    async onMarkupRendered() {
        $(`#${this.id}-title`).html(`<b>${this.translations.dashboard_title}</b>`);
        const context = $('#dashboard-plus-interface-statistics-canvas')[0].getContext('2d');
        this.chart = new Chart(context, {
            type: 'doughnut',
            data: {labels: [], datasets: [{data: [], backgroundColor: []}]},
            options: {
                cutout: '40%',
                maintainAspectRatio: true,
                responsive: true,
                aspectRatio: 2,
                layout: {
                    padding: 10
                },
                normalized: true,
                parsing: false,
                plugins: {
                    legend: {display: true, position: 'left'},
                    colorschemes: false
                }
            }
        });
        this.currentConfig = await this.getWidgetConfig();
        this._applyConfig(this.currentConfig);
    }

    async onWidgetTick() {
        const data = await this.ajaxCall('/api/diagnostics/traffic/interface');
        if (this.configChanged) {
            this.currentConfig = await this.getWidgetConfig();
            this._applyConfig(this.currentConfig);
            this._clearTable();
            this.configChanged = false;
        }
        const config = this.currentConfig;
        const colors = Chart.colorschemes.tableau.Classic10;
        const labels = [];
        const chartData = [];
        const chartColors = [];
        Object.entries(data.interfaces || {}).forEach(([id, intf], index) => {
            if (!(config.interfaces || []).includes(id)) {
                return;
            }
            const received = parseInt(intf['bytes received']) || 0;
            const transmitted = parseInt(intf['bytes transmitted']) || 0;
            const packetsReceived = parseInt(intf['packets received']) || 0;
            const packetsTransmitted = parseInt(intf['packets transmitted']) || 0;
            const errorsReceived = parseInt(intf['input errors']) || 0;
            const errorsTransmitted = parseInt(intf['output errors']) || 0;
            super.updateTable('dashboard-plus-interface-statistics-table', [[
                intf.name,
                this._pair(this._formatBytes(received) || '0', this._formatBytes(transmitted) || '0'),
                this._pair(packetsReceived.toLocaleString(), packetsTransmitted.toLocaleString()),
                this._pair(errorsReceived.toLocaleString(), errorsTransmitted.toLocaleString()),
                (parseInt(intf.collisions) || 0).toLocaleString()
            ]], id);
            labels.push(intf.name);
            chartData.push(config.chart_metric === 'packets'
                ? packetsReceived + packetsTransmitted
                : received + transmitted);
            chartColors.push(colors[index % colors.length]);
        });
        this.chart.data.labels = labels;
        this.chart.data.datasets[0].data = chartData;
        this.chart.data.datasets[0].backgroundColor = chartColors;
        this.chart.update();
        this._applyFieldVisibility(config);
    }

    async getWidgetOptions() {
        const data = await this.ajaxCall('/api/diagnostics/traffic/interface');
        const interfaces = Object.entries(data.interfaces || {}).map(([id, intf]) => ({value: id, label: intf.name}));
        return {
            display: {
                title: this.translations.display,
                type: 'select',
                id: 'dashboard-plus-interface-statistics-display',
                options: [
                    {value: 'both', label: this.translations.both},
                    {value: 'graph', label: this.translations.graph},
                    {value: 'table', label: this.translations.table}
                ],
                default: 'both'
            },
            interfaces: {
                title: this.translations.interfaces,
                type: 'select_multiple',
                id: 'dashboard-plus-interface-statistics-interfaces',
                options: interfaces,
                default: interfaces.filter(item => ['lan', 'wan'].includes(item.value)).map(item => item.value)
            },
            fields: {
                title: this.translations.fields,
                type: 'select_multiple',
                id: 'dashboard-plus-interface-statistics-fields',
                options: [
                    {value: 'bytes', label: this.translations.bytes},
                    {value: 'packets', label: this.translations.packets},
                    {value: 'errors', label: this.translations.errors},
                    {value: 'collisions', label: this.translations.collisions}
                ],
                default: ['bytes', 'packets', 'errors', 'collisions']
            },
            chart_metric: {
                title: this.translations.chart_metric,
                type: 'select',
                id: 'dashboard-plus-interface-statistics-chart-metric',
                options: [
                    {value: 'bytes', label: this.translations.traffic_bytes},
                    {value: 'packets', label: this.translations.traffic_packets}
                ],
                default: 'bytes'
            }
        };
    }

    onWidgetOptionsChanged() {
        this.configChanged = true;
    }

    onWidgetClose() {
        if (this.chart !== null) {
            this.chart.destroy();
        }
    }
}
