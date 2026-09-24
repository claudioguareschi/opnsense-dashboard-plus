/*
 * Copyright (C) 2026 Claudio Guareschi
 * All rights reserved.
 */

export default class DashboardPlusInterfaceStatistics extends BaseTableWidget {
    constructor(config) {
        super(config);
        this.configurable = true;
        this.configChanged = false;
        this.currentConfig = null;
    }

    getGridOptions() {
        return {sizeToContent: 650};
    }

    getMarkup() {
        const $container = $('<div class="dashboard-plus-interface-statistics"></div>');
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

        // The core table uses 100px minimum columns, which makes five columns
        // wrap in a standard dashboard cell.  Keep the compact statistics table
        // on one line, while still redistributing its width when fields are hidden.
        const columns = {
            0: '100%',
            1: '42% 58%',
            2: '32% 34% 34%',
            3: '27% 24.5% 24.5% 24%',
            4: '22% 22% 21% 20% 15%'
        }[visibleFields.length];
        $table.children('.grid-header-container, .grid-row').css('grid-template-columns', columns);
    }

    _clearTable() {
        const id = 'dashboard-plus-interface-statistics-table';
        $(`#${id}`).children('.grid-row').remove();
        this.tables[id].data = [];
    }

    async onMarkupRendered() {
        $(`#${this.id}-title`).html(`<b>${this.translations.dashboard_title}</b>`);
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
        Object.entries(data.interfaces || {}).forEach(([id, intf]) => {
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
        });
        this._applyFieldVisibility(config);
    }

    async getWidgetOptions() {
        const data = await this.ajaxCall('/api/diagnostics/traffic/interface');
        const interfaces = Object.entries(data.interfaces || {}).map(([id, intf]) => ({value: id, label: intf.name}));
        return {
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
            }
        };
    }

    onWidgetOptionsChanged() {
        this.configChanged = true;
    }
}
