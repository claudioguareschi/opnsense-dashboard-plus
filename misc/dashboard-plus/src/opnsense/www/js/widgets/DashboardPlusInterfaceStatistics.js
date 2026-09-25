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
        this.tickTimeout = 1;
        this.lastRefresh = 0;
    }

    getGridOptions() {
        return {sizeToContent: 650};
    }

    getMarkup() {
        const $container = $('<div class="dashboard-plus-interface-statistics"></div>');
        const $table = this.createTable('dashboard-plus-interface-statistics-table', {
            // Use the stock dashboard table so its 95% width, padding and
            // separators match Interfaces+ and the native widgets.
            headerPosition: 'none'
        });
        const $header = $('<div class="flextable-header dashboard-plus-interface-statistics-header" role="row"></div>');
        [
            this.translations.interface,
            this.translations.bytes,
            this.translations.packets,
            this.translations.errors,
            this.translations.collisions_short
        ].forEach(title => $header.append(`<div class="flex-cell" role="columnheader">${title}</div>`));
        $table.prepend($header);
        $container.append($table);
        return $container;
    }

    _pair(first, second) {
        return `<div style="font-size: 0.92em; line-height: 1.4;">${this.translations.in}: ${first}<br>${this.translations.out}: ${second}</div>`;
    }

    _escape(value) {
        return $('<div>').text(value ?? '').html();
    }

    _applyConfig(config) {
        this._applyFieldVisibility(config);
    }

    _applyFieldVisibility(config) {
        const visibleFields = config.fields || ['bytes', 'packets', 'errors', 'collisions'];
        const fieldColumns = {bytes: 1, packets: 2, errors: 3, collisions: 4};
        const widths = {
            0: ['100%'],
            1: ['42%', '58%'],
            2: ['32%', '34%', '34%'],
            3: ['27%', '24.5%', '24.5%', '24%'],
            4: ['27%', '21%', '21%', '20%', '11%']
        }[visibleFields.length];
        const $table = $('#dashboard-plus-interface-statistics-table');
        $table.children('.flextable-header, .flextable-row').each((_, row) => {
            let visibleIndex = 0;
            $(row).children('.flex-cell').each((column, cell) => {
                const field = Object.keys(fieldColumns).find(key => fieldColumns[key] === column);
                const visible = !field || visibleFields.includes(field);
                $(cell).toggle(visible).css({
                    width: visible ? widths[visibleIndex++] : '',
                    textAlign: column === fieldColumns.collisions ? 'right' : 'left'
                });
            });
        });
    }

    _clearTable() {
        const id = 'dashboard-plus-interface-statistics-table';
        $(`#${id}`).children('.flextable-row').remove();
        this.tables[id].data = [];
    }

    _orderedInterfaces(interfaces, config) {
        const order = config.interfaces || Object.keys(interfaces);
        return order.filter(id => interfaces[id]).map(id => [id, interfaces[id]]);
    }

    _saveInterfaceOrder() {
        const order = $('#dashboard-plus-interface-statistics-table').children('.flextable-row')
            .map((_, row) => $(row).data('interface')).get();
        this.currentConfig.interfaces = order;
        this.setWidgetConfig(this.currentConfig);
        $('#save-grid').show();
    }

    _makeRowsSortable() {
        const $table = $('#dashboard-plus-interface-statistics-table');
        let $draggedRow = null;
        let $placeholder = null;
        const clearDragState = () => {
            $draggedRow?.css({opacity: '', outline: ''});
            $placeholder?.remove();
            $draggedRow = null;
            $placeholder = null;
        };
        $table.on('mousedown', '.flextable-row .flex-cell:nth-child(1)', event => event.stopPropagation());
        $table.on('dragstart', '.flextable-row .flex-cell:nth-child(1)', event => {
            $draggedRow = $(event.currentTarget).closest('.flextable-row');
            $draggedRow.css({opacity: 0.4, outline: '2px dashed #d94f00'});
            $placeholder = $('<div class="flextable-row dashboard-plus-interface-statistics-drop-placeholder" aria-label="Drop interface here"></div>')
                .css({
                    height: $draggedRow.outerHeight(),
                    border: '2px dashed #d94f00',
                    background: 'rgba(217, 79, 0, 0.08)'
                });
            event.originalEvent.dataTransfer.effectAllowed = 'move';
            event.stopPropagation();
        });
        $table.on('dragover', event => {
            event.preventDefault();
            event.originalEvent.dataTransfer.dropEffect = 'move';
            const $target = $(event.target).closest('.flextable-row');
            if (!$draggedRow || !$target.length || $target[0] === $draggedRow[0]) {
                return;
            }
            const halfway = $target.offset().top + ($target.outerHeight() / 2);
            event.originalEvent.clientY < halfway ? $target.before($placeholder) : $target.after($placeholder);
        });
        $table.on('drop', event => {
            event.preventDefault();
            if ($draggedRow && $placeholder?.parent().length) {
                $placeholder.replaceWith($draggedRow);
                this._saveInterfaceOrder();
            }
            clearDragState();
        });
        $table.on('dragend', '.flextable-row .flex-cell:nth-child(1)', clearDragState);
    }

    async onMarkupRendered() {
        $(`#${this.id}-title`).html(`<b>${this.translations.dashboard_title}</b>`);
        this.currentConfig = await this.getWidgetConfig();
        this._applyConfig(this.currentConfig);
        this._makeRowsSortable();
    }

    async onWidgetTick() {
        if (this.configChanged || !this.currentConfig) {
            this.currentConfig = await this.getWidgetConfig();
            this._applyConfig(this.currentConfig);
            this._clearTable();
            this.configChanged = false;
            this.lastRefresh = 0;
        }
        const refreshInterval = (parseInt(this.currentConfig.refresh_interval, 10) || 5) * 1000;
        if (this.lastRefresh && Date.now() - this.lastRefresh < refreshInterval) {
            return;
        }
        this.lastRefresh = Date.now();
        const data = await this.ajaxCall('/api/diagnostics/traffic/interface');
        const config = this.currentConfig;
        const rows = [];
        const orderedInterfaces = this._orderedInterfaces(data.interfaces || {}, config);
        orderedInterfaces.forEach(([id, intf]) => {
            const received = parseInt(intf['bytes received']) || 0;
            const transmitted = parseInt(intf['bytes transmitted']) || 0;
            const packetsReceived = parseInt(intf['packets received']) || 0;
            const packetsTransmitted = parseInt(intf['packets transmitted']) || 0;
            const errorsReceived = parseInt(intf['input errors']) || 0;
            const errorsTransmitted = parseInt(intf['output errors']) || 0;
            rows.push([
                `<a href="/interfaces.php?if=${encodeURIComponent(id)}">${this._escape(intf.name)}</a>`,
                this._pair(this._formatBytes(received) || '0', this._formatBytes(transmitted) || '0'),
                this._pair(packetsReceived.toLocaleString(), packetsTransmitted.toLocaleString()),
                this._pair(errorsReceived.toLocaleString(), errorsTransmitted.toLocaleString()),
                `<span style="font-size: 0.92em;">${(parseInt(intf.collisions) || 0).toLocaleString()}</span>`
            ]);
        });
        super.updateTable('dashboard-plus-interface-statistics-table', rows);
        $('#dashboard-plus-interface-statistics-table').children('.flextable-row').each((index, row) => {
            $(row).data('interface', orderedInterfaces[index][0]);
            $(row).children('.flex-cell').eq(0).attr({
                draggable: 'true', title: this.translations.drag_to_reorder
            }).css('cursor', 'grab');
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
            },
            refresh_interval: {
                title: this.translations.refresh_interval,
                type: 'select',
                id: 'dashboard-plus-interface-statistics-refresh-interval',
                options: [
                    {value: '1', label: this.translations.second_1},
                    {value: '5', label: this.translations.seconds_5},
                    {value: '10', label: this.translations.seconds_10}
                ],
                default: '5'
            }
        };
    }

    onWidgetOptionsChanged() {
        this.configChanged = true;
    }
}
