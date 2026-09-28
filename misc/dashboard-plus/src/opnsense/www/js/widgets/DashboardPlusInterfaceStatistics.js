/*
 * Copyright (C) 2026 Claudio Guareschi
 * All rights reserved.
 */

const {escapeHtml, renderTitle, mergeOrder, makeSortable, isDragging, sizeToContent} =
    await import(`./DashboardPlusCommon.js${new URL(import.meta.url).search}`);

const FIELDS = ['bytes', 'packets', 'errors', 'collisions'];

export default class DashboardPlusInterfaceStatistics extends BaseWidget {
    constructor(config) {
        super(config);
        this.configurable = true;
        this.currentConfig = null;
        this.tickTimeout = 1;
        this.lastRefresh = 0;
        this.interfaces = null;
    }

    getGridOptions() {
        return {sizeToContent: 650};
    }

    _tableId() {
        return `${this.id}-table`;
    }

    getMarkup() {
        // The stock flextable classes give the native width, separators and hover. The table
        // is one grid and each row a subgrid of it, so every row shares the same column widths
        // and a gutter at any width.
        const table = `#${this._tableId()}`;
        return $(`
            <div>
                <style>
                    ${table} { display: grid; grid-template-columns: var(--dashboard-plus-ifstats-columns); column-gap: 0.9em; }
                    ${table} > .dashboard-plus-ifstats-row { grid-column: 1 / -1; display: grid; grid-template-columns: subgrid; align-items: center; text-align: left; }
                    ${table} .dashboard-plus-ifstats-row > div { min-width: 0; word-break: normal; }
                    ${table} .dashboard-plus-ifstats-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
                    ${table} .dashboard-plus-ifstats-number { text-align: right; white-space: nowrap; font-variant-numeric: tabular-nums; }
                    ${table} .dashboard-plus-ifstats-direction { opacity: 0.7; white-space: nowrap; }
                    ${table} .dashboard-plus-ifstats-pair { font-size: 0.92em; line-height: 1.4; }
                </style>
                <div class="flextable-container" id="${this._tableId()}" role="table"></div>
            </div>
        `);
    }

    _fields() {
        const fields = this.currentConfig?.fields;
        return FIELDS.filter(field => !Array.isArray(fields) || fields.includes(field));
    }

    _headerRow(fields) {
        const titles = {
            bytes: this.translations.bytes,
            packets: this.translations.packets,
            errors: this.translations.errors,
            collisions: this.translations.collisions_short
        };
        const cells = fields.map(field => `<div class="dashboard-plus-ifstats-number" role="columnheader"${field === 'collisions' ? ` title="${escapeHtml(this.translations.collisions)}"` : ''}>${escapeHtml(titles[field])}</div>`);
        return `<div class="flextable-header dashboard-plus-ifstats-row" role="row">
            <div role="columnheader">${escapeHtml(this.translations.interface)}</div><div></div>${cells.join('')}
        </div>`;
    }

    _pair(first, second) {
        return `<div class="dashboard-plus-ifstats-number dashboard-plus-ifstats-pair" role="cell">${escapeHtml(first)}<br>${escapeHtml(second)}</div>`;
    }

    _row(id, intf, fields) {
        const number = key => parseInt(intf[key], 10) || 0;
        const cells = {
            bytes: () => this._pair(this._formatBytes(number('bytes received')) || '0 B', this._formatBytes(number('bytes transmitted')) || '0 B'),
            packets: () => this._pair(number('packets received').toLocaleString(), number('packets transmitted').toLocaleString()),
            errors: () => this._pair(number('input errors').toLocaleString(), number('output errors').toLocaleString()),
            // FreeBSD counts collisions for the interface as a whole, not per direction.
            collisions: () => `<div class="dashboard-plus-ifstats-number dashboard-plus-ifstats-pair" role="cell">${number('collisions').toLocaleString()}<br>&nbsp;</div>`
        };
        return `<div class="flextable-row dashboard-plus-ifstats-row" role="row" data-sort-id="${escapeHtml(id)}">
            <div class="dashboard-plus-ifstats-name" role="cell" draggable="true" title="${escapeHtml(`${intf.name} · ${this.translations.drag_to_reorder}`)}" style="cursor: grab;">
                <a href="/interfaces.php?if=${encodeURIComponent(id)}">${escapeHtml(intf.name)}</a>
            </div>
            <div class="dashboard-plus-ifstats-direction dashboard-plus-ifstats-pair">${escapeHtml(this.translations.in)}<br>${escapeHtml(this.translations.out)}</div>
            ${fields.map(field => cells[field]()).join('')}
        </div>`;
    }

    _render() {
        const $table = $(`#${this._tableId()}`);
        if (!this.interfaces || isDragging($table)) {
            return;
        }
        const fields = this._fields();
        const selected = mergeOrder(this.currentConfig.interfaces, this.currentConfig.interfaces || Object.keys(this.interfaces));
        const rows = selected.filter(id => this.interfaces[id]).map(id => this._row(id, this.interfaces[id], fields));
        $table[0].style.setProperty(
            '--dashboard-plus-ifstats-columns',
            `minmax(4.5em, 1fr) auto${' auto'.repeat(fields.length)}`
        );
        $table.html(this._headerRow(fields) + rows.join(''));
    }

    async onMarkupRendered() {
        renderTitle(this);
        this.currentConfig = await this.getWidgetConfig();
        makeSortable($(`#${this._tableId()}`), {
            itemSelector: '.flextable-row',
            handleSelector: '.dashboard-plus-ifstats-name',
            placeholderClass: 'flextable-row dashboard-plus-ifstats-row',
            label: this.translations.drag_to_reorder,
            onReorder: order => {
                this.currentConfig.interfaces = mergeOrder(order, this.currentConfig.interfaces);
                this.setWidgetConfig(this.currentConfig);
            }
        });
        sizeToContent(this);
    }

    async onWidgetTick() {
        const refreshInterval = (parseInt(this.currentConfig.refresh_interval, 10) || 5) * 1000;
        if (this.lastRefresh && Date.now() - this.lastRefresh < refreshInterval) {
            return;
        }
        this.lastRefresh = Date.now();
        const data = await this.ajaxCall('/api/diagnostics/traffic/interface');
        this.interfaces = data.interfaces || {};
        this._render();
    }

    async getWidgetOptions() {
        const source = this.interfaces ?? (await this.ajaxCall('/api/diagnostics/traffic/interface')).interfaces ?? {};
        const interfaces = Object.entries(source).map(([id, intf]) => ({value: id, label: intf.name}));
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
                options: FIELDS.map(field => ({value: field, label: this.translations[field]})),
                default: FIELDS
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

    async onWidgetOptionsChanged() {
        const previous = this.currentConfig?.interfaces;
        const config = await this.getWidgetConfig();
        // The dialog lists the selection in option order; keep the dragged order.
        config.interfaces = mergeOrder(previous, config.interfaces);
        this.setWidgetConfig(config);
        this.currentConfig = config;
        this._render();
    }
}
