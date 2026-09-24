/*
 * Copyright (C) 2026 Claudio Guareschi
 * All rights reserved.
 */

export default class DashboardPlusInterfaces extends BaseTableWidget {
    constructor(config) {
        super(config);
        this.configurable = true;
        this.cachedInterfaces = [];
        this.currentConfig = null;
        this.configChanged = false;
    }

    getGridOptions() {
        return {sizeToContent: 650};
    }

    getMarkup() {
        const $container = $('<div class="dashboard-plus-interfaces"></div>');
        const $table = this.createTable('dashboard-plus-interfaces-table', {
            // Match the stock Interfaces widget: its flex table owns the
            // native 95% width and row gutters.
            headerPosition: 'none'
        });
        $container.append($table);
        return $container;
    }

    _escape(value) {
        return $('<div>').text(value ?? '').html();
    }

    _availableInterfaces(data) {
        return (data.rows || []).filter(intf =>
            intf.config && intf.enabled !== false &&
            !(intf.config.virtual && intf.config.virtual === '1')
        );
    }

    _orderedInterfaces(interfaces, config) {
        const order = config.interfaces || interfaces.map(intf => intf.identifier);
        return interfaces.filter(intf => order.includes(intf.identifier)).sort((left, right) =>
            order.indexOf(left.identifier) - order.indexOf(right.identifier)
        );
    }

    _media(intf) {
        const media = $('<textarea>').html(String(intf.media ?? intf.cell_mode ?? '')).text().trim();
        if (!media) {
            return {type: '—', duplex: ''};
        }
        const match = media.match(/^\s*([^<]+?)(?:\s*<([^>]+)>)?\s*$/);
        const type = (match?.[1]?.trim() || media).replace(/base/gi, 'Base');
        const attributes = (match?.[2] || '').split(',').map(attribute => attribute.trim());
        const duplex = attributes.find(attribute => attribute.includes('duplex'))?.replace('-', ' ');
        return {type, duplex: duplex || ''};
    }

    _link(intf) {
        const status = String(intf.status || '').toLowerCase();
        const state = status === 'up' ? {
            icon: 'fa-arrow-up', color: '#2ca02c', title: this.translations.up
        } : status === 'down' ? {
            icon: 'fa-arrow-down', color: '#d62728', title: this.translations.down
        } : {
            icon: 'fa-minus', color: '#777777', title: this.translations.unavailable
        };
        const media = this._media(intf);
        return `<div style="display: flex; align-items: flex-start; gap: 0.55em; text-align: left; line-height: 1.35;">
            <i class="fa ${state.icon}" title="${state.title}" style="color: ${state.color}; margin-top: 0.1em;"></i>
            <span><div>${this._escape(media.type)}</div>${media.duplex ? `<div>${this._escape(media.duplex)}</div>` : ''}</span>
        </div>`;
    }

    _identity(intf) {
        return `<div style="display: flex; align-items: center; gap: 0.55em; min-height: 2.7em; text-align: left;">
            <i class="fa fa-sitemap" aria-hidden="true"></i>
            <a href="/interfaces.php?if=${encodeURIComponent(intf.identifier)}" title="${this._escape(intf.identifier)}">${this._escape(intf.description)}</a>
        </div>`;
    }

    _addresses(intf) {
        return [intf.addr4, intf.addr6].filter(Boolean).map(address =>
            `<div>${this._escape(address)}</div>`
        ).join('') || '—';
    }

    _saveInterfaceOrder() {
        const order = $('#dashboard-plus-interfaces-table').children('.flextable-row')
            .map((_, row) => $(row).data('interface')).get();
        const selected = this.currentConfig.interfaces || order;
        this.currentConfig.interfaces = [
            ...order.filter(identifier => selected.includes(identifier)),
            ...selected.filter(identifier => !order.includes(identifier))
        ];
        this.setWidgetConfig(this.currentConfig);
        $('#save-grid').show();
    }

    _makeRowsSortable() {
        const $table = $('#dashboard-plus-interfaces-table');
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
            $placeholder = $('<div class="flextable-row dashboard-plus-interfaces-drop-placeholder" aria-label="Drop interface here"></div>')
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
        this._makeRowsSortable();
    }

    async onWidgetTick() {
        if (this.configChanged || !this.currentConfig) {
            this.currentConfig = await this.getWidgetConfig();
            this.configChanged = false;
        }
        const data = await this.ajaxCall('/api/interfaces/overview/interfaces_info');
        const interfaces = this._availableInterfaces(data);
        this.cachedInterfaces = interfaces;
        const orderedInterfaces = this._orderedInterfaces(interfaces, this.currentConfig);
        const $table = $('#dashboard-plus-interfaces-table');
        if (!orderedInterfaces.length) {
            $table.children('.flextable-row, .dashboard-plus-interfaces-empty').remove();
            $table.append(`<div class="dashboard-plus-interfaces-empty" style="padding: 0.75em;">${this.translations.no_interfaces}</div>`);
            return;
        }

        $table.children('.dashboard-plus-interfaces-empty').remove();

        const rows = orderedInterfaces.map(intf => [
            this._identity(intf), this._link(intf), this._addresses(intf)
        ]);
        super.updateTable('dashboard-plus-interfaces-table', rows);
        $table.children('.flextable-row').each((index, row) => {
            const $cells = $(row).children();
            $(row).data('interface', orderedInterfaces[index].identifier);
            $cells.css('text-align', 'left');
            $cells.eq(0).attr({draggable: 'true', title: this.translations.drag_to_reorder})
                .css('cursor', 'grab');
        });
    }

    async getWidgetOptions() {
        const interfaces = this.cachedInterfaces.length ? this.cachedInterfaces :
            this._availableInterfaces(await this.ajaxCall('/api/interfaces/overview/interfaces_info'));
        return {
            interfaces: {
                title: this.translations.interfaces,
                type: 'select_multiple',
                id: 'dashboard-plus-interfaces-selection',
                options: interfaces.map(intf => ({value: intf.identifier, label: intf.description})),
                default: interfaces.map(intf => intf.identifier)
            }
        };
    }

    onWidgetOptionsChanged() {
        this.configChanged = true;
    }
}
