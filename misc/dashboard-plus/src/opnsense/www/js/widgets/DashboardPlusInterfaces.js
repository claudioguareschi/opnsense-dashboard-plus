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
        const $container = $('<div class="dashboard-plus-interfaces" style="padding: 0 0.25em;"></div>');
        const $table = this.createTable('dashboard-plus-interfaces-table', {
            headerPosition: 'top',
            headers: ['', this.translations.interface, this.translations.link, this.translations.addresses]
        });
        // The grid needs columns for reliable alignment, but the row design is
        // deliberately self-explanatory, so it does not need a visible header.
        $table.find('.grid-header-container').hide();
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
        const media = String(intf.media ?? intf.cell_mode ?? '').trim();
        if (!media) {
            return '—';
        }
        const match = media.match(/^\s*([^<]+?)(?:\s*<([^>]+)>)?\s*$/);
        const type = match?.[1]?.trim() || media;
        const attributes = (match?.[2] || '').split(',').map(attribute => attribute.trim());
        const duplex = attributes.find(attribute => attribute.includes('duplex'))?.replace('-', ' ');
        return [type, duplex].filter(Boolean).join(' · ');
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
        return `<div style="display: flex; align-items: flex-start; gap: 0.55em; text-align: left; line-height: 1.35;">
            <i class="fa ${state.icon}" title="${state.title}" style="color: ${state.color}; margin-top: 0.1em;"></i>
            <span>${this._escape(this._media(intf))}</span>
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

    _setGridColumns() {
        $('#dashboard-plus-interfaces-table').children('.grid-row').css({
            gridTemplateColumns: '8% 28% 29% 35%',
            alignItems: 'center'
        });
    }

    _saveInterfaceOrder() {
        const order = $('#dashboard-plus-interfaces-table').children('.grid-row')
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
        $table.on('mousedown', '.grid-row .grid-item:nth-child(2)', event => event.stopPropagation());
        $table.on('dragstart', '.grid-row .grid-item:nth-child(2)', event => {
            $draggedRow = $(event.currentTarget).closest('.grid-row');
            $draggedRow.css({opacity: 0.4, outline: '2px dashed #d94f00'});
            $placeholder = $('<div class="grid-row dashboard-plus-interfaces-drop-placeholder" aria-label="Drop interface here"></div>')
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
            const $target = $(event.target).closest('.grid-row');
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
        $table.on('dragend', '.grid-row .grid-item:nth-child(2)', clearDragState);
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
            $table.html(`<div style="padding: 0.75em;">${this.translations.no_interfaces}</div>`);
            return;
        }

        const rows = orderedInterfaces.map(intf => [
            '', this._identity(intf), this._link(intf), this._addresses(intf)
        ]);
        // BaseTableWidget inserts new rows right after the header; reverse the
        // source so that the configured order remains the visual order.
        super.updateTable('dashboard-plus-interfaces-table', [...rows].reverse());
        $table.children('.grid-header-container').hide();
        $table.children('.grid-row').each((index, row) => {
            const $cells = $(row).children();
            $(row).data('interface', orderedInterfaces[index].identifier);
            $cells.css('text-align', 'left');
            $cells.eq(1).attr({draggable: 'true', title: this.translations.drag_to_reorder})
                .css('cursor', 'grab');
        });
        this._setGridColumns();
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
