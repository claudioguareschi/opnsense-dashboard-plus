/*
 * Copyright (C) 2026 Claudio Guareschi
 * All rights reserved.
 */

const {escapeHtml, renderTitle, mergeOrder, makeSortable, isDragging, sizeToContent, widthChanged} =
    await import(`./DashboardPlusCommon.js${new URL(import.meta.url).search}`);

// Tunnel devices have no media line; name the tunnel type instead.
const TUNNEL_TYPES = [
    [/^ipsec\d+$/i, 'ipsec_vti'],
    [/^wg\d+$/i, 'wireguard'],
    [/^ovpnc\d+$/i, 'openvpn_client'],
    [/^ovpns\d+$/i, 'openvpn_server'],
    [/^ovpn\d+$/i, 'openvpn']
];

export default class DashboardPlusInterfaces extends BaseTableWidget {
    constructor(config) {
        super(config);
        this.configurable = true;
        this.cachedInterfaces = [];
        this.currentConfig = null;
    }

    getGridOptions() {
        return {sizeToContent: 650};
    }

    _tableId() {
        return `${this.id}-table`;
    }

    _tunnelType(intf) {
        const device = String(intf.device || '');
        return TUNNEL_TYPES.find(([pattern]) => pattern.test(device))?.[1] ?? null;
    }

    getMarkup() {
        const $container = $('<div class="dashboard-plus-interfaces"></div>');
        const $table = this.createTable(this._tableId(), {
            // Match the stock Interfaces widget: its flex table owns the
            // native 95% width and row gutters.
            headerPosition: 'none'
        });
        $container.append($table);
        return $container;
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
            const tunnel = this._tunnelType(intf);
            return {type: tunnel ? this.translations[tunnel] : '—', duplex: ''};
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
            <i class="fa ${state.icon}" title="${escapeHtml(state.title)}" style="color: ${state.color}; margin-top: 0.1em;"></i>
            <span><div>${escapeHtml(media.type)}</div>${media.duplex ? `<div>${escapeHtml(media.duplex)}</div>` : ''}</span>
        </div>`;
    }

    _identity(intf) {
        const isTunnel = this._tunnelType(intf) !== null;
        return `<div style="display: flex; align-items: center; gap: 0.55em; min-height: 2.7em; text-align: left;">
            <i class="fa ${isTunnel ? 'fa-exchange' : 'fa-sitemap'}" aria-hidden="true"></i>
            <a href="/interfaces.php?if=${encodeURIComponent(intf.identifier)}" title="${escapeHtml(intf.identifier)}">${escapeHtml(intf.description)}</a>
        </div>`;
    }

    _addresses(intf) {
        return [intf.addr4, intf.addr6].filter(Boolean).map(address =>
            `<div>${escapeHtml(address)}</div>`
        ).join('') || '—';
    }

    async onMarkupRendered() {
        renderTitle(this);
        this.currentConfig = await this.getWidgetConfig();
        makeSortable($(`#${this._tableId()}`), {
            itemSelector: '.flextable-row',
            handleSelector: '.flex-cell:nth-child(1)',
            placeholderClass: 'flextable-row',
            label: this.translations.drag_to_reorder,
            onReorder: order => {
                this.currentConfig.interfaces = mergeOrder(order, this.currentConfig.interfaces || order);
                this.setWidgetConfig(this.currentConfig);
            }
        });
        sizeToContent(this);
    }

    async onWidgetTick() {
        const data = await this.ajaxCall('/api/interfaces/overview/interfaces_info');
        this.cachedInterfaces = this._availableInterfaces(data);
        this._render();
    }

    _render() {
        const $table = $(`#${this._tableId()}`);
        if (isDragging($table)) {
            return;
        }
        const orderedInterfaces = this._orderedInterfaces(this.cachedInterfaces, this.currentConfig);
        if (!orderedInterfaces.length) {
            $table.children('.flextable-row, .dashboard-plus-interfaces-empty').remove();
            $table.append(`<div class="dashboard-plus-interfaces-empty" style="padding: 0.75em;">${escapeHtml(this.translations.no_interfaces)}</div>`);
            return;
        }

        $table.children('.dashboard-plus-interfaces-empty').remove();

        const rows = orderedInterfaces.map(intf => [
            this._identity(intf), this._link(intf), this._addresses(intf)
        ]);
        super.updateTable(this._tableId(), rows);
        $table.children('.flextable-row').each((index, row) => {
            const $cells = $(row).children();
            $(row).attr('data-sort-id', orderedInterfaces[index].identifier);
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

    async onWidgetOptionsChanged() {
        const previous = this.currentConfig?.interfaces;
        const config = await this.getWidgetConfig();
        // The dialog lists the selection in option order; keep the dragged order.
        config.interfaces = mergeOrder(previous, config.interfaces);
        this.setWidgetConfig(config);
        this.currentConfig = config;
        this._render();
    }

    onWidgetResize(elem, width, height) {
        const layoutChanged = super.onWidgetResize(elem, width, height);
        return widthChanged(this, width) || layoutChanged;
    }
}
