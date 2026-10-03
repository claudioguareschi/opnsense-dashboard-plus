/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
 * All rights reserved.
 */

const {escapeHtml, renderTitle, mergeOrder, makeSortable, isDragging, ensureTableStyle, DashboardPlusWidget} =
    await import(`./DashboardPlusCommon.js${new URL(import.meta.url).search}`);

// Tunnel devices have no media line; name the tunnel type instead.
const TUNNEL_TYPES = [
    [/^ipsec\d+$/i, 'ipsec_vti'],
    [/^wg\d+$/i, 'wireguard'],
    [/^ovpnc\d+$/i, 'openvpn_client'],
    [/^ovpns\d+$/i, 'openvpn_server'],
    [/^ovpn\d+$/i, 'openvpn']
];

export default class DashboardPlusInterfaces extends DashboardPlusWidget(BaseWidget) {
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
        ensureTableStyle();
        // Two lines per interface at any width: name and link on the first, addresses and
        // duplex under them, so nothing stacks or wraps mid-word when the column narrows.
        return $(`<div class="flextable-container dashboard-plus-table" id="${this._tableId()}" role="table"
            style="--dashboard-plus-columns: auto minmax(0, 1fr) auto; row-gap: 0;"></div>`);
    }

    _availableInterfaces(data) {
        return (data.rows || []).filter(intf =>
            intf.config && intf.enabled !== false &&
            !(intf.config.virtual && intf.config.virtual === '1')
        );
    }

    _orderedInterfaces() {
        const byId = new Map(this.cachedInterfaces.map(intf => [intf.identifier, intf]));
        const order = mergeOrder(this.currentConfig.interfaces, this.currentConfig.interfaces ?? [...byId.keys()]);
        return order.filter(id => byId.has(id)).map(id => byId.get(id));
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

    _linkState(intf) {
        const status = String(intf.status || '').toLowerCase();
        if (status === 'up') {
            return {icon: 'fa-arrow-up', color: '#2ca02c', title: this.translations.up};
        }
        if (status === 'down') {
            return {icon: 'fa-arrow-down', color: '#d62728', title: this.translations.down};
        }
        return {icon: 'fa-minus', color: '#777777', title: this.translations.unavailable};
    }

    _row(intf) {
        const link = this._linkState(intf);
        const media = this._media(intf);
        const addresses = [intf.addr4, intf.addr6].filter(Boolean);
        const icon = this._tunnelType(intf) !== null ? 'fa-exchange' : 'fa-sitemap';
        return `<div class="flextable-row dashboard-plus-row" role="row" data-sort-id="${escapeHtml(intf.identifier)}" draggable="true" title="${escapeHtml(this.translations.drag_to_reorder)}" style="row-gap: 0.15em; align-items: start; cursor: grab;">
            <div role="cell" style="grid-row: 1 / span 2;"><i class="fa ${icon}" aria-hidden="true"></i></div>
            <div role="cell" class="dashboard-plus-ellipsis dashboard-plus-interface-name">
                <a href="/interfaces.php?if=${encodeURIComponent(intf.identifier)}" title="${escapeHtml(intf.identifier)}">${escapeHtml(intf.description)}</a>
            </div>
            <div role="cell" class="dashboard-plus-nowrap" style="text-align: right;">
                <i class="fa ${link.icon}" title="${escapeHtml(link.title)}" style="color: ${link.color};"></i> ${escapeHtml(media.type)}
            </div>
            <div role="cell" class="dashboard-plus-muted dashboard-plus-small">${addresses.map(escapeHtml).join('<br>') || '—'}</div>
            <div role="cell" class="dashboard-plus-muted dashboard-plus-small dashboard-plus-nowrap" style="text-align: right;">${escapeHtml(media.duplex)}</div>
        </div>`;
    }

    _render() {
        const $table = $(`#${this._tableId()}`);
        if (!this.currentConfig || isDragging($table)) {
            return;
        }
        const rows = this._orderedInterfaces().map(intf => this._row(intf));
        $table.html(rows.join('') || `<div class="dashboard-plus-span" style="padding: 0.75em;">${escapeHtml(this.translations.no_interfaces)}</div>`);
    }

    async onMarkupRendered() {
        renderTitle(this);
        this.currentConfig = await this.getWidgetConfig();
        makeSortable($(`#${this._tableId()}`), {
            itemSelector: '.flextable-row[data-sort-id]',
            placeholderClass: 'flextable-row dashboard-plus-row',
            label: this.translations.drag_to_reorder,
            onReorder: order => {
                this.currentConfig.interfaces = mergeOrder(order, this.currentConfig.interfaces || order);
                this.setWidgetConfig(this.currentConfig);
            }
        });
        this.fitToContent();
    }

    async onWidgetTick() {
        const data = await this.ajaxCall('/api/interfaces/overview/interfaces_info');
        this.cachedInterfaces = this._availableInterfaces(data);
        this._render();
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
}
