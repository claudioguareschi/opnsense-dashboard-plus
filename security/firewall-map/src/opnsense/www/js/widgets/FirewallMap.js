/*
 * Copyright (C) 2026 Claudio Guareschi
 * All rights reserved.
 */

export default class FirewallMap extends BaseWidget {
    constructor(config) {
        super(config);
        this.tickTimeout = 5;
        this.renderer = null;
        this.loadingRenderer = null;
    }

    getGridOptions() {
        return {sizeToContent: 500};
    }

    getMarkup() {
        return $(`
            <div id="${this.id}-firewall-map" style="position: relative; height: 430px; overflow: hidden; border-radius: 8px; background: #07111f; box-shadow: inset 0 0 0 1px rgba(87, 155, 185, 0.28);">
                <div aria-hidden="true" style="pointer-events: none; position: absolute; inset: 0; z-index: 0; opacity: .4; background-image: linear-gradient(rgba(78, 136, 165, .16) 1px, transparent 1px), linear-gradient(90deg, rgba(78, 136, 165, .16) 1px, transparent 1px); background-size: 36px 36px;"></div>
                <div id="${this.id}-firewall-map-canvas" style="position: absolute; inset: 0; z-index: 1;"></div>
                <div id="${this.id}-firewall-map-status" style="position: absolute; left: 14px; bottom: 11px; z-index: 2; color: #a9c8d9; font-size: .82em; letter-spacing: .02em; text-shadow: 0 1px 2px #000;"></div>
            </div>
        `);
    }

    async _loadRenderer() {
        if (window.FirewallMapRenderer) {
            return window.FirewallMapRenderer;
        }
        if (!this.loadingRenderer) {
            this.loadingRenderer = $.getScript('/ui/js/firewall-map-renderer.js');
        }
        await this.loadingRenderer;
        return window.FirewallMapRenderer;
    }

    _status(message) {
        $(`#${this.id}-firewall-map-status`).text(message || '');
    }

    async onMarkupRendered() {
        $(`#${this.id}-title`).html(`<b>${this.translations.dashboard_title}</b>`);
        try {
            const renderer = await this._loadRenderer();
            if (!renderer?.create) {
                throw new Error('Flowmap.gl did not initialise');
            }
            this.renderer = renderer.create($(`#${this.id}-firewall-map-canvas`)[0]);
            await this.onWidgetTick();
        } catch (_) {
            this._status(this.translations.webgl_unavailable);
        }
    }

    async onWidgetTick() {
        if (!this.renderer) {
            return;
        }
        try {
            const snapshot = await this.ajaxCall('/api/firewallmap/flow/snapshot');
            if (snapshot.status !== 'ok') {
                this._status(this.translations.data_unavailable);
                return;
            }
            this.renderer.render(snapshot);
            const count = snapshot.flows?.length || 0;
            this._status(count ? `${count} ${this.translations.active_flows}` : this.translations.no_flows);
        } catch (_) {
            this._status(this.translations.data_unavailable);
        }
    }

    onWidgetResize() {
        this.renderer?.resize();
        return true;
    }

    onWidgetClose() {
        this.renderer?.destroy();
        this.renderer = null;
        super.onWidgetClose();
    }
}
