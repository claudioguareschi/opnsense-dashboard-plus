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
        try {
            await this.loadingRenderer;
        } catch (error) {
            this.loadingRenderer = null;
            throw new Error(`renderer script failed to load (${error?.status || ''} ${error?.statusText || error})`);
        }
        const renderer = window.FirewallMapRenderer;
        if (typeof renderer?.create !== 'function') {
            throw new Error('renderer script loaded but did not expose FirewallMapRenderer.create()');
        }
        return renderer;
    }

    _hasWebGL() {
        try {
            const canvas = document.createElement('canvas');
            return !!(canvas.getContext('webgl2') || canvas.getContext('webgl'));
        } catch (_) {
            return false;
        }
    }

    _status(message) {
        $(`#${this.id}-firewall-map-status`).text(message || '');
    }

    async onMarkupRendered() {
        $(`#${this.id}-title`).html(`<b>${this.translations.dashboard_title}</b>`);
        if (!this._hasWebGL()) {
            this._status(this.translations.webgl_unavailable);
            return;
        }
        try {
            const renderer = await this._loadRenderer();
            this.renderer = renderer.create($(`#${this.id}-firewall-map-canvas`)[0]);
        } catch (error) {
            console.error('Firewall Map+: renderer initialisation failed', error);
            this._status(`${this.translations.renderer_failed}: ${error?.message || error}`);
            return;
        }
        await this.onWidgetTick();
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
        } catch (error) {
            console.error('Firewall Map+: flow update failed', error);
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
