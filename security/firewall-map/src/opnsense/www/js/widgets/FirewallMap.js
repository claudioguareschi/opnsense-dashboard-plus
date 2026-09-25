/*
 * Copyright (C) 2026 Claudio Guareschi
 * All rights reserved.
 */

export default class FirewallMap extends BaseWidget {
    constructor(config) {
        super(config);
        this.tickTimeout = 2;
        this.renderer = null;
        this.loadingRenderer = null;
        this.configurable = true;
    }

    async getWidgetOptions() {
        const choices = (values) => values.map(([value, label]) => ({value, label}));
        return {
            heavy_top: {
                id: `${this.id}-option-heavy-top`,
                title: this.translations.heavy_top,
                type: 'select',
                options: choices([['0', this.translations.none], ['3', '3'], ['5', '5'], ['10', '10']]),
                default: '5',
            },
            heavy_rate: {
                id: `${this.id}-option-heavy-rate`,
                title: this.translations.heavy_rate,
                type: 'select',
                options: choices([
                    ['100000', '100 KB/s'], ['500000', '500 KB/s'], ['1000000', '1 MB/s'],
                    ['5000000', '5 MB/s'], ['10000000', '10 MB/s'],
                ]),
                default: '1000000',
            },
            max_arcs: {
                id: `${this.id}-option-max-arcs`,
                title: this.translations.max_arcs,
                type: 'select',
                options: choices([['50', '50'], ['100', '100'], ['150', '150']]),
                default: '100',
            },
            labels: {
                id: `${this.id}-option-labels`,
                title: this.translations.labels,
                type: 'select',
                options: choices([['1', this.translations.labels_zoomed], ['0', this.translations.labels_off]]),
                default: '1',
            },
        };
    }

    async _settings() {
        const config = await this.getWidgetConfig();
        return {
            heavyTop: parseInt(config.heavy_top, 10),
            heavyRate: parseInt(config.heavy_rate, 10),
            maxArcs: parseInt(config.max_arcs, 10),
            labels: config.labels !== '0',
        };
    }

    async onWidgetOptionsChanged() {
        this.renderer?.setSettings(await this._settings());
    }

    getGridOptions() {
        return {sizeToContent: 500};
    }

    getMarkup() {
        // Colours are applied from the active theme in _applyTheme() once the widget is in the page.
        return $(`
            <div id="${this.id}-firewall-map" style="position: relative; height: 430px; overflow: hidden; border-radius: 6px;">
                <div id="${this.id}-firewall-map-grid" aria-hidden="true" style="pointer-events: none; position: absolute; inset: 0; z-index: 0; background-size: 36px 36px;"></div>
                <div id="${this.id}-firewall-map-canvas" style="position: absolute; inset: 0; z-index: 1; text-align: left;"></div>
                <div id="${this.id}-firewall-map-status" style="position: absolute; left: 12px; bottom: 9px; z-index: 2; font-size: .82em; letter-spacing: .02em; pointer-events: none;"></div>
            </div>
        `);
    }

    /**
     * Read the dashboard theme's own colours (themes don't expose CSS variables): the widget
     * background, body text, the link colour (theme accent) and the success colour (green).
     */
    _readTheme() {
        const parse = (value) => {
            const match = /rgba?\(([^)]+)\)/.exec(value || '');
            if (!match) {
                return null;
            }
            const [r, g, b, a = 1] = match[1].split(',').map((part) => parseFloat(part));
            return a === 0 ? null : [r, g, b];
        };
        const map = document.getElementById(`${this.id}-firewall-map`);
        let background = null;
        for (let node = map?.parentElement; node && !background; node = node.parentElement) {
            background = parse(getComputedStyle(node).backgroundColor);
        }
        background = background || [255, 255, 255];
        const text = parse(getComputedStyle(map).color) || [55, 55, 54];
        const probeColor = (element) => {
            map.appendChild(element);
            const color = parse(getComputedStyle(element).color);
            element.remove();
            return color;
        };
        const link = document.createElement('a');
        link.href = '#';
        const accent = probeColor(link) || [192, 62, 20];
        const success = document.createElement('span');
        success.className = 'text-success';
        const green = probeColor(success) || [76, 175, 80];
        const luminance = (0.2126 * background[0] + 0.7152 * background[1] + 0.0722 * background[2]) / 255;
        return {dark: luminance < 0.5, background, text, accent, success: green};
    }

    _applyTheme(theme) {
        const rgba = (color, alpha) => `rgba(${color.join(', ')}, ${alpha})`;
        $(`#${this.id}-firewall-map`).css({
            background: `rgb(${theme.background.join(', ')})`,
            boxShadow: `inset 0 0 0 1px ${rgba(theme.accent, theme.dark ? 0.3 : 0.18)}`,
        });
        const line = rgba(theme.text, theme.dark ? 0.07 : 0.05);
        $(`#${this.id}-firewall-map-grid`).css('background-image',
            `linear-gradient(${line} 1px, transparent 1px), linear-gradient(90deg, ${line} 1px, transparent 1px)`);
        $(`#${this.id}-firewall-map-status`).css('color', rgba(theme.text, 0.75));
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
            const container = $(`#${this.id}-firewall-map-canvas`)[0];
            const theme = this._readTheme();
            this._applyTheme(theme);
            this.renderer = renderer.create(container, {theme, settings: await this._settings()});
            // deck.gl positions its canvas absolutely without left/top, so pin it explicitly
            // rather than relying on the static position (the dashboard centres widget text).
            $(container).children('canvas').css({left: 0, top: 0});
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
            if (snapshot.status === 'starting') {
                this._status(this.translations.collector_starting);
                return;
            }
            if (snapshot.status !== 'ok') {
                console.error('Firewall Map+: collector reported', snapshot);
                this._status(this.translations.data_unavailable);
                return;
            }
            this.renderer.render(snapshot);
            const count = snapshot.flows?.length || 0;
            let status = count ? `${count} ${this.translations.active_flows}` : this.translations.no_flows;
            if (snapshot.carp === 'backup') {
                status += ` · ${this.translations.carp_backup}`;
            }
            this._status(status);
        } catch (error) {
            console.error('Firewall Map+: flow update failed', error);
            this._status(this.translations.data_unavailable);
        }
    }

    onWidgetResize(elem, width) {
        // Keep a world-map aspect ratio (80N to 56S at full width) instead of a fixed height,
        // and let the dashboard size the cell to it.
        const map = document.getElementById(`${this.id}-firewall-map`);
        if (map && width) {
            map.style.height = `${Math.round(Math.min(640, Math.max(240, width * 0.6)))}px`;
        }
        this.renderer?.resize();
        return true;
    }

    onWidgetClose() {
        this.renderer?.destroy();
        this.renderer = null;
        super.onWidgetClose();
    }
}
