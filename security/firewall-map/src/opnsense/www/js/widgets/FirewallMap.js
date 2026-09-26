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
        this.geoSettings = null;
    }

    async _loadGeoSettings() {
        // only administrators may read (and change) the firewall-wide database settings
        try {
            this.geoSettings = await this.ajaxCall('/api/firewallmap/settings/get');
        } catch (_) {
            this.geoSettings = null;
        }
        return this.geoSettings;
    }

    _geoOptions(choices) {
        const geo = this.geoSettings;
        if (!geo?.provider) {
            return {};
        }
        const keySource = geo.database?.key_source;
        const keyHint = keySource === 'plugin' ? this.translations.key_set
            : keySource === 'alias' ? this.translations.key_from_alias : this.translations.key_none;
        return {
            geo_provider: {
                id: `${this.id}-option-geo-provider`,
                title: this.translations.geo_provider,
                type: 'select',
                options: choices([
                    ['maxmind', this.translations.provider_maxmind],
                    ['maxmind_paid', this.translations.provider_maxmind_paid],
                    ['dbip', this.translations.provider_dbip],
                ]),
                default: geo.provider,
            },
            geo_key: {
                id: `${this.id}-option-geo-key`,
                title: this.translations.geo_key,
                type: 'text',
                placeholder: keyHint,
                default: '',
            },
            geo_update_days: {
                id: `${this.id}-option-geo-update`,
                title: this.translations.geo_update,
                type: 'select',
                options: choices([['1', '1'], ['3', '3'], ['7', '7'], ['14', '14'], ['30', '30']].map(
                    ([value]) => [value, `${value} ${this.translations.days}`])),
                default: geo.update_days,
            },
        };
    }

    /**
     * The dashboard's options dialog only renders selects and text inputs. Once it is on screen,
     * show "Lookup hostnames" as a checkbox (backed by its select) and show the license key field
     * only while a MaxMind provider is selected.
     */
    _enhanceOptionsDialog() {
        if (this.enhancingDialog) {
            return;
        }
        this.enhancingDialog = true;
        const started = Date.now();
        const poll = () => {
            const $hostnames = $(`#${this.id}-option-hostnames`);
            const ready = $hostnames.length && $hostnames.closest('.bootstrap-select').length;
            if (!ready) {
                if (Date.now() - started < 3000) {
                    setTimeout(poll, 50);
                } else {
                    this.enhancingDialog = false;
                }
                return;
            }
            this.enhancingDialog = false;
            const $container = $hostnames.closest('.widget-option-container');
            $container.find('.bootstrap-select').hide();
            const $checkbox = $('<input type="checkbox" style="margin: 0 6px 0 0;">')
                .prop('checked', $hostnames.val() === '1')
                .on('change', (event) => $hostnames.val(event.target.checked ? '1' : '0'));
            $container.children('div').first().empty().append(
                $('<label style="font-weight: bold; cursor: pointer;"></label>')
                    .append($checkbox, document.createTextNode(this.translations.hostnames)),
                $('<div class="text-muted" style="font-size: .9em; margin: 0 0 4px 20px;"></div>')
                    .text(this.translations.hostnames_hint),
            );
            const $provider = $(`#${this.id}-option-geo-provider`);
            const $key = $(`#${this.id}-option-geo-key`).closest('.widget-option-container');
            const toggleKey = () => $key.toggle(($provider.val() || '').startsWith('maxmind'));
            $provider.on('change', toggleKey);
            toggleKey();
        };
        poll();
    }

    async getWidgetOptions() {
        const choices = (values) => values.map(([value, label]) => ({value, label}));
        if (this.geoSettings === null) {
            await this._loadGeoSettings();
        }
        this._enhanceOptionsDialog();
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
            hostnames: {
                id: `${this.id}-option-hostnames`,
                title: this.translations.hostnames,
                type: 'select',
                options: choices([['0', this.translations.labels_off], ['1', this.translations.hostnames]]),
                default: '0',
            },
            ...this._geoOptions(choices),
        };
    }

    async _settings() {
        const config = await this.getWidgetConfig();
        return {
            heavyTop: parseInt(config.heavy_top, 10),
            heavyRate: parseInt(config.heavy_rate, 10),
            maxArcs: parseInt(config.max_arcs, 10),
            labels: config.labels !== '0',
            hostnames: config.hostnames === '1',
        };
    }

    async onWidgetOptionsChanged(values) {
        if (this.geoSettings?.provider && values && 'geo_provider' in values) {
            const update = {
                provider: values.geo_provider,
                update_days: values.geo_update_days,
                license_key: (values.geo_key || '').trim(),
            };
            // firewall-wide values are saved to the plugin, never into this user's dashboard layout
            for (const key of ['geo_provider', 'geo_key', 'geo_update_days']) {
                delete values[key];
            }
            try {
                const result = await this.ajaxCall('/api/firewallmap/settings/set', JSON.stringify(update), 'POST');
                if (result.result !== 'saved') {
                    console.error('Firewall Map+: settings not saved', result);
                }
            } catch (error) {
                console.error('Firewall Map+: settings not saved', error);
            }
            await this._loadGeoSettings();
        }
        this.settings = await this._settings();
        this.renderer?.setSettings(this.settings);
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
                <div id="${this.id}-firewall-map-credit" style="position: absolute; right: 10px; bottom: 9px; z-index: 2; font-size: .75em; opacity: .7;"></div>
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
            this.settings = await this._settings();
            this.renderer = renderer.create(container, {theme, settings: this.settings});
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
            const query = this.settings?.hostnames ? '?hostnames=1' : '';
            const snapshot = await this.ajaxCall(`/api/firewallmap/flow/snapshot${query}`);
            if (snapshot.status === 'starting') {
                this._status(this.translations.collector_starting);
                return;
            }
            if (snapshot.status === 'no_database') {
                // no locations without a geolocation database: keep the map empty and say why
                this.renderer.render({flows: [], locations: []});
                this._status(snapshot.reason === 'maxmind_key_missing'
                    ? this.translations.key_missing : this.translations.database_downloading);
                return;
            }
            if (snapshot.status !== 'ok') {
                console.error('Firewall Map+: collector reported', snapshot);
                this._status(this.translations.data_unavailable);
                return;
            }
            this.renderer.render(snapshot);
            // DB-IP Lite is CC BY 4.0: credit it while it is the source
            $(`#${this.id}-firewall-map-credit`).html(snapshot.provider === 'dbip'
                ? '<a href="https://db-ip.com" target="_blank" rel="noopener">IP Geolocation by DB-IP</a>' : '');
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
