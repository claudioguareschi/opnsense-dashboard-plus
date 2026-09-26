/*
 * Copyright (C) 2026 Claudio Guareschi
 * All rights reserved.
 */

export default class FirewallMap extends BaseWidget {
    static FIREWALL_WIDE = ['geo_provider', 'geo_key', 'geo_update_days', 'abuseipdb_key', 'threat_lists'];

    constructor(config) {
        super(config);
        this.tickTimeout = 2;
        // the dashboard ticks on a fixed interval: never stack requests or abort-and-retry them,
        // a slow firewall would otherwise get a burst of cancelled HTTP/2 streams
        this.timeoutPeriod = 15000;
        this.retryLimit = 0;
        this.polling = false;
        this.renderer = null;
        this.loadingRenderer = null;
        this.configurable = true;
        this.geoSettings = null;
    }

    _settingsError(message) {
        BootstrapDialog.show({
            type: BootstrapDialog.TYPE_DANGER,
            title: this.translations.title,
            message: $('<div></div>').text(`${this.translations.settings_failed}: ${message}`),
            buttons: [{label: 'OK', action: (dialog) => dialog.close()}],
        });
    }

    async _loadGeoSettings() {
        // only administrators may read (and change) the firewall-wide database settings
        try {
            this.geoSettings = await this.ajaxCall('/api/firewallmap/settings/get');
        } catch (_) {
            this.geoSettings = null;
            return null;
        }
        try {
            this.threatTables = await this.ajaxCall('/api/firewallmap/settings/tables');
        } catch (_) {
            this.threatTables = {tables: [], automatic: []};
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
                    ['auto', this.translations.provider_auto],
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
                options: choices([...new Set(['1', '3', '7', '14', '30', String(geo.update_days)])]
                    .sort((a, b) => a - b).map((value) => [value, `${value} ${this.translations.days}`])),
                default: geo.update_days,
            },
            abuseipdb_key: {
                id: `${this.id}-option-abuseipdb-key`,
                title: this.translations.abuseipdb_key,
                type: 'text',
                placeholder: geo.abuseipdb_configured ? this.translations.key_set_abuse : this.translations.abuseipdb_none,
                default: '',
            },
            threat_lists: {
                id: `${this.id}-option-threat-lists`,
                title: this.translations.threat_lists,
                type: 'select_multiple',
                // nothing selected means automatic (feed tables and URL aliases used by block rules)
                options: choices((this.threatTables?.tables || []).map((table) => [table.name,
                    `${table.label || table.name}${table.curated && !table.installed ? ` ${this.translations.feed_will_install}` : ''}`
                    + `${(this.threatTables.automatic || []).includes(table.name) ? ' ★' : ''}`])),
                default: (geo.threat_lists || '').split(',').filter(Boolean),
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
            // yes/no options render as checkboxes backed by their (hidden) selects
            for (const [option, label] of [
                ['blocks', this.translations.blocks],
                ['hostnames', this.translations.hostnames],
                ['asn', this.translations.asn],
            ]) {
                const $select = $(`#${this.id}-option-${option}`);
                const $container = $select.closest('.widget-option-container');
                $container.find('.bootstrap-select').hide();
                const $checkbox = $('<input type="checkbox" style="margin: 0 6px 0 0;">')
                    .prop('checked', $select.val() === '1')
                    .on('change', (event) => $select.val(event.target.checked ? '1' : '0'));
                $container.children('div').first().empty().append(
                    $('<label style="font-weight: bold; cursor: pointer;"></label>')
                        .append($checkbox, document.createTextNode(label)),
                );
            }
            const $provider = $(`#${this.id}-option-geo-provider`);
            const $key = $(`#${this.id}-option-geo-key`).closest('.widget-option-container');
            const toggleKey = () => $key.toggle(($provider.val() || '') !== 'dbip');
            $provider.on('change', toggleKey);
            toggleKey();
        };
        poll();
    }

    /**
     * Firewall-wide values belong to the plugin, not to this user's dashboard layout: drop any copy
     * the dashboard saved with the layout, so the dialog always starts from the server's values.
     */
    async getWidgetConfig() {
        if (this.config?.widget) {
            for (const key of FirewallMap.FIREWALL_WIDE) {
                delete this.config.widget[key];
            }
        }
        return super.getWidgetConfig();
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
            blocks: {
                id: `${this.id}-option-blocks`,
                title: this.translations.blocks,
                type: 'select',
                options: choices([['1', this.translations.blocks], ['0', this.translations.labels_off]]),
                default: '1',
            },
            block_min: {
                id: `${this.id}-option-block-min`,
                title: this.translations.block_min,
                type: 'select',
                options: choices(['1', '2', '3', '5', '10'].map(
                    (value) => [value, value === '1' ? this.translations.every_attempt : `${value} ${this.translations.attempts}`])),
                default: '3',
            },
            hostnames: {
                id: `${this.id}-option-hostnames`,
                title: this.translations.hostnames,
                type: 'select',
                options: choices([['0', this.translations.labels_off], ['1', this.translations.hostnames]]),
                default: '0',
            },
            asn: {
                id: `${this.id}-option-asn`,
                title: this.translations.asn,
                type: 'select',
                options: choices([['1', this.translations.asn], ['0', this.translations.labels_off]]),
                default: '1',
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
            asn: config.asn !== '0',
            blocks: config.blocks !== '0',
            blockMin: parseInt(config.block_min ?? '3', 10) || 3,
        };
    }

    async onWidgetOptionsChanged(values) {
        if (this.geoSettings?.provider && values && 'geo_provider' in values) {
            const geo = this.geoSettings;
            // send only what the administrator changed, so an unrelated save never overwrites
            // another administrator's firewall-wide choices
            const update = {};
            if (values.geo_provider !== geo.provider) {
                update.provider = values.geo_provider;
            }
            if (String(values.geo_update_days) !== String(geo.update_days)) {
                update.update_days = values.geo_update_days;
            }
            if ((values.geo_key || '').trim()) {
                update.license_key = values.geo_key.trim();
            }
            if ((values.abuseipdb_key || '').trim()) {
                update.abuseipdb_key = values.abuseipdb_key.trim();
            }
            const values_lists = values.threat_lists || [];
            const lists = values_lists.join(',');
            // without the table list (lookup failed) the selection cannot be trusted
            if ((this.threatTables?.tables || []).length && lists !== (geo.threat_lists || '')) {
                update.threat_lists = lists;
            }
            // firewall-wide values are saved to the plugin, never into this user's dashboard layout
            for (const key of FirewallMap.FIREWALL_WIDE) {
                delete values[key];
            }
            // curated feeds picked here are created as URL table aliases before they are used
            const install = (this.threatTables?.tables || []).filter((table) =>
                table.curated && !table.installed && (values_lists || []).includes(table.name));
            for (const feed of install) {
                try {
                    const saved = await this.ajaxCall('/api/firewall/alias/add_item', JSON.stringify({alias: {
                        enabled: '1', name: feed.name, type: 'urltable', content: feed.url, updatefreq: '1',
                        description: `Firewall Map+ threat feed: ${feed.label}`,
                    }}), 'POST');
                    if (saved.result !== 'saved') {
                        throw new Error(JSON.stringify(saved.validations || saved));
                    }
                } catch (error) {
                    this._settingsError(`${feed.label}: ${error?.message || error?.statusText || error}`);
                }
            }
            if (install.length) {
                try {
                    await this.ajaxCall('/api/firewall/alias/reconfigure', JSON.stringify({}), 'POST');
                } catch (error) {
                    this._settingsError(error?.statusText || String(error));
                }
            }
            if (!Object.keys(update).length) {
                this.settings = await this._settings();
                this.renderer?.setSettings(this.settings);
                return;
            }
            try {
                const result = await this.ajaxCall('/api/firewallmap/settings/set', JSON.stringify(update), 'POST');
                if (result.result !== 'saved') {
                    console.error('Firewall Map+: settings not saved', result);
                    this._settingsError((result.validations || []).join(' ') || result.result);
                }
            } catch (error) {
                console.error('Firewall Map+: settings not saved', error);
                this._settingsError(error?.statusText || String(error));
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
        return window.FirewallMapRenderer.readTheme(document.getElementById(`${this.id}-firewall-map`));
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
        if (!this.renderer || this.polling) {
            return;
        }
        this.polling = true;
        try {
            const query = `?blocks_min=${this.settings?.blockMin ?? 3}${this.settings?.hostnames ? '&hostnames=1' : ''}`;
            const snapshot = await this.ajaxCall(`/api/firewallmap/flow/snapshot${query}`);
            if (snapshot.status === 'starting') {
                this._status(this.translations.collector_starting);
                return;
            }
            if (snapshot.status === 'no_database') {
                // no locations without a geolocation database: keep the map empty and say why
                this.renderer.render({flows: [], locations: []});
                this._status(snapshot.reason === 'maxmind_key_missing' ? this.translations.key_missing
                    : snapshot.error ? `${this.translations.database_failed}: ${snapshot.error}`
                    : this.translations.database_downloading);
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
            if (this.settings?.blocks) {
                const shown = (snapshot.blocks || []).length;
                const below = snapshot.blocks_below || 0;
                if (shown || below) {
                    status += ` · ${shown} ${this.translations.blocked_sources}`;
                    if (below) {
                        status += ` · ${below} ${this.translations.below_threshold}`;
                    }
                }
            }
            if (snapshot.carp === 'backup') {
                status += ` · ${this.translations.carp_backup}`;
            }
            this._status(status);
        } catch (error) {
            console.error('Firewall Map+: flow update failed', error);
            this._status(this.translations.data_unavailable);
        } finally {
            this.polling = false;
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
