/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
 * All rights reserved.
 */

// A cap far above any widget: the map fits its content (see _fitToContent).
const AUTO_HEIGHT = 10000;
// follow traffic is the map's own toggle, remembered per browser (as on the full-size map)
const FOLLOW_KEY = 'firewallmap.widget.follow';
const CAMERA_ICON = '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 8.5A1.5 1.5 0 0 1 4.5 7h2.6l1.6-2.4h6.6L16.9 7h2.6A1.5 1.5 0 0 1 21 8.5v9A1.5 1.5 0 0 1 19.5 19h-15A1.5 1.5 0 0 1 3 17.5z"/><circle cx="12" cy="12.8" r="3.4"/></svg>';
const TARGET_ICON = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="7"/><circle cx="12" cy="12" r="2.5"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/></svg>';

function readStorage(key) {
    try {
        return window.localStorage.getItem(key);
    } catch (_) {
        return null;
    }
}

function writeStorage(key, value) {
    try {
        window.localStorage.setItem(key, value);
    } catch (_) {
        // private windows or blocked storage: the choice lasts for this page only
    }
}

export default class FirewallMap extends BaseWidget {
    static FIREWALL_WIDE = ['geo_provider', 'geo_key', 'geo_update_days', 'abuseipdb_key', 'threat_lists', 'blocklist_aliases'];

    constructor(config) {
        super(config);
        this.tickTimeout = 2;
        // the dashboard ticks on a fixed interval: never stack requests or abort-and-retry them,
        // a slow firewall would otherwise get a burst of canceled HTTP/2 streams
        this.timeoutPeriod = 15000;
        this.retryLimit = 0;
        this.polling = false;
        this.renderer = null;
        this.loadingRenderer = null;
        this.configurable = true;
        this.geoSettings = null;
        // set when the widget is removed: work still under way must not create anything after it
        this.closed = false;
        this.manualHeight = parseInt(config?.widget?.manual_height, 10) || null;
        this.heightManaged = false;
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
                default: '',
            },
            threat_lists: {
                id: `${this.id}-option-threat-lists`,
                title: this.translations.threat_lists,
                type: 'select_multiple',
                // nothing selected means automatic (feed tables and URL aliases used by block rules)
                options: choices((this.threatTables?.tables || []).map((table) => [table.name, table.label || table.name])),
                default: (geo.threat_lists || '').split(',').filter(Boolean),
            },
            blocklist_aliases: {
                id: `${this.id}-option-blocklist-aliases`,
                title: this.translations.blocklist_aliases,
                type: 'select',
                options: choices([['0', this.translations.none], ['1', this.translations.blocklist_aliases]]),
                default: geo.blocklist_aliases === '1' ? '1' : '0',
            },
        };
    }

    /** Help under the key fields, saying what is stored now (hints used to hide in placeholders). */
    _keyHelp() {
        const geo = this.geoSettings || {};
        const source = geo.database?.key_source;
        return {
            'geo-key': source === 'plugin' ? this.translations.key_set
                : source === 'alias' ? this.translations.key_from_alias : this.translations.key_none,
            'abuseipdb-key': geo.abuseipdb_configured ? this.translations.key_set_abuse : this.translations.abuseipdb_none,
            'threat-lists': this.translations.threat_lists_help,
            'blocklist-aliases': this.translations.blocklist_aliases_help,
        };
    }

    /**
     * The dashboard's options dialog only renders selects and text inputs. Once it is on screen:
     * yes/no options become checkboxes (backed by their selects), help text goes under the key
     * fields, the per-user and firewall-wide options get their own headings, and the license key
     * field shows only while a MaxMind provider is selected.
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
            const containerOf = (option) => $(`#${this.id}-option-${option}`).closest('.widget-option-container');
            for (const [option, label] of [
                ['blocks', this.translations.blocks],
                ['hostnames', this.translations.hostnames],
                ['asn', this.translations.asn],
                ['blocklist-aliases', this.translations.blocklist_aliases],
            ]) {
                const $select = $(`#${this.id}-option-${option}`);
                const $container = containerOf(option);
                $container.css({marginTop: '8px', marginBottom: '2px'});
                $container.find('.bootstrap-select').hide();
                // flex keeps the box on the text's line whatever the theme's checkbox margins are
                const $checkbox = $('<input type="checkbox" style="margin: 0 8px 0 0; flex: none; position: static;">')
                    .prop('checked', $select.val() === '1')
                    .on('change', (event) => $select.val(event.target.checked ? '1' : '0'));
                $container.children('div').first().empty().append(
                    $('<label style="display: flex; align-items: center; font-weight: bold; cursor: pointer; margin: 0; line-height: 20px;"></label>')
                        .append($checkbox, document.createTextNode(label)),
                );
            }
            const heading = (text) => $('<h4 style="margin: 14px 0 4px; font-size: 1.1em;"></h4>').text(text);
            containerOf('heavy-top').before(heading(this.translations.display_heading));
            containerOf('geo-provider').before(heading(this.translations.firewall_heading));
            for (const [option, help] of Object.entries(this._keyHelp())) {
                containerOf(option).append($('<div class="help-block" style="margin: 2px 0 0; font-size: .9em;"></div>').text(help));
            }
            const $provider = $(`#${this.id}-option-geo-provider`);
            const $key = containerOf('geo-key');
            const toggleKey = () => $key.toggle(($provider.val() || '') !== 'dbip');
            $provider.on('change', toggleKey);
            toggleKey();
        };
        poll();
    }

    /**
     * Firewall-wide values belong to the plugin, not to this user's dashboard layout: drop any copy
     * the dashboard saved with the layout, so the dialog always starts from the server's values.
     * A height the user chose is kept with the widget's options (see _recordManualResize).
     */
    async getWidgetConfig() {
        if (this.config?.widget) {
            for (const key of FirewallMap.FIREWALL_WIDE) {
                delete this.config.widget[key];
            }
        }
        const config = await super.getWidgetConfig();
        if (this.manualHeight) {
            config.manual_height = this.manualHeight;
        }
        return config;
    }

    setWidgetConfig(config) {
        const {manual_height: _, ...rest} = config ?? {};
        super.setWidgetConfig(this.manualHeight ? {...rest, manual_height: this.manualHeight} : rest);
    }

    async getWidgetOptions() {
        const choices = (values) => values.map(([value, label]) => ({value, label}));
        if (this.geoSettings === null) {
            await this._loadGeoSettings();
        }
        this._enhanceOptionsDialog();
        const defaults = window.FirewallMapRenderer?.DEFAULT_OPTIONS || {};
        return {
            heavy_top: {
                id: `${this.id}-option-heavy-top`,
                title: this.translations.heavy_top,
                type: 'select',
                options: choices([['0', this.translations.none], ['3', '3'], ['5', '5'], ['10', '10']]),
                default: String(defaults.heavyTop ?? 5),
            },
            heavy_rate: {
                id: `${this.id}-option-heavy-rate`,
                title: this.translations.heavy_rate,
                type: 'select',
                options: choices([
                    ['100000', '100 KB/s'], ['500000', '500 KB/s'], ['1000000', '1 MB/s'],
                    ['5000000', '5 MB/s'], ['10000000', '10 MB/s'],
                ]),
                default: String(defaults.heavyRate ?? 1000000),
            },
            max_arcs: {
                id: `${this.id}-option-max-arcs`,
                title: this.translations.max_arcs,
                type: 'select',
                options: choices([['50', '50'], ['100', '100'], ['150', '150']]),
                default: String(defaults.maxArcs ?? 100),
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
                default: String(defaults.blockMin ?? 3),
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
        // the renderer script parses the options; without it there is no map to configure
        if (!window.FirewallMapRenderer) {
            return null;
        }
        return {...window.FirewallMapRenderer.parseSettings(config), follow: this._follow()};
    }

    /** Follow traffic: the map's toggle wins; until it is used, the old dashboard option decides. */
    _follow() {
        const stored = readStorage(FOLLOW_KEY);
        return stored === null ? this.config?.widget?.follow === '1' : stored === '1';
    }

    _setFollow(on, tellRenderer = true) {
        writeStorage(FOLLOW_KEY, on ? '1' : '0');
        if (this.settings) {
            this.settings.follow = on;
        }
        $(`#${this.id}-firewall-map-follow`).attr('aria-pressed', String(on))
            .css({color: on ? 'var(--fwmap-accent)' : 'inherit', background: on ? 'rgba(128, 128, 128, .22)' : 'transparent'});
        if (tellRenderer) {
            this.renderer?.setFollow(on);
        }
    }

    /** The camera: a flash and a saved snapshot, then a note that opens it on the full-size map. */
    async _takeSnapshot() {
        const frame = document.getElementById(`${this.id}-firewall-map`);
        const host = window.FirewallMapRenderer?.host;
        if (!frame || !host) {
            return;
        }
        host.flash(frame);
        const $button = $(`#${this.id}-firewall-map-camera`).prop('disabled', true);
        try {
            // not ajaxCall: its 5 s timeout is shorter than the collector may take to answer, and
            // its retry on timeout would save the snapshot twice
            const result = await $.ajax({
                type: 'POST', url: '/api/firewallmap/snapshots/save', dataType: 'json',
                contentType: 'application/json', data: JSON.stringify({}), timeout: 30000,
            });
            if (result.result !== 'saved') {
                throw new Error(result.error || result.result);
            }
            const meta = result.snapshot;
            const time = new Date(meta.taken * 1000).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit', second: '2-digit'});
            const escape = window.FirewallMapRenderer.escapeHtml;
            host.toast(frame, `<span><b>${escape(this.translations.snapshot_saved)}</b> <span style="opacity: .7;">· ${escape(time)}</span></span>`
                + `<a href="/ui/firewallmap#snapshot=${encodeURIComponent(meta.id)}" class="btn btn-primary btn-xs">${escape(this.translations.snapshot_open)}</a>`);
        } catch (error) {
            console.error('Firewall Map+: snapshot not saved', error);
            host.toast(frame, `<span>${window.FirewallMapRenderer.escapeHtml(this.translations.snapshot_failed)}</span>`);
        } finally {
            $button.prop('disabled', false);
        }
    }

    /** Curated feeds picked in the dialog become URL table aliases; returns the names that failed. */
    /** Send only what the administrator changed, so an unrelated save never overwrites another's choices. */
    async _saveFirewallWide(values) {
        const geo = this.geoSettings;
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
        if (String(values.blocklist_aliases) !== String(geo.blocklist_aliases === '1' ? '1' : '0')) {
            update.blocklist_aliases = values.blocklist_aliases === '1' ? '1' : '0';
        }
        // curated feeds are downloaded by the plugin; their aliases follow "Maintain blocklist aliases"
        const lists = (values.threat_lists || []).join(',');
        // without the table list (lookup failed) the selection cannot be trusted
        if ((this.threatTables?.tables || []).length && lists !== (geo.threat_lists || '')) {
            update.threat_lists = lists;
        }
        if (!Object.keys(update).length) {
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

    async onWidgetOptionsChanged(values) {
        if (this.geoSettings?.provider && values && 'geo_provider' in values) {
            // firewall-wide values are saved to the plugin, never into this user's dashboard layout
            const firewallWide = {...values};
            for (const key of FirewallMap.FIREWALL_WIDE) {
                delete values[key];
            }
            await this._saveFirewallWide(firewallWide);
        }
        this.settings = await this._settings();
        this.renderer?.setSettings(this.settings);
    }

    getGridOptions() {
        return {sizeToContent: 500};
    }

    getMarkup() {
        // Colors are applied from the active theme once the widget is in the page.
        return $(`
            <div id="${this.id}-firewall-map" style="position: relative; height: 430px; overflow: hidden; border-radius: 6px; isolation: isolate;">
                <div id="${this.id}-firewall-map-grid" aria-hidden="true" style="pointer-events: none; position: absolute; inset: 0; z-index: 0; background-size: 36px 36px;"></div>
                <div id="${this.id}-firewall-map-canvas" style="position: absolute; inset: 0; z-index: 1; text-align: left;"></div>
                <div id="${this.id}-firewall-map-status" style="position: absolute; left: 12px; right: 150px; bottom: 9px; z-index: 2; font-size: .82em; letter-spacing: .02em; pointer-events: none; text-align: left;"></div>
                <div id="${this.id}-firewall-map-credit" style="position: absolute; right: 10px; bottom: 9px; z-index: 2; font-size: .75em; opacity: .7;"></div>
                <div style="position: absolute; right: 10px; top: 10px; z-index: 3; display: flex; flex-direction: column; border: 1px solid rgba(128, 128, 128, .3); border-radius: 6px; overflow: hidden; background: var(--fwmap-panel, #fff); color: var(--fwmap-text, inherit); box-shadow: 0 1px 3px rgba(0, 0, 0, .08);">
                    <button type="button" id="${this.id}-firewall-map-follow" aria-pressed="false" title="${this.translations.follow}" aria-label="${this.translations.follow}" style="width: 30px; height: 30px; padding: 0; border: 0; background: transparent; color: inherit; display: flex; align-items: center; justify-content: center;">${TARGET_ICON}</button>
                    <button type="button" id="${this.id}-firewall-map-camera" title="${this.translations.snapshot_take}" aria-label="${this.translations.snapshot_take}" style="width: 30px; height: 30px; padding: 0; border: 0; border-top: 1px solid rgba(128, 128, 128, .25); background: transparent; color: var(--fwmap-accent, inherit); display: flex; align-items: center; justify-content: center;">${CAMERA_ICON}</button>
                </div>
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

    _status(message) {
        $(`#${this.id}-firewall-map-status`).text(message || '');
    }

    /** The status line's words, in this widget's translations. */
    _text() {
        const t = this.translations;
        return {...t, starting: t.collector_starting, unavailable: t.data_unavailable, downloading: t.database_downloading};
    }

    _gridItem() {
        return document.querySelector(`.widget-${this.id}`)?.closest('.grid-stack-item') ?? null;
    }

    /**
     * The dashboard caps a widget at the height saved with the layout, so a map that grows with a
     * wider column (the side menu is collapsed) was cut off. Fit the map instead, unless the user
     * dragged the widget shorter: that height is kept with its options and the rest scrolls.
     */
    _fitToContent() {
        const node = this._gridItem()?.gridstackNode;
        if (node) {
            this.heightManaged = true;
            node.sizeToContent = this.manualHeight ?? AUTO_HEIGHT;
            this.config.callbacks?.updateGrid?.();
        }
    }

    /** The grid sets sizeToContent to the new height when the user finishes a resize. */
    _recordManualResize() {
        const item = this._gridItem();
        const node = item?.gridstackNode;
        const cap = this.manualHeight ?? AUTO_HEIGHT;
        if (!this.heightManaged || !node || !Number.isInteger(node.sizeToContent) || node.sizeToContent === cap) {
            return;
        }
        const content = item.querySelector('.grid-stack-item-content');
        const clipped = content && content.scrollHeight - content.clientHeight > 1;
        this.manualHeight = clipped ? node.sizeToContent : null;
        node.sizeToContent = this.manualHeight ?? AUTO_HEIGHT;
        this.setWidgetConfig(this.config.widget ?? {});
        $('#save-grid').show();
    }

    async onMarkupRendered() {
        $(`#${this.id}-title`).html(`<b>${this.translations.dashboard_title}</b>`);
        this._fitToContent();
        let renderer;
        try {
            renderer = await this._loadRenderer();
        } catch (error) {
            console.error('Firewall Map+: renderer initialization failed', error);
            this._status(`${this.translations.renderer_failed}: ${error?.message || error}`);
            return;
        }
        if (!renderer.host.hasWebGL()) {
            this._status(this.translations.webgl_unavailable);
            return;
        }
        const settings = await this._settings();
        // removed while the renderer or the settings loaded: create nothing
        if (this.closed) {
            return;
        }
        try {
            const frame = document.getElementById(`${this.id}-firewall-map`);
            const theme = renderer.readTheme(frame);
            renderer.host.applyTheme(frame, theme, {
                grid: document.getElementById(`${this.id}-firewall-map-grid`),
                overlays: [document.getElementById(`${this.id}-firewall-map-status`)],
            });
            this.settings = settings;
            const container = document.getElementById(`${this.id}-firewall-map-canvas`);
            // moving the map by hand ends follow mode, as on the full-size map
            this.renderer = renderer.create(container, {theme, settings, text: this.translations,
                onFollowChange: (on) => this._setFollow(on, false)});
            this._setFollow(settings.follow, false);
            $(`#${this.id}-firewall-map-follow`).on('click', () => this._setFollow(!this.settings.follow));
            $(`#${this.id}-firewall-map-camera`).on('click', () => this._takeSnapshot());
            // deck.gl positions its canvas absolutely without left/top, so pin it explicitly
            // rather than relying on the static position (the dashboard centers widget text).
            $(container).children('canvas').css({left: 0, top: 0});
        } catch (error) {
            console.error('Firewall Map+: renderer initialization failed', error);
            this._status(`${this.translations.renderer_failed}: ${error?.message || error}`);
            return;
        }
        await this.onWidgetTick();
    }

    async onWidgetTick() {
        // a dashboard left open in a background tab must not keep the collector sampling forever:
        // without requests it slows down and stops (or keeps only background recording)
        if (!this.renderer || this.polling || this.closed || document.hidden) {
            return;
        }
        this.polling = true;
        try {
            const host = window.FirewallMapRenderer.host;
            const snapshot = await this.ajaxCall(`/api/firewallmap/flow/snapshot${window.FirewallMapRenderer.snapshotQuery(this.settings)}`);
            // removed while the request was under way
            if (!this.renderer) {
                return;
            }
            const problem = host.problemText(snapshot, this._text());
            if (problem) {
                if (snapshot.status === 'no_database' || snapshot.status === 'too_many_states') {
                    // no locations or no sample: keep the map empty and say why
                    this.renderer.render({flows: [], locations: []});
                } else if (snapshot.status !== 'starting') {
                    console.error('Firewall Map+: collector reported', snapshot);
                }
                this._status(problem);
                return;
            }
            this.renderer.render(snapshot);
            $(`#${this.id}-firewall-map-credit`).html(host.creditHtml(snapshot.provider));
            const parts = host.statusParts(snapshot, snapshot, this.settings, this._text());
            // the parts are HTML-escaped: set them as HTML, not text
            $(`#${this.id}-firewall-map-status`).html(parts.join(' · '));
        } catch (error) {
            console.error('Firewall Map+: flow update failed', error);
            this._status(this.translations.data_unavailable);
        } finally {
            this.polling = false;
        }
    }

    onWidgetResize(elem, width) {
        this._recordManualResize();
        // Keep a world-map aspect ratio (80N to 56S at full width) instead of a fixed height; the
        // widget fits it (see _fitToContent), so the status line is never cut off.
        const map = document.getElementById(`${this.id}-firewall-map`);
        const changed = Boolean(map && width && this.lastWidth !== width);
        if (changed) {
            this.lastWidth = width;
            map.style.height = `${Math.round(Math.min(640, Math.max(240, width * 0.6)))}px`;
            this.renderer?.resize();
        }
        return changed;
    }

    onWidgetClose() {
        this.closed = true;
        this.renderer?.destroy();
        this.renderer = null;
        super.onWidgetClose();
    }
}
