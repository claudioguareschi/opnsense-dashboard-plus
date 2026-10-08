/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

// A cap far above any widget: the map fits its content (see _fitToContent).
const AUTO_HEIGHT = 10000;
// the renderer's content hash, written by tools/build-renderer.sh: a new renderer has a new
// address, so a browser never runs an old cached copy with a newer widget
const RENDERER_VERSION = '5442ec5f5d0a';
// follow traffic is the map's own toggle, remembered per browser (as on the full-size map)
const FOLLOW_KEY = 'firewallmap.widget.follow';

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
        // whether this user may change the plugin settings (Retry now): null until asked
        this.admin = null;
        // set when the widget is removed: work still under way must not create anything after it
        this.closed = false;
        this.manualHeight = parseInt(config?.widget?.manual_height, 10) || null;
        this.heightManaged = false;
    }

    /**
     * Whether this user may change the plugin settings, which decides if the geolocation card
     * offers Retry now. Asked outside this.ajaxCall: its endpoints (the Metadata list) decide who
     * sees the widget at all, and listing this one would hide the widget from viewers.
     */
    async _loadAdmin() {
        try {
            await $.ajax({url: '/api/firewallmap/settings/status', dataType: 'json', timeout: 15000});
            this.admin = true;
        } catch (_) {
            this.admin = false;
        }
    }

    /** A height the user chose is kept with the widget's options (see _recordManualResize). */
    async getWidgetConfig() {
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

    /** How this widget draws the map. The plugin's own settings are at Reporting: Firewall Map: Settings. */
    async getWidgetOptions() {
        const choices = (values) => values.map(([value, label]) => ({value, label}));
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
                options: choices([['1', this.translations.on], ['0', this.translations.labels_off]]),
                default: '1',
            },
            block_min: {
                id: `${this.id}-option-block-min`,
                title: this.translations.block_min,
                type: 'select',
                options: choices(['1', '2', '3', '5', '10'].map(
                    (value) => [value, value === '1' ? this.translations.every_attempt : this.translations.attempts.replace('{count}', value)])),
                default: String(defaults.blockMin ?? 3),
            },
            hostnames: {
                id: `${this.id}-option-hostnames`,
                title: this.translations.hostnames,
                type: 'select',
                options: choices([['0', this.translations.labels_off], ['1', this.translations.on]]),
                default: '0',
            },
            asn: {
                id: `${this.id}-option-asn`,
                title: this.translations.asn,
                type: 'select',
                options: choices([['1', this.translations.on], ['0', this.translations.labels_off]]),
                default: '1',
            },
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
        $(`#${this.id}-firewall-map-follow`).toggleClass('active', on).attr('aria-pressed', String(on));
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
            // a plain request with room to spare: the save waits for the collector's full snapshot, and
            // a busy firewall should not cut it short. The save is not in the Metadata endpoint list;
            // the widget privilege that shows the widget also covers it.
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
            const text = error?.message === 'too_soon' ? this.translations.snapshot_too_soon : this.translations.snapshot_failed;
            host.toast(frame, `<span>${window.FirewallMapRenderer.escapeHtml(text)}</span>`);
        } finally {
            $button.prop('disabled', false);
        }
    }

    async onWidgetOptionsChanged() {
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
                <div id="${this.id}-firewall-map-geo"></div>
                <div id="${this.id}-firewall-map-status" style="position: absolute; left: 12px; right: 150px; bottom: 9px; z-index: 2; font-size: .82em; letter-spacing: .02em; pointer-events: none; text-align: left;"></div>
                <div id="${this.id}-firewall-map-credit" style="position: absolute; right: 10px; bottom: 9px; z-index: 2; font-size: .75em; opacity: .7;"></div>
                <div class="btn-group-vertical btn-group-sm" role="group" style="position: absolute; right: 10px; top: 10px; z-index: 3;">
                    <button type="button" class="btn btn-default" id="${this.id}-firewall-map-follow" aria-pressed="false" title="${this.translations.follow}" aria-label="${this.translations.follow}"><i class="fa fa-fw fa-crosshairs" aria-hidden="true"></i></button>
                    <button type="button" class="btn btn-default" id="${this.id}-firewall-map-camera" title="${this.translations.snapshot_take}" aria-label="${this.translations.snapshot_take}"><i class="fa fa-fw fa-camera" aria-hidden="true"></i></button>
                </div>
            </div>
        `);
    }

    async _loadRenderer() {
        if (window.FirewallMapRenderer) {
            return window.FirewallMapRenderer;
        }
        if (!this.loadingRenderer) {
            // cached by the browser ($.getScript forbids it), so a dashboard load does not fetch 1.2 MB;
            // OPNsense lets /ui/js be cached for two days, so the version names this exact build
            this.loadingRenderer = $.ajax({url: `/ui/js/firewall-map-renderer.js?v=${RENDERER_VERSION}`, dataType: 'script', cache: true});
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
                onFollowChange: (on) => this._setFollow(on, false),
                onContextLost: () => this._recoverRenderer()});
            this._setFollow(settings.follow, false);
            $(`#${this.id}-firewall-map-follow`).off('click').on('click', () => this._setFollow(!this.settings.follow));
            $(`#${this.id}-firewall-map-camera`).off('click').on('click', () => this._takeSnapshot());
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
            const summary = await this.ajaxCall('/api/firewallmap/flow/summary', window.FirewallMapRenderer.summaryParams(this.settings));
            // removed while the request was under way
            if (!this.renderer) {
                return;
            }
            const problem = host.problemText(summary, this._text());
            await this._showGeo(summary);
            if (problem) {
                if (['no_database', 'too_many_states', 'collector_incompatible'].includes(summary.status)) {
                    // no locations or no sample: keep the map empty and say why
                    this.renderer.render({flows: [], locations: []});
                } else if (summary.status !== 'starting') {
                    console.error('Firewall Map+: collector reported', summary);
                }
                // the geolocation card says it on the map itself
                this._status(summary.status === 'no_database' ? '' : problem);
                return;
            }
            this.renderer.render(summary);
            $(`#${this.id}-firewall-map-credit`).html(host.creditHtml(summary.provider));
            const parts = host.statusParts(summary, summary, this.settings, this._text());
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

    /**
     * The geolocation card over an empty map (downloading, failed, key missing), or the small note
     * when only network names are missing. Retry now and Settings are for administrators: whether this user is
     * one is learned once, from the plugin status they can (or cannot) read.
     */
    async _showGeo(summary) {
        const host = window.FirewallMapRenderer.host;
        if (summary?.status === 'no_database' && this.admin === null) {
            await this._loadAdmin();
        }
        const admin = Boolean(this.admin);
        const html = host.geoCardHtml(summary, this._text(), {admin}) || host.geoNoteHtml(summary, this._text(), this.geoNoteDismissed);
        const slot = document.getElementById(`${this.id}-firewall-map-geo`);
        if (slot && slot.dataset.html !== html) {
            slot.innerHTML = html;
            slot.dataset.html = html;
            slot.querySelector('.fwmap-geo-note-close')?.addEventListener('click', () => {
                this.geoNoteDismissed = host.geoNoteKey(summary);
                slot.innerHTML = '';
                slot.dataset.html = '';
            });
            host.tickCountdowns();
        }
    }

    /**
     * The browser took the GPU away (memory pressure, sleep, a driver reset): say so and build the
     * map again on a new canvas. A browser that keeps doing it is not fought: after three resets in
     * two minutes the widget asks for a reload instead.
     */
    _recoverRenderer() {
        const now = Date.now();
        this.resets = (this.resets || []).filter((time) => now - time < 120000).concat(now);
        if (this.rebuilding || this.closed) {
            return;
        }
        if (this.resets.length > 3) {
            this._status(this.translations.webgl_failed);
            return;
        }
        this._status(this.translations.webgl_lost);
        this.rebuilding = setTimeout(async () => {
            this.rebuilding = null;
            if (this.closed) {
                return;
            }
            try {
                this.renderer?.destroy();
            } catch (_) {
                // the old context is gone; nothing left to release
            }
            this.renderer = null;
            $(`#${this.id}-firewall-map-canvas`).empty();
            await this.onMarkupRendered();
        }, 2000);
    }

    onWidgetClose() {
        this.closed = true;
        this.renderer?.destroy();
        this.renderer = null;
        super.onWidgetClose();
    }
}
