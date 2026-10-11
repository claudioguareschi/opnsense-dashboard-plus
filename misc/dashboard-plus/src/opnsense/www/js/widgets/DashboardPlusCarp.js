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

const {escapeHtml, renderTitle, ensureStyle, fill, DashboardPlusWidget} =
    await import(`./DashboardPlusCommon.js${new URL(import.meta.url).search}`);

// The node's role over all its VIPs: a healthy master in the theme's success color, a healthy backup
// in its info color, VIPs still initializing in warning, and a node that is master for some VIPs and
// backup for others (split) in danger, the classic high-availability fault.
const ROLE_COLORS = {master: 'text-success', backup: 'text-info', init: 'text-warning', split: 'text-danger', none: 'text-muted'};
const STATE_COLORS = {master: 'text-success', backup: 'text-info', init: 'text-warning'};
const HISTORY_SHOWN = 8;

export default class DashboardPlusCarp extends DashboardPlusWidget(BaseWidget) {
    constructor(config) {
        super(config);
        this.tickTimeout = 10;
        this.data = null;
        this.previous = null;
        this.rates = null;
        this.expanded = {vips: null, history: false};
        this.error = '';
    }

    getGridOptions() {
        return {sizeToContent: 650};
    }

    getMarkup() {
        ensureStyle();
        return $(`<div id="${this.id}-carp" class="dashboard-plus-carp"></div>`);
    }

    /* Counter rates per second between this read and the one before (null until there are two). */
    _updateRates(data) {
        const counters = data.counters || {};
        if (this.previous && data.sampled_at > this.previous.at) {
            const seconds = data.sampled_at - this.previous.at;
            this.rates = Object.fromEntries(Object.entries(counters).map(([key, value]) => {
                const delta = value - (this.previous.counters[key] ?? value);
                return [key, delta >= 0 ? delta / seconds : null];
            }));
        }
        this.previous = {at: data.sampled_at, counters};
    }

    _rate(key) {
        const value = this.rates?.[key];
        if (value === null || value === undefined) {
            return null;
        }
        return value >= 10 || value === 0 ? Math.round(value).toLocaleString() : value.toFixed(1);
    }

    _age(epoch) {
        const t = this.translations;
        const seconds = Math.max(0, Date.now() / 1000 - epoch);
        if (seconds < 60) {
            return t.just_now;
        }
        if (seconds < 3600) {
            return fill(t.minutes_ago, {count: Math.floor(seconds / 60)});
        }
        if (seconds < 86400) {
            return fill(t.hours_ago, {count: Math.floor(seconds / 3600)});
        }
        return fill(t.days_ago, {count: Math.floor(seconds / 86400)});
    }

    _stamp(epoch) {
        return new Date(epoch * 1000).toLocaleString();
    }

    _pill(state, text, compact = false, title = '') {
        const color = ROLE_COLORS[state] || STATE_COLORS[state] || 'text-muted';
        return `<span class="dashboard-plus-state-pill${compact ? ' dashboard-plus-compact' : ''} ${color}"${title ? ` title="${escapeHtml(title)}"` : ''}>`
            + `<span class="dashboard-plus-state-dot" aria-hidden="true"></span> ${escapeHtml(text)}</span>`;
    }

    /* One status line: an icon in the theme's state color, a main text, and muted details under it. */
    _line(icon, color, main, details = '') {
        return `<div class="dashboard-plus-carp-line">
            <i class="fa fa-fw fa-${icon} ${color}" aria-hidden="true"></i>
            <div><div>${main}</div>${details ? `<div class="dashboard-plus-carp-detail">${details}</div>` : ''}</div>
        </div>`;
    }

    _head(data) {
        const t = this.translations;
        const summary = data.summary;
        const role = summary.state;
        const scope = role === 'split' ? fill(t.scope_split, summary)
            : role === 'init' ? fill(t.scope_init, {init: summary.init, count: summary.total})
            : fill(summary.total === 1 ? t.scope_one : t.scope_all, {count: summary.total});
        const skews = [...new Set(data.vips.map(vip => vip.advskew))];
        const flags = [
            `<span>${escapeHtml(data.carp.preempt === 0 ? t.preempt_off : t.preempt_on)}</span>`,
            skews.length === 1 ? `<span>${escapeHtml(fill(t.skew, {skew: skews[0]}))}</span>` : '',
            data.carp.demotion > 0
                ? `<span class="text-warning" title="${escapeHtml(t.demoted_title)}">${escapeHtml(fill(t.demoted, {value: data.carp.demotion}))}</span>`
                : `<span>${escapeHtml(t.not_demoted)}</span>`,
        ].filter(Boolean).join('<span class="dashboard-plus-carp-separator" aria-hidden="true">·</span>');
        return `<div class="dashboard-plus-carp-head">
            <div class="dashboard-plus-carp-role">${this._pill(role, t[`role_${role}`] || role)}
                <span class="dashboard-plus-carp-scope">${escapeHtml(scope)}</span></div>
            <div class="dashboard-plus-carp-flags">${flags}</div>
        </div>`;
    }

    /* Whether the peer is heard: a backup hears the master's advertisements, a master sends its own. */
    _peerLine(data) {
        const t = this.translations;
        const master = data.summary.state === 'master';
        const rate = this._rate(master ? 'carp_sent' : 'carp_received');
        const errors = this.rates?.carp_errors ?? 0;
        let color = 'text-success';
        let main = master ? t.advertising : t.master_advertising;
        if (rate === null) {
            color = 'text-muted';
        } else if (Number(rate) === 0) {
            color = 'text-danger';
            main = master ? t.not_advertising : t.no_advertisements;
        }
        const details = [rate === null ? escapeHtml(t.measuring) : escapeHtml(fill(t.advertisements_per_second, {rate}))];
        if (errors > 0) {
            details.push(`<span class="text-warning">${escapeHtml(fill(t.errors_per_second, {rate: errors.toFixed(1)}))}</span>`);
        }
        return this._line('tower-broadcast', color, escapeHtml(main), details.join(' · '));
    }

    _pfsyncLine(data) {
        const t = this.translations;
        const pfsync = data.pfsync;
        if (!pfsync || !pfsync.syncdev) {
            return this._line('arrows-rotate', 'text-warning', escapeHtml(t.pfsync_off));
        }
        const where = `${pfsync.syncdev_name}${pfsync.syncdev_name !== pfsync.syncdev ? ` (${pfsync.syncdev})` : ''}`;
        const main = escapeHtml(pfsync.peer ? fill(t.pfsync_on, {interface: where, peer: pfsync.peer}) : fill(t.pfsync_no_peer, {interface: where}));
        const color = !pfsync.up ? 'text-danger' : pfsync.syncok === false ? 'text-warning' : 'text-success';
        const bulk = pfsync.syncok === false ? `<span class="text-warning">${escapeHtml(t.bulk_pending)}</span>` : escapeHtml(t.bulk_complete);
        const updatesIn = this._rate('pfsync_updates_in');
        const updatesOut = this._rate('pfsync_updates_out');
        const flow = updatesIn === null ? escapeHtml(t.measuring)
            : `<i class="fa fa-arrow-down" aria-label="${escapeHtml(t.received)}"></i> ${escapeHtml(fill(t.per_second, {rate: updatesIn}))}`
              + ` <i class="fa fa-arrow-up" aria-label="${escapeHtml(t.sent)}"></i> ${escapeHtml(fill(t.per_second, {rate: updatesOut}))}`;
        const errorRate = this.rates?.pfsync_errors ?? 0;
        const errors = errorRate > 0
            ? `<span class="text-danger">${escapeHtml(fill(t.errors_per_second, {rate: errorRate.toFixed(1)}))}</span>`
            : escapeHtml(t.no_errors);
        return this._line('arrows-rotate', color, main, [bulk, `<span title="${escapeHtml(t.updates_title)}">${flow}</span>`, errors].join(' · '));
    }

    _configSyncLine(data) {
        const t = this.translations;
        const target = data.config_sync?.target;
        const main = target
            ? `<a href="/ui/core/hasync" class="dashboard-plus-carp-plain">${escapeHtml(fill(t.config_sync_to, {target}))}</a>`
            : `<a href="/ui/core/hasync" class="dashboard-plus-carp-quiet">${escapeHtml(t.config_sync_none)}</a>`;
        return this._line('file-arrow-up', target ? 'text-success' : 'text-muted', main);
    }

    _change(change) {
        const t = this.translations;
        const state = value => t[`state_${value}`] || value;
        return `${escapeHtml(change.name)} · ${escapeHtml(fill(t.vhid, {vhid: change.vhid}))} · `
            + `${escapeHtml(state(change.from))} <i class="fa fa-arrow-right" aria-hidden="true"></i> `
            + `<span class="${STATE_COLORS[change.to] || ''}">${escapeHtml(state(change.to))}</span>`
            + (change.reason ? ` <span class="dashboard-plus-carp-quiet">(${escapeHtml(change.reason)})</span>` : '');
    }

    _historyLine(data) {
        const t = this.translations;
        const changes = (data.transitions || []).filter(change => change.time);
        if (!changes.length) {
            return this._line('clock-rotate-left', 'text-muted', escapeHtml(t.no_changes));
        }
        const latest = changes[0];
        const toggle = changes.length > 1
            ? ` <a href="#" class="dashboard-plus-carp-toggle" data-toggle-section="history">${escapeHtml(this.expanded.history ? t.hide_history : fill(t.show_history, {count: Math.min(changes.length, HISTORY_SHOWN)}))}`
              + ` <i class="fa fa-chevron-${this.expanded.history ? 'up' : 'down'}" aria-hidden="true"></i></a>`
            : '';
        const main = `<span title="${escapeHtml(this._stamp(latest.time))}">${escapeHtml(fill(t.last_change, {age: this._age(latest.time)}))}</span>${toggle}`;
        let details = this._change(latest);
        if (this.expanded.history) {
            details = `<ol class="dashboard-plus-carp-history">${changes.slice(0, HISTORY_SHOWN).map(change => `
                <li><span class="dashboard-plus-carp-when" title="${escapeHtml(this._stamp(change.time))}">${escapeHtml(this._age(change.time))}</span>
                    <span>${this._change(change)}</span></li>`).join('')}</ol>`;
        }
        return this._line('clock-rotate-left', 'text-muted', main, details);
    }

    /* The VIPs: one line while they all agree, the table when asked or when they do not. */
    _vips(data) {
        const t = this.translations;
        const summary = data.summary;
        const agree = summary.state === 'master' || summary.state === 'backup';
        const expanded = this.expanded.vips ?? !agree;
        const toggle = `<a href="#" class="dashboard-plus-carp-toggle" data-toggle-section="vips">${escapeHtml(expanded ? t.hide : t.show)}`
            + ` <i class="fa fa-chevron-${expanded ? 'up' : 'down'}" aria-hidden="true"></i></a>`;
        const heading = agree
            ? fill(summary.total === 1 ? t.vips_summary_one : t.vips_summary, {count: summary.total, state: t[`state_${summary.state}`]})
            : fill(t.vips_count, {count: summary.total});
        const rows = expanded ? data.vips.map(vip => `
            <div class="flextable-row dashboard-plus-row" role="row">
                <div role="cell">
                    <div class="dashboard-plus-carp-vip-name dashboard-plus-ellipsis" title="${escapeHtml(vip.name)}">${escapeHtml(vip.name)}</div>
                    <div class="dashboard-plus-muted dashboard-plus-small dashboard-plus-ellipsis" title="${escapeHtml(vip.description)}">${escapeHtml([fill(t.vhid, {vhid: vip.vhid}), vip.description].filter(Boolean).join(' · '))}</div>
                </div>
                <div role="cell" class="dashboard-plus-small dashboard-plus-tabular">${vip.addresses.map(address => escapeHtml(address).replace(/:/g, ':<wbr>')).join('<br>') || '—'}</div>
                <div role="cell">${this._pill(vip.state, t[`state_${vip.state}`] || vip.state, true,
                    fill(t.vip_title, {advbase: vip.advbase, advskew: vip.advskew, device: vip.device}))}</div>
            </div>`).join('') : '';
        return `<div class="dashboard-plus-carp-vips">
            <div class="dashboard-plus-carp-vips-head"><span><i class="fa fa-fw fa-circle-nodes" aria-hidden="true"></i> ${escapeHtml(heading)}</span>${toggle}</div>
            ${rows ? `<div class="flextable-container dashboard-plus-table dashboard-plus-carp-table" role="table">${rows}</div>` : ''}
        </div>`;
    }

    _render() {
        const $root = $(`#${this.id}-carp`);
        const t = this.translations;
        if (this.error) {
            $root.html(`<div class="dashboard-plus-empty">${escapeHtml(this.error)}</div>`);
            return;
        }
        const data = this.data;
        if (!data) {
            return;
        }
        if (!data.available) {
            $root.html(`<div class="dashboard-plus-empty"><a href="/ui/interfaces/vip">${escapeHtml(t.unconfigured)}</a></div>`);
            return;
        }
        $root.html(`${this._head(data)}
            <div class="dashboard-plus-carp-lines">${this._peerLine(data)}${this._pfsyncLine(data)}${this._configSyncLine(data)}${this._historyLine(data)}</div>
            ${this._vips(data)}`);
    }

    async onMarkupRendered() {
        renderTitle(this);
        $(`#${this.id}-carp`).on('click', '[data-toggle-section]', event => {
            event.preventDefault();
            const section = $(event.currentTarget).data('toggle-section');
            const summary = this.data?.summary;
            const agree = summary && (summary.state === 'master' || summary.state === 'backup');
            this.expanded[section] = section === 'vips' ? !(this.expanded.vips ?? !agree) : !this.expanded[section];
            this._render();
            this.fitToContent();
        });
        await this.onWidgetTick();
        this.fitToContent();
    }

    async onWidgetTick() {
        try {
            const data = await this.ajaxCall('/api/dashboardplus/system/carp');
            if (data?.status !== 'ok') {
                throw new Error(this.translations.fetch_failed);
            }
            this._updateRates(data);
            this.data = data;
            this.error = '';
        } catch (error) {
            this.error = this.translations.fetch_failed;
        }
        this._render();
    }

    onWidgetClose() {
        $(`#${this.id}-carp`).off('click');
    }
}
