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

const {
    escapeHtml, renderTitle, fill, DashboardPlusWidget, mergeOrder, makeSortable, isDragging,
    isEditMode, watchEditMode
} = await import(`./DashboardPlusCommon.js${new URL(import.meta.url).search}`);

// Every section, in the default order. Boot Environment and Crypto Hardware show only where the
// firewall has them.
const SECTIONS = [
    'name', 'user', 'hardware', 'firmware', 'boot_environment', 'version', 'cpu', 'accelerator',
    'ipsec', 'accelerated_algorithms', 'pti', 'mds', 'uptime', 'datetime', 'dns_servers'
];

export default class DashboardPlusSystemInformation extends DashboardPlusWidget(BaseTableWidget) {
    constructor(config) {
        super(config);
        this.configurable = true;
        this.tickTimeout = 10;
        this.loaded = false;
        this.data = null;
        this.currentConfig = null;
    }

    getGridOptions() {
        return {sizeToContent: 650};
    }

    _tableId() {
        return `${this.id}-table`;
    }

    getMarkup() {
        // Label and value side by side at every width. The stock table stacks them below
        // 450 px, so the widget changed layout whenever the side menu was toggled.
        const markup = this.createTable(this._tableId(), {headerPosition: 'left', headerBreakpoint: 0});
        Object.assign(this.sizeStates[0], {
            '.flextable-row > .flex-cell.first': {width: '32%', 'padding-right': '0.75em', 'box-sizing': 'border-box'},
            '.flextable-row > .flex-cell:not(.first)': {width: '68%'}
        });
        return markup;
    }

    _value(value) {
        return escapeHtml(value === null || value === undefined || value === '' ? this.translations.unavailable : value);
    }

    _list(values, separator = '<br>') {
        if (!Array.isArray(values) || values.length === 0) {
            return this._value(null);
        }
        return values.map(value => this._value(value)).join(separator);
    }

    _group(items) {
        const values = items.filter(item => item.value !== null && item.value !== undefined && item.value !== '');
        if (values.length === 0) {
            return this._value(null);
        }
        return values.map(item => {
            const value = item.html ? item.value : this._value(item.value);
            return item.label ? `<strong>${escapeHtml(item.label)}:</strong> ${value}` : value;
        }).join('<br>');
    }

    _cryptoHardware(providers) {
        return this._list((providers || []).map(provider => {
            const state = this.translations[provider.state] || this.translations.inactive;
            const count = provider.count > 1 ? ` ×${provider.count}` : '';
            return `${provider.feature}: ${provider.provider}${count} (${state})`;
        }));
    }

    /* What the firewall itself resolves through: its local resolver, else the resolv.conf servers. */
    _dns(dns) {
        if (!dns) {
            return this._value(null);
        }
        const t = this.translations;
        const servers = dns.servers || [];
        const lines = [];
        if (dns.resolver) {
            const forwarders = (dns.forwarders || []).join(', ');
            const phrase = !dns.running ? t.dns_local_not_running
                : dns.mode === 'recursive' ? t.dns_local_recursive
                : dns.mode === 'forwarding' ? (dns.tls ? t.dns_local_forwarding_tls : t.dns_local_forwarding) : t.dns_local;
            const line = fill(phrase, {resolver: dns.resolver, servers: forwarders});
            lines.push(escapeHtml(line));
            if (servers.length > 0) {
                lines.push(`${escapeHtml(t.dns_fallback)}: ${escapeHtml(servers.join(', '))}`);
            }
        } else {
            lines.push(...servers.map(server => escapeHtml(server)));
        }
        return lines.length > 0 ? lines.join('<br>') : escapeHtml(t.not_set);
    }

    /* The system script reports states as codes; show them in the UI language. */
    _state(code) {
        return {
            enabled: this.translations.enabled,
            disabled: this.translations.disabled,
            active: this.translations.hardware_acceleration_active,
            unavailable: this.translations.hardware_acceleration_unavailable
        }[code] ?? code;
    }

    /* The kernel reports the MDS state in lower case ("inactive", "software (Silvermont)"). */
    _mds(state) {
        if (state === 'inactive') {
            return this.translations.inactive;
        }
        return typeof state === 'string' && state ? state.charAt(0).toUpperCase() + state.slice(1) : state;
    }

    _frequency(cpu) {
        if (!cpu?.current_mhz) {
            return null;
        }
        const maximum = cpu.maximum_mhz ? `, ${this.translations.maximum}: ${cpu.maximum_mhz} MHz` : '';
        return `${this.translations.current}: ${cpu.current_mhz} MHz${maximum}`;
    }

    _topology(cpu) {
        if (!(cpu.threads && cpu.packages && cpu.cores && cpu.threads_per_core)) {
            return null;
        }
        return fill(this.translations.cpu_topology,
            {threads: cpu.threads, packages: cpu.packages, cores: cpu.cores, threads_per_core: cpu.threads_per_core});
    }

    /* The rows of every section the firewall has, by section name. */
    _sections({system, time, details}) {
        const t = this.translations;
        const versions = Array.isArray(system?.versions) ? system.versions : [];
        const hardware = details.hardware || {};
        const bios = details.bios || {};
        const bootEnvironment = details.boot_environment || {};
        const cpu = details.cpu || {};
        const mitigations = details.mitigations || {};
        const frequency = this._frequency(cpu);
        const updateLink = $('<a>')
            .attr('href', '/ui/core/firmware#checkupdate')
            .text(system?.updates || t.unavailable)
            .prop('outerHTML');

        const sections = {
            name: this._value(system?.name),
            user: this._value(details.user),
            hardware: this._group([
                {label: t.manufacturer, value: hardware.manufacturer},
                {label: t.model, value: hardware.model},
                {label: t.serial, value: hardware.serial}
            ]),
            firmware: this._group([
                {label: t.vendor, value: bios.vendor},
                {label: t.version, value: bios.version},
                {label: t.release_date, value: bios.date},
                {label: t.boot_method, value: bios.boot_method}
            ]),
            version: this._group([
                {label: t.opnsense, value: versions[0]},
                {label: t.freebsd, value: versions[1]},
                {label: t.update_status, value: updateLink, html: true}
            ]),
            cpu: this._group([
                {label: t.model, value: cpu.model},
                {label: '', value: frequency ? `<span id="${this.id}-frequency">${escapeHtml(frequency)}</span>` : null, html: true},
                {label: '', value: this._topology(cpu)}
            ]),
            ipsec: this._value(this._state(details.ipsec)),
            accelerated_algorithms: this._list(details.accelerated_algorithms, ', '),
            pti: this._value(this._state(mitigations.pti)),
            mds: this._value(this._mds(mitigations.mds)),
            uptime: `<span id="${this.id}-uptime">${this._value(time?.uptime)}</span>`,
            datetime: `<span id="${this.id}-datetime">${this._value(time?.datetime)}</span>`,
            dns_servers: this._dns(details.dns)
        };
        if (bootEnvironment.current || bootEnvironment.next) {
            sections.boot_environment = this._group([
                {label: t.current, value: bootEnvironment.current},
                {label: t.next, value: bootEnvironment.next}
            ]);
        }
        if ((details.crypto_hardware || []).length > 0) {
            sections.accelerator = this._cryptoHardware(details.crypto_hardware);
        }
        return sections;
    }

    /* The chosen sections in the user's order. */
    _order() {
        const chosen = this.currentConfig?.sections;
        return mergeOrder(chosen, chosen ?? SECTIONS).filter(section => SECTIONS.includes(section));
    }

    _render() {
        const $table = $(`#${this._tableId()}`);
        if (!this.data || !this.currentConfig || isDragging($table)) {
            return;
        }
        const sections = this._sections(this.data);
        const shown = this._order().filter(section => section in sections);
        super.updateTable(this._tableId(), shown.map(section => [escapeHtml(this.translations[section]), sections[section]]));
        // updateTable appends one row per entry, in order
        $table.children('.flextable-row').each((index, row) => {
            $(row).attr('data-sort-id', shown[index]);
        });
        this._applyEditMode(isEditMode());
    }

    /* Sections can be dragged into a new order only while the dashboard is being edited. */
    _applyEditMode(editing) {
        $(`#${this._tableId()} > .flextable-row[data-sort-id]`)
            .attr('draggable', editing ? 'true' : null)
            .attr('title', editing ? this.translations.drag_to_reorder : null)
            .css('cursor', editing ? 'grab' : '');
    }

    async onMarkupRendered() {
        renderTitle(this);
        this.currentConfig = await this.getWidgetConfig();
        makeSortable($(`#${this._tableId()}`), {
            itemSelector: '.flextable-row[data-sort-id]',
            placeholderClass: 'flextable-row',
            label: this.translations.drag_to_reorder,
            onReorder: order => {
                this.currentConfig.sections = mergeOrder(order, this.currentConfig.sections || order);
                this.setWidgetConfig(this.currentConfig);
            }
        });
        this.stopWatchingEditMode = watchEditMode(editing => this._applyEditMode(editing));
        this.fitToContent();
    }

    async getWidgetOptions() {
        // List the sections in the widget's order, so the dropdown reads like the widget.
        const chosen = this.currentConfig?.sections;
        const order = Array.isArray(chosen) ? mergeOrder(chosen, [...chosen, ...SECTIONS]) : SECTIONS;
        return {
            sections: {
                title: this.translations.sections,
                type: 'select_multiple',
                id: `${this.id}-sections`,
                options: order.map(section => ({value: section, label: this.translations[section]})),
                default: SECTIONS
            }
        };
    }

    async onWidgetOptionsChanged() {
        const previous = this.currentConfig?.sections;
        const config = await this.getWidgetConfig();
        // The dialog returns the selection in option order; keep the dragged order.
        config.sections = mergeOrder(previous, config.sections);
        this.setWidgetConfig(config);
        this.currentConfig = config;
        this._render();
    }

    onWidgetClose() {
        super.onWidgetClose();
        this.stopWatchingEditMode?.();
    }

    async onWidgetTick() {
        if (!this.loaded) {
            // Load in the tick, not in onMarkupRendered: a failure then shows the dashboard's
            // error state and the next tick retries.
            const [system, time, details] = await Promise.all([
                this.ajaxCall('/api/diagnostics/system/system_information'),
                this.ajaxCall('/api/diagnostics/system/system_time'),
                this.ajaxCall('/api/dashboardplus/system/info')
            ]);
            if (details?.status !== 'ok') {
                throw new Error('System information is unavailable');
            }
            this.data = {system, time, details};
            this._render();
            this.loaded = true;
            return;
        }
        const [time, frequency] = await Promise.all([
            this.ajaxCall('/api/diagnostics/system/system_time'),
            this.ajaxCall('/api/dashboardplus/system/frequency')
        ]);
        if (time?.uptime) {
            $(`#${this.id}-uptime`).text(time.uptime);
        }
        if (time?.datetime) {
            $(`#${this.id}-datetime`).text(time.datetime);
        }
        const text = this._frequency(frequency);
        if (text) {
            $(`#${this.id}-frequency`).text(text);
        }
    }

}
