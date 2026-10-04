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

const {escapeHtml, renderTitle, fill, DashboardPlusWidget} =
    await import(`./DashboardPlusCommon.js${new URL(import.meta.url).search}`);

export default class DashboardPlusSystemInformation extends DashboardPlusWidget(BaseTableWidget) {
    constructor(config) {
        super(config);
        this.tickTimeout = 10;
        this.loaded = false;
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

    _rows(system, time, details) {
        const versions = Array.isArray(system?.versions) ? system.versions : [];
        const hardware = details.hardware || {};
        const bios = details.bios || {};
        const bootEnvironment = details.boot_environment || {};
        const cpu = details.cpu || {};
        const mitigations = details.mitigations || {};
        const frequency = this._frequency(cpu);
        const updateLink = $('<a>')
            .attr('href', '/ui/core/firmware#checkupdate')
            .text(system?.updates || this.translations.unavailable)
            .prop('outerHTML');

        const rows = [
            [this.translations.name, this._value(system?.name)],
            [this.translations.user, this._value(details.user)],
            [this.translations.hardware, this._group([
                {label: this.translations.manufacturer, value: hardware.manufacturer},
                {label: this.translations.model, value: hardware.model},
                {label: this.translations.serial, value: hardware.serial}
            ])],
            [this.translations.firmware, this._group([
                {label: this.translations.vendor, value: bios.vendor},
                {label: this.translations.version, value: bios.version},
                {label: this.translations.release_date, value: bios.date},
                {label: this.translations.boot_method, value: bios.boot_method}
            ])]
        ];
        if (bootEnvironment.current || bootEnvironment.next) {
            rows.push([this.translations.boot_environment, this._group([
                {label: this.translations.current, value: bootEnvironment.current},
                {label: this.translations.next, value: bootEnvironment.next}
            ])]);
        }
        rows.push(
            [this.translations.version, this._group([
                {label: this.translations.opnsense, value: versions[0]},
                {label: this.translations.freebsd, value: versions[1]},
                {label: this.translations.update_status, value: updateLink, html: true}
            ])],
            [this.translations.cpu, this._group([
                {label: this.translations.model, value: cpu.model},
                {label: '', value: frequency ? `<span id="${this.id}-frequency">${escapeHtml(frequency)}</span>` : null, html: true},
                {label: '', value: this._topology(cpu)}
            ])]
        );
        if ((details.crypto_hardware || []).length > 0) {
            rows.push([this.translations.accelerator, this._cryptoHardware(details.crypto_hardware)]);
        }
        rows.push(
            [this.translations.ipsec, this._value(this._state(details.ipsec))],
            [this.translations.accelerated_algorithms, this._list(details.accelerated_algorithms, ', ')],
            [this.translations.pti, this._value(this._state(mitigations.pti))],
            [this.translations.mds, this._value(this._state(mitigations.mds))],
            [this.translations.uptime, `<span id="${this.id}-uptime">${this._value(time?.uptime)}</span>`],
            [this.translations.datetime, `<span id="${this.id}-datetime">${this._value(time?.datetime)}</span>`],
            [this.translations.dns_servers, this._dns(details.dns)]
        );
        return rows.map(([label, value]) => [escapeHtml(label), value]);
    }

    async onMarkupRendered() {
        renderTitle(this);
        this.fitToContent();
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
            super.updateTable(this._tableId(), this._rows(system, time, details));
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
