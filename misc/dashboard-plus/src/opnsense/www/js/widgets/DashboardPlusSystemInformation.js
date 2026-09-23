/*
 * Copyright (C) 2026 Claudio Guareschi
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

export default class DashboardPlusSystemInformation extends BaseTableWidget {
    constructor(config) {
        super(config);
        this.tickTimeout = 10;
    }

    getGridOptions() {
        return {
            sizeToContent: 650
        };
    }

    getMarkup() {
        return this.createTable('dashboard-plus-system-information', {
            headerPosition: 'left'
        });
    }

    escape(value) {
        const displayValue = value === null || value === undefined || value === ''
            ? this.translations.unavailable
            : String(value);
        return $('<div>').text(displayValue).html();
    }

    formatList(values) {
        if (!Array.isArray(values) || values.length === 0) {
            return this.escape(this.translations.unavailable);
        }
        return values.map(value => this.escape(value)).join('<br>');
    }

    formatGroup(items) {
        const values = items.filter(item => item.value !== null && item.value !== undefined && item.value !== '');
        if (values.length === 0) {
            return this.escape(this.translations.unavailable);
        }
        return values.map(item => {
            const value = item.html ? item.value : this.escape(item.value);
            return item.label ? `<strong>${this.escape(item.label)}:</strong> ${value}` : value;
        }).join('<br>');
    }

    formatAccelerators(acceleratorData) {
        const devices = acceleratorData?.devices || [];
        const identity = [];
        const capabilities = [];

        devices.forEach(device => {
            const state = device.ocf_active ? this.translations.active : this.translations.inactive;
            identity.push(`${device.model} (${state})`);
            capabilities.push((device.capabilities || []).join(', '));
        });

        return {
            identity: this.formatList(identity),
            capabilities: this.formatList(capabilities.filter(value => value !== ''))
        };
    }

    formatAlgorithms(providerData) {
        const providers = Array.isArray(providerData) ? providerData : [];
        const values = providers.map(provider => {
            const algorithms = (provider.algorithms || []).join(', ');
            return algorithms ? `${provider.provider}: ${algorithms}` : '';
        }).filter(Boolean);
        const note = `<small>${this.escape(this.translations.offload_note)}</small>`;
        return `${this.formatList(values)}<br>${note}`;
    }

    formatCpuCrypto(cpu, providers) {
        const capabilities = cpu.crypto_capabilities || [];
        const aesniActive = (providers || []).some(provider => provider.provider === 'CPU AES-NI');
        const aesniAvailable = capabilities.includes('AESNI');
        const status = aesniActive ? this.translations.active : aesniAvailable
            ? this.translations.available : this.translations.no;
        const features = capabilities.filter(capability => capability !== 'AESNI');
        const values = [`${this.translations.aesni_cpu_crypto}: ${status}`];
        if (features.length > 0) {
            values.push(`${this.translations.cpu_features}: ${features.join(', ')}`);
        }
        return values.join('<br>');
    }

    async onMarkupRendered() {
        const [system, time, details] = await Promise.all([
            this.ajaxCall('/api/diagnostics/system/system_information'),
            this.ajaxCall('/api/diagnostics/system/system_time'),
            this.ajaxCall('/api/dashboardplus/system/info')
        ]);

        if (!details || details.status !== 'ok') {
            this.displayError(this.translations.unavailable);
            return;
        }

        const versions = Array.isArray(system?.versions) ? system.versions : [];
        const hardware = details.hardware || {};
        const bios = details.bios || {};
        const bootEnvironment = details.boot_environment || {};
        const cpu = details.cpu || {};
        const mitigations = details.mitigations || {};
        const accelerators = this.formatAccelerators(details.accelerator);
        const hardwareName = [hardware.manufacturer, hardware.model].filter(Boolean).join(' ');
        const biosName = [bios.vendor, bios.version, bios.date].filter(Boolean).join(' / ');
        const topologyDetails = [
            cpu.packages ? `${cpu.packages} package${cpu.packages === 1 ? '' : 's'}` : null,
            cpu.cores ? `${cpu.cores} core${cpu.cores === 1 ? '' : 's'}` : null,
            cpu.threads_per_core ? `${cpu.threads_per_core} hardware thread${cpu.threads_per_core === 1 ? '' : 's'}/core` : null
        ].filter(Boolean).join(' × ');
        const topology = cpu.threads
            ? `${cpu.threads} CPUs: ${topologyDetails}`
            : topologyDetails;
        const updateLink = $('<a>')
            .attr('href', '/ui/core/firmware#checkupdate')
            .text(system?.updates || this.translations.unavailable)
            .prop('outerHTML');

        const rows = [
            [this.translations.name, this.escape(system?.name)],
            [this.translations.user, this.escape(details.user)],
            [this.translations.hardware, this.formatGroup([
                {label: this.translations.manufacturer, value: hardware.manufacturer},
                {label: this.translations.model, value: hardware.model || hardwareName},
                {label: this.translations.serial, value: hardware.serial}
            ])],
            [this.translations.firmware, this.formatGroup([
                {label: this.translations.vendor, value: bios.vendor},
                {label: this.translations.version, value: bios.version},
                {label: this.translations.release_date, value: bios.date},
                {label: this.translations.boot_method, value: bios.boot_method}
            ])]
        ];

        if (bootEnvironment.current || bootEnvironment.next) {
            rows.push([this.translations.boot_environment, this.formatGroup([
                {label: this.translations.current, value: bootEnvironment.current},
                {label: this.translations.next, value: bootEnvironment.next}
            ])]);
        }

        rows.push(
            [this.translations.version, this.formatGroup([
                {label: this.translations.opnsense, value: versions[0]},
                {label: this.translations.freebsd, value: versions[1]},
                {label: this.translations.update_status, value: updateLink, html: true}
            ])],
            [this.translations.cpu, this.formatGroup([
                {label: '', value: cpu.model},
                {label: '', value: topology},
                {label: '', value: this.formatCpuCrypto(cpu, details.accelerated_algorithms), html: true}
            ])]
        );

        if ((details.accelerator?.devices || []).length > 0) {
            rows.push(
                [this.translations.accelerator, this.formatGroup([
                    {label: '', value: accelerators.identity, html: true},
                    {label: '', value: accelerators.capabilities, html: true}
                ])]
            );
        }

        rows.push(
            [this.translations.accelerated_algorithms, this.formatAlgorithms(details.accelerated_algorithms)],
            [this.translations.pti, this.escape(mitigations.pti)],
            [this.translations.mds, this.escape(mitigations.mds)],
            [this.translations.uptime, `<span id="dashboard-plus-uptime">${this.escape(time?.uptime)}</span>`],
            [this.translations.datetime, `<span id="dashboard-plus-datetime">${this.escape(time?.datetime)}</span>`],
            [this.translations.dns_servers, this.formatList(details.dns_servers)]
        );

        super.updateTable('dashboard-plus-system-information', rows);
    }

    async onWidgetTick() {
        const data = await this.ajaxCall('/api/diagnostics/system/system_time');
        if (data?.uptime) {
            $('#dashboard-plus-uptime').text(data.uptime);
        }
        if (data?.datetime) {
            $('#dashboard-plus-datetime').text(data.datetime);
        }
    }
}
