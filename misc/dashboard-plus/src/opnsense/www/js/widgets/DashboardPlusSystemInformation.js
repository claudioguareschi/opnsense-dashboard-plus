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

    formatAccelerators(acceleratorData) {
        const devices = acceleratorData?.devices || [];
        const identity = [];
        const state = [];
        const capabilities = [];

        devices.forEach(device => {
            const location = device.pci_address ? ` (${device.pci_address})` : '';
            identity.push(`${device.integration}: ${device.model}${location}`);

            const ocfState = device.ocf_active ? this.translations.active : this.translations.inactive;
            state.push(`${device.driver}; ${device.state}; OCF ${ocfState}`);
            capabilities.push((device.capabilities || []).join(', '));
        });

        return {
            identity: this.formatList(identity),
            state: this.formatList(state),
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
        const cpu = details.cpu || {};
        const mitigations = details.mitigations || {};
        const accelerators = this.formatAccelerators(details.accelerator);
        const hardwareName = [hardware.manufacturer, hardware.model].filter(Boolean).join(' ');
        const biosName = [bios.vendor, bios.version, bios.date].filter(Boolean).join(' / ');
        const topology = [
            cpu.cores ? `${cpu.cores} cores` : null,
            cpu.threads ? `${cpu.threads} threads` : null,
            cpu.threads_per_core ? `${cpu.threads_per_core} threads/core` : null
        ].filter(Boolean).join(' / ');
        const updateLink = $('<a>')
            .attr('href', '/ui/core/firmware#checkupdate')
            .text(system?.updates || this.translations.unavailable)
            .prop('outerHTML');

        const rows = [
            [this.translations.name, this.escape(system?.name)],
            [this.translations.user, this.escape(details.user)],
            [this.translations.hardware, this.escape(hardwareName)],
            [this.translations.serial, this.escape(hardware.serial)],
            [this.translations.bios, this.escape(biosName)],
            [this.translations.boot_method, this.escape(bios.boot_method)],
            [this.translations.opnsense_version, this.escape(versions[0])],
            [this.translations.freebsd_version, this.escape(versions[1])],
            [this.translations.updates, updateLink],
            [this.translations.cpu, this.escape(cpu.model)],
            [this.translations.cpu_topology, this.escape(topology)],
            [this.translations.cpu_crypto, this.formatList(cpu.crypto_capabilities)],
        ];

        if ((details.accelerator?.devices || []).length > 0) {
            rows.push(
                [this.translations.accelerator, accelerators.identity],
                [this.translations.accelerator_state, accelerators.state],
                [this.translations.accelerator_capabilities, accelerators.capabilities]
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
