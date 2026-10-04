/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
 * All rights reserved.
 */

const {escapeHtml, renderTitle, ensureStyle, fill, DashboardPlusWidget} =
    await import(`./DashboardPlusCommon.js${new URL(import.meta.url).search}`);

export default class DashboardPlusThermalSensors extends DashboardPlusWidget(BaseWidget) {
    constructor(config) {
        super(config);
        this.tickTimeout = 10;
        this.configurable = true;
        this.currentConfig = null;
        this.sensors = [];
    }

    getGridOptions() {
        return {sizeToContent: 650};
    }

    _sensorLabel(sensor) {
        if (sensor.type === 'cpu') {
            return fill(this.translations.core, {number: sensor.device_seq});
        }
        return `${sensor.type_translated} ${sensor.device_seq}`;
    }

    /* The theme's progress bar colors: hot from 70 °C, critical from 80 °C. */
    _sensorColor(celsius) {
        return celsius >= 80 ? 'danger' : celsius >= 70 ? 'warning' : 'success';
    }

    _renderSensors() {
        const $container = $(`#${this.id}-sensors`);
        const selected = this.currentConfig?.sensors || this.sensors.map(sensor => sensor.device);
        const sensors = this.sensors.filter(sensor => selected.includes(sensor.device) && Number.isFinite(parseFloat(sensor.temperature)));
        if (sensors.length === 0) {
            $container.html(`<div class="dashboard-plus-empty">${escapeHtml(this.translations.no_sensors)}</div>`);
            return;
        }
        $container.html(sensors.map(sensor => {
            const celsius = parseFloat(sensor.temperature);
            const width = Math.min(Math.max(celsius, 0), 100);
            return `<div class="dashboard-plus-sensor">
                <div class="dashboard-plus-sensor-head"><span>${escapeHtml(this._sensorLabel(sensor))}</span>
                    <span class="dashboard-plus-tabular">${escapeHtml(celsius.toFixed(1))} °C</span></div>
                <div class="progress dashboard-plus-bar"><div class="progress-bar progress-bar-${this._sensorColor(celsius)}" role="progressbar"
                    aria-valuenow="${width}" aria-valuemin="0" aria-valuemax="100" style="width: ${width}%;"></div></div>
            </div>`;
        }).join(''));
    }

    getMarkup() {
        ensureStyle();
        return $(`
            <div id="${this.id}-sensors" class="dashboard-plus-sensors"></div>
        `);
    }

    async onMarkupRendered() {
        renderTitle(this);
        this.currentConfig = await this.getWidgetConfig();
        this.fitToContent();
    }

    async getWidgetOptions() {
        const data = await this.ajaxCall('/api/diagnostics/system/system_temperature');
        const sensors = Array.isArray(data) ? data : [];
        return {
            sensors: {
                title: this.translations.sensors,
                type: 'select_multiple',
                id: 'dashboard-plus-thermal-sensors',
                options: sensors.map(sensor => ({value: sensor.device, label: this._sensorLabel(sensor)})),
                default: sensors.map(sensor => sensor.device)
            }
        };
    }

    async onWidgetOptionsChanged() {
        // Read back through getWidgetConfig so an empty selection means the defaults now,
        // as it will after the dashboard reloads.
        this.currentConfig = await this.getWidgetConfig();
        this._renderSensors();
    }

    async onWidgetTick() {
        const data = await this.ajaxCall('/api/diagnostics/system/system_temperature');
        this.sensors = Array.isArray(data) ? data : [];
        this._renderSensors();
    }
}
