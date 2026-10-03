/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
 * All rights reserved.
 */

const {renderTitle, DashboardPlusWidget} =
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
            return `${this.translations.core} ${sensor.device_seq}`;
        }
        return `${sensor.type_translated} ${sensor.device_seq}`;
    }

    _sensorColor(celsius) {
        return celsius >= 80 ? '#d62728' : celsius >= 70 ? '#ff7f0e' : '#2ca02c';
    }

    _renderSensors() {
        const container = document.getElementById(`${this.id}-sensors`);
        if (!container) {
            return;
        }
        const selected = this.currentConfig?.sensors || this.sensors.map(sensor => sensor.device);
        const sensors = this.sensors.filter(sensor => selected.includes(sensor.device));
        container.replaceChildren();
        if (sensors.length === 0) {
            const empty = document.createElement('div');
            empty.textContent = this.translations.no_sensors;
            container.append(empty);
            return;
        }
        for (const sensor of sensors) {
            const celsius = parseFloat(sensor.temperature);
            if (!Number.isFinite(celsius)) {
                continue;
            }
            const row = document.createElement('div');
            row.style.cssText = 'padding: 0.35em 0;';
            const header = document.createElement('div');
            header.style.cssText = 'display: flex; justify-content: space-between; align-items: baseline;';
            const label = document.createElement('span');
            label.textContent = this._sensorLabel(sensor);
            const value = document.createElement('span');
            value.textContent = `${celsius.toFixed(1)} °C`;
            header.append(label, value);
            const bar = document.createElement('div');
            bar.style.cssText = 'margin-top: 0.2em; height: 0.75em; background: rgba(119,119,119,0.12); border-radius: 0.375em; overflow: hidden;';
            const fill = document.createElement('div');
            fill.style.cssText = `height: 100%; width: ${Math.min(celsius, 100)}%; background: ${this._sensorColor(celsius)}; transition: width 0.2s ease;`;
            bar.append(fill);
            row.append(header, bar);
            container.append(row);
        }
    }

    getMarkup() {
        return $(`
            <div id="${this.id}-sensors" style="width: 95%; margin: 0.25em auto;"></div>
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
