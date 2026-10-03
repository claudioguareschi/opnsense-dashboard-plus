/*
 * VNStat Traffic+ dashboard widget for OPNsense.
 *
 * This widget uses the read-only API exposed by os-vnstat.  It deliberately
 * lives beside the stock Vnstat widget so the original widget remains an
 * immediate rollback option.
 */

export default class VnstatPlus extends BaseWidget {
    constructor(config) {
        super(config);
        this.configurable = true;
        this.currentPeriod = 'month';
        this.currentInterface = null;
        this.excludedInterfaces = [];
        this.refreshSeconds = 300;
        this.fetchPromise = null;
    }

    getGridOptions() {
        return {
            sizeToContent: 720
        };
    }

    _elementId(name) {
        return `${this.id}-vnstat-plus-${name}`;
    }

    _escape(value) {
        return $('<div>').text(String(value ?? '')).html();
    }

    async getWidgetOptions() {
        const data = await this.ajaxCall('/api/vnstat/service/interface_list');
        const interfaces = (data?.interfaces ?? []).map(name => ({value: name, label: name}));

        return {
            excluded_interfaces: {
                id: this._elementId('exclude-interfaces'),
                title: this.translations.excluded_interfaces,
                type: 'select_multiple',
                options: interfaces,
                default: []
            },
            refresh_interval: {
                id: this._elementId('refresh-interval'),
                title: this.translations.refresh_interval,
                type: 'select',
                options: [
                    {value: '60', label: '1'},
                    {value: '120', label: '2'},
                    {value: '300', label: '5'},
                    {value: '600', label: '10'},
                    {value: '900', label: '15'},
                    {value: '1800', label: '30'}
                ],
                default: '300'
            }
        };
    }

    async onWidgetOptionsChanged() {
        this._applyConfig(await this.getWidgetConfig());
        await this._populateInterfaceDropdown();
        await this._fetchAndRender();
        this.config.callbacks?.updateGrid?.();
    }

    getMarkup() {
        const rootId = this._elementId('root');
        const interfaceId = this._elementId('interface');
        const periodId = this._elementId('period');
        const refreshId = this._elementId('refresh');

        return $(`
            <div id="${rootId}" class="vnstat-plus-root" style="padding: 0 0.35em 0.35em;">
                <style>
                    #${rootId} .vnstat-plus-controls { display: flex; gap: 0.4em; align-items: center; margin: 0 0 0.55em; }
                    #${rootId} .vnstat-plus-controls select { min-width: 0; flex: 1 1 0; }
                    #${rootId} .vnstat-plus-controls button { flex: 0 0 auto; }
                    #${rootId} .vnstat-plus-summary { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 0.45em; margin-bottom: 0.7em; }
                    #${rootId} .vnstat-plus-card { border: 1px solid rgba(128,128,128,0.32); border-radius: 4px; padding: 0.45em 0.55em; min-width: 0; }
                    #${rootId} .vnstat-plus-card-label { color: #888; font-size: 0.78em; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
                    #${rootId} .vnstat-plus-card-value { font-size: 1.15em; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
                    #${rootId} .vnstat-plus-card-rx .vnstat-plus-card-value { color: #58a6ff; }
                    #${rootId} .vnstat-plus-card-tx .vnstat-plus-card-value { color: #f0a35b; }
                    #${rootId} .vnstat-plus-card-total .vnstat-plus-card-value { color: #70c596; }
                    #${rootId} .vnstat-plus-section-title { font-size: 0.9em; font-weight: 600; margin: 0.4em 0; }
                    #${rootId} .vnstat-plus-chart { display: flex; flex-direction: column; gap: 0.25em; }
                    #${rootId} .vnstat-plus-bar-row { display: grid; grid-template-columns: 6.2em minmax(0, 1fr) 5.2em; gap: 0.45em; align-items: center; font-size: 0.82em; }
                    #${rootId} .vnstat-plus-bar-label, #${rootId} .vnstat-plus-bar-total { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
                    #${rootId} .vnstat-plus-bar-total { text-align: right; color: #aaa; }
                    #${rootId} .vnstat-plus-bar-track { height: 0.9em; display: flex; min-width: 0; background: rgba(128,128,128,0.15); border-radius: 2px; overflow: hidden; }
                    #${rootId} .vnstat-plus-bar-rx { background: #58a6ff; }
                    #${rootId} .vnstat-plus-bar-tx { background: #f0a35b; }
                    #${rootId} .vnstat-plus-legend { display: flex; gap: 0.9em; color: #999; font-size: 0.78em; margin: 0.5em 0 0.7em 6.65em; }
                    #${rootId} .vnstat-plus-dot { display: inline-block; width: 0.7em; height: 0.7em; border-radius: 50%; margin-right: 0.25em; }
                    #${rootId} .vnstat-plus-table-wrap { overflow-x: auto; }
                    #${rootId} table { width: 100%; margin-bottom: 0; font-size: 0.82em; }
                    #${rootId} th { color: #999; font-weight: 600; }
                    #${rootId} th:not(:first-child), #${rootId} td:not(:first-child) { text-align: right; }
                    #${rootId} .vnstat-plus-empty { color: #999; padding: 1em 0; text-align: center; }
                    @media (max-width: 420px) {
                        #${rootId} .vnstat-plus-summary { grid-template-columns: 1fr; }
                        #${rootId} .vnstat-plus-bar-row { grid-template-columns: 5.4em minmax(0, 1fr) 4.5em; }
                        #${rootId} .vnstat-plus-legend { margin-left: 5.85em; }
                    }
                </style>
                <div class="vnstat-plus-controls">
                    <select id="${interfaceId}" class="form-control" aria-label="${this._escape(this.translations.interface)}"></select>
                    <select id="${periodId}" class="form-control" aria-label="${this._escape(this.translations.period)}">
                        <option value="hour">${this._escape(this.translations.period_hourly)}</option>
                        <option value="day">${this._escape(this.translations.period_daily)}</option>
                        <option value="month" selected>${this._escape(this.translations.period_monthly)}</option>
                        <option value="year">${this._escape(this.translations.period_yearly)}</option>
                    </select>
                    <button id="${refreshId}" type="button" class="btn btn-default" title="${this._escape(this.translations.refresh)}" aria-label="${this._escape(this.translations.refresh)}"><i class="fa fa-refresh"></i></button>
                </div>
                <div id="${this._elementId('summary')}" class="vnstat-plus-summary"></div>
                <div class="vnstat-plus-section-title">${this._escape(this.translations.traffic_chart)}</div>
                <div id="${this._elementId('chart')}" class="vnstat-plus-chart"></div>
                <div class="vnstat-plus-legend">
                    <span><i class="vnstat-plus-dot" style="background:#58a6ff;"></i>${this._escape(this.translations.download)}</span>
                    <span><i class="vnstat-plus-dot" style="background:#f0a35b;"></i>${this._escape(this.translations.upload)}</span>
                </div>
                <div class="vnstat-plus-section-title">${this._escape(this.translations.history)}</div>
                <div id="${this._elementId('table')}" class="vnstat-plus-table-wrap"></div>
            </div>
        `);
    }

    async onMarkupRendered() {
        this._applyConfig(await this.getWidgetConfig());
        const $root = $(`#${this._elementId('root')}`);
        const $interface = $(`#${this._elementId('interface')}`);
        const $period = $(`#${this._elementId('period')}`);

        const prefs = this._loadPrefs();
        if (prefs?.period) {
            this.currentPeriod = prefs.period;
            $period.val(this.currentPeriod);
        }
        if (prefs?.interface) {
            this.currentInterface = prefs.interface;
        }

        $root.on('change.vnstat-plus-widget', `#${this._elementId('period')}`, async event => {
            this.currentPeriod = event.target.value;
            this._savePrefs();
            await this._fetchAndRender();
            this.config.callbacks?.updateGrid?.();
        });
        $root.on('change.vnstat-plus-widget', `#${this._elementId('interface')}`, async event => {
            this.currentInterface = event.target.value;
            this._savePrefs();
            await this._fetchAndRender();
            this.config.callbacks?.updateGrid?.();
        });
        $root.on('click.vnstat-plus-widget', `#${this._elementId('refresh')}`, async event => {
            event.preventDefault();
            await this._fetchAndRender();
        });

        await this._populateInterfaceDropdown();
        await this._fetchAndRender();
    }

    async onWidgetTick() {
        await this._fetchAndRender();
    }

    onWidgetClose() {
        $(`#${this._elementId('root')}`).off('.vnstat-plus-widget');
    }

    _applyConfig(config = {}) {
        this.excludedInterfaces = config.excluded_interfaces ?? [];
        this.refreshSeconds = Number(config.refresh_interval) || 300;
        this.tickTimeout = this.refreshSeconds;
    }

    async _populateInterfaceDropdown() {
        const data = await this.ajaxCall('/api/vnstat/service/interface_list');
        if (!data?.interfaces) {
            return;
        }

        const names = data.interfaces.filter(name => !this.excludedInterfaces.includes(name));
        const $select = $(`#${this._elementId('interface')}`);
        $select.empty();
        names.forEach(name => {
            $select.append($('<option></option>').val(name).text(name));
        });

        if (this.currentInterface && names.includes(this.currentInterface)) {
            $select.val(this.currentInterface);
        } else if (names.includes('WAN')) {
            this.currentInterface = 'WAN';
            $select.val('WAN');
        } else if (names.length > 0) {
            this.currentInterface = names[0];
            $select.val(names[0]);
        } else {
            this.currentInterface = null;
        }
        this._savePrefs();
    }

    async _fetchAndRender() {
        if (this.fetchPromise) {
            return this.fetchPromise;
        }

        this.fetchPromise = this._fetchAndRenderOnce().finally(() => {
            this.fetchPromise = null;
        });
        return this.fetchPromise;
    }

    async _fetchAndRenderOnce() {
        if (!this.currentInterface) {
            this._renderEmpty(this.translations.msg_no_data);
            return;
        }

        const data = await this.ajaxCall(`/api/vnstat/service/get_json_data?iface=${encodeURIComponent(this.currentInterface)}`);
        const iface = data?.interfaces?.[0];
        const traffic = iface?.traffic?.[this.currentPeriod];
        if (data?.error || !Array.isArray(traffic) || traffic.length === 0) {
            this._renderEmpty(this.translations.msg_no_data);
            return;
        }

        const limits = {hour: 12, day: 14, month: 12, year: 5};
        const entries = traffic.slice().sort((a, b) => this._dateToSortKey(a) - this._dateToSortKey(b));
        const visible = entries.slice(-limits[this.currentPeriod]);
        this._renderSummary(visible[visible.length - 1]);
        this._renderChart(visible);
        this._renderTable(visible.slice().reverse());
    }

    _renderEmpty(message) {
        const empty = `<div class="vnstat-plus-empty">${this._escape(message)}</div>`;
        $(`#${this._elementId('summary')}`).html(empty);
        $(`#${this._elementId('chart')}`).empty();
        $(`#${this._elementId('table')}`).html(empty);
    }

    _renderSummary(entry) {
        const rx = Number(entry?.rx) || 0;
        const tx = Number(entry?.tx) || 0;
        const cards = [
            {className: 'rx', label: this.translations.download, value: this._formatBytes(rx)},
            {className: 'tx', label: this.translations.upload, value: this._formatBytes(tx)},
            {className: 'total', label: this.translations.total, value: this._formatBytes(rx + tx)}
        ];
        const html = cards.map(card => `
            <div class="vnstat-plus-card vnstat-plus-card-${card.className}">
                <div class="vnstat-plus-card-label">${this._escape(card.label)}</div>
                <div class="vnstat-plus-card-value">${this._escape(card.value)}</div>
            </div>
        `).join('');
        $(`#${this._elementId('summary')}`).html(html);
    }

    _renderChart(entries) {
        const maxTotal = Math.max(...entries.map(entry => (Number(entry.rx) || 0) + (Number(entry.tx) || 0)), 1);
        const html = entries.map(entry => {
            const rx = Number(entry.rx) || 0;
            const tx = Number(entry.tx) || 0;
            const total = rx + tx;
            const rxWidth = Math.min(100, (rx / maxTotal) * 100);
            const txWidth = Math.min(100 - rxWidth, (tx / maxTotal) * 100);
            const date = this._formatDate(entry);
            return `
                <div class="vnstat-plus-bar-row" title="${this._escape(`${date}: ${this._formatBytes(total)}`)}">
                    <span class="vnstat-plus-bar-label">${this._escape(date)}</span>
                    <span class="vnstat-plus-bar-track"><i class="vnstat-plus-bar-rx" style="width:${rxWidth}%;"></i><i class="vnstat-plus-bar-tx" style="width:${txWidth}%;"></i></span>
                    <span class="vnstat-plus-bar-total">${this._escape(this._formatBytes(total))}</span>
                </div>
            `;
        }).join('');
        $(`#${this._elementId('chart')}`).html(html);
    }

    _renderTable(entries) {
        const rows = entries.map(entry => {
            const rx = Number(entry.rx) || 0;
            const tx = Number(entry.tx) || 0;
            return `
                <tr>
                    <td>${this._escape(this._formatDate(entry))}</td>
                    <td>${this._escape(this._formatBytes(rx))}</td>
                    <td>${this._escape(this._formatBytes(tx))}</td>
                    <td>${this._escape(this._formatBytes(rx + tx))}</td>
                </tr>
            `;
        }).join('');
        const html = `
            <table class="table table-condensed">
                <thead><tr><th>${this._escape(this.translations.date)}</th><th>${this._escape(this.translations.download)}</th><th>${this._escape(this.translations.upload)}</th><th>${this._escape(this.translations.total)}</th></tr></thead>
                <tbody>${rows}</tbody>
            </table>
        `;
        $(`#${this._elementId('table')}`).html(html);
    }

    _savePrefs() {
        try {
            localStorage.setItem('vnstat-plus-widget-prefs', JSON.stringify({
                interface: this.currentInterface,
                period: this.currentPeriod
            }));
        } catch (error) {
            // localStorage can be unavailable in private browsing modes.
        }
    }

    _loadPrefs() {
        try {
            const raw = localStorage.getItem('vnstat-plus-widget-prefs');
            return raw ? JSON.parse(raw) : null;
        } catch (error) {
            return null;
        }
    }

    _formatBytes(bytes) {
        if (!bytes) {
            return '0 B';
        }
        const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
        const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
        const value = bytes / Math.pow(1024, index);
        return `${value >= 100 || index === 0 ? value.toFixed(0) : value.toFixed(2)} ${units[index]}`;
    }

    _formatDate(entry) {
        const date = entry.date || {};
        if (this.currentPeriod === 'year') {
            return `${date.year}`;
        }
        if (this.currentPeriod === 'month') {
            return `${date.year}-${String(date.month).padStart(2, '0')}`;
        }
        if (this.currentPeriod === 'hour') {
            return `${date.year}-${String(date.month).padStart(2, '0')}-${String(date.day).padStart(2, '0')} ${String(entry.time?.hour ?? 0).padStart(2, '0')}:00`;
        }
        return `${date.year}-${String(date.month).padStart(2, '0')}-${String(date.day).padStart(2, '0')}`;
    }

    _dateToSortKey(entry) {
        const date = entry.date || {};
        if (this.currentPeriod === 'year') {
            return date.year;
        }
        if (this.currentPeriod === 'month') {
            return date.year * 100 + date.month;
        }
        if (this.currentPeriod === 'hour') {
            return date.year * 100000000 + date.month * 1000000 + date.day * 10000 + (entry.time?.hour ?? 0);
        }
        return date.year * 10000 + date.month * 100 + date.day;
    }
}
