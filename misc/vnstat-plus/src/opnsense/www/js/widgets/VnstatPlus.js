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
        this.showKpi = true;
        this.showChart = true;
        this.showHistory = true;
        this.barRange = '3';
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
            },
            visible_sections: {
                id: this._elementId('visible-sections'),
                title: this.translations.visible_sections,
                type: 'select_multiple',
                options: [
                    {value: 'kpi', label: this.translations.kpi_cards},
                    {value: 'chart', label: this.translations.traffic_overview},
                    {value: 'history', label: this.translations.history}
                ],
                default: ['kpi', 'chart', 'history']
            },
            bar_range: {
                id: this._elementId('bar-range'),
                title: this.translations.bar_range,
                type: 'select',
                options: [
                    {value: 'current', label: this.translations.current_period},
                    {value: '1', label: this.translations.latest_one},
                    {value: '3', label: this.translations.latest_three},
                    {value: '6', label: this.translations.latest_six},
                    {value: '12', label: this.translations.latest_twelve}
                ],
                default: '3'
            }
        };
    }

    async onWidgetOptionsChanged() {
        this._applyConfig(await this.getWidgetConfig());
        await this._populateInterfaceDropdown();
        await this._fetchAndRender();
        this._applyVisibility();
        this.config.callbacks?.updateGrid?.();
    }

    getMarkup() {
        const rootId = this._elementId('root');
        const interfaceId = this._elementId('interface');
        const periodId = this._elementId('period');
        const rangeId = this._elementId('range');
        const refreshId = this._elementId('refresh');

        return $(`
            <div id="${rootId}" class="vnstat-plus-root" style="padding: 0 0.35em 0.35em;">
                <style>
                    #${rootId} .vnstat-plus-controls { display: flex; flex-wrap: wrap; gap: 0.4em; align-items: center; margin: 0 0 0.55em; }
                    #${rootId} .vnstat-plus-controls select { min-width: 7em; flex: 1 1 7em; }
                    #${rootId} .vnstat-plus-controls button { flex: 0 0 auto; }
                    #${rootId} .vnstat-plus-summary { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 0.45em; margin-bottom: 0.7em; }
                    #${rootId} .vnstat-plus-card { border: 1px solid rgba(128,128,128,0.32); border-radius: 4px; padding: 0.45em 0.55em; min-width: 0; }
                    #${rootId} .vnstat-plus-card-label { color: var(--vnstat-plus-muted); font-size: 0.78em; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
                    #${rootId} .vnstat-plus-card-value { font-size: 1.15em; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
                    #${rootId} .vnstat-plus-card-rx .vnstat-plus-card-value { color: var(--vnstat-plus-rx); }
                    #${rootId} .vnstat-plus-card-tx .vnstat-plus-card-value { color: var(--vnstat-plus-tx); }
                    #${rootId} .vnstat-plus-card-total .vnstat-plus-card-value { color: var(--vnstat-plus-total); }
                    #${rootId} .vnstat-plus-section-title { color: var(--vnstat-plus-muted); font-size: 0.9em; font-weight: 600; margin: 0.4em 0; }
                    #${rootId} .vnstat-plus-chart { display: flex; flex-direction: column; gap: 0.25em; }
                    #${rootId} .vnstat-plus-bar-row { display: grid; grid-template-columns: 6.2em minmax(0, 1fr) 5.2em; gap: 0.45em; align-items: center; font-size: 0.82em; position: relative; outline: none; }
                    #${rootId} .vnstat-plus-bar-label, #${rootId} .vnstat-plus-bar-total { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
                    #${rootId} .vnstat-plus-bar-total { text-align: right; color: var(--vnstat-plus-muted); }
                    #${rootId} .vnstat-plus-bar-track { height: 0.9em; display: flex; min-width: 0; border: 1px solid var(--vnstat-plus-border); border-radius: 2px; overflow: hidden; }
                    #${rootId} .vnstat-plus-bar-rx { background: var(--vnstat-plus-rx); }
                    #${rootId} .vnstat-plus-bar-tx { background: var(--vnstat-plus-tx); }
                    #${rootId} .vnstat-plus-tooltip { display: none; position: absolute; left: 6.65em; bottom: calc(100% + 0.35em); z-index: 5; max-width: 90%; padding: 0.35em 0.55em; border: 1px solid var(--vnstat-plus-tooltip-border); border-radius: 4px; background: var(--vnstat-plus-tooltip-bg); color: var(--vnstat-plus-tooltip-text); white-space: nowrap; pointer-events: none; box-shadow: 0 2px 8px rgba(0,0,0,0.35); }
                    #${rootId} .vnstat-plus-bar-row:hover .vnstat-plus-tooltip, #${rootId} .vnstat-plus-bar-row:focus .vnstat-plus-tooltip { display: block; }
                    #${rootId} .vnstat-plus-legend { display: flex; gap: 0.9em; color: var(--vnstat-plus-muted); font-size: 0.78em; margin: 0.5em 0 0.7em 6.65em; }
                    #${rootId} .vnstat-plus-dot { display: inline-block; width: 0.7em; height: 0.7em; border-radius: 50%; margin-right: 0.25em; }
                    #${rootId} .vnstat-plus-table-wrap { overflow-x: auto; }
                    #${rootId} table { width: 100%; margin-bottom: 0; font-size: 0.82em; }
                    #${rootId} th { color: var(--vnstat-plus-muted); font-weight: 600; }
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
                    <select id="${rangeId}" class="form-control" aria-label="${this._escape(this.translations.bar_range)}">
                        <option value="current">${this._escape(this.translations.current_period)}</option>
                        <option value="1">${this._escape(this.translations.latest_one)}</option>
                        <option value="3" selected>${this._escape(this.translations.latest_three)}</option>
                        <option value="6">${this._escape(this.translations.latest_six)}</option>
                        <option value="12">${this._escape(this.translations.latest_twelve)}</option>
                    </select>
                    <button id="${refreshId}" type="button" class="btn btn-default" title="${this._escape(this.translations.refresh)}" aria-label="${this._escape(this.translations.refresh)}"><i class="fa fa-refresh"></i></button>
                </div>
                <div id="${this._elementId('summary')}" class="vnstat-plus-summary"></div>
                <div id="${this._elementId('chart-title')}" class="vnstat-plus-section-title">${this._escape(this.translations.traffic_chart)}</div>
                <div id="${this._elementId('chart')}" class="vnstat-plus-chart"></div>
                <div id="${this._elementId('legend')}" class="vnstat-plus-legend">
                    <span><i class="vnstat-plus-dot" style="background:var(--vnstat-plus-rx);"></i>${this._escape(this.translations.download)}</span>
                    <span><i class="vnstat-plus-dot" style="background:var(--vnstat-plus-tx);"></i>${this._escape(this.translations.upload)}</span>
                </div>
                <div id="${this._elementId('history-title')}" class="vnstat-plus-section-title">${this._escape(this.translations.history)}</div>
                <div id="${this._elementId('table')}" class="vnstat-plus-table-wrap"></div>
            </div>
        `);
    }

    async onMarkupRendered() {
        this._applyConfig(await this.getWidgetConfig());
        const $root = $(`#${this._elementId('root')}`);
        const $interface = $(`#${this._elementId('interface')}`);
        const $period = $(`#${this._elementId('period')}`);
        const $range = $(`#${this._elementId('range')}`);
        this._applyTheme();
        $(`#${this.id}-title`).html(`<b>${this._escape(this.translations.dashboard_title)}</b>`);

        const prefs = this._loadPrefs();
        if (prefs?.period) {
            this.currentPeriod = prefs.period;
            $period.val(this.currentPeriod);
        }
        if (prefs?.interface) {
            this.currentInterface = prefs.interface;
        }
        if (prefs?.barRange) {
            this.barRange = prefs.barRange;
            $range.val(this.barRange);
        }

        $root.on('change.vnstat-plus-widget', `#${this._elementId('period')}`, async event => {
            this.currentPeriod = event.target.value;
            this._savePrefs();
            await this._fetchAndRender();
            this.config.callbacks?.updateGrid?.();
        });
        $root.on('change.vnstat-plus-widget', `#${this._elementId('range')}`, async event => {
            this.barRange = event.target.value;
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
        this._applyVisibility();
        this.config.callbacks?.updateGrid?.();
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
        let sections = config.visible_sections;
        if (!sections) {
            sections = ['kpi', 'chart', 'history']
                .filter(section => config[`show_${section}`] !== 'no');
        }
        if (!Array.isArray(sections)) {
            sections = String(sections).split(',').map(section => section.trim()).filter(Boolean);
        }
        this.showKpi = sections.includes('kpi');
        this.showChart = sections.includes('chart');
        this.showHistory = sections.includes('history');
        this.barRange = ['current', '1', '3', '6', '12'].includes(config.bar_range) ? config.bar_range : '3';
        $(`#${this._elementId('range')}`).val(this.barRange);
        this._applyVisibility();
    }

    _applyTheme() {
        const $root = $(`#${this._elementId('root')}`);
        if (!$root.length || typeof getComputedStyle !== 'function') {
            return;
        }

        const readSemanticColor = className => {
            const probe = $('<span></span>').addClass(className).css({
                position: 'absolute',
                visibility: 'hidden'
            }).appendTo($root)[0];
            const color = getComputedStyle(probe).color;
            $(probe).remove();
            return color;
        };
        const readUsableColor = (node, property, fallback) => {
            const color = node ? getComputedStyle(node)[property] : '';
            return color && color !== 'rgba(0, 0, 0, 0)' ? color : fallback;
        };
        const widget = $root.closest('.widget')[0] || $root[0];
        const widgetStyle = getComputedStyle(widget);
        const rootStyle = $root[0].style;
        rootStyle.setProperty('--vnstat-plus-rx', readSemanticColor('text-info'));
        rootStyle.setProperty('--vnstat-plus-tx', readSemanticColor('text-warning'));
        rootStyle.setProperty('--vnstat-plus-total', readSemanticColor('text-success'));
        rootStyle.setProperty('--vnstat-plus-muted', readSemanticColor('text-muted'));
        rootStyle.setProperty('--vnstat-plus-border', readSemanticColor('text-muted'));
        rootStyle.setProperty('--vnstat-plus-tooltip-bg', readUsableColor(widget, 'backgroundColor', '#20242b'));
        rootStyle.setProperty('--vnstat-plus-tooltip-text', readUsableColor(widget, 'color', '#f4f4f4'));
        rootStyle.setProperty('--vnstat-plus-tooltip-border', widgetStyle.color || '#888');
    }

    _applyVisibility() {
        $(`#${this._elementId('summary')}`).toggle(this.showKpi);
        $(`#${this._elementId('chart-title')}, #${this._elementId('chart')}, #${this._elementId('legend')}`).toggle(this.showChart);
        $(`#${this._elementId('history-title')}, #${this._elementId('table')}`).toggle(this.showHistory);
        $(`#${this._elementId('range')}`).toggle(this.showChart);
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

        const entries = traffic.slice().sort((a, b) => this._dateToSortKey(a) - this._dateToSortKey(b));
        const tableLimits = {hour: 12, day: 14, month: 12, year: 5};
        const tableEntries = entries.slice(-tableLimits[this.currentPeriod]);
        const chartEntries = this._chartEntries(entries);
        this._renderSummary(entries[entries.length - 1]);
        this._renderChart(chartEntries);
        this._renderTable(tableEntries.slice().reverse());
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
            const tooltip = `${date} · ${this.translations.download}: ${this._formatBytes(rx)} · ${this.translations.upload}: ${this._formatBytes(tx)} · ${this.translations.total}: ${this._formatBytes(total)}`;
            return `
                <div class="vnstat-plus-bar-row" tabindex="0" aria-label="${this._escape(tooltip)}">
                    <span class="vnstat-plus-bar-label">${this._escape(date)}</span>
                    <span class="vnstat-plus-bar-track"><i class="vnstat-plus-bar-rx" style="width:${rxWidth}%;" title="${this._escape(`${this.translations.download}: ${this._formatBytes(rx)}`)}"></i><i class="vnstat-plus-bar-tx" style="width:${txWidth}%;" title="${this._escape(`${this.translations.upload}: ${this._formatBytes(tx)}`)}"></i></span>
                    <span class="vnstat-plus-bar-total">${this._escape(this._formatBytes(total))}</span>
                    <span class="vnstat-plus-tooltip">${this._escape(tooltip)}</span>
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
                period: this.currentPeriod,
                barRange: this.barRange
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

    _chartEntries(entries) {
        if (this.barRange === 'current') {
            return entries.slice(-1);
        }
        return entries.slice(-Math.max(1, Number(this.barRange) || 3));
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
