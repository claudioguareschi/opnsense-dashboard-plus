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
        this.barRange = '12';
        this.chartOffset = 0;
        this.trafficChart = null;
        this.chartPaging = false;
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
        const data = await this.ajaxCall('/api/vnstatplus/interfaces/list');
        const interfaces = data?.interfaces ?? [];

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
                default: '12'
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
            <div id="${rootId}" class="vnstat-plus-root">
                <style>
                    #${rootId} { width: 95%; margin: 0.25em auto; }
                    #${rootId} .vnstat-plus-controls { display: flex; flex-wrap: wrap; gap: 0.4em; align-items: center; margin: 0 0 0.55em; }
                    #${rootId} .vnstat-plus-controls .bootstrap-select { min-width: 7em; flex: 1 1 7em; }
                    #${rootId} .vnstat-plus-controls .bootstrap-select > .dropdown-toggle { height: 2.55em; padding: 0.45em 0.7em; border-color: rgba(127,127,127,0.3); background: var(--vnstat-plus-select-background); color: inherit; }
                    #${rootId} .vnstat-plus-controls .bootstrap-select.open > .dropdown-toggle,
                    #${rootId} .vnstat-plus-controls .bootstrap-select > .dropdown-toggle:focus { border-color: #d94f00; box-shadow: 0 0 0 0.15rem rgba(217,79,0,0.2); }
                    #${rootId} .vnstat-plus-controls .bootstrap-select .dropdown-menu > li.selected > a { background: #d94f00; color: #fff; }
                    #${rootId} .vnstat-plus-controls button { flex: 0 0 auto; }
                    #${rootId} .vnstat-plus-summary { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 0.45em; margin-bottom: 0.7em; }
                    #${rootId} .vnstat-plus-card { border: 1px solid rgba(127,127,127,0.24); border-radius: 3px; background: rgba(127,127,127,0.06); padding: 0.6em 0.65em; min-width: 0; }
                    #${rootId} .vnstat-plus-card-label { color: currentColor; opacity: 0.68; font-size: 0.78em; letter-spacing: 0.02em; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
                    #${rootId} .vnstat-plus-card-value { margin-top: 0.18em; font-size: 1.16em; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-variant-numeric: tabular-nums; }
                    #${rootId} .vnstat-plus-card-detail { margin-top: 0.12em; color: currentColor; opacity: 0.64; font-size: 0.76em; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
                    #${rootId} .vnstat-plus-section-title { color: var(--vnstat-plus-muted); font-size: 0.9em; font-weight: 600; margin: 0.7em 0 0.4em; text-align: left; }
                    #${rootId} .vnstat-plus-chart { height: 16em; min-height: 12em; position: relative; }
                    #${rootId} .vnstat-plus-chart canvas { height: 100% !important; width: 100% !important; }
                    #${rootId} .vnstat-plus-legend { display: flex; flex-wrap: wrap; justify-content: center; gap: 0.3em 1.2em; margin: 0.55em 0 0.75em; font-size: 0.9em; }
                    #${rootId} .vnstat-plus-bar-row { display: grid; grid-template-columns: 6.2em minmax(0, 1fr) 5.2em; gap: 0.45em; align-items: center; font-size: 0.82em; position: relative; outline: none; }
                    #${rootId} .vnstat-plus-bar-label, #${rootId} .vnstat-plus-bar-total { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
                    #${rootId} .vnstat-plus-bar-total { text-align: right; color: var(--vnstat-plus-muted); }
                    #${rootId} .vnstat-plus-bar-track { height: 0.9em; display: flex; min-width: 0; border: 1px solid var(--vnstat-plus-border); border-radius: 2px; overflow: hidden; }
                    #${rootId} .vnstat-plus-bar-rx { background: var(--vnstat-plus-rx); }
                    #${rootId} .vnstat-plus-bar-tx { background: var(--vnstat-plus-tx); }
                    #${rootId} .vnstat-plus-tooltip { display: none; position: absolute; left: 6.65em; bottom: calc(100% + 0.35em); z-index: 5; max-width: 90%; padding: 0.35em 0.55em; border: 1px solid var(--vnstat-plus-tooltip-border); border-radius: 4px; background: var(--vnstat-plus-tooltip-bg); color: var(--vnstat-plus-tooltip-text); white-space: nowrap; pointer-events: none; box-shadow: 0 2px 8px rgba(0,0,0,0.35); }
                    #${rootId} .vnstat-plus-bar-row:hover .vnstat-plus-tooltip, #${rootId} .vnstat-plus-bar-row:focus .vnstat-plus-tooltip { display: block; }
                    #${rootId} .vnstat-plus-dot { display: inline-block; width: 0.8em; height: 0.8em; border-radius: 50%; margin-right: 0.3em; vertical-align: -0.05em; }
                    #${rootId} .vnstat-plus-table-wrap { overflow-x: auto; }
                    #${rootId} .vnstat-plus-table-wrap { max-height: 10.5em; overflow-y: auto; }
                    #${rootId} table { width: 100%; margin-bottom: 0; font-size: 0.82em; }
                    #${rootId} th { color: var(--vnstat-plus-muted); font-weight: 600; }
                    #${rootId} thead th { position: sticky; top: 0; background: var(--vnstat-plus-table-background); z-index: 1; }
                    #${rootId} th:not(:first-child), #${rootId} td:not(:first-child) { text-align: right; }
                    #${rootId} .vnstat-plus-empty { color: #999; padding: 1em 0; text-align: center; }
                    @media (max-width: 420px) {
                        #${rootId} .vnstat-plus-summary { grid-template-columns: 1fr; }
                        #${rootId} .vnstat-plus-bar-row { grid-template-columns: 5.4em minmax(0, 1fr) 4.5em; }
                    }
                </style>
                <div class="vnstat-plus-controls">
                    <select id="${interfaceId}" class="selectpicker" data-live-search="true" aria-label="${this._escape(this.translations.interface)}"></select>
                    <select id="${periodId}" class="selectpicker" aria-label="${this._escape(this.translations.period)}">
                        <option value="hour" data-icon="fa fa-clock-o">${this._escape(this.translations.period_hourly)}</option>
                        <option value="day" data-icon="fa fa-calendar">${this._escape(this.translations.period_daily)}</option>
                        <option value="month" data-icon="fa fa-calendar" selected>${this._escape(this.translations.period_monthly)}</option>
                        <option value="year" data-icon="fa fa-calendar">${this._escape(this.translations.period_yearly)}</option>
                    </select>
                    <select id="${rangeId}" class="selectpicker" aria-label="${this._escape(this.translations.bar_range)}">
                    </select>
                    <button id="${refreshId}" type="button" class="btn btn-default" title="${this._escape(this.translations.refresh)}" aria-label="${this._escape(this.translations.refresh)}"><i class="fa fa-refresh"></i></button>
                </div>
                <div id="${this._elementId('chart-title')}" class="vnstat-plus-section-title">${this._escape(this.translations.traffic_chart)}</div>
                <div id="${this._elementId('chart')}" class="vnstat-plus-chart" title="${this._escape(this.translations.chart_scroll_hint)}"></div>
                <div id="${this._elementId('legend')}" class="vnstat-plus-legend">
                    <span><i class="vnstat-plus-dot" style="background:var(--vnstat-plus-rx);"></i>${this._escape(this.translations.download)}</span>
                    <span><i class="vnstat-plus-dot" style="background:var(--vnstat-plus-tx);"></i>${this._escape(this.translations.upload)}</span>
                    <span><i class="vnstat-plus-dot" style="background:var(--vnstat-plus-total);"></i>${this._escape(this.translations.total)}</span>
                </div>
                <div id="${this._elementId('summary')}" class="vnstat-plus-summary"></div>
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
        }
        this._populateRangeDropdown();
        this._initSelectPickers();

        $root.on('change.vnstat-plus-widget', `#${this._elementId('period')}`, async event => {
            this.currentPeriod = event.target.value;
            this.chartOffset = 0;
            this._populateRangeDropdown();
            this._savePrefs();
            await this._fetchAndRender();
            this.config.callbacks?.updateGrid?.();
        });
        $root.on('change.vnstat-plus-widget', `#${this._elementId('range')}`, async event => {
            this.barRange = event.target.value;
            this.chartOffset = 0;
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
        $root.on('wheel.vnstat-plus-widget', `#${this._elementId('chart')}`, async event => {
            const source = event.originalEvent;
            const delta = Math.abs(source.deltaX) > Math.abs(source.deltaY) ? source.deltaX : source.deltaY;
            if (!delta || this.chartPaging) {
                return;
            }
            event.preventDefault();
            this.chartPaging = true;
            try {
                if (delta > 0) {
                    this.chartOffset += 1;
                } else if (this.chartOffset > 0) {
                    this.chartOffset -= 1;
                }
                await this._fetchAndRender();
            } finally {
                this.chartPaging = false;
            }
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
        this.trafficChart?.destroy();
        this.trafficChart = null;
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
        this.barRange = ['current', '1', '3', '6', '12'].includes(config.bar_range) ? config.bar_range : '12';
        this._populateRangeDropdown();
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
        rootStyle.setProperty('--vnstat-plus-rx', '#2ca02c');
        rootStyle.setProperty('--vnstat-plus-tx', '#ff7f0e');
        rootStyle.setProperty('--vnstat-plus-total', '#a0cbe8');
        rootStyle.setProperty('--vnstat-plus-muted', readSemanticColor('text-muted'));
        rootStyle.setProperty('--vnstat-plus-border', readSemanticColor('text-muted'));
        rootStyle.setProperty('--vnstat-plus-tooltip-bg', readUsableColor(widget, 'backgroundColor', '#20242b'));
        rootStyle.setProperty('--vnstat-plus-tooltip-text', readUsableColor(widget, 'color', '#f4f4f4'));
        rootStyle.setProperty('--vnstat-plus-tooltip-border', widgetStyle.color || '#888');
        rootStyle.setProperty('--vnstat-plus-select-background', readUsableColor(widget, 'backgroundColor', '#ffffff'));
        rootStyle.setProperty('--vnstat-plus-table-background', readUsableColor(widget, 'backgroundColor', '#ffffff'));
    }

    _applyVisibility() {
        $(`#${this._elementId('summary')}`).toggle(this.showKpi);
        $(`#${this._elementId('chart-title')}, #${this._elementId('chart')}, #${this._elementId('legend')}`).toggle(this.showChart);
        $(`#${this._elementId('history-title')}, #${this._elementId('table')}`).toggle(this.showHistory);
        $(`#${this._elementId('range')}`).toggle(this.showChart);
    }

    _rangeOptions() {
        const units = {
            hour: this.translations.hours,
            day: this.translations.days,
            month: this.translations.months,
            year: this.translations.years
        };
        const values = {
            hour: [24, 12, 6],
            day: [30, 14, 7],
            month: [12, 6, 3],
            year: [5, 3, 1]
        };
        return (values[this.currentPeriod] || values.month).map(value => ({
            value: String(value),
            label: `${this.translations.latest} ${value} ${units[this.currentPeriod] || units.month}`
        }));
    }

    _populateRangeDropdown() {
        const options = this._rangeOptions();
        if (!options.some(option => option.value === this.barRange)) {
            this.barRange = options[0].value;
        }
        const $range = $(`#${this._elementId('range')}`);
        if (!$range.length) {
            return;
        }
        $range.empty();
        options.forEach(option => $range.append($('<option></option>').val(option.value).attr('data-icon', 'fa fa-calendar').text(option.label)));
        $range.val(this.barRange);
        this._refreshSelectPicker($range);
    }

    _initSelectPickers() {
        if (typeof $.fn.selectpicker !== 'function') {
            return;
        }
        $(`#${this._elementId('root')} select.selectpicker`).each((_, select) => {
            const $select = $(select);
            if ($select.parent().hasClass('bootstrap-select')) {
                $select.selectpicker('refresh');
            } else {
                $select.selectpicker({style: 'btn-default btn-sm', size: 8});
            }
        });
    }

    _refreshSelectPicker($select) {
        if (typeof $.fn.selectpicker === 'function' && $select.parent().hasClass('bootstrap-select')) {
            $select.selectpicker('refresh');
        }
    }

    async _populateInterfaceDropdown() {
        const data = await this.ajaxCall('/api/vnstatplus/interfaces/list');
        if (!data?.interfaces) {
            return;
        }

        const interfaces = data.interfaces.filter(item => !this.excludedInterfaces.includes(item.value));
        const $select = $(`#${this._elementId('interface')}`);
        $select.empty();
        interfaces.forEach(item => {
            $select.append($('<option></option>').val(item.value).attr('data-icon', 'fa fa-sitemap').text(item.label));
        });

        const names = interfaces.map(item => item.value);
        if (this.currentInterface && names.includes(this.currentInterface)) {
            $select.val(this.currentInterface);
        } else if (interfaces.some(item => item.label === 'WAN')) {
            this.currentInterface = interfaces.find(item => item.label === 'WAN').value;
            $select.val(this.currentInterface);
        } else if (names.length > 0) {
            this.currentInterface = names[0];
            $select.val(names[0]);
        } else {
            this.currentInterface = null;
        }
        this._refreshSelectPicker($select);
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
        const tableLimits = {hour: 25, day: 25, month: 25, year: 25};
        const tableEntries = entries.slice(-tableLimits[this.currentPeriod]);
        const chart = this._chartEntries(entries);
        this._renderSummary(entries[entries.length - 1]);
        this._renderChart(chart.entries);
        this._renderTable(tableEntries.slice().reverse());
    }

    _renderEmpty(message) {
        const empty = `<div class="vnstat-plus-empty">${this._escape(message)}</div>`;
        $(`#${this._elementId('summary')}`).html(empty);
        this.trafficChart?.destroy();
        this.trafficChart = null;
        $(`#${this._elementId('chart')}`).empty();
        $(`#${this._elementId('table')}`).html(empty);
    }

    _renderSummary(entry) {
        const rx = Number(entry?.rx) || 0;
        const tx = Number(entry?.tx) || 0;
        const period = this._formatDate(entry);
        const cards = [
            {className: 'rx', icon: 'arrow-down', label: this.translations.download, value: this._formatBytes(rx), detail: period},
            {className: 'tx', icon: 'arrow-up', label: this.translations.upload, value: this._formatBytes(tx), detail: period},
            {className: 'total', icon: 'exchange', label: this.translations.total, value: this._formatBytes(rx + tx), detail: period}
        ];
        const html = cards.map(card => `
            <div class="vnstat-plus-card vnstat-plus-card-${card.className}">
                <div class="vnstat-plus-card-label"><i class="fa fa-fw fa-${card.icon}" aria-hidden="true"></i> ${this._escape(card.label)}</div>
                <div class="vnstat-plus-card-value">${this._escape(card.value)}</div>
                <div class="vnstat-plus-card-detail">${this._escape(card.detail)}</div>
            </div>
        `).join('');
        $(`#${this._elementId('summary')}`).html(html);
    }

    _renderChart(entries) {
        this.trafficChart?.destroy();
        this.trafficChart = null;
        const $chart = $(`#${this._elementId('chart')}`);
        if (typeof Chart === 'undefined' || !entries.length) {
            $chart.html(`<div class="vnstat-plus-empty">${this._escape(this.translations.msg_no_data)}</div>`);
            return;
        }
        $chart.html(`<canvas id="${this._elementId('chart-canvas')}"></canvas>`);
        // Match Traffic Graph+'s direction palette and translucent area treatment exactly.
        const seriesColors = {
            rx: {line: '#2ca02c', fill: 'rgba(44, 160, 44, 0.28)'},
            tx: {line: '#ff7f0e', fill: 'rgba(255, 127, 14, 0.28)'},
            total: {line: '#a0cbe8', fill: 'rgba(160, 203, 232, 0.28)'}
        };
        const labels = entries.map(entry => this._formatChartLabel(entry));
        const rx = entries.map(entry => Number(entry.rx) || 0);
        const tx = entries.map(entry => Number(entry.tx) || 0);
        const total = entries.map((entry, index) => rx[index] + tx[index]);
        const canvas = document.getElementById(this._elementId('chart-canvas'));
        this.trafficChart = new Chart(canvas.getContext('2d'), {
            type: 'line',
            data: {
                labels,
                datasets: [
                    {label: this.translations.total, data: total, borderColor: seriesColors.total.line, backgroundColor: seriesColors.total.fill, fill: true, pointRadius: 0, borderWidth: 2},
                    {label: this.translations.download, data: rx, borderColor: seriesColors.rx.line, backgroundColor: seriesColors.rx.fill, fill: true, pointRadius: 0, borderWidth: 2},
                    {label: this.translations.upload, data: tx, borderColor: seriesColors.tx.line, backgroundColor: seriesColors.tx.fill, fill: true, pointRadius: 0, borderWidth: 2}
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {mode: 'index', intersect: false},
                elements: {line: {fill: true, cubicInterpolationMode: 'monotone', clip: 0}},
                plugins: {
                    colorschemes: false,
                    legend: {display: false},
                    tooltip: {callbacks: {
                        label: context => `${context.dataset.label}: ${this._formatBytes(context.raw)}`,
                        labelColor: context => ({borderColor: context.dataset.borderColor, backgroundColor: context.dataset.borderColor})
                    }}
                },
                scales: {
                    y: {beginAtZero: true, ticks: {callback: value => this._formatBytes(value)}},
                    x: {ticks: {maxRotation: 0, autoSkip: true, maxTicksLimit: 8}}
                }
            }
        });
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
        const size = Math.max(1, Number(this.barRange) || 3);
        const maxOffset = Math.max(0, Math.ceil(entries.length / size) - 1);
        this.chartOffset = Math.min(this.chartOffset, maxOffset);
        const end = entries.length - this.chartOffset * size;
        return {
            entries: entries.slice(Math.max(0, end - size), end),
            canGoPrevious: end > size,
            canGoNext: this.chartOffset > 0
        };
    }

    _formatBytes(bytes) {
        if (!bytes) {
            return '0 B';
        }
        const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
        const index = Math.max(0, Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1));
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

    _formatChartLabel(entry) {
        const date = entry.date || {};
        if (this.currentPeriod === 'hour') {
            return [`${date.year}-${String(date.month).padStart(2, '0')}-${String(date.day).padStart(2, '0')}`, `${String(entry.time?.hour ?? 0).padStart(2, '0')}:00`];
        }
        if (this.currentPeriod === 'day') {
            return [`${date.year}-${String(date.month).padStart(2, '0')}`, String(date.day).padStart(2, '0')];
        }
        if (this.currentPeriod === 'month') {
            return [String(date.year), String(date.month).padStart(2, '0')];
        }
        return [String(date.year), ''];
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
