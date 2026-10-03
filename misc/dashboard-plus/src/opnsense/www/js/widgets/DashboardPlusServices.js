/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
 * All rights reserved.
 */

const {escapeHtml, renderTitle, ensureTableStyle, DashboardPlusWidget} =
    await import(`./DashboardPlusCommon.js${new URL(import.meta.url).search}`);

const SERVICE_STYLE_ID = 'dashboard-plus-services-style';

export default class DashboardPlusServices extends DashboardPlusWidget(BaseWidget) {
    constructor(config) {
        super(config);
        this.configurable = true;
        this.services = [];
        this.currentConfig = null;
        this.filter = 'all';
        this.search = '';
        this.busyService = null;
        this.error = '';
    }

    getGridOptions() {
        return {sizeToContent: 650};
    }

    _elementId(name) {
        return `${this.id}-services-${name}`;
    }

    _addStyle() {
        if (document.getElementById(SERVICE_STYLE_ID)) {
            return;
        }
        const css = `
            .dashboard-plus-services-toolbar {
                display: flex;
                align-items: center;
                gap: 0.6em;
                flex-wrap: wrap;
                padding: 0.25em 0 0.7em;
            }
            .dashboard-plus-services-summary {
                display: flex;
                align-items: center;
                gap: 0.55em;
                flex-wrap: wrap;
                margin-right: auto;
                font-size: 0.88em;
            }
            .dashboard-plus-services-summary span {
                white-space: nowrap;
            }
            .dashboard-plus-services-search {
                min-width: 10em;
                max-width: 18em;
            }
            .dashboard-plus-services-table .dashboard-plus-services-action {
                min-width: 2.1em;
                padding: 0.2em 0.45em;
                margin-left: 0.2em;
            }
            .dashboard-plus-services-status {
                white-space: nowrap;
                font-size: 0.88em;
                font-weight: 600;
            }
            .dashboard-plus-services-status i {
                margin-right: 0.25em;
            }
            .dashboard-plus-services-id {
                opacity: 0.7;
                font-size: 0.82em;
            }
            .dashboard-plus-services-empty,
            .dashboard-plus-services-error {
                padding: 0.75em;
                text-align: center;
            }
            .dashboard-plus-services-error {
                color: var(--danger, #d62728);
            }
            @media (max-width: 34em) {
                .dashboard-plus-services-search {
                    min-width: 100%;
                    max-width: none;
                }
            }
        `;
        $('<style>').attr('id', SERVICE_STYLE_ID).text(css).appendTo('head');
    }

    getMarkup() {
        ensureTableStyle();
        this._addStyle();
        return $(`
            <div id="${this._elementId('root')}" class="dashboard-plus-services">
                <div class="dashboard-plus-services-toolbar">
                    <div id="${this._elementId('summary')}" class="dashboard-plus-services-summary"></div>
                    <input id="${this._elementId('search')}" class="form-control input-sm dashboard-plus-services-search"
                        type="search" autocomplete="off" placeholder="${escapeHtml(this.translations.search)}"
                        aria-label="${escapeHtml(this.translations.search)}">
                    <select id="${this._elementId('filter')}" class="form-control input-sm">
                        <option value="all">${escapeHtml(this.translations.all)}</option>
                        <option value="running">${escapeHtml(this.translations.running)}</option>
                        <option value="stopped">${escapeHtml(this.translations.stopped)}</option>
                        <option value="locked">${escapeHtml(this.translations.locked)}</option>
                    </select>
                </div>
                <div id="${this._elementId('error')}" class="dashboard-plus-services-error" style="display: none;"></div>
                <div id="${this._elementId('table')}" class="flextable-container dashboard-plus-table dashboard-plus-services-table"
                    role="table" style="--dashboard-plus-columns: auto minmax(0, 1.25fr) minmax(0, 2fr) auto;">
                </div>
                <div id="${this._elementId('empty')}" class="dashboard-plus-services-empty" style="display: none;"></div>
            </div>
        `);
    }

    _asBoolean(value) {
        return value === true || value === 1 || value === '1' || value === 'true';
    }

    _serviceData() {
        const selected = this.currentConfig?.services;
        if (!Array.isArray(selected)) {
            return this.services;
        }
        const wanted = new Set(selected);
        return this.services.filter(service => wanted.has(service.id));
    }

    _visibleServices() {
        const query = this.search.trim().toLowerCase();
        return this._serviceData()
            .filter(service => this.filter === 'all' ||
                (this.filter === 'locked' ? service.locked : (service.running ? 'running' : 'stopped') === this.filter))
            .filter(service => !query || `${service.description} ${service.id}`.toLowerCase().includes(query))
            .sort((left, right) => left.description.localeCompare(right.description));
    }

    _status(service) {
        return service.running
            ? {label: this.translations.running, color: 'text-success', icon: 'check-circle-o'}
            : {label: this.translations.stopped, color: 'text-danger', icon: 'times-circle-o'};
    }

    _actionButton(service, action, icon, title) {
        const disabled = this.busyService ? ' disabled' : '';
        return `<button type="button" class="btn btn-default btn-xs dashboard-plus-services-action"
            data-service-action="${escapeHtml(action)}" data-service-id="${escapeHtml(service.id)}"
            title="${escapeHtml(title)}" aria-label="${escapeHtml(title)}"${disabled}>
            <i class="fa fa-${escapeHtml(icon)}"></i>
        </button>`;
    }

    _actions(service) {
        if (service.locked) {
            return this._actionButton(service, 'restart', 'refresh', this.translations.restart);
        }
        if (service.running) {
            return this._actionButton(service, 'stop', 'stop', this.translations.stop) +
                this._actionButton(service, 'restart', 'refresh', this.translations.restart);
        }
        return this._actionButton(service, 'start', 'play', this.translations.start);
    }

    _headerRow() {
        return `<div class="flextable-header dashboard-plus-row" role="row">
            <div role="columnheader">${escapeHtml(this.translations.status)}</div>
            <div role="columnheader">${escapeHtml(this.translations.service)}</div>
            <div role="columnheader">${escapeHtml(this.translations.identifier)}</div>
            <div role="columnheader" style="text-align: right;">${escapeHtml(this.translations.actions)}</div>
        </div>`;
    }

    _row(service) {
        const status = this._status(service);
        const locked = service.locked ? ` <span class="dashboard-plus-services-id">(${escapeHtml(this.translations.locked)})</span>` : '';
        const busy = this.busyService === service.id;
        return `<div class="flextable-row dashboard-plus-row" role="row"${busy ? ' aria-busy="true"' : ''}>
            <div role="cell" class="dashboard-plus-services-status ${status.color}">
                <i class="fa fa-${status.icon}" aria-hidden="true"></i>${escapeHtml(status.label)}${locked}
            </div>
            <div role="cell" class="dashboard-plus-ellipsis">
                <a href="/ui/core/service" target="_blank" rel="noopener noreferrer">${escapeHtml(service.description)}</a>
            </div>
            <div role="cell" class="dashboard-plus-ellipsis dashboard-plus-muted">${escapeHtml(service.id)}</div>
            <div role="cell" style="text-align: right; white-space: nowrap;">${this._actions(service)}</div>
        </div>`;
    }

    _render() {
        const $table = $(`#${this._elementId('table')}`);
        const services = this._visibleServices();
        const selected = this._serviceData();
        const running = selected.filter(service => service.running).length;
        const stopped = selected.length - running;
        const locked = selected.filter(service => service.locked).length;
        const summary = [
            `<span class="text-success"><i class="fa fa-check-circle-o"></i> ${running} ${escapeHtml(this.translations.running.toLowerCase())}</span>`,
            `<span class="text-danger"><i class="fa fa-times-circle-o"></i> ${stopped} ${escapeHtml(this.translations.stopped.toLowerCase())}</span>`,
            locked ? `<span class="text-muted"><i class="fa fa-lock"></i> ${locked} ${escapeHtml(this.translations.locked.toLowerCase())}</span>` : ''
        ].filter(Boolean).join('<span class="dashboard-plus-muted">·</span>');
        $(`#${this._elementId('summary')}`).html(summary);
        $(`#${this._elementId('error')}`).text(this.error).toggle(Boolean(this.error));
        $table.empty();
        if (services.length) {
            $table.html(this._headerRow() + services.map(service => this._row(service)).join(''));
            $(`#${this._elementId('empty')}`).hide();
        } else {
            $(`#${this._elementId('empty')}`).text(this.error || this.translations.no_matches).show();
        }
        this.config.callbacks?.updateGrid?.();
    }

    async _fetchServices() {
        const data = await this.ajaxCall('/api/core/service/search');
        this.services = (data?.rows ?? []).map(service => this._normalizeService(service))
            .filter(service => service.id);
    }

    _normalizeService(service) {
        return {
            id: String(service.id ?? ''),
            description: String(service.description ?? service.id ?? ''),
            running: this._asBoolean(service.running),
            locked: this._asBoolean(service.locked)
        };
    }

    _serviceEndpoint(action, serviceId) {
        const path = String(serviceId).split('/').map(part => encodeURIComponent(part)).join('/');
        return `/api/core/service/${encodeURIComponent(action)}/${path}`;
    }

    async _runAction(serviceId, action) {
        if (this.busyService) {
            return;
        }
        const service = this.services.find(item => item.id === serviceId);
        if (!service) {
            return;
        }
        const actionLabel = this.translations[action];
        if (!window.confirm(`${actionLabel} ${service.description}?`)) {
            return;
        }
        this.busyService = serviceId;
        this.error = '';
        this._render();
        try {
            await this.ajaxCall(this._serviceEndpoint(action, serviceId), {}, 'POST');
            await this._fetchServices();
        } catch (error) {
            this.error = error?.message || this.translations.action_failed;
        } finally {
            this.busyService = null;
            this._render();
        }
    }

    _applyConfig(config = {}) {
        this.currentConfig = config;
        this.refreshSeconds = Number(config.refresh_interval) || 30;
        this.tickTimeout = this.refreshSeconds;
    }

    async onMarkupRendered() {
        renderTitle(this);
        const $root = $(`#${this._elementId('root')}`);
        this.currentConfig = await this.getWidgetConfig();
        this._applyConfig(this.currentConfig);
        $root.on('input.dashboard-plus-services', `#${this._elementId('search')}`, event => {
            this.search = event.currentTarget.value;
            this._render();
        });
        $root.on('change.dashboard-plus-services', `#${this._elementId('filter')}`, event => {
            this.filter = event.currentTarget.value;
            this._render();
        });
        $root.on('click.dashboard-plus-services', '[data-service-action]', async event => {
            event.preventDefault();
            event.stopPropagation();
            const button = event.currentTarget;
            await this._runAction($(button).data('service-id'), $(button).data('service-action'));
        });
        try {
            await this._fetchServices();
        } catch (error) {
            this.error = error?.message || this.translations.fetch_failed;
        }
        this._render();
        this.fitToContent();
    }

    async onWidgetTick() {
        if (this.busyService) {
            return;
        }
        try {
            await this._fetchServices();
            this.error = '';
        } catch (error) {
            this.error = error?.message || this.translations.fetch_failed;
        }
        this._render();
    }

    onWidgetClose() {
        $(`#${this._elementId('root')}`).off('.dashboard-plus-services');
    }

    async getWidgetOptions() {
        const data = this.services.length ? {rows: this.services} : await this.ajaxCall('/api/core/service/search');
        const services = (data?.rows ?? []).map(service => this._normalizeService(service))
            .filter(service => service.id)
            .map(service => ({value: service.id, label: service.description}));
        return {
            services: {
                title: this.translations.services,
                type: 'select_multiple',
                id: this._elementId('service-selection'),
                options: services,
                default: services.map(service => service.value)
            },
            refresh_interval: {
                title: this.translations.refresh_interval,
                type: 'select',
                id: this._elementId('refresh-interval'),
                options: [
                    {value: '15', label: this.translations.seconds_15},
                    {value: '30', label: this.translations.seconds_30},
                    {value: '60', label: this.translations.minute_1},
                    {value: '120', label: this.translations.minutes_2}
                ],
                default: '30'
            }
        };
    }

    async onWidgetOptionsChanged() {
        const config = await this.getWidgetConfig();
        this.setWidgetConfig(config);
        this._applyConfig(config);
        this._render();
    }
}
