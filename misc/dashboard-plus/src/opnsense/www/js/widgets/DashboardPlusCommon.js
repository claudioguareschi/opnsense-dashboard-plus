/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
 * All rights reserved.
 */

/*
 * Helpers shared by the Dashboard Plus widgets. This file has no metadata entry, so the
 * dashboard never loads it as a widget; each widget imports it with its own cache-busting
 * query string (see importCommon in the widgets).
 */

const ENTITIES = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'};

/* Escape text for use in element content and in quoted attribute values. */
export function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, character => ENTITIES[character]);
}

export function renderTitle(widget) {
    $(`#${widget.id}-title`).html(`<b>${escapeHtml(widget.translations.dashboard_title)}</b>`);
}

/*
 * Keep the items of `order` that are still selected, in that order, then append newly
 * selected items. Used when a drag reorders a subset, and when the options dialog returns
 * a selection in the order of its option list. Duplicates are dropped: layouts saved by
 * 0.1_42 and earlier can list an interface twice (Traffic Graph+ could build its panels
 * twice and a drag then saved both).
 */
export function mergeOrder(order, selected) {
    const current = [...new Set(Array.isArray(order) ? order : [])];
    const wanted = [...new Set(Array.isArray(selected) ? selected : [])];
    return [
        ...current.filter(item => wanted.includes(item)),
        ...wanted.filter(item => !current.includes(item))
    ];
}

/*
 * Drag-to-reorder for the rows or panels of a widget.
 *   itemSelector:   the elements being reordered (direct children of $container)
 *   handleSelector: the part of an item that starts a drag; omitted, the whole item does. A
 *                   press anywhere on a handle never starts a drag of the widget panel itself,
 *                   which the dashboard allows from any point of a widget in edit mode.
 *   placeholderClass: extra classes for the drop placeholder, so it inherits the row styles
 *   onReorder(ids): called with the item ids (data-sort-id) in their new order
 */
export function makeSortable($container, {itemSelector, handleSelector, placeholderClass = '', label = '', onReorder}) {
    let $dragged = null;
    let $placeholder = null;
    const handle = handleSelector ? `${itemSelector} ${handleSelector}` : itemSelector;
    const clear = () => {
        delete $container[0].dataset.dragging;
        $dragged?.removeClass('dashboard-plus-dragging');
        $placeholder?.remove();
        $dragged = null;
        $placeholder = null;
    };
    // Stop the grid from starting a widget drag when a row handle is pressed.
    $container.on('mousedown', handle, event => event.stopPropagation());
    $container.on('dragstart', handle, event => {
        $dragged = $(event.currentTarget).closest(itemSelector);
        $container[0].dataset.dragging = '1';
        $dragged.addClass('dashboard-plus-dragging');
        // the theme's accent (text-primary) outlines the drop place
        $placeholder = $(`<div class="${placeholderClass} text-primary dashboard-plus-drop"></div>`)
            .attr('aria-label', label)
            .css('height', $dragged.outerHeight());
        event.originalEvent.dataTransfer.effectAllowed = 'move';
        // Firefox starts a drag only when it carries data
        event.originalEvent.dataTransfer.setData('text/plain', $dragged.attr('data-sort-id') ?? '');
        event.stopPropagation();
    });
    $container.on('dragover', event => {
        if (!$dragged) {
            return;
        }
        event.preventDefault();
        event.originalEvent.dataTransfer.dropEffect = 'move';
        const $target = $(event.target).closest(itemSelector);
        if (!$target.length || $target[0] === $dragged[0] || $target[0] === $placeholder[0] ||
                !$container[0].contains($target[0])) {
            return;
        }
        const halfway = $target.offset().top + ($target.outerHeight() / 2);
        event.originalEvent.clientY < halfway ? $target.before($placeholder) : $target.after($placeholder);
    });
    $container.on('drop', event => {
        if (!$dragged) {
            return;
        }
        event.preventDefault();
        if ($placeholder?.parent().length) {
            $placeholder.replaceWith($dragged);
            onReorder($container.children(itemSelector).map((_, item) => $(item).attr('data-sort-id')).get());
            $('#save-grid').show();
        }
        clear();
    });
    $container.on('dragend', handle, clear);
}

/* True while a row of $container is being dragged; a refresh then would drop the drag. */
export function isDragging($container) {
    return $container[0]?.dataset.dragging === '1';
}

/* True while the dashboard is in edit mode (the pencil button in the page header is active). */
export function isEditMode() {
    return $('#edit-grid').hasClass('active');
}

/*
 * Call onChange(editing) whenever the dashboard enters or leaves edit mode. Returns a function
 * that stops watching.
 */
export function watchEditMode(onChange) {
    const button = document.getElementById('edit-grid');
    if (!button) {
        return () => {};
    }
    let editing = isEditMode();
    const observer = new MutationObserver(() => {
        if (isEditMode() !== editing) {
            editing = isEditMode();
            onChange(editing);
        }
    });
    observer.observe(button, {attributes: true, attributeFilter: ['class']});
    return () => observer.disconnect();
}

/*
 * The Dashboard Plus styles, added to the page once with the widget code (so a cached stylesheet
 * can never pair with a newer widget). Colors are the theme's: Bootstrap's text-* classes, labels
 * and progress bars. The list widgets use the stock flextable classes for the native width,
 * separators and hover; the table is one CSS grid and each row a subgrid of it, so every row
 * shares the same column widths and gutter at any widget width. A widget sets the columns with
 * the --dashboard-plus-columns property of its table class.
 */
// The doubled classes outrank the theme's .flextable-container and .flextable-row rules.
const STYLE = `
    .dashboard-plus-table.dashboard-plus-table { display: grid; grid-template-columns: var(--dashboard-plus-columns); column-gap: 0.75em; }
    .dashboard-plus-table > .dashboard-plus-row.dashboard-plus-row { grid-column: 1 / -1; display: grid; grid-template-columns: subgrid; align-items: center; text-align: left; }
    .dashboard-plus-table > .dashboard-plus-span { grid-column: 1 / -1; }
    .dashboard-plus-row > * { min-width: 0; word-break: normal; overflow-wrap: anywhere; }
    .dashboard-plus-row .dashboard-plus-number { text-align: right; white-space: nowrap; overflow-wrap: normal; font-variant-numeric: tabular-nums; }
    .dashboard-plus-row .dashboard-plus-nowrap { white-space: nowrap; overflow-wrap: normal; }
    .dashboard-plus-row .dashboard-plus-ellipsis { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; overflow-wrap: normal; }
    .dashboard-plus-row .dashboard-plus-muted { opacity: 0.7; }
    .dashboard-plus-row .dashboard-plus-small { font-size: 0.88em; line-height: 1.4; }
    /* an icon beside a two-line name cell, dropped when the column is too narrow for both */
    .dashboard-plus-row .dashboard-plus-named { container-type: inline-size; display: flex; align-items: center; gap: 0.6em; }
    .dashboard-plus-row .dashboard-plus-named > :first-child { min-width: 0; }
    .dashboard-plus-row .dashboard-plus-side-icon { flex: none; font-size: 1em; opacity: 0.7; }
    @container (max-width: 6em) { .dashboard-plus-row .dashboard-plus-side-icon { display: none; } }
    .dashboard-plus-row .dashboard-plus-center { text-align: center; }
    .dashboard-plus-tabular { font-variant-numeric: tabular-nums; }
    .dashboard-plus-empty { padding: 0.75em; }
    .dashboard-plus-dragging { opacity: 0.4; outline: 2px dashed currentColor; }
    .dashboard-plus-drop { border: 2px dashed currentColor; }
    .dashboard-plus-grab { cursor: grab; }
    /* a state (Healthy, Online...) in the theme's success, warning or danger color, with a light fill
       and border made from that same color, so it follows the light and dark themes */
    .dashboard-plus-state-pill { display: inline-flex; align-items: center; gap: 0.35em; padding: 0.15em 0.65em;
        border-radius: 0.35em; font-weight: 600; white-space: nowrap; }
    /* the theme's state color (read once by ensureStyle) for the dot, fill and border; the label mixes it
       with the theme's text color, darker on a light theme and lighter on a dark one, for contrast */
    .dashboard-plus-state-pill.text-success { --dashboard-plus-state: var(--dashboard-plus-success); }
    .dashboard-plus-state-pill.text-warning { --dashboard-plus-state: var(--dashboard-plus-warning); }
    .dashboard-plus-state-pill.text-danger { --dashboard-plus-state: var(--dashboard-plus-danger); }
    .dashboard-plus-state-pill.text-muted { --dashboard-plus-state: var(--dashboard-plus-muted); }
    .dashboard-plus-state-pill.dashboard-plus-state-pill[class*="text-"] {
        color: color-mix(in srgb, var(--dashboard-plus-state) 60%, var(--dashboard-plus-ink));
        background: color-mix(in srgb, var(--dashboard-plus-state) 15%, transparent);
        box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--dashboard-plus-state) 45%, transparent); }
    .dashboard-plus-state-pill > .fa { line-height: 1; }
    /* in a table column beside numbers, the size the Bootstrap labels had there */
    .dashboard-plus-state-pill.dashboard-plus-compact { font-size: 85%; padding: 0.1em 0.55em; }
    /* a dot in the pill's color, centered by the flex box rather than by a font's glyph metrics */
    .dashboard-plus-state-dot { width: 0.6em; height: 0.6em; border-radius: 50%; flex: none;
        background: var(--dashboard-plus-state, currentColor); }
    .dashboard-plus-bar.progress { height: 0.75em; margin: 0.2em 0 0; }
    .dashboard-plus-gateway-name { line-height: 1.35; }

    /* System Metrics+ and Traffic Graph+: panels with a heading, charts, gauges, bars */
    .dashboard-plus-inner { width: 95%; margin: 0 auto; }
    .dashboard-plus-panel-head { display: flex; justify-content: space-between; align-items: baseline; gap: 1em; margin: 0 0.25em; }
    .dashboard-plus-panel-head h3 { margin: 0; }
    .dashboard-plus-chart { margin: 0 0.5em; }
    .dashboard-plus-metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1em; padding: 0 0.25em; }
    .dashboard-plus-metrics .dashboard-plus-wide { grid-column: 1 / -1; }
    .dashboard-plus-metrics canvas { width: 100%; height: 90px; }
    .dashboard-plus-metrics-load { font-size: 0.9em; margin: 0.25em 0; }

    .dashboard-plus-gauges { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.5em; }
    .dashboard-plus-gauge { text-align: center; min-width: 0; }
    .dashboard-plus-gauge svg { width: 100%; max-width: 96px; display: block; margin: 0 auto; }
    .dashboard-plus-gauge path { fill: none; stroke: currentColor; stroke-width: 9; stroke-linecap: round; }
    .dashboard-plus-gauge .gauge-track { opacity: 0.12; }
    .dashboard-plus-gauge .gauge-fill { transition: stroke-dasharray 0.2s ease; }
    .dashboard-plus-gauge .gauge-value { fill: currentColor; font-size: 19px; font-weight: 600; font-variant-numeric: tabular-nums; }
    .dashboard-plus-gauge .gauge-label { font-weight: 600; margin-top: -0.4em; white-space: nowrap; }
    .dashboard-plus-gauge .gauge-link { font-weight: normal; font-size: 0.9em; }
    .dashboard-plus-gauge .gauge-detail { font-size: 0.85em; font-variant-numeric: tabular-nums; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .dashboard-plus-filesystems { margin-top: 0.25em; }
    .dashboard-plus-filesystem { display: grid; grid-template-columns: 28% 72%; padding: 0.35em 0; text-align: left; }
    .dashboard-plus-filesystem > span { padding-right: 0.75em; }
    .dashboard-plus-filesystem > div { padding-left: 0.75em; }
    .dashboard-plus-filesystem .dashboard-plus-bar.progress { margin: 0; }
    .dashboard-plus-filesystem-detail { font-size: 0.9em; margin-top: 0.15em; }

    /* System Information+: a ZFS pool, its usage bar, then health, errors and last scrub side by side */
    .dashboard-plus-zfs + .dashboard-plus-zfs { margin-top: 0.75em; }
    .dashboard-plus-zfs-usage { display: flex; align-items: center; gap: 0.5em; margin-top: 0.3em; }
    .dashboard-plus-zfs-usage .dashboard-plus-bar.progress { flex: 1 1 auto; margin: 0; }
    .dashboard-plus-zfs-usage strong { flex: none; min-width: 2.4em; text-align: right; font-variant-numeric: tabular-nums; }
    .dashboard-plus-zfs-detail { font-size: 0.9em; margin-top: 0.1em; font-variant-numeric: tabular-nums; }
    /* one row in a widget column: a slightly smaller font and tighter spacing than the lines above */
    .dashboard-plus-zfs-status { display: flex; flex-wrap: wrap; align-items: center; gap: 0.35em 0; margin-top: 0.4em;
        font-size: 0.88em; white-space: nowrap; }
    .dashboard-plus-zfs-status > span { padding: 0 0.55em; border-left: 1px solid rgba(128, 128, 128, 0.35); }
    .dashboard-plus-zfs-status > span:first-child { padding-left: 0; border-left: 0; }
    /* the pill takes the theme's success, warning or danger color, a light fill and border made from it */
    .dashboard-plus-zfs-status > .dashboard-plus-state-pill { margin-right: 0.55em; padding: 0.1em 0.5em; }

    .dashboard-plus-traffic { padding: 0 0.25em; }
    .dashboard-plus-legend { display: flex; flex-wrap: wrap; gap: 0.2em 1em; white-space: nowrap; }
    .dashboard-plus-combined-legend { gap: 0.2em 0.75em; margin: 0 0.5em 0.35em; font-size: 0.82em; }
    .dashboard-plus-combined-chart { height: 180px; }
    .dashboard-plus-dot { display: inline-block; width: 0.8em; height: 0.8em; border-radius: 50%; vertical-align: -0.05em; }

    /* Thermal Sensors+ */
    .dashboard-plus-sensors { width: 95%; margin: 0.25em auto; }
    .dashboard-plus-sensor { padding: 0.35em 0; }
    .dashboard-plus-sensor-head { display: flex; justify-content: space-between; align-items: baseline; }

    /* Interfaces+: the icon, name and addresses; after a divider the link, MAC address and state */
    .dashboard-plus-interfaces { --dashboard-plus-columns: auto minmax(0, 1fr) auto; row-gap: 0; }
    /* top-aligned: the name stays beside the icon however many address lines follow */
    .dashboard-plus-interfaces > .dashboard-plus-row.dashboard-plus-row { align-items: start; padding: 0.65em 0; }
    .dashboard-plus-interfaces .dashboard-plus-interface-icon { align-self: start; font-size: 1.45em; padding: 0.05em 0.1em 0 0.15em; }
    .dashboard-plus-interfaces .dashboard-plus-interface-name { font-weight: 600; font-size: 1.05em; color: inherit; }
    .dashboard-plus-interfaces .dashboard-plus-interface-addresses,
    .dashboard-plus-interfaces .dashboard-plus-interface-link { margin-top: 0.15em; line-height: 1.5; font-variant-numeric: tabular-nums; }
    /* the media may wrap between its words in a narrow widget; the MAC address and the pill never do */
    .dashboard-plus-interfaces .dashboard-plus-interface-link { margin-top: 0; padding: 0 0.25em 0 1em; overflow-wrap: normal;
        border-left: 1px solid rgba(128, 128, 128, 0.35); }
    .dashboard-plus-interfaces .dashboard-plus-interface-link > div:nth-child(2) { white-space: nowrap; }
    .dashboard-plus-interfaces .dashboard-plus-state-pill { margin-top: 0.35em; }
    /* IPv6 a little smaller, and broken only after a colon when it must wrap (<wbr> marks those) */
    .dashboard-plus-interfaces .dashboard-plus-interface-v6 { font-size: 0.9em; overflow-wrap: normal; }

    /* Firewall Logs+: the interface and rule go on a second line, so the addresses keep room */
    .dashboard-plus-logs { --dashboard-plus-columns: auto auto minmax(0, 1fr) minmax(0, 1fr); }
    .dashboard-plus-logs > .dashboard-plus-row.dashboard-plus-row { align-items: start; row-gap: 0.1em; }
    .dashboard-plus-logs .dashboard-plus-action { font-size: 1.2em; }
    .dashboard-plus-logs .dashboard-plus-detail { grid-column: 2 / -1; }
`;

/* Add the Dashboard Plus styles to the page once. */
/* The theme color of a usage share, as every Dashboard Plus bar and gauge shows it. */
export function usageColor(percent) {
    return percent >= 80 ? 'danger' : percent >= 50 ? 'warning' : 'success';
}

/*
 * The theme's state colors (text-success, -warning, -danger, -muted) and its text color, as CSS
 * variables for the state pill: CSS cannot mix an element's own color into that same color.
 */
function themeColors() {
    const root = document.documentElement.style;
    const probe = $('<span style="position: absolute; visibility: hidden;"></span>').appendTo('body');
    for (const state of ['success', 'warning', 'danger', 'muted']) {
        root.setProperty(`--dashboard-plus-${state}`, getComputedStyle(probe.attr('class', `text-${state}`)[0]).color);
    }
    probe.remove();
    root.setProperty('--dashboard-plus-ink', getComputedStyle(document.body).color);
}

export function ensureStyle() {
    if (!document.getElementById('dashboard-plus-style')) {
        $('<style id="dashboard-plus-style"></style>').text(STYLE).appendTo('head');
        themeColors();
    }
}

// A cap far above any widget: the widget grows with its content.
const AUTO_HEIGHT = 10000;

/*
 * Height handling shared by the Dashboard Plus widgets, as a mixin over BaseWidget or
 * BaseTableWidget.
 *
 * The dashboard caps a widget at the height saved with the layout, whether the user chose
 * that height or it was just the content's height when the layout was saved. Content that
 * grows later (the side menu is toggled and text rewraps, more rows arrive) then ends up
 * behind an inner scrollbar. These widgets fit their content instead, unless the user drags
 * one shorter than its content: that height is kept, saved with the widget's options as
 * manual_height, and the rest scrolls. Dragging it back to full height returns it to fitting.
 */
export const DashboardPlusWidget = Base => class extends Base {
    constructor(config) {
        super(config);
        this.manualHeight = parseInt(config?.widget?.manual_height, 10) || null;
        this.lastWidth = undefined;
        this.heightManaged = false;
        this._pauseWhileHidden();
    }

    /*
     * A dashboard in a background tab refreshes nothing: browsers still fire its timers (once a
     * minute), and every refresh starts work on the firewall. The widget's own onWidgetTick runs
     * again once, as soon as the tab is visible, when a refresh was skipped meanwhile.
     */
    _pauseWhileHidden() {
        const tick = this.onWidgetTick;
        if (typeof tick !== 'function') {
            return;
        }
        let skipped = false;
        this.onWidgetTick = (...args) => {
            if (document.hidden) {
                skipped = true;
                return Promise.resolve();
            }
            skipped = false;
            return tick.apply(this, args);
        };
        this._onVisibilityChange = () => {
            if (!document.hidden && skipped) {
                Promise.resolve(this.onWidgetTick()).catch(error => console.error(error));
            }
        };
        document.addEventListener('visibilitychange', this._onVisibilityChange);
    }

    onWidgetClose() {
        super.onWidgetClose?.();
        document.removeEventListener('visibilitychange', this._onVisibilityChange);
    }

    _gridItem() {
        return document.querySelector(`.widget-${this.id}`)?.closest('.grid-stack-item') ?? null;
    }

    _heightCap() {
        return this.manualHeight ?? AUTO_HEIGHT;
    }

    /* Call from onMarkupRendered, once the widget is in the grid. */
    fitToContent() {
        const node = this._gridItem()?.gridstackNode;
        if (node) {
            this.heightManaged = true;
            node.sizeToContent = this._heightCap();
            this.config.callbacks?.updateGrid?.();
        }
    }

    /*
     * The grid sets sizeToContent to the new height when the user finishes a resize. Keep that
     * height only when it is shorter than the content; otherwise go back to fitting.
     */
    _recordManualResize() {
        const item = this._gridItem();
        const node = item?.gridstackNode;
        if (!this.heightManaged || !node || !Number.isInteger(node.sizeToContent) || node.sizeToContent === this._heightCap()) {
            return;
        }
        const content = item.querySelector('.grid-stack-item-content');
        const clipped = content && content.scrollHeight - content.clientHeight > 1;
        this.manualHeight = clipped ? node.sizeToContent : null;
        node.sizeToContent = this._heightCap();
        this.setWidgetConfig(this.config.widget ?? {});
        $('#save-grid').show();
    }

    async getWidgetConfig() {
        const config = await super.getWidgetConfig();
        if (this.manualHeight) {
            config.manual_height = this.manualHeight;
        }
        return config;
    }

    setWidgetConfig(config) {
        // The options dialog passes only its own fields; keep the height with them.
        const {manual_height: _, ...rest} = config ?? {};
        super.setWidgetConfig(this.manualHeight ? {...rest, manual_height: this.manualHeight} : rest);
    }

    /*
     * Re-measure (return true) when the width changed: content only reflows then. A height
     * change is the grid applying our own size, and re-measuring on it would only loop.
     */
    onWidgetResize(elem, width, height) {
        this._recordManualResize();
        const layoutChanged = super.onWidgetResize(elem, width, height);
        const widthChanged = this.lastWidth !== undefined && this.lastWidth !== width;
        this.lastWidth = width;
        if (widthChanged) {
            this.onWidthChanged(width);
        }
        return widthChanged || layoutChanged;
    }

    /* Hook for widgets that must redraw when their width changes (charts). */
    onWidthChanged(width) {
    }
};

// How long widgets reuse one answer: they refresh every 10 s, a few seconds apart.
const SHARED_REQUEST_AGE = 4000;

/*
 * GET url through the widget's ajaxCall, sharing the answer with every widget that asks for the
 * same url within a few seconds, so System Metrics+, Thermal Sensors+ and System Information+ on
 * one dashboard make one request per refresh. The answer is shared: callers must not modify it.
 * The cache is kept on the page, not in this module: each widget imports this file with its own
 * query string, which can make separate copies of it.
 */
export function sharedRequest(widget, url) {
    const requests = window.dashboardPlusRequests ??= new Map();
    const cached = requests.get(url);
    if (cached && Date.now() - cached.time < SHARED_REQUEST_AGE) {
        return cached.promise;
    }
    const promise = widget.ajaxCall(url);
    requests.set(url, {time: Date.now(), promise});
    // a failed request is not shared: the next widget asks again
    promise.catch(() => {
        if (requests.get(url)?.promise === promise) {
            requests.delete(url);
        }
    });
    return promise;
}

/*
 * A translated phrase with its {placeholders} filled in, e.g. "Core {number}". Whole phrases keep
 * the word order of each language; fragments joined in code would force the English one.
 */
export function fill(template, values) {
    return String(template).replace(/\{(\w+)\}/g, (match, name) => (name in values ? String(values[name]) : match));
}

/* Bits per second with at most one decimal, e.g. "2.5 Mb/s". */
export function formatBitRate(value) {
    const number = Number(value);
    if (!Number.isFinite(number) || number <= 0) {
        return '0 b/s';
    }
    const units = ['b/s', 'Kb/s', 'Mb/s', 'Gb/s', 'Tb/s'];
    // Chart.js can generate fractional tick values for an idle graph. Do not index before
    // the first unit (which used to render values such as 0.5 as "500 undefined").
    const index = Math.max(0, Math.min(Math.floor(Math.log(number) / Math.log(1000)), units.length - 1));
    const scaled = number / Math.pow(1000, index);
    return `${scaled.toFixed(scaled < 10 ? 1 : 0).replace(/\.0$/, '')} ${units[index]}`;
}
