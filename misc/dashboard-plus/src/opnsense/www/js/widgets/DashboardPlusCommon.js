/*
 * Copyright (C) 2026 Claudio Guareschi
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
 *   handleSelector: the part of an item that starts a drag
 *   placeholderClass: extra classes for the drop placeholder, so it inherits the row styles
 *   onReorder(ids): called with the item ids (data-sort-id) in their new order
 */
export function makeSortable($container, {itemSelector, handleSelector, placeholderClass = '', label = '', onReorder}) {
    let $dragged = null;
    let $placeholder = null;
    const handle = `${itemSelector} ${handleSelector}`;
    const clear = () => {
        delete $container[0].dataset.dragging;
        $dragged?.css({opacity: '', outline: ''});
        $placeholder?.remove();
        $dragged = null;
        $placeholder = null;
    };
    // Stop the grid from starting a widget drag when a row handle is pressed.
    $container.on('mousedown', handle, event => event.stopPropagation());
    $container.on('dragstart', handle, event => {
        $dragged = $(event.currentTarget).closest(itemSelector);
        $container[0].dataset.dragging = '1';
        $dragged.css({opacity: 0.4, outline: '2px dashed #d94f00'});
        $placeholder = $(`<div class="${placeholderClass}"></div>`)
            .attr('aria-label', label)
            .css({
                height: $dragged.outerHeight(),
                border: '2px dashed #d94f00',
                background: 'rgba(217, 79, 0, 0.08)'
            });
        event.originalEvent.dataTransfer.effectAllowed = 'move';
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

/*
 * The dashboard caps a widget's height at the height saved with the layout, so content
 * that grows later (the side menu is toggled and text rewraps, more rows arrive) ends up
 * in an inner scrollbar. The Dashboard Plus widgets belong in the page's own scroll,
 * so let them always size to their content.
 */
export function sizeToContent(widget) {
    const node = document.querySelector(`.widget-${widget.id}`)?.closest('.grid-stack-item')?.gridstackNode;
    if (node) {
        node.sizeToContent = true;
        widget.config.callbacks?.updateGrid?.();
    }
}

/*
 * True when the widget's width changed since the last call. Content only reflows on a
 * width change; a height change is the grid applying our own size, so re-measuring then
 * would only loop.
 */
export function widthChanged(widget, width) {
    const changed = widget._dashboardPlusWidth !== undefined && widget._dashboardPlusWidth !== width;
    widget._dashboardPlusWidth = width;
    return changed;
}

/* Bits per second with at most one decimal, e.g. "2.5 Mb/s". */
export function formatBitRate(value) {
    const number = Number(value);
    if (!Number.isFinite(number) || number <= 0) {
        return '0 b/s';
    }
    const units = ['b/s', 'Kb/s', 'Mb/s', 'Gb/s', 'Tb/s'];
    const index = Math.min(Math.floor(Math.log(number) / Math.log(1000)), units.length - 1);
    const scaled = number / Math.pow(1000, index);
    return `${scaled.toFixed(scaled < 10 && index > 0 ? 1 : 0).replace(/\.0$/, '')} ${units[index]}`;
}
