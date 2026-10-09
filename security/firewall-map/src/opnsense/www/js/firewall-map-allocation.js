/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
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

/*
 * The ranking profile editor's allocation bars: 100 percentage points split into segments, shown
 * with Bootstrap's stacked progress bars, with a handle on each boundary between two segments.
 *
 * The numeric fields are the state: a bar reads them, draws itself from them and writes whole
 * points back into them; nothing is ever taken from pixel widths. A handle moves points only
 * between the two segments it separates, so a total of 100 stays 100. A derived segment (Security
 * visibility's General) has no field: it is whatever the others leave of 100.
 */
(function (root) {
    'use strict';

    const TOTAL = 100;
    const SHIFT_STEP = 5;
    // a 0% segment keeps a narrow striped slot of its own (pixels), so its two boundaries are apart
    const ZERO_SLOT = 14;

    /** A field's text as a value: a whole number from 0 to 100, or null. */
    function parse(text) {
        const value = String(text ?? '').trim();
        return /^\d{1,3}$/.test(value) && Number(value) <= TOTAL ? Number(value) : null;
    }

    /** The segments' values (the derived one computed) and whether they form a valid split. */
    function evaluate(segments, texts) {
        const values = segments.map((segment, index) => segment.derived ? 0 : parse(texts[index]));
        const bad = values.some((value, index) => value === null && !segments[index].derived);
        const derived = segments.findIndex((segment) => segment.derived);
        const sum = values.reduce((total, value) => total + (value || 0), 0);
        if (derived >= 0) {
            values[derived] = Math.max(0, TOTAL - sum);
        }
        const total = derived >= 0 ? Math.max(sum, TOTAL) : sum;
        return {values, total, valid: !bad && total === TOTAL, bad, over: total - TOTAL};
    }

    /** Pixel arithmetic, free of binary fractions. */
    function round(value) {
        return Math.round(value * 1e6) / 1e6;
    }

    /** Moves `delta` points across boundary `k` (between segments k and k + 1): the left one gains
     *  what the right one loses, neither below 0; the others never change. */
    function move(values, k, delta) {
        const step = Math.max(-values[k], Math.min(values[k + 1], delta));
        const next = values.slice();
        next[k] = values[k] + step;
        next[k + 1] = values[k + 1] - step;
        return next;
    }

    /** The whole points a drag moves a boundary now at `edge`: it was at `start` when the pointer
     *  went down, and the pointer has moved `pixels` on a bar of `scale` pixels per point. */
    function dragDelta(start, edge, pixels, scale) {
        const target = Math.max(0, Math.min(TOTAL, start + Math.round(pixels / scale)));
        return target - edge;
    }

    /** The points a key moves a boundary (null: not ours): arrows 1, with Shift 5, Home and End
     *  as far as the neighbours allow. */
    function keyDelta(key, shift, values, k) {
        const step = shift ? SHIFT_STEP : 1;
        switch (key) {
        case 'ArrowLeft': case 'ArrowDown': return -step;
        case 'ArrowRight': case 'ArrowUp': return step;
        case 'Home': return -values[k];
        case 'End': return values[k + 1];
        default: return null;
        }
    }

    /** Where everything goes: each segment's width and each boundary's position, as a percentage
     *  plus pixels. A 0% segment gets a ZERO_SLOT-pixel slot and the others give up that room in
     *  proportion, so the shares stay exact and every boundary has a place of its own. */
    function layout(values) {
        const shares = widths(values);
        const zeros = shares.filter((share) => !share).length;
        const room = (percent) => -zeros * ZERO_SLOT * percent / TOTAL;
        let edge = 0;
        let before = 0;
        const boundaries = shares.slice(0, -1).map((share) => {
            edge = round(edge + share);
            before += share ? 0 : 1;
            return {percent: edge, px: round(before * ZERO_SLOT + room(edge))};
        });
        return {
            zeros,
            segments: shares.map((share) => ({percent: share, px: share ? round(room(share)) : ZERO_SLOT, zero: !share})),
            boundaries,
        };
    }

    /** Segment widths (percent of the bar): the values themselves, or scaled to fit while the
     *  fields do not add up. */
    function widths(values) {
        const sum = values.reduce((total, value) => total + (value || 0), 0);
        return values.map((value) => (sum > 0 ? (value || 0) * TOTAL / Math.max(sum, TOTAL) : 0));
    }

    const api = {TOTAL, SHIFT_STEP, ZERO_SLOT, parse, evaluate, move, dragDelta, keyDelta, layout, widths};

    /**
     * A bar over a set of fields. options: container (element), segments ([{label, short, css,
     * field (jQuery input; absent for the derived one), derived}]), changed (callback after any
     * change).
     */
    api.create = function (options) {
        const $ = root.jQuery;
        const segments = options.segments;
        const wrap = $('<div class="fwmap-allocation"/>');
        const bar = $('<div class="progress fwmap-allocation-bar"/>').appendTo(wrap);
        const parts = segments.map((segment) => $('<div class="progress-bar"/>').addClass(segment.css).appendTo(bar)
            .append($('<span class="fwmap-allocation-name"/>'), $('<span class="fwmap-allocation-value"/>')));
        // a handle: a thin bar on the boundary, like the map's panel splitters
        const handles = segments.slice(0, -1).map((segment, k) => $('<span class="fwmap-allocation-handle"'
            + ' role="slider" tabindex="0" aria-valuemin="0" aria-valuemax="100"></span>')
            .attr('aria-label', `${segment.label} | ${segments[k + 1].label}`).appendTo(wrap));
        $(options.container).append(wrap);

        const state = () => evaluate(segments, segments.map((segment) => segment.field && segment.field.val()));
        const write = (values) => {
            segments.forEach((segment, index) => segment.field && segment.field.val(String(values[index])));
            render();
            options.changed();
        };
        const place = (percent, px) => `calc(${percent}% + ${px}px)`;
        const render = () => {
            const current = state();
            const plan = layout(current.values.map((value) => value || 0));
            plan.segments.forEach(({percent, px, zero}, index) => {
                const value = current.values[index];
                const text = value === null ? '?' : `${value}%`;
                // a 0% segment: its own narrow striped slot, so it reads as empty, never as a sliver
                parts[index].css('width', zero ? `${px}px` : place(percent, px))
                    .toggleClass('fwmap-allocation-zero progress-bar-striped', zero)
                    .attr('title', `${segments[index].label}: ${text}`)
                    .find('.fwmap-allocation-name').text(percent >= 16 ? segments[index].label : percent >= 8 ? segments[index].short : '').end()
                    .find('.fwmap-allocation-value').text(percent >= 5 ? text : '');
            });
            plan.boundaries.forEach(({percent: position, px}, k) => {
                handles[k].css({left: place(position, px)})
                    .toggleClass('disabled', !current.valid).attr('aria-disabled', String(!current.valid))
                    .attr('aria-valuenow', String(position))
                    .attr('aria-valuetext', `${segments[k].label} ${current.values[k] ?? '?'}%, `
                        + `${segments[k + 1].label} ${current.values[k + 1] ?? '?'}%`);
            });
            return current;
        };
        const shift = (k, delta) => {
            const current = state();
            if (current.valid && delta) {
                write(move(current.values, k, delta));
                tips[k].refresh();
            }
        };
        // hovering a handle names the two segments it resizes (with their colours and shares):
        // a narrow segment shows no name of its own. Bootstrap's tooltip, kept open while dragging
        const tips = handles.map((handle, k) => {
            const side = (index, value) => $('<span class="fwmap-allocation-tip-side"/>').append(
                $('<span class="fwmap-allocation-swatch"/>').addClass(segments[index].css), ' ',
                $('<b/>').text(segments[index].label), ` ${value ?? '?'}%`);
            const content = () => {
                const values = state().values;
                return $('<span class="fwmap-allocation-tip"/>').append(side(k, values[k]),
                    '<i class="fa fa-arrows-left-right" aria-hidden="true"></i>', side(k + 1, values[k + 1]))[0].outerHTML;
            };
            let hovered = false;
            let dragging = false;
            handle.tooltip({html: true, placement: 'top', container: 'body', trigger: 'manual', animation: false, title: content,
                template: '<div class="tooltip fwmap-allocation-tooltip" role="tooltip"><div class="tooltip-arrow"></div><div class="tooltip-inner"></div></div>'});
            const settle = () => handle.tooltip(hovered || dragging ? 'show' : 'hide');
            handle.on('mouseenter', () => { hovered = true; settle(); }).on('mouseleave', () => { hovered = false; settle(); });
            return {
                refresh: () => (hovered || dragging) && handle.tooltip('show'),
                drag: (active) => { dragging = active; settle(); },
            };
        });
        handles.forEach((handle, k) => {
            handle.on('keydown', (event) => {
                const current = state();
                const delta = keyDelta(event.key, event.shiftKey, current.values, k);
                if (delta !== null) {
                    event.preventDefault();
                    shift(k, delta);
                }
            });
            handle.on('pointerdown', (event) => {
                if (!state().valid) {
                    return;
                }
                event.preventDefault();
                handle[0].setPointerCapture(event.pointerId);
                handle.trigger('focus');
                // measured from where the handle was taken (it may stand beside its boundary), so
                // taking it moves nothing
                // the boundary follows the pointer from where it was taken, on the bar's scale at
                // that moment (its 0% slots left out), so neither taking a handle beside its
                // boundary nor a slot appearing or vanishing on the way makes it jump
                const box = bar[0].getBoundingClientRect();
                const scale = (box.width - layout(state().values).zeros * ZERO_SLOT) / TOTAL;
                const startX = event.clientX;
                const startEdge = state().values.slice(0, k + 1).reduce((total, value) => total + value, 0);
                const drag = (moved) => {
                    const values = state().values;
                    const edge = values.slice(0, k + 1).reduce((total, value) => total + value, 0);
                    shift(k, dragDelta(startEdge, edge, moved.clientX - startX, scale));
                };
                handle.on('pointermove.fwmap', drag);
                handle.addClass('fwmap-dragging');
                tips[k].drag(true);
                handle.one('pointerup pointercancel', () => {
                    handle.off('pointermove.fwmap').removeClass('fwmap-dragging');
                    tips[k].drag(false);
                });
            });
        });
        segments.forEach((segment) => segment.field && segment.field.on('input change', () => {
            render();
            options.changed();
        }));
        return {render, state, refresh: () => {
            render();
            options.changed();
        }};
    };

    root.FirewallMapAllocation = api;
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = api;
    }
})(typeof window !== 'undefined' ? window : globalThis);
