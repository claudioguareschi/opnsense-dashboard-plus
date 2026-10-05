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

import assert from 'node:assert/strict';
import {test} from 'node:test';
import {loadBrowserWidget} from '../../../tools/browser-widget-test.mjs';

const QuickAssist = await loadBrowserWidget(
    new URL('../src/opnsense/www/js/widgets/DashboardPlusQuickAssist.js', import.meta.url)
);

const translations = {active: 'Active', degraded: 'Degraded', fault: 'Fault', unavailable: 'Unavailable'};
const sample = (at, devices, ocf = {present: true, enabled: true}) => ({available: true, sampled_at: at, devices, ocf});
const device = (unit, responses, requests, extra = {}) => ({
    unit, responses, requests, state: 'up', heartbeat: 1, heartbeat_failed: 0, ae_count: 10, ...extra
});

test('QuickAssist+ calculates rates with actual elapsed time and no lag when requests equal responses', () => {
    const widget = new QuickAssist({translations});
    assert.equal(widget._rates(sample(1000, [device(0, 1000000, 1000000)])).reset, true);
    const rates = widget._rates(sample(1002, [device(0, 1100000, 1100000)]));
    assert.deepEqual(rates, {completed: 50000, requests: 50000, lag: 0, outstanding: 0, reset: false});
});

test('QuickAssist+ reports lag and a single outstanding request without declaring it unhealthy', () => {
    const widget = new QuickAssist({translations});
    widget._rates(sample(1000, [device(0, 10, 11)]));
    const rates = widget._rates(sample(1002, [device(0, 20, 23)]));
    assert.equal(rates.completed, 5);
    assert.equal(rates.lag, 1);
    assert.equal(rates.outstanding, 3);
    assert.equal(widget._health(sample(1002, [device(0, 20, 23)])).key, 'active');
});

test('QuickAssist+ establishes a baseline after a counter reset or device disappearance', () => {
    const widget = new QuickAssist({translations});
    widget._rates(sample(1000, [device(0, 100, 100), device(2, 100, 100)]));
    assert.equal(widget._rates(sample(1002, [device(0, 10, 10), device(2, 120, 120)])).reset, true);
    widget._rates(sample(1004, [device(0, 20, 20), device(2, 130, 130)]));
    assert.equal(widget._rates(sample(1006, [device(0, 30, 30)])).reset, true);
});

test('QuickAssist+ treats historical heartbeat failures as healthy but new failures as degraded then fault', () => {
    const widget = new QuickAssist({translations});
    widget.previous = widget._snapshot(sample(1000, [device(0, 1, 1, {heartbeat_failed: 7})]));
    assert.equal(widget._health(sample(1002, [device(0, 2, 2, {heartbeat_failed: 7})])).key, 'active');
    widget.previous = widget._snapshot(sample(1002, [device(0, 2, 2, {heartbeat_failed: 7})]));
    assert.equal(widget._health(sample(1004, [device(0, 3, 3, {heartbeat_failed: 8})])).key, 'degraded');
    widget.previous = widget._snapshot(sample(1004, [device(0, 3, 3, {heartbeat_failed: 8})]));
    widget._health(sample(1006, [device(0, 4, 4, {heartbeat_failed: 9})]));
    widget.previous = widget._snapshot(sample(1006, [device(0, 4, 4, {heartbeat_failed: 9})]));
    assert.equal(widget._health(sample(1008, [device(0, 5, 5, {heartbeat_failed: 10})])).key, 'fault');
});

test('QuickAssist+ reports state and OCF problems without requiring System Information+', () => {
    const widget = new QuickAssist({translations});
    assert.equal(widget._health(sample(1000, [device(0, 1, 1, {state: 'down'})])).key, 'fault');
    assert.equal(widget._health(sample(1000, [device(0, 1, 1, {state: '', heartbeat: null})])).key, 'active');
    assert.equal(widget._health(sample(1000, [device(0, 1, 1)], {present: true, enabled: false})).key, 'degraded');
    assert.equal(widget._health({available: false, devices: [], ocf: {}}).key, 'unavailable');
});

test('QuickAssist+ shows a per-device AE figure only when all device counts match', () => {
    const widget = new QuickAssist({translations});
    assert.equal(widget._serviceList([{services: 'sym;dc'}, {services: 'dc;asym'}]),
        'Symmetric cryptography · Data compression · Asymmetric cryptography');
    assert.equal(widget._mhz(685000000), '685 MHz');
    assert.equal(widget._mhz(0), '');
});

test('QuickAssist+ retains only the current minute of Chart.js samples', () => {
    const widget = new QuickAssist({translations});
    widget._recordRate({completed: 1}, 1000);
    widget._recordRate({completed: 2}, 61000);
    assert.deepEqual(widget.rateSamples, [{x: 1000, y: 1}, {x: 61000, y: 2}]);
    widget._recordRate({completed: 3}, 61001);
    assert.deepEqual(widget.rateSamples, [{x: 61000, y: 2}, {x: 61001, y: 3}]);
});

test('QuickAssist+ requests its live sample through the widget request context', async () => {
    const widget = new QuickAssist({translations});
    let requested = null;
    widget.ajaxCall = async url => {
        requested = url;
        return sample(1000, [device(0, 10, 10)]);
    };
    widget._render = () => {};
    widget._renderChart = () => {};
    await widget._sample();
    assert.equal(requested, '/api/dashboardplus/system/qat');
});

test('QuickAssist+ ignores a repeated shared sample instead of rendering a zero rate', async () => {
    const widget = new QuickAssist({translations});
    const live = sample(1000, [device(0, 10, 10)]);
    let renders = 0;
    widget.ajaxCall = async () => live;
    widget._render = () => { renders += 1; };
    widget._renderChart = () => {};
    await widget._sample();
    await widget._sample();
    assert.equal(renders, 1);
});
