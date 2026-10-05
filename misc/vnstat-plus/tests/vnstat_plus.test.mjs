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

const VnstatPlus = await loadBrowserWidget(new URL('../src/opnsense/www/js/widgets/VnstatPlus.js', import.meta.url));
const translations = {
    hours: 'hours', days: 'days', months: 'months', years: 'years', latest: 'Latest',
    msg_no_data: 'No data'
};

test('VNStat Plus selects period-specific chart windows and preserves legacy visibility settings', () => {
    const widget = new VnstatPlus({translations});
    widget.currentPeriod = 'day';
    assert.deepEqual(widget._rangeOptions().map(option => option.value), ['30', '14', '7']);

    widget._populateRangeDropdown = () => {};
    widget._applyVisibility = () => {};
    widget._applyConfig({show_kpi: 'no', show_chart: 'yes', show_history: 'no', bar_range: '6'});
    assert.deepEqual([widget.showKpi, widget.showChart, widget.showHistory, widget.barRange], [false, true, false, '6']);
});

test('VNStat Plus pages chart history from newest entries without crossing bounds', () => {
    const widget = new VnstatPlus({translations});
    widget.barRange = '3';
    widget.chartOffset = 0;
    const entries = [1, 2, 3, 4, 5, 6, 7].map(day => ({date: {year: 2026, month: 10, day}}));

    assert.deepEqual(widget._chartEntries(entries).entries.map(entry => entry.date.day), [5, 6, 7]);
    widget.chartOffset = 20;
    const oldest = widget._chartEntries(entries);
    assert.deepEqual(oldest.entries.map(entry => entry.date.day), [1]);
    assert.equal(widget.chartOffset, 2);
    assert.equal(oldest.canGoNext, true);
});

test('VNStat Plus requests the chosen interface safely and sorts returned history', async () => {
    const widget = new VnstatPlus({translations});
    widget.currentInterface = 'igb 1';
    widget.currentPeriod = 'day';
    widget._renderSummary = entry => { widget.summary = entry; };
    widget._renderChart = entries => { widget.chart = entries; };
    widget._renderTable = entries => { widget.table = entries; };
    widget._chartEntries = entries => ({entries, canGoPrevious: false, canGoNext: false});
    let url;
    widget.ajaxCall = async value => {
        url = value;
        return {interfaces: [{traffic: {day: [
            {date: {year: 2026, month: 10, day: 2}, rx: 2, tx: 3},
            {date: {year: 2026, month: 10, day: 1}, rx: 1, tx: 1}
        ]}}]};
    };

    await widget._fetchAndRenderOnce();
    assert.equal(url, '/api/vnstat/service/get_json_data?iface=igb%201');
    assert.equal(widget.summary.date.day, 2);
    assert.deepEqual(widget.chart.map(entry => entry.date.day), [1, 2]);
    assert.deepEqual(widget.table.map(entry => entry.date.day), [2, 1]);
});
