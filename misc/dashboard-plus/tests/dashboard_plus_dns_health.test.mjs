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

const DnsHealth = await loadBrowserWidget(new URL('../src/opnsense/www/js/widgets/DashboardPlusDnsHealth.js', import.meta.url));
const translations = {
    disabled: 'Disabled', running: 'Running', stopped: 'Stopped', unavailable: 'Unavailable',
    local_forwarding: 'Forwarding', local_recursive: 'Recursive'
};

test('DNS Health+ calculates query rate only from monotonic counters', () => {
    const widget = new DnsHealth({translations});
    const originalNow = Date.now;
    try {
        Date.now = () => 1000;
        widget._recordQueryRate(100);
        Date.now = () => 4000;
        widget._recordQueryRate(130);
        Date.now = () => 5000;
        widget._recordQueryRate(10);
    } finally {
        Date.now = originalNow;
    }
    assert.deepEqual(widget.queryRateSamples.map(sample => sample.ratePerSecond), [10]);
});

test('DNS Health+ derives status, resolver mode and cache metrics from partial API data', () => {
    const widget = new DnsHealth({translations});
    widget.data = {
        status: {status: 'running'},
        settings: {unbound: {general: {enabled: '1'}, forwarding: {enabled: '1'}}},
        stats: {data: {total: {num: {queries: 100, cachehits: 75, cachemiss: 25}, recursion: {time: {avg: 0.042}}}}},
        totals: {blocked: {total: 8}, total: 80, resolved: {total: 55}, local: {total: 17}}
    };
    widget.queryRateSamples = [{at: 0, ratePerSecond: 3.5}];

    assert.deepEqual(widget._status(), {label: 'Running', state: 'healthy'});
    assert.equal(widget._mode(), 'Forwarding');
    assert.deepEqual(widget._stats(), {
        rate: 3.5, totalQueries: 100, cacheHits: 75, cacheMisses: 25, cacheRate: 75,
        blocked: 8, blockedRate: 10, resolved: 55, local: 17, lookup: 42
    });
});

test('DNS Health+ keeps useful data when one of its read-only API calls fails', async () => {
    const widget = new DnsHealth({translations: {...translations, fetch_failed: 'Failed'}});
    const calls = [];
    const responses = {
        '/api/unbound/service/status': {status: 'running'},
        '/api/unbound/diagnostics/stats': {data: {total: {num: {queries: 10}}}},
        '/api/unbound/settings/get': {unbound: {general: {enabled: '1'}}},
        '/api/dashboardplus/dns/recent': {queries: [{name: 'example.test'}], types: {A: 1}}
    };
    widget.ajaxCall = async endpoint => {
        calls.push(endpoint);
        if (endpoint === '/api/unbound/settings/searchForward') {
            throw new Error('unavailable');
        }
        return responses[endpoint];
    };
    widget._refreshTotals = () => {};

    await widget._fetchData();
    assert.deepEqual(calls, [
        '/api/unbound/service/status', '/api/unbound/diagnostics/stats', '/api/unbound/settings/get',
        '/api/unbound/settings/searchForward', '/api/dashboardplus/dns/recent'
    ]);
    assert.equal(widget.loading, false);
    assert.deepEqual(widget.data.upstreams, []);
    assert.deepEqual(widget.data.recent.queries, [{name: 'example.test'}]);
});
