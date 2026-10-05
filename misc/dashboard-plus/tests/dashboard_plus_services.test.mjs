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

const Services = await loadBrowserWidget(new URL('../src/opnsense/www/js/widgets/DashboardPlusServices.js', import.meta.url));
const translations = {start: 'Start', stop: 'Stop', restart: 'Restart'};

test('Services+ normalizes service API values and narrows the selected services', () => {
    const widget = new Services({translations});
    widget.services = [
        widget._normalizeService({id: 'dns', description: 'DNS resolver', running: '1', locked: '0'}),
        widget._normalizeService({id: 'ssh', description: 'SSH daemon', running: false, locked: true}),
        widget._normalizeService({id: 'ntp', description: 'Time service', running: 0, locked: false})
    ];
    widget.currentConfig = {services: ['ssh', 'dns']};

    assert.deepEqual(widget._serviceData().map(service => service.id), ['dns', 'ssh']);
    assert.equal(widget.services[0].running, true);
    assert.equal(widget.services[1].locked, true);

    widget.filter = 'running';
    assert.deepEqual(widget._visibleServices().map(service => service.id), ['dns']);
    widget.filter = 'locked';
    assert.deepEqual(widget._visibleServices().map(service => service.id), ['ssh']);
    widget.filter = 'all';
    widget.search = 'resolver';
    assert.deepEqual(widget._visibleServices().map(service => service.id), ['dns']);
});

test('Services+ builds safe action endpoints and exposes only valid actions', () => {
    const widget = new Services({translations});
    assert.equal(widget._serviceEndpoint('restart', 'unbound/custom?name'),
        '/api/core/service/restart/unbound/custom%3Fname');

    assert.match(widget._actions({id: 'ssh', running: true, locked: false}), /data-service-action="stop"/);
    assert.match(widget._actions({id: 'ssh', running: true, locked: false}), /data-service-action="restart"/);
    assert.match(widget._actions({id: 'unbound', running: false, locked: false}), /data-service-action="start"/);
    const locked = widget._actions({id: 'configd', running: true, locked: true});
    assert.match(locked, /data-service-action="restart"/);
    assert.doesNotMatch(locked, /data-service-action="stop"/);
});

test('Services+ sends a control request only after confirmation', async () => {
    const widget = new Services({translations});
    widget.services = [{id: 'unbound', description: 'DNS resolver', running: true, locked: false}];
    widget._render = () => {};
    widget._fetchServices = async () => {};
    const calls = [];
    widget.ajaxCall = async (...arguments_) => calls.push(arguments_);
    const previousWindow = globalThis.window;
    try {
        globalThis.window = {confirm: () => false};
        await widget._runAction('unbound', 'restart');
        assert.deepEqual(calls, []);

        globalThis.window = {confirm: () => true};
        await widget._runAction('unbound', 'restart');
    } finally {
        globalThis.window = previousWindow;
    }
    assert.deepEqual(calls, [['/api/core/service/restart/unbound', {}, 'POST']]);
    assert.equal(widget.busyService, null);
});
