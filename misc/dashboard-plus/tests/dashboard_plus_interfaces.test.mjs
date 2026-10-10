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

const Interfaces = await loadBrowserWidget(new URL('../src/opnsense/www/js/widgets/DashboardPlusInterfaces.js', import.meta.url));

test('Interfaces+ lists the enabled, non-virtual interfaces of system/interfaces', () => {
    const widget = new Interfaces({translations: {}});
    const rows = [
        {identifier: 'lan', enabled: true, virtual: false},
        {identifier: 'opt1', enabled: false, virtual: false},
        {identifier: 'lo0', enabled: true, virtual: true},
        {identifier: 'opt9', enabled: true, virtual: false}
    ];
    assert.deepEqual(widget._availableInterfaces({rows}).map(row => row.identifier), ['lan', 'opt9']);
    assert.deepEqual(widget._availableInterfaces({status: 'failed'}), []);
    assert.deepEqual(widget._availableInterfaces(null), []);
});

test('Interfaces+ reads its own endpoint, not the interfaces overview', async () => {
    const widget = new Interfaces({translations: {}});
    const calls = [];
    widget.ajaxCall = async url => {
        calls.push(url);
        return {rows: [{identifier: 'lan', enabled: true, virtual: false, description: 'LAN', status: 'up'}]};
    };
    widget._render = () => {};
    widget.currentConfig = {refresh_interval: '10'};
    await widget.onWidgetTick();
    assert.deepEqual(calls, ['/api/dashboardplus/system/interfaces']);
    assert.deepEqual(widget.cachedInterfaces.map(row => row.identifier), ['lan']);
});
