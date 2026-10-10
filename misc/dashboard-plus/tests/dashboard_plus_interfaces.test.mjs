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

test('Interfaces+ rows: name and addresses, then link, MAC address and a state pill in the theme colors', () => {
    // _media decodes the HTML-escaped media text with jQuery: a stand-in that returns it as is
    globalThis.$ = () => ({html(value) { this.value = value; return this; }, text() { return this.value; }});
    const widget = new Interfaces({translations: {online: 'Online', offline: 'Offline', no_carrier: 'No carrier',
        unavailable: 'Unavailable', ipsec_vti: 'IPsec VTI', drag_to_reorder: 'Drag to reorder'}});
    const wan = widget._row({identifier: 'wan', description: 'WAN', device: 'igb0', status: 'up',
        media: '1000baseT <full-duplex>', macaddr: '00:1c:42:9c:ba:c5', addr4: '73.180.73.118/22',
        addr6: '2001:558:6041:1:9cba:c5ad:3caa:d05e/128'});
    assert.match(wan, /<i class="fa fa-fw fa-plug text-success"/);
    assert.match(wan, /<a class="dashboard-plus-interface-name" href="\/interfaces.php\?if=wan"[^>]*>WAN<\/a>/);
    assert.match(wan, /<div>73.180.73.118\/22<\/div><div class="dashboard-plus-muted dashboard-plus-interface-v6">2001:<wbr>558:<wbr>6041:<wbr>1:<wbr>9cba:<wbr>c5ad:<wbr>3caa:<wbr>d05e\/128<\/div>/);
    assert.match(wan, /<div>1000BaseT full duplex<\/div><div class="dashboard-plus-muted">00:1c:42:9c:ba:c5<\/div>/);
    assert.match(wan, /<span class="dashboard-plus-state-pill text-success"><span class="dashboard-plus-state-dot"[^>]*><\/span> Online<\/span>/);
    // a tunnel: its type, no MAC address, no IPv6
    const vti = widget._row({identifier: 'opt3', description: 'GreenwoodVTI', device: 'ipsec1', status: 'up',
        media: '', macaddr: '', addr4: '10.255.255.2/30', addr6: ''});
    // no dash for an address it lacks
    assert.match(vti, /<div class="dashboard-plus-interface-addresses"><div>10.255.255.2\/30<\/div><\/div>/);
    const bare = widget._row({identifier: 'z', description: 'Z', status: 'up'});
    assert.doesNotMatch(bare, /dashboard-plus-interface-addresses/);
    assert.match(vti, /<div>IPsec VTI<\/div><div class="dashboard-plus-muted">—<\/div>/);
    // down and no carrier in the danger color, anything else in ifconfig's own word, muted
    assert.match(widget._row({identifier: 'a', description: 'A', status: 'no carrier'}), /text-danger"><span class="dashboard-plus-state-dot"[^>]*><\/span> No carrier/);
    assert.match(widget._row({identifier: 'b', description: 'B', status: 'down'}), /fa-plug text-danger[\s\S]*Offline/);
    assert.match(widget._row({identifier: 'c', description: 'C', status: 'associated'}), /text-muted"><span class="dashboard-plus-state-dot"[^>]*><\/span> Associated/);
    // names are escaped
    assert.match(widget._row({identifier: 'x', description: '<b>', status: 'up'}), />&lt;b&gt;<\/a>/);
});
