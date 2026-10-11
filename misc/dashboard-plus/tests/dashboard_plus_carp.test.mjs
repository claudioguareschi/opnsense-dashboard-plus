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
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import {loadBrowserWidget} from '../../../tools/browser-widget-test.mjs';

const Carp = await loadBrowserWidget(new URL('../src/opnsense/www/js/widgets/DashboardPlusCarp.js', import.meta.url));

const metadata = readFileSync(new URL('../src/opnsense/www/js/widgets/Metadata/DashboardPlus.xml', import.meta.url), 'utf8');
const block = metadata.slice(metadata.indexOf('<dashboardpluscarp>'), metadata.indexOf('</dashboardpluscarp>'));
const translations = Object.fromEntries([...block.matchAll(/<(\w+)>([^<]*)<\/\1>/g)].map(match => [match[1], match[2]]));

const vip = (vhid, state, extra = {}) => ({name: `LAN${vhid}`, identifier: `opt${vhid}`, device: `vlan0${vhid}`, vhid,
    addresses: [`192.0.2.${vhid}/24`], state, advbase: 1, advskew: 100, description: `VIP ${vhid}`, ...extra});

const counters = (extra = {}) => ({carp_received: 1000, carp_sent: 10, carp_errors: 0, pfsync_received: 500,
    pfsync_sent: 200, pfsync_updates_in: 5000, pfsync_updates_out: 2000, pfsync_errors: 0, ...extra});

const sample = (at, extra = {}) => ({
    status: 'ok', available: true, hostname: 'fw-b', sampled_at: at,
    carp: {allow: 1, preempt: 1, demotion: 0, log: 1},
    summary: {state: 'backup', total: 2, master: 0, backup: 2, init: 0},
    vips: [vip(1, 'backup'), vip(2, 'backup')],
    pfsync: {up: true, syncdev: 'igb4', syncdev_name: 'HA_SYNC', peer: '203.0.113.1', maxupd: 128, defer: 'off',
             version: 1500, syncok: true},
    counters: counters(),
    config_sync: {target: ''},
    transitions: [],
    ...extra,
});

/* Two reads ten seconds apart, the second one with these counters. */
const widgetAfter = (later, first = sample(1000)) => {
    const widget = new Carp({translations});
    widget._updateRates(first);
    widget._updateRates(later);
    widget.data = later;
    return widget;
};

const text = html => html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();

test('CARP+ turns counters into rates per second, and waits for a second read', () => {
    const widget = new Carp({translations});
    widget._updateRates(sample(1000));
    assert.equal(widget._rate('carp_received'), null);
    assert.match(text(widget._peerLine(sample(1000))), /measuring/);
    widget._updateRates(sample(1010, {counters: counters({carp_received: 1110, pfsync_updates_in: 5003})}));
    assert.equal(widget._rate('carp_received'), '11');
    assert.equal(widget._rate('pfsync_updates_in'), '0.3');
    assert.equal(widget._rate('carp_sent'), '0');
});

test('CARP+ shows a counter reset as measuring, not as a negative rate', () => {
    const widget = widgetAfter(sample(1010, {counters: counters({carp_received: 3})}));
    assert.equal(widget._rate('carp_received'), null);
});

test('CARP+ hears the master on a backup and turns red when the advertisements stop', () => {
    const healthy = widgetAfter(sample(1010, {counters: counters({carp_received: 1110})}));
    const line = healthy._peerLine(healthy.data);
    assert.match(line, /fa-tower-broadcast text-success/);
    assert.equal(text(line), 'Master advertising 11 advertisements/s');
    const silent = widgetAfter(sample(1010));
    assert.match(silent._peerLine(silent.data), /text-danger/);
    assert.match(text(silent._peerLine(silent.data)), /^No advertisements from the master 0 advertisements\/s$/);
});

test('CARP+ counts what a master sends', () => {
    const master = {summary: {state: 'master', total: 2, master: 2, backup: 0, init: 0},
                    vips: [vip(1, 'master'), vip(2, 'master')]};
    const widget = widgetAfter(sample(1010, {...master, counters: counters({carp_sent: 120})}), sample(1000, master));
    assert.equal(text(widget._peerLine(widget.data)), 'Advertising to the backup 11 advertisements/s');
});

test('CARP+ heads with the role over all VIPs and the shared settings', () => {
    const widget = new Carp({translations});
    const head = widget._head(sample(1000));
    assert.match(head, /dashboard-plus-state-pill text-info/);
    assert.equal(text(head), 'Backup all 2 VIPs Preempt on · Skew 100 · Not demoted');
    const split = sample(1000, {summary: {state: 'split', total: 2, master: 1, backup: 1, init: 0},
        vips: [vip(1, 'master', {advskew: 0}), vip(2, 'backup')], carp: {allow: 1, preempt: 0, demotion: 240, log: 1}});
    const faulty = widget._head(split);
    assert.match(faulty, /dashboard-plus-state-pill text-danger/);
    assert.equal(text(faulty), 'Split 1 master · 1 backup Preempt off · Demoted (240)');
    assert.match(faulty, /class="text-warning" title="The demotion counter/);
});

test('CARP+ folds agreeing VIPs into one line and opens them when they disagree', () => {
    const widget = new Carp({translations});
    const agreeing = widget._vips(sample(1000));
    assert.equal(text(agreeing), '2 VIPs · all Backup Show');
    assert.doesNotMatch(agreeing, /role="row"/);
    widget.expanded.vips = true;
    const open = widget._vips(sample(1000));
    assert.equal((open.match(/role="row"/g) || []).length, 2);
    assert.match(text(open), /LAN1 VHID 1 · VIP 1 192\.0\.2\.1\/24 Backup/);
    assert.match(open, /title="vlan01 · advbase 1 · advskew 100"/);
    const split = new Carp({translations})._vips(sample(1000, {
        summary: {state: 'split', total: 2, master: 1, backup: 1, init: 0}, vips: [vip(1, 'master'), vip(2, 'backup')]}));
    assert.match(text(split), /^2 VIPs Hide/);
    assert.equal((split.match(/role="row"/g) || []).length, 2);
});

test('CARP+ lets an IPv6 VIP address break at its colons', () => {
    const widget = new Carp({translations});
    widget.expanded.vips = true;
    const html = widget._vips(sample(1000, {vips: [vip(3, 'backup', {addresses: ['2001:db8::250/64']})],
        summary: {state: 'backup', total: 1, master: 0, backup: 1, init: 0}}));
    assert.match(html, /2001:<wbr>db8:<wbr>:<wbr>250\/64/);
});

test('CARP+ shows state sync: the peer, bulk sync, update rates and real errors', () => {
    const healthy = widgetAfter(sample(1010, {counters: counters({pfsync_updates_in: 5940, pfsync_updates_out: 2400})}));
    const line = healthy._pfsyncLine(healthy.data);
    assert.match(line, /fa-arrows-rotate text-success/);
    assert.equal(text(line), 'State sync on HA_SYNC (igb4) to 203.0.113.1 Bulk sync complete · 94/s 40/s · no errors');
    const pending = widgetAfter(sample(1010, {pfsync: {...sample(0).pfsync, syncok: false},
                                              counters: counters({pfsync_errors: 24})}));
    const faulty = pending._pfsyncLine(pending.data);
    assert.match(faulty, /fa-arrows-rotate text-warning/);
    assert.match(faulty, /<span class="text-warning">Bulk sync in progress<\/span>/);
    assert.match(faulty, /<span class="text-danger">2\.4 errors\/s<\/span>/);
    const down = new Carp({translations})._pfsyncLine(sample(1000, {pfsync: {...sample(0).pfsync, up: false}}));
    assert.match(down, /fa-arrows-rotate text-danger/);
    const off = new Carp({translations})._pfsyncLine(sample(1000, {pfsync: null}));
    assert.equal(text(off), 'State sync (pfsync) is not configured');
});

test('CARP+ links config sync to the high availability settings', () => {
    const widget = new Carp({translations});
    const sending = widget._configSyncLine(sample(1000, {config_sync: {target: '203.0.113.1'}}));
    assert.match(sending, /fa-file-arrow-up text-success/);
    assert.match(sending, /<a href="\/ui\/core\/hasync" class="dashboard-plus-carp-plain">Config sync to 203\.0\.113\.1<\/a>/);
    const quiet = widget._configSyncLine(sample(1000));
    assert.match(quiet, /fa-file-arrow-up text-muted/);
    assert.equal(text(quiet), 'Config sync is not sent from this firewall');
});

test('CARP+ shows the last change and up to eight more on request', () => {
    const now = Date.now() / 1000;
    const transitions = Array.from({length: 12}, (_, index) => ({time: now - 7200 - index * 60, vhid: 1, device: 'vlan01',
        name: 'LAN1', from: 'init', to: 'backup', reason: index ? 'initialization complete' : ''}));
    const widget = new Carp({translations});
    const closed = widget._historyLine(sample(1000, {transitions}));
    assert.equal(text(closed), 'Last change 2 h ago History (8) LAN1 · VHID 1 · Init Backup');
    assert.match(closed, /<span class="text-info">Backup<\/span>/);
    widget.expanded.history = true;
    const open = widget._historyLine(sample(1000, {transitions}));
    assert.equal((open.match(/<li>/g) || []).length, 8);
    assert.match(text(open), /Hide history/);
    assert.match(text(open), /\(initialization complete\)/);
    assert.equal(text(widget._historyLine(sample(1000))), 'No CARP changes logged recently');
});

test('CARP+ escapes names from the configuration and the log', () => {
    const widget = new Carp({translations});
    widget.expanded.vips = true;
    const html = widget._vips(sample(1000, {vips: [vip(1, 'backup', {name: '<b>LAN</b>', description: '"x" & y'})],
        summary: {state: 'backup', total: 1, master: 0, backup: 1, init: 0}}));
    assert.doesNotMatch(html, /<b>LAN<\/b>/);
    assert.match(html, /&lt;b&gt;LAN&lt;\/b&gt;/);
    const history = widget._historyLine(sample(1000, {transitions: [{time: 1000, vhid: 1, device: 'x', name: 'x',
        from: 'init', to: 'backup', reason: '<script>'}]}));
    assert.doesNotMatch(history, /<script>/);
});

test('CARP+ without CARP points to the virtual IP settings', () => {
    const html = [];
    globalThis.$ = () => ({html: value => html.push(value)});
    const widget = new Carp({translations});
    widget.data = sample(1000, {available: false, vips: [], summary: {state: 'none', total: 0, master: 0, backup: 0, init: 0}});
    widget._render();
    assert.match(html[0], /<a href="\/ui\/interfaces\/vip">No CARP virtual IPs configured/);
    widget.error = translations.fetch_failed;
    widget._render();
    assert.match(html[1], /CARP status is unavailable/);
});
