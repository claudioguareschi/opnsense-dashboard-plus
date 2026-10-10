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

const SystemInformation = await loadBrowserWidget(
    new URL('../src/opnsense/www/js/widgets/DashboardPlusSystemInformation.js', import.meta.url));
// the widget's own English texts
const metadata = readFileSync(new URL('../src/opnsense/www/js/widgets/Metadata/DashboardPlus.xml', import.meta.url), 'utf8');
const block = metadata.slice(metadata.indexOf('<dashboardplussysteminformation>'), metadata.indexOf('</dashboardplussysteminformation>'));
const translations = Object.fromEntries([...block.matchAll(/<(\w+)>([^<]*)<\/\1>/g)].map(match => [match[1], match[2]]));

const NOW = Date.UTC(2026, 9, 10, 12) / 1000;
const pool = (extra = {}) => ({name: 'zroot', state: 'ONLINE', layout: 'mirror', device_errors: 0, data_errors: 0,
    size: 229780750336, allocated: 1960869888, capacity: 0, scan: null, ...extra});
const text = html => html.replace(/<[^>]+>/g, '|').replace(/\|+/g, '|');

test('ZFS: layout, health, errors and capacity on one line, the last scrub under it', () => {
    const widget = new SystemInformation({translations});
    const html = widget._zfs([pool({scan: {function: 'scrub', state: 'finished', start: NOW - 5 * 86400 - 60,
        end: NOW - 5 * 86400, errors: 0, repaired: 0, progress: 100}})], NOW);
    assert.match(text(html), /zroot:\| Mirror · \|Healthy\| · No errors · 0% of 214 GiB\|Last scrub \d{4}-\d\d-\d\d \d\d:\d\d \(5 days ago\) · repaired 0 B/);
    assert.match(html, /<span class="text-success">Healthy<\/span>/);
});

test('ZFS: never scrubbed, a stale scrub and problems stand out', () => {
    const widget = new SystemInformation({translations});
    assert.match(widget._zfs([pool({layout: 'single'})], NOW), /Single disk.*<span class="text-warning">Never scrubbed<\/span>/);
    const stale = widget._zfs([pool({scan: {function: 'scrub', state: 'finished', end: NOW - 40 * 86400, errors: 0, repaired: 0}})], NOW);
    assert.match(stale, /<span class="text-warning">Last scrub [^<]*\(40 days ago\)/);
    const bad = widget._zfs([pool({state: 'DEGRADED', layout: 'raidz2', device_errors: 3, data_errors: 2,
        scan: {function: 'resilver', state: 'scanning', progress: 42}})], NOW);
    assert.match(bad, /RAID-Z2 · <span class="text-warning">Degraded<\/span> · <span class="text-danger">Data loss \(2\)<\/span>/);
    assert.match(bad, /<span class="text-warning">Resilver in progress: 42%<\/span>/);
    const devices = widget._zfs([pool({state: 'FAULTED', device_errors: 5})], NOW);
    assert.match(devices, /<span class="text-danger">Faulted<\/span> · <span class="text-warning">Device errors \(5\)<\/span>/);
    const repaired = widget._zfs([pool({scan: {function: 'scrub', state: 'finished', end: NOW - 3600, errors: 4, repaired: 1536}})], NOW);
    assert.match(repaired, /<span class="text-danger">Last scrub [^<]*\(today\) · repaired 1.5 KiB, 4 errors<\/span>/);
});

test('ZFS shows only where there are pools', () => {
    // the update link is built with jQuery: a stand-in that renders nothing
    globalThis.$ = () => ({attr() { return this; }, text() { return this; }, prop() { return ''; }});
    const widget = new SystemInformation({translations});
    const data = {system: {}, time: {}, details: {zfs_pools: []}};
    assert.equal('zfs' in widget._sections(data), false);
    data.details.zfs_pools = [pool()];
    assert.equal('zfs' in widget._sections(data), true);
});

test('a layout saved before ZFS existed shows it once, after Boot Environment, then keeps its choice', () => {
    const widget = new SystemInformation({translations});
    const saved = [];
    widget.setWidgetConfig = config => saved.push(config);
    // a default layout (no section list) needs nothing
    assert.deepEqual(widget._withNewSections({}), {});
    const old = {sections: ['name', 'boot_environment', 'version', 'uptime']};
    const updated = widget._withNewSections(old);
    assert.deepEqual(updated.sections, ['name', 'boot_environment', 'zfs', 'version', 'uptime']);
    assert.equal(saved.length, 1);
    // hidden afterwards: it stays hidden
    const hidden = {sections: ['name', 'version'], known_sections: updated.known_sections};
    assert.deepEqual(widget._withNewSections(hidden).sections, ['name', 'version']);
    assert.equal(saved.length, 1);
    // without Boot Environment it follows the section before that
    assert.deepEqual(widget._withNewSections({sections: ['firmware', 'cpu']}).sections, ['firmware', 'zfs', 'cpu']);
});
