/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
 * All rights reserved.
 */

import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {test} from 'node:test';
import {loadBrowserWidget} from '../../../tools/browser-widget-test.mjs';

const Traffic = await loadBrowserWidget(
    new URL('../src/opnsense/www/js/widgets/DashboardPlusTraffic.js', import.meta.url)
);
const commonSource = await readFile(
    new URL('../src/opnsense/www/js/widgets/DashboardPlusCommon.js', import.meta.url), 'utf8'
);
const {formatBitRate} = await import(`data:text/javascript;base64,${Buffer.from(commonSource).toString('base64')}`);

test('Traffic Graph+ anchors an idle series to zero', () => {
    const widget = new Traffic();
    assert.equal(widget._chartConfig([]).options.scales.y.beginAtZero, true);
});

test('Traffic Graph+ formats fractional bits without an invalid unit', () => {
    assert.equal(formatBitRate(0.5), '0.5 b/s');
    assert.equal(formatBitRate(0.2), '0.2 b/s');
});
