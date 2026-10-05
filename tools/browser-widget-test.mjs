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

import {readFile} from 'node:fs/promises';

const COMMON_STUB = `
const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, character => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;'}[character]));
const renderTitle = () => {};
const ensureStyle = () => {};
const sharedRequest = (widget, url) => widget.ajaxCall(url);
const DashboardPlusWidget = Base => Base;
`;

const COMMON_IMPORT = /const \{[^}]+\}\s*=\s*\n\s*await import\(`\.\/DashboardPlusCommon\.js\$\{new URL\(import\.meta\.url\)\.search\}`\);/;

/** Load a browser widget in Node with only the shared widget primitives it uses in unit tests. */
export async function loadBrowserWidget(path) {
    const previousBaseWidget = globalThis.BaseWidget;
    globalThis.BaseWidget = class {
        constructor(config = {}) {
            this.config = config;
            this.id = config.id || 'test-widget';
            this.translations = config.translations || {};
        }
    };
    try {
        const source = (await readFile(path, 'utf8')).replace(COMMON_IMPORT, COMMON_STUB);
        return (await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`)).default;
    } finally {
        globalThis.BaseWidget = previousBaseWidget;
    }
}
