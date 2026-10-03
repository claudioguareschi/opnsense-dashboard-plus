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

/* Requests and dialogs. */
import {escapeHtml} from '../src/format.js';
import {T} from './context.js';

export function postJSON(url, payload) {
  return $.ajax({url, type: 'POST', dataType: 'json', contentType: 'application/json', data: JSON.stringify(payload || {})});
}

export function getJSON(url) {
  return $.getJSON(url);
}

/** A failed request or thrown error as one line. */
export function errorText(error) {
  return error?.message || error?.statusText || String(error);
}

export function notify(message, type) {
  BootstrapDialog.show({
    type: type || BootstrapDialog.TYPE_INFO, title: T.firewall_map, message: escapeHtml(message),
    buttons: [{label: T.close, action: (dialog) => dialog.close()}],
  });
}

export function notifyFailure(error) {
  notify(`${T.action_failed}: ${errorText(error)}`, BootstrapDialog.TYPE_DANGER);
}

export function confirmAction(message, onConfirm) {
  BootstrapDialog.confirm({
    title: T.firewall_map, message: escapeHtml(message), type: BootstrapDialog.TYPE_WARNING,
    btnOKLabel: T.confirm, btnCancelLabel: T.cancel,
    callback: (confirmed) => confirmed && onConfirm(),
  });
}
