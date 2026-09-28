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
