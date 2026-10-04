<?php

/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the
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
namespace OPNsense\FirewallMap\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;
use OPNsense\FirewallMap\AuditLog;
use OPNsense\FirewallMap\ConfigdArgument;

/**
 * Threat history organized by observed disposition (administrators only, see ACL).
 * Workflow status and notes never change firewall rules.
 */
class ThreatsController extends ApiControllerBase
{
    private const STATUSES = ['new', 'reviewed', 'dismissed', 'blocked'];
    private const VIEWS = ['passed', 'firewall_blocked', 'ips_dropped', 'all', 'reviewed', 'dismissed'];

    /* a note's limit in bytes, not characters: configd reads one 4 kB message, and base64 grows the
       text by a third (2400 bytes: 800 characters of CJK, 600 emoji, 2400 of Latin text) */
    private const NOTE_BYTES = 2400;

    private function audit($action)
    {
        AuditLog::record((string)$this->session->get('Username'), $action);
    }

    /** The search a bulk action applied to, as the administrator typed it. */
    private function searched()
    {
        /* one log line: control characters (a newline) cannot start a fake entry */
        $query = trim(preg_replace('/[\x00-\x1f\x7f]+/u', ' ', (string)($this->request->getPost('query') ?? '')));
        return $query !== '' ? ' (search: ' . mb_substr($query, 0, 200) . ')' : '';
    }

    /** One page of a tab; `q` searches what the queue displays, `offset` and `limit` page it. */
    public function listAction($status = null)
    {
        $status = in_array($status, self::VIEWS, true) || $status === 'counts' ? $status : 'all';
        $offset = max(0, (int)($this->request->get('offset') ?? 0));
        $limit = max(1, min(500, (int)($this->request->get('limit') ?? 100)));
        $query = ConfigdArgument::text($this->request->get('q') ?? '', 200);
        $result = json_decode((new Backend())->configdpRun(
            'firewallmap threats list',
            [$status, (string)$offset, (string)$limit, $query]
        ) ?? '', true);
        return is_array($result) ? $result : ['status' => 'failed', 'rows' => [], 'counts' => []];
    }

    public function setAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        $address = (string)$this->request->getPost('address');
        $status = (string)$this->request->getPost('status');
        if (filter_var($address, FILTER_VALIDATE_IP) === false) {
            return ['result' => 'failed', 'error' => 'not an IP address'];
        }
        if (!in_array($status, self::STATUSES, true)) {
            return ['result' => 'failed', 'error' => 'unknown status'];
        }
        /* "-": no note sent, keep the old one; "=": an empty note, clear it */
        $note = '-';
        if ($this->request->hasPost('note')) {
            $note = ConfigdArgument::text($this->request->getPost('note'), self::NOTE_BYTES, '=');
        }
        $result = json_decode(
            (new Backend())->configdpRun('firewallmap threats set', [$address, $status, $note]) ?? '',
            true
        );
        if (($result['result'] ?? '') === 'saved') {
            $this->audit("set threat {$address} to {$status}" . ($note !== '-' ? ' and changed its note' : ''));
        }
        return is_array($result) ? $result : ['result' => 'failed', 'error' => 'no response'];
    }

    /** Move every entry of one status (matching `query`, when given) to another, e.g. dismiss all new entries. */
    public function bulkAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        $from = (string)$this->request->getPost('from');
        $to = (string)$this->request->getPost('to');
        if (!in_array($from, self::VIEWS, true) || !in_array($to, self::STATUSES, true)) {
            return ['result' => 'failed', 'error' => 'unknown status'];
        }
        $query = ConfigdArgument::text($this->request->getPost('query') ?? '', 200);
        $output = (new Backend())->configdpRun('firewallmap threats bulk', [$from, $to, $query]);
        $result = json_decode($output ?? '', true);
        if (($result['result'] ?? '') === 'saved') {
            $this->audit("set {$result['changed']} {$from} threat entries to {$to}" . $this->searched());
        }
        return is_array($result) ? $result : ['result' => 'failed', 'error' => 'no response'];
    }

    /** Delete dismissed or reviewed entries (matching `query`, when given) for good. */
    public function purgeAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        $status = (string)$this->request->getPost('status');
        if (!in_array($status, ['dismissed', 'reviewed'], true)) {
            return ['result' => 'failed', 'error' => 'only dismissed or reviewed entries can be deleted'];
        }
        $query = ConfigdArgument::text($this->request->getPost('query') ?? '', 200);
        $result = json_decode((new Backend())->configdpRun('firewallmap threats purge', [$status, $query]) ?? '', true);
        if (($result['result'] ?? '') === 'deleted') {
            $this->audit("deleted {$result['deleted']} {$status} threat entries" . $this->searched());
        }
        return is_array($result) ? $result : ['result' => 'failed', 'error' => 'no response'];
    }
}
