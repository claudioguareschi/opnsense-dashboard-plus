<?php

/*
 * Copyright (C) 2026 Claudio Guareschi
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

/**
 * Review queue of permitted traffic to or from flagged addresses (administrators only, see ACL).
 * Setting a status never changes firewall rules.
 */
class ThreatsController extends ApiControllerBase
{
    private const STATUSES = ['new', 'reviewed', 'dismissed', 'blocked'];

    public function listAction($status = null)
    {
        $status = in_array($status, self::STATUSES, true) || $status === 'counts' ? $status : 'all';
        $result = json_decode((new Backend())->configdpRun('firewallmap threats list', [$status]) ?? '', true);
        return is_array($result) ? $result : ['status' => 'failed', 'rows' => [], 'counts' => []];
    }

    public function setAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        $address = (string)$this->request->getPost('address');
        $status = (string)$this->request->getPost('status');
        if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            return ['result' => 'failed', 'error' => 'not an IPv4 address'];
        }
        if (!in_array($status, self::STATUSES, true)) {
            return ['result' => 'failed', 'error' => 'unknown status'];
        }
        /* free text travels as base64url so configd only ever sees [A-Za-z0-9_-] */
        $note = '-';
        if ($this->request->hasPost('note')) {
            $text = mb_substr((string)$this->request->getPost('note'), 0, 1000);
            $note = $text === '' ? '=' : rtrim(strtr(base64_encode($text), '+/', '-_'), '=');
        }
        $result = json_decode(
            (new Backend())->configdpRun('firewallmap threats set', [$address, $status, $note]) ?? '',
            true
        );
        return is_array($result) ? $result : ['result' => 'failed', 'error' => 'no response'];
    }
}
