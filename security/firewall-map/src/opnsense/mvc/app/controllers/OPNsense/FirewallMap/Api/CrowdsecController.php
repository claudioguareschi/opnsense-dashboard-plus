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

/**
 * Ban or unban one public address with CrowdSec (administrators only, see ACL). POST only, so a
 * link cannot change a ban (OPNsense checks the CSRF token on POST). The address is
 * percent-decoded first: the router passes path segments still encoded (IPv6 arrives with %3A).
 */
class CrowdsecController extends ApiControllerBase
{
    private const DURATIONS = ['1h', '4h', '24h', '168h', '720h'];

    private function address($address)
    {
        $address = rawurldecode((string)$address);
        return filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false
            ? null : $address;
    }

    private function run(array $parameters)
    {
        $result = json_decode((new Backend())->configdpRun('firewallmap crowdsec', $parameters) ?? '', true);
        return is_array($result) ? $result : ['status' => 'failed', 'error' => 'no response'];
    }

    public function banAction($address = null)
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed', 'error' => 'POST required'];
        }
        $address = $this->address($address);
        $duration = (string)$this->request->getPost('duration');
        if ($address === null) {
            return ['status' => 'failed', 'error' => 'not a public IP address'];
        }
        if (!in_array($duration, self::DURATIONS, true)) {
            return ['status' => 'failed', 'error' => 'unsupported duration'];
        }
        // a short note: letters, digits and simple punctuation, as one configd parameter
        $reason = substr(preg_replace('/[^A-Za-z0-9 .,:_\/-]/', '', (string)$this->request->getPost('reason')), 0, 100);
        $reason = trim($reason) !== '' ? 'firewallmap: ' . trim($reason) : '';
        $result = $this->run(['ban', $address, $duration, $reason]);
        if (($result['status'] ?? '') === 'ok') {
            AuditLog::record((string)$this->getUserName(), "banned {$address} with CrowdSec for {$duration}");
        }
        return $result;
    }

    public function unbanAction($address = null)
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed', 'error' => 'POST required'];
        }
        $address = $this->address($address);
        if ($address === null) {
            return ['status' => 'failed', 'error' => 'not a public IP address'];
        }
        $result = $this->run(['unban', $address, '', '']);
        if (($result['status'] ?? '') === 'ok') {
            AuditLog::record((string)$this->getUserName(), "unbanned {$address} in CrowdSec");
        }
        return $result;
    }
}
