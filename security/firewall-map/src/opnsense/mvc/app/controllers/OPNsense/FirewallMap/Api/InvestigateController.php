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

/**
 * On-demand registry, routing and reputation lookups for one public IPv4 or IPv6 address.
 * Administrators only (see ACL): the lookups send the address to RDAP, RIPEstat and AbuseIPDB.
 */
class InvestigateController extends ApiControllerBase
{
    /**
     * POST only: a lookup spends third-party quota (the AbuseIPDB key) and stores a verdict, so it
     * must not be started by a link (OPNsense checks the CSRF token on POST).
     */
    public function addressAction($address = null)
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed', 'error' => 'POST required'];
        }
        if (!is_string($address) || filter_var($address, FILTER_VALIDATE_IP) === false) {
            return ['status' => 'failed', 'error' => 'not an IP address'];
        }
        // "abuseipdb" for the Reputation card's check; anything else looks up every source
        $sources = $this->request->getPost('sources') === 'abuseipdb' ? 'abuseipdb' : 'all';
        $result = json_decode((new Backend())->configdpRun('firewallmap investigate', [$address, $sources]) ?? '', true);
        return is_array($result) ? $result : ['status' => 'failed', 'error' => 'no response'];
    }
}
