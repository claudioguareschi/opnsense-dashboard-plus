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

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

/**
 * Reporting: Firewall Map: Status. The collector is a standard OPNsense service (status, start,
 * stop, restart for the page header's controls), plus the downloads' freshness and "Update now".
 */
class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = 'OPNsense\FirewallMap\FirewallMap';
    protected static $internalServiceName = 'firewallmap';

    /* what each "Update now" downloads again, in the background */
    private const UPDATES = [
        'geodb' => 'firewallmap geodb force',
        'feeds' => 'firewallmap feeds refresh',
        'abuseipdb' => 'firewallmap abuseipdb refresh',
    ];

    /**
     * The collector starts by itself when a map is opened, and keeps running in the background
     * while background recording is on: there is no separate switch to enable it.
     */
    protected function serviceEnabled()
    {
        return true;
    }

    /** The collector, the geolocation database and the threat-list downloads. */
    public function overviewAction()
    {
        $overview = json_decode((new Backend())->configdRun('firewallmap overview'), true);
        return is_array($overview) ? $overview : [];
    }

    /** Download the geolocation database, the threat feeds or the AbuseIPDB blacklist now. */
    public function updateAction($what = null)
    {
        if (!$this->request->isPost() || !isset(self::UPDATES[$what])) {
            return ['result' => 'failed'];
        }
        (new Backend())->configdRun(self::UPDATES[$what], true);
        return ['result' => 'started'];
    }
}
