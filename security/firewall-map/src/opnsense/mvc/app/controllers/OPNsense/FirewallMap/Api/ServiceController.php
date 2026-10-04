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
use OPNsense\Core\Config;
use OPNsense\Core\Syslog;
use OPNsense\FirewallMap\BlocklistAliases;
use OPNsense\FirewallMap\FirewallMap;

/**
 * The collector as a standard OPNsense service (status, start, stop, restart for the page header's
 * controls), Apply for the settings (reconfigure), and the Status page's downloads ("Update now").
 */
class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = 'OPNsense\FirewallMap\FirewallMap';
    protected static $internalServiceName = 'firewallmap';

    /* what each "Update now" downloads again, in the background (not again within minutes of a
     * successful download: see FORCED_REPEAT_SECONDS in the scripts) */
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

    /**
     * Apply the saved settings (the settings page's Apply button). Every step only does what the
     * settings ask for and is not done yet, so applying twice changes nothing: the blocklist aliases
     * (definitions only, never rules), the collector's settings, and the feed, AbuseIPDB and
     * geolocation downloads.
     */
    public function reconfigureAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        $backend = new Backend();
        /* ask configd for the feed tables before taking the config lock, not while holding it */
        $feeds = BlocklistAliases::feeds();
        Config::getInstance()->lock();
        $general = (new FirewallMap())->general;
        [$aliases, $changes, $error] = BlocklistAliases::reconcile(
            (string)$general->blocklist_aliases === '1',
            (string)$general->threat_lists,
            $general->abuseipdb_key->getValue() !== '',
            $feeds
        );
        if ($error === null && $changes) {
            $aliases->serializeToConfig();
            Config::getInstance()->save();
        }
        Config::getInstance()->unlock();
        $log = new Syslog('firewallmap', null, LOG_DAEMON);
        if ($error !== null) {
            $log->warning("settings not applied: {$error}");
            return ['status' => 'failed', 'status_msg' => $error];
        }
        if ($changes) {
            BlocklistAliases::apply();
            $log->notice('blocklist aliases: ' . implode(', ', $changes));
        }
        $log->notice('settings applied');
        /* the scripts read the settings from the file this template renders, never from config.xml */
        $backend->configdRun('template reload OPNsense/FirewallMap');
        /* reload in place: keep live flow and alert history while the chosen list index is rebuilt */
        $backend->configdRun('firewallmap reload');
        $backend->configdRun('firewallmap feeds update', true);
        /* downloads only for a new key, or once a day: the free plan allows only a few a day */
        $backend->configdRun('firewallmap abuseipdb update', true);
        $backend->configdRun('firewallmap abuseipdb sync', true);
        $backend->configdRun('firewallmap ensure', true);
        /* a new key or provider downloads now, not after an earlier failure's wait */
        $backend->configdRun('firewallmap geodb retry', true);
        return ['status' => 'ok'];
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
