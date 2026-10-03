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

function firewallmap_cron()
{
    /* the updater only downloads when the database is older than the configured age */
    return [
        ['autocron' => ['/usr/local/sbin/configctl -d firewallmap geodb update', '17', '4']],
        /* at most once a day; skipped without an AbuseIPDB key */
        ['autocron' => ['/usr/local/sbin/configctl -d firewallmap abuseipdb update', '43', '4']],
        /* the curated feeds in use, at most once a day */
        ['autocron' => ['/usr/local/sbin/configctl -d firewallmap feeds update', '51', '4']],
        /* keeps threat history fed after a reboot; a no-op unless the widget is in use */
        ['autocron' => ['/usr/local/sbin/configctl -d firewallmap ensure', '*/10']],
    ];
}

function firewallmap_xmlrpc_sync()
{
    /*
     * System > High Availability: the plugin settings, including the MaxMind and AbuseIPDB
     * keys, copy to the peer like any other service. Threat history, caches and downloaded
     * databases stay local to each firewall.
     */
    return [[
        'description' => gettext('Firewall Map+'),
        'id' => 'firewallmap',
        'section' => 'OPNsense.FirewallMap',
    ]];
}
