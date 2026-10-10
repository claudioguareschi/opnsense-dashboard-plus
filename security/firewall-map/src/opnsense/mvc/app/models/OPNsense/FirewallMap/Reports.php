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

namespace OPNsense\FirewallMap;

use OPNsense\Core\Backend;

/**
 * The two configd reports the settings model reads: the PF tables (threat list and classification
 * set candidates, the curated feeds) and the ranking profiles (the built-ins). Each is asked for at
 * most once per request; a controller warms both before it takes the config lock, so validation
 * under the lock never waits on configd (a Python start and pfctl every time).
 */
class Reports
{
    private static $tables = null;
    private static $profiles = null;

    /** Ask for both now (call before Config::lock()). */
    public static function warm(): void
    {
        self::tables();
        self::profiles();
    }

    /** `firewallmap tables`: {"tables": [...], "automatic": [...], "sets": [...]} */
    public static function tables(): array
    {
        if (self::$tables === null) {
            $report = json_decode((string)(new Backend())->configdRun('firewallmap tables'), true);
            self::$tables = is_array($report) ? $report : [];
        }
        return self::$tables;
    }

    /** `firewallmap profiles`: {"profiles": [...]} */
    public static function profiles(): array
    {
        if (self::$profiles === null) {
            $report = json_decode((string)(new Backend())->configdRun('firewallmap profiles'), true);
            self::$profiles = is_array($report) ? $report : [];
        }
        return self::$profiles;
    }
}
