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
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
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

namespace OPNsense\DashboardPlus\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class DnsController extends ApiControllerBase
{
    /**
     * Return a small, privacy-preserving view of the recent Unbound statistics.
     *
     * The native details endpoint contains the client address and other diagnostic fields. DNS
     * Health+ only needs query type distribution and recent externally resolved domains, so do
     * not expose the raw records under the Dashboard privilege.
     */
    public function recentAction()
    {
        $records = json_decode((new Backend())->configdpRun('unbound qstats details', [100]), true);
        if (!is_array($records)) {
            return ['queries' => [], 'types' => []];
        }

        $queries = [];
        $types = [];
        $now = time();
        foreach ($records as $record) {
            if (!is_array($record)) {
                continue;
            }

            $type = strtoupper((string)($record['type'] ?? ''));
            if (!preg_match('/^[A-Z0-9]{1,12}$/', $type)) {
                $type = 'OTHER';
            }
            $types[$type] = ($types[$type] ?? 0) + 1;

            // Unbound calls both a recursive lookup and a forward-zone lookup "Recursion".
            // Local answers and cache hits never leave the resolver and are not activity here.
            if (($record['source'] ?? '') !== 'Recursion' || count($queries) >= 25) {
                continue;
            }
            $domain = rtrim((string)($record['domain'] ?? ''), '.');
            if ($domain === '') {
                continue;
            }
            $timestamp = filter_var($record['time'] ?? null, FILTER_VALIDATE_INT);
            $lookup = filter_var($record['resolve_time_ms'] ?? null, FILTER_VALIDATE_INT);
            $rcode = strtoupper((string)($record['rcode'] ?? ''));
            if (!preg_match('/^[A-Z_]{1,16}$/', $rcode)) {
                $rcode = '';
            }
            $queries[] = [
                'domain' => $domain,
                'type' => $type,
                'age' => $timestamp === false ? null : max(0, $now - $timestamp),
                'lookup_ms' => $lookup === false ? null : $lookup,
                'rcode' => $rcode,
            ];
        }

        arsort($types);
        return ['queries' => $queries, 'types' => $types];
    }
}
