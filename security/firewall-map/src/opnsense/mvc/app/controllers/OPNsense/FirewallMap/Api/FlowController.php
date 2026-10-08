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
use OPNsense\FirewallMap\FlowSummary;

class FlowController extends ApiControllerBase
{
    /**
     * Return the latest capped, geo-enriched flow summary from the collector.
     *
     * The collector samples PF counters every 2 seconds in the background; this
     * request only reads its output (through configd: the file is root's), so
     * dashboard polling never walks the state table or performs GeoIP lookups.
     */
    public function summaryAction()
    {
        $backend = new Backend();
        /* reverse DNS only runs while a viewer who enabled it is polling */
        $hostnames = $this->request->get('hostnames') === '1';
        /* per-viewer threshold: blocked sources need this many hits before they are drawn */
        $minimum = max(1, min(100, (int)($this->request->get('blocks_min') ?? 1)));
        /* per-viewer Focus: one of the profiles the collector selected for (default when absent) */
        $focus = $this->request->get('focus');
        $focus = is_string($focus) && preg_match('/^[a-z0-9_-]{1,32}$/', $focus) ? $focus : null;
        $output = $backend->configdpRun('firewallmap flow summary', [$hostnames ? 'hostnames' : 'plain']);

        return FlowSummary::fromBackend($output, $hostnames, $minimum, null, $focus);
    }
}
