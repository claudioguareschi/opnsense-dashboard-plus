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

class FlowController extends ApiControllerBase
{
    /**
     * Return the latest capped, geo-enriched flow summary from the collector.
     *
     * The collector samples PF counters every second in the background; this
     * request only reads its output, so dashboard polling never walks the
     * state table or performs GeoIP lookups.
     */
    public function snapshotAction()
    {
        $backend = new Backend();
        /* reverse DNS only runs while a viewer who enabled it is polling */
        $mode = $this->request->get('hostnames') === '1' ? 'hostnames' : 'plain';
        /* per-viewer threshold: blocked sources need this many hits before they are drawn */
        $minimum = max(1, min(100, (int)($this->request->get('blocks_min') ?? 1)));
        $result = json_decode($backend->configdpRun('firewallmap flow snapshot', [$mode, (string)$minimum]) ?? '', true);

        return is_array($result) ? $result : ['status' => 'failed', 'flows' => []];
    }
}
