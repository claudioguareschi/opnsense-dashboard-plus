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

/**
 * The map's poll as the browser receives it, from what flow_summary.sh printed: the collector's
 * summary as {"modified": <its mtime>, "summary": ...}, or flow_summary.py's document as
 * {"summary": ...}. The viewer's settings are applied here, so the shell script only prints a file.
 */
class FlowSummary
{
    /**
     * @param string|null $output what configd returned
     * @param bool $hostnames the viewer shows host names (reverse DNS)
     * @param int $minimum blocked sources need this many hits before they are drawn
     * @param float|null $now the current time (epoch seconds), for the summary's age
     * @param string|null $focus the viewer's Focus (a profile key); null: the configured default
     */
    public static function fromBackend($output, $hostnames, $minimum, $now = null, $focus = null)
    {
        $result = json_decode($output ?? '', true);
        if (!is_array($result) || !isset($result['summary']) || !is_array($result['summary'])) {
            return ['status' => 'failed', 'flows' => []];
        }
        $summary = $result['summary'];
        if (isset($result['modified'])) {
            /* flow_summary.py gives its document an age; the file the shell printed gets one here */
            $summary['age'] = self::age($summary, $result['modified'], $now ?? microtime(true));
        }
        if (!$hostnames) {
            unset($summary['hostnames']);
        }
        return self::applyBlockThreshold(self::applyFocus($summary, $focus), $minimum);
    }

    /**
     * The collector writes every enabled profile's selection as positions in its flows (their
     * union); a viewer receives only the flows of its Focus, in that profile's order. An unknown
     * Focus falls back to the default.
     */
    public static function applyFocus(array $summary, $focus)
    {
        if (!isset($summary['focus']) || !is_array($summary['focus']) || !isset($summary['flows'])) {
            return $summary;
        }
        $key = is_string($focus) && isset($summary['focus'][$focus]) ? $focus : ($summary['focus_default'] ?? null);
        $positions = isset($summary['focus'][$key]) && is_array($summary['focus'][$key]) ? $summary['focus'][$key] : [];
        $flows = [];
        foreach ($positions as $position) {
            if (is_int($position) && isset($summary['flows'][$position])) {
                $flows[] = $summary['flows'][$position];
            }
        }
        $summary['flows'] = $flows;
        $summary['focus'] = $key;
        unset($summary['focus_default']);
        return $summary;
    }

    /**
     * Seconds since the collector wrote the summary, to a tenth: from the file's mtime (whole
     * seconds, from the shell), or the summary's own time stamp when that is later (taken just
     * before the file is written, to the microsecond).
     */
    public static function age(array $summary, $modified, $now)
    {
        $written = (float)$modified;
        if (is_string($summary['sampled_at'] ?? null)) {
            try {
                $written = max($written, (float)(new \DateTime($summary['sampled_at']))->format('U.u'));
            } catch (\Exception $e) {
                /* the mtime alone */
            }
        }
        return round(max(0.0, $now - $written), 1);
    }

    /** Keep blocked sources with at least `$minimum` hits in the window; count the rest. */
    public static function applyBlockThreshold(array $summary, $minimum)
    {
        if (!isset($summary['blocks']) || !is_array($summary['blocks'])) {
            return $summary;
        }
        $shown = [];
        foreach ($summary['blocks'] as $block) {
            $hits = is_array($block) && array_key_exists('hits', $block) ? $block['hits'] : 1;
            if ($hits >= $minimum) {
                $shown[] = $block;
            }
        }
        $total = count($summary['blocks']);
        $summary['blocks'] = $shown;
        $summary['blocks_below'] = $total - count($shown);
        return $summary;
    }
}
