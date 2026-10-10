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

namespace OPNsense\DashboardPlus;

/**
 * System Metrics+, Thermal Sensors+ and System Information+: the readings metrics.sh prints, in
 * "@@section" blocks, parsed into what the widgets draw. Memory is computed as OPNsense's own
 * System Resources endpoint computes it, temperatures and filesystems carry the fields of its
 * temperature and disk endpoints, and pf states and mbufs are the numbers its own widgets show.
 */
class Metrics
{
    /** The output split at its "@@name" lines, by name (an "@@time" stamp line is not a section). */
    public static function sections($output)
    {
        $sections = [];
        $current = null;
        foreach (preg_split('/\r\n|\n|\r/', (string)$output) as $line) {
            if (preg_match('/^@@([a-z]+)$/', $line, $match)) {
                $current = $match[1];
                $sections[$current] = [];
            } elseif ($current !== null) {
                $sections[$current][] = $line;
            }
        }
        return array_map(function ($lines) {
            return implode("\n", $lines);
        }, $sections);
    }

    /** sysctl -e output, one "name=value" per line. */
    public static function sysctlValues($output)
    {
        $values = [];
        foreach (preg_split('/\r\n|\n|\r/', (string)$output) as $line) {
            $separator = strpos($line, '=');
            if ($separator === false || $separator === 0) {
                continue;
            }
            $name = substr($line, 0, $separator);
            if (strpos($name, ' ') === false) {
                $values[$name] = trim(substr($line, $separator + 1));
            }
        }
        return $values;
    }

    /** An integer, or null for anything else (a JSON number stays a number). */
    public static function integer($value)
    {
        if (is_int($value)) {
            return $value;
        }
        if (!is_string($value)) {
            return null;
        }
        $number = filter_var(trim($value), FILTER_VALIDATE_INT);
        return $number === false ? null : $number;
    }

    /** Memory in MiB: the share of pages neither inactive, cached nor free, applied to physmem. */
    public static function memory(array $values)
    {
        $physical = self::integer($values['hw.physmem'] ?? null);
        $pages = self::integer($values['vm.stats.vm.v_page_count'] ?? null);
        if (!$physical || !$pages) {
            return null;
        }
        $idle = 0;
        foreach (['vm.stats.vm.v_inactive_count', 'vm.stats.vm.v_cache_count', 'vm.stats.vm.v_free_count'] as $name) {
            $idle += self::integer($values[$name] ?? null) ?? 0;
        }
        $used = round(($pages - $idle) / $pages * $physical);
        $arc = self::integer($values['kstat.zfs.misc.arcstats.size'] ?? null) ?? 0;
        return [
            'total_mib' => (int)($physical / 1024 / 1024),
            'used_mib' => (int)($used / 1024 / 1024),
            'arc_mib' => (int)($arc / 1024 / 1024),
        ];
    }

    /** vm.loadavg ("{ 0.52 0.48 0.45 }") as "0.52, 0.48, 0.45". */
    public static function load($value)
    {
        $value = trim((string)$value, '{} ');
        return $value === '' ? '' : implode(', ', preg_split('/\s+/', $value));
    }

    /** The current and the highest CPU frequency cpufreq reports. */
    public static function cpu($current, $levels)
    {
        preg_match_all('/(?:^|\s)(\d+)(?:\/\d+)?/', (string)$levels, $matches);
        $available = array_map('intval', $matches[1]);
        return [
            'current_mhz' => self::integer($current),
            'maximum_mhz' => $available ? max($available) : null,
        ];
    }

    /** The readings of the known sensors, shaped like OPNsense's temperature endpoint. */
    public static function temperatures(array $oids, array $values)
    {
        $readings = [];
        foreach ($oids as $oid) {
            $temperature = trim(str_replace('C', '', $values[$oid] ?? ''));
            if (!is_numeric($temperature)) {
                continue;
            }
            $readings[] = [
                'device' => $oid,
                'device_seq' => preg_replace('/[^0-9+-]/', '', $oid),
                'temperature' => $temperature,
                'type' => strpos($oid, 'hw.acpi') !== false ? 'zone' : 'cpu',
            ];
        }
        return $readings;
    }

    /** Swap devices from swapinfo -k, sizes in KiB, without the "Total" line of several. */
    public static function swap($output)
    {
        $devices = [];
        foreach (array_slice(preg_split('/\r\n|\n|\r/', (string)$output), 1) as $line) {
            $fields = preg_split('/\s+/', trim($line));
            if (count($fields) < 4 || $fields[0] === 'Total') {
                continue;
            }
            $total = self::integer($fields[1]);
            $used = self::integer($fields[2]);
            if ($total !== null && $used !== null) {
                $devices[] = ['device' => $fields[0], 'total' => $total, 'used' => $used];
            }
        }
        return $devices;
    }

    /** Filesystems from df -hT --libxo json, with the fields of OPNsense's disk endpoint. */
    public static function filesystems($output)
    {
        $data = json_decode((string)$output, true);
        $filesystems = $data['storage-system-information']['filesystem'] ?? null;
        $devices = [];
        foreach (is_array($filesystems) && array_is_list($filesystems) ? $filesystems : [] as $filesystem) {
            if (!is_array($filesystem)) {
                continue;
            }
            $device = [
                'device' => $filesystem['name'] ?? '',
                'type' => $filesystem['type'] ?? '',
                'blocks' => $filesystem['blocks'] ?? ($filesystem['total-blocks'] ?? ''),
                'used' => $filesystem['used'] ?? ($filesystem['used-blocks'] ?? ''),
                'available' => $filesystem['available'] ?? ($filesystem['available-blocks'] ?? ''),
                'used_pct' => $filesystem['used-percent'] ?? '',
                'mountpoint' => $filesystem['mounted-on'] ?? '',
            ];
            /* /tmp on the root filesystem is reported as "/" a second time */
            if (!empty($device['mountpoint']) && !in_array($device, $devices, true)) {
                $devices[] = $device;
            }
        }
        return $devices;
    }

    /** Mbuf clusters in use or cached and their limit, as OPNsense's Mbuf endpoint reports them. */
    public static function mbufs($output)
    {
        $data = json_decode((string)$output, true);
        if (!is_array($data)) {
            return null;
        }
        $statistics = $data['mbuf-statistics'] ?? ($data['statistics']['mbuf-statistics'] ?? null);
        if (!is_array($statistics)) {
            return null;
        }
        $current = self::integer($statistics['cluster-total'] ?? null);
        $limit = self::integer($statistics['cluster-max'] ?? null);
        return $current === null || !$limit ? null : ['current' => $current, 'limit' => $limit];
    }

    /** Everything the widgets draw, or null when the readings are missing (configd failed). */
    public static function parse($output)
    {
        $sections = self::sections($output);
        if (!isset($sections['values'])) {
            return null;
        }
        $values = self::sysctlValues($sections['values']);
        $sensors = array_values(array_filter(array_map('trim', explode("\n", $sections['sensors'] ?? ''))));
        $current = !empty($values['dev.cpu.0.freq']) ? $values['dev.cpu.0.freq'] : ($values['hw.clockrate'] ?? null);
        preg_match('/^\s*current entries\s+(\d+)/m', $sections['pfinfo'] ?? '', $states);
        preg_match('/^\s*states\s+hard limit\s+(\d+)/m', $sections['pfmemory'] ?? '', $limit);
        return [
            'memory' => self::memory($values),
            'load' => self::load($values['vm.loadavg'] ?? ''),
            'cpu' => self::cpu($current, $values['dev.cpu.0.freq_levels'] ?? ''),
            'temperatures' => self::temperatures($sensors, $values),
            'states' => [
                'current' => isset($states[1]) ? (int)$states[1] : null,
                'limit' => isset($limit[1]) ? (int)$limit[1] : null,
            ],
            'mbufs' => self::mbufs($sections['mbufs'] ?? ''),
            'swap' => self::swap($sections['swap'] ?? ''),
            'filesystems' => self::filesystems($sections['filesystems'] ?? ''),
        ];
    }
}
