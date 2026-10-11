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
 * CARP+: this firewall's CARP and pfsync state from carp.sh and carp_history.sh (configd), joined
 * with the configuration (interface names, VIP descriptions, the HA settings) into what the widget
 * shows: the node's role over all its VIPs, each VIP, the peer, state and config sync, and history.
 */
class Carp
{
    private static function lines($text)
    {
        return preg_split('/\r\n|\n|\r/', (string)$text);
    }

    /** Per device: its CARP entries by VHID (state, advbase, advskew) and its VIP addresses by VHID. */
    public static function interfaces($text)
    {
        $result = [];
        $device = null;
        foreach (self::lines($text) as $line) {
            if (preg_match('/^([A-Za-z0-9_.]+): flags=/', $line, $match)) {
                $device = $match[1];
            } elseif ($device === null) {
                continue;
            } elseif (preg_match('/^\s+carp: (\S+) vhid (\d+) advbase (\d+) advskew (\d+)/', $line, $match)) {
                $result[$device]['carp'][(int)$match[2]] = [
                    'state' => strtolower($match[1]), 'advbase' => (int)$match[3], 'advskew' => (int)$match[4],
                ];
            } elseif (preg_match('/^\s+inet (\S+) netmask (0x[0-9a-f]+).*\bvhid (\d+)/i', $line, $match)) {
                $bits = substr_count(decbin(hexdec($match[2])), '1');
                $result[$device]['addresses'][(int)$match[3]][] = "{$match[1]}/{$bits}";
            } elseif (preg_match('/^\s+inet6 (\S+) prefixlen (\d+).*\bvhid (\d+)/', $line, $match)) {
                $result[$device]['addresses'][(int)$match[3]][] = strtok($match[1], '%') . "/{$match[2]}";
            }
        }
        return $result;
    }

    /** sysctl net.inet.carp ("net.inet.carp.preempt: 1") as integers by name. */
    public static function sysctls($text)
    {
        $values = [];
        foreach (self::lines($text) as $line) {
            if (preg_match('/^net\.inet\.carp\.([a-z_]+): (-?\d+)/', $line, $match)) {
                $values[$match[1]] = (int)$match[2];
            }
        }
        return $values;
    }

    /** ifconfig pfsync0: the sync device and peer, and whether the bulk update has completed. */
    public static function pfsync($text)
    {
        $info = null;
        foreach (self::lines($text) as $line) {
            if (preg_match('/^pfsync\d+: flags=\d+<([^>]*)>/', $line, $match)) {
                $info = ['up' => in_array('UP', explode(',', $match[1]), true), 'syncdev' => '', 'peer' => '',
                         'maxupd' => null, 'defer' => null, 'version' => null, 'syncok' => null];
            } elseif ($info === null) {
                continue;
            } elseif (preg_match('/syncdev: (\S+)/', $line, $match)) {
                $info['syncdev'] = $match[1];
                foreach (['syncpeer' => 'peer', 'maxupd' => 'maxupd', 'defer' => 'defer', 'version' => 'version'] as $key => $name) {
                    if (preg_match("/{$key}: (\\S+)/", $line, $value)) {
                        $info[$name] = ctype_digit($value[1]) ? (int)$value[1] : $value[1];
                    }
                }
            } elseif (preg_match('/syncok: (\d+)/', $line, $match)) {
                $info['syncok'] = $match[1] === '1';
            }
        }
        return $info;
    }

    /** The CARP and pfsync counters (netstat -s --libxo json) the widget turns into rates. */
    public static function counters($carpJson, $pfsyncJson)
    {
        $carp = json_decode((string)$carpJson, true)['statistics']['carp'] ?? [];
        $pfsync = json_decode((string)$pfsyncJson, true)['statistics']['pfsync'] ?? [];
        $sum = function (array $values, $pattern) {
            $total = 0;
            foreach ($values as $key => $value) {
                if (is_int($value) && preg_match($pattern, $key)) {
                    $total += $value;
                }
            }
            return $total;
        };
        /* state messages, not framing (end-of-frame and bulk marks) */
        $updates = function ($histogram) {
            $total = 0;
            foreach (is_array($histogram) ? $histogram : [] as $entry) {
                if (is_array($entry) && !in_array($entry['name'] ?? '', ['end-of-frame-mark', 'bulk-update-mark'], true)) {
                    $total += (int)($entry['count'] ?? 0);
                }
            }
            return $total;
        };
        return [
            'carp_received' => $sum($carp, '/^received-/'),
            'carp_sent' => $sum($carp, '/^sent-/'),
            /* advertisements for VHIDs this node does not have (another HA pair on the segment) are routine */
            'carp_errors' => $sum($carp, '/^(dropped-(?!bad-vhid$)|send-failed)/'),
            'pfsync_received' => $sum($pfsync, '/^received-/'),
            'pfsync_sent' => $sum($pfsync, '/^sen[dt]-inet6?-packets$/'),
            'pfsync_updates_in' => $updates($pfsync['input-histogram'] ?? []),
            'pfsync_updates_out' => $updates($pfsync['output-histogram'] ?? []),
            /* damaged or foreign packets and failed sends; updates for states already gone (stale, failed lookup) are routine */
            'pfsync_errors' => $sum($pfsync, '/^(dropped-(bad-interface|bad-ttl|short-header|bad-version|bad-auth|short|bad-values)|send-errors|discarded-no-memory)$/'),
        ];
    }

    /** The logged CARP state changes, newest first. */
    public static function transitions($text)
    {
        $result = [];
        foreach (self::lines($text) as $line) {
            if (preg_match('/^(?:<\d+>\d+ )?(\S+) .*?carp: (\d+)@([^:\s]+): ([A-Z]+) -> ([A-Z]+)(?: \(([^)]*)\))?/', $line, $match)) {
                $time = strtotime($match[1]);
                $result[] = ['time' => $time === false ? null : $time, 'vhid' => (int)$match[2], 'device' => $match[3],
                             'from' => strtolower($match[4]), 'to' => strtolower($match[5]), 'reason' => $match[6] ?? ''];
            }
        }
        return array_reverse($result);
    }

    /**
     * What CARP+ shows. $config: interfaces (identifier => [if, descr]), vips (the CARP entries of
     * virtualip: interface, vhid, descr), hasync (pfsyncinterface, pfsyncpeerip, synchronizetoip),
     * hostname.
     */
    public static function summary($output, $history, array $config, $now)
    {
        $sections = Metrics::sections($output);
        $live = self::interfaces($sections['ifconfig'] ?? '');
        $names = $identifiers = [];
        foreach ($config['interfaces'] ?? [] as $identifier => $interface) {
            if (!empty($interface['if'])) {
                $identifiers[$interface['if']] = $identifier;
                $names[$interface['if']] = !empty($interface['descr']) ? $interface['descr'] : strtoupper($identifier);
            }
        }
        $descriptions = [];
        foreach ($config['vips'] ?? [] as $vip) {
            $descriptions[($vip['interface'] ?? '') . '/' . ($vip['vhid'] ?? '')] = $vip['descr'] ?? '';
        }
        $vips = [];
        $counts = ['master' => 0, 'backup' => 0, 'init' => 0];
        foreach ($live as $device => $info) {
            foreach ($info['carp'] ?? [] as $vhid => $carp) {
                $identifier = $identifiers[$device] ?? $device;
                $vips[] = [
                    'name' => $names[$device] ?? $device, 'identifier' => $identifier, 'device' => $device,
                    'vhid' => $vhid, 'addresses' => $info['addresses'][$vhid] ?? [], 'state' => $carp['state'],
                    'advbase' => $carp['advbase'], 'advskew' => $carp['advskew'],
                    'description' => $descriptions["{$identifier}/{$vhid}"] ?? '',
                ];
                $counts[$carp['state']] = ($counts[$carp['state']] ?? 0) + 1;
            }
        }
        usort($vips, function ($a, $b) {
            return [$a['vhid'], $a['device']] <=> [$b['vhid'], $b['device']];
        });
        $total = count($vips);
        $state = $total === 0 ? 'none'
            : ($counts['master'] && $counts['backup'] ? 'split'
            : ($counts['master'] === $total ? 'master'
            : ($counts['backup'] === $total ? 'backup' : 'init')));
        $sysctls = self::sysctls($sections['sysctl'] ?? '');
        $pfsync = self::pfsync($sections['pfsync'] ?? '');
        $hasync = $config['hasync'] ?? [];
        if ($pfsync !== null) {
            $pfsync['syncdev_name'] = $names[$pfsync['syncdev']] ?? $pfsync['syncdev'];
            if ($pfsync['peer'] === '' && !empty($hasync['pfsyncpeerip'])) {
                $pfsync['peer'] = $hasync['pfsyncpeerip'];
            }
        }
        $transitions = array_map(function ($change) use ($names) {
            return $change + ['name' => $names[$change['device']] ?? $change['device']];
        }, self::transitions($history));
        return [
            'available' => $total > 0,
            'hostname' => $config['hostname'] ?? '',
            'sampled_at' => $now,
            'carp' => [
                'allow' => $sysctls['allow'] ?? null, 'preempt' => $sysctls['preempt'] ?? null,
                'demotion' => $sysctls['demotion'] ?? 0, 'log' => $sysctls['log'] ?? null,
            ],
            'summary' => ['state' => $state, 'total' => $total] + $counts,
            'vips' => $vips,
            'pfsync' => $pfsync,
            'counters' => self::counters($sections['carpstats'] ?? '', $sections['pfsyncstats'] ?? ''),
            'config_sync' => ['target' => (string)($hasync['synchronizetoip'] ?? '')],
            'transitions' => $transitions,
        ];
    }
}
