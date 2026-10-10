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
 * QuickAssist+: one live sample from `sysctl -i -e dev.qat dev.qat_ocf` (configd action
 * dashboardplus system qat), parsed here. The whole QAT tree costs about 6 ms of CPU to read;
 * no unit discovery is needed because the prefixes name every unit present.
 */
class QuickAssist
{
    /* the crypto(9) algorithms the qat_ocf driver offers (system_info.py QAT_OCF_ALGORITHMS) */
    const OCF_ALGORITHMS = [
        'AES-CBC', 'AES-CTR', 'AES-XTS', 'AES-GCM', 'AES-GMAC', 'SHA-1', 'SHA-2 256/384/512',
        'HMAC-SHA-1', 'HMAC-SHA-2 256/384/512',
    ];

    /* Device_Capabilities_Mask bits (system_info.py QAT_CAPABILITY_BITS) */
    const CAPABILITY_BITS = [
        0 => 'symmetric cryptography', 1 => 'asymmetric cryptography', 2 => 'cipher', 3 => 'authentication',
        5 => 'compression', 7 => 'random number generation', 8 => 'ZUC', 9 => 'SHA-3', 10 => 'key protection',
        12 => 'HKDF', 13 => 'Edwards/Montgomery curves', 15 => 'extended SHA-3', 16 => 'AES-GCM single-pass',
        17 => 'ChaCha20-Poly1305', 18 => 'SM2', 19 => 'SM3', 20 => 'SM4', 21 => 'inline processing',
        22 => 'compression integrity', 23 => '64-bit compression integrity', 24 => 'LZ4 compression',
        25 => 'LZ4S compression', 26 => 'AES v2',
    ];

    /**
     * The per-unit QAT and qat_ocf OIDs and their values. Some values are small reports that span
     * lines (the firmware counters, dev_cfg): every line after an OID's header belongs to it until
     * the next OID, of any kind (the tree also holds driver-level ones such as dev.qat.%parent,
     * which are not kept). NULs, which some driver versions print, are dropped.
     */
    public static function values($output)
    {
        $values = [];
        $current = null;
        foreach (preg_split('/\r\n|[\n\r\x0b\x0c\x1c\x1d\x1e]/', str_replace("\0", '', (string)$output)) as $line) {
            if (preg_match('/^(dev\.[^=\s]+)=(.*)$/', $line, $match)) {
                $current = preg_match('/^dev\.(?:qat|qat_ocf)\.\d+\./', $match[1]) ? $match[1] : null;
                if ($current !== null) {
                    $values[$current] = trim($match[2]);
                }
            } elseif ($current !== null) {
                $values[$current] .= "\n" . $line;
            }
        }
        return $values;
    }

    /** Complete AE request/response records of one firmware counter report. */
    public static function counters($report)
    {
        $text = str_replace("\0", '', (string)$report);
        $counters = [];
        preg_match_all('/^\s*AE\s+(\d+)\b/im', $text, $records, PREG_SET_ORDER | PREG_OFFSET_CAPTURE);
        foreach ($records as $index => $record) {
            $start = $record[0][1] + strlen($record[0][0]);
            $end = isset($records[$index + 1]) ? $records[$index + 1][0][1] : strlen($text);
            $body = substr($text, $start, $end - $start);
            if (
                preg_match('/^\s*Firmware\s+Responses\s*:\s*(\d+)\s*$/im', $body, $responses) &&
                preg_match('/^\s*Firmware\s+Requests\s*:\s*(\d+)\s*$/im', $body, $requests)
            ) {
                $counters[] = ['ae' => (int)$record[1][0], 'responses' => (int)$responses[1],
                               'requests' => (int)$requests[1]];
            }
        }
        return $counters;
    }

    /** The capabilities named by a dev_cfg report's Device_Capabilities_Mask. */
    public static function capabilities($config)
    {
        if (!preg_match('/^Device_Capabilities_Mask\s*=\s*(0x[0-9a-fA-F]+|\d+)/m', (string)$config, $match)) {
            return [];
        }
        $mask = intval($match[1], 0);
        $labels = [];
        foreach (self::CAPABILITY_BITS as $bit => $label) {
            if ($mask & (1 << $bit)) {
                $labels[] = $label;
            }
        }
        return $labels;
    }

    private static function integer($value)
    {
        $number = filter_var(trim((string)$value), FILTER_VALIDATE_INT);
        return $number === false || $value === null ? null : $number;
    }

    /** The sample QuickAssist+ draws: devices with health and counters, and the kernel crypto state. */
    public static function sample($output, $now)
    {
        $values = self::values($output);
        $units = ['qat' => [], 'qat_ocf' => []];
        foreach (array_keys($values) as $key) {
            if (preg_match('/^dev\.(qat|qat_ocf)\.(\d+)\./', $key, $match)) {
                $units[$match[1]][$match[2]] = true;
            }
        }
        foreach ($units as &$list) {
            $list = array_map('strval', array_keys($list));
            sort($list, SORT_NUMERIC);
        }
        unset($list);

        $devices = [];
        foreach ($units['qat'] as $unit) {
            $prefix = "dev.qat.{$unit}";
            $counters = self::counters($values["{$prefix}.fw_counters"] ?? '');
            $devices[] = [
                'unit' => $unit,
                'description' => mb_substr($values["{$prefix}.%desc"] ?? '', 0, 200),
                'frequency_hz' => self::integer($values["{$prefix}.frequency"] ?? null) ?: 0,
                'services' => mb_substr($values["{$prefix}.cfg_services"] ?? '', 0, 100),
                'capabilities' => self::capabilities($values["{$prefix}.dev_cfg"] ?? ''),
                'state' => mb_substr($values["{$prefix}.state"] ?? '', 0, 100),
                'heartbeat' => self::integer($values["{$prefix}.heartbeat"] ?? null),
                'heartbeat_failed' => self::integer($values["{$prefix}.heartbeat_failed"] ?? null) ?: 0,
                'ae_count' => count($counters),
                'counters_available' => array_key_exists("{$prefix}.fw_counters", $values),
                'requests' => array_sum(array_column($counters, 'requests')),
                'responses' => array_sum(array_column($counters, 'responses')),
            ];
        }
        $enabled = false;
        foreach ($units['qat_ocf'] as $unit) {
            $enabled = $enabled || self::integer($values["dev.qat_ocf.{$unit}.enable"] ?? null) === 1;
        }
        /* the algorithms only while a symmetric-crypto device is up to serve them */
        $serving = false;
        foreach ($devices as $device) {
            $serving = $serving || (strtolower($device['state']) === 'up' &&
                in_array('sym', explode(';', strtolower($device['services'])), true));
        }
        return [
            'available' => !empty($devices),
            'sampled_at' => $now,
            'devices' => $devices,
            'ocf' => ['present' => !empty($units['qat_ocf']), 'enabled' => $enabled,
                      'algorithms' => $enabled && $serving ? self::OCF_ALGORITHMS : []],
        ];
    }
}
