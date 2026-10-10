#!/usr/local/bin/php
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

/*
 * Interfaces+: the assigned interfaces with their link status, media and primary addresses.
 *
 * OPNsense's interfaces overview reads `ifconfig -Lmv`, whose -v reads every SFP module over its
 * I2C bus (about 200 ms of CPU per module) and does so twice per refresh; the widget shows none of
 * that. This reads `ifconfig -L` once, keeps what the widget shows, and leaves the choice of the
 * primary addresses to OPNsense's own functions (CARP and alias addresses, ULA order, prefix-only
 * IPv6 and lifetimes as everywhere else).
 */

/** The subset of legacy_interfaces_details() the primary address functions and the widget use. */
function dashboardplus_ifconfig_details(array $lines)
{
    $result = [];
    $current = null;

    foreach ($lines as $line) {
        $parts = explode(' ', $line);
        if ($line !== '' && $line[0] != "\t" && strpos($line, 'flags=') !== false) {
            $current = explode(':', $line)[0];
            $result[$current] = ['device' => $current, 'flags' => [], 'ipv4' => [], 'ipv6' => []];
            if (preg_match('/<(.*)>.*$/', $line, $matches)) {
                $result[$current]['flags'] = explode(',', strtolower($matches[1]));
            }
        } elseif ($current === null) {
            continue;
        } elseif (strpos($line, "\tether ") === 0) {
            $result[$current]['macaddr'] = $parts[1] ?? '';
        } elseif (strpos($line, "\tinet ") !== false) {
            $address = ['ipaddr' => $parts[1], 'tunnel' => false];
            for ($i = 0; $i < count($parts); ++$i) {
                if ($parts[$i] == 'netmask' && isset($parts[$i + 1])) {
                    $address['subnetbits'] = substr_count(base_convert(hexdec($parts[++$i]), 10, 2), '1');
                } elseif ($parts[$i] == 'vhid' && isset($parts[$i + 1])) {
                    $address['vhid'] = $parts[++$i];
                }
            }
            if (($parts[2] ?? '') == '-->') {
                $address['tunnel'] = true;
                $address['endpoint'] = $parts[3] ?? '';
            }
            if (isset($address['subnetbits'])) {
                $result[$current]['ipv4'][] = $address;
            }
        } elseif (strpos($line, "\tinet6 ") !== false) {
            $ip = strtok($parts[1], '%');
            $address = [
                'autoconf' => false, 'deprecated' => false, 'detached' => false, 'ipaddr' => $ip,
                'link-local' => !!preg_match('/^fe[89ab][0-9a-f]:/i', $ip), 'pltime' => '0',
                'tentative' => false, 'tunnel' => false, 'vltime' => '0',
            ];
            for ($i = 0; $i < count($parts); ++$i) {
                if ($parts[$i] == 'prefixlen' && isset($parts[$i + 1])) {
                    $address['subnetbits'] = intval($parts[++$i]);
                } elseif ($parts[$i] == 'vhid' && isset($parts[$i + 1])) {
                    $address['vhid'] = $parts[++$i];
                } elseif ($parts[$i] == '-->' && isset($parts[$i + 1])) {
                    $address['endpoint'] = $parts[++$i];
                    $address['tunnel'] = true;
                } elseif (in_array($parts[$i], ['autoconf', 'deprecated', 'detached', 'tentative'])) {
                    $address[$parts[$i]] = true;
                } elseif (in_array($parts[$i], ['pltime', 'vltime']) && isset($parts[$i + 1])) {
                    $address[$parts[$i]] = $parts[++$i];
                }
            }
            if (isset($address['subnetbits'])) {
                $result[$current]['ipv6'][] = $address;
                /* link-local last, the rest in kernel order (the primary address on top) */
                usort($result[$current]['ipv6'], function ($a, $b) {
                    return $a['link-local'] - $b['link-local'];
                });
            }
        } elseif (preg_match('/media: (.*)/', $line, $matches)) {
            /* the link part when there is one, as the interfaces overview shows it */
            $result[$current]['media'] = $matches[1];
            if (preg_match('/media: .*? \((.*?)\)/', $line, $matches)) {
                $result[$current]['media'] = $matches[1];
            }
        } elseif (preg_match('/status: (.*)$/', $line, $matches)) {
            $result[$current]['status'] = $matches[1];
        }
    }

    return $result;
}

/**
 * One row per assigned interface present on the system, in configuration order, with the fields
 * the interfaces overview gives them; $primary4 and $primary6 return OPNsense's primary address
 * tuples (address, network, bits, device) for an interface identifier.
 */
function dashboardplus_interface_rows(array $interfaces, array $details, callable $primary4, callable $primary6)
{
    $rows = [];

    foreach ($interfaces as $identifier => $config) {
        $device = is_array($config) ? (string)($config['if'] ?? '') : '';
        if ($device === '' || empty($details[$device])) {
            continue;
        }
        $info = $details[$device];
        $status = in_array('up', $info['flags']) ? 'up' : 'down';
        if (!empty($info['status']) && !in_array($info['status'], ['active', 'running'])) {
            /* the current ifconfig status, such as "no carrier" */
            $status = $info['status'];
        }
        $row = [
            'identifier' => $identifier,
            'description' => !empty($config['descr']) ? $config['descr'] : strtoupper($identifier),
            'device' => $device,
            'enabled' => !empty($config['enable']),
            'virtual' => !empty($config['virtual']),
            'status' => $status,
            'media' => $info['media'] ?? '',
            'macaddr' => $info['macaddr'] ?? '',
        ];
        foreach (['addr4' => $primary4, 'addr6' => $primary6] as $key => $primary) {
            $address = $primary($identifier);
            $row[$key] = !empty($address[0]) ? "{$address[0]}/{$address[2]}" : '';
        }
        $rows[] = $row;
    }

    return $rows;
}

if (PHP_SAPI === 'cli' && realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    require_once 'config.inc';
    require_once 'util.inc';
    require_once 'interfaces.inc';

    exec('/sbin/ifconfig -L 2> /dev/null', $lines);
    $details = dashboardplus_ifconfig_details($lines);
    $rows = dashboardplus_interface_rows(
        $config['interfaces'] ?? [],
        $details,
        function ($identifier) use ($details) {
            return interfaces_primary_address($identifier, $details);
        },
        function ($identifier) use ($details) {
            return interfaces_primary_address6($identifier, $details);
        }
    );
    echo json_encode(['rows' => $rows]) . PHP_EOL;
}
