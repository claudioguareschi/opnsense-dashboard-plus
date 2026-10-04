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
use OPNsense\Firewall\Alias;

/**
 * "Maintain blocklist aliases": one FWMAP_* alias per chosen curated feed (a daily URL table)
 * and FWMAP_AbuseIPDB (an external alias filled by firewallmap_abuseipdb.py). No rules are made.
 * Only aliases this plugin created are changed or removed, and never while something uses them.
 */
class BlocklistAliases
{
    public const ABUSE = 'FWMAP_AbuseIPDB';
    public const ABUSE_DESCRIPTION = 'Firewall Map+ AbuseIPDB blacklist (100% confidence; no rules added)';
    public const FEED_PREFIX = 'Firewall Map+ threat feed: ';

    /** Curated feeds as the collector lists them: [name => [url, label]] */
    private static function feeds(): array
    {
        $report = json_decode((string)(new Backend())->configdRun('firewallmap tables'), true);
        $feeds = [];
        foreach ($report['tables'] ?? [] as $table) {
            if (!empty($table['curated']) && !empty($table['url'])) {
                $feeds[$table['name']] = ['url' => $table['url'], 'label' => $table['label'] ?? $table['name']];
            }
        }
        return $feeds;
    }

    private static function ours($alias): bool
    {
        $description = (string)$alias->description;
        return ((string)$alias->type === 'urltable' && strpos($description, self::FEED_PREFIX) === 0) ||
            ((string)$alias->type === 'external' && $description === self::ABUSE_DESCRIPTION);
    }

    /**
     * Bring the aliases in line with the settings. $threatLists empty means automatic: existing
     * feed aliases are kept, none are added. Returns [alias model, changes ("added FWMAP_x",
     * "removed FWMAP_y"), error].
     */
    public static function reconcile(bool $enabled, string $threatLists, bool $abuseKey): array
    {
        $model = new Alias();
        $feeds = self::feeds();
        $chosen = array_filter(array_map('trim', explode(',', $threatLists)));
        $existing = [];
        foreach ($model->aliases->alias->iterateItems() as $uuid => $alias) {
            $existing[(string)$alias->name] = [$uuid, $alias];
        }
        $wanted = [];
        if ($enabled) {
            foreach ($feeds as $name => $feed) {
                if (in_array($name, $chosen, true) || (empty($chosen) && isset($existing[$name]))) {
                    $wanted[$name] = [
                        'enabled' => '1', 'name' => $name, 'type' => 'urltable', 'content' => $feed['url'],
                        'updatefreq' => '1', 'description' => self::FEED_PREFIX . $feed['label'],
                    ];
                }
            }
            if ($abuseKey) {
                $wanted[self::ABUSE] = [
                    'enabled' => '1', 'name' => self::ABUSE, 'type' => 'external',
                    'description' => self::ABUSE_DESCRIPTION,
                ];
            }
        }
        $changes = [];
        foreach ($wanted as $name => $nodes) {
            if (!isset($existing[$name])) {
                $model->aliases->alias->add()->setNodes($nodes);
                $changes[] = "added {$name}";
            } elseif ($name === self::ABUSE && !self::ours($existing[$name][1])) {
                return [$model, [], sprintf(
                    gettext('An alias named %s already exists and was not created by Firewall Map+.'),
                    $name
                )];
            }
        }
        $inUse = [];
        foreach ($existing as $name => [$uuid, $alias]) {
            if (isset($wanted[$name]) || !self::ours($alias)) {
                continue;
            }
            if (!empty($model->whereUsed($name))) {
                $inUse[] = $name;
                continue;
            }
            $model->aliases->alias->del($uuid);
            $changes[] = "removed {$name}";
        }
        if (!empty($inUse)) {
            return [$model, [], sprintf(
                gettext('Used in firewall rules or other aliases, remove them there first: %s.'),
                implode(', ', $inUse)
            )];
        }
        $messages = [];
        foreach ($model->performValidation() as $message) {
            $messages[] = $message->getMessage();
        }
        return [$model, $changes, empty($messages) ? null : implode(' ', $messages)];
    }

    /** Load changed alias definitions into PF without touching rules, then fill the tables. */
    public static function apply(): void
    {
        $backend = new Backend();
        $backend->configdRun('filter reload skip_alias');
        $backend->configdRun('template reload OPNsense/Filter');
        $backend->configdRun('filter refresh_aliases');
        $backend->configdRun('firewallmap abuseipdb sync');
    }
}
