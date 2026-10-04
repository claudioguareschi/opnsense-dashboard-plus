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
 * Arguments the API passes to the plugin's configd actions. configd splits on spaces and reads
 * one 4 kB message, so free text travels as base64url (only [A-Za-z0-9_-] reach configd) and is
 * cut to a byte budget on a character boundary.
 */
class ConfigdArgument
{
    /** A saved snapshot's id (firewallmap_snapshots.py, ID_PATTERN). */
    public const SNAPSHOT_ID = '/^\d{8}T\d{6}Z-[0-9a-f]{4}$/';

    /** `$text`, trimmed and cut to `$bytes` bytes, as base64url; `$empty` when there is none. */
    public static function text($text, $bytes, $empty = '-')
    {
        $text = mb_strcut(trim((string)$text), 0, $bytes, 'UTF-8');
        return $text === '' ? $empty : rtrim(strtr(base64_encode($text), '+/', '-_'), '=');
    }

    public static function isSnapshotId($id)
    {
        return is_string($id) && preg_match(self::SNAPSHOT_ID, $id) === 1;
    }
}
