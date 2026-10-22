#!/usr/local/bin/python3

# Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""Ban or unban one address with CrowdSec, for Firewall Map+ (configd, administrators only).

    firewallmap_crowdsec.py ban <address> <duration> [reason]
    firewallmap_crowdsec.py unban <address>

Prints one JSON object: {"status": "ok", ...} or {"status": "failed", "error": ...}. Needs
*Use CrowdSec* and the CrowdSec plugin; the plugin applies the change to its ban tables.
"""

import json
import sys

from lib.common import secure_umask
from lib.config import settings
from lib.crowdsec import CrowdSecError, available, ban, unban


def main(arguments):
    if settings().get("crowdsec", "1") != "1":
        return {"status": "failed", "error": "Use CrowdSec is off"}
    if not available():
        return {"status": "failed", "error": "CrowdSec is not installed"}
    action = arguments[0] if arguments else ""
    try:
        if action == "ban" and len(arguments) >= 3:
            return {"status": "ok", **ban(arguments[1], arguments[2], " ".join(arguments[3:]))}
        if action == "unban" and len(arguments) >= 2:
            return {"status": "ok", **unban(arguments[1])}
    except CrowdSecError as error:
        return {"status": "failed", "error": str(error)}
    return {"status": "failed", "error": "usage: ban <address> <duration> [reason] | unban <address>"}


if __name__ == "__main__":
    secure_umask()
    print(json.dumps(main(sys.argv[1:])))
