# Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
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

"""Every Firewall Map endpoint belongs to a privilege, and the widget's privilege stays the widget's.

A static walk of the controllers against ACL.xml: a controller or action added without a pattern
would otherwise be refused to every user but root, or (worse) covered by the wrong privilege.
"""

import fnmatch
import re
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

MVC = Path(__file__).resolve().parents[1] / "src/opnsense/mvc/app"
CONTROLLERS = MVC / "controllers/OPNsense/FirewallMap"
ACL = MVC / "models/OPNsense/FirewallMap/ACL/ACL.xml"
WIDGET = "page-dashboard-widget-firewall-map"
SETTINGS = "page-firewall-map-settings"


def snake(name):
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def privileges():
    return {node.tag: [pattern.text for pattern in node.iter("pattern")] for node in ET.parse(ACL).getroot()}


def endpoints():
    """(path, controller file) for every action the plugin's controllers declare."""
    found = []
    for path in sorted((CONTROLLERS / "Api").glob("*Controller.php")):
        controller = snake(path.stem.removesuffix("Controller"))
        actions = re.findall(r"public function (\w+)Action\(", path.read_text())
        found += [(f"api/firewallmap/{controller}/{snake(action)}", path.name) for action in actions]
        # actions inherited from OPNsense's base controllers (get, set, search_item...) live under
        # the same controller prefix
        found.append((f"api/firewallmap/{controller}/inherited", path.name))
    for path in sorted(CONTROLLERS.glob("*Controller.php")):
        page = snake(path.stem.removesuffix("Controller"))
        found.append(("ui/firewallmap" if page == "index" else f"ui/firewallmap/{page}", path.name))
    return found


class AclTest(unittest.TestCase):
    def test_every_endpoint_has_a_privilege(self):
        patterns = [pattern for group in privileges().values() for pattern in group]
        for endpoint, source in endpoints():
            with self.subTest(endpoint=endpoint, source=source):
                self.assertTrue(any(fnmatch.fnmatchcase(endpoint, pattern) for pattern in patterns))

    def test_the_widget_privilege_reaches_only_the_widget(self):
        """Dashboard users see the map and its snapshots; settings, investigations (which send an
        address to outside services), the review queue, the service and deleting snapshots are the
        settings privilege's."""
        widget, settings = privileges()[WIDGET], privileges()[SETTINGS]
        for endpoint, _ in endpoints():
            covered = any(fnmatch.fnmatchcase(endpoint, pattern) for pattern in widget)
            widget_only = endpoint.startswith(("api/firewallmap/flow/", "api/firewallmap/snapshots/")) \
                or endpoint == "ui/firewallmap"
            with self.subTest(endpoint=endpoint):
                self.assertEqual(covered, widget_only)
                if not widget_only:
                    self.assertTrue(any(fnmatch.fnmatchcase(endpoint, pattern) for pattern in settings))


if __name__ == "__main__":
    unittest.main()
