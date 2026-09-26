# Dashboard Plus for OPNsense

Two community plugins for [OPNsense](https://opnsense.org) 26.7, published as signed packages:

| Package | What it adds |
|---|---|
| **os-dashboard-plus** | Enhanced dashboard widgets: System Information+, Traffic Graph+, System Metrics+, Thermal Sensors+, Interface Statistics+, Gateways+, Interfaces+ and Firewall Logs+. |
| **os-firewall-map** (Firewall Map+) | The firewall's live traffic on a world map, as a dashboard widget and a full-size page (*Firewall Map* link in the widget), with threat flagging and a review queue. |

These are not official OPNsense plugins. They do not modify the OPNsense core.

## Install

As `root` on the OPNsense console or over SSH:

```sh
fetch -qo - https://raw.githubusercontent.com/claudioguareschi/opnsense-dashboard-plus/packages/install.sh | sh
```

This adds the package repository (`/usr/local/etc/pkg/repos/dashboard-plus.conf`) and its public
signing key. Then install from **System ▸ Firmware ▸ Plugins** (`os-dashboard-plus`,
`os-firewall-map`), or with `pkg install os-firewall-map`. Updates arrive with normal firmware
updates. The repository contains only these two packages.

To remove it: uninstall the plugins, then delete `/usr/local/etc/pkg/repos/dashboard-plus.conf`
and `/usr/local/etc/pkg/keys/dashboard-plus-repository.pub`.

## Firewall Map+

- **Live flows**: arcs from the firewall to every remote endpoint, built from PF state counters
  sampled every 2 seconds. Colour shows who opened the connection (green: inside, orange:
  outside); pulses show which way the data flows. Arcs fade in and out.
- **Blocked attempts**: connection attempts dropped by the firewall (from the filter log) pulse
  in red, with a configurable minimum number of hits.
- **Plain-language details**: hover or click any arc or endpoint, e.g. *"This firewall queried
  DNS (53/udp) at a.ns.example (Example Networks, The Netherlands)"* or *"203.0.113.9 (…) reached
  mail (192.168.1.2) on HTTPS (443/tcp) through a port forward"*, led by whether the traffic was
  allowed or blocked.
- **Full-size page**: filters by traffic type, service, interface, inside host, country and
  network; colour by who connected, data direction, egress or service; top talkers.
- **Threats**: addresses in threat-list aliases (Spamhaus DROP, abuse.ch Feodo, Emerging Threats,
  FireHOL level 1 can be added in one click, or any URL-table alias of your own), the daily
  AbuseIPDB blacklist, cached AbuseIPDB verdicts of 75% or more, and a local watchlist
  (*Mark as threat*) are flagged in red.
- **Review queue** (administrators): every permitted connection to or from a flagged address is
  recorded with who it belongs to, what it reached and when, and can be investigated, annotated
  and marked reviewed, dismissed or blocked (added to an alias of your choice).
- **Investigate** (administrators, per click): registry (RDAP), routing (RIPEstat) and, with a
  key, AbuseIPDB reputation for one address; plus show or kill its states, add it to an alias, or
  add its country to a GeoIP alias.

Threat lists only mark traffic on the map. **No firewall rule is added or changed** unless you use
an alias in a rule yourself.

### Settings

Per-user display settings are in the widget's settings dialog. Administrators also see the
firewall-wide settings there: geolocation service, MaxMind license key, update frequency,
AbuseIPDB API key and threat lists. Keys are write-only and never shown or logged.

### What leaves the firewall

| When | Where | What is sent |
|---|---|---|
| Geolocation database update (every few days) | MaxMind or DB-IP | Your MaxMind key (MaxMind only). Lookups themselves are local. |
| Daily, with an AbuseIPDB key | AbuseIPDB | Your key, to download the blacklist. |
| Threat-list aliases (daily, OPNsense's alias updater) | The list provider | Nothing but the download request. |
| *Investigate* clicked | rdap.org, stat.ripe.net, AbuseIPDB | The one address being investigated. |
| *Lookup hostnames* enabled | Your DNS resolver | Reverse lookups of remote addresses. |

The collector runs only while a map is open, or in the background (a slow sample every 20 s)
while the widget is on a dashboard and threat recording is on.

## Dashboard Plus

Adds eight widgets to the dashboard's widget list, next to the built-in ones: System
Information+ (platform, firmware, CPU security and crypto capabilities, accelerators,
mitigations, time and DNS), Traffic Graph+, System Metrics+, Thermal Sensors+, Interface
Statistics+, Gateways+, Interfaces+ and Firewall Logs+. Everything is read locally.

## Building from source

On an OPNsense machine of the target release (git is required):

```sh
git clone https://github.com/claudioguareschi/opnsense-dashboard-plus.git
cd opnsense-dashboard-plus
./build.sh                       # both plugins; packages in ./dist
DEVEL=1 ./build.sh security/firewall-map   # a development package
pkg add -f dist/os-firewall-map-devel-*.pkg
```

`build.sh` fetches the [opnsense/plugins](https://github.com/opnsense/plugins) build framework
for the running release and builds each plugin in it unchanged, so the plugin folders can also be
copied into a fork of opnsense/plugins as they are.

Firewall Map+'s map renderer (`security/firewall-map/renderer`) is built separately with Vite; the
built bundle is committed. See `renderer/package.json`.

### Publishing (maintainer)

The signed feed lives in the `packages` branch. On the machine holding the signing key:

```sh
./build.sh
./publish.sh /path/to/packages-branch-checkout
```

then commit and push that checkout. Every package of the feed must be in the folder when it is
signed; `publish.sh` replaces older versions and signs the whole catalogue.

## Licence

BSD 2-Clause, see [LICENSE](LICENSE). Firewall Map+ bundles deck.gl and luma.gl (MIT) and Natural
Earth data (public domain); DB-IP Lite data is CC BY 4.0; MaxMind GeoLite2 is subject to MaxMind's
EULA. See [THIRD_PARTY_NOTICES](security/firewall-map/THIRD_PARTY_NOTICES).
