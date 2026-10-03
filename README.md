# Dashboard Plus package repository

This repository supplies the stable `os-dashboard-plus` and `os-firewall-map`
packages for OPNsense 26.7 on amd64.  Its catalogue is signed; clients
validate it with the included public key.

## Add the repository

Run as `root` on the OPNsense console or over SSH:

```sh
fetch -qo - https://raw.githubusercontent.com/claudioguareschi/opnsense-dashboard-plus/packages/install.sh | sh
```

Then open **System -> Firmware -> Plugins** and install **os-dashboard-plus**
and/or **os-firewall-map** (Firewall Map+).
