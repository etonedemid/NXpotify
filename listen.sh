#!/usr/bin/env bash
# Upload nxpotify.nro and stream its stdout via nxlink.
# Switch must be in hbmenu with netloader active.
cd "$(dirname "${BASH_SOURCE[0]}")"
exec /opt/devkitpro/tools/bin/nxlink -a 192.168.31.160 -s nxpotify.nro
