#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

export DEVKITPRO="${DEVKITPRO:-/opt/devkitpro}"
export DEVKITA64="$DEVKITPRO/devkitA64"
export PATH="$DEVKITA64/bin:$DEVKITPRO/tools/bin:$PATH"

echo "=== NXpotify build ==="
echo "DEVKITPRO  : $DEVKITPRO"
echo "DEVKITA64  : $DEVKITA64"
echo "Compiler   : $(aarch64-none-elf-g++ --version 2>&1 | head -1)"
echo ""

make -j"$(nproc)" 2>&1

if [[ -f nxpotify.nro ]]; then
    echo ""
    echo "=== Build OK ==="
    ls -lh nxpotify.nro
    echo ""
    echo "=== Sending to Switch (nxlink) ==="
    "$DEVKITPRO/tools/bin/nxlink" -a 192.168.31.160 -s nxpotify.nro
else
    echo ""
    echo "=== Build FAILED (nxpotify.nro not found) ===" >&2
    exit 1
fi
