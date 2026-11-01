#!/bin/bash
# Build the Windows PC client (nxus.exe) and drop it in dist/pc/.
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"

NXUS_ROOT=/c/anyWorkspace/nx/Nxus
cd "$NXUS_ROOT/pc/Nxus.Cli"

echo "== cargo build --release =="
cargo build --release 2>&1 | tail -3

mkdir -p "$NXUS_ROOT/dist/pc"
cp target/release/nxus.exe "$NXUS_ROOT/dist/pc/nxus.exe"
if [ -f target/release/NCL.exe ]; then
    cp target/release/NCL.exe "$NXUS_ROOT/dist/pc/NCL.exe"
fi

# The CLI's file-cheat commands look for cheats/<BUILDID>.txt here by default.
mkdir -p "$NXUS_ROOT/dist/pc/cheats"
cat > "$NXUS_ROOT/dist/pc/cheats/README.txt" <<'EOF'
Cheat files for the PC-side cheat engine
========================================

Put Atmosphere cheat files in this folder, named:

    <16-HEX-BUILDID>.txt

The build id must be exactly 16 hexadecimal digits (uppercase is the canonical
form, e.g. 9D4C86E6EF74504A.txt).  `nxus metadata` prints the current title's
build id.  `nxus cheat list`, `nxus cheat on <name>` and `nxus cheat off <name>`
load this file automatically; use `--file <path>` to select another one.

The matching <16-HEX-BUILDID>.backup sidecar is written here before a patch is
applied, so `nxus cheat off` / `nxus cheat panic-off` can restore the original
bytes even after the PC client was restarted.
EOF

# Keep the convenient local install in sync (the folder the tools use on this PC).
APPS_DIR="C:/apps/nxus"
mkdir -p "$APPS_DIR/cheats"
cp target/release/nxus.exe "$APPS_DIR/nxus.exe"
if [ -f target/release/NCL.exe ]; then
    cp target/release/NCL.exe "$APPS_DIR/NCL.exe"
fi
cp "$NXUS_ROOT/dist/pc/cheats/README.txt" "$APPS_DIR/cheats/README.txt"

echo "== result =="
ls -la "$NXUS_ROOT/dist/pc/nxus.exe"
if [ -f "$NXUS_ROOT/dist/pc/NCL.exe" ]; then
    ls -la "$NXUS_ROOT/dist/pc/NCL.exe"
fi
"$NXUS_ROOT/dist/pc/nxus.exe" --help | head -3
