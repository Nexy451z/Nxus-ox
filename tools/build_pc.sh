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

echo "== result =="
ls -la "$NXUS_ROOT/dist/pc/nxus.exe"
"$NXUS_ROOT/dist/pc/nxus.exe" --help | head -3
