#!/usr/bin/env bash
# Package the plugin: komari-plugin.json + script.js at the ZIP root (no nesting).
set -euo pipefail
cd "$(dirname "$0")"

version=$(grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]+"' komari-plugin.json | head -1 | sed -E 's/.*"([^"]+)"$/\1/')
out="dist/ufw-sync-${version}.zip"

mkdir -p dist
rm -f "$out"
zip -j "$out" komari-plugin.json script.js >/dev/null
echo "built $out"
unzip -l "$out"
