#!/usr/bin/env bash
# Package the plugin. ZIP root must contain komari-plugin.json + script.js;
# the admin page lives at web/index.html (path preserved). The on-node applier
# (agent/ufw-sync.sh) is the single source of truth; its base64 is injected
# into script.js (placeholder __APPLIER_B64__) at build time.
set -euo pipefail
cd "$(dirname "$0")"

version=$(grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]+"' komari-plugin.json | head -1 | sed -E 's/.*"([^"]+)"$/\1/')
out="dist/ufw-sync-${version}.zip"

rm -rf build
mkdir -p dist build/web

b64=$(base64 < agent/ufw-sync.sh | tr -d '\n')
sed "s|__APPLIER_B64__|${b64}|" script.js > build/script.js
cp komari-plugin.json build/komari-plugin.json
cp web/index.html build/web/index.html

rm -f "$out"
( cd build && zip -r "../$out" komari-plugin.json script.js web >/dev/null )
echo "built $out"
unzip -l "$out"
