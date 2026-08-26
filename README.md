# komari-ufw-sync

A [Komari](https://github.com/komari-monitor/komari) **server-side plugin** that
centrally keeps a **UFW whitelist** in sync across every agent — fleet cross-allow
IPs plus dynamic **home broadband exits resolved from DDNS** (IPv4 + IPv6 `/64`) —
by pushing commands through Komari's `admin:exec`.

Instead of every server pulling a `curl | bash` script from a central HTTP host
(a SPOF that fails silently when that host is down), the always-on Komari
dashboard becomes the brain: it already knows every node and can run root
commands on each agent.

## Status: Phase 1 — read-only probe

This first version **does not change any firewall rule**. It only validates the
plumbing end-to-end:

1. `admin:listClients` → enumerate nodes
2. `admin:exec` a **harmless** probe command (`hostname`, `id`, `ufw status | head -1`,
   public v4/v6) on every node
3. poll `admin:getTaskResultsByTaskId` → collect per-node `exit_code` + output

Results are written to the plugin log and exposed at a manual test route.

### Why a phased rollout

`admin:exec` runs as **root on every agent**. Before wiring that to `ufw`, we
prove dispatch, task polling, per-node results, and offline-node behaviour with
zero risk.

## Roadmap

- **Phase 2** — ship a thin, idempotent, **fail-safe** `ufw-sync.sh` on each node.
  The plugin computes each node's desired whitelist (fleet IPs from Komari +
  home DDNS) and invokes the applier with it. The applier does a **diff** and
  only touches rules on change; on empty/garbage input it **refuses to flush**
  (never lock yourself out). `ufw` rules are persistent, so a dashboard outage
  never drops existing rules.
- **Phase 3** — per-host public-port policy (80/443/25…) + audit & close
  accidentally world-exposed ports.

## Design notes / safety

- **No secrets in this repo.** The Komari API key lives in Komari, not here. The
  plugin runs inside Komari and calls RPCs directly.
- **Trust concentration.** A plugin that can `admin:exec` can root the whole
  fleet — but that capability already exists (the dashboard's `/admin/exec`).
  Harden the dashboard (2FA, restrict exec) accordingly.
- **Coupling.** Firewall updates depend on the dashboard being up. Mitigated by
  persistent `ufw` rules + fail-safe applier + Tailscale as an out-of-band path.

## Install & test (Phase 1)

### Option A — plugin source (recommended)

Add this repo's catalog as a **plugin source** in Komari, then install/update
from the UI (needs the repo to be **public** so Komari can fetch the release):

```
https://raw.githubusercontent.com/lddcc/komari-ufw-sync/main/v1.json
```

### Option B — manual upload

1. Zip the plugin (manifest + script at ZIP **root**, no nested folder):
   ```bash
   ./build.sh        # produces dist/ufw-sync-<version>.zip
   ```
2. Komari admin panel → **Plugins → Upload** the zip (or grab it from Releases).

### Then

3. It declares sensitive permissions (`allowSystemRPC`, `allowRoutes`) → approve.
4. **Enable** the plugin (plugins default to disabled).
5. Trigger a probe:
   - hit the plugin's `GET /exec-test` route (returns a JSON report), or
   - wait for the `@every 5m` cron and read **plugin logs**.

Expected: each online node returns `exit=0` with its `host/user/ufw/pubv4/pubv6`;
offline nodes show up under `missing` / `queued_offline`.

## Manifest permissions

| Permission | Why |
| --- | --- |
| `allowSystemRPC` | call `admin:listClients` / `admin:exec` / `admin:getTaskResultsByTaskId` |
| `allowRoutes` | expose `GET /exec-test` for manual runs |

## References

- Plugin docs: https://komari-document.pages.dev/dev/plugin/
- Plugin SDK (RPC catalog & types): https://github.com/komari-monitor/plugin-sdk
