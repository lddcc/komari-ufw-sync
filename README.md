# komari-ufw-sync

A [Komari](https://github.com/komari-monitor/komari) **server-side plugin** that
centrally keeps a **UFW whitelist** in sync across every agent — fleet
cross-allow IPs plus dynamic **home broadband exits resolved from DDNS**
(IPv4 + IPv6 `/64`) — by shipping a small applier and running it via
Komari's `admin:exec`.

The always-on dashboard is the brain: it knows every node (and their
authoritative public IPs) and can run root commands on each agent, so there is
no separate `curl | bash` host to keep alive.

## How it works

1. **Whitelist** = fleet node IPs (from Komari `admin:getClient`, authoritative —
   several nodes egress via a proxy so self-probing gives the wrong IP)
   \+ static v4/v6 + home DDNS **names** (from config).
2. The plugin base64-ships **`agent/ufw-sync.sh`** and runs it on the selected
   nodes via `admin:exec`, passing the whitelist as env.
3. The applier resolves DDNS **locally on each node**, diffs against its current
   tagged rules, and (in apply mode) syncs `ufw allow from` + `ufw route allow
   from` for each trusted source.

### Safety

- **Dry-run by default.** Effective mode is `apply` only when you click **Apply**
  in the UI, or turn on the `apply` config switch (used by the cron). Otherwise
  `check` — it computes and prints the diff and changes nothing.
- **Fail-safe applier:** refuses an empty whitelist (never locks you out), skips
  hosts without ufw (never auto-installs), and only ever touches its own
  `komari-ufw-sync`-tagged rules — never ufw defaults or public-port rules.
- The manual routes are guarded (admin session, or `?token=` = `trigger_token`).

## Admin UI

Adds an admin page **UFW Sync** listing every node with its ufw status and
trusted-rule count, plus checkboxes to choose which nodes to act on —
**全选 / 反选 / 重置**, a **刷新状态** probe, and **Dry-run** / **应用** buttons.
The selection is persisted; the cron acts on it too.

## Configuration

| Key | Meaning |
| --- | --- |
| `apply` | Off = dry-run only. On = the cron enforces changes. |
| `include_fleet` | Auto-add every Komari node's public v4/v6 to the whitelist. |
| `ddns_v4` / `ddns_v6` | Home DDNS hostnames, resolved on each node (v6 → `/64`). |
| `static_v4` / `static_v6` | Extra fixed addrs/CIDRs (LAN, tailnet, …). |
| `notify_on_apply` | Off = silent. On = push a Komari notification after an apply run that actually changed something (or failed) on any node. Every apply run is archived to the "同步历史" panel regardless. |
| `trigger_token` | Token for anonymous `?token=` triggering (admins need none). |

## Install

Add this repo's catalog as a **plugin source** in Komari (repo is public):

```
https://raw.githubusercontent.com/lddcc/komari-ufw-sync/main/v1.json
```

or upload the release zip via **Plugins → Upload**. It declares sensitive
permissions (`allowSystemRPC`, `allowRoutes`, `node`) → approve, then enable.

## Manifest permissions

| Permission | Why |
| --- | --- |
| `allowSystemRPC` | `admin:listClients` / `admin:getClient` / `admin:exec` / task results / `admin:sendNotification` (for `notify_on_apply`, routed through Komari's own configured notification channels) |
| `allowRoutes` | UI + JSON endpoints (`/ufw/api/*`) |
| `node` | `fs` — persist node selection under the plugin storage dir |

## References

- Plugin docs: https://komari-document.pages.dev/dev/plugin/
- Plugin SDK (RPC catalog & types): https://github.com/komari-monitor/plugin-sdk
