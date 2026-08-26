/**
 * Komari UFW Sync — Phase 2 + node-selection UI
 * ------------------------------------------------------------------
 * Brain runs on the dashboard. It builds a whitelist (fleet node IPs from
 * Komari + static v4/v6 + home DDNS names from config) and runs the on-node
 * applier (agent/ufw-sync.sh, base64-shipped) via admin:exec — on the SELECTED
 * nodes only. An admin page (web/index.html) lists nodes, shows ufw status,
 * and lets you pick which nodes to act on (select-all / invert / reset).
 *
 * SAFETY: effective mode is "apply" only when explicitly requested (page Apply
 * button, or the `apply` config switch for the cron); otherwise "check"
 * (dry-run). The applier is fail-safe (refuses empty set, skips hosts w/o ufw,
 * never touches untagged rules). Fleet IPs come from Komari (authoritative),
 * not from probing nodes (several egress via a proxy).
 */

const server = require("server");
const fs = require("fs");

// Injected at build time from agent/ufw-sync.sh (base64). See build.sh.
const APPLIER_B64 = "__APPLIER_B64__";

const POLL_ATTEMPTS = 30;
const POLL_INTERVAL_MS = 2000;

const SEL_FILE =
  (typeof __storageDir__ !== "undefined" ? __storageDir__ : ".") + "/selection.json";

// Read-only status probe: reports ufw state + count of our tagged rules.
const STATUS_CMD = [
  'echo ufw=$(command -v ufw >/dev/null 2>&1 && (ufw status 2>/dev/null | head -1 | sed "s/^Status: //") || echo missing)',
  "echo trusted=$(ufw status 2>/dev/null | grep -c komari-ufw-sync)",
].join("; ");

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
function shq(s) {
  return "'" + String(s || "").replace(/'/g, "'\\''") + "'";
}
function splitList(s) {
  return String(s || "").split(/[\s,]+/).filter(Boolean);
}
function uniq(arr) {
  return Array.from(new Set(arr.filter(Boolean)));
}

// selection = array of uuids to act on; null/absent means "all".
function loadSelection() {
  try {
    return JSON.parse(fs.readFileSync(SEL_FILE, "utf8"));
  } catch (e) {
    return null;
  }
}
function saveSelection(uuids) {
  try {
    fs.writeFileSync(SEL_FILE, JSON.stringify(uuids || []));
    return true;
  } catch (e) {
    return false;
  }
}

/** Guard for root-mounted plugin routes (no Komari auth on them). */
function isAuthorized(req, cfg) {
  const ctx = (req && req.context) || {};
  const p = ctx.principal || {};
  const roles = p.roles || [];
  const isAdmin =
    ctx.role === "admin" || (p.type === "user" && roles.indexOf("admin") !== -1);
  if (isAdmin) return true;
  const want = cfg && cfg.trigger_token ? String(cfg.trigger_token) : "";
  const got = req && req.query && req.query.token ? String(req.query.token) : "";
  return want !== "" && got === want;
}

function parseBody(req) {
  try {
    return JSON.parse((req && req.body) || "{}");
  } catch (e) {
    return {};
  }
}

async function listClients() {
  const clients = await server.call("admin:listClients");
  const arr = Array.isArray(clients) ? clients : Object.values(clients || {});
  return arr
    .filter((c) => c && c.uuid)
    .map((c) => ({ uuid: c.uuid, name: c.name || c.uuid, region: c.region || "" }));
}

/** Collect fleet public v4/v6 from Komari's authoritative per-node detail. */
async function fleetIps(nodes) {
  const v4 = [];
  const v6 = [];
  for (const n of nodes) {
    try {
      const c = await server.call("admin:getClient", { uuid: n.uuid });
      const d = (c && c.data) || c || {};
      if (d.ipv4) v4.push(String(d.ipv4));
      if (d.ipv6) v6.push(String(d.ipv6));
    } catch (e) {
      /* not fatal */
    }
  }
  return { v4, v6 };
}

async function pollResults(taskId, want) {
  let results = [];
  for (let i = 0; i < POLL_ATTEMPTS; i++) {
    await sleep(POLL_INTERVAL_MS);
    try {
      results = await server.call("admin:getTaskResultsByTaskId", { task_id: taskId });
    } catch (e) {
      results = results || [];
    }
    if (Array.isArray(results) && results.length >= want) break;
  }
  return results || [];
}

function targetNodes(nodes, uuids) {
  const sel = Array.isArray(uuids) ? uuids : loadSelection();
  if (!Array.isArray(sel)) return nodes; // null = all
  return nodes.filter((n) => sel.indexOf(n.uuid) !== -1);
}

function buildCommand(mode, wl4, wl6, ddns4, ddns6) {
  return (
    "echo " + APPLIER_B64 + " | base64 -d | MODE=" + mode +
    " WL_V4=" + shq(wl4.join(" ")) +
    " WL_V6=" + shq(wl6.join(" ")) +
    " DDNS_V4=" + shq(ddns4.join(" ")) +
    " DDNS_V6=" + shq(ddns6.join(" ")) +
    " bash"
  );
}

async function syncAll(mode, uuids) {
  const cfg = (await server.getConfig()) || {};
  const nodes = await listClients();
  const nameByUuid = {};
  nodes.forEach((n) => (nameByUuid[n.uuid] = n.name));

  const target = targetNodes(nodes, uuids);
  if (target.length === 0) return { error: "no target nodes selected" };

  const staticV4 = splitList(cfg.static_v4);
  const staticV6 = splitList(cfg.static_v6);
  const ddns4 = splitList(cfg.ddns_v4);
  const ddns6 = splitList(cfg.ddns_v6);

  let wl4 = staticV4.slice();
  let wl6 = staticV6.slice();
  if (cfg.include_fleet !== false && cfg.include_fleet !== "false") {
    const f = await fleetIps(nodes); // whitelist covers the whole fleet
    wl4 = wl4.concat(f.v4);
    wl6 = wl6.concat(f.v6);
  }
  wl4 = uniq(wl4);
  wl6 = uniq(wl6);

  const targetUuids = target.map((n) => n.uuid);
  const command = buildCommand(mode, wl4, wl6, ddns4, ddns6);
  const summary = await server.call("admin:exec", { command, clients: targetUuids });
  const taskId = summary && summary.task_id;
  const queued = (summary && summary.queued_clients) || [];
  console.log(
    `[ufw-sync] mode=${mode} targets=${targetUuids.length} wl_v4=${wl4.length} wl_v6=${wl6.length} -> task ${taskId}`
  );

  const results = await pollResults(taskId, targetUuids.length - queued.length);
  const report = results.map((r) => ({
    node: nameByUuid[r.client] || r.client,
    exit_code: r.exit_code,
    output: String(r.result || "").trim(),
  }));
  report.forEach((r) =>
    console.log(`[ufw-sync] ${r.node} exit=${r.exit_code} :: ${r.output.replace(/\n/g, " | ")}`)
  );
  const missing = target
    .filter((n) => !report.find((r) => r.node === n.name))
    .map((n) => n.name);
  return {
    mode,
    task_id: taskId,
    whitelist: { v4: wl4, v6: wl6, ddns_v4: ddns4, ddns_v6: ddns6 },
    dispatched: targetUuids.length,
    returned: report.length,
    missing,
    results: report,
  };
}

async function statusAll(uuids) {
  const nodes = await listClients();
  const nameByUuid = {};
  nodes.forEach((n) => (nameByUuid[n.uuid] = n.name));
  const target = targetNodes(nodes, Array.isArray(uuids) && uuids.length ? uuids : null);
  const targetUuids = (target.length ? target : nodes).map((n) => n.uuid);

  const summary = await server.call("admin:exec", { command: STATUS_CMD, clients: targetUuids });
  const taskId = summary && summary.task_id;
  const queued = (summary && summary.queued_clients) || [];
  const results = await pollResults(taskId, targetUuids.length - queued.length);
  const out = results.map((r) => {
    const kv = {};
    String(r.result || "").split("\n").forEach((l) => {
      const i = l.indexOf("=");
      if (i > 0) kv[l.slice(0, i).trim()] = l.slice(i + 1).trim();
    });
    return {
      uuid: r.client,
      node: nameByUuid[r.client] || r.client,
      ufw: kv.ufw || null,
      trusted: kv.trusted != null && kv.trusted !== "" ? Number(kv.trusted) : null,
      exit_code: r.exit_code,
    };
  });
  return { results: out };
}

function json(res, code, obj) {
  res.statusCode = code;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(obj));
}

function load() {
  console.log("[ufw-sync] v0.3 loaded (dry-run by default; UI at plugin page)");

  async function guard(req, res) {
    const cfg = await server.getConfig();
    if (!isAuthorized(req, cfg)) {
      json(res, 403, { error: "forbidden — admin session or ?token= required" });
      return false;
    }
    return true;
  }

  // UI: list nodes + saved selection
  server.route("GET", "/ufw/api/state", async (req, res) => {
    if (!(await guard(req, res))) return;
    try {
      const nodes = await listClients();
      json(res, 200, { nodes, selection: loadSelection() });
    } catch (e) {
      json(res, 500, { error: String((e && e.message) || e) });
    }
  });

  // UI: save selection
  server.route("POST", "/ufw/api/selection", async (req, res) => {
    if (!(await guard(req, res))) return;
    const body = parseBody(req);
    const ok = saveSelection(Array.isArray(body.uuids) ? body.uuids : []);
    json(res, ok ? 200 : 500, { ok });
  });

  // UI: live status probe (read-only)
  server.route("POST", "/ufw/api/status", async (req, res) => {
    if (!(await guard(req, res))) return;
    try {
      const body = parseBody(req);
      json(res, 200, await statusAll(body.uuids));
    } catch (e) {
      json(res, 500, { error: String((e && e.message) || e) });
    }
  });

  // UI: run sync (mode: check|apply) on selected nodes
  server.route("POST", "/ufw/api/run", async (req, res) => {
    if (!(await guard(req, res))) return;
    try {
      const body = parseBody(req);
      const mode = body.mode === "apply" ? "apply" : "check";
      json(res, 200, await syncAll(mode, body.uuids));
    } catch (e) {
      json(res, 500, { error: String((e && e.message) || e) });
    }
  });

  // Scheduled sync — effective mode from the `apply` config switch, on the
  // saved selection. Read plugin logs for output.
  server.cron("@every 5m", async () => {
    try {
      const cfg = (await server.getConfig()) || {};
      const mode = cfg.apply === true || cfg.apply === "true" ? "apply" : "check";
      await syncAll(mode);
    } catch (e) {
      console.log("[ufw-sync] cron error: " + String((e && e.message) || e));
    }
  });
}

function unload() {
  console.log("[ufw-sync] v0.3 unloaded");
}

// Komari's goja runtime discovers top-level `load`/`unload`.
// Do NOT use `module.exports` — `module` is not defined in the entry script.
