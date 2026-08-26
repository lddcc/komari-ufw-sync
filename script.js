/**
 * Komari UFW Sync — v0.5 (list-style whitelist + per-node public ports)
 * ------------------------------------------------------------------
 * Brain runs on the dashboard. It builds a trusted whitelist (fleet node IPs
 * from Komari + static v4/v6 + home DDNS names) and, per node, a set of public
 * ports; then runs the on-node applier (agent/ufw-sync.sh, base64-shipped) via
 * admin:exec — one exec per selected node so each carries its own public ports.
 *
 * The whitelist lists (DDNS + static v4/v6) and the per-node public ports are
 * stored by THIS plugin in its storage dir (not in the managed config), and are
 * edited as add/remove lists in the admin page (web/index.html). The managed
 * config only holds the operational switches (apply / include_fleet / interval /
 * trigger_token).
 *
 * SAFETY: effective mode is "apply" only when explicitly requested (page Apply
 * button, or the `apply` config switch for the cron); otherwise "check" (dry).
 * The applier is fail-safe (skips empty trusted set so it never locks you out,
 * skips hosts w/o ufw, only ever touches its own komari-ufw-* tagged rules).
 */

const server = require("server");
const fs = require("fs");

const SHORT = "ufw-sync";

// Injected at build time from agent/ufw-sync.sh (base64). See build.sh.
const APPLIER_B64 = "__APPLIER_B64__";

const POLL_ATTEMPTS = 30;
const POLL_INTERVAL_MS = 2000;

const STORE = typeof __storageDir__ !== "undefined" ? __storageDir__ : ".";
const SEL_FILE = STORE + "/selection.json";
const TS_FILE = STORE + "/laststate.json";
const WL_FILE = STORE + "/whitelist.json";
const PUB_FILE = STORE + "/pubports.json";
const SET_FILE = STORE + "/settings.json";

// Read-only status probe: ufw state + counts of each of our tagged rule sets.
const STATUS_CMD = [
  'echo ufw=$(command -v ufw >/dev/null 2>&1 && (ufw status 2>/dev/null | head -1 | sed "s/^Status: //") || echo missing)',
  "echo trusted=$(ufw status 2>/dev/null | grep -c komari-ufw-sync)",
  "echo pub=$(ufw status 2>/dev/null | grep -F komari-ufw-pub | grep -oE '[0-9]+(:[0-9]+)?/(tcp|udp)' | sort -u | wc -l)",
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
// normalise an incoming array (or delimited string) into a clean token list
function cleanList(v) {
  const arr = Array.isArray(v) ? v : splitList(v);
  return uniq(arr.map((x) => String(x || "").trim()).filter(Boolean));
}

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    return fallback;
  }
}
function writeJson(file, obj) {
  try {
    fs.writeFileSync(file, JSON.stringify(obj));
    return true;
  } catch (e) {
    return false;
  }
}

// selection = array of uuids to act on; null/absent means "all".
function loadSelection() {
  return readJson(SEL_FILE, null);
}
function saveSelection(uuids) {
  return writeJson(SEL_FILE, uuids || []);
}
function loadLastRun() {
  return (readJson(TS_FILE, {}) || {}).last || 0;
}
function saveLastRun(ts) {
  writeJson(TS_FILE, { last: ts });
}

// whitelist lists (arrays), plugin-managed (not in the Komari config)
function loadWL() {
  const w = readJson(WL_FILE, {}) || {};
  return {
    ddns_v4: cleanList(w.ddns_v4),
    ddns_v6: cleanList(w.ddns_v6),
    static_v4: cleanList(w.static_v4),
    static_v6: cleanList(w.static_v6),
  };
}
function saveWL(w) {
  return writeJson(WL_FILE, {
    ddns_v4: cleanList(w.ddns_v4),
    ddns_v6: cleanList(w.ddns_v6),
    static_v4: cleanList(w.static_v4),
    static_v6: cleanList(w.static_v6),
  });
}

// operational settings, plugin-managed in fs (NOT Komari's managed config, so
// saving never reloads the plugin). Defaults: dry-run, trust fleet, 5-min sync.
function loadSettings() {
  const s = readJson(SET_FILE, {}) || {};
  return {
    apply: s.apply === true,
    include_fleet: s.include_fleet !== false,
    interval_minutes: Number(s.interval_minutes != null ? s.interval_minutes : 5),
  };
}
function saveSettings(s) {
  const cur = loadSettings();
  return writeJson(SET_FILE, {
    apply: "apply" in s ? !!s.apply : cur.apply,
    include_fleet: "include_fleet" in s ? !!s.include_fleet : cur.include_fleet,
    interval_minutes: "interval_minutes" in s ? (Number(s.interval_minutes) || 0) : cur.interval_minutes,
  });
}

// per-node public ports: { <uuid>: { tcp:[...], udp:[...] } }
function loadPub() {
  const p = readJson(PUB_FILE, {}) || {};
  const out = {};
  Object.keys(p).forEach((u) => {
    out[u] = { tcp: cleanList(p[u] && p[u].tcp), udp: cleanList(p[u] && p[u].udp) };
  });
  return out;
}
function savePub(map) {
  return writeJson(PUB_FILE, map || {});
}
function setNodePub(uuid, tcp, udp) {
  const map = loadPub();
  const t = cleanList(tcp);
  const u = cleanList(udp);
  if (t.length === 0 && u.length === 0) delete map[uuid];
  else map[uuid] = { tcp: t, udp: u };
  return savePub(map);
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

/** Poll many dispatched tasks (one per node) until all return or we time out. */
async function pollMany(tasks) {
  const done = {};
  for (let i = 0; i < POLL_ATTEMPTS; i++) {
    await sleep(POLL_INTERVAL_MS);
    let all = true;
    for (const t of tasks) {
      if (!t.task_id || done[t.task_id]) continue;
      try {
        const r = await server.call("admin:getTaskResultsByTaskId", { task_id: t.task_id });
        if (Array.isArray(r) && r.length >= 1) done[t.task_id] = r[0];
        else all = false;
      } catch (e) {
        all = false;
      }
    }
    if (all) break;
  }
  return done;
}

function targetNodes(nodes, uuids) {
  const sel = Array.isArray(uuids) ? uuids : loadSelection();
  if (!Array.isArray(sel)) return nodes; // null = all
  return nodes.filter((n) => sel.indexOf(n.uuid) !== -1);
}

function buildCommand(mode, wl4, wl6, ddns4, ddns6, ptcp, pudp) {
  return (
    "echo " + APPLIER_B64 + " | base64 -d | MODE=" + mode +
    " WL_V4=" + shq(wl4.join(" ")) +
    " WL_V6=" + shq(wl6.join(" ")) +
    " DDNS_V4=" + shq(ddns4.join(" ")) +
    " DDNS_V6=" + shq(ddns6.join(" ")) +
    " PUBLIC_TCP=" + shq((ptcp || []).join(",")) +
    " PUBLIC_UDP=" + shq((pudp || []).join(",")) +
    " bash"
  );
}

async function syncAll(mode, uuids) {
  const settings = loadSettings();
  const wl = loadWL();
  const pub = loadPub();
  const nodes = await listClients();
  const nameByUuid = {};
  nodes.forEach((n) => (nameByUuid[n.uuid] = n.name));

  const target = targetNodes(nodes, uuids);
  if (target.length === 0) return { error: "no target nodes selected" };

  let wl4 = wl.static_v4.slice();
  let wl6 = wl.static_v6.slice();
  if (settings.include_fleet) {
    const f = await fleetIps(nodes); // whitelist covers the whole fleet
    wl4 = wl4.concat(f.v4);
    wl6 = wl6.concat(f.v6);
  }
  wl4 = uniq(wl4);
  wl6 = uniq(wl6);

  // one exec per node so each carries its own public ports
  const tasks = [];
  for (const n of target) {
    const np = pub[n.uuid] || { tcp: [], udp: [] };
    const command = buildCommand(mode, wl4, wl6, wl.ddns_v4, wl.ddns_v6, np.tcp, np.udp);
    try {
      const summary = await server.call("admin:exec", { command, clients: [n.uuid] });
      tasks.push({ uuid: n.uuid, node: n.name, task_id: summary && summary.task_id });
    } catch (e) {
      tasks.push({ uuid: n.uuid, node: n.name, task_id: null, err: String((e && e.message) || e) });
    }
  }
  console.log(
    `[ufw-sync] mode=${mode} targets=${target.length} wl_v4=${wl4.length} wl_v6=${wl6.length}`
  );

  const done = await pollMany(tasks);
  const results = tasks.map((t) => {
    const r = t.task_id ? done[t.task_id] : null;
    return {
      node: t.node,
      exit_code: r ? r.exit_code : null,
      output: r ? String(r.result || "").trim() : (t.err || "no result"),
    };
  });
  results.forEach((r) =>
    console.log(`[ufw-sync] ${r.node} exit=${r.exit_code} :: ${String(r.output).replace(/\n/g, " | ")}`)
  );
  const missing = results.filter((r) => r.exit_code == null).map((r) => r.node);
  return {
    mode,
    whitelist: { v4: wl4, v6: wl6, ddns_v4: wl.ddns_v4, ddns_v6: wl.ddns_v6 },
    dispatched: target.length,
    returned: results.filter((r) => r.exit_code != null).length,
    missing,
    results,
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
  const done = await pollMany([{ task_id: taskId }]);
  // status uses a single multi-client task; fetch its full result array
  let results = [];
  try {
    results = await server.call("admin:getTaskResultsByTaskId", { task_id: taskId });
  } catch (e) {
    results = [];
  }
  const out = (results || []).map((r) => {
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
      pub: kv.pub != null && kv.pub !== "" ? Number(kv.pub) : null,
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
  console.log("[ufw-sync] v0.5 loaded (dry-run by default; UI at plugin page)");

  async function guard(req, res) {
    const cfg = await server.getConfig();
    if (!isAuthorized(req, cfg)) {
      json(res, 403, { error: "forbidden — admin session or ?token= required" });
      return false;
    }
    return true;
  }

  // UI: list nodes + saved selection + per-node public ports
  server.route("GET", "/ufw/api/state", async (req, res) => {
    if (!(await guard(req, res))) return;
    try {
      const nodes = await listClients();
      json(res, 200, { nodes, selection: loadSelection(), pub: loadPub() });
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

  // UI: save a single node's public ports
  server.route("POST", "/ufw/api/pub", async (req, res) => {
    if (!(await guard(req, res))) return;
    const body = parseBody(req);
    if (!body.uuid) return json(res, 400, { error: "uuid required" });
    const ok = setNodePub(body.uuid, body.tcp, body.udp);
    json(res, ok ? 200 : 500, { ok, pub: loadPub() });
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

  // UI: read editable settings + whitelist lists (all from plugin storage)
  server.route("GET", "/ufw/api/config", async (req, res) => {
    if (!(await guard(req, res))) return;
    const s = loadSettings();
    const wl = loadWL();
    json(res, 200, {
      apply: s.apply,
      include_fleet: s.include_fleet,
      interval_minutes: s.interval_minutes,
      ddns_v4: wl.ddns_v4,
      ddns_v6: wl.ddns_v6,
      static_v4: wl.static_v4,
      static_v6: wl.static_v6,
    });
  });

  // UI: save settings + whitelist lists — pure fs writes, so this is instant
  // and NEVER reloads the plugin or triggers a sync/exec. (Operational settings
  // live in plugin storage, not Komari's managed config, precisely so that
  // saving doesn't call admin:setPluginConfiguration, which reloads the plugin
  // — and reloading mid-request was what made saving hang.)
  server.route("POST", "/ufw/api/config", async (req, res) => {
    if (!(await guard(req, res))) return;
    try {
      const body = parseBody(req);
      const wl = loadWL();
      ["ddns_v4", "ddns_v6", "static_v4", "static_v6"].forEach((k) => {
        if (k in body) wl[k] = cleanList(body[k]);
      });
      const okWl = saveWL(wl);
      const okSet = saveSettings(body);
      json(res, okWl && okSet ? 200 : 500, { ok: okWl && okSet });
    } catch (e) {
      json(res, 500, { error: String((e && e.message) || e) });
    }
  });

  // Scheduled sync — ticks every minute, runs when `interval_minutes` has
  // elapsed since the last run (0 = disabled). Effective mode from `apply`.
  server.cron("@every 1m", async () => {
    try {
      const s = loadSettings();
      const iv = Number(s.interval_minutes);
      if (!(iv > 0)) return;
      const now = Date.now();
      if (now - loadLastRun() < iv * 60 * 1000) return;
      saveLastRun(now); // claim the slot before running to avoid overlap
      const mode = s.apply ? "apply" : "check";
      await syncAll(mode);
    } catch (e) {
      console.log("[ufw-sync] cron error: " + String((e && e.message) || e));
    }
  });
}

function unload() {
  console.log("[ufw-sync] v0.5 unloaded");
}

// Komari's goja runtime discovers top-level `load`/`unload`.
// Do NOT use `module.exports` — `module` is not defined in the entry script.
