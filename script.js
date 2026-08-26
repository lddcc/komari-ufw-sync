/**
 * Komari UFW Sync — Phase 1 (read-only probe)
 * ------------------------------------------------------------------
 * Goal of this phase: prove the admin:exec round-trip end-to-end
 *   list clients -> admin:exec a HARMLESS command -> poll task results
 * WITHOUT touching any firewall rule. Once validated, Phase 2 swaps the
 * probe command for a thin, idempotent, fail-safe `ufw-sync.sh` applier.
 *
 * Runtime: Komari goja sandbox, CommonJS. Globals: require, console,
 * setTimeout, fetch, __storageDir__ (fs only when permissions.node=true).
 *
 * RPC used (needs permissions.allowSystemRPC):
 *   admin:listClients               -> Client[] { uuid, name, ... }
 *   admin:exec {command, clients[]} -> { task_id, clients[], queued_clients[] }
 *   admin:getTaskResultsByTaskId {task_id} -> TaskResult[] { client, result, exit_code }
 */

const server = require("server");

/* Harmless, read-only probe. Reports identity + whether ufw exists +
 * the node's own public v4/v6 (short timeouts, "na" on failure). Nothing
 * here mutates state. */
const PROBE_CMD = [
  'echo "host=$(hostname)"',
  'echo "user=$(id -un)"',
  'echo "ufw=$(command -v ufw >/dev/null && ufw status 2>/dev/null | head -1 || echo missing)"',
  'echo "ufwdocker=$(grep -ql \\"BEGIN UFW AND DOCKER\\" /etc/ufw/after.rules 2>/dev/null && echo yes || echo no)"',
  'echo "pubv4=$(curl -s4 --max-time 3 https://api.ipify.org 2>/dev/null || echo na)"',
  'echo "pubv6=$(curl -s6 --max-time 3 https://api6.ipify.org 2>/dev/null || echo na)"',
].join("; ");

const POLL_ATTEMPTS = 10;   // * interval below
const POLL_INTERVAL_MS = 1500;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function listClients() {
  const clients = await server.call("admin:listClients");
  const arr = Array.isArray(clients) ? clients : Object.values(clients || {});
  return arr
    .filter((c) => c && c.uuid)
    .map((c) => ({ uuid: c.uuid, name: c.name || c.uuid }));
}

async function runProbe() {
  const nodes = await listClients();
  if (nodes.length === 0) {
    console.log("[ufw-sync] no clients registered");
    return { error: "no clients" };
  }
  const uuids = nodes.map((n) => n.uuid);
  const nameByUuid = {};
  nodes.forEach((n) => (nameByUuid[n.uuid] = n.name));

  const summary = await server.call("admin:exec", {
    command: PROBE_CMD,
    clients: uuids,
  });
  const taskId = summary && summary.task_id;
  const queued = (summary && summary.queued_clients) || [];
  console.log(
    `[ufw-sync] task ${taskId}: dispatched=${uuids.length} queued(offline?)=${queued.length}`
  );

  // Poll until every online client has reported (or attempts run out).
  const onlineCount = uuids.length - queued.length;
  let results = [];
  for (let i = 0; i < POLL_ATTEMPTS; i++) {
    await sleep(POLL_INTERVAL_MS);
    try {
      results = await server.call("admin:getTaskResultsByTaskId", {
        task_id: taskId,
      });
    } catch (e) {
      results = results || [];
    }
    if (Array.isArray(results) && results.length >= onlineCount) break;
  }

  const report = (results || []).map((r) => ({
    node: nameByUuid[r.client] || r.client,
    uuid: r.client,
    exit_code: r.exit_code,
    output: String(r.result || "").trim(),
  }));
  report.forEach((r) =>
    console.log(
      `[ufw-sync] ${r.node} exit=${r.exit_code} :: ${r.output.replace(/\n/g, " | ")}`
    )
  );
  const returnedUuids = report.map((r) => r.uuid);
  const missing = nodes
    .filter((n) => returnedUuids.indexOf(n.uuid) === -1)
    .map((n) => n.name);

  return {
    task_id: taskId,
    dispatched: uuids.length,
    queued_offline: queued.length,
    returned: report.length,
    missing,
    results: report,
  };
}

function load() {
  console.log("[ufw-sync] Phase 1 loaded — read-only probe, no firewall changes");

  // Manual trigger for testing: GET <plugin route base>/exec-test -> JSON report
  server.route("GET", "/exec-test", async (req, res) => {
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    try {
      const out = await runProbe();
      res.end(JSON.stringify(out, null, 2));
    } catch (e) {
      res.end(JSON.stringify({ error: String((e && e.message) || e) }));
    }
  });

  // Scheduled probe (logs only). Inspect via admin plugin logs.
  server.cron("@every 5m", async () => {
    try {
      await runProbe();
    } catch (e) {
      console.log("[ufw-sync] cron error: " + String((e && e.message) || e));
    }
  });
}

function unload() {
  console.log("[ufw-sync] Phase 1 unloaded");
}

// Komari calls load() on enable/startup and unload() on disable/shutdown.
module.exports = { load, unload };
