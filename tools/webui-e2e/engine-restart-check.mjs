// Verifies bounded persisted history/inbox continuity across a per-user engine
// restart. It does not edit recipes or acknowledge notifications. The Web UI
// remains up and the engine is restarted through its supported CLI controls.
import { spawnSync } from "node:child_process";
import path from "node:path";

const args = process.argv.slice(2);
const urlIndex = args.indexOf("--url");
if (urlIndex < 0 || !args[urlIndex + 1])
  throw new Error("Pass --url http://127.0.0.1:PORT/");
const base = new URL(args[urlIndex + 1]);
if (base.protocol !== "http:" || base.hostname !== "127.0.0.1")
  throw new Error("Only the loopback Web UI is supported");

const executable = path.resolve("build/wintcp.exe");
let token = "";
let stoppedByTest = false;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function refreshToken() {
  const response = await fetch(base);
  assert(response.ok, `Web UI unavailable: HTTP ${response.status}`);
  const html = await response.text();
  token = html.match(/name="wintcp-api-token"\s+content="([a-f0-9]{64})"/)?.[1] || "";
  assert(token, "Web UI session token missing");
}

async function request(pathname) {
  const response = await fetch(new URL(pathname, base), {
    headers: { "X-WinTCP-Token": token },
  });
  const text = await response.text();
  let body;
  try { body = JSON.parse(text); }
  catch { throw new Error(`${pathname}: expected JSON, got HTTP ${response.status}`); }
  return { response, body };
}

async function get(pathname) {
  const { response, body } = await request(pathname);
  if (!response.ok)
    throw new Error(`${pathname}: HTTP ${response.status} ${body.code || ""}`);
  return body;
}

function cli(action) {
  const result = spawnSync(executable, ["engine", action], {
    cwd: process.cwd(), encoding: "utf8", windowsHide: true, timeout: 15000,
  });
  if (result.error || result.status !== 0)
    throw new Error(`engine ${action} failed: ${result.stderr || result.error || result.stdout}`);
  try { return JSON.parse(result.stdout.trim()); }
  catch { throw new Error(`engine ${action} returned invalid JSON: ${result.stdout}`); }
}

function cliStatus() {
  const result = spawnSync(executable, ["engine", "status"], {
    cwd: process.cwd(), encoding: "utf8", windowsHide: true, timeout: 5000,
  });
  if (result.error || result.status !== 0) return null;
  try { return JSON.parse(result.stdout.trim()); }
  catch { return null; }
}

function ids(items, key) {
  assert(Array.isArray(items), `${key} page has no items array`);
  const values = items.map((item) => item[key]);
  assert(values.length > 0 && values.every((value) => typeof value === "string" && value),
    `${key} page is empty or contains a missing ID`);
  assert(new Set(values).size === values.length, `${key} page contains duplicate IDs`);
  return values;
}

async function snapshotPages() {
  const history = await get("/api/engine/history?limit=20");
  const historyIds = ids(history.items, "eventId");
  assert(history.nextCursor, "History fixture is too short to test cursor continuity");

  const notifications = await get("/api/engine/notifications?limit=100");
  const notificationIds = ids(notifications.items, "id");
  const acknowledgment = new Map(notifications.items.map((item) => [
    item.id, item.acknowledged,
  ]));
  assert(notifications.items.some((item) => item.acknowledged === true),
    "Need a retained acknowledged notification fixture; run passive-closed-ui-check.mjs first");
  return { history, historyIds, notificationIds, acknowledgment };
}

async function waitForService() {
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    try {
      const status = await get("/api/engine");
      if (status.running) return status;
    } catch { /* The independent Web UI can answer while the engine restarts. */ }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error("Web UI did not observe the restarted engine");
}

try {
  await refreshToken();
  const before = await get("/api/engine");
  assert(before.running, "Engine must already be running");
  const recipes = await get("/api/engine/recipes");
  assert(recipes.items?.length === 0,
    "Recipe store is not empty; preserving existing definitions and aborting");
  assert(before.lifecycle?.enabled === false,
    "Lifecycle collector is active; leaving it untouched");
  const restrictions = await request("/api/restrictions");
  assert(restrictions.response.status === 503,
    "Elevated collector is connected; leaving it untouched");

  const initial = await snapshotPages();
  const stopped = cli("stop");
  assert(stopped.stopping === true, "Engine did not acknowledge stop");
  stoppedByTest = true;
  assert(cliStatus() === null, "Engine still responds after acknowledged stop");

  const restarted = cli("start");
  assert(restarted.running === true && restarted.epoch !== before.epoch,
    "Engine did not start as a fresh epoch");
  stoppedByTest = false;
  const after = await waitForService();

  const historyAgain = await get("/api/engine/history?limit=20");
  const historyIdsAgain = ids(historyAgain.items, "eventId");
  assert(JSON.stringify(historyIdsAgain) === JSON.stringify(initial.historyIds),
    "Persisted history page changed across restart");
  assert(historyAgain.nextCursor === initial.history.nextCursor,
    "Persisted history cursor changed across restart");
  const cursorPage = await get(`/api/engine/history?limit=20&cursor=${
    encodeURIComponent(initial.history.nextCursor)}`);
  assert(cursorPage.code !== "cursor_expired" && cursorPage.code !== "history_error",
    "Persisted cursor was rejected after engine restart");

  const notificationsAgain = await get("/api/engine/notifications?limit=100");
  const notificationIdsAgain = ids(notificationsAgain.items, "id");
  assert(JSON.stringify(notificationIdsAgain) === JSON.stringify(initial.notificationIds),
    "Notification IDs or order changed across restart");
  for (const item of notificationsAgain.items) {
    assert(item.acknowledged === initial.acknowledgment.get(item.id),
      `Acknowledgement state changed across restart for ${item.id}`);
  }
  assert(after.recipes.definitions === 0,
    "Recipe store changed during the restart check");
  console.log(`engine-restart-test=PASS epochChanged=true historyIds=${historyIdsAgain.length} notifications=${notificationIdsAgain.length} cursorContinued=true acknowledgementsPreserved=true`);
} finally {
  if (stoppedByTest && cliStatus() === null) cli("start");
}
