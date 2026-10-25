// Proves the per-user Passive engine continues sampling and storing inbox
// notifications while the Web UI process (and therefore any browser client)
// is stopped. Uses only a copied PowerShell probe and a local IPv4 listener.
import { randomUUID } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

const args = process.argv.slice(2);
const urlIndex = args.indexOf("--url");
if (urlIndex < 0 || !args[urlIndex + 1])
  throw new Error("Pass --url http://127.0.0.1:PORT/");
let base = new URL(args[urlIndex + 1]);
if (base.protocol !== "http:" || base.hostname !== "127.0.0.1")
  throw new Error("Only the loopback Web UI is supported");

let token = "";
let tempRoot = "";
let child;
let listener;
let serverSockets = [];
let childLines = [];
let lineWaiters = [];
let accepted = 0;
let acceptWaiter;
let serviceStopped = false;
let engineStopped = false;
let recipeId = "";
let savedRevision = "";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function refreshToken() {
  const html = await (await fetch(base)).text();
  token = html.match(/name="wintcp-api-token"\s+content="([a-f0-9]{64})"/)?.[1] || "";
  assert(token, "Web UI session token missing");
}

function headers() {
  return { "X-WinTCP-Token": token, Origin: base.origin };
}

async function get(pathname) {
  const response = await fetch(new URL(pathname, base), { headers: headers() });
  const body = await response.json();
  if (!response.ok)
    throw new Error(`${pathname}: HTTP ${response.status} ${body.code || ""}`);
  return body;
}

async function post(pathname, fields) {
  const response = await fetch(new URL(pathname, base), {
    method: "POST",
    headers: { ...headers(), "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ ...fields, requestId: randomUUID().replaceAll("-", "") }),
  });
  return { response, body: await response.json() };
}

async function operation(pathname, fields) {
  const { response, body } = await post(pathname, fields);
  assert(response.status === 202 && body.operationId,
    `${pathname} was not queued: HTTP ${response.status} ${body.code || ""}`);
  const deadline = Date.now() + 120000;
  while (Date.now() < deadline) {
    const result = await get(`/api/engine/operations/${body.operationId}`);
    if (result.status === "succeeded") return result.result;
    if (result.status === "failed")
      throw new Error(`${fields.action || pathname} failed: ${result.error?.code || "unknown"}`);
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(`${pathname} timed out`);
}

async function controlEngine(action) {
  const response = await fetch(new URL("/api/engine/control", base), {
    method: "POST",
    headers: { ...headers(), "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ action }),
  });
  const body = await response.json();
  const expectedRunning = action === "start";
  assert(response.status === 200 && body.running === expectedRunning,
    `Engine ${action} failed: HTTP ${response.status} ${body.code || ""}`);
  engineStopped = !expectedRunning;
}

async function saveRecipes(text) {
  const current = await get("/api/engine/recipes");
  const { response, body } = await post("/api/engine/recipes", {
    expectedRevision: current.revision, recipesText: text,
  });
  assert(response.status === 202 && body.operationId,
    `Recipe update was not queued: HTTP ${response.status} ${body.code || ""}`);
  const deadline = Date.now() + 120000;
  while (Date.now() < deadline) {
    const result = await get(`/api/engine/operations/${body.operationId}`);
    if (result.status === "succeeded") return result.result;
    if (result.status === "failed")
      throw new Error(`Recipe update failed: ${result.error?.code || "unknown"}`);
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error("Recipe update timed out");
}

function service(action) {
  const result = spawnSync("cmd.exe", ["/c", `webui-service.bat ${action}`], {
    cwd: process.cwd(), encoding: "utf8", windowsHide: true,
  });
  assert(result.status === 0 && !result.error,
    `Web UI service ${action} failed: ${result.stderr || result.error || result.stdout}`);
  return result.stdout || "";
}

function engineStatus() {
  const exe = path.resolve("build/wintcp.exe");
  const result = spawnSync(exe, ["engine", "status"], {
    encoding: "utf8", windowsHide: true,
  });
  assert(result.status === 0 && !result.error,
    `Engine status failed while Web UI was stopped: ${result.stderr || result.error || "CLI failed"}`);
  return JSON.parse(result.stdout);
}

function enqueueLine(line) {
  const waiter = lineWaiters.shift();
  if (waiter) {
    clearTimeout(waiter.timer);
    waiter.resolve(line);
  } else childLines.push(line);
}

function waitLine(timeoutMs = 12000) {
  if (childLines.length) return Promise.resolve(childLines.shift());
  return new Promise((resolve, reject) => {
    const waiter = { resolve, timer: null };
    waiter.timer = setTimeout(() => {
      lineWaiters = lineWaiters.filter((item) => item !== waiter);
      reject(new Error("Disposable probe output timed out"));
    }, timeoutMs);
    lineWaiters.push(waiter);
  });
}

function startProbe(imagePath, address, port) {
  const source = `
$client = [System.Net.Sockets.TcpClient]::new([System.Net.Sockets.AddressFamily]::InterNetwork)
try {
  $task = $client.ConnectAsync([System.Net.IPAddress]::Parse('${address}'), ${port})
  if (-not $task.Wait(8000)) { [Console]::Out.WriteLine('INIT=TIMEOUT'); exit 2 }
  $null = $task.GetAwaiter().GetResult()
  [Console]::Out.WriteLine('READY')
  while ([Console]::In.ReadLine() -ne 'quit') { }
  exit 0
} catch { [Console]::Out.WriteLine('INIT=FAILED'); exit 2 }
`;
  const encoded = Buffer.from(source, "utf16le").toString("base64");
  const process = spawn(imagePath,
    ["-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
    { windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
  process.stdout.setEncoding("utf8");
  let pending = "";
  process.stdout.on("data", (chunk) => {
    pending += chunk;
    const parts = pending.split(/\r?\n/);
    pending = parts.pop() || "";
    for (const line of parts) if (line) enqueueLine(line.trim());
  });
  return process;
}

try {
  await refreshToken();
  const engine = await get("/api/engine");
  assert(engine.running, "Engine must already be running");
  const recipes = await get("/api/engine/recipes");
  assert(recipes.items?.length === 0,
    "Recipe store is not empty; preserving existing definitions and aborting");
  assert(engine.lifecycle?.enabled === false,
    "Collector is already running; leaving it untouched");
  const inventory = await fetch(new URL("/api/restrictions", base), { headers: headers() });
  assert(inventory.status === 503,
    "Elevated collector is already connected; leaving it untouched");

  const address = Object.values(os.networkInterfaces()).flat().find((entry) =>
    entry && entry.family === "IPv4" && !entry.internal &&
    !entry.address.startsWith("169.254."))?.address;
  assert(address, "No non-loopback IPv4 address is available");
  tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "wintcp-passive-closed-ui-"));
  const image = path.join(tempRoot, "probe.exe");
  await fs.copyFile(path.join(process.env.WINDIR || "C:\\Windows",
    "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), image);
  const canonicalImage = await fs.realpath(image);

  listener = net.createServer((socket) => {
    socket.on("error", () => {});
    serverSockets.push(socket);
    accepted++;
    if (acceptWaiter) { clearTimeout(acceptWaiter.timer); acceptWaiter.resolve(); acceptWaiter = null; }
  });
  await new Promise((resolve, reject) => {
    listener.once("error", reject);
    listener.listen(0, address, resolve);
  });
  const port = listener.address().port;

  recipeId = `passive-closed-${randomUUID().slice(0, 8)}`;
  const hex = (value) => Array.from(new TextEncoder().encode(value),
    (byte) => byte.toString(16).padStart(2, "0")).join("");
  const recipeText = (enabled, revision) => "WinTCP-Recipes:1\n" + [
    recipeId, revision, enabled ? "1" : "0", "outbound_activity", "60",
    hex("Passive acceptance with UI stopped"), hex(canonicalImage),
  ].join("|") + "\n";
  await saveRecipes(recipeText(false, 1));
  await saveRecipes(recipeText(true, 2));

  const before = engineStatus();
  child = startProbe(canonicalImage, address, port);
  assert(await waitLine() === "READY", "Disposable process failed to establish local TCP flow");
  await new Promise((resolve, reject) => {
    if (accepted > 0) { resolve(); return; }
    acceptWaiter = { resolve, reject, timer: setTimeout(() => {
      acceptWaiter = null;
      reject(new Error("Local listener did not accept the test flow"));
    }, 8000) };
  });

  service("stop");
  serviceStopped = true;
  await new Promise((resolve) => setTimeout(resolve, 5000));
  const whileUiStopped = engineStatus();
  assert(BigInt(whileUiStopped.samples) > BigInt(before.samples),
    "Engine sampling stopped when the Web UI service was stopped");
  assert(BigInt(whileUiStopped.recipes.notificationsWritten) >
    BigInt(before.recipes.notificationsWritten),
  "Passive engine did not persist the monitor notice while the UI was stopped");

  const startOutput = service("start");
  serviceStopped = false;
  const serviceUrl = startOutput.match(/URL:\s*(http:\/\/127\.0\.0\.1:\d+\/?)/)?.[1];
  if (serviceUrl) base = new URL(serviceUrl);
  else {
    const status = spawnSync("cmd.exe", ["/c", "webui-service.bat status"], {
      cwd: process.cwd(), encoding: "utf8", windowsHide: true,
    });
    const statusUrl = status.stdout.match(/URL:\s*(http:\/\/127\.0\.0\.1:\d+\/?)/)?.[1];
    if (statusUrl) base = new URL(statusUrl);
  }
  await refreshToken();
  let notice;
  const noticeDeadline = Date.now() + 10000;
  while (Date.now() < noticeDeadline) {
    const inbox = await get("/api/engine/notifications?limit=500");
    notice = inbox.items?.find((item) => item.recipeId === recipeId &&
      item.reason === "new_remote_tcp_endpoint" && item.coverage ===
        "snapshot_tcp_appearance_direction_unknown");
    if (notice) break;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  assert(notice?.deliveryStatus === "inbox",
    "Passive notification was not retained as a durable local inbox record");
  for (const field of ["recoveryCooldownKey", "recoveryCooldownRemainingNs",
    "recoverySavedMonotonicNs", "recoverySavedUtcMs"])
    assert(!(field in notice), `Private cooldown recovery field leaked through API: ${field}`);

  await controlEngine("stop");
  await controlEngine("start");
  const restartedEngine = await get("/api/engine");
  assert(restartedEngine.running && restartedEngine.recipes.notificationError === null,
    "Engine restart failed to load the durable inbox/cooldown state cleanly");
  const restartedRecipes = await get("/api/engine/recipes");
  const restartedRecipe = restartedRecipes.items?.find((item) => item.id === recipeId);
  assert(restartedRecipe?.runtime?.condition === "cooldown",
    "Passive cooldown was not restored after engine restart");
  const restartedInbox = await get("/api/engine/notifications?limit=500");
  const matchingNotices = restartedInbox.items?.filter((item) =>
    item.recipeId === recipeId && item.eventId === notice.eventId) || [];
  assert(matchingNotices.length === 1 && matchingNotices[0].id === notice.id,
    "Engine restart duplicated or lost the retained recipe notice");

  child.stdin.write("quit\n");
  const exitCode = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Disposable probe did not exit")), 5000);
    child.once("exit", (code) => { clearTimeout(timer); resolve(code); });
  });
  child = null;
  assert(exitCode === 0, `Disposable probe exited with ${exitCode}`);
  await operation(`/api/engine/notifications/${notice.id}/acknowledge`, {});
  const empty = await saveRecipes("WinTCP-Recipes:1\n");
  savedRevision = empty.revision;
  recipeId = "";
  console.log(`passive-closed-ui-test=PASS recipeNotice=${notice.id} samplesAdvanced=true notificationStoredWhileUiStopped=true restartCooldownRestored=true noDuplicateNotice=true acknowledged=true recoveryMetadataPrivate=true`);
} finally {
  if (child && child.exitCode === null) {
    try { child.stdin.write("quit\n"); } catch { /* process may already be closed */ }
    await new Promise((resolve) => {
      const timer = setTimeout(() => { child.kill(); resolve(); }, 3000);
      child.once("exit", () => { clearTimeout(timer); resolve(); });
    });
  }
  for (const socket of serverSockets) socket.destroy();
  if (listener) await new Promise((resolve) => listener.close(resolve));
  if (serviceStopped) {
    try {
      const output = service("start");
      const serviceUrl = output.match(/URL:\s*(http:\/\/127\.0\.0\.1:\d+\/?)/)?.[1];
      if (serviceUrl) base = new URL(serviceUrl);
      serviceStopped = false;
    } catch (error) { console.error(`Web UI service restart failed: ${error.message}`); }
  }
  if (engineStopped) {
    try { await controlEngine("start"); }
    catch (error) { console.error(`Engine restart failed: ${error.message}`); }
  }
  if (recipeId) {
    try { await saveRecipes("WinTCP-Recipes:1\n"); }
    catch (error) { console.error(`Passive recipe cleanup failed: ${error.message}`); }
  }
  if (tempRoot) {
    const root = await fs.realpath(os.tmpdir());
    const target = await fs.realpath(tempRoot);
    assert(target.startsWith(root + path.sep) &&
      path.basename(target).startsWith("wintcp-passive-closed-ui-"),
    "Refusing cleanup outside the dedicated temporary test directory");
    await fs.rm(target, { recursive: true, force: true });
  }
}
