// Disposable, elevated end-to-end check of the reviewed reactive recipe path.
// Traffic stays on one local IPv4 interface and the WFP scope is the copied
// probe executable + one ephemeral local address/port for one minute.
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
const base = new URL(args[urlIndex + 1]);
if (base.protocol !== "http:" || base.hostname !== "127.0.0.1")
  throw new Error("Only the loopback Web UI is supported");

const tokenHtml = await (await fetch(base)).text();
const token = tokenHtml.match(/name="wintcp-api-token"\s+content="([a-f0-9]{64})"/)?.[1];
if (!token) throw new Error("Web UI session token missing");
const headers = { "X-WinTCP-Token": token, Origin: base.origin };
let collectorStarted = false;
let eventsStarted = false;
let tempRoot = "";
let child;
let listener;
let sockets = [];
let recipeId = "";
let recipeRevision = "";
let recipeStoreRevision = "";
let armed = false;
let leaseId = "";
let output = "";
let errors = "";
let lines = [];
let waiters = [];
let accepted = [];
let acceptWaiters = [];

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function get(pathname) {
  const response = await fetch(new URL(pathname, base), { headers });
  const body = await response.json();
  if (!response.ok)
    throw new Error(`${pathname}: HTTP ${response.status} ${body.code || ""}`);
  return body;
}

async function post(pathname, fields) {
  const response = await fetch(new URL(pathname, base), {
    method: "POST",
    headers: { ...headers, "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ ...fields, requestId: randomUUID().replaceAll("-", "") }),
  });
  return { response, body: await response.json() };
}

async function operation(pathname, fields) {
  const { response, body } = await post(pathname, fields);
  assert(response.status === 202 && typeof body.operationId === "string",
    `${pathname} was not queued: HTTP ${response.status} ${body.code || ""}`);
  const deadline = Date.now() + 120000;
  while (Date.now() < deadline) {
    const result = await get(`/api/engine/operations/${body.operationId}`);
    if (result.status === "succeeded") return result.result;
    if (result.status === "failed")
      throw new Error(`${fields.action || pathname} failed: ${result.error?.code || "unknown"}`);
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(`${fields.action || pathname} timed out`);
}

async function engineControl(action) {
  const response = await fetch(new URL("/api/engine/control", base), {
    method: "POST",
    headers: { ...headers, "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ action }),
  });
  const result = await response.json();
  assert(response.ok && result.running === (action === "start"),
    `Engine ${action} failed: HTTP ${response.status} ${result.code || ""}`);
}

function queueLine(line) {
  const waiter = waiters.shift();
  if (waiter) {
    clearTimeout(waiter.timer);
    waiter.resolve(line);
  } else lines.push(line);
}

function waitLine(timeoutMs = 12000) {
  if (lines.length) return Promise.resolve(lines.shift());
  return new Promise((resolve, reject) => {
    const waiter = { resolve, timer: null };
    waiter.timer = setTimeout(() => {
      waiters = waiters.filter((item) => item !== waiter);
      reject(new Error(`Probe output timed out; stderr=${errors.slice(-400)}`));
    }, timeoutMs);
    waiters.push(waiter);
  });
}

function waitAccepted(count, timeoutMs = 8000) {
  if (accepted.length >= count) return Promise.resolve(accepted[count - 1]);
  return new Promise((resolve, reject) => {
    const waiter = { count, resolve, timer: null };
    waiter.timer = setTimeout(() => {
      acceptWaiters = acceptWaiters.filter((item) => item !== waiter);
      reject(new Error(`Local test listener did not accept connection ${count}`));
    }, timeoutMs);
    acceptWaiters.push(waiter);
  });
}

function startProbe(imagePath, address, port) {
  // The same unique image-path process establishes the eligible outbound flow,
  // waits for the reviewed action, then attempts a second identical flow.
  const source = `
$address = [System.Net.IPAddress]::Parse('${address}')
$held = [System.Net.Sockets.TcpClient]::new([System.Net.Sockets.AddressFamily]::InterNetwork)
try {
  $task = $held.ConnectAsync($address, ${port})
  if (-not $task.Wait(8000)) { [Console]::Out.WriteLine('INIT=TIMEOUT'); exit 2 }
  $null = $task.GetAwaiter().GetResult()
  [Console]::Out.WriteLine('READY')
  while ($true) {
    $command = [Console]::In.ReadLine()
    if ($command -eq 'retry') {
      $held.Close()
      $candidate = [System.Net.Sockets.TcpClient]::new([System.Net.Sockets.AddressFamily]::InterNetwork)
      try {
        $retryTask = $candidate.ConnectAsync($address, ${port})
        if (-not $retryTask.Wait(3000)) { [Console]::Out.WriteLine('RETRY=TIMEOUT') }
        else { $null = $retryTask.GetAwaiter().GetResult(); [Console]::Out.WriteLine('RETRY=CONNECTED') }
      } catch { [Console]::Out.WriteLine('RETRY=BLOCKED') }
      finally { $candidate.Close() }
    } elseif ($command -eq 'quit') { break }
  }
  exit 0
} catch { [Console]::Out.WriteLine('INIT=FAILED'); exit 2 }
`;
  const encoded = Buffer.from(source, "utf16le").toString("base64");
  const process = spawn(imagePath,
    ["-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
    { windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
  process.stdout.setEncoding("utf8");
  process.stderr.setEncoding("utf8");
  let pending = "";
  process.stdout.on("data", (chunk) => {
    pending += chunk;
    const parts = pending.split(/\r?\n/);
    pending = parts.pop() || "";
    for (const line of parts) if (line) queueLine(line.trim());
  });
  process.stderr.on("data", (chunk) => { errors += chunk; });
  return process;
}

function recipeText(enabled, revision, imagePath, schedule = null) {
  const hex = (value) => Array.from(new TextEncoder().encode(value),
    (byte) => byte.toString(16).padStart(2, "0")).join("");
  const fields = [recipeId, revision, enabled ? "1" : "0",
    "outbound_activity", "0", hex("Disposable Active integration check"),
    hex(imagePath)];
  if (schedule) fields.push("weekly_window", String(schedule.daysMask),
    String(schedule.startMinute), String(schedule.endMinute), hex(schedule.timeZoneId));
  return (schedule ? "WinTCP-Recipes:2\n" : "WinTCP-Recipes:1\n") +
    fields.join("|") + "\n";
}

async function saveRecipes(expectedRevision, text) {
  const { response, body } = await post("/api/engine/recipes", {
    expectedRevision, recipesText: text,
  });
  assert(response.status === 202 && body.operationId,
    `Recipe update was not queued: HTTP ${response.status} ${body.code || ""}`);
  const deadline = Date.now() + 120000;
  while (Date.now() < deadline) {
    const operationResult = await get(`/api/engine/operations/${body.operationId}`);
    if (operationResult.status === "succeeded") return operationResult.result;
    if (operationResult.status === "failed")
      throw new Error(`Recipe update failed: ${operationResult.error?.code || "unknown"}`);
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error("Recipe update timed out");
}

async function releaseOwnedAuthorization() {
  if (!armed || !recipeId) return;
  try {
    await operation("/api/collector/control", {
      action: "release-owner", owner: `recipe:${recipeId}`,
    });
    armed = false;
  } catch (error) {
    console.error(`owner release cleanup failed: ${error.message}`);
  }
}

function exactCollectorPid() {
  const executable = path.resolve("build/wintcp.exe").replaceAll("'", "''");
  const query = `Get-CimInstance Win32_Process -Filter \"Name = 'wintcp.exe'\" | ` +
    `Where-Object { $_.ExecutablePath -ieq '${executable}' -and ` +
    `$_.CommandLine -match 'collector run' } | ForEach-Object { $_.ProcessId }`;
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive",
    "-Command", query], { encoding: "utf8", windowsHide: true });
  assert(result.status === 0 && !result.error,
    `Could not identify the exact disposable collector process: ${result.stderr || result.error || "query failed"}`);
  const pids = result.stdout.split(/\r?\n/).map((line) => Number(line.trim()))
    .filter((pid) => Number.isInteger(pid) && pid > 0);
  assert(pids.length === 1,
    `Expected exactly one matching collector for this build, found ${pids.length}`);
  return pids[0];
}

try {
  const engine = await get("/api/engine");
  assert(engine.running, "The per-user engine must already be running");
  const recipes = await get("/api/engine/recipes");
  assert(recipes.items?.length === 0,
    "Recipe store is not empty; preserving it and aborting the integration test");
  const tcpCapability = engine.capabilities?.find((item) =>
    item.id === "events.tcpLifecycle");
  assert(tcpCapability?.enabled !== true && engine.lifecycle?.enabled !== true,
    "An event collector is already active; leaving it untouched");
  const inventoryResponse = await fetch(new URL("/api/restrictions", base), { headers });
  assert(inventoryResponse.status === 503,
    "A collector or restriction inventory is already active; leaving it untouched");

  const interfaces = Object.values(os.networkInterfaces()).flat();
  const address = interfaces.find((entry) => entry && entry.family === "IPv4" &&
    !entry.internal && !entry.address.startsWith("169.254."))?.address;
  assert(address, "No non-loopback IPv4 interface address is available for local testing");

  const systemPowerShell = path.join(process.env.WINDIR || "C:\\Windows",
    "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "wintcp-active-recipe-check-"));
  const probePath = path.join(tempRoot, "probe.exe");
  await fs.copyFile(systemPowerShell, probePath);
  const canonicalProbePath = await fs.realpath(probePath);
  const windowsRoot = await fs.realpath(process.env.WINDIR || "C:\\Windows");
  assert(!canonicalProbePath.toLowerCase().startsWith(windowsRoot.toLowerCase() + path.sep),
    "Disposable executable unexpectedly resolves under Windows");

  listener = net.createServer((socket) => {
    // WFP rejection/lease teardown can reset an already accepted test socket.
    // Treat that as expected probe teardown instead of an unhandled Node error.
    socket.on("error", () => {});
    sockets.push(socket);
    accepted.push(socket);
    for (const waiter of [...acceptWaiters]) {
      if (accepted.length >= waiter.count) {
        acceptWaiters = acceptWaiters.filter((item) => item !== waiter);
        clearTimeout(waiter.timer);
        waiter.resolve(socket);
      }
    }
  });
  await new Promise((resolve, reject) => {
    listener.once("error", reject);
    listener.listen(0, address, resolve);
  });
  const port = listener.address().port;

  recipeId = `active-check-${randomUUID().slice(0, 8)}`;
  recipeStoreRevision = recipes.revision;
  const created = await saveRecipes(recipeStoreRevision,
    recipeText(false, 1, canonicalProbePath));
  recipeStoreRevision = created.revision;
  const enabled = await saveRecipes(recipeStoreRevision,
    recipeText(true, 2, canonicalProbePath));
  recipeStoreRevision = enabled.revision;
  const saved = await get("/api/engine/recipes");
  const recipe = saved.items?.find((item) => item.id === recipeId);
  assert(recipe?.enabled === true && String(recipe.revision) === "2",
    "Disposable monitor did not persist enabled at its reviewed revision");
  recipeRevision = String(recipe.revision);

  await operation("/api/collector/control", { action: "start" });
  collectorStarted = true;
  const eventStart = await operation("/api/collector/control", { action: "events-start" });
  eventsStarted = true;
  assert(eventStart.events?.running === true && Number(eventStart.events.traceResult) === 0,
    "ETW lifecycle tracking did not start successfully");

  await operation("/api/collector/control", {
    action: "arm-reactive", imagePath: canonicalProbePath, remoteAddress: address,
    remotePort: String(port), protocol: "both", minutes: "1",
    owner: `recipe:${recipeId}`, recipeRevision,
    grantMinutes: "2", maxActions: "1", cumulativeMinutes: "1",
  });
  armed = true;

  child = startProbe(canonicalProbePath, address, port);
  assert(await waitLine(12000) === "READY",
    `Disposable process could not establish its first local connection; stderr=${errors.slice(-400)}`);
  await waitAccepted(1);

  let activeNotice;
  const deadline = Date.now() + 45000;
  while (Date.now() < deadline) {
    const page = await get("/api/engine/notifications?limit=100");
    activeNotice = page.items?.find((item) => item.recipeId === recipeId &&
      item.reason === "active_recipe_action_verified");
    if (activeNotice) break;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  assert(activeNotice?.restrictionLeaseId && activeNotice.triggerEventId,
    "No durable Active-action notice linked the verified lease to its ETW trigger");
  assert(activeNotice.deliveryStatus === "inbox",
    "The action notice did not report durable local inbox delivery");

  await operation(`/api/engine/notifications/${activeNotice.id}/acknowledge`, {});
  const acknowledged = await get("/api/engine/notifications?limit=100");
  assert(acknowledged.items?.filter((item) => item.id === activeNotice.id).length === 1 &&
    acknowledged.items.find((item) => item.id === activeNotice.id).acknowledged === true,
  "Acknowledgment did not update exactly one retained inbox record");

  const lease = (await get("/api/restrictions")).items?.find((item) =>
    item.id === activeNotice.restrictionLeaseId);
  assert(lease && lease.imagePath.toLowerCase() === canonicalProbePath.toLowerCase() &&
    lease.remoteAddress === address && Number(lease.remotePort) === port,
  "Verified temporary lease did not retain the reviewed executable/peer/port scope");

  child.stdin.write("retry\n");
  const retry = await waitLine(8000);
  assert(retry === "RETRY=BLOCKED",
    `The reviewed Active action did not block the same probe's next connection: ${retry}`);

  let leaseExpired = false;
  const expiryDeadline = Date.now() + 80000;
  while (Date.now() < expiryDeadline) {
    const current = await get("/api/restrictions");
    if (!current.items?.some((item) => item.id === activeNotice.restrictionLeaseId)) {
      leaseExpired = true;
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  assert(leaseExpired, "The one-minute Active lease did not expire automatically");
  const expiryAccept = waitAccepted(2, 10000);
  child.stdin.write("retry\n");
  const afterExpiry = await waitLine(8000);
  assert(afterExpiry === "RETRY=CONNECTED",
    `The exact flow did not recover after its lease expired: ${afterExpiry}`);
  await expiryAccept;

  await releaseOwnedAuthorization();
  const afterRelease = await get("/api/restrictions");
  assert(!afterRelease.items?.some((item) => item.id === activeNotice.restrictionLeaseId),
    "Disarming the recipe did not release its owned temporary lease");

  child.stdin.write("quit\n");
  const exitCode = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Probe did not exit after cleanup")), 5000);
    child.once("exit", (code) => { clearTimeout(timer); resolve(code); });
  });
  child = null;
  assert(exitCode === 0, `Probe exited with ${exitCode}`);

  await operation("/api/collector/control", { action: "events-stop" });
  eventsStarted = false;
  await operation("/api/collector/control", { action: "stop" });
  collectorStarted = false;
  assert((await fetch(new URL("/api/restrictions", base), { headers })).status === 503,
    "Stopping the collector did not tear down its owned dynamic restriction session");
  let stoppedStatus;
  for (let attempt = 0; attempt < 20; ++attempt) {
    stoppedStatus = await get("/api/engine");
    if (stoppedStatus.lifecycle?.error === null) break;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  const stoppedTcp = stoppedStatus.capabilities?.find((item) =>
    item.id === "events.tcpLifecycle");
  assert(stoppedStatus.lifecycle?.enabled === false &&
    stoppedStatus.lifecycle?.error === null && stoppedTcp?.reason === "collector_not_connected",
  "A clean collector stop must report unavailable coverage, not a collector failure");

  await engineControl("stop");
  await engineControl("start");
  const restartedStatus = await get("/api/engine");
  const restartedRecipe = (await get("/api/engine/recipes")).items?.find((item) =>
    item.id === recipeId);
  const restartedInbox = await get("/api/engine/notifications?limit=100");
  const retainedNotice = restartedInbox.items?.filter((item) => item.id === activeNotice.id);
  assert(restartedRecipe?.enabled === true &&
    restartedRecipe.runtime?.activeActionGrant === false,
  "Engine restart must not restore Active authorization for a persisted recipe");
  assert(retainedNotice?.length === 1 && retainedNotice[0].acknowledged === true,
    "Acknowledged inbox record was duplicated or lost across engine restart");
  assert(restartedInbox.items?.every((item) => item.deliveryStatus !== "pending"),
    "Legacy durable inbox records must not report a permanently pending delivery state");
  assert(restartedStatus.lifecycle?.enabled === false,
    "Lifecycle collection unexpectedly resumed after engine restart");

  const latest = await get("/api/engine/recipes");
  const deleted = await saveRecipes(latest.revision, "WinTCP-Recipes:1\n");
  recipeStoreRevision = deleted.revision;
  recipeId = "";

  // Prove that killing the exact elevated collector drops its dynamic WFP
  // session. The only filter scope is the copied probe and a local ephemeral
  // address/port with a one-minute expiry as a safety backstop.
  await operation("/api/collector/control", { action: "start" });
  collectorStarted = true;
  const crashPreview = await operation("/api/restrictions/preview", {
    imagePath: canonicalProbePath, remoteAddress: address,
    remotePort: String(port), protocol: "tcp", minutes: "1",
  });
  assert(crashPreview.confirmationToken,
    "Crash-cleanup restriction preview returned no one-use confirmation");
  const crashLease = await operation("/api/restrictions/apply", {
    confirmationToken: crashPreview.confirmationToken,
  });
  leaseId = crashLease.lease?.id || "";
  assert(leaseId && crashLease.lease.imagePath.toLowerCase() ===
    canonicalProbePath.toLowerCase() && crashLease.lease.remoteAddress === address &&
    Number(crashLease.lease.remotePort) === port,
  "Crash-cleanup filter did not match its disposable scope");

  child = startProbe(canonicalProbePath, address, port);
  assert(await waitLine(12000) === "INIT=FAILED",
    "Disposable restriction did not block the probe before broker termination");
  const blockedProbeExit = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Blocked probe did not exit")), 5000);
    child.once("exit", (code) => { clearTimeout(timer); resolve(code); });
  });
  child = null;
  assert(blockedProbeExit === 2, `Blocked probe exited with ${blockedProbeExit}`);

  const collectorPid = exactCollectorPid();
  const killed = spawnSync("taskkill.exe", ["/PID", String(collectorPid), "/F"],
    { encoding: "utf8", windowsHide: true });
  assert(killed.status === 0 && !killed.error,
    `Could not terminate exact collector PID ${collectorPid}: ${killed.stderr || killed.error || "taskkill failed"}`);
  collectorStarted = false;
  leaseId = ""; // Dynamic-session teardown must remove the filter with the broker.

  let disconnected = false;
  const disconnectDeadline = Date.now() + 10000;
  while (Date.now() < disconnectDeadline) {
    const response = await fetch(new URL("/api/restrictions", base), { headers });
    if (response.status === 503) { disconnected = true; break; }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  assert(disconnected, "Engine did not observe the terminated collector as unavailable");

  const acceptedBeforeCrashRetry = accepted.length;
  child = startProbe(canonicalProbePath, address, port);
  assert(await waitLine(12000) === "READY",
    `The dynamic WFP scope survived collector termination; stderr=${errors.slice(-400)}`);
  await waitAccepted(acceptedBeforeCrashRetry + 1);
  child.stdin.write("quit\n");
  const recoveredExit = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Crash-recovery probe did not exit")), 5000);
    child.once("exit", (code) => { clearTimeout(timer); resolve(code); });
  });
  child = null;
  assert(recoveredExit === 0, `Crash-recovery probe exited with ${recoveredExit}`);

  // A grant's approval lifetime is independent of the short WFP lease. Arm a
  // second unused grant, let it expire, then prove a later eligible ETW flow
  // is recorded but cannot install a restriction or produce an Active notice.
  recipeId = `active-expiry-${randomUUID().slice(0, 8)}`;
  const currentRecipes = await get("/api/engine/recipes");
  const grantRecipeCreated = await saveRecipes(currentRecipes.revision,
    recipeText(false, 1, canonicalProbePath));
  recipeStoreRevision = grantRecipeCreated.revision;
  const grantRecipeEnabled = await saveRecipes(recipeStoreRevision,
    recipeText(true, 2, canonicalProbePath));
  recipeStoreRevision = grantRecipeEnabled.revision;

  await operation("/api/collector/control", { action: "start" });
  collectorStarted = true;
  await operation("/api/collector/control", { action: "events-start" });
  eventsStarted = true;
  await operation("/api/collector/control", {
    action: "arm-reactive", imagePath: canonicalProbePath,
    remoteAddress: address, remotePort: String(port), protocol: "both",
    minutes: "1", owner: `recipe:${recipeId}`, recipeRevision: "2",
    grantMinutes: "1", maxActions: "1", cumulativeMinutes: "1",
  });
  armed = true;
  const activeGrant = (await get("/api/engine/recipes")).items?.find((item) =>
    item.id === recipeId);
  assert(activeGrant?.runtime?.activeActionGrant === true,
    "Fresh one-minute reactive approval was not shown as armed");

  let grantExpired = false;
  const grantExpiryDeadline = Date.now() + 80000;
  while (Date.now() < grantExpiryDeadline) {
    const current = (await get("/api/engine/recipes")).items?.find((item) =>
      item.id === recipeId);
    if (current?.runtime?.activeActionGrant === false) {
      grantExpired = true;
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  assert(grantExpired, "Unused one-minute Active authorization did not expire");

  const acceptedBeforeGrantProbe = accepted.length;
  child = startProbe(canonicalProbePath, address, port);
  assert(await waitLine(12000) === "READY",
    `Eligible flow after grant expiry was unexpectedly blocked; stderr=${errors.slice(-400)}`);
  const grantProbePid = child.pid;
  await waitAccepted(acceptedBeforeGrantProbe + 1);
  let eligibleEventObserved = false;
  const eventDeadline = Date.now() + 30000;
  while (Date.now() < eventDeadline && !eligibleEventObserved) {
    let cursor = "";
    for (let pageIndex = 0; pageIndex < 64; ++pageIndex) {
      const query = cursor
        ? `?limit=500&cursor=${encodeURIComponent(cursor)}` : "?limit=500";
      const page = await get(`/api/engine/events${query}`);
      eligibleEventObserved ||= page.items?.some((event) =>
        String(event.process?.pid) === String(grantProbePid) &&
        event.kind === "connection_established" && event.direction === "outbound" &&
        event.remote?.address === address && Number(event.remote?.port) === port) === true;
      if (eligibleEventObserved || !page.items?.length || !page.nextCursor ||
          page.nextCursor === cursor) break;
      cursor = page.nextCursor;
    }
    if (!eligibleEventObserved) await new Promise((resolve) => setTimeout(resolve, 250));
  }
  assert(eligibleEventObserved,
    "Post-expiry probe did not produce the eligible normalized outbound ETW event");
  await new Promise((resolve) => setTimeout(resolve, 1500));
  const expiredInventory = await get("/api/restrictions");
  const expiredInbox = await get("/api/engine/notifications?limit=500");
  assert(expiredInventory.items?.length === 0 &&
    !expiredInbox.items?.some((item) => item.recipeId === recipeId &&
      item.reason === "active_recipe_action_verified"),
  "Expired authorization still installed an automatic restriction");

  child.stdin.write("quit\n");
  const grantProbeExit = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Grant-expiry probe did not exit")), 5000);
    child.once("exit", (code) => { clearTimeout(timer); resolve(code); });
  });
  child = null;
  assert(grantProbeExit === 0, `Grant-expiry probe exited with ${grantProbeExit}`);

  // Reuse the isolated recipe to prove a real, recipe-owned dynamic filter is
  // removed when a weekly UTC window closes (before its five-minute lease TTL).
  const now = new Date();
  const minute = now.getUTCHours() * 60 + now.getUTCMinutes();
  const startMinute = (minute + 1439) % 1440;
  const endMinute = (minute + (now.getUTCSeconds() > 40 ? 2 : 1)) % 1440;
  const closeSchedule = { daysMask: 127, startMinute, endMinute, timeZoneId: "UTC" };
  const scheduleCurrent = await get("/api/engine/recipes");
  const scheduleDisabled = await saveRecipes(scheduleCurrent.revision,
    recipeText(false, 3, canonicalProbePath, closeSchedule));
  recipeStoreRevision = scheduleDisabled.revision;
  const scheduleEnabled = await saveRecipes(recipeStoreRevision,
    recipeText(true, 4, canonicalProbePath, closeSchedule));
  recipeStoreRevision = scheduleEnabled.revision;
  const scheduled = (await get("/api/engine/recipes")).items?.find((item) =>
    item.id === recipeId);
  assert(scheduled?.enabled && scheduled.runtime?.scheduleActive === true,
    "Short UTC schedule was not active before the lease test");
  const scheduleOwner = `recipe:${recipeId}`;
  const preview = await operation("/api/restrictions/preview", {
    imagePath: canonicalProbePath, remoteAddress: address,
    remotePort: String(port), protocol: "tcp", minutes: "5",
    owner: scheduleOwner,
  });
  assert(preview.confirmationToken,
    "Could not preview the isolated schedule-bound recipe lease");
  const applied = await operation("/api/restrictions/apply", {
    confirmationToken: preview.confirmationToken,
  });
  const scheduledLeaseId = applied.lease?.id;
  assert(scheduledLeaseId && applied.lease.owner === scheduleOwner,
    "The schedule test did not install a lease owned by its recipe");
  let scheduleReleased = false;
  const scheduleDeadline = Date.now() + 145000;
  while (Date.now() < scheduleDeadline) {
    const current = (await get("/api/engine/recipes")).items?.find((item) =>
      item.id === recipeId);
    const inventory = await get("/api/restrictions");
    const leaseStillPresent = inventory.items?.some((item) =>
      item.id === scheduledLeaseId) === true;
    if (current?.runtime?.scheduleActive === false &&
        current.runtime.scheduleLeaseReleaseState === "released" &&
        !leaseStillPresent) {
      scheduleReleased = true;
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  assert(scheduleReleased,
    "The real recipe-owned temporary lease survived its UTC schedule boundary");
  const acceptedAfterScheduleRelease = accepted.length + 1;
  child = startProbe(canonicalProbePath, address, port);
  assert(await waitLine(12000) === "READY",
    `The isolated flow did not recover after schedule release; stderr=${errors.slice(-400)}`);
  await waitAccepted(acceptedAfterScheduleRelease);
  child.stdin.write("quit\n");
  const scheduleProbeExit = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Schedule-release probe did not exit")), 5000);
    child.once("exit", (code) => { clearTimeout(timer); resolve(code); });
  });
  child = null;
  assert(scheduleProbeExit === 0, `Schedule-release probe exited with ${scheduleProbeExit}`);

  await releaseOwnedAuthorization();
  const finalRecipes = await get("/api/engine/recipes");
  const finalDelete = await saveRecipes(finalRecipes.revision, "WinTCP-Recipes:1\n");
  recipeStoreRevision = finalDelete.revision;
  recipeId = "";
  await operation("/api/collector/control", { action: "events-stop" });
  eventsStarted = false;
  await operation("/api/collector/control", { action: "stop" });
  collectorStarted = false;
  console.log(`active-recipe-test=PASS image=${canonicalProbePath} peer=${address}:${port} verifiedNotice=true blockedRetry=true leaseExpired=true restoredAfterExpiry=true ownedLeaseReleased=true scheduleBoundaryReleased=true scheduleFlowRestored=true cleanStop=true ackRestart=true grantNotRestored=true brokerCrashCleanup=true unusedGrantExpired=true noLateAction=true`);
} finally {
  if (child && child.exitCode === null) {
    try { child.stdin.write("quit\n"); } catch { /* child may have already exited */ }
    await new Promise((resolve) => {
      const timer = setTimeout(() => { child.kill(); resolve(); }, 3000);
      child.once("exit", () => { clearTimeout(timer); resolve(); });
    });
  }
  for (const socket of sockets) socket.destroy();
  if (listener) await new Promise((resolve) => listener.close(resolve));
  if (leaseId && collectorStarted) {
    try { await operation("/api/restrictions/release", { id: leaseId }); }
    catch (error) { console.error(`restriction lease cleanup failed: ${error.message}`); }
  }
  await releaseOwnedAuthorization();
  if (collectorStarted) {
    if (eventsStarted) {
      try { await operation("/api/collector/control", { action: "events-stop" }); }
      catch (error) { console.error(`event-stop cleanup failed: ${error.message}`); }
    }
    try { await operation("/api/collector/control", { action: "stop" }); }
    catch (error) { console.error(`collector-stop cleanup failed: ${error.message}`); }
  }
  if (recipeId && recipeStoreRevision) {
    try {
      await saveRecipes(recipeStoreRevision, "WinTCP-Recipes:1\n");
    } catch (error) { console.error(`recipe cleanup failed: ${error.message}`); }
  }
  if (tempRoot) {
    const root = await fs.realpath(os.tmpdir());
    const target = await fs.realpath(tempRoot);
    assert(target.startsWith(root + path.sep) &&
      path.basename(target).startsWith("wintcp-active-recipe-check-"),
    "Refusing cleanup outside the dedicated temporary test directory");
    await fs.rm(target, { recursive: true, force: true });
  }
}
