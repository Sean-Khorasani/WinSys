// Disposable elevated loopback check for the IPv6 WFP restriction path.
// Requires a running Web UI/engine and may request the collector's UAC approval.
import { randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
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
let child;
let listener;
let tempRoot;
let leaseId = "";
let childLines = [];
let lineWaiters = [];
let accepted = [];
let acceptWaiters = [];
let childStdout = "";
let childStderr = "";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function get(pathname) {
  const response = await fetch(new URL(pathname, base), { headers });
  const body = await response.json();
  if (!response.ok) throw new Error(`${pathname}: HTTP ${response.status} ${body.code || ""}`);
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

function queueLine(line) {
  const waiter = lineWaiters.shift();
  if (waiter) {
    clearTimeout(waiter.timer);
    waiter.resolve(line);
  } else childLines.push(line);
}

function waitLine(timeoutMs = 10000) {
  if (childLines.length) return Promise.resolve(childLines.shift());
  return new Promise((resolve, reject) => {
    const waiter = { resolve, timer: null };
    waiter.timer = setTimeout(() => {
      lineWaiters = lineWaiters.filter((entry) => entry !== waiter);
      reject(new Error(`Timed out waiting for probe output; stderr=${childStderr.slice(-300)}`));
    }, timeoutMs);
    lineWaiters.push(waiter);
  });
}

function waitAccepted(count, timeoutMs = 5000) {
  if (accepted.length >= count) return Promise.resolve(accepted[count - 1]);
  return new Promise((resolve, reject) => {
    const waiter = { count, resolve, timer: null };
    waiter.timer = setTimeout(() => {
      acceptWaiters = acceptWaiters.filter((entry) => entry !== waiter);
      reject(new Error(`IPv6 loopback listener did not accept connection ${count}`));
    }, timeoutMs);
    acceptWaiters.push(waiter);
  });
}

function startProbe(imagePath, port) {
  // Console I/O provides a deterministic gate so the exact same executable
  // instance holds the baseline socket, then attempts the blocked/released peer.
  const source = `
function ConnectOnce([string]$label, [int]$port) {
  $candidate = [System.Net.Sockets.TcpClient]::new([System.Net.Sockets.AddressFamily]::InterNetworkV6)
  try {
    $task = $candidate.ConnectAsync([System.Net.IPAddress]::IPv6Loopback, $port)
    if (-not $task.Wait(4000)) { [Console]::Out.WriteLine($label + '=TIMEOUT'); return }
    $null = $task.GetAwaiter().GetResult()
    [Console]::Out.WriteLine($label + '=CONNECTED')
  } catch {
    [Console]::Out.WriteLine($label + '=BLOCKED')
  } finally { $candidate.Close() }
}
try {
  $held = [System.Net.Sockets.TcpClient]::new([System.Net.Sockets.AddressFamily]::InterNetworkV6)
  $held.Connect([System.Net.IPAddress]::IPv6Loopback, ${port})
  [Console]::Out.WriteLine('READY')
  while ($true) {
    $command = [Console]::In.ReadLine()
    if ($command -eq 'block') { $held.Close(); ConnectOnce 'BLOCK' ${port} }
    elseif ($command -eq 'release') { ConnectOnce 'RELEASE' ${port} }
    elseif ($command -eq 'quit') { break }
  }
  exit 0
} catch { [Console]::Out.WriteLine('INIT-FAIL'); exit 2 }
`;
  const encoded = Buffer.from(source, "utf16le").toString("base64");
  const process = spawn(imagePath,
    ["-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
    { windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
  process.stdout.setEncoding("utf8");
  process.stderr.setEncoding("utf8");
  process.stdout.on("data", (chunk) => {
    childStdout += chunk;
    const parts = (childStdout + "").split(/\r?\n/);
    childStdout = parts.pop() || "";
    for (const line of parts) if (line) queueLine(line.trim());
  });
  process.stderr.on("data", (chunk) => { childStderr += chunk; });
  return process;
}

async function ensureTestLeaseReleased() {
  if (!leaseId) return;
  try {
    await operation("/api/restrictions/release", { id: leaseId });
    leaseId = "";
  } catch { /* Collector stop below still closes its owned dynamic session. */ }
}

try {
  const engine = await get("/api/engine");
  assert(engine.running, "The per-user engine must be running");
  const restrictionCapability = engine.capabilities?.find(
    (item) => item.id === "restrictions.temporary");
  assert(restrictionCapability?.enabled !== true,
    "An elevated collector is already connected; leaving it untouched");
  const recipes = await get("/api/engine/recipes");
  assert(recipes.items?.length === 0,
    "Recipe store is not empty; preserving it and aborting the test");
  assert(engine.lifecycle?.enabled === false,
    "Lifecycle tracking is already enabled; leaving the collector untouched");
  const existingInventory = await fetch(new URL("/api/restrictions", base), { headers });
  assert(existingInventory.status === 503,
    "A collector or restriction inventory is already available; leaving it untouched");

  const systemPowerShell = path.join(process.env.WINDIR || "C:\\Windows",
    "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "wintcp-ipv6-check-"));
  const probePath = path.join(tempRoot, "probe.exe");
  await fs.copyFile(systemPowerShell, probePath);
  const canonicalProbePath = await fs.realpath(probePath);
  assert(!canonicalProbePath.toLowerCase().startsWith(
    path.join(process.env.WINDIR || "C:\\Windows").toLowerCase() + path.sep),
  "Disposable executable unexpectedly resolves under Windows");

  await operation("/api/collector/control", { action: "start" });
  collectorStarted = true;
  const inventory = await get("/api/restrictions");
  assert(Array.isArray(inventory.items) && inventory.items.length === 0,
    "Fresh collector did not provide an empty restriction inventory");

  listener = net.createServer((socket) => {
    accepted.push(socket);
    for (const waiter of [...acceptWaiters]) {
      if (accepted.length >= waiter.count) {
        acceptWaiters = acceptWaiters.filter((entry) => entry !== waiter);
        clearTimeout(waiter.timer);
        waiter.resolve(accepted[waiter.count - 1]);
      }
    }
  });
  await new Promise((resolve, reject) => {
    listener.once("error", reject);
    listener.listen(0, "::1", resolve);
  });
  const port = listener.address().port;
  child = startProbe(canonicalProbePath, port);
  assert(await waitLine() === "READY", "Copied executable could not establish baseline IPv6 flow");
  await waitAccepted(1);

  const preview = await operation("/api/restrictions/preview", {
    imagePath: canonicalProbePath,
    remoteAddress: "::1",
    remotePort: String(port),
    protocol: "tcp",
    minutes: "1",
  });
  assert(preview.imagePath === canonicalProbePath && preview.remoteAddress === "::1" &&
    Number(preview.remotePort) === port && preview.protocol === "tcp" &&
    typeof preview.confirmationToken === "string" && preview.confirmationToken.length > 0,
  "Preview did not preserve the exact IPv6 application/peer/port/TCP scope");

  const applied = await operation("/api/restrictions/apply", {
    confirmationToken: preview.confirmationToken,
  });
  leaseId = applied.lease?.id || "";
  assert(leaseId, "Apply returned no owned lease ID");
  assert(applied.lease.remoteAddress === "::1" &&
    applied.lease.imagePath === canonicalProbePath &&
    applied.lease.remotePort === port && applied.lease.protocol === "tcp" &&
    applied.lease.filterIds?.length === 1,
  "Applied lease/filter inventory did not match the single IPv6 TCP scope");

  child.stdin.write("block\n");
  const blocked = await waitLine(10000);
  assert(blocked === "BLOCK=BLOCKED",
    `Expected the scoped IPv6 reconnect to be blocked, received ${blocked}`);
  const current = await get("/api/restrictions");
  assert(current.items?.length === 1 && current.items[0].id === leaseId &&
    current.items[0].remoteAddress === "::1" &&
    current.items[0].imagePath === canonicalProbePath,
  "Active inventory does not show only the expected test lease");

  await operation("/api/restrictions/release", { id: leaseId });
  leaseId = "";
  const releasedInventory = await get("/api/restrictions");
  assert(releasedInventory.items?.length === 0,
    "Explicit release left a restriction lease active");
  const restoredAccept = waitAccepted(2);
  child.stdin.write("release\n");
  const restored = await waitLine(10000);
  assert(restored === "RELEASE=CONNECTED",
    `Expected connectivity after release, received ${restored}`);
  await restoredAccept;
  child.stdin.write("quit\n");
  const childExit = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Probe process did not exit")), 5000);
    child.once("exit", (code) => { clearTimeout(timer); resolve(code); });
  });
  child = null;
  assert(childExit === 0, `Probe process exited with ${childExit}`);

  await operation("/api/collector/control", { action: "stop" });
  collectorStarted = false;
  console.log(`ipv6-restriction-test=PASS image=${canonicalProbePath} peer=::1 port=${port} blocked=true releaseRestored=true filters=1`);
} finally {
  if (child && child.exitCode === null) {
    try { child.stdin.write("quit\n"); } catch { /* process may have closed stdin */ }
    await new Promise((resolve) => {
      const timer = setTimeout(() => { child.kill(); resolve(); }, 3000);
      child.once("exit", () => { clearTimeout(timer); resolve(); });
    });
  }
  for (const socket of accepted) socket.destroy();
  if (listener) await new Promise((resolve) => listener.close(resolve));
  await ensureTestLeaseReleased();
  if (collectorStarted) {
    try { await operation("/api/collector/control", { action: "stop" }); }
    catch (error) { console.error(`collector-stop cleanup failed: ${error.message}`); }
  }
  if (tempRoot) {
    const root = await fs.realpath(os.tmpdir());
    const target = await fs.realpath(tempRoot);
    assert(target.startsWith(root + path.sep) &&
      path.basename(target).startsWith("wintcp-ipv6-check-"),
    "Refusing cleanup outside the dedicated temporary test directory");
    await fs.rm(target, { recursive: true, force: true });
  }
}
