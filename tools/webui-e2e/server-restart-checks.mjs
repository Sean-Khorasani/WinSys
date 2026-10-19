import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { copyFile, cp, mkdir, mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import net from "node:net";
import { chromium } from "@playwright/test";
import { basename, dirname, join, resolve, sep } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const sourceExe = resolve(process.env.WINTCP_TEST_EXE || join(root, "build-cmake", "Release", "wintcp.exe"));
const scratch = await mkdtemp(join(tmpdir(), "wintcp-webui-restart-"));
const profile = join(scratch, "profile");
const stagedExe = join(scratch, "app", "wintcp.exe");
let service = null;
let browser = null;

async function freeLoopbackPort() {
  const server = net.createServer();
  await new Promise((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolveListen);
  });
  const port = server.address().port;
  await new Promise((resolveClose, reject) => server.close((error) => error ? reject(error) : resolveClose()));
  return port;
}

async function stopOwnedService(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const exited = once(child, "exit");
  child.kill();
  await exited;
}

async function startService(port) {
  const child = spawn(stagedExe, ["webui", "serve", "--port", String(port)], {
    cwd: root,
    windowsHide: true,
    env: {
      ...process.env,
      WINTCP_WEBUI_OPEN_BROWSER: "0",
      WINTCP_WEBUI_DATA_DIR: profile,
      WINTCP_WEBUI_LOG_FILE: join(profile, "webui.log"),
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.setEncoding("utf8").on("data", (chunk) => { output += chunk; });
  child.stderr.setEncoding("utf8").on("data", (chunk) => { output += chunk; });
  const origin = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`Web UI exited during startup: ${output}`);
    try {
      const response = await fetch(`${origin}/`);
      if (response.ok) return { child, origin, html: await response.text() };
    } catch {}
    await new Promise((done) => setTimeout(done, 100));
  }
  await stopOwnedService(child);
  throw new Error(`Timed out waiting for the isolated Web UI: ${output}`);
}

function sessionToken(html) {
  const match = html.match(/<meta\s+name="wintcp-api-token"\s+content="([^"]+)"/i);
  assert.ok(match, "Web UI shell must contain its session token");
  return match[1];
}

async function readConfig(origin, token) {
  const response = await fetch(`${origin}/api/config`, {
    headers: { "X-WinTCP-Token": token },
  });
  assert.equal(response.status, 200, "configuration read should succeed");
  return { body: await response.json(), etag: response.headers.get("ETag") };
}

async function writeConfig(origin, token, etag, body) {
  return fetch(`${origin}/api/config`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "If-Match": etag,
      Origin: origin,
      "X-WinTCP-Token": token,
    },
    body: JSON.stringify(body),
  });
}

try {
  await stat(sourceExe);
  await mkdir(dirname(stagedExe), { recursive: true });
  await mkdir(profile, { recursive: true });
  await copyFile(sourceExe, stagedExe);
  await cp(join(root, "wintcp", "webui"), join(dirname(stagedExe), "webui"), { recursive: true });

  const port = await freeLoopbackPort();
  let running = await startService(port);
  service = running.child;
  const firstToken = sessionToken(running.html);
  const initial = await readConfig(running.origin, firstToken);
  assert.ok(initial.etag, "first server must issue a config ETag");
  assert.ok(Number.isInteger(initial.body.version) && Array.isArray(initial.body.rules),
    "a missing config file must resolve to a usable default object");
  console.log("[ ok ] missing config resolves to a usable default with an ETag");
  const changedUnits = initial.body.preferences?.units === "si" ? "iec" : "si";
  const savedBody = {
    ...initial.body,
    preferences: { ...initial.body.preferences, units: changedUnits },
  };
  const firstWrite = await writeConfig(running.origin, firstToken, initial.etag, savedBody);
  assert.equal(firstWrite.status, 200, "initial conditional config write should succeed");
  const preRestartEtag = firstWrite.headers.get("ETag");
  assert.ok(preRestartEtag, "successful write must return a new ETag");
  assert.equal((await firstWrite.json()).ok, true);
  console.log("[ ok ] isolated service persists a conditional preference write");

  const externallyEditedBody = { ...savedBody, externalEditProbe: "observed" };
  await writeFile(join(profile, "config.json"), JSON.stringify(externallyEditedBody), "utf8");
  const afterExternalEdit = await readConfig(running.origin, firstToken);
  assert.equal(afterExternalEdit.body.externalEditProbe, "observed",
    "GET must observe valid configuration edited outside the running service");
  assert.notEqual(afterExternalEdit.etag, preRestartEtag,
    "an external file edit must establish a new configuration revision");
  console.log("[ ok ] external config-file edits are observed with a new ETag");

  const staleExternalWrite = await writeConfig(running.origin, firstToken, preRestartEtag, {
    ...externallyEditedBody,
    externalEditProbe: "stale-write",
  });
  assert.equal(staleExternalWrite.status, 412,
    "an ETag from before an external edit must be rejected");
  assert.equal((await readConfig(running.origin, firstToken)).body.externalEditProbe, "observed",
    "a stale write must preserve the externally edited file contents");
  console.log("[ ok ] stale writes cannot overwrite an external config-file edit");

  browser = await chromium.launch({ headless: true });
  const browserContext = await browser.newContext();
  const browserErrors = [];
  const firstTab = await browserContext.newPage();
  const secondTab = await browserContext.newPage();
  firstTab.on("pageerror", (error) => browserErrors.push(error.message));
  secondTab.on("pageerror", (error) => browserErrors.push(error.message));
  const settingsUrl = `${running.origin}/index.html#/settings`;
  await Promise.all([
    firstTab.goto(settingsUrl, { waitUntil: "domcontentloaded" }),
    secondTab.goto(settingsUrl, { waitUntil: "domcontentloaded" }),
  ]);
  await Promise.all([
    firstTab.getByLabel("Units", { exact: true }).waitFor(),
    secondTab.getByLabel("Units", { exact: true }).waitFor(),
  ]);
  assert.equal(await firstTab.getByLabel("Units", { exact: true }).inputValue(), changedUnits);
  console.log("[ ok ] two live Settings tabs are open with the persisted preference");

  await stopOwnedService(service);
  service = null;
  running = await startService(port);
  service = running.child;
  const secondToken = sessionToken(running.html);
  assert.notEqual(secondToken, firstToken, "server restart must rotate the session token");
  const afterRestart = await readConfig(running.origin, secondToken);
  assert.equal(afterRestart.body.preferences.units, changedUnits, "saved preference must survive restart");
  assert.ok(afterRestart.etag && afterRestart.etag !== preRestartEtag,
    "new server process must establish a fresh config revision");
  console.log("[ ok ] restart rotates session identity and retains saved configuration");

  const changedUnitsAgain = changedUnits === "si" ? "iec" : "si";
  await Promise.all([
    firstTab.getByLabel("Units", { exact: true }).selectOption(changedUnitsAgain),
    secondTab.getByLabel("Units", { exact: true }).selectOption(changedUnitsAgain),
  ]);
  await Promise.all([
    firstTab.getByRole("button", { name: "Reload dashboard", exact: true }).waitFor(),
    secondTab.getByRole("button", { name: "Reload dashboard", exact: true }).waitFor(),
  ]);
  assert.equal(await firstTab.getByText("Your dashboard session expired. Pending changes were not saved; reload to reconnect.", { exact: true }).count(), 1);
  assert.equal(await secondTab.getByText("Your dashboard session expired. Pending changes were not saved; reload to reconnect.", { exact: true }).count(), 1);
  console.log("[ ok ] both real browser tabs identify the expired post-restart session");

  const firstReload = firstTab.waitForNavigation({ waitUntil: "domcontentloaded" });
  const secondReload = secondTab.waitForNavigation({ waitUntil: "domcontentloaded" });
  await Promise.all([
    firstTab.getByRole("button", { name: "Reload dashboard", exact: true }).click(),
    secondTab.getByRole("button", { name: "Reload dashboard", exact: true }).click(),
  ]);
  await Promise.all([firstReload, secondReload]);
  await Promise.all([
    firstTab.getByRole("heading", { name: "Settings", exact: true }).waitFor(),
    secondTab.getByRole("heading", { name: "Settings", exact: true }).waitFor(),
  ]);
  assert.equal(await firstTab.getByLabel("Units", { exact: true }).inputValue(), changedUnits);
  assert.equal(await secondTab.getByLabel("Units", { exact: true }).inputValue(), changedUnits);
  assert.equal(browserErrors.length, 0, browserErrors.join("\n"));
  console.log("[ ok ] both tabs reload with the new token and preserve the last saved preference");

  const expiredTokenWrite = await writeConfig(running.origin, firstToken, afterRestart.etag, afterRestart.body);
  assert.equal(expiredTokenWrite.status, 403, "pre-restart session token must be refused");
  assert.equal((await expiredTokenWrite.json()).error, "mutation authorization failed",
    "expired-session response must be recognizable by the dashboard");
  console.log("[ ok ] pre-restart token returns the expired-session refusal");

  const changedTheme = afterRestart.body.preferences.theme === "dark" ? "light" : "dark";
  const staleWrite = await writeConfig(running.origin, secondToken, preRestartEtag, {
    ...afterRestart.body,
    preferences: { ...afterRestart.body.preferences, theme: changedTheme },
  });
  assert.equal(staleWrite.status, 412, "pre-restart ETag must not authorize a write");
  const afterStaleWrite = await readConfig(running.origin, secondToken);
  assert.equal(afterStaleWrite.body.preferences.units, changedUnits);
  assert.notEqual(afterStaleWrite.body.preferences.theme, changedTheme,
    "stale conditional write must not modify persisted configuration");
  console.log("[ ok ] stale pre-restart ETag is rejected without changing configuration");

  const freshWriteBody = {
    ...afterStaleWrite.body,
    preferences: { ...afterStaleWrite.body.preferences, theme: changedTheme },
  };
  const freshWrite = await writeConfig(running.origin, secondToken, afterStaleWrite.etag, freshWriteBody);
  assert.equal(freshWrite.status, 200, "fresh post-restart ETag must permit a write");
  const final = await readConfig(running.origin, secondToken);
  assert.equal(final.body.preferences.theme, changedTheme);
  console.log("[ ok ] conditional writes recover with the fresh post-restart revision");

  await writeFile(join(profile, "config.json"), "{ invalid", "utf8");
  const afterCorruptEdit = await readConfig(running.origin, secondToken);
  assert.ok(Number.isInteger(afterCorruptEdit.body.version) && Array.isArray(afterCorruptEdit.body.rules),
    "a corrupt config file must resolve to a usable default object");
  assert.notEqual(afterCorruptEdit.etag, final.etag,
    "corrupt-file fallback must not reuse the prior saved revision");
  console.log("[ ok ] corrupt config resolves to a usable default with a new ETag");

  const staleCorruptWrite = await writeConfig(running.origin, secondToken, final.etag, {
    ...final.body,
    externalEditProbe: "stale-corrupt-write",
  });
  assert.equal(staleCorruptWrite.status, 412,
    "a pre-corruption ETag must not authorize a write over the fallback state");
  console.log("[ ok ] stale writes are refused after corrupt-file fallback");
  console.log("13 isolated server-restart checks passed.");
} finally {
  if (browser) await browser.close();
  await stopOwnedService(service);
  const scratchPath = resolve(scratch);
  const tempPath = resolve(tmpdir());
  if (!scratchPath.startsWith(tempPath + sep) || basename(scratchPath) !== basename(scratch) ||
      !basename(scratchPath).startsWith("wintcp-webui-restart-")) {
    throw new Error("Refusing to remove an unexpected isolated test directory");
  }
  await rm(scratchPath, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}
