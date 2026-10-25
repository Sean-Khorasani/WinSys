// Headless end-to-end replay acceptance. Creates and removes one local fixture archive.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readdir, lstat, unlink, rmdir } from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import { chromium } from "playwright";

const args = process.argv.slice(2);
const urlIndex = args.indexOf("--url");
if (urlIndex < 0 || !args[urlIndex + 1]) {
  console.error("usage: node incident-replay-ui-check.mjs --url http://127.0.0.1:PORT/");
  process.exit(2);
}
const base = new URL(args[urlIndex + 1]);
assert.equal(base.protocol, "http:");
assert.equal(base.hostname, "127.0.0.1", "replay fixture must remain loopback-only");
base.pathname = "/";
base.search = "";
base.hash = "";
const root = base.toString().replace(/\/$/, "");
const origin = base.origin;
const html = await (await fetch(root + "/")).text();
const token = html.match(/name="wintcp-api-token"\s+content="([a-f0-9]{64})"/)?.[1];
assert.ok(token, "Web UI session token must be present");

async function get(urlPath, authorized = true) {
  const headers = authorized ? { "X-WinTCP-Token": token } : {};
  const response = await fetch(root + urlPath, { headers });
  return { response, body: await response.json() };
}

async function post(fields) {
  const response = await fetch(root + "/api/engine/incidents", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded",
      "X-WinTCP-Token": token, Origin: origin },
    body: new URLSearchParams(fields),
  });
  return { response, body: await response.json() };
}

function requestId() { return randomUUID().replaceAll("-", ""); }
function waitForConnection(port) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: "127.0.0.1", port });
    const timer = setTimeout(() => { socket.destroy(); reject(new Error("fixture connection timed out")); }, 5000);
    socket.once("connect", () => { clearTimeout(timer); resolve(socket); });
    socket.once("error", (error) => { clearTimeout(timer); reject(error); });
  });
}

const before = await get("/api/engine/incidents");
assert.equal(before.response.status, 200);
assert.equal(before.body.armed, false, "refusing to disturb an armed recorder");
assert.equal(before.body.incident, null, "refusing to overwrite an existing incident");
const server = net.createServer((socket) => socket.end());
await new Promise((resolve, reject) => {
  server.once("error", reject);
  server.listen(0, "127.0.0.1", resolve);
});
const port = server.address().port;
const tempRoot = path.resolve(process.env.LOCALAPPDATA, "WinTCP", "Engine", "Incidents");
let armed = false;
let browser;
let page;
let archivePath = null;
const requestedDuringReplay = [];
let portableExport = null;
try {
  const armedReply = await post({ action: "arm", requestId: requestId() });
  assert.equal(armedReply.response.status, 202);
  armed = true;
  const trigger = await post({ action: "trigger", requestId: requestId(),
    triggerId: `replay-ui-${randomUUID().slice(0, 8)}`,
    reason: "read-only replay UI fixture" });
  assert.equal(trigger.response.status, 202);
  const socket = await waitForConnection(port);
  await new Promise((resolve) => setTimeout(resolve, 2200));
  const statusBrowser = await chromium.launch({ headless: true });
  const statusPage = await statusBrowser.newPage();
  await statusPage.goto(`${root}/#/automations`, { waitUntil: "networkidle" });
  await statusPage.getByRole("tab", { name: "Event history" }).click();
  await statusPage.getByText(/Observed pre-trigger span/).waitFor({ timeout: 10000 });
  const incidentStatusText = await statusPage.getByText(/Observed pre-trigger span/).textContent();
  assert.match(incidentStatusText,
    /Observed pre-trigger span \d+\.\d+s of \d+\.\d+s requested/,
    "the UI must show measured retained pre-trigger duration beside the requested window");
  await statusBrowser.close();
  socket.destroy();
  const stopped = await post({ action: "disarm", requestId: requestId() });
  assert.equal(stopped.response.status, 202);
  armed = false;
  const saved = await post({ action: "save", requestId: requestId() });
  assert.equal(saved.response.status, 202);
  assert.equal(saved.body.durable, true);
  assert.match(saved.body.archiveId, /^[a-f0-9]{32}$/);
  archivePath = path.resolve(tempRoot, `incident-${saved.body.archiveId}`);
  assert.equal(path.dirname(archivePath), tempRoot);
  const portableRecords = [];
  let portableManifest = null;
  let portableOffset = 0;
  for (let pageNumber = 0; pageNumber < 100; pageNumber++) {
    const archivePage = await get(`/api/engine/incidents/archives/${saved.body.archiveId}?offset=${portableOffset}&limit=100`);
    assert.equal(archivePage.response.status, 200);
    portableManifest ||= archivePage.body.manifest;
    portableRecords.push(...archivePage.body.items);
    if (!archivePage.body.hasMore) break;
    assert.ok(archivePage.body.nextOffset > portableOffset);
    portableOffset = archivePage.body.nextOffset;
    assert.ok(pageNumber < 99, "fixture archive pagination must be bounded");
  }
  portableExport = { schemaVersion: 1, exportProfile: "full",
    manifest: portableManifest, records: portableRecords };
  assert.equal(portableRecords.length, portableManifest.recordCount);

  browser = await chromium.launch({ headless: true });
  page = await browser.newPage();
  await page.goto(`${root}/#/automations`, { waitUntil: "networkidle" });
  await page.getByRole("tab", { name: "Event history" }).click();
  await page.locator('select[aria-label="Saved incident archive"]').selectOption(saved.body.archiveId);
  await page.on("request", (request) => requestedDuringReplay.push({
    method: request.method(), url: request.url(),
  }));
  await page.getByRole("button", { name: "Load read-only replay" }).click();
  await page.waitForFunction(() =>
    document.querySelector(".incident-replay")?.textContent.includes("Loaded "),
  null, { timeout: 15000 });
  const replay = page.locator(".incident-replay");
  assert.match(await replay.textContent(), /Why this was captured: read-only replay UI fixture/);
  assert.match(await replay.textContent(), /Complete snapshot-only state|Partial snapshot-only state/);
  assert.match(await replay.textContent(), /Recorded events up to this position/);
  const slider = replay.locator('input[type="range"]');
  const earliestEvidenceCount = Number((await replay.textContent()).match(/(\d+) non-checkpoint event\(s\) occurred by this replay position/)?.[1]);
  await slider.evaluate((element) => {
    element.value = "1000";
    element.dispatchEvent(new Event("input", { bubbles: true }));
  });
  assert.match(await replay.textContent(), /Recorded position \+/);
  const latestEvidenceCount = Number((await replay.textContent()).match(/(\d+) non-checkpoint event\(s\) occurred by this replay position/)?.[1]);
  assert.ok(Number.isFinite(earliestEvidenceCount) && latestEvidenceCount >= earliestEvidenceCount,
    "historical event evidence must advance with the selected replay position");

  const play = replay.getByRole("button", { name: "Play" });
  if (await play.isEnabled()) {
    await slider.evaluate((element) => {
      element.value = "0";
      element.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await play.click();
    await replay.getByRole("button", { name: "Pause" }).waitFor({ state: "visible", timeout: 1000 });
    await replay.getByRole("button", { name: "Pause" }).click();
  }
  await replay.getByRole("searchbox", { name: "Filter replay endpoints" }).fill("no-match-for-fixture");
  assert.match(await replay.textContent(), /No endpoints match the current replay filters/);
  const replayButtonLabels = await replay.locator("button").allTextContents();
  assert.ok(replayButtonLabels.every((label) => !/block|close|lookup|resolve/i.test(label)),
    "replay exposes no live action or external lookup button");
  assert.ok(requestedDuringReplay.every((request) => new URL(request.url).origin === origin),
    "offline replay must not make external requests");
  assert.ok(requestedDuringReplay.every((request) => request.method === "GET" || request.method === "HEAD"),
    "replay must not issue a mutation request");
  const requestCountBeforeImport = requestedDuringReplay.length;
  portableExport.manifest.triggers[0].reason = '<img src=x onerror="alert(1)">';
  await page.locator('input[aria-label="Import incident export"]').setInputFiles({
    name: "untrusted-fixture.json", mimeType: "application/json",
    buffer: Buffer.from(JSON.stringify(portableExport)),
  });
  await page.waitForFunction(() =>
    document.querySelector('[aria-label="Offline incident replay"]')?.textContent.includes("untrusted record(s)"),
  null, { timeout: 15000 });
  const importedReplay = page.locator('[aria-label="Offline incident replay"]');
  assert.match(await importedReplay.textContent(), /untrusted record\(s\)/);
  assert.match(await page.locator('[role="status"]').allTextContents().then((items) => items.join(" ")),
    /Imported untrusted-fixture\.json as untrusted, read-only evidence/);
  assert.match(await importedReplay.textContent(), /<img src=x onerror=/,
    "untrusted trigger metadata must remain inert text");
  assert.equal(await importedReplay.locator("img").count(), 0,
    "imported metadata must not become executable markup");
  assert.ok(requestedDuringReplay.slice(requestCountBeforeImport)
    .every((request) => request.method === "GET" || request.method === "HEAD"),
  "import must not upload or mutate imported content");
  assert.ok(requestedDuringReplay.every((request) => new URL(request.url).origin === origin),
    "replay and import must not make external requests");
  console.log("incident-replay-ui-test=PASS prehistoryDuration=true localArchive=true loaded=true triggerReason=true scrub=true timelineEvidence=true playback=true filters=true readOnly=true sameOriginOnly=true noMutation=true importValidated=true importLocalOnly=true");
} finally {
  if (armed) await post({ action: "disarm", requestId: requestId() }).catch(() => {});
  const status = await get("/api/engine/incidents").catch(() => null);
  if (status?.body?.incident && status.body.incident.active === false)
    await post({ action: "discard", requestId: requestId() }).catch(() => {});
  if (page) await page.close().catch(() => {});
  if (browser) await browser.close().catch(() => {});
  await new Promise((resolve) => server.close(resolve));
  if (archivePath) {
    const info = await lstat(archivePath).catch(() => null);
    if (info?.isDirectory() && !info.isSymbolicLink()) {
      for (const name of await readdir(archivePath)) {
        if (!["manifest.json", "events.ndjson", "checkpoints.ndjson", "index.json", "pinned.txt"].includes(name))
          throw new Error(`refusing to remove unexpected archive content: ${name}`);
        await unlink(path.join(archivePath, name));
      }
      await rmdir(archivePath);
    }
  }
}
