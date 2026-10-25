// Volatile engine incident-recorder acceptance check.
// Uses only a disposable loopback TCP socket and clears its in-memory fixture.
import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { readdir, readFile, writeFile, lstat, unlink, rmdir } from "node:fs/promises";
import net from "node:net";
import path from "node:path";

const args = process.argv.slice(2);
const urlIndex = args.indexOf("--url");
const durationIndex = args.indexOf("--soak-seconds");
if (urlIndex < 0 || !args[urlIndex + 1]) {
  console.error("usage: node incident-recorder-check.mjs --url http://127.0.0.1:PORT/ [--soak-seconds 6..120]");
  process.exit(2);
}
const soakSeconds = durationIndex < 0 ? 6 : Number(args[durationIndex + 1]);
assert.ok(Number.isInteger(soakSeconds) && soakSeconds >= 6 && soakSeconds <= 120,
  "soak duration must be an integer from 6 through 120 seconds");
const base = new URL(args[urlIndex + 1]);
assert.equal(base.protocol, "http:");
assert.equal(base.hostname, "127.0.0.1", "test is loopback-only");
base.pathname = "/";
base.search = "";
base.hash = "";
const origin = base.origin;
const root = base.toString().replace(/\/$/, "");
const html = await (await fetch(root + "/")).text();
const token = html.match(/name="wintcp-api-token"\s+content="([a-f0-9]{64})"/)?.[1];
assert.ok(token, "Web UI session token must be present");

async function get(path, authorized = true) {
  const headers = authorized ? { "X-WinTCP-Token": token } : {};
  const response = await fetch(root + path, { headers });
  const body = await response.json();
  return { response, body };
}

async function post(fields) {
  const response = await fetch(root + "/api/engine/incidents", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "X-WinTCP-Token": token,
      Origin: origin,
    },
    body: new URLSearchParams(fields),
  });
  return { response, body: await response.json() };
}

async function archiveMutation(id, action, requestId = randomUUID().replaceAll("-", "")) {
  const response = await fetch(`${root}/api/engine/incidents/archives/${id}/${action}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "X-WinTCP-Token": token,
      Origin: origin,
    },
    body: new URLSearchParams({ requestId }),
  });
  return { response, body: await response.json(), requestId };
}

function waitForSocket(port) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: "127.0.0.1", port });
    const timeout = setTimeout(() => {
      socket.destroy();
      reject(new Error("loopback fixture socket did not connect"));
    }, 5000);
    socket.once("connect", () => {
      clearTimeout(timeout);
      resolve(socket);
    });
    socket.once("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
  });
}

const initial = await get("/api/engine/incidents", false);
assert.equal(initial.response.status, 403, "incident status must require the session token");
const privateArchiveList = await get("/api/engine/incidents/archives", false);
assert.equal(privateArchiveList.response.status, 403, "archive library must require the session token");
const current = await get("/api/engine/incidents");
assert.equal(current.response.status, 200);
assert.equal(current.body.armed, false, "refusing to disturb an already-armed recorder");
assert.equal(current.body.incident, null, "refusing to overwrite an existing incident");

let armed = false;
let archivePath = null;
let savedCheckpointCount = 0;
let triggerId = `incident-check-${randomUUID().slice(0, 8)}`;
try {
  const armedResult = await post({ action: "arm", requestId: randomUUID().replaceAll("-", "") });
  assert.equal(armedResult.response.status, 202);
  assert.equal(armedResult.body.armed, true);
  armed = true;

  const trigger = await post({
    action: "trigger",
    requestId: randomUUID().replaceAll("-", ""),
    triggerId,
    reason: "loopback acceptance fixture",
  });
  assert.equal(trigger.response.status, 202);
  assert.equal(trigger.body.incident?.active, true);
  assert.equal(trigger.body.incident?.whyCaptured?.reason,
    "loopback acceptance fixture");
  assert.ok(/^\d+$/.test(trigger.body.incident?.prehistoryWindowNs || ""));
  assert.ok(/^\d+$/.test(trigger.body.incident?.prehistoryRetainedNs || ""));
  assert.ok(BigInt(trigger.body.incident.prehistoryRetainedNs) <=
    BigInt(trigger.body.incident.prehistoryWindowNs),
  "reported retained prehistory span must not exceed the requested capture window");

  const socket = await waitForSocket(Number(base.port));
  // Cross one or more checkpoint intervals to verify ongoing capture rather
  // than merely serializing the arm-time baseline.
  const captureStartedAt = Date.now();
  let nextExtensionMs = 20000;
  while (Date.now() - captureStartedAt < soakSeconds * 1000) {
    const elapsedMs = Date.now() - captureStartedAt;
    await new Promise((resolve) => setTimeout(resolve,
      Math.min(1000, Math.max(1, nextExtensionMs - elapsedMs),
        soakSeconds * 1000 - elapsedMs)));
    const elapsedAfterWait = Date.now() - captureStartedAt;
    if (elapsedAfterWait < soakSeconds * 1000 && elapsedAfterWait >= nextExtensionMs) {
      const extension = await post({ action: "trigger",
        requestId: randomUUID().replaceAll("-", ""),
        triggerId: `incident-soak-${Math.floor(nextExtensionMs / 20000)}`,
        reason: "sustained recorder acceptance" });
      assert.equal(extension.response.status, 202,
        "a related trigger should extend the bounded post-trigger capture window");
      nextExtensionMs += 20000;
    }
  }
  const page = await get("/api/engine/incidents?offset=0&limit=100");
  assert.equal(page.response.status, 200);
  assert.ok(page.body.incident?.items?.some((item) =>
    item.event?.source === "snapshot" && item.event?.kind === "endpoint_observed"),
  "engine sampling should place a real loopback endpoint in the incident window");
  socket.destroy();

  const disarmed = await post({ action: "disarm", requestId: randomUUID().replaceAll("-", "") });
  assert.equal(disarmed.response.status, 202);
  armed = false;
  assert.equal(disarmed.body.incident?.active, false);
  assert.equal(disarmed.body.incident?.postWindowIncomplete, true,
    "an early stop must be labeled as a partial post-trigger window");

  const saved = await post({ action: "save", requestId: randomUUID().replaceAll("-", "") });
  assert.equal(saved.response.status, 202);
  assert.equal(saved.body.durable, true, "explicit save should finalize an archive");
  assert.match(saved.body.archiveId, /^[a-f0-9]{32}$/);
  const localAppData = process.env.LOCALAPPDATA;
  assert.ok(localAppData, "LOCALAPPDATA is required to inspect the local archive");
  const archiveRoot = path.resolve(localAppData, "WinTCP", "Engine", "Incidents");
  archivePath = path.resolve(archiveRoot, `incident-${saved.body.archiveId}`);
  assert.equal(path.dirname(archivePath), archiveRoot, "archive path must remain in its generated root");
  const archiveStat = await lstat(archivePath);
  assert.ok(archiveStat.isDirectory() && !archiveStat.isSymbolicLink());
  const files = await readdir(archivePath);
  assert.deepEqual(files.sort(), ["checkpoints.ndjson", "events.ndjson", "index.json", "manifest.json"]);
  const manifestText = await readFile(path.join(archivePath, "manifest.json"), "utf8");
  const manifest = JSON.parse(manifestText);
  const eventText = await readFile(path.join(archivePath, "events.ndjson"), "utf8");
  const checkpointText = await readFile(path.join(archivePath, "checkpoints.ndjson"), "utf8");
  const indexText = await readFile(path.join(archivePath, "index.json"), "utf8");
  assert.equal(manifest.complete, true);
  assert.equal(manifest.replayReady, true,
    "archive with captured checkpoint records should be eligible for offline replay");
  assert.ok(Number(manifest.checkpointCount) > 0,
    "incident should persist periodic state checkpoints separately from deltas");
  assert.equal(typeof manifest.checkpointStateComplete, "boolean",
    "archive should state whether retained checkpoint snapshots are complete");
  assert.equal(manifest.replayUnavailableReason, null);
  assert.ok(/^\d+$/.test(manifest.prehistoryWindowNs || ""));
  assert.ok(/^\d+$/.test(manifest.prehistoryRetainedNs || ""));
  assert.ok(BigInt(manifest.prehistoryRetainedNs) <= BigInt(manifest.prehistoryWindowNs));
  assert.match(eventText, /"kind":"endpoint_observed"/);
  assert.match(checkpointText, /"kind":"state_checkpoint"/);
  const savedCheckpoint = JSON.parse(checkpointText.trim().split("\n")[0]).event;
  const checkpointRecords = checkpointText.trim().split("\n").map((line) => JSON.parse(line));
  savedCheckpointCount = checkpointRecords.length;
  assert.ok(checkpointRecords.length >= Math.max(2, Math.floor(soakSeconds / 5)),
    "capture should persist the arm-time checkpoint and periodic checkpoints throughout the soak");
  const checkpointTimes = checkpointRecords.map((record) => BigInt(record.captureMonotonicNs));
  for (let index = 1; index < checkpointTimes.length; index++) {
    const checkpointGap = checkpointTimes[index] - checkpointTimes[index - 1];
    assert.ok(checkpointGap > 0n && checkpointGap <= 10_000_000_000n,
      "periodic checkpoints should remain ordered and bounded during sustained capture");
  }
  assert.equal(savedCheckpoint.state.coverage, "snapshot_only");
  assert.equal(savedCheckpoint.state.items.length, savedCheckpoint.state.includedEndpoints);
  assert.ok(savedCheckpoint.state.includedEndpoints <= savedCheckpoint.state.totalEndpoints);
  assert.equal(manifest.sha256["events.ndjson"], createHash("sha256").update(eventText).digest("hex"));
  assert.equal(manifest.sha256["checkpoints.ndjson"], createHash("sha256").update(checkpointText).digest("hex"));
  assert.equal(manifest.sha256["index.json"], createHash("sha256").update(indexText).digest("hex"));

  const archiveList = await get("/api/engine/incidents/archives?limit=50");
  assert.equal(archiveList.response.status, 200);
  const listedArchive = archiveList.body.items.find((item) => item.id === saved.body.archiveId);
  assert.ok(listedArchive,
    "saved archive should be discoverable after finalization");
  assert.equal(listedArchive.pinned, false);
  assert.ok(Number(listedArchive.bytes) > 0, "archive inventory should expose bounded size metadata");
  assert.match(listedArchive.createdFileTime, /^\d+$/,
    "archive inventory should expose a stable creation time for newest-first ordering");
  const deniedPin = await fetch(`${root}/api/engine/incidents/archives/${saved.body.archiveId}/pin`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: origin },
    body: new URLSearchParams({ requestId: randomUUID().replaceAll("-", "") }),
  });
  assert.equal(deniedPin.status, 403, "archive pin mutation must require a session token");
  const pinned = await archiveMutation(saved.body.archiveId, "pin");
  assert.equal(pinned.response.status, 200);
  assert.equal(pinned.body.pinned, true);
  const repeatedPin = await archiveMutation(saved.body.archiveId, "pin", pinned.requestId);
  assert.equal(repeatedPin.response.status, 200,
    "same pin request ID and signature should be idempotent");
  const conflictingPin = await archiveMutation(saved.body.archiveId, "unpin", pinned.requestId);
  assert.equal(conflictingPin.response.status, 409,
    "a pin request ID must not be reused for an unpin mutation");
  const pinnedList = await get("/api/engine/incidents/archives?limit=50");
  assert.equal(pinnedList.body.items.find((item) => item.id === saved.body.archiveId)?.pinned, true);
  const unpinned = await archiveMutation(saved.body.archiveId, "unpin");
  assert.equal(unpinned.response.status, 200);
  assert.equal(unpinned.body.pinned, false);
  const replayItems = [];
  let replayOffset = 0;
  let replayManifest;
  for (let pageNumber = 0; pageNumber < 100; pageNumber++) {
    const replayPage = await get(`/api/engine/incidents/archives/${saved.body.archiveId}?offset=${replayOffset}&limit=100`);
    assert.equal(replayPage.response.status, 200, JSON.stringify(replayPage.body));
    replayManifest = replayPage.body.manifest;
    replayItems.push(...replayPage.body.items);
    if (!replayPage.body.hasMore) break;
    assert.ok(replayPage.body.nextOffset > replayOffset,
      "archive pagination must advance while loading replay records");
    replayOffset = replayPage.body.nextOffset;
    assert.ok(pageNumber < 99, "archive pagination must be bounded");
  }
  assert.equal(replayManifest.replayReady, true);
  assert.ok(replayItems.some((item) =>
    item.event?.source === "snapshot" &&
    item.event?.kind === "endpoint_observed"),
  "read-only archive page should return the recorded loopback observation");
  assert.ok(replayItems.some((item) =>
    item.eventId === "state_checkpoint" &&
    item.event?.state?.coverage === "snapshot_only" &&
    item.event?.state?.items?.length === item.event?.state?.includedEndpoints &&
    item.event?.state?.includedEndpoints <= item.event?.state?.totalEndpoints),
  "read-only archive page should expose a structurally complete or honestly partial checkpoint");
  try {
    await writeFile(path.join(archivePath, "events.ndjson"), `${eventText} `, "utf8");
    const tampered = await get(`/api/engine/incidents/archives/${saved.body.archiveId}?offset=0&limit=100`);
    assert.equal(tampered.response.status, 422,
      "archive reader must reject content changed after its manifest hash was written");
  } finally {
    await writeFile(path.join(archivePath, "events.ndjson"), eventText, "utf8");
  }

  const discarded = await post({ action: "discard", requestId: randomUUID().replaceAll("-", "") });
  assert.equal(discarded.response.status, 202);
  assert.equal(discarded.body.incident, null);
console.log(`incident-recorder-test=PASS durationSeconds=${soakSeconds} token=true arm=true trigger=true sampledLoopback=true periodicCheckpoints=${savedCheckpointCount} explicitArchive=true hashes=true archiveList=true sizeMetadata=true pinUnpin=true pinTokenProtected=true pinRequestDeduplicated=true pinRequestConflictRejected=true readOnlyArchivePage=true tamperRejected=true replayClaimHonest=true fixtureDiscarded=true`);
} finally {
  if (armed) {
    await post({ action: "disarm", requestId: randomUUID().replaceAll("-", "") }).catch(() => {});
  }
  const status = await get("/api/engine/incidents").catch(() => null);
  if (status?.body?.incident && status.body.incident.active === false) {
    await post({ action: "discard", requestId: randomUUID().replaceAll("-", "") }).catch(() => {});
  }
  if (archivePath) {
    const archiveStat = await lstat(archivePath).catch(() => null);
    if (archiveStat?.isDirectory() && !archiveStat.isSymbolicLink()) {
      for (const name of ["manifest.json", "events.ndjson", "checkpoints.ndjson", "index.json"])
        await unlink(path.join(archivePath, name));
      await unlink(path.join(archivePath, "pinned.txt")).catch((error) => {
        if (error.code !== "ENOENT") throw error;
      });
      await rmdir(archivePath);
    }
  }
}
