// Volatile engine incident-recorder acceptance check.
// Uses only a disposable loopback TCP socket and clears its in-memory fixture.
import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { readdir, readFile, writeFile, lstat, unlink, rmdir } from "node:fs/promises";
import net from "node:net";
import path from "node:path";

const args = process.argv.slice(2);
const urlIndex = args.indexOf("--url");
if (urlIndex < 0 || !args[urlIndex + 1]) {
  console.error("usage: node incident-recorder-check.mjs --url http://127.0.0.1:PORT/");
  process.exit(2);
}
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

  const socket = await waitForSocket(Number(base.port));
  await new Promise((resolve) => setTimeout(resolve, 1800));
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
  assert.equal(manifest.replayReady, false, "archive must not claim replay without state checkpoints");
  assert.match(eventText, /"kind":"endpoint_observed"/);
  assert.equal(manifest.sha256["events.ndjson"], createHash("sha256").update(eventText).digest("hex"));
  assert.equal(manifest.sha256["checkpoints.ndjson"], createHash("sha256").update(checkpointText).digest("hex"));
  assert.equal(manifest.sha256["index.json"], createHash("sha256").update(indexText).digest("hex"));

  const archiveList = await get("/api/engine/incidents/archives?limit=50");
  assert.equal(archiveList.response.status, 200);
  assert.ok(archiveList.body.items.some((item) => item.id === saved.body.archiveId),
    "saved archive should be discoverable after finalization");
  const replayPage = await get(`/api/engine/incidents/archives/${saved.body.archiveId}?offset=0&limit=100`);
  assert.equal(replayPage.response.status, 200);
  assert.equal(replayPage.body.manifest.replayReady, false);
  assert.ok(replayPage.body.items.some((item) =>
    item.event?.source === "snapshot" &&
    item.event?.kind === "endpoint_observed"),
  "read-only archive page should return the recorded loopback observation");
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
  console.log("incident-recorder-test=PASS token=true arm=true trigger=true sampledLoopback=true explicitArchive=true hashes=true archiveList=true readOnlyArchivePage=true tamperRejected=true replayClaimHonest=true fixtureDiscarded=true");
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
      await rmdir(archivePath);
    }
  }
}
