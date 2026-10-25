// Verify an enabled Passive recipe can trigger an armed local incident recorder.
// Uses a disposable same-host TCP peer on a non-loopback interface and restores
// the previously empty recipe/incident state on every exit path.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import net from "node:net";
import os from "node:os";

const args = process.argv.slice(2);
const urlIndex = args.indexOf("--url");
if (urlIndex < 0 || !args[urlIndex + 1]) {
  console.error("usage: node incident-recipe-trigger-check.mjs --url http://127.0.0.1:PORT/");
  process.exit(2);
}
const base = new URL(args[urlIndex + 1]);
assert.equal(base.protocol, "http:");
assert.equal(base.hostname, "127.0.0.1", "integration fixture must use loopback Web UI");
base.pathname = "/";
base.search = "";
base.hash = "";
const root = base.toString().replace(/\/$/, "");
const origin = base.origin;
const html = await (await fetch(root + "/")).text();
const token = html.match(/name="wintcp-api-token"\s+content="([a-f0-9]{64})"/)?.[1];
assert.ok(token, "Web UI session token must be present");

async function get(path) {
  const response = await fetch(root + path, { headers: { "X-WinTCP-Token": token } });
  return { response, body: await response.json() };
}

async function post(path, fields) {
  const response = await fetch(root + path, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded",
      "X-WinTCP-Token": token, Origin: origin },
    body: new URLSearchParams(fields),
  });
  return { response, body: await response.json() };
}

const requestId = () => randomUUID().replaceAll("-", "");
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const interfaces = Object.values(os.networkInterfaces()).flat().filter((row) =>
  row && row.family === "IPv4" && !row.internal && !row.address.startsWith("169.254."));
assert.ok(interfaces.length, "a non-loopback IPv4 interface is required for the local peer fixture");
const localAddress = interfaces[0].address;
const recipesBefore = await get("/api/engine/recipes");
assert.equal(recipesBefore.response.status, 200);
assert.deepEqual(recipesBefore.body.items, [],
  "refusing to modify user recipes; this isolated check requires an empty recipe store");
const incidentBefore = await get("/api/engine/incidents");
assert.equal(incidentBefore.response.status, 200);
assert.equal(incidentBefore.body.armed, false, "refusing to disturb an armed recorder");
assert.equal(incidentBefore.body.incident, null, "refusing to overwrite a current incident");

const recipeId = `i1-trigger-${randomUUID().replaceAll("-", "").slice(0, 12)}`;
const recipeName = "I1 recipe-to-recorder integration fixture";
const hex = (value) => Buffer.from(value, "utf8").toString("hex");
const recipeText = (revision, enabled) => "WinTCP-Recipes:1\n" + [
  recipeId, revision, enabled ? "1" : "0", "outbound_activity", "0",
  hex(recipeName), hex(process.execPath),
].join("|") + "\n";
let recipeStoreModified = false;
let recipeRevision = recipesBefore.body.revision;
let recorderArmed = false;
let server;
let client;

async function saveRecipes(expectedRevision, value) {
  const submitted = await post("/api/engine/recipes", {
    requestId: requestId(), expectedRevision, recipesText: value,
  });
  assert.equal(submitted.response.status, 202,
    `recipe config should queue successfully: ${submitted.body.code || submitted.response.status}`);
  assert.ok(submitted.body.operationId);
  let operation;
  for (let attempt = 0; attempt < 120; attempt++) {
    const result = await get(`/api/engine/operations/${submitted.body.operationId}`);
    operation = result.body;
    if (operation.status === "succeeded" || operation.status === "failed") break;
    await sleep(250);
  }
  assert.equal(operation?.status, "succeeded", operation?.error?.code || "recipe operation timed out");
  assert.ok(operation.result?.revision, "successful recipe update must return its new revision");
  return operation.result.revision;
}

try {
  recipeStoreModified = true;
  recipeRevision = await saveRecipes(recipeRevision, recipeText("1", false));
  recipeRevision = await saveRecipes(recipeRevision, recipeText("2", true));
  await sleep(1300); // Let the enabled recipe see one stable baseline before the fixture flow.

  const armed = await post("/api/engine/incidents", {
    action: "arm", requestId: requestId(),
  });
  assert.equal(armed.response.status, 202);
  recorderArmed = true;

  server = net.createServer((socket) => { socket.on("error", () => {}); });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, localAddress, resolve);
  });
  client = net.createConnection({ host: localAddress, port: server.address().port });
  client.on("error", () => {});
  await new Promise((resolve, reject) => {
    client.once("connect", resolve);
    client.once("error", reject);
  });

  let captured = null;
  for (let attempt = 0; attempt < 40; attempt++) {
    const status = await get("/api/engine/incidents");
    assert.equal(status.response.status, 200);
    if (status.body.incident?.whyCaptured?.reason?.includes(recipeName)) {
      captured = status.body.incident;
      break;
    }
    await sleep(250);
  }
  assert.ok(captured, "enabled recipe firing should trigger the armed incident recorder");
  assert.match(captured.whyCaptured.reason, /outbound_tcp_connection_established|new_remote_tcp_endpoint/);
  let foundEvidence = false;
  let offset = 0;
  for (let pageNumber = 0; pageNumber < 100; pageNumber++) {
    const records = await get(`/api/engine/incidents?offset=${offset}&limit=100`);
    assert.equal(records.response.status, 200);
    foundEvidence = records.body.incident?.items?.some((item) =>
      item.event?.source === "snapshot" && item.event?.kind === "endpoint_observed" &&
      item.event?.remote?.address === localAddress) || foundEvidence;
    if (foundEvidence || !records.body.incident?.hasMore) break;
    assert.ok(records.body.incident.nextOffset > offset,
      "incident evidence pagination must advance");
    offset = records.body.incident.nextOffset;
  }
  assert.ok(foundEvidence,
  "the triggering endpoint evidence should be retained with the recipe-generated trigger");

  let foundNotification = false;
  let cursor = "";
  for (let pageNumber = 0; pageNumber < 100; pageNumber++) {
    const notifications = await get(`/api/engine/notifications?limit=500${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`);
    assert.equal(notifications.response.status, 200);
    foundNotification = notifications.body.items?.some((item) => item.recipeId === recipeId) || foundNotification;
    if (foundNotification || !notifications.body.nextCursor ||
        notifications.body.nextCursor === cursor) break;
    cursor = notifications.body.nextCursor;
  }
  assert.ok(foundNotification,
    "the same recipe fire should retain its ordinary Passive notification");
  console.log("incident-recipe-trigger-test=PASS passiveRecipe=true armedRecorderTriggered=true evidenceRetained=true notificationRetained=true cleanup=true");
} finally {
  client?.destroy();
  if (server?.listening) await new Promise((resolve) => server.close(resolve));
  if (recorderArmed) {
    const status = await get("/api/engine/incidents").catch(() => null);
    if (status?.body?.armed)
      await post("/api/engine/incidents", { action: "disarm", requestId: requestId() }).catch(() => {});
    const after = await get("/api/engine/incidents").catch(() => null);
    if (after?.body?.incident && after.body.incident.active === false)
      await post("/api/engine/incidents", { action: "discard", requestId: requestId() }).catch(() => {});
  }
  if (recipeStoreModified) {
    const current = await get("/api/engine/recipes").catch(() => null);
    if (current?.body?.revision)
      await saveRecipes(current.body.revision, "WinTCP-Recipes:1\n");
  }
}

const recipesAfter = await get("/api/engine/recipes");
assert.deepEqual(recipesAfter.body.items, [], "recipe fixture must be removed after verification");
const incidentAfter = await get("/api/engine/incidents");
assert.equal(incidentAfter.body.armed, false, "incident recorder must be disarmed after verification");
assert.equal(incidentAfter.body.incident, null, "incident fixture must be discarded after verification");
