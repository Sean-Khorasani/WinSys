// Quick, non-privileged restriction API checks. Never starts the collector,
// requests elevation, or applies a filter. Requires a running Web UI and engine.
import { randomUUID } from "node:crypto";

const args = process.argv.slice(2);
const index = args.indexOf("--url");
if (index < 0 || !args[index + 1]) throw new Error("Pass --url http://127.0.0.1:PORT/");
const base = new URL(args[index + 1]);
if (base.hostname !== "127.0.0.1" || base.protocol !== "http:")
  throw new Error("Only the loopback Web UI is supported");
const html = await (await fetch(base)).text();
const token = html.match(/name="wintcp-api-token"\s+content="([^"]+)"/)?.[1];
if (!token) throw new Error("Web UI session token missing");
let checks = 0;
function check(condition, message) {
  if (!condition) throw new Error(message);
  checks++;
}
async function post(path, fields, authorized = true) {
  return fetch(new URL(path, base), {
    method: "POST",
    headers: { Origin: base.origin, ...(authorized ? { "X-WinTCP-Token": token } : {}) },
    body: new URLSearchParams(fields),
  });
}
check((await fetch(new URL("/api/restrictions", base))).status === 403,
  "Restriction history must require the session token");
check((await fetch(new URL("/api/restrictions/history", base))).status === 403,
  "Durable restriction outcomes must require the session token");
check((await fetch(new URL("/api/engine/lifecycle", base))).status === 403,
  "Lifecycle evidence must require the session token");
const lifecycleResponse = await fetch(new URL("/api/engine/lifecycle?limit=5", base),
  { headers: { "X-WinTCP-Token": token } });
const lifecycle = await lifecycleResponse.json();
check(lifecycleResponse.status === 200 && Array.isArray(lifecycle.items) &&
  typeof lifecycle.nextCursor === "string" && lifecycle.coverage?.source === "etw_raw",
  `Lifecycle history must remain queryable without enabling a privileged collector: ${JSON.stringify({
    status: lifecycleResponse.status, keys: Object.keys(lifecycle), coverage: lifecycle.coverage,
    code: lifecycle.code,
  })}`);
const outcomes = await fetch(new URL("/api/restrictions/history?limit=5", base),
  { headers: { "X-WinTCP-Token": token } });
const history = await outcomes.json();
check(outcomes.status === 200 && history.schemaVersion === 1 &&
  Array.isArray(history.items) && typeof history.nextCursor === "string",
  "Outcome history must use the shared paginated engine contract");
const engine = await (await fetch(new URL("/api/engine", base),
  { headers: { "X-WinTCP-Token": token } })).json();
const recipes = await (await fetch(new URL("/api/engine/recipes", base),
  { headers: { "X-WinTCP-Token": token } })).json();
const eventsResponse = await fetch(new URL("/api/engine/events?limit=5", base),
  { headers: { "X-WinTCP-Token": token } });
const events = await eventsResponse.json();
const capability = engine.capabilities?.find((item) => item.id === "restrictions.temporary");
const tcp = engine.capabilities?.find((item) => item.id === "events.tcpLifecycle");
check(eventsResponse.status === 200 && Array.isArray(events.items) &&
  events.coverage?.source === "snapshot+etw_lifecycle" &&
  typeof events.coverage.loss === "boolean",
  `Shared event history must identify both data sources and its loss state: ${JSON.stringify({
    status: eventsResponse.status, coverage: events.coverage, code: events.code,
  })}`);
check(tcp?.supported === true && tcp.available === false &&
  typeof tcp.reason === "string" && tcp.reason.length > 0,
  "Unavailable lifecycle collection must report why normalized actions are not ready");
if (tcp?.enabled === true)
  check(tcp.available === true,
    "A running lifecycle source must be available before its first event, so reactive recipes can pre-arm");
check(typeof recipes.activeActionQueueLosses === "string" &&
  typeof recipes.activeActionFailures === "string" &&
  Array.isArray(recipes.items) && recipes.items.every((item) =>
  typeof item.runtime?.restrictionPreviouslyApplied === "boolean" &&
  typeof item.runtime?.activeActionGrant === "boolean"),
  "Recipe runtime reports whether a restriction was previously applied");
check(capability?.supported === true && capability.requiresElevation === true &&
  (capability.available || typeof capability.reason === "string" && capability.reason.length > 0),
  "Restriction capability must report collector readiness rather than not_implemented");
check((await post("/api/collector/control", { action: "start", requestId: "unauthorized" }, false)).status === 403,
  "Unauthorized control must be rejected before any elevation request");
check((await post("/api/collector/control", {
  action: "arm-reactive", requestId: randomUUID().replaceAll("-", ""),
})).status === 400,
  "Reactive arming must reject incomplete scope and budget fields before queueing");
const armRequestId = randomUUID().replaceAll("-", "");
const armResponse = await post("/api/collector/control", {
  requestId: armRequestId, action: "arm-reactive",
  imagePath: "C:\\WinTCP-fixture-does-not-exist\\probe.exe",
  remoteAddress: "", remotePort: "0", protocol: "both", minutes: "1",
  owner: "recipe:missing-monitor", recipeRevision: "1", grantMinutes: "1",
  maxActions: "1", cumulativeMinutes: "1",
});
const armQueued = await armResponse.json();
check(armResponse.status === 202 && typeof armQueued.operationId === "string",
  "A well-formed reactive arm request enters the shared operation journal");
let armResult;
for (let attempt = 0; attempt < 30; ++attempt) {
  const result = await fetch(new URL(`/api/engine/operations/${armQueued.operationId}`, base),
    { headers: { "X-WinTCP-Token": token } });
  armResult = await result.json();
  if (["succeeded", "failed"].includes(armResult.status)) break;
  await new Promise((resolve) => setTimeout(resolve, 100));
}
check(armResult?.status === "failed" &&
  armResult.error?.code === "recipe_not_enabled_or_target_changed" &&
  armResult.audit?.recorded === true,
  "Reactive arming refuses an absent recipe without contacting the collector and records the outcome");
const requestId = randomUUID().replaceAll("-", "");
const fields = { requestId, imagePath: "C:\\WinTCP-fixture-does-not-exist\\probe.exe",
  remoteAddress: "", remotePort: "0", protocol: "both", minutes: "1" };
const response = await post("/api/restrictions/preview", fields);
check(response.status === 202, `Preview should enqueue immediately: HTTP ${response.status}`);
const submitted = await response.json();
check(typeof submitted.operationId === "string", "Enqueued preview must have an operation ID");
const duplicate = await post("/api/restrictions/preview", fields);
check(duplicate.status === 202 && (await duplicate.json()).operationId === submitted.operationId,
  "Retried request must return the same operation");
check((await post("/api/restrictions/preview", { ...fields, minutes: "5" })).status === 409,
  "Reusing a request ID for a different plan must conflict");
let terminal;
for (let attempt = 0; attempt < 30; ++attempt) {
  const result = await fetch(new URL(`/api/engine/operations/${submitted.operationId}`, base),
    { headers: { "X-WinTCP-Token": token } });
  const operation = await result.json();
  if (["succeeded", "failed"].includes(operation.status)) { terminal = operation; break; }
  await new Promise((resolve) => setTimeout(resolve, 100));
}
check(terminal?.status === "failed" && terminal.result === null &&
  ["collector_unavailable", "target_executable_unavailable"].includes(terminal.error?.code),
  "Missing collector/fixture must fail explicitly without returning an approval");
check(terminal.audit?.recorded === true && terminal.audit.error === null,
  "Queued command request and outcome must be durably audited");
console.log(`[restrictions] ${checks} safe API checks passed`);
