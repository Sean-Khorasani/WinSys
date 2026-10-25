// Strict parser for portable incident exports. Imported content is always
// untrusted, inert evidence; this module has no network or filesystem access.
const kMaxBytes = 64 * 1024 * 1024;
const kMaxRecords = 100000;
const kMaxDepth = 64;
const kMaxNodes = 1000000;
const kUint64Max = 18446744073709551615n;

function assertSafeTree(root) {
  const pending = [{ value: root, depth: 0 }];
  let nodes = 0;
  while (pending.length) {
    const { value, depth } = pending.pop();
    if (++nodes > kMaxNodes) throw new Error("Import contains too many JSON values.");
    if (depth > kMaxDepth) throw new Error("Import JSON nesting exceeds the safety limit.");
    if (Array.isArray(value)) {
      for (const child of value) pending.push({ value: child, depth: depth + 1 });
    } else if (value && typeof value === "object") {
      for (const [key, child] of Object.entries(value)) {
        if (key === "__proto__" || key === "prototype" || key === "constructor")
          throw new Error("Import contains a prohibited object key.");
        if (key.length > 256) throw new Error("Import contains an oversized field name.");
        pending.push({ value: child, depth: depth + 1 });
      }
    }
  }
}

function uint64String(value, label) {
  if (typeof value !== "string" || !/^\d{1,20}$/.test(value))
    throw new Error(`Import ${label} must be an unsigned decimal string.`);
  const parsed = BigInt(value);
  if (parsed > kUint64Max) throw new Error(`Import ${label} exceeds the supported range.`);
  return parsed;
}

export function parseIncidentImport(text) {
  if (typeof text !== "string") throw new TypeError("Incident import must be JSON text.");
  if (new TextEncoder().encode(text).byteLength > kMaxBytes)
    throw new Error("Incident import exceeds the 64 MiB safety limit.");

  let payload;
  try { payload = JSON.parse(text); }
  catch { throw new Error("Incident import is not valid JSON."); }
  assertSafeTree(payload);
  if (!payload || typeof payload !== "object" || Array.isArray(payload) ||
      payload.schemaVersion !== 1 ||
      (payload.exportProfile !== "private" && payload.exportProfile !== "full"))
    throw new Error("Unsupported incident export format.");

  const manifest = payload.manifest;
  const records = payload.records;
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest) ||
      manifest.schemaVersion !== 1 || manifest.complete !== true ||
      !Array.isArray(records) || !Number.isSafeInteger(manifest.recordCount) ||
      manifest.recordCount < 0 || manifest.recordCount > kMaxRecords ||
      records.length !== manifest.recordCount)
    throw new Error("Incident export manifest and record count do not match the supported format.");

  if (!Array.isArray(manifest.triggers) || manifest.triggers.length > 256)
    throw new Error("Incident export trigger metadata is invalid.");
  for (const trigger of manifest.triggers) {
    if (!trigger || typeof trigger !== "object" || Array.isArray(trigger) ||
        typeof trigger.id !== "string" || trigger.id.length > 256 ||
        typeof trigger.reason !== "string" || trigger.reason.length > 1024)
      throw new Error("Incident export contains invalid trigger metadata.");
    uint64String(trigger.monotonicNs, "trigger time");
  }

  let checkpointCount = 0;
  for (const record of records) {
    if (!record || typeof record !== "object" || Array.isArray(record) ||
        typeof record.eventId !== "string" || record.eventId.length === 0 ||
        record.eventId.length > 256 || !record.event ||
        typeof record.event !== "object" || Array.isArray(record.event) ||
        typeof record.event.kind !== "string" || record.event.kind.length === 0 ||
        record.event.kind.length > 128)
      throw new Error("Incident export contains a malformed evidence record.");
    uint64String(record.captureMonotonicNs, "record time");
    if (record.eventId === "state_checkpoint" || record.event.kind === "state_checkpoint") {
      checkpointCount++;
      const state = record.event.state;
      if (!state || typeof state !== "object" || Array.isArray(state) ||
          state.coverage !== "snapshot_only" || typeof state.complete !== "boolean" ||
          !Array.isArray(state.items) || !Number.isSafeInteger(state.includedEndpoints) ||
          !Number.isSafeInteger(state.totalEndpoints) || state.includedEndpoints < 0 ||
          state.totalEndpoints < state.includedEndpoints ||
          state.items.length !== state.includedEndpoints ||
          (state.complete && state.includedEndpoints !== state.totalEndpoints))
        throw new Error("Incident export contains an invalid state checkpoint.");
    }
  }
  if (!Number.isSafeInteger(manifest.checkpointCount) ||
      manifest.checkpointCount !== checkpointCount ||
      !Number.isSafeInteger(manifest.eventCount) ||
      manifest.eventCount !== records.length - checkpointCount)
    throw new Error("Incident export record categories do not match its manifest.");

  return { manifest, records, exportProfile: payload.exportProfile,
    trust: "untrusted" };
}
