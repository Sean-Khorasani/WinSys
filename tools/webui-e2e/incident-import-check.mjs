// Host-independent validation tests for untrusted portable incident exports.
import assert from "node:assert/strict";
import { buildIncidentExport } from "../../wintcp/webui/js/incident-export.mjs";
import { parseIncidentImport } from "../../wintcp/webui/js/incident-import.mjs";

const valid = {
  schemaVersion: 1,
  exportProfile: "private",
  manifest: { schemaVersion: 1, complete: true, recordCount: 2,
    eventCount: 1, checkpointCount: 1, triggers: [
      { monotonicNs: "10", id: "trigger-1", reason: "[omitted]" },
    ] },
  records: [
    { captureMonotonicNs: "10", eventId: "event-1",
      event: { source: "snapshot", kind: "endpoint_observed", transport: "tcp",
        process: { pid: "process-1" }, local: { address: "endpoint-1", port: 50000 },
        remote: { address: "endpoint-2", port: 443 } } },
    { captureMonotonicNs: "20", eventId: "checkpoint-1", event: {
      source: "snapshot", kind: "state_checkpoint", state: {
        coverage: "snapshot_only", complete: true, includedEndpoints: 1,
        totalEndpoints: 1, items: [{ transport: "tcp", process: { pid: "process-1" },
          local: { address: "endpoint-1", port: 50000 },
          remote: { address: "endpoint-2", port: 443 } }],
      } } },
  ],
};

const parsed = parseIncidentImport(JSON.stringify(valid));
assert.equal(parsed.trust, "untrusted");
assert.equal(parsed.exportProfile, "private");
assert.equal(parsed.records.length, 2);
for (const profile of ["private", "full"]) {
  const generated = buildIncidentExport(valid.manifest, valid.records, profile);
  const roundTrip = parseIncidentImport(JSON.stringify(generated));
  assert.equal(roundTrip.exportProfile, profile);
  assert.equal(roundTrip.records.length, valid.records.length);
}
assert.throws(() => parseIncidentImport("{"), /not valid JSON/);
assert.throws(() => parseIncidentImport(JSON.stringify({ ...valid, schemaVersion: 2 })), /Unsupported/);
assert.throws(() => parseIncidentImport(JSON.stringify({ ...valid,
  manifest: { ...valid.manifest, recordCount: 99 } })), /record count/);

const badTime = structuredClone(valid);
badTime.records[0].captureMonotonicNs = "-1";
assert.throws(() => parseIncidentImport(JSON.stringify(badTime)), /unsigned decimal/);
const badCategory = structuredClone(valid);
badCategory.manifest.checkpointCount = 0;
assert.throws(() => parseIncidentImport(JSON.stringify(badCategory)), /categories/);
const badCheckpoint = structuredClone(valid);
badCheckpoint.records[1].event.state.includedEndpoints = 2;
assert.throws(() => parseIncidentImport(JSON.stringify(badCheckpoint)), /invalid state checkpoint/);
assert.throws(() => parseIncidentImport('{"__proto__":{"polluted":true}}'), /prohibited object key/);
const tooDeep = { value: null };
let cursor = tooDeep;
for (let i = 0; i < 70; i++) { cursor.next = {}; cursor = cursor.next; }
assert.throws(() => parseIncidentImport(JSON.stringify(tooDeep)), /nesting/);
assert.throws(() => parseIncidentImport(" ".repeat(64 * 1024 * 1024 + 1)), /64 MiB/);
assert.deepEqual(valid.records[0].event.remote.address, "endpoint-2",
  "parsing must not mutate caller-owned input");
console.log("incident-import-check=PASS schema=true bounds=true untrusted=true timestamps=true counts=true checkpoints=true prototypeKeys=true nesting=true immutable=true");
