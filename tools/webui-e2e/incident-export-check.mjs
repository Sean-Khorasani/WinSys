// Pure regression checks for the privacy profiles used by the incident exporter.
import { strict as assert } from "node:assert";
import { buildIncidentExport } from "../../wintcp/webui/js/incident-export.mjs";

const source = {
  manifest: { archiveId: "archive-A", incidentId: "incident-A", triggers: [
    { id: "trigger-A", reason: "private user note" },
  ] },
  records: [
    { eventId: "event-A", sourceSequence: "9", flowId: "flow-A", timebaseId: "clock-A",
      process: { pid: 1234, creationTimeFileTime: "456", imagePath: "C:\\Users\\A\\app.exe",
        observedImageName: "app.exe" }, evidenceIds: ["event-A"],
      local: { address: "192.0.2.4" }, remote: { address: "198.51.100.7" } },
    { eventId: "event-B", evidenceIds: ["event-A"], remote: { address: "198.51.100.7" } },
  ],
};
const original = structuredClone(source);
const result = buildIncidentExport(source.manifest, source.records, "private");
assert.equal(result.exportProfile, "private");
assert.equal(result.manifest.triggers[0].reason, "[omitted]");
assert.equal(result.records[0].process.imagePath, null);
assert.equal(result.records[0].process.observedImageName, null);
assert.match(result.records[0].local.address, /^endpoint-/);
assert.equal(result.records[0].remote.address, result.records[1].remote.address);
assert.equal(result.records[0].eventId, result.records[0].evidenceIds[0]);
assert.equal(result.records[1].evidenceIds[0], result.records[0].eventId);
assert.notEqual(result.records[0].process.pid, 1234);
assert.deepEqual(source, original, "export must not mutate the verified archive data");

const full = buildIncidentExport(source.manifest, source.records, "full");
assert.equal(full.records[0].process.imagePath, source.records[0].process.imagePath);
assert.equal(full.records[0].remote.address, source.records[0].remote.address);
assert.throws(() => buildIncidentExport(source.manifest, source.records, "unknown"), TypeError);
console.log("incident-export-check=PASS privateRedaction=true stablePseudonyms=true fullProfile=true sourceUnchanged=true");
