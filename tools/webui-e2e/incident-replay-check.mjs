// Pure deterministic replay reducer tests. No browser, engine, DNS, or network calls.
import assert from "node:assert/strict";
import { buildIncidentReplay } from "../../wintcp/webui/js/incident-replay.mjs";

const endpoint = (flowId, port) => ({ source: "snapshot", kind: "endpoint_observed",
  flowId, transport: "tcp", family: "ipv4", local: { address: "192.0.2.5", port },
  remote: { address: "198.51.100.9", port: 443 }, process: { pid: 12,
    creationTimeFileTime: "1234", imagePath: "C:\\Fixture\\app.exe" } });
const wrap = (time, eventId, event) => ({ captureMonotonicNs: String(time), eventId, event });
const checkpoint = (time, items, complete = true) => wrap(time, "state_checkpoint", {
  kind: "state_checkpoint", monotonicNs: String(time), state: {
    coverage: "snapshot_only", complete, includedEndpoints: items.length,
    totalEndpoints: complete ? items.length : items.length + 1, items,
  },
});
const disappeared = (flowId, port) => ({ ...endpoint(flowId, port), kind: "endpoint_disappeared" });

const source = [
  checkpoint(10, [endpoint("flow-1", 51001)]),
  wrap(20, "event-2", endpoint("flow-2", 51002)),
  wrap(30, "event-3", disappeared("flow-1", 51001)),
  wrap(40, "gap", { kind: "coverage_gap", lossReason: "sampling_gap" }),
  checkpoint(50, [endpoint("flow-2", 51002)]),
];
const original = JSON.stringify(source);
const replay = buildIncidentReplay(source, { checkpointCount: 2 });
assert.equal(replay.checkpoints, 2);
assert.deepEqual(replay.eventsAt("25").items.map((record) => record.eventId), ["event-2"],
  "timeline evidence must include only non-checkpoint events at or before the selected replay time");
assert.equal(replay.eventsAt("45").total, 3,
  "coverage-gap evidence is included in the historical event timeline");
assert.equal(replay.eventsAt("55", 1).truncated, true,
  "historical evidence is explicitly bounded");
assert.deepEqual(replay.reconstruct("15").endpoints.map((item) => item.flowId), ["flow-1"]);
assert.deepEqual(replay.reconstruct("25").endpoints.map((item) => item.flowId), ["flow-1", "flow-2"]);
assert.deepEqual(replay.reconstruct("35").endpoints.map((item) => item.flowId), ["flow-2"]);
assert.equal(replay.reconstruct("45").complete, false,
  "a coverage gap after the selected checkpoint must make replay partial");
const recovered = replay.reconstruct("55");
assert.equal(recovered.complete, true,
  "a later complete checkpoint re-establishes known snapshot state after a gap");
assert.deepEqual(recovered.endpoints.map((item) => item.flowId), ["flow-2"]);
assert.equal(replay.reconstruct("9").available, false,
  "state before the first checkpoint is explicitly unavailable");
assert.equal(JSON.stringify(source), original, "replay must not mutate archived records");

const partial = buildIncidentReplay([checkpoint(100, [endpoint("flow-3", 51003)], false)]);
assert.equal(partial.reconstruct("100").complete, false,
  "truncated checkpoint cannot be presented as complete state");
assert.equal(partial.reconstruct("100").reason, "checkpoint_partial_or_invalid");
assert.throws(() => buildIncidentReplay({}), TypeError);
assert.throws(() => replay.reconstruct("not-a-time"), TypeError);
assert.equal(buildIncidentReplay([{}]).malformedCount, 1);

console.log("incident-replay-check=PASS checkpoint-seek=true ordered-deltas=true disappearances=true gap-degrades=true full-checkpoint-recovers=true partial-checkpoint-honest=true precheckpoint-unavailable=true immutable-input=true malformed-input=true");
