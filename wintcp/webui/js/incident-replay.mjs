// Deterministic offline reconstruction of snapshot endpoint state.
// This module has no network, DNS, engine, or mutation dependencies.

function timestampNs(value) {
  if (typeof value === "bigint") return value >= 0n ? value : null;
  if (typeof value !== "string" || !/^\d+$/.test(value)) return null;
  try { return BigInt(value); } catch { return null; }
}

function recordTime(record) {
  return timestampNs(record?.captureMonotonicNs) ??
    timestampNs(record?.event?.monotonicNs);
}

function flowKey(event) {
  if (typeof event?.flowId === "string" && event.flowId.length)
    return `flow:${event.flowId}`;
  const endpoint = (value) => value && typeof value === "object"
    ? [value.address || "", value.port ?? "", value.scopeId ?? ""] : ["", "", ""];
  const identity = [event?.process?.pid ?? "", event?.process?.creationTimeFileTime ?? "",
    event?.transport || "", event?.family || "", ...endpoint(event?.local),
    ...endpoint(event?.remote)];
  if (identity.every((value) => value === "")) return null;
  return `tuple:${JSON.stringify(identity)}`;
}

function isCheckpoint(record) {
  return record?.eventId === "state_checkpoint" ||
    record?.event?.kind === "state_checkpoint";
}

function isEndpointDelta(event) {
  return event?.source === "snapshot" &&
    (event.kind === "endpoint_observed" || event.kind === "endpoint_disappeared");
}

export function buildIncidentReplay(records, manifest = {}) {
  if (!Array.isArray(records)) throw new TypeError("Replay records must be an array.");
  const normalized = [];
  let malformedCount = 0;
  for (let index = 0; index < records.length; index++) {
    const record = records[index];
    const timeNs = recordTime(record);
    if (!record || typeof record !== "object" || timeNs === null ||
        !record.event || typeof record.event !== "object") {
      malformedCount++;
      continue;
    }
    normalized.push({ record, event: record.event, timeNs, index,
      checkpoint: isCheckpoint(record) });
  }
  normalized.sort((left, right) => left.timeNs < right.timeNs ? -1 :
    left.timeNs > right.timeNs ? 1 : left.index - right.index);
  const checkpoints = normalized.filter((item) => item.checkpoint);
  const minNs = normalized.length ? normalized[0].timeNs : null;
  const maxNs = normalized.length ? normalized[normalized.length - 1].timeNs : null;

  function reconstruct(targetValue) {
    const targetNs = timestampNs(targetValue);
    if (targetNs === null) throw new TypeError("Replay time must be unsigned nanoseconds.");
    let checkpoint = null;
    for (const item of checkpoints) {
      if (item.timeNs > targetNs) break;
      checkpoint = item;
    }
    if (!checkpoint) return {
      available: false, complete: false, reason: "no_checkpoint_at_or_before_time",
      checkpointNs: null, targetNs: targetNs.toString(), endpoints: [],
      appliedDeltas: 0, malformedCount,
    };

    const map = new Map();
    const state = checkpoint.event.state;
    const checkpointItems = Array.isArray(state?.items) ? state.items : [];
    let complete = state?.complete === true &&
      Number(state?.includedEndpoints) === checkpointItems.length &&
      Number(state?.totalEndpoints) >= checkpointItems.length;
    let reason = complete ? null : "checkpoint_partial_or_invalid";
    for (const endpoint of checkpointItems) {
      const key = flowKey(endpoint);
      if (!key) {
        complete = false;
        reason ||= "checkpoint_contains_unkeyed_endpoint";
        continue;
      }
      map.set(key, endpoint);
    }

    let appliedDeltas = 0;
    for (const item of normalized) {
      if (item.timeNs < checkpoint.timeNs ||
          (item.timeNs === checkpoint.timeNs && item.index <= checkpoint.index)) continue;
      if (item.timeNs > targetNs) break;
      if (item.checkpoint) continue;
      if (item.event.kind === "coverage_gap") {
        complete = false;
        reason ||= item.event.lossReason || "coverage_gap";
        continue;
      }
      if (!isEndpointDelta(item.event)) continue;
      const key = flowKey(item.event);
      if (!key) {
        complete = false;
        reason ||= "endpoint_delta_missing_identity";
        continue;
      }
      if (item.event.kind === "endpoint_observed") map.set(key, item.event);
      else if (!map.delete(key)) {
        complete = false;
        reason ||= "disappearance_without_checkpointed_endpoint";
      }
      appliedDeltas++;
    }

    const endpoints = [...map.entries()]
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([, endpoint]) => endpoint);
    return {
      available: true, complete, reason,
      checkpointNs: checkpoint.timeNs.toString(), targetNs: targetNs.toString(),
      endpoints, appliedDeltas, malformedCount,
      coverage: state?.coverage === "snapshot_only" ? "snapshot_only" : "unknown",
    };
  }

  function eventsAt(targetValue, limit = 100) {
    const targetNs = timestampNs(targetValue);
    if (targetNs === null) throw new TypeError("Replay time must be unsigned nanoseconds.");
    const safeLimit = Number.isSafeInteger(limit) ? Math.max(1, Math.min(limit, 1000)) : 100;
    const eligible = normalized.filter((item) => !item.checkpoint && item.timeNs <= targetNs);
    return { items: eligible.slice(-safeLimit).map((item) => item.record),
      total: eligible.length, truncated: eligible.length > safeLimit };
  }

  return {
    manifest,
    records: normalized,
    checkpoints: checkpoints.length,
    malformedCount,
    minNs,
    maxNs,
    reconstruct,
    eventsAt,
  };
}
