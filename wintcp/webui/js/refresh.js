const SOURCES = [
  ["connections", "/api/connections"],
  ["metrics", "/api/metrics/now"],
  ["capabilities", "/api/capabilities"],
  ["processes", "/api/processes?sort=cpu&limit=2000"],
  ["networkSummary", "/api/network/summary"],
  ["geoSummary", "/api/geo/summary"],
  ["systemInfo", "/api/system/info"],
];

const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const isCount = (value) => Number.isFinite(value) && value >= 0;

function sourcePayloadError(name, value) {
  if (!isObject(value)) return `Invalid ${name} response: expected an object`;
  switch (name) {
    case "connections":
      return Array.isArray(value.connections) &&
        value.connections.every((row) => isObject(row))
        ? null : "Invalid connections response: expected a connection array";
    case "metrics":
      return isObject(value.facts)
        ? null : "Invalid metrics response: expected a facts object";
    case "capabilities":
      return typeof value.elevated === "boolean" &&
        typeof value.pdh === "boolean" && typeof value.perCore === "boolean"
        ? null : "Invalid capabilities response: required flags are missing";
    case "processes":
      return Array.isArray(value.processes) && typeof value.known === "boolean" &&
        (value.total == null || isCount(value.total))
        ? null : "Invalid processes response: expected a process array and known flag";
    case "networkSummary":
      return isCount(value.total) && isObject(value.byState) &&
        isObject(value.byProto) && isObject(value.byFamily) &&
        isObject(value.byProcess) && isObject(value.listeners) &&
        typeof value.snapshotKnown === "boolean"
        ? null : "Invalid network summary response: required fields are missing";
    case "geoSummary":
      return isObject(value.countries) && isObject(value.asns) &&
        isCount(value.local) && isCount(value.unknown) &&
        typeof value.geoIpConfigured === "boolean" &&
        typeof value.snapshotKnown === "boolean"
        ? null : "Invalid geographic summary response: required fields are missing";
    case "systemInfo":
      return typeof value.hostname === "string" && typeof value.uptime === "string" &&
        isObject(value.os) && isObject(value.cpu) &&
        (value.memory === null || isObject(value.memory))
        ? null : "Invalid system information response: required fields are missing";
    default:
      return `Invalid ${name} response`;
  }
}

export function createSnapshotRefresh({ api, store, onUpdate = () => {} }) {
  let generation = 0;
  let inFlight = null;

  async function refresh({ manual = false } = {}) {
    if (store.get().paused && !manual) return;
    if (inFlight) {
      if (inFlight.generation === generation) return inFlight.promise;
      await inFlight.promise.catch(() => {});
      return refresh({ manual });
    }
    const mine = generation;
    const operation = { generation: mine, promise: null };
    operation.promise = (async () => {
      const results = await Promise.allSettled(SOURCES.map(([, path]) => api.get(path)));
      if (mine !== generation) return;
      const previous = store.get();
      const sourceStatus = { ...previous.sourceStatus };
      const patch = {};
      const sampledAt = new Date();
      results.forEach((result, index) => {
        const name = SOURCES[index][0];
        const payloadError = result.status === "fulfilled"
          ? sourcePayloadError(name, result.value) : null;
        if (result.status === "rejected" || payloadError) {
          sourceStatus[name] = {
            ...sourceStatus[name],
            error: payloadError || result.reason?.message || String(result.reason),
          };
          return;
        }
        const value = result.value;
        sourceStatus[name] = { updatedAt: sampledAt, error: null };
        if (name === "connections") {
          patch.connections = value.connections;
          patch.lastUpdate = sampledAt;
          patch.connectionGeneratedAt = value.generatedAt || null;
        } else if (name === "processes") {
          patch.processes = Array.isArray(value.processes) ? value.processes : [];
          patch.processesKnown = value.known !== false;
          patch.processCount = value.total ?? null;
          patch.processSampleAgeMs = value.ageMs ?? null;
          patch.processSampledAtMs = value.sampledAtMs ?? null;
        } else {
          patch[name] = value;
          if (name === "metrics") patch.sysUptime = value["sys.uptimeSeconds"] ?? null;
        }
      });
      const failures = SOURCES.filter(([name]) => sourceStatus[name]?.error);
      patch.sourceStatus = sourceStatus;
      patch.status = sourceStatus.connections?.error ? "error" : failures.length ? "degraded" : "online";
      patch.lastError = failures.map(([name]) => `${name}: ${sourceStatus[name].error}`).join("; ") || null;
      store.set(patch);
      onUpdate();
      if (sourceStatus.connections?.error) throw new Error(sourceStatus.connections.error);
    })();
    inFlight = operation;
    try {
      return await operation.promise;
    } finally {
      if (inFlight === operation) inFlight = null;
    }
  }

  return { refresh, invalidate: () => { generation++; } };
}
