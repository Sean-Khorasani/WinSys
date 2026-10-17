// legacy/monitors.js - Monitor evaluation (T01, T06, T07, T08, T11, T12, T29)
// Browser-side evaluators run only while the page is open.

const T08_WILDCARD = new Set(["0.0.0.0", "::", "*", "[::]"]);

export function evalT08(connections) {
  const listeners = connections.filter(c =>
    c.state === "LISTENING" && c.proto && c.proto.startsWith("TCP")
  );
  const wildcard = listeners.filter(c => {
    const local = c.local || "";
    return T08_WILDCARD.has(local.split(":")[0]) || local.startsWith("[*]:");
  }).length;
  return { wildcard, total: listeners.length, fires: wildcard >= 1 };
}

export function evalT11(connections, threshold = 10) {
  const byPid = {};
  for (const c of connections) {
    if (c.state !== "LISTENING") continue;
    const key = c.pid;
    if (!byPid[key]) byPid[key] = new Set();
    byPid[key].add(c.local);
  }
  const offenders = Object.entries(byPid)
    .filter(([_, set]) => set.size >= threshold)
    .map(([pid, set]) => ({ pid: Number(pid), count: set.size }));
  return { offenders, fires: offenders.length > 0 };
}

export function evalT12(connections, threshold = 50) {
  const byPid = {};
  for (const c of connections) {
    if (c.state !== "ESTABLISHED") continue;
    const key = c.pid;
    if (!byPid[key]) byPid[key] = new Set();
    byPid[key].add(c.remote);
  }
  const offenders = Object.entries(byPid)
    .filter(([_, set]) => set.size >= threshold)
    .map(([pid, set]) => ({ pid: Number(pid), count: set.size }));
  return { offenders, fires: offenders.length > 0 };
}

export function evalT29(connections, thresholdMs = 250) {
  const offenders = connections
    .filter(c => c.rttMs != null && c.rttMs > thresholdMs)
    .map(c => ({ pid: c.pid, remote: c.remote, rttMs: c.rttMs }));
  return { offenders, fires: offenders.length > 0 };
}
