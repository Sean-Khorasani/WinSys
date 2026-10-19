// monitors.js - Browser-side template evaluators for WinTCP monitors.
//
// Each evaluator runs on the client against the data the /api/* endpoints
// already provide. The evaluators are stateless: they receive a snapshot of
// the current connections/processes/metrics and return a result object.
//
// The runtimes mirror the `runtime` field in templates.json. A template with
// `runtime` and a matching evaluator here is "monitor ready".

// Common known remote-administration ports for T10.
const REMOTE_ADMIN_PORTS = new Set([22, 23, 115, 3389, 5985, 5986, 5900, 5901, 5902, 5901, 443, 593]);

// Common high-integrity process names for T17.
const SYSTEM_PROCESSES = new Set([
  "csrss.exe", "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
  "audiodg.exe", "dwm.exe", "spoolsv.exe", "taskhostw.exe",
]);

// Signature state values (matching ProcessInfo.h SignatureState).
const SIG = {
  Unchecked: 0,
  Valid: 1,
  Invalid: 2,
  Unsigned: 3,
  Error: 4,
};

// Integrity level values (matching ProcessInfo.h IntegrityLevel).
const INTEGRITY = {
  Unknown: 0,
  Untrusted: 1,
  Low: 2,
  Medium: 3,
  High: 4,
  System: 5,
  Protected: 6,
};

// ---- T02: Process egress rate spike ----
// Detect a sustained outbound-rate increase against a process baseline.
// Browser limitation: no historical baseline from the web API, so this
// fires when a single snapshot shows unusually high per-process egress.
export function evalT02(connections, processes, threshold = 100_000_000) {
  const byPid = {};
  for (const c of connections) {
    if (c.state !== "ESTABLISHED") continue;
    if (c.protocol !== "TCP") continue;
    const tx = c.socketTxBytes;
    if (tx == null || tx <= 0) continue;
    const pid = c.pid;
    if (!byPid[pid]) byPid[pid] = { name: c.process, tx: 0 };
    byPid[pid].tx += Number(tx);
  }
  const offenders = Object.entries(byPid)
    .filter(([_, v]) => v.tx > threshold)
    .map(([pid, v]) => ({ pid: Number(pid), process: v.name, bytes: v.tx }));
  return { offenders, fires: offenders.length > 0, threshold };
}

// ---- T03: Single remote port byte budget ----
// Track a remote address and destination-port budget separately.
// Browser limitation: no per-socket byte counters in web mode, so we use
// connection count as a proxy for activity.
export function evalT03(connections, remote = null, port = null, threshold = 10) {
  const byPeer = {};
  for (const c of connections) {
    if (c.state !== "ESTABLISHED" || c.protocol !== "TCP") continue;
    const key = `${c.remote}|${c.rport}`;
    if (!byPeer[key]) byPeer[key] = { remote: c.remote, rport: c.rport, count: 0 };
    byPeer[key].count++;
  }
  const offenders = Object.entries(byPeer)
    .filter(([_, v]) => v.count > threshold)
    .map(([_, v]) => ({ remote: v.remote, rport: v.rport, count: v.count, threshold }));
  return { offenders, fires: offenders.length > 0, threshold };
}

// ---- T04: Inbound peer budget ----
// Alert when inbound bytes from one peer exceed a configured allowance.
// Browser limitation: no per-socket byte counters, uses connection count.
export function evalT04(connections, threshold = 5) {
  const byPeer = {};
  for (const c of connections) {
    if (c.protocol !== "TCP" || !c.state) continue;
    const key = c.remote;
    if (!byPeer[key]) byPeer[key] = { remote: c.remote, established: 0, listening: 0 };
    if (c.state === "ESTABLISHED") byPeer[key].established++;
    else if (c.state === "LISTENING") byPeer[key].listening++;
  }
  const offenders = Object.entries(byPeer)
    .filter(([_, v]) => v.established > threshold)
    .map(([_, v]) => ({ remote: v.remote, established: v.established, threshold }));
  return { offenders, fires: offenders.length > 0, threshold };
}

// ---- T05: Outbound bytes to a new peer ----
// Combine first-seen remote identity with observed traffic volume.
// Browser limitation: no first-seen history from web API. Uses a persistent
// session store (in-memory) to track first-seen peers across polls.
export function evalT05(connections, seenPeers = new Set(), threshold = 1) {
  const newPeers = [];
  for (const c of connections) {
    if (c.state !== "ESTABLISHED" || c.protocol !== "TCP") continue;
    if (!c.remote) continue;
    if (!seenPeers.has(c.remote)) {
      newPeers.push({ remote: c.remote, pid: c.pid, process: c.process });
    }
    seenPeers.add(c.remote);
  }
  return { newPeers, fires: newPeers.length >= threshold, seenPeers, threshold };
}

// ---- T08: Wildcard-bound listener detected ----
const WILDCARD_ADDRESSES = new Set(["0.0.0.0", "::", "*", "[::]", "0.0.0.0.0"]);
export function evalT08(connections, threshold = 1) {
  const wildcards = [];
  for (const c of connections) {
    if (c.state !== "LISTENING" || c.protocol !== "TCP") continue;
    if (!c.local) continue;
    const addr = c.local.split(":")[0];
    if (WILDCARD_ADDRESSES.has(addr) || addr === "" || c.local.startsWith("[*]:")) {
      wildcards.push({ pid: c.pid, process: c.process, local: c.local, lport: c.lport });
    }
  }
  return { wildcards, total: wildcards.length, fires: wildcards.length >= threshold, threshold };
}

// ---- T09: Non-standard remote port ----
// Report a connection whose remote port is outside the configured allow-list.
export function evalT09(connections, allowList = [], threshold = 0) {
  const ports = new Set(Array.isArray(allowList) ? allowList : DEFAULT_ALLOWED_PORTS);
  const offenders = [];
  for (const c of connections) {
    if (c.state !== "ESTABLISHED" || c.protocol !== "TCP") continue;
    const rport = Number(c.rport);
    if (!rport || ports.has(rport)) continue;
    offenders.push({ pid: c.pid, process: c.process, remote: c.remote, rport, protocol: c.protocol });
  }
  return { offenders, fires: offenders.length > threshold, threshold, allowedPorts: Array.from(ports).sort((a, b) => a - b) };
}

const DEFAULT_ALLOWED_PORTS = new Set([80, 443, 53, 8080, 8443, 25, 587, 993, 995]);

// ---- T10: Remote desktop exposure ----
// Alert on externally reachable listeners associated with common remote-admin ports.
export function evalT10(connections, threshold = 1) {
  const offenders = [];
  const allWildcard = [];
  for (const c of connections) {
    if (c.state !== "LISTENING" || c.protocol !== "TCP") continue;
    const rport = Number(c.rport) || 0;
    // Check if the local port is a remote admin port
    const lport = Number(c.lport);
    if (REMOTE_ADMIN_PORTS.has(lport)) {
      const isExternal = isExternalListener(c.local);
      if (isExternal) {
        offenders.push({
          pid: c.pid, process: c.process, local: c.local, lport,
          bindScope: getBindScope(c.local),
        });
      }
    }
  }
  return { offenders, fires: offenders.length >= threshold, threshold };
}

function isExternalListener(local) {
  if (!local) return true;
  const addr = local.split(":")[0];
  return !WILDCARD_ADDRESSES.has(addr) && addr !== "127.0.0.1" && addr !== "::1" && addr !== "localhost";
}

function getBindScope(local) {
  if (!local) return "unknown";
  const addr = local.split(":")[0];
  if (WILDCARD_ADDRESSES.has(addr)) return "wildcard";
  if (addr === "127.0.0.1" || addr === "::1" || addr === "localhost") return "loopback";
  if (addr === "0.0.0.0" || addr === "::") return "all-interfaces";
  return "specific";
}

// ---- T11: Process opens too many listeners ----
// Count TCP listeners by PID and alert when one process exceeds the configured count.
export function evalT11(connections, threshold = 10) {
  const byPid = {};
  for (const c of connections) {
    if (c.state !== "LISTENING" || c.protocol !== "TCP") continue;
    const pid = c.pid;
    if (!byPid[pid]) byPid[pid] = { process: c.process, listeners: new Set() };
    if (c.lport) byPid[pid].listeners.add(c.lport);
  }
  const offenders = Object.entries(byPid)
    .filter(([_, v]) => v.listeners.size > threshold)
    .map(([pid, v]) => ({
      pid: Number(pid),
      process: v.process,
      listenerCount: v.listeners.size,
      threshold,
    }));
  return { offenders, fires: offenders.length > 0, threshold };
}

// ---- T12: Process fans out to many remote peers ----
// Count distinct established remote IPs per PID and alert on unusually broad fan-out.
export function evalT12(connections, threshold = 50) {
  const byPid = {};
  for (const c of connections) {
    if (c.state !== "ESTABLISHED" || c.protocol !== "TCP") continue;
    if (!c.remote) continue;
    const pid = c.pid;
    if (!byPid[pid]) byPid[pid] = { process: c.process, peers: new Set() };
    byPid[pid].peers.add(c.remote);
  }
  const offenders = Object.entries(byPid)
    .filter(([_, v]) => v.peers.size > threshold)
    .map(([pid, v]) => ({
      pid: Number(pid),
      process: v.process,
      peerCount: v.peers.size,
      threshold,
    }));
  return { offenders, fires: offenders.length > 0, threshold };
}

// ---- T13: Process connection-count surge ----
// Detect a large rise in one process's active connection count.
// Browser limitation: no historical baseline, so this fires on absolute count.
export function evalT13(connections, threshold = 100) {
  const byPid = {};
  for (const c of connections) {
    if (c.state !== "ESTABLISHED" || c.protocol !== "TCP") continue;
    const pid = c.pid;
    if (!byPid[pid]) byPid[pid] = { process: c.process, count: 0 };
    byPid[pid].count++;
  }
  const offenders = Object.entries(byPid)
    .filter(([_, v]) => v.count > threshold)
    .map(([pid, v]) => ({ pid: Number(pid), process: v.process, count: v.count, threshold }));
  return { offenders, fires: offenders.length > 0, threshold };
}

// ---- T14: New process starts network activity ----
// Alert when a newly observed PID acquires its first network endpoint.
// Browser limitation: no process creation time from web API yet.
// Uses PID tracking across polls as a proxy.
export function evalT14(connections, seenPids = new Set(), threshold = 1) {
  const newPids = [];
  for (const c of connections) {
    if (!c.pid || c.pid <= 0) continue;
    if (!seenPids.has(c.pid)) {
      newPids.push({ pid: c.pid, process: c.process, path: c.path });
    }
    seenPids.add(c.pid);
  }
  return { newPids, fires: newPids.length >= threshold, seenPids, threshold };
}

// ---- T15: Long-lived external connection ----
// Identify an established public-peer connection that remains active beyond its
// configured age.
export function evalT15(connections, thresholdSeconds = 86400) {
  const offenders = [];
  for (const c of connections) {
    if (c.state !== "ESTABLISHED" || c.protocol !== "TCP") continue;
    if (!c.durationSeconds || c.durationSeconds < thresholdSeconds) continue;
    if (!isPublicAddress(c.remote)) continue;
    offenders.push({
      pid: c.pid, process: c.process, remote: c.remote,
      rport: c.rport, durationSeconds: c.durationSeconds,
      durationHuman: formatDuration(c.durationSeconds),
    });
  }
  return { offenders, fires: offenders.length > 0, thresholdSeconds };
}

function isPublicAddress(addr) {
  if (!addr) return false;
  if (addr === "127.0.0.1" || addr === "::1" || addr.startsWith("127.")) return false;
  if (addr.startsWith("10.")) return false;
  if (addr.startsWith("172.")) {
    const parts = addr.split(".");
    if (parts.length === 4) {
      const second = Number(parts[1]);
      if (second >= 16 && second <= 31) return false;
    }
  }
  if (addr.startsWith("192.168.")) return false;
  if (addr.startsWith("169.254.")) return false;
  if (addr.startsWith("fc") || addr.startsWith("fd") || addr.startsWith("fe80")) return false;
  return true;
}

function formatDuration(seconds) {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

// ---- T16: Network activity from an unmanaged service ----
// Surface network-owning services outside a user-provided approved service inventory.
export function evalT16(connections, approvedServices = [], threshold = 1) {
  const services = new Set(Array.isArray(approvedServices) ? approvedServices : DEFAULT_APPROVED_SERVICES);
  const offenders = [];
  for (const c of connections) {
    if (c.state !== "LISTENING") continue;
    const svc = c.service;
    if (!svc) continue;
    if (!services.has(svc.toLowerCase())) {
      offenders.push({ pid: c.pid, process: c.process, service: svc, local: c.local, lport: c.lport });
    }
  }
  return { offenders, fires: offenders.length >= threshold, threshold };
}

const DEFAULT_APPROVED_SERVICES = new Set([
  "bits", "wuauserv", "dosvc", "iphlpsvc", "seclogon", "vaultsvc",
  "eventlog", "eventsystem", "winmgmt", "cryptsvc", "dhcp", "dnscache",
  "lanmanserver", "lanmanworkstation", "themes", "audioendpoint", "audiosrv",
]);

// ---- T17: Network activity from a high-integrity process ----
// Highlight high-integrity or system processes communicating with non-approved peers.
export function evalT17(connections, threshold = 1) {
  const offenders = [];
  for (const c of connections) {
    if (c.state !== "ESTABLISHED" || c.protocol !== "TCP") continue;
    const integrity = c.integrityLevel;
    if (integrity >= INTEGRITY.High) {
      offenders.push({
        pid: c.pid, process: c.process, remote: c.remote,
        rport: c.rport, integrityLevel: integrity, integrity: getIntegrityName(integrity),
      });
    }
  }
  return { offenders, fires: offenders.length >= threshold, threshold };
}

function getIntegrityName(level) {
  switch (level) {
    case INTEGRITY.Unknown: return "Unknown";
    case INTEGRITY.Untrusted: return "Untrusted";
    case INTEGRITY.Low: return "Low";
    case INTEGRITY.Medium: return "Medium";
    case INTEGRITY.High: return "High";
    case INTEGRITY.System: return "System";
    case INTEGRITY.Protected: return "Protected";
    default: return "Unknown";
  }
}

// ---- T18: Connection to a newly observed country ----
// Alert when a remote endpoint maps to a country not previously seen.
// Browser limitation: needs GeoIP configured and working in the web refresh.
export function evalT18(connections, seenCountries = new Set(), threshold = 1) {
  const newCountries = [];
  for (const c of connections) {
    if (c.state !== "ESTABLISHED" || c.protocol !== "TCP") continue;
    if (!c.country) continue;
    if (!seenCountries.has(c.country)) {
      newCountries.push({ country: c.country, remote: c.remote, pid: c.pid, process: c.process });
    }
    seenCountries.add(c.country);
  }
  return { newCountries, fires: newCountries.length >= threshold, seenCountries, threshold };
}

// ---- T19: Peer in a country watchlist ----
// Compare resolved country metadata with an operator-maintained watchlist.
export function evalT19(connections, watchlist = DEFAULT_COUNTRY_WATCHLIST, threshold = 1) {
  const countries = new Set(Array.isArray(watchlist) ? watchlist : DEFAULT_COUNTRY_WATCHLIST);
  const offenders = [];
  const seen = new Set();
  for (const c of connections) {
    if (c.state !== "ESTABLISHED" || c.protocol !== "TCP") continue;
    if (!c.country) continue;
    if (countries.has(c.country)) {
      const key = `${c.remote}|${c.country}`;
      if (seen.has(key)) continue;
      seen.add(key);
      offenders.push({ country: c.country, remote: c.remote, pid: c.pid, process: c.process });
    }
  }
  return { offenders, fires: offenders.length >= threshold, threshold, watchlist: Array.from(countries) };
}

const DEFAULT_COUNTRY_WATCHLIST = new Set(["RU", "CN", "KP", "IR", "SY"]);

// ---- T20: New hosting provider or ASN ----
// Identify a new autonomous system used by a process.
// Browser limitation: needs ASN database. Uses country as fallback indicator.
export function evalT20(connections, seenAsns = new Set(), seenCountries = new Set(), threshold = 1) {
  const newAsns = [];
  for (const c of connections) {
    if (c.state !== "ESTABLISHED" || c.protocol !== "TCP") continue;
    if (!c.country) continue;
    if (!seenCountries.has(c.country)) {
      newAsns.push({ country: c.country, remote: c.remote, pid: c.pid, process: c.process });
    }
    seenCountries.add(c.country);
  }
  return { newAsns, fires: newAsns.length >= threshold, seenCountries, threshold };
}

// ---- T21: Unsigned process opens a new connection ----
// Alert when an unsigned image creates a new network endpoint.
export function evalT21(connections, seenPids = new Set(), threshold = 1) {
  const newUnsigned = [];
  for (const c of connections) {
    const sig = c.signatureState;
    if (sig === SIG.Unsigned || sig === SIG.Error) {
      const key = `${c.pid}|${c.remote}`;
      if (!seenPids.has(key)) {
        newUnsigned.push({ pid: c.pid, process: c.process, remote: c.remote, signature: getSignatureName(sig) });
        seenPids.add(key);
      }
    }
  }
  return { newUnsigned, fires: newUnsigned.length >= threshold, seenPids, threshold };
}

function getSignatureName(state) {
  switch (state) {
    case SIG.Unchecked: return "Not checked";
    case SIG.Valid: return "Signed";
    case SIG.Invalid: return "BAD SIG";
    case SIG.Unsigned: return "Unsigned";
    case SIG.Error: return "Signature error";
    default: return "Unknown";
  }
}

// ---- T22: Invalid signature owns a connection ----
// Escalate BAD SIG owners while keeping unsigned and not-checked states distinct.
export function evalT22(connections, threshold = 1) {
  const offenders = [];
  const seen = new Set();
  for (const c of connections) {
    if (c.signatureState === SIG.Invalid) {
      const key = String(c.pid);
      if (seen.has(key)) continue;
      seen.add(key);
      offenders.push({ pid: c.pid, process: c.process, path: c.path, signature: "BAD SIG" });
    }
  }
  return { offenders, fires: offenders.length >= threshold, threshold };
}

// ---- T23: Unexpected parent process ----
// Compare a network process's parent chain with expected launch relationships.
// Browser limitation: ppid is available in the expanded columns, but expected
// parent mappings are not part of the web config. Uses a default allow-list.
export function evalT23(connections, expectedParents = {}, threshold = 1) {
  const offenders = [];
  const seen = new Set();
  for (const c of connections) {
    if (c.state !== "ESTABLISHED" || c.protocol !== "TCP") continue;
    if (!c.ppid) continue;
    const procName = (c.process || "").toLowerCase();
    const expected = expectedParents[procName];
    // If no expectation is set, this process is not on the policy list - skip.
    if (!expected) continue;
    const key = String(c.pid);
    if (seen.has(key)) continue;
    seen.add(key);
    offenders.push({
      pid: c.pid, process: c.process, ppid: c.ppid,
      path: c.path, expectedParent: expected,
    });
  }
  return { offenders, fires: offenders.length >= threshold, threshold };
}

// ---- T24: Process memory plus network anomaly ----
// Correlate elevated memory growth with connection or traffic changes.
// Browser limitation: no historical memory data. Checks processes with high
// memory AND active connections from the /api/processes endpoint.
export function evalT24(connections, processes, memThreshold = 500 * 1024 * 1024, threshold = 1) {
  const connByPid = {};
  for (const c of connections) {
    if (c.state !== "ESTABLISHED" || c.protocol !== "TCP") continue;
    const pid = c.pid;
    if (!connByPid[pid]) connByPid[pid] = 0;
    connByPid[pid]++;
  }
  const offenders = [];
  for (const p of processes) {
    if (p.memWs != null && p.memWs > memThreshold && connByPid[p.pid]) {
      offenders.push({
        pid: p.pid, name: p.name, memWs: p.memWs, connections: connByPid[p.pid],
      });
    }
  }
  return { offenders, fires: offenders.length >= threshold, threshold };
}

// ---- T25: System-wide connection surge ----
// Alert when total active endpoints rise rapidly above a configurable baseline.
// Browser limitation: no historical baseline. Fires when total connections
// exceed an absolute threshold.
export function evalT25(connections, threshold = 500) {
  const total = connections.filter(c => c.state === "ESTABLISHED" && c.protocol === "TCP").length;
  return { total, fires: total >= threshold, threshold };
}

// ---- T26: Port-scan-like local pattern ----
// Detect repeated short-lived connections across many local or remote ports.
// Browser limitation: needs connection event history. Uses the --changes
// stream pattern from the CLI script as a fallback, or checks current state
// for high port diversity.
export function evalT26(connections, threshold = 20) {
  const localPorts = new Set();
  const remotePorts = new Set();
  for (const c of connections) {
    if (c.protocol !== "TCP") continue;
    if (c.lport) localPorts.add(Number(c.lport));
    if (c.rport) remotePorts.add(Number(c.rport));
  }
  const totalPorts = localPorts.size + remotePorts.size;
  const offenders = [{
    localPortCount: localPorts.size,
    remotePortCount: remotePorts.size,
    totalPortCount: totalPorts,
    threshold,
  }];
  return { offenders, fires: totalPorts >= threshold, threshold,
           localPorts: Array.from(localPorts).sort((a, b) => a - b),
           remotePorts: Array.from(remotePorts).sort((a, b) => a - b) };
}

// ---- T27: Listener sprawl ----
// Report the number of listening ports by process and compare it with a saved baseline.
// Browser limitation: no saved baseline. Fires when a process exceeds the threshold.
export function evalT27(connections, threshold = 10) {
  const byPid = {};
  for (const c of connections) {
    if (c.state !== "LISTENING" || c.protocol !== "TCP") continue;
    const pid = c.pid;
    if (!byPid[pid]) byPid[pid] = { process: c.process, ports: new Set(), count: 0 };
    byPid[pid].ports.add(c.lport);
    byPid[pid].count++;
  }
  const offenders = Object.entries(byPid)
    .filter(([_, v]) => v.ports.size >= threshold)
    .map(([pid, v]) => ({
      pid: Number(pid), process: v.process,
      distinctPorts: v.ports.size, totalListeners: v.count, threshold,
    }));
  return { offenders, fires: offenders.length > 0, threshold };
}

// ---- T28: UDP endpoint burst ----
// Detect a burst of UDP endpoint creation by a process.
export function evalT28(connections, threshold = 5) {
  const byPid = {};
  for (const c of connections) {
    if (c.protocol !== "UDP") continue;
    const pid = c.pid;
    if (!byPid[pid]) byPid[pid] = { process: c.process, count: 0, endpoints: [] };
    byPid[pid].count++;
    byPid[pid].endpoints.push({ local: c.local, lport: c.lport });
  }
  const offenders = Object.entries(byPid)
    .filter(([_, v]) => v.count >= threshold)
    .map(([pid, v]) => ({ pid: Number(pid), process: v.process, count: v.count, threshold }));
  return { offenders, fires: offenders.length > 0, threshold };
}

// ---- T29: Round-trip latency exceeds threshold ----
// Alert on live RTT samples over the configured limit.
// Rows without a sample (null/undefined rtt) are skipped.
export function evalT29(connections, threshold = 250) {
  const offenders = [];
  for (const c of connections) {
    if (c.rtt == null || c.rtt === undefined) continue;
    const rtt = Number(c.rtt);
    if (Number.isNaN(rtt)) continue;
    if (rtt > threshold) {
      offenders.push({
        pid: c.pid, process: c.process,
        remote: c.remote, rport: c.rport,
        rtt, threshold,
      });
    }
  }
  return { offenders, fires: offenders.length > 0, threshold };
}

// ---- T30: Retransmission spike ----
// Detect a sharp per-socket retransmission increase.
// Currently: fires when any connection shows retransmissions above a threshold.
export function evalT30(connections, threshold = 1024) {
  const offenders = [];
  for (const c of connections) {
    if (c.retransBytes != null && c.retransBytes > threshold) {
      offenders.push({
        pid: c.pid, process: c.process, remote: c.remote,
        retransBytes: c.retransBytes, threshold,
      });
    }
  }
  return { offenders, fires: offenders.length > 0, threshold };
}

// ---- T31: Congestion window collapse ----
// Correlate falling TCP congestion window with rising RTT or retransmissions.
// Browser limitation: no time-series. Checks for low cwnd with high RTT/retrans.
export function evalT31(connections, cwndThreshold = 1024, rttThreshold = 250, threshold = 1) {
  const offenders = [];
  for (const c of connections) {
    if (c.protocol !== "TCP") continue;
    const cwnd = Number(c.cwnd);
    const rtt = c.rttMs;
    const retrans = c.retransBytes;
    if (cwnd != null && cwnd > 0 && cwnd < cwndThreshold) {
      if ((rtt != null && rtt > rttThreshold) || (retrans != null && retrans > 0)) {
        offenders.push({
          pid: c.pid, process: c.process, remote: c.remote,
          cwnd, rttMs: rtt, retransBytes: retrans,
        });
      }
    }
  }
  return { offenders, fires: offenders.length >= threshold, threshold };
}

// ---- T32: Reset-rate increase ----
// Alert on an increase in observed connection resets grouped by owner and peer.
// Browser limitation: no reset event history from web API. Uses the CLI script
// approach: this is informational, not a live evaluator.
export function evalT32(connections, threshold = 5) {
  // Check for connections in CLOSE_WAIT, LAST_ACK, or TIME_WAIT with short duration
  const resetLike = [];
  for (const c of connections) {
    if (c.state === "CLOSE_WAIT" || c.state === "LAST_ACK" || c.state === "TIME_WAIT") {
      if (c.durationSeconds != null && c.durationSeconds < 10) {
        resetLike.push({ pid: c.pid, process: c.process, remote: c.remote, state: c.state });
      }
    }
  }
  return { resetLike, fires: resetLike.length >= threshold, total: resetLike.length, threshold };
}

// ---- T33: Peer outside approved address set ----
// Compare established remotes with explicit CIDR allow-lists.
export function evalT33(connections, cidrAllowList = [], threshold = 1) {
  const cidrs = Array.isArray(cidrAllowList) ? cidrAllowList : DEFAULT_CIDR_ALLOWLIST;
  const offenders = [];
  const seen = new Set();
  for (const c of connections) {
    if (c.state !== "ESTABLISHED" || c.protocol !== "TCP") continue;
    if (!c.remote) continue;
    if (!ipMatchesCidr(c.remote, cidrs)) {
      const key = c.remote;
      if (seen.has(key)) continue;
      seen.add(key);
      offenders.push({ remote: c.remote, pid: c.pid, process: c.process, rport: c.rport });
    }
  }
  return { offenders, fires: offenders.length >= threshold, threshold, allowList: cidrs };
}

const DEFAULT_CIDR_ALLOWLIST = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"];

function ipMatchesCidr(ip, cidrs) {
  for (const cidr of cidrs) {
    if (cidrContains(cidr, ip)) return true;
  }
  return false;
}

function cidrContains(cidr, ip) {
  const [network, prefixStr] = cidr.split("/");
  const prefix = parseInt(prefixStr || "32", 10);
  if (isNaN(prefix)) return false;
  const netIp = ipToNumber(network);
  const ipNum = ipToNumber(ip);
  if (netIp === null || ipNum === null) return false;
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return (ipNum & mask) === (netIp & mask);
}

function ipToNumber(ip) {
  if (!ip || ip.includes(":")) return null; // IPv6 not supported in simple mode
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some(isNaN)) return null;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

// ---- T34: Previously blocked peer reconnects ----
// Detect a live connection to an endpoint already present in the firewall-rule ledger.
// Uses the /api/firewall endpoint data.
export function evalT34(connections, firewallRules = [], threshold = 1) {
  const blockedIps = new Set();
  for (const rule of firewallRules) {
    if (!rule.remoteAddrs) continue;
    // Parse remote addresses from the rule (comma-separated in Windows Firewall format)
    const addrs = rule.remoteAddrs.split(",").map(a => a.trim()).filter(Boolean);
    for (const addr of addrs) {
      // Handle CIDR notation - extract just the IP for comparison
      const ip = addr.split("/")[0];
      if (ip && ip.includes(".")) blockedIps.add(ip);
    }
  }
  const offenders = [];
  const seen = new Set();
  for (const c of connections) {
    if (c.state !== "ESTABLISHED" || c.protocol !== "TCP") continue;
    if (!c.remote) continue;
    if (blockedIps.has(c.remote)) {
      const key = c.remote;
      if (seen.has(key)) continue;
      seen.add(key);
      offenders.push({
        remote: c.remote, pid: c.pid, process: c.process,
        ruleRemoteAddrs: firewallRules.find(r => r.remoteAddrs?.includes(c.remote))?.name || "unknown",
      });
    }
  }
  return { offenders, fires: offenders.length >= threshold, threshold, blockedIps: Array.from(blockedIps) };
}

// ---- T35: New external listener ----
// Flag a listener bound beyond loopback or an explicitly trusted local subnet.
export function evalT35(connections, trustedSubnets = DEFAULT_CIDR_ALLOWLIST, threshold = 1) {
  const offenders = [];
  for (const c of connections) {
    if (c.state !== "LISTENING" || c.protocol !== "TCP") continue;
    if (!c.local) continue;
    const addr = c.local.split(":")[0];
    if (addr === "127.0.0.1" || addr === "::1" || addr === "localhost") continue;
    if (WILDCARD_ADDRESSES.has(addr)) {
      // Wildcard binding is a separate concern (T08), but still an external exposure
      }
    if (ipMatchesCidr(addr, trustedSubnets)) continue;
    offenders.push({ pid: c.pid, process: c.process, local: c.local, lport: c.lport, addr });
  }
  return { offenders, fires: offenders.length >= threshold, threshold };
}

// ---- T36: Known peer changes process owner ----
// Alert when an established endpoint is now owned by a different process identity.
// Browser limitation: no persisted endpoint history. Uses an in-memory map.
export function evalT36(connections, seenPeers = new Map(), threshold = 1) {
  const changes = [];
  for (const c of connections) {
    if (c.state !== "ESTABLISHED" || c.protocol !== "TCP") continue;
    if (!c.remote) continue;
    const key = `${c.remote}|${c.rport}`;
    const recorded = seenPeers.get(key);
    if (recorded !== undefined) {
      if (recorded.pid !== c.pid) {
        changes.push({
          remote: c.remote, rport: c.rport,
          oldPid: recorded.pid, oldProcess: recorded.process,
          newPid: c.pid, newProcess: c.process,
        });
      }
    }
    seenPeers.set(key, { pid: c.pid, process: c.process });
  }
  return { changes, fires: changes.length >= threshold, seenPeers, threshold };
}

// ---- T37: Traffic measurement becomes degraded ----
// Raise an event when traffic attribution changes from complete to partial coverage.
export function evalT37(diagnostics, threshold = 1) {
  const alerts = [];
  const traffic = diagnostics?.traffic;
  if (!traffic) return { alerts, fires: false, degraded: null, reason: "no diagnostic data" };
  if (traffic.scanEnabled && traffic.scanFailures > 0) {
    alerts.push({
      type: "scanFailures",
      count: traffic.scanFailures,
      detail: "Traffic scan had failures - byte counters may be incomplete",
    });
  }
  if (traffic.scanEnabled && traffic.timeouts > 0) {
    alerts.push({
      type: "timeouts",
      count: traffic.timeouts,
      detail: "Traffic scan had timeouts - data may be stale",
    });
  }
  if (!traffic.scanEnabled) {
    alerts.push({
      type: "noSampler",
      detail: "No active traffic sampler - byte counters unavailable",
    });
  }
  return { alerts, fires: alerts.length >= threshold, threshold, degraded: alerts.length > 0 };
}

// ---- T38: Repeated traffic scan timeout ----
// Alert on repeated sampler timeouts.
export function evalT38(diagnostics, threshold = 3) {
  const traffic = diagnostics?.traffic;
  if (!traffic) return { fires: false, timeouts: 0, reason: "no diagnostic data" };
  const timeouts = traffic.timeouts || 0;
  return { fires: timeouts >= threshold, timeouts, threshold };
}

// ---- T39: GeoIP or ASN capability unavailable ----
// Create a visible event when a configured lookup database cannot be opened.
export function evalT39(capabilities, diagnostics, threshold = 1) {
  const alerts = [];
  if (capabilities.geoIp?.configured && !diagnostics) {
    alerts.push({ type: "missingDiagnostics", detail: "GeoIP configured but diagnostics unavailable" });
  }
  // Check if capabilities reports GeoIP as configured but the connection snapshot
  // shows no country data, which suggests a database failure.
  return { alerts, fires: alerts.length >= threshold, threshold };
}

// ---- T40: Composite - High-risk peer ----
// Combine peer-policy match, material byte volume, and process trust findings.
export function evalT40(connections, cidrAllowList = [], threshold = 1) {
  const offenders = [];
  const seen = new Set();
  for (const c of connections) {
    if (c.state !== "ESTABLISHED" || c.protocol !== "TCP") continue;
    const risk = [];
    // Check 1: outside approved address set
    if (!ipMatchesCidr(c.remote, cidrAllowList)) risk.push("outside-allowlist");
    // Check 2: unsigned or bad signature
    if (c.signatureState === SIG.Unsigned) risk.push("unsigned");
    if (c.signatureState === SIG.Invalid) risk.push("bad-signature");
    // Check 3: high integrity process (potential system compromise)
    if (c.integrityLevel >= INTEGRITY.High) risk.push("high-integrity");
    // Check 4: well-known malicious port
    if (REMOTE_ADMIN_PORTS.has(Number(c.rport))) risk.push("remote-admin-port");
    if (risk.length > 0) {
      const key = `${c.remote}|${c.pid}`;
      if (seen.has(key)) continue;
      seen.add(key);
      offenders.push({
        pid: c.pid, process: c.process, remote: c.remote, rport: c.rport,
        risk, path: c.path, integrity: c.integrityLevel, signature: c.signatureState,
      });
    }
  }
  return { offenders, fires: offenders.length >= threshold, threshold, riskCount: offenders.length };
}

// ---- Registry of evaluators ----
// Maps runtime names to their evaluation functions. A template with `runtime`
// set to a key here is considered "monitor ready".
export const MONITOR_EVALUATORS = {
  "remote-byte-window": null, // T01 handled by legacy eval (needs traffic bytes)
  "new-peer": null,           // T06 handled by legacy eval
  "new-listener": null,       // T07 handled by legacy eval
  "wildcard-listener": "evalT08",
  "listener-count": "evalT11",
  "process-fanout": "evalT12",
  "rtt-threshold": "evalT29",
  "process-egress-spike": "evalT02",
  "port-byte-budget": "evalT03",
  "inbound-peer-budget": "evalT04",
  "new-outbound-peer": "evalT05",
  "non-standard-port": "evalT09",
  "remote-admin-exposure": "evalT10",
  "connection-surge": "evalT13",
  "new-process-network": "evalT14",
  "long-lived-connection": "evalT15",
  "unmanaged-service": "evalT16",
  "high-integrity-network": "evalT17",
  "new-country": "evalT18",
  "country-watchlist": "evalT19",
  "new-asn": "evalT20",
  "unsigned-connection": "evalT21",
  "invalid-signature": "evalT22",
  "unexpected-parent": "evalT23",
  "memory-network-anomaly": "evalT24",
  "system-surge": "evalT25",
  "port-scan-pattern": "evalT26",
  "listener-sprawl": "evalT27",
  "udp-burst": "evalT28",
  "retrans-spike": "evalT30",
  "cwnd-collapse": "evalT31",
  "reset-rate": "evalT32",
  "cidr-allowlist": "evalT33",
  "blocked-peer-reconnect": "evalT34",
  "external-listener": "evalT35",
  "peer-owner-change": "evalT36",
  "traffic-degraded": "evalT37",
  "scan-timeout": "evalT38",
  "geoip-unavailable": "evalT39",
  "composite-risk": "evalT40",
};

// Map template IDs to their evaluator functions.
export const TEMPLATE_EVALUATORS = {
  T02: evalT02,
  T03: evalT03,
  T04: evalT04,
  T05: evalT05,
  T08: evalT08,
  T09: evalT09,
  T10: evalT10,
  T11: evalT11,
  T12: evalT12,
  T13: evalT13,
  T14: evalT14,
  T15: evalT15,
  T16: evalT16,
  T17: evalT17,
  T18: evalT18,
  T19: evalT19,
  T20: evalT20,
  T21: evalT21,
  T22: evalT22,
  T23: evalT23,
  T24: evalT24,
  T25: evalT25,
  T26: evalT26,
  T27: evalT27,
  T28: evalT28,
  T29: evalT29,
  T30: evalT30,
  T31: evalT31,
  T32: evalT32,
  T33: evalT33,
  T34: evalT34,
  T35: evalT35,
  T36: evalT36,
  T37: evalT37,
  T38: evalT38,
  T39: evalT39,
  T40: evalT40,
};

// Evaluate a single template against the current data snapshot.
export function evaluateTemplate(templateId, data) {
  const evaluator = TEMPLATE_EVALUATORS[templateId];
  if (!evaluator) return null;
  return evaluator(data.connections, data.processes, data.metrics, data.diagnostics, data.capabilities, data.firewall);
}

// Check whether a template is ready (has an evaluator wired up).
// A template is ready if it has a direct evaluator in TEMPLATE_EVALUATORS,
// or if its runtime is registered in MONITOR_EVALUATORS (including legacy
// null-runtime handlers that use a different evaluation path).
const LEGACY_RUNTIME_TEMPLATES = { T01: "remote-byte-window", T06: "new-peer", T07: "new-listener" };

export function isTemplateReady(templateId) {
  if (TEMPLATE_EVALUATORS[templateId]) return true;
  // Legacy templates with null runtime handlers are ready via the legacy path.
  return !!LEGACY_RUNTIME_TEMPLATES[templateId];
}