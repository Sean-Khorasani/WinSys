export function endpointNumber(value, maximum = Number.MAX_SAFE_INTEGER) {
  if (typeof value === "string") {
    if (!/^\d+$/.test(value.trim())) return null;
    value = Number(value.trim());
  }
  return Number.isSafeInteger(value) && value >= 0 && value <= maximum ? value : null;
}

export function normalizeConnection(row) {
  return {
    ...row,
    pid: endpointNumber(row.pid, 0xffffffff),
    ppid: endpointNumber(row.ppid, 0xffffffff),
    lport: endpointNumber(row.lport, 65535),
    rport: endpointNumber(row.rport, 65535),
    removed: row.removed === true,
  };
}

export function normalizeConnections(snapshot) {
  if (!snapshot || !Array.isArray(snapshot.connections)) {
    throw new Error(snapshot?.error || "The server did not return a connection snapshot");
  }
  return {
    ...snapshot,
    connections: snapshot.connections.filter((row) => row && typeof row === "object")
      .map(normalizeConnection),
  };
}

export function liveConnectionSummary(rows) {
  const byState = Object.create(null);
  let total = 0;
  for (const row of Array.isArray(rows) ? rows : []) {
    if (!row || row.removed === true) continue;
    const state = String(row.state || "UNKNOWN").trim().toUpperCase() || "UNKNOWN";
    byState[state] = (byState[state] || 0) + 1;
    total++;
  }
  return { total, byState };
}

function tsvCell(value) {
  const text = value == null ? "" : String(value);
  const normalized = text.trim().toLowerCase();
  if (["pending", "...pending...", "…", "—", "-", "(resolving...)", "(not resolved)"]
    .includes(normalized)) return "";
  return /[\t\r\n"]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

export function connectionRowsTsv(rows, visibleColumns = null) {
  const fields = {
    process: (row) => row.process || row.processName,
    pid: (row) => endpointNumber(row.pid, 0xffffffff) || null,
    proto: (row) => row.proto,
    local: (row) => row.local || row.localAddress,
    lport: (row) => row.lport,
    remote: (row) => row.remote || row.remoteAddress,
    rport: (row) => {
      const port = endpointNumber(row.rport, 65535);
      return port === 0 && String(row.proto || "").toUpperCase().startsWith("UDP")
        ? "*" : port;
    },
    hostname: remoteHostnameValue,
    country: (row) => row.country,
    path: (row) => row.path && row.path !== "System" ? row.path : null,
    state: (row) => row.removed ? "Closed (retained history)" : row.state,
    exposure: (row) => exposureOf(row).label,
  };
  const defaults = [
    ["process", "Process"], ["pid", "PID"], ["proto", "Proto"],
    ["local", "Local address"], ["lport", "Local port"],
    ["remote", "Remote address"], ["rport", "Remote port"],
    ["hostname", "Hostname"], ["country", "Country"],
    ["path", "Path"], ["state", "State"],
  ];
  const selectedColumns = Array.isArray(visibleColumns)
    ? visibleColumns.filter((column) => column && column.key !== "actions" &&
        typeof fields[column.key] === "function")
      .map((column) => [column.key, column.label || column.key])
    : defaults;
  const columns = selectedColumns.length ? selectedColumns : defaults;
  const lines = [columns.map(([, label]) => tsvCell(label)).join("\t")];
  for (const row of Array.isArray(rows) ? rows : []) {
    if (!row || typeof row !== "object") continue;
    lines.push(columns.map(([key]) => tsvCell(fields[key](row))).join("\t"));
  }
  return lines.length > 1 ? `${lines.join("\r\n")}\r\n` : "";
}

export function connectionKey(row) {
  if (row.id != null) return `connection:${row.id}`;
  return JSON.stringify([row.pid, row.proto, row.local, row.lport, row.remote, row.rport]);
}

export function processKey(row) {
  return row.instanceId || `${row.pid}:${row.startedAt || "unknown"}`;
}

export function endpoint(address, port) {
  if (!address || address === "*" || address === "—") return address || "—";
  if (port == null) return address;
  return `${address.includes(":") ? `[${address}]` : address}:${port}`;
}

function isUnspecifiedAddress(address) {
  let value = String(address || "").toLowerCase().split("%")[0];
  if (value === "0.0.0.0") return true;
  if (!value.includes(":")) return false;

  const dottedIndex = value.lastIndexOf(":");
  if (value.includes(".")) {
    const ipv4 = value.slice(dottedIndex + 1).split(".").map(Number);
    if (ipv4.length !== 4 || ipv4.some((part) => !Number.isInteger(part) || part < 0 || part > 255))
      return false;
    value = value.slice(0, dottedIndex + 1) +
      ((ipv4[0] << 8) | ipv4[1]).toString(16) + ":" +
      ((ipv4[2] << 8) | ipv4[3]).toString(16);
  }

  const halves = value.split("::");
  if (halves.length > 2) return false;
  const parseHalf = (half) => half ? half.split(":") : [];
  const left = parseHalf(halves[0]);
  const right = parseHalf(halves[1] || "");
  if ([...left, ...right].some((part) => !/^[0-9a-f]{1,4}$/.test(part))) return false;
  const groups = [...left, ...right];
  if (halves.length === 1 ? groups.length !== 8 : groups.length >= 8) return false;
  return groups.every((part) => Number.parseInt(part, 16) === 0);
}

export function remoteIpValue(row) {
  if (!row || row.removed || String(row.state || "").toUpperCase().startsWith("LISTEN") ||
      !endpointNumber(row.rport, 65535)) return null;
  const address = String(row.remote || row.remoteAddress || "");
  return ["", "*", "—", "-"].includes(address.toLowerCase()) || isUnspecifiedAddress(address)
    ? null : address;
}

export function remoteEndpointValue(row) {
  const address = remoteIpValue(row);
  const port = endpointNumber(row?.rport, 65535);
  return address && port ? endpoint(address, port) : null;
}

export function remoteHostnameValue(row) {
  return remoteIpValue(row) ? resolvedHostname(row.hostname) : null;
}

export function resolvedHostname(value) {
  const name = String(value || "").trim();
  return !name || ["pending", "...pending...", "…", "—", "-", "(resolving...)", "(not resolved)"]
    .includes(name.toLowerCase()) ? null : name;
}

export function hostnameLabel(value) {
  const name = String(value || "").trim();
  return ["pending", "...pending...", "(resolving...)", "…"].includes(name.toLowerCase())
    ? "Resolving…" : resolvedHostname(name) || "Not resolved";
}

export function exposureOf(row) {
  let address = String(row.local || row.localAddress || "").toLowerCase().split("%")[0];
  const mappedDotted = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(address);
  const mappedHex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(address);
  if (mappedDotted) {
    address = mappedDotted[1];
  } else if (mappedHex) {
    const high = Number.parseInt(mappedHex[1], 16);
    const low = Number.parseInt(mappedHex[2], 16);
    address = `${high >>> 8}.${high & 255}.${low >>> 8}.${low & 255}`;
  }
  if (address === "0.0.0.0" || address === "::" || address === "*") {
    return { key: "wildcard", label: "All interfaces", hint: "Bound to all interfaces; firewall and routing determine reachability" };
  }
  const parts = address.split(".");
  const validIpv4 = parts.length === 4 && parts.every((part) =>
    /^\d{1,3}$/.test(part) && Number(part) <= 255);
  const octets = validIpv4 ? parts.map(Number) : [];
  if ((validIpv4 && octets[0] === 127) || address === "::1") {
    return { key: "loopback", label: "Loopback", hint: "Bound to the local loopback interface" };
  }
  const privateV4 = validIpv4 && (octets[0] === 10 ||
    (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
    (octets[0] === 192 && octets[1] === 168) ||
    (octets[0] === 169 && octets[1] === 254));
  const privateV6 = /^(?:f[cd][0-9a-f]{2}:|fe[89ab][0-9a-f]:)/.test(address);
  if (privateV4 || privateV6) {
    return { key: "private", label: "Private / link-local", hint: "Bound to one private or link-local address" };
  }
  return { key: "specific", label: "Specific address", hint: "Bound to one address; binding alone does not prove external reachability" };
}
