const NUMBER_FIELDS = new Set(["pid", "lport", "rport"]);
const TEXT_FIELDS = new Set(["processInstanceId", "remote", "local", "country", "proto", "state"]);

export function normalizeConnectionFilters(filters) {
  if (!Array.isArray(filters)) throw new Error("Connection filters must be a list");
  return filters.map(({ field, value, exclude = false }) => {
    if (NUMBER_FIELDS.has(field)) {
      const maximum = field === "pid" ? 0xffffffff : 65535;
      if (!Number.isSafeInteger(value) || value < 0 || value > maximum)
        throw new Error(`Invalid ${field} filter`);
    } else if (!TEXT_FIELDS.has(field) || typeof value !== "string" || !value.trim()) {
      throw new Error("Unknown or empty connection filter");
    }
    return { field, value, exclude: Boolean(exclude) };
  });
}

export function matchesConnectionFilters(row, filters = []) {
  return filters.every(({ field, value, exclude }) => {
    const actual = row[field];
    const matches = actual != null && (NUMBER_FIELDS.has(field)
      ? actual === value : String(actual).toLowerCase() === value.toLowerCase());
    return exclude ? !matches : matches;
  });
}

export function processConnectionFilter(row) {
  const instance = row.instanceId || row.processInstanceId;
  return instance ? { field: "processInstanceId", value: instance }
    : Number.isSafeInteger(row.pid) && row.pid > 0 ? { field: "pid", value: row.pid } : null;
}

export function connectionFilterLabel(filter) {
  const names = { pid: "PID", lport: "Local port", rport: "Remote port",
    processInstanceId: "Process instance", remote: "Remote IP", local: "Local IP",
    country: "Country", proto: "Protocol", state: "State" };
  return `${filter.exclude ? "Exclude " : ""}${names[filter.field]}: ${filter.value}`;
}

export function investigateConnections(filters, mode = "replace") {
  document.dispatchEvent(new CustomEvent("wintcp:investigate", {
    detail: { filters: normalizeConnectionFilters(filters), mode },
  }));
}
