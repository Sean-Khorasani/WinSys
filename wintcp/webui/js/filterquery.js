const TEXT_FIELDS = new Set([
  "process", "service", "path", "host", "hostname", "local", "remote",
  "state", "proto", "country", "family",
]);
const NUMBER_FIELDS = new Set(["pid", "port", "lport", "rport"]);
const FIELDS = new Set([...TEXT_FIELDS, ...NUMBER_FIELDS]);

function tokenize(query) {
  const tokens = [];
  let token = "";
  let quoted = false;
  for (let index = 0; index < query.length; index++) {
    const character = query[index];
    if (character === '"') {
      if (quoted && query[index + 1] === '"') {
        token += '"';
        index++;
      } else {
        quoted = !quoted;
      }
    } else if (/\s/.test(character) && !quoted) {
      if (token) tokens.push(token);
      token = "";
    } else {
      token += character;
    }
  }
  if (quoted) return { tokens: [], error: "Close the quoted filter value with a double quote." };
  if (token) tokens.push(token);
  return { tokens, error: null };
}

function parseRange(field, value) {
  if (!/^\d+(?:-\d+)?$/.test(value)) return null;
  const [minimumText, maximumText = minimumText] = value.split("-");
  const minimum = Number(minimumText);
  const maximum = Number(maximumText);
  const ceiling = field === "pid" ? 0xffffffff : 65535;
  if (!Number.isSafeInteger(minimum) || !Number.isSafeInteger(maximum) ||
      minimum > maximum || maximum > ceiling) return null;
  return { minimum, maximum };
}

export function parseConnectionQuery(query) {
  const { tokens, error: tokenError } = tokenize(String(query || ""));
  if (tokenError) return { terms: [], clauses: [], error: tokenError };
  const terms = [];
  const clauses = [];
  let excludeNext = false;
  for (let raw of tokens) {
    if (raw.toLowerCase() === "exclude:") {
      excludeNext = true;
      continue;
    }
    let exclude = excludeNext;
    excludeNext = false;
    if (raw.toLowerCase().startsWith("exclude:")) {
      raw = raw.slice("exclude:".length);
      exclude = true;
    }
    if (!raw) return { terms, clauses, error: "An exclusion must name a filter term." };

    const separator = raw.indexOf(":");
    if (separator <= 0 || !/^[a-z][a-z0-9_-]*$/i.test(raw.slice(0, separator))) {
      terms.push({ value: raw.toLocaleLowerCase(), exclude });
      continue;
    }
    const name = raw.slice(0, separator).toLowerCase();
    const value = raw.slice(separator + 1);
    if (!FIELDS.has(name)) {
      return { terms, clauses, error: `Unsupported filter field “${name}”.` };
    }
    if (!value) return { terms, clauses, error: `Add a value after “${name}:”.` };

    let field = name;
    let matchValue = value;
    if ((name === "local" || name === "remote") && value.toLowerCase().startsWith("port:")) {
      field = name === "local" ? "lport" : "rport";
      matchValue = value.slice("port:".length);
    }
    if (field === "hostname") field = "host";
    if (field === "port" || NUMBER_FIELDS.has(field)) {
      const range = parseRange(field, matchValue);
      if (!range) return { terms, clauses, error: `Invalid ${field} value or range.` };
      clauses.push({ field, ...range, exclude });
    } else {
      clauses.push({ field, value: matchValue.toLocaleLowerCase(), exclude });
    }
  }
  if (excludeNext) return { terms, clauses, error: "An exclusion must be followed by a filter term." };
  return { terms, clauses, error: null };
}

function isIPv4Address(value) {
  const octets = value.split(".");
  return octets.length === 4 && octets.every((octet) => /^\d{1,3}$/.test(octet) &&
    Number(octet) >= 0 && Number(octet) <= 255);
}

function fieldValues(row, field) {
  switch (field) {
    case "process": return [row.process, row.processName];
    case "path": return [row.path];
    case "service": return [row.service];
    case "host": return [row.hostname];
    case "local": return [row.local, row.localAddress];
    case "remote": return [row.remote, row.remoteAddress];
    case "state": return [row.state];
    case "proto": return [row.proto];
    case "country": return [row.country];
    case "family": {
      if (String(row.family || "").toLowerCase() === "ipv4") return ["ipv4"];
      if (String(row.family || "").toLowerCase() === "ipv6") return ["ipv6"];
      const protocol = String(row.proto || "").toLowerCase();
      if (protocol.includes("v6")) return ["ipv6"];
      if (protocol.includes("v4")) return ["ipv4"];
      const addresses = [row.local || row.localAddress, row.remote || row.remoteAddress]
        .filter((address) => typeof address === "string" && address.trim() &&
          !["*", "—", "-"].includes(address.trim()));
      const families = new Set(addresses.map((address) => address.includes(":") ? "ipv6"
        : isIPv4Address(address) ? "ipv4" : null).filter(Boolean));
      return families.size === 1 ? [...families] : [];
    }
    default: return [];
  }
}

function textMatch(row, field, value) {
  if (field === "proto" && ["4", "ipv4", "6", "ipv6"].includes(value)) {
    const family = String(value) === "4" || value === "ipv4" ? "ipv4" : "ipv6";
    return fieldValues(row, "family").some((candidate) => candidate === family);
  }
  const normalize = (text) => field === "state" ? text.replace(/-/g, "_") : text;
  const requested = normalize(value);
  return fieldValues(row, field).some((candidate) => candidate != null &&
    normalize(String(candidate).toLocaleLowerCase()).includes(requested));
}

function numberValues(row, field) {
  const integer = (value) => {
    const number = typeof value === "number" ? value : /^\d+$/.test(String(value ?? "")) ? Number(value) : NaN;
    return Number.isSafeInteger(number) && number >= 0 ? number : null;
  };
  if (field === "pid") {
    const pid = integer(row.pid);
    return [pid === 0 ? null : pid];
  }
  const local = integer(row.lport);
  const remote = integer(row.rport);
  const knownLocal = local === 0 ? null : local;
  const knownRemote = remote === 0 ? null : remote;
  if (field === "lport") return [knownLocal];
  if (field === "rport") return [knownRemote];
  return [knownLocal, knownRemote];
}

export function matchesConnectionQuery(row, parsed) {
  if (!parsed || parsed.error) return false;
  const textFields = ["process", "path", "service", "local", "remote", "state",
    "host", "proto", "country", "family", "lport", "rport", "pid"];
  const matchesTerm = ({ value, exclude }) => {
    const matched = textFields.some((field) => {
      const candidates = fieldValues(row, field);
      return candidates.some((candidate) => candidate != null &&
        String(candidate).toLocaleLowerCase().includes(value));
    }) || numberValues(row, "pid").concat(numberValues(row, "lport"), numberValues(row, "rport"))
      .some((candidate) => candidate != null && String(candidate) === value);
    return exclude ? !matched : matched;
  };
  const matchesClause = (clause) => {
    const matched = NUMBER_FIELDS.has(clause.field)
      ? numberValues(row, clause.field).some((candidate) => candidate != null &&
          candidate >= clause.minimum && candidate <= clause.maximum)
      : textMatch(row, clause.field, clause.value);
    return clause.exclude ? !matched : matched;
  };
  return parsed.terms.every(matchesTerm) && parsed.clauses.every(matchesClause);
}
