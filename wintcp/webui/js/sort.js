const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });
const unknownValues = new Set(["", "-", "—", "–", "n/a", "unknown", "unavailable", "(unnamed)"]);
const stateOrder = [
  "LISTENING", "ESTABLISHED", "SYN_SENT", "SYN_RECEIVED", "FIN_WAIT_1",
  "FIN_WAIT_2", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB",
];
const stateRanks = new Map(stateOrder.map((state, index) => [state, index]));

function knownText(value) {
  if (value === null || value === undefined) return null;
  const text = String(value).trim();
  return unknownValues.has(text.toLowerCase()) ? null : text;
}

function stableKeyCompare(a, b, keyOf, tieBreak) {
  if (tieBreak) {
    const result = tieBreak(a, b);
    if (result) return result;
  }
  const left = String(keyOf(a) ?? "");
  const right = String(keyOf(b) ?? "");
  return left < right ? -1 : left > right ? 1 : 0;
}

function compareValues(a, b, direction, read, compare, keyOf, tieBreak) {
  const left = read(a);
  const right = read(b);
  if (left === null && right === null) return stableKeyCompare(a, b, keyOf, tieBreak);
  if (left === null) return 1;
  if (right === null) return -1;
  const order = compare(left, right);
  return (direction === "asc" ? order : -order) || stableKeyCompare(a, b, keyOf, tieBreak);
}

export function textComparator(read, keyOf, tieBreak = null) {
  return (a, b, direction) => compareValues(
    a, b, direction,
    (row) => knownText(read(row)),
    (left, right) => collator.compare(left, right),
    keyOf, tieBreak,
  );
}

export function numberComparator(read, keyOf, tieBreak = null) {
  return (a, b, direction) => compareValues(
    a, b, direction,
    (row) => {
      const value = read(row);
      if (value === null || value === undefined || (typeof value === "string" && !value.trim())) return null;
      if (typeof value === "bigint") return value;
      if (typeof value === "string" && /^-?\d+$/.test(value.trim())) {
        try { return BigInt(value.trim()); } catch { return null; }
      }
      const numeric = typeof value === "number" ? value : Number(String(value).trim());
      return Number.isFinite(numeric) ? numeric : null;
    },
    (left, right) => typeof left === "bigint" && typeof right === "bigint"
      ? left < right ? -1 : left > right ? 1 : 0
      : typeof left === "bigint" || typeof right === "bigint"
        ? Number(left) - Number(right)
        : left - right,
    keyOf, tieBreak,
  );
}

function parseAddress(value) {
  const text = knownText(value);
  if (!text) return null;
  const bracketed = text.startsWith("[") && text.endsWith("]");
  const unwrapped = bracketed ? text.slice(1, -1) : text;
  const scopeIndex = unwrapped.indexOf("%");
  const address = scopeIndex < 0 ? unwrapped : unwrapped.slice(0, scopeIndex);
  const scope = scopeIndex < 0 ? "" : unwrapped.slice(scopeIndex + 1);
  const ipv4 = address.split(".");
  if (ipv4.length === 4 && ipv4.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)) {
    return { family: 4, bytes: ipv4.map(Number), scope };
  }
  if (!address.includes(":")) return null;
  let expanded = address;
  const embedded = /(?:^|:)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(expanded);
  if (embedded) {
    const parts = embedded[1].split(".").map(Number);
    if (!parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255)) return null;
    const hex = `${((parts[0] << 8) | parts[1]).toString(16)}:${((parts[2] << 8) | parts[3]).toString(16)}`;
    expanded = expanded.slice(0, embedded.index) + (embedded[0].startsWith(":") ? ":" : "") + hex;
  }
  if ((expanded.match(/::/g) || []).length > 1) return null;
  const compressed = expanded.includes("::");
  const [leftText, rightText = ""] = expanded.split("::");
  const left = leftText ? leftText.split(":") : [];
  const right = rightText ? rightText.split(":") : [];
  const missing = 8 - left.length - right.length;
  if ((!compressed && missing !== 0) || (compressed && missing < 1)) return null;
  const groups = [...left, ...Array(compressed ? missing : 0).fill("0"), ...right];
  if (groups.length !== 8 || groups.some((part) => !/^[\da-f]{1,4}$/i.test(part))) return null;
  const bytes = groups.flatMap((part) => {
    const word = Number.parseInt(part, 16);
    return [word >> 8, word & 255];
  });
  return { family: 6, bytes, scope };
}

function compareAddress(left, right) {
  if (left.family !== right.family) return left.family - right.family;
  for (let index = 0; index < left.bytes.length; index++) {
    if (left.bytes[index] !== right.bytes[index]) return left.bytes[index] - right.bytes[index];
  }
  const leftScope = left.scope || "";
  const rightScope = right.scope || "";
  const leftNumeric = /^\d+$/.test(leftScope) ? Number(leftScope) : null;
  const rightNumeric = /^\d+$/.test(rightScope) ? Number(rightScope) : null;
  if (leftNumeric !== null && rightNumeric !== null) return leftNumeric - rightNumeric;
  return collator.compare(leftScope, rightScope);
}

export function addressComparator(read, keyOf, tieBreak = null) {
  return (a, b, direction) => compareValues(
    a, b, direction,
    (row) => parseAddress(read(row)),
    compareAddress,
    keyOf, tieBreak,
  );
}

export function stateComparator(read, keyOf, tieBreak = null) {
  return (a, b, direction) => compareValues(
    a, b, direction,
    (row) => {
      const state = knownText(read(row))?.toUpperCase();
      return state && stateRanks.has(state) ? state : null;
    },
    (left, right) => stateRanks.get(left) - stateRanks.get(right),
    keyOf, tieBreak,
  );
}
