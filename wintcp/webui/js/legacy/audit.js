// legacy/audit.js - Audit trail management

export function formatAuditRecord(record) {
  const ts = record.ts || "";
  const action = record.action || "";
  const detail = record.detail || "";
  return `[${ts}] ${action}: ${detail}`;
}

export function filterAudit(records, query) {
  if (!query) return records;
  const q = query.toLowerCase();
  return records.filter(r =>
    (r.action || "").toLowerCase().includes(q) ||
    (r.detail || "").toLowerCase().includes(q)
  );
}
