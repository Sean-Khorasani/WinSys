// Privacy-aware client-side export for already verified incident archives.
// This transformation is presentation/export only; it never mutates the archive.
export function buildIncidentExport(manifest, records, profile) {
  if (!manifest || typeof manifest !== "object" || !Array.isArray(records) ||
      (profile !== "private" && profile !== "full"))
    throw new TypeError("Invalid incident export input.");

  const payload = { schemaVersion: 1, exportProfile: profile,
    manifest, records };
  if (profile === "full") return payload;

  const pseudonyms = new Map();
  const pseudonym = (field, value) => {
    const key = `${field}:${String(value)}`;
    if (!pseudonyms.has(key)) pseudonyms.set(key, `${field}-${pseudonyms.size + 1}`);
    return pseudonyms.get(key);
  };
  const privateFields = new Set([
    "imagePath", "observedImageName", "hostname", "domain", "host",
    "processName", "applicationName", "userName", "username", "url",
    "urlPath", "urlQuery", "initiator", "title",
  ]);
  const redact = (value, field = "") => {
    if (Array.isArray(value)) return value.map((item) => redact(item, field));
    if (!value || typeof value !== "object") {
      if (privateFields.has(field)) return null;
      if (field === "reason") return "[omitted]";
      if (field === "address" && typeof value === "string")
        return pseudonym("endpoint", value);
      if (field === "pid" && value != null) return pseudonym("process", value);
      if (field === "creationTimeFileTime" && value != null)
        return pseudonym("process-instance", value);
      if (field === "sourceSequence" && value != null)
        return pseudonym("sequence", value);
      if ((field === "evidenceIds" || field === "id" || field.endsWith("Id") ||
           field === "flowGeneration" || field === "machinePseudonym" ||
           field === "interfaceGuid") && value != null)
        return pseudonym("identifier", value);
      return value;
    }
    const result = {};
    for (const [key, child] of Object.entries(value)) result[key] = redact(child, key);
    return result;
  };
  const result = redact(payload);
  result.exportProfile = "private";
  result.manifest.privacy =
    "names_reasons_and_addresses_redacted; identifiers_pseudonymized";
  return result;
}
