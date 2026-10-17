// legacy/presets.js - Saved views (column presets, filters, sort)

export const COLUMN_PRESETS = {
  default: ["process", "pid", "proto", "local", "remote", "state"],
  minimal: ["process", "pid", "state"],
  full: ["process", "pid", "proto", "local", "remote", "state", "traffic", "host", "country"],
  network: ["process", "pid", "proto", "local", "remote", "state", "rtt", "traffic"],
  security: ["process", "pid", "integrity", "signature", "path"],
};

export function getPreset(name) {
  return COLUMN_PRESETS[name] || COLUMN_PRESETS.default;
}
