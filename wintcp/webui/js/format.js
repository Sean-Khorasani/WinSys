// format.js - Intl.* formatters

const nf = new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 });
const nf0 = new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 });
const nf2 = new Intl.NumberFormat(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });

export function fmtNum(v, digits = 1) {
  if (v == null || Number.isNaN(v)) return "-";
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: digits }).format(v);
}

export function fmtInt(v) {
  if (v == null || Number.isNaN(v)) return "-";
  return nf0.format(v);
}

export function fmtBytes(v, si = false) {
  if (v == null || Number.isNaN(v)) return "-";
  const base = si ? 1000 : 1024;
  const units = si ? ["B", "KB", "MB", "GB", "TB"] : ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  while (v >= base && i < units.length - 1) { v /= base; i++; }
  return (i === 0 ? nf0.format(v) : nf.format(v)) + " " + units[i];
}

export function fmtBps(v, si = false) {
  if (v == null || Number.isNaN(v)) return "-";
  return fmtBytes(v, si) + "/s";
}

export function fmtPct(v, digits = 1) {
  if (v == null || Number.isNaN(v)) return "-";
  return nf.format(v) + "%";
}

export function fmtDuration(seconds) {
  if (seconds == null || Number.isNaN(seconds)) return "-";
  if (seconds < 60) return seconds + "s";
  if (seconds < 3600) return Math.floor(seconds / 60) + "m " + Math.floor(seconds % 60) + "s";
  if (seconds < 86400) return Math.floor(seconds / 3600) + "h " + Math.floor((seconds % 3600) / 60) + "m";
  return Math.floor(seconds / 86400) + "d " + Math.floor((seconds % 86400) / 3600) + "h";
}

export function fmtTime(date) {
  return new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(date);
}

export function fmtDate(date) {
  return new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "numeric" }).format(date);
}

export function fmtRelative(date) {
  const diff = (Date.now() - date.getTime()) / 1000;
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (Math.abs(diff) < 60) return rtf.format(-Math.round(diff), "second");
  if (Math.abs(diff) < 3600) return rtf.format(-Math.round(diff / 60), "minute");
  if (Math.abs(diff) < 86400) return rtf.format(-Math.round(diff / 3600), "hour");
  return rtf.format(-Math.round(diff / 86400), "day");
}

export function fmtUptime(seconds) {
  if (seconds == null || Number.isNaN(seconds)) return "-";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return d + "d " + h + "h " + m + "m";
  if (h > 0) return h + "h " + m + "m";
  return m + "m";
}
