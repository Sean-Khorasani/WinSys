import { openContextMenu } from "./contextmenu.js";
import { copyText } from "./feedback.js";
import { processConnectionFilter, investigateConnections } from "../connectionfilters.js";

export function processMenu(row, { event, anchor, onDetails, onBlockApplication, onAllowApplication }) {
  const scope = processConnectionFilter(row);
  const path = typeof row.path === "string" ? row.path.trim() : "";
  const pathKnown = Boolean(path) && path.includes("\\") && path.toLowerCase() !== "system" &&
    !["pending", "...pending...", "…", "—", "-", "(resolving...)", "(not resolved)"]
      .includes(path.toLowerCase());
  const hasProcessIdentity = Number.isSafeInteger(Number(row.pid)) && Number(row.pid) > 0 &&
    typeof row.instanceId === "string" && row.instanceId.length > 0;
  const hasApplicationTarget = pathKnown && hasProcessIdentity;
  const applicationReason = !pathKnown
    ? "A readable full executable path is required"
    : !hasProcessIdentity ? "A verified process lifetime is required" : undefined;
  const allowApplicationTarget = hasApplicationTarget && typeof onAllowApplication === "function";
  return openContextMenu([
    { label: "Process details", action: () => onDetails(row) },
    { label: "Block this executable", destructive: true,
      disabled: !hasApplicationTarget || typeof onBlockApplication !== "function",
      reason: applicationReason || (typeof onBlockApplication !== "function"
        ? "Application rules are unavailable in this view" : undefined),
      action: () => onBlockApplication?.(row) },
    { label: "Allow this executable", disabled: !allowApplicationTarget,
      reason: applicationReason || (!onAllowApplication
        ? "Application rules are unavailable in this view" : undefined),
      action: () => onAllowApplication?.(row) },
    { label: scope?.field === "processInstanceId" ? "Show this process's connections" : "Show connections for this PID",
      disabled: !scope, reason: !scope ? "A process identity is unavailable" : undefined,
      action: () => investigateConnections([scope]) },
    { separator: true },
    { label: "Copy process name", disabled: !row.name,
      action: () => copyText(row.name, "Process name") },
    { label: "Copy PID", disabled: !row.pid,
      action: () => copyText(row.pid, "PID") },
    { label: "Copy executable path", disabled: !row.path || row.path === "System",
      reason: !row.path || row.path === "System" ? "An executable path is unavailable" : undefined,
      action: () => copyText(row.path, "Executable path") },
  ], { event, anchor, label: `${row.name || "Process"} actions` });
}
