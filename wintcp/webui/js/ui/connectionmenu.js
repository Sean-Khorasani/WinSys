import { connectionRowsTsv, endpoint, remoteEndpointValue, remoteHostnameValue, remoteIpValue } from "../connections.js";
import { copyText } from "./feedback.js";
import { openContextMenu } from "./contextmenu.js";
import { processConnectionFilter, investigateConnections } from "../connectionfilters.js";

function closeUnavailableReason(row) {
  if (row.removed) return "Retained history is no longer live";
  const protocol = String(row.proto || "").toUpperCase();
  if (!protocol.startsWith("TCP")) return "Windows teardown supports TCP connections only";
  if (protocol.includes("V6") || row.family === "IPv6") return "Windows exposes no public IPv6 connection teardown";
  if (!protocol.includes("V4") && row.family !== "IPv4") return "The address family is unknown, so this connection cannot be closed";
  if (String(row.state || "").toUpperCase() !== "ESTABLISHED") return "Only established TCP connections can be closed";
  if (!(Number(row.pid) > 0) || !row.processInstanceId) return "The owning process lifetime is unknown, so this target cannot be verified";
  return null;
}

const unavailableCopyValues = new Set([
  "", "pending", "...pending...", "…", "—", "-", "(resolving...)", "(not resolved)",
]);

function copyableValue(value) {
  if (typeof value === "number") return Number.isSafeInteger(value) && value > 0;
  const text = String(value ?? "").trim();
  return !unavailableCopyValues.has(text.toLowerCase());
}

function positiveInteger(value, maximum) {
  const text = String(value ?? "").trim();
  if (!/^\d+$/.test(text)) return null;
  const number = Number(text);
  return Number.isSafeInteger(number) && number > 0 && number <= maximum ? number : null;
}

export function connectionMenu(row, { event, anchor, onDetails, onClose, onBlock, onBlockApplication, onBlockApplicationPeer, onBlockServicePeer, onCloseAndBlock, blockReason, serializeRow }) {
  const remote = row.remote || row.remoteAddress || "";
  const remoteIp = remoteIpValue(row);
  const remoteEndpoint = remoteEndpointValue(row);
  const hostname = remoteHostnameValue(row);
  const hasRemote = Boolean(remoteIp);
  const hasHostname = Boolean(hostname);
  const isListener = String(row.state || "").toUpperCase().startsWith("LISTEN");
  const localAddress = row.local || row.localAddress || "";
  const localPort = positiveInteger(row.lport, 65535);
  const localEndpoint = copyableValue(localAddress) && localPort
    ? endpoint(localAddress, localPort) : null;
  const canInvestigateInbound = !row.removed && isListener && Boolean(localAddress) &&
    Number.isInteger(localPort) && localPort > 0 && localPort <= 65535 &&
    /^(TCP|UDP)/i.test(String(row.proto || ""));
  const closeReason = closeUnavailableReason(row);
  const processPath = typeof row.path === "string" ? row.path.trim() : "";
  const pathKnown = Boolean(processPath) && processPath.includes("\\") &&
    processPath.toLowerCase() !== "system" && copyableValue(processPath);
  const processIdentityKnown = Number.isSafeInteger(Number(row.pid)) && Number(row.pid) > 0 &&
    typeof row.processInstanceId === "string" && row.processInstanceId.length > 0;
  const applicationReason = !pathKnown ? "A readable full executable path is required" :
    !processIdentityKnown ? "A verified process lifetime is required" : undefined;
  const applicationPeerReason = applicationReason || blockReason ||
    !/^(?:TCPv4|TCPv6)$/i.test(String(row.proto || "")) ?
      (applicationReason || blockReason || "Application-peer rules support TCP connections only") :
    String(row.state || "").toUpperCase() !== "ESTABLISHED" ? "Only established connections have a peer to scope" :
    !row.idExact ? "A stable connection identity is unavailable" :
    !remoteIp || remoteIp.includes("%") ? "A literal, unscoped remote IP address is required" :
    !positiveInteger(row.rport, 65535) ? "A valid remote TCP port is unavailable" : undefined;
  const service = typeof row.service === "string" ? row.service.trim() : "";
  const servicePeerReason = applicationPeerReason || !service ||
    !/^[A-Za-z0-9_.-]{1,256}$/.test(service)
      ? (applicationPeerReason || "A known Windows service short name is required") : undefined;
  const processScope = processConnectionFilter(row);
  const copyItem = (label, value, available = value != null && value !== "") => ({
    label: `Copy ${label === "PID" ? label : label[0].toLowerCase() + label.slice(1)}`,
    disabled: !available || !copyableValue(value),
    reason: !available || !copyableValue(value) ? `${label} is unavailable for this row` : undefined,
    action: () => copyText(String(value), label),
  });
  const summary = [
    ["Process", row.process || row.processName || "—"],
    ["PID", row.pid ?? "—"],
    ["Protocol", row.proto || "—"],
    ["Local", endpoint(row.local || row.localAddress, row.lport)],
    ["Remote", endpoint(remote, row.rport)],
    ["Hostname", hasHostname ? hostname : "Not resolved"],
    ["Country", row.country || "—"],
    ["State", row.removed ? "Closed (retained history)" : row.state || "—"],
  ].map(([label, value]) => `${label}: ${value}`).join("\n");
  return openContextMenu([
    { label: "Connection details", action: () => onDetails(row) },
    ...(isListener ? [{ label: "Find inbound firewall rules for this listening port", disabled: !canInvestigateInbound,
      reason: !canInvestigateInbound ? "A live listener with a known local address, port, and protocol is required" : undefined,
      action: () => document.dispatchEvent(new CustomEvent("wintcp:firewall-investigate", {
        detail: { target: {
          direction: "Inbound",
          proto: row.proto,
          local: localAddress,
          lport: localPort,
          remote: null,
          rport: null,
          path: row.path || null,
          service: row.service || null,
        } },
      })) }] : []),
    { label: "Find related firewall rules", disabled: row.removed || !hasRemote,
      reason: row.removed ? "Retained history is not a live endpoint" : !hasRemote ? "A remote endpoint is unavailable" : undefined,
      action: () => document.dispatchEvent(new CustomEvent("wintcp:firewall-investigate", {
        detail: { target: {
          proto: row.proto || null,
          local: row.local || row.localAddress || null,
          lport: row.lport ?? null,
          remote,
          rport: row.rport ?? null,
          path: row.path || null,
          service: row.service || null,
        } },
      })) },
    { label: "Close this connection", destructive: true, disabled: !onClose || Boolean(closeReason),
      reason: closeReason,
      action: () => onClose?.(row) },
    { label: "Block this executable", destructive: true,
      disabled: !onBlockApplication || Boolean(applicationReason),
      reason: applicationReason || (!onBlockApplication ? "Application rules are unavailable in this view" : undefined),
      action: () => onBlockApplication?.(row) },
    { label: "Block this executable to this peer", destructive: true,
      disabled: !onBlockApplicationPeer || Boolean(applicationPeerReason),
      reason: applicationPeerReason || (!onBlockApplicationPeer ? "Application-peer rules are unavailable in this view" : undefined),
      action: () => onBlockApplicationPeer?.(row) },
    { label: "Block this service to this peer", destructive: true,
      disabled: !onBlockServicePeer || Boolean(servicePeerReason),
      reason: servicePeerReason || (!onBlockServicePeer ? "Service-scoped rules are unavailable in this view" : undefined),
      action: () => onBlockServicePeer?.(row) },
    { label: "Block remote peer", destructive: true, disabled: row.removed || !onBlock || Boolean(blockReason),
      reason: row.removed ? "Retained history is no longer live" : blockReason,
      action: () => onBlock?.(row) },
    { label: "Close and block this connection", destructive: true,
      disabled: !onCloseAndBlock || Boolean(blockReason) || Boolean(closeReason),
      reason: closeReason || blockReason,
      action: () => onCloseAndBlock?.(row) },
    { label: processScope?.field === "processInstanceId" ? "Show this process's connections" : "Filter by this PID",
      disabled: !processScope, reason: !processScope ? "A process identity is unavailable" : undefined,
      action: () => investigateConnections([processScope]) },
    { label: "Filter by remote IP", disabled: !hasRemote,
      action: () => investigateConnections([{ field: "remote", value: remote }]) },
    { label: "Filter by remote port", disabled: !hasRemote || !(row.rport > 0),
      action: () => investigateConnections([{ field: "rport", value: row.rport }]) },
    { label: "Exclude this remote IP", disabled: !hasRemote,
      action: () => investigateConnections([{ field: "remote", value: remote, exclude: true }], "add") },
    { label: "Clear connection filters", action: () => investigateConnections([], "replace") },
    { separator: true },
    copyItem("Remote IP", remoteIp, hasRemote),
    copyItem("Remote hostname", hostname, hasHostname),
    copyItem("Remote endpoint", remoteEndpoint, Boolean(remoteEndpoint)),
    copyItem("Remote port", row.rport, hasRemote && row.rport > 0),
    { separator: true },
    copyItem("Local endpoint", localEndpoint),
    copyItem("Local port", row.lport, localPort !== null),
    copyItem("PID", row.pid, positiveInteger(row.pid, 0xffffffff) !== null),
    copyItem("Executable path", row.path,
      copyableValue(row.path) && String(row.path).toLowerCase() !== "system"),
    { separator: true },
    { label: "Copy connection summary", action: () => copyText(summary, "Connection summary") },
    { label: "Copy row (visible columns, TSV)", action: () => copyText(
      serializeRow ? serializeRow(row) : connectionRowsTsv([row]), "connection row") },
  ], { event, anchor, label: `${row.process || "Connection"} actions` });
}
