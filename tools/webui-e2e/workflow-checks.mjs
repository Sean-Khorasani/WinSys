import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { dirname, extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "@playwright/test";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../wintcp/webui");
const connectionRows = [
  { id: 1, idExact: "1", pid: "20", process: "beta.exe", path: "C:\\Apps\\beta.exe", service: "Dnscache", processInstanceId: "20:1:2", proto: "TCPv4", local: "127.0.0.1", lport: "8000", remote: "203.0.113.1", rport: "443", state: "ESTABLISHED", hostname: "peer.example", country: "US" },
  { id: 2, idExact: "2", pid: "3", process: "alpha.exe", proto: "TCPv4", local: "0.0.0.0", lport: "80", remote: "0.0.0.0", rport: "0", state: "LISTENING" },
  { id: 3, idExact: "3", pid: "20", process: "beta.exe", processInstanceId: "20:1:2", proto: "UDPv6", local: "::1", lport: "53", remote: "2001:db8::53", rport: "53", state: "ESTABLISHED" },
  { id: 4, idExact: "4", pid: "20", process: "beta.exe", proto: "TCPv4", local: "127.0.0.1", lport: "8001", remote: "203.0.113.1", rport: "443", state: "ESTABLISHED", removed: true, country: "CA" },
];
const types = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".json": "application/json" };
let configuration = { version: 3, preferences: { theme: "light", units: "iec", futurePreference: "keep" }, bookmarks: [{ id: "keep" }], rules: [{ address: "198.51.100.99", proto: "udp", remotePorts: "53", label: "Automation only" }] };
let configRevision = 1;
const firewallActionRequests = [];
const firewallCreateRequests = [];
let failNextFirewallInventoryRead = false;
const blockActionRequests = [];
const closeActionRequests = [];
const server = createServer(async (request, response) => {
  const pathname = new URL(request.url, "http://localhost").pathname;
  if (pathname === "/test") {
    response.setHeader("Content-Type", "text/html");
    response.end('<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Workflow checks</title><link rel="stylesheet" href="/app.css"></head><body><main id="checks"></main></body></html>');
    return;
  }
  if (pathname === "/api/connections") {
    response.setHeader("Content-Type", "application/json");
    response.end(JSON.stringify({ connections: connectionRows }));
    return;
  }
  if (pathname === "/api/connections/action/preview" && request.method === "POST") {
    let body = "";
    for await (const chunk of request) body += chunk;
    const target = JSON.parse(body);
    closeActionRequests.push({ path: pathname, body: target });
    response.setHeader("Content-Type", "application/json");
    response.end(JSON.stringify({
      ok: true, requiresElevation: true,
      canExecute: closeActionRequests.length > 1,
      reason: closeActionRequests.length > 1 ? null : "Closing a TCP connection requires an elevated WinTCP process.",
      ...(closeActionRequests.length > 1 ? { nonce: "c".repeat(32), expiresInMs: 30000 } : {}),
      snapshotKnown: true, snapshotAgeMs: 2500, target,
    }));
    return;
  }
  if (pathname === "/api/connections/action/execute" && request.method === "POST") {
    let body = "";
    for await (const chunk of request) body += chunk;
    closeActionRequests.push({ path: pathname, body: JSON.parse(body) });
    response.setHeader("Content-Type", "application/json");
    response.end(JSON.stringify({ ok: true, connection: { status: "closed" } }));
    return;
  }
  if (pathname === "/api/block/preview" && request.method === "POST") {
    let body = "";
    for await (const chunk of request) body += chunk;
    blockActionRequests.push({ path: pathname, body: Object.fromEntries(new URLSearchParams(body)) });
    response.setHeader("Content-Type", "application/json");
    response.end(JSON.stringify({ ok: true, nonce: "b".repeat(32), ruleName: "WinTCP exact peer rule", plan: "outbound TCP block for exact peer" }));
    return;
  }
  if (pathname === "/api/block/commit" && request.method === "POST") {
    let body = "";
    for await (const chunk of request) body += chunk;
    blockActionRequests.push({ path: pathname, body: Object.fromEntries(new URLSearchParams(body)) });
    response.setHeader("Content-Type", "application/json");
    const priorCommits = blockActionRequests.filter((item) => item.path === pathname).length;
    const ok = priorCommits !== 2;
    const ruleStatus = !ok ? "failed" : priorCommits > 2 ? "already-present" : "created";
    response.end(JSON.stringify({ ok, auditRecorded: true, ruleName: "WinTCP exact peer rule", ruleStatus, message: !ok ? "Simulated firewall denial" : ruleStatus === "already-present" ? "Rule already existed" : "Rule created" }));
    return;
  }
  if (pathname === "/api/processes") {
    response.setHeader("Content-Type", "application/json");
    response.end(JSON.stringify({ known: true, total: 2, processes: [
      { pid: 3, instanceId: "3:1:2", name: "alpha.exe", cpuPct: 0, memWs: 1, connections: 1 },
      { pid: 20, instanceId: "20:1:2", name: "beta.exe", path: "C:\\Apps\\beta.exe", cpuPct: 0, memWs: 2, connections: 2 },
    ] }));
    return;
  }
  if (pathname === "/api/firewall") {
    response.setHeader("Content-Type", "application/json");
    if (failNextFirewallInventoryRead) {
      failNextFirewallInventoryRead = false;
      response.statusCode = 503;
      response.end(JSON.stringify({ error: "Temporary firewall read failure." }));
      return;
    }
    response.end(JSON.stringify({ available: true, reason: null, generatedAt: "2026-10-19T17:00:00.000Z", activeProfileKnown: true, activeProfileTypes: 2, activeProfileReason: null, scope: "fixture", warnings: [], rules: [
      { name: "WinTCP block: fixture", ownership: "wintcp", enabled: true, blocking: true, direction: 2, action: 0, protocol: 6, profiles: 7, localAddrs: "*", remoteAddrs: "203.0.113.7", localPorts: "*", remotePorts: "443", application: "*", service: "*" },
      { name: "WinTCP candidate fixture", ownership: "wintcp", enabled: true, blocking: true, direction: 2, action: 0, protocol: 6, profiles: 7, localAddrs: "*", remoteAddrs: "203.0.113.1", localPorts: "*", remotePorts: "443", application: "*", service: "*" },
      { name: "Windows wrong-profile fixture", ownership: "windows", enabled: true, blocking: true, direction: 2, action: 0, protocol: 6, profiles: 1, localAddrs: "*", remoteAddrs: "203.0.113.1", localPorts: "*", remotePorts: "443", application: "*", service: "*" },
      { name: "Windows managed allow fixture", ownership: "windows", enabled: false, blocking: false, direction: 2, action: 1, protocol: 6, profiles: 2, localAddrs: "*", remoteAddrs: "*", localPorts: "*", remotePorts: "*", application: "C:\\Apps\\beta.exe", service: "*" },
      { name: "Windows managed fixture", ownership: "windows", enabled: false, blocking: false, direction: 1, action: 1, protocol: 17, profiles: 2, localAddrs: "*", remoteAddrs: "*", localPorts: "53", remotePorts: "*", application: "*", service: "*" },
      { name: "Inbound listener fixture", ownership: "windows", enabled: true, blocking: true, direction: 1, action: 0, protocol: 6, profiles: 7, localAddrs: "*", remoteAddrs: "*", localPorts: "80", remotePorts: "*", application: "*", service: "*" },
    ] }));
    return;
  }
  if (pathname === "/test-firewall-read-failure" && request.method === "POST") {
    failNextFirewallInventoryRead = true;
    response.end("ok");
    return;
  }
  if (pathname === "/api/firewall/rule/preview" && request.method === "POST") {
    let body = "";
    for await (const chunk of request) body += chunk;
    firewallActionRequests.push({ path: pathname, body: JSON.parse(body) });
    response.setHeader("Content-Type", "application/json");
    response.end(JSON.stringify({ ok: true, canExecute: true, requiresElevation: false, reason: null, nonce: "a".repeat(32), expiresInMs: 30000, name: "WinTCP block: fixture", operation: "disable", enabled: true, ownership: "wintcp", direction: 1, action: 1, protocol: 17, profiles: 2, localAddresses: "192.0.2.9", remoteAddresses: "198.51.100.22", localPorts: "8080", remotePorts: "5353", application: "C:\\Verified\\service.exe", service: "Dnscache" }));
    return;
  }
  if (pathname === "/api/firewall/rule/create/preview" && request.method === "POST") {
    let body = "";
    for await (const chunk of request) body += chunk;
    const fields = Object.fromEntries(new URLSearchParams(body));
    firewallCreateRequests.push(fields);
    response.setHeader("Content-Type", "application/json");
    if (fields.label === "Invalid preview fixture") {
      response.statusCode = 400;
      response.end(JSON.stringify({ ok: false, field: "localAddress", message: "Use a valid local address." }));
      return;
    }
    response.end(JSON.stringify({ ok: true, canExecute: true, requiresElevation: true,
      reason: null, operation: "create", nonce: "d".repeat(32), name: "WinTCP custom rule fixture",
      plan: "rule WinTCP custom rule fixture\n  block  inbound from 192.0.2.1  proto=tcp\n" }));
    return;
  }
  if (pathname === "/api/firewall/rule/execute" && request.method === "POST") {
    let body = "";
    for await (const chunk of request) body += chunk;
    firewallActionRequests.push({ path: pathname, body: JSON.parse(body) });
    response.setHeader("Content-Type", "application/json");
    response.end(JSON.stringify(body.nonce === "d".repeat(32)
      ? { ok: true, status: "created", ruleStatus: "created", reason: null, ruleName: "WinTCP custom rule fixture" }
      : { ok: true, status: "verified", reason: null }));
    return;
  }
  if (pathname === "/test-state") {
    response.setHeader("Content-Type", "application/json");
    response.end(JSON.stringify({ firewallActionRequests, firewallCreateRequests, blockActionRequests, closeActionRequests }));
    return;
  }
  if (pathname === "/api/config") {
    if (request.method === "POST") {
      let body = "";
      for await (const chunk of request) body += chunk;
      if (request.headers["if-match"] && request.headers["if-match"] !== `"${configRevision}"`) {
        response.writeHead(412, { "Content-Type": "application/json" });
        response.end(JSON.stringify({ error: "Configuration changed" }));
        return;
      }
      configuration = JSON.parse(body);
      configRevision++;
    }
    response.setHeader("Content-Type", "application/json");
    response.setHeader("ETag", `"${configRevision}"`);
    response.end(JSON.stringify(configuration));
    return;
  }
  if (pathname === "/api/audit") {
    response.setHeader("Content-Type", "application/json");
    response.end("[]");
    return;
  }
  if (pathname === "/api/delayed") {
    await new Promise((done) => setTimeout(done, 200));
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end("{}");
    return;
  }
  const filename = resolve(root, `.${decodeURIComponent(pathname)}`);
  if (!filename.startsWith(root + sep)) { response.writeHead(404).end(); return; }
  try {
    const data = await readFile(filename);
    response.setHeader("Content-Type", types[extname(filename)] || "application/octet-stream");
    response.end(data);
  } catch {
    response.writeHead(404).end();
  }
});
await new Promise((ready) => server.listen(0, "127.0.0.1", ready));
const browser = await chromium.launch({ headless: true });
let checks = 0;
try {
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto(`http://127.0.0.1:${server.address().port}/test`);
  const results = await page.evaluate(async () => {
    const results = [];
    const check = (name, pass, detail = "") => results.push({ name, pass: Boolean(pass), detail });
    const { api } = await import("/js/api.js");
    const { matchesConnectionFilters, normalizeConnectionFilters, processConnectionFilter } = await import("/js/connectionfilters.js");
    const { matchesConnectionQuery, parseConnectionQuery } = await import("/js/filterquery.js");
    const { normalizeFirewallInventory, explainFirewallRuleMatch } = await import("/js/firewallinventory.js");
    const { renderTreemap } = await import("/js/charts/treemap.js");
    const { connectionPopup, mapData } = await import("/js/pages/map.js");
    const mapFixture = mapData({ features: [{
      id: "US", properties: { iso2: "US", name: "United States" },
      geometry: { type: "Polygon", coordinates: [[[-10, -10], [10, -10], [10, 10], [-10, 10], [-10, -10]]] },
    }] }, { geoSummary: { geoIpConfigured: true }, connections: [
      { id: "live-1", pid: 7, process: "client.exe", proto: "TCPv4", remote: "203.0.113.7", rport: 443, country: "US" },
      { id: "closed-1", pid: 8, process: "closed.exe", remote: "203.0.113.8", country: "US", removed: true },
      { id: "unknown-1", pid: 9, process: "unknown.exe", remote: "—", country: "US" },
    ] });
    check("Map colors only live GeoIP-matched countries and preserves exact connection identity",
      mapFixture.countries.features[0].properties.count === 1 &&
      mapFixture.connections.features.length === 1 &&
      mapFixture.connections.features[0].properties.connectionKey === "connection:connection:live-1" &&
      mapFixture.connections.features[0].properties.remote === "203.0.113.7" &&
      mapFixture.topCountries[0].count === 1);
    let inspectedMapConnection = "";
    const mapInspectListener = (event) => { inspectedMapConnection = event.detail?.key || ""; };
    document.addEventListener("wintcp:inspect-connection", mapInspectListener);
    connectionPopup(mapFixture.connections.features[0].properties)
      .querySelector(".map-inspect-action")?.click();
    document.removeEventListener("wintcp:inspect-connection", mapInspectListener);
    check("Map marker details action requests the exact connection inspector", inspectedMapConnection === "connection:connection:live-1");
    check("Process drilldowns prefer creation identity over a reused PID", matchesConnectionFilters({ pid: 20, processInstanceId: "20:1:2" }, [processConnectionFilter({ pid: 20, instanceId: "20:1:2" })]) && !matchesConnectionFilters({ pid: 20, processInstanceId: "20:9:9" }, [processConnectionFilter({ pid: 20, instanceId: "20:1:2" })]));
    check("Scoped port filters compare numeric values exactly", matchesConnectionFilters({ rport: 443 }, [{ field: "rport", value: 443 }]) && !matchesConnectionFilters({ rport: 1443 }, [{ field: "rport", value: 443 }]));
    let invalidFilterRefused = false;
    try { normalizeConnectionFilters([{ field: "rport", value: 65536 }]); } catch { invalidFilterRefused = true; }
    check("Invalid structured filters are refused", invalidFilterRefused);
    const queryFixture = { process: "client.exe", path: "C:\\Program Files\\client.exe",
      pid: 120, proto: "TCPv6", state: "TIME_WAIT", local: "fe80::2%7", lport: 51000,
      remote: "fe80::1%12", rport: 443, hostname: "peer.example" };
    const typedQuery = parseConnectionQuery('path:"Program Files" pid:100-200 proto:ipv6 remote:fe80::1%12 remote:port:443 exclude:listen');
    check("Typed filters support quoted paths, numeric ranges, scoped IPv6, directional ports and exclusions",
      !typedQuery.error && matchesConnectionQuery(queryFixture, typedQuery) &&
      !matchesConnectionQuery({ ...queryFixture, rport: 80 }, typedQuery));
    check("Bare Network terms search all supported visible text fields",
      matchesConnectionQuery({ ...queryFixture, service: "Dnscache" }, parseConnectionQuery("dnscache")) &&
      matchesConnectionQuery({ ...queryFixture, country: "DE" }, parseConnectionQuery("de")) &&
      matchesConnectionQuery(queryFixture, parseConnectionQuery("tcpv6")) &&
      matchesConnectionQuery(queryFixture, parseConnectionQuery("ipv6")));
    const invalidQuery = parseConnectionQuery("owner:client.exe");
    check("Unsupported browser filter clauses are explicitly rejected",
      Boolean(invalidQuery.error?.includes("Unsupported filter field")) &&
      !matchesConnectionQuery(queryFixture, invalidQuery));
    const malformedQuery = parseConnectionQuery('path:"Program Files');
    check("Unclosed quotes produce a visible query error instead of a silent no-match",
      Boolean(malformedQuery.error?.includes("Close the quoted filter value")));
    const unknownOwnerQuery = { pid: 0, proto: "", local: "—", lport: 0,
      remote: "", rport: 0 };
    check("Typed PID, port and family filters do not turn unknown sentinels into values",
      !matchesConnectionQuery(unknownOwnerQuery, parseConnectionQuery("pid:0")) &&
      !matchesConnectionQuery(unknownOwnerQuery, parseConnectionQuery("port:0")) &&
      !matchesConnectionQuery(unknownOwnerQuery, parseConnectionQuery("family:ipv4")));
    check("Typed filter comparisons preserve Unicode names",
      matchesConnectionQuery({ process: "Café.exe" },
        parseConnectionQuery("process:café")));
    const unknownFirewall = normalizeFirewallInventory({ available: true, activeProfileKnown: false, activeProfileTypes: null, warnings: [], rules: [
      { name: "rule", enabled: null, enabledReason: "unreadable", blocking: null, blockingReason: "unreadable", remoteAddrs: null },
    ] });
    check("Firewall inventory preserves unknown fields instead of treating them as disabled or any",
      unknownFirewall.available && unknownFirewall.rules[0].enabled === null &&
      unknownFirewall.rules[0].blocking === null && unknownFirewall.rules[0].remoteAddresses === null &&
      unknownFirewall.rules[0].direction === null && unknownFirewall.rules[0].application === null &&
      unknownFirewall.rules[0].ownership === "Unknown" && unknownFirewall.activeProfileTypes === null &&
      Boolean(unknownFirewall.activeProfileReason));
    const candidateRule = { direction: "Outbound", protocol: "TCP", remoteAddresses: "203.0.113.7", remotePorts: "443", localAddresses: "*", localPorts: "*", application: "*", service: "*" };
    const candidateTarget = { proto: "TCPv4", local: "127.0.0.1", lport: 8000, remote: "203.0.113.7", rport: 443 };
    const exactCandidate = explainFirewallRuleMatch(candidateRule, candidateTarget);
    const mismatch = explainFirewallRuleMatch({ ...candidateRule, remotePorts: "80" }, candidateTarget);
    check("Related-rule explanations distinguish candidate scope from definite mismatch",
      exactCandidate.candidate && exactCandidate.kind === "Partial / unknown" && exactCandidate.explanation.includes("Active profile: unknown") && !mismatch.candidate && mismatch.explanation.includes("Remote port: no"));
    const privateProfileRule = { ...candidateRule, profileTypes: 2 };
    const wrongProfileRule = { ...candidateRule, profileTypes: 1 };
    const partialProfileRule = { ...candidateRule, profileTypes: 3 };
    const privateProfileMatch = explainFirewallRuleMatch(privateProfileRule, candidateTarget, 2);
    const wrongProfileMatch = explainFirewallRuleMatch(wrongProfileRule, candidateTarget, 2);
    const partialProfileMatch = explainFirewallRuleMatch(partialProfileRule, candidateTarget, 6);
    check("Firewall candidates honor current profile mismatch and disclose partial coverage",
      privateProfileMatch.candidate && privateProfileMatch.explanation.includes("Active profile: exact") &&
      !wrongProfileMatch.candidate && wrongProfileMatch.explanation.includes("Active profile: no") &&
      partialProfileMatch.candidate && partialProfileMatch.explanation.includes("Active profile: partial") &&
      partialProfileMatch.kind === "Partial / unknown");
    const inboundTarget = { direction: "Inbound", proto: "TCPv4", local: "0.0.0.0", lport: 8080, path: "C:\\Apps\\listener.exe" };
    const inboundCandidate = explainFirewallRuleMatch({ direction: "Inbound", protocol: "TCP", localAddresses: "*", localPorts: "8080", remoteAddresses: "*", remotePorts: "*", application: "C:\\Apps\\listener.exe", service: "*" }, inboundTarget);
    const inboundPeerScoped = explainFirewallRuleMatch({ direction: "Inbound", protocol: "TCP", localAddresses: "*", localPorts: "8080", remoteAddresses: "203.0.113.5", remotePorts: "443", application: "C:\\Apps\\listener.exe", service: "*" }, inboundTarget);
    const inboundMismatch = explainFirewallRuleMatch({ direction: "Outbound", protocol: "TCP", localPorts: "8080", localAddresses: "*" }, inboundTarget);
    const inboundPortMismatch = explainFirewallRuleMatch({ direction: "Inbound", protocol: "TCP", localPorts: "443", localAddresses: "*" }, inboundTarget);
    check("Inbound firewall candidates use listener local port and reject direction or port mismatches",
      inboundCandidate.candidate && inboundCandidate.explanation.includes("Direction: exact") && inboundCandidate.explanation.includes("Local port: exact") && inboundCandidate.explanation.includes("Remote address: broad") && !inboundMismatch.candidate && !inboundPortMismatch.candidate);
    check("Inbound peer-restricted rules stay candidates with explicit unknown peer scope",
      inboundPeerScoped.candidate && inboundPeerScoped.explanation.includes("Remote address: unknown") && inboundPeerScoped.explanation.includes("Remote port: unknown"));
    const { connectionRowsTsv, endpoint, liveConnectionSummary, remoteEndpointValue, remoteHostnameValue, remoteIpValue } = await import("/js/connections.js");
    const escapedTsv = connectionRowsTsv([{ process: 'client\t"one"\nnext', pid: 7, remote: "fe80::1%12", rport: 443, hostname: "...pending..." }]);
    check("Full-row TSV escapes delimiters and omits unresolved hostnames",
      escapedTsv.includes('"client\t""one""\nnext"') && escapedTsv.includes("fe80::1%12\t443\t\t") && !escapedTsv.includes("pending"));
    const visibleTsv = connectionRowsTsv([{ pid: 7, remote: "203.0.113.7" }], [
      { key: "remote", label: "Peer" },
      { key: "pid", label: "PID" },
      { key: "actions", label: "Actions" },
    ]);
    check("TSV copy follows visible column order and omits action controls",
      visibleTsv === "Peer\tPID\r\n203.0.113.7\t7\r\n");
    const historyUdpTsv = connectionRowsTsv([{
      proto: "UDPv6", local: "::1", rport: 0, state: "—", removed: true,
    }], [
      { key: "local", label: "Local address" },
      { key: "rport", label: "Remote port" },
      { key: "state", label: "State" },
    ]);
    check("Web TSV matches native labels and formatting for UDP history rows",
      historyUdpTsv === "Local address\tRemote port\tState\r\n::1\t*\tClosed (retained history)\r\n",
      JSON.stringify(historyUdpTsv));
    const unknownValueTsv = connectionRowsTsv([
      { pid: 0, path: "System", hostname: "...pending...", remote: "203.0.113.8", rport: 443 },
      { pid: 42, path: "C:\\Apps\\client.exe", hostname: "peer.example", remote: "203.0.113.9", rport: 443, state: "ESTABLISHED" },
      { pid: 43, path: "C:\\Apps\\listener.exe", hostname: "not-a-peer.example", remote: "0.0.0.0", rport: 0, state: "LISTENING" },
    ], [
      { key: "pid", label: "PID" },
      { key: "path", label: "Path" },
      { key: "hostname", label: "Hostname" },
    ]);
    check("TSV omits unknown owners, system paths, pending and listener hostnames",
      unknownValueTsv === "PID\tPath\tHostname\r\n\t\t\r\n42\tC:\\Apps\\client.exe\tpeer.example\r\n43\tC:\\Apps\\listener.exe\t\r\n",
      JSON.stringify(unknownValueTsv));
    const placeholderTsv = connectionRowsTsv([{
      process: "—", pid: 7, proto: "…", local: "—", lport: 0,
      remote: "-", rport: 443, hostname: "(resolving...)", country: "pending",
      state: "—", path: "—",
    }]);
    check("TSV leaves unavailable placeholder fields empty instead of copying markers",
      placeholderTsv === "Process\tPID\tProto\tLocal address\tLocal port\tRemote address\tRemote port\tHostname\tCountry\tPath\tState\r\n\t7\t\t\t0\t\t443\t\t\t\t\r\n",
      JSON.stringify(placeholderTsv));
    check("Local endpoint formatting matches native IPv4 and scoped IPv6 copy",
      endpoint("192.0.2.10", 51000) === "192.0.2.10:51000" &&
      endpoint("fe80::2%7", 55000) === "[fe80::2%7]:55000");
    const listeningEndpoint = { remote: "0.0.0.0", rport: "0", state: "LISTENING" };
    const retainedEndpoint = { remote: "203.0.113.1", rport: "443", state: "ESTABLISHED", removed: true };
    const unknownPortEndpoint = { remote: "203.0.113.1", rport: "0", state: "ESTABLISHED" };
    const liveEndpoint = { remote: "fe80::1%12", rport: "443", state: "ESTABLISHED" };
    const scopedUnspecifiedEndpoint = { remote: "0:0::%12", rport: "443", state: "ESTABLISHED" };
    check("Peer copy omits listeners and retained history but preserves scoped IPv6",
      remoteIpValue(listeningEndpoint) === null && remoteEndpointValue(listeningEndpoint) === null &&
      remoteIpValue(retainedEndpoint) === null && remoteEndpointValue(retainedEndpoint) === null &&
      remoteIpValue(unknownPortEndpoint) === null && remoteEndpointValue(unknownPortEndpoint) === null &&
      remoteIpValue(scopedUnspecifiedEndpoint) === null && remoteEndpointValue(scopedUnspecifiedEndpoint) === null &&
      remoteHostnameValue({ ...listeningEndpoint, hostname: "bogus.example" }) === null &&
      remoteIpValue(liveEndpoint) === "fe80::1%12" && remoteEndpointValue(liveEndpoint) === "[fe80::1%12]:443");
    const mapCountry = { type: "Feature", id: "US", properties: { name: "United States of America" }, geometry: { type: "Polygon", coordinates: [[[-130, 20], [-60, 20], [-60, 55], [-130, 55], [-130, 20]]] } };
    const mapSnapshot = mapData({ type: "FeatureCollection", features: [mapCountry] }, {
      geoSummary: { geoIpConfigured: true },
      connections: [
        { id: 1, pid: 2, process: "live.exe", remote: "203.0.113.7", rport: 443, country: "US" },
        { id: 2, pid: 3, process: "closed.exe", remote: "203.0.113.8", rport: 443, country: "US", removed: true },
      ],
    });
    const mixedConnectionSummary = liveConnectionSummary([
      { state: "ESTABLISHED" },
      { state: "LISTENING" },
      { state: "ESTABLISHED", removed: true },
    ]);
    const historyOnlySummary = liveConnectionSummary([
      { state: "ESTABLISHED", removed: true },
    ]);
    check("Connection totals and state breakdowns use only live rows",
      mixedConnectionSummary.total === 2 && mixedConnectionSummary.byState.ESTABLISHED === 1 &&
      mixedConnectionSummary.byState.LISTENING === 1 && historyOnlySummary.total === 0 &&
      Object.keys(historyOnlySummary.byState).length === 0);
    check("Map country shading and markers exclude retained history",
      mapSnapshot.countries.features[0].properties.count === 1 &&
      mapSnapshot.connections.features.length === 1 && mapSnapshot.connections.features[0].id === "1");
    const tinyTreemapHost = document.createElement("div");
    tinyTreemapHost.style.width = "320px";
    document.body.append(tinyTreemapHost);
    let omittedTreemapTiles = 0;
    const tinyTreemapRows = [{ label: "largest.exe", value: 100000 },
      ...Array.from({ length: 49 }, (_, index) => ({ label: `small-${index}.exe`, value: 1 }))];
    const tinyTreemap = renderTreemap(tinyTreemapHost, tinyTreemapRows, {
      height: 180, onOmittedTiles: (count) => { omittedTreemapTiles = count; },
    });
    check("Treemap reports tiny tiles that need the Tree or Table alternative",
      Boolean(tinyTreemap) && omittedTreemapTiles > 0 && tinyTreemap.querySelectorAll("button").length > 0);
    tinyTreemapHost.remove();
    const duplicateTileHost = document.createElement("div");
    duplicateTileHost.style.width = "320px";
    document.body.append(duplicateTileHost);
    const duplicateTiles = renderTreemap(duplicateTileHost, [
      { label: "same.exe", accessibleLabel: "same.exe (PID 7)", value: 9 },
      { label: "same.exe", accessibleLabel: "same.exe (PID 8)", value: 8 },
    ], { height: 180 });
    check("Treemap exposes PID to distinguish repeated process names",
      duplicateTiles.querySelector('[aria-label^="same.exe (PID 7):"]') &&
      duplicateTiles.querySelector('[aria-label^="same.exe (PID 8):"]'));
    duplicateTileHost.remove();
    const { normalizeConnection, connectionKey, exposureOf, resolvedHostname, hostnameLabel } = await import("/js/connections.js");
    const { createStore } = await import("/js/store.js");
    const { renderOverview, updateOverview } = await import("/js/pages/overview.js");
    const { createVirtualTable } = await import("/js/ui/virtualtable.js");
    const { createSnapshotRefresh } = await import("/js/refresh.js");
    const { createPoller } = await import("/js/poller.js");
    const { addressComparator, numberComparator, stateComparator, textComparator } = await import("/js/sort.js");
    const { dialog, openDialog, closeDialog } = await import("/js/ui/dialog.js");
    const { renderNetwork } = await import("/js/pages/network.js");
    const { renderProcesses, updateProcesses } = await import("/js/pages/processes.js");
    const { renderSettings } = await import("/js/pages/settings.js");
    const { fmtBytes, setFormatUnits } = await import("/js/format.js");
    const overviewHost = document.createElement("main");
    document.body.append(overviewHost);
    const overviewStore = createStore({
      connections: [
        { id: 1, state: "ESTABLISHED" },
        { id: 2, state: "LISTENING" },
        { id: 3, state: "ESTABLISHED", removed: true },
      ],
      networkSummary: { total: 99, byState: { ESTABLISHED: 98, LISTENING: 1 } },
      metrics: {},
      lastUpdate: new Date(),
    });
    await renderOverview(overviewHost, overviewStore);
    const overviewConnectionCard = overviewHost.querySelector('[data-kpi="connections"]');
    check("Overview renders totals and state counts from its live snapshot",
      overviewConnectionCard?.querySelector(".kpi-value")?.textContent === "2" &&
      overviewConnectionCard?.querySelector(".kpi-foot")?.textContent.includes("1 established") &&
      overviewConnectionCard?.querySelector(".kpi-foot")?.textContent.includes("1 listening") &&
      [...overviewHost.querySelectorAll("#overview-states [data-state]")].some((cell) =>
        cell.dataset.state === "ESTABLISHED" && cell.querySelector(".state-value")?.textContent === "1"));
    overviewStore.set({
      connections: [{ id: 4, state: "ESTABLISHED", removed: true }],
      lastUpdate: new Date(),
      metrics: { _timestamp: 1 },
    });
    await updateOverview(overviewHost, overviewStore);
    check("Overview reports zero live endpoints when the snapshot contains only history",
      overviewHost.querySelector('[data-kpi="connections"] .kpi-value')?.textContent === "0" &&
      overviewHost.querySelectorAll("#overview-states [data-state]").length === 0);
    overviewStore.set({
      connections: [{ id: 5, state: "ESTABLISHED" }, { id: 6, state: "LISTENING" }],
      lastUpdate: new Date(Date.now() + 5000),
      metrics: { _timestamp: 1 },
    });
    await updateOverview(overviewHost, overviewStore);
    check("Overview updates connection counts when metrics are unchanged",
      overviewHost.querySelector('[data-kpi="connections"] .kpi-value')?.textContent === "2" &&
      overviewHost.querySelector('[data-kpi="connections"] .kpi-foot')?.textContent.includes("1 established"));
    overviewStore.set({ connections: [], lastUpdate: null, metrics: { _timestamp: 2 } });
    await updateOverview(overviewHost, overviewStore);
    check("Overview keeps an unsampled connection count unavailable instead of zero",
      overviewHost.querySelector('[data-kpi="connections"]')?.classList.contains("kpi-card-unknown") &&
      overviewHost.querySelector('[data-kpi="connections"] .kpi-value')?.textContent.trim() === "—");
    overviewHost._chartDestroy?.();
    overviewHost.remove();
    const sample = await api.get("/api/connections");
    sample.connections[0].local = "fe80::1%12";
    sample.connections[0].hostname = "Remote.EXAMPLE";
    sample.connections[0].path = "C:\\Apps\\client.exe";
    sample.connections[1].remote = sample.connections[0].remote;
    check("API decodes PID and port strings", sample.connections[0].pid === 20 && sample.connections[0].rport === 443);
    check("Unknown numeric fields stay unknown", normalizeConnection({ pid: "—", lport: "", rport: "65536" }).pid === null && normalizeConnection({ rport: "65536" }).rport === null);
    check("Malformed numeric input is rejected", normalizeConnection({ pid: "1e3", lport: "8.5" }).pid === null && normalizeConnection({ pid: "4294967296" }).pid === null);
    const numericRows = [{ id: "pid-10", pid: 10 }, { id: "pid-2", pid: 2 }, { id: "pid-unknown", pid: null }];
    const byNumericPid = numberComparator((row) => row.pid, (row) => row.id);
    check("Typed numeric sorts keep unknown values last in both directions",
      numericRows.slice().sort((a, b) => byNumericPid(a, b, "asc")).map((row) => row.id).join(",") === "pid-2,pid-10,pid-unknown" &&
      numericRows.slice().sort((a, b) => byNumericPid(a, b, "desc")).map((row) => row.id).join(",") === "pid-10,pid-2,pid-unknown");
    const addressRows = [
      { id: "v6", address: "2001:db8::1" }, { id: "v4-ten", address: "192.0.2.10" },
      { id: "v4-two", address: "192.0.2.2" }, { id: "scope-ten", address: "fe80::1%10" },
      { id: "scope-two", address: "fe80::1%2" }, { id: "unknown", address: "—" },
    ];
    const byAddress = addressComparator((row) => row.address, (row) => row.id);
    check("IP sorting compares address bytes, family, and numeric scope IDs",
      addressRows.slice().sort((a, b) => byAddress(a, b, "asc")).map((row) => row.id).join(",") ===
      "v4-two,v4-ten,v6,scope-two,scope-ten,unknown");
    const stateRows = [{ id: "wait", state: "TIME_WAIT" }, { id: "established", state: "ESTABLISHED" },
      { id: "listen", state: "LISTENING" }, { id: "unknown", state: "—" }];
    const byState = stateComparator((row) => row.state, (row) => row.id);
    check("TCP states follow the documented order and unknown states remain last",
      stateRows.slice().sort((a, b) => byState(a, b, "asc")).map((row) => row.id).join(",") ===
      "listen,established,wait,unknown" &&
      stateRows.slice().sort((a, b) => byState(a, b, "desc")).at(-1).id === "unknown");
    const namedRows = [{ id: "svchost-10", name: "svchost10.exe" }, { id: "chrome", name: "Chrome.exe" },
      { id: "svchost-2", name: "svchost2.exe" }, { id: "unknown", name: "—" }];
    const byName = textComparator((row) => row.name, (row) => row.id);
    check("Case-insensitive natural name sorting is deterministic with unknowns last",
      namedRows.slice().sort((a, b) => byName(a, b, "asc")).map((row) => row.id).join(",") ===
      "chrome,svchost-2,svchost-10,unknown" &&
      namedRows.slice().sort((a, b) => byName(a, b, "desc")).at(-1).id === "unknown");
    check("Identity survives a TCP state change", connectionKey(sample.connections[0]) === connectionKey({ ...sample.connections[0], state: "CLOSE_WAIT" }));
    check("Separate ports retain distinct identities", connectionKey(sample.connections[0]) !== connectionKey(sample.connections[3]));
    check("IPv6 loopback is classified", exposureOf({ local: "::1" }).key === "loopback");
    check("Link-local scope is classified", exposureOf({ local: "fe80::1%12" }).key === "private");
    const exposureCases = [
      ["0.0.0.0", "wildcard"], ["::", "wildcard"], ["*", "wildcard"],
      ["127.42.0.1", "loopback"], ["::1", "loopback"],
      ["10.10.0.1", "private"], ["172.31.0.1", "private"],
      ["192.168.1.2", "private"], ["169.254.7.8", "private"],
      ["172.32.0.1", "specific"], ["8.8.8.8", "specific"],
      ["fc00::1", "private"], ["fdff::1", "private"],
      ["fe80::1%12", "private"], ["febf::1", "private"],
      ["2001:4860:4860::8888", "specific"],
      ["::ffff:192.168.1.1", "private"], ["::ffff:c0a8:0101", "private"],
      ["10.bad.1.1", "specific"],
    ];
    check("Listening exposure classifies IPv4, IPv6, mapped, scoped and invalid addresses conservatively",
      exposureCases.every(([local, expected]) => exposureOf({ local }).key === expected),
      exposureCases.map(([local, expected]) => `${local}:${exposureOf({ local }).key}/${expected}`).join(", "));
    check("Pending DNS markers are not copyable hostnames", resolvedHostname("...pending...") === null && hostnameLabel("...pending...") === "Resolving…");

    const host = document.getElementById("checks");
    const settle = () => new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(done)));
    let customCells = 0;
    let clickedRows = 0;
    let clickedActions = 0;
    const sorts = [];
    let valueFormatterCalls = 0;
    let selectionState = { rows: [], selectedCount: 0, visibleCount: 0, hiddenCount: 0 };
    const table = createVirtualTable(host, {
      columns: [
        { key: "value", label: "Value", align: "right", sortable: true },
        { key: "action", label: "Action", renderCell: () => {
          customCells++;
          const button = document.createElement("button");
          button.textContent = "Run";
          button.onclick = () => { clickedActions++; };
          return button;
        } },
      ],
      rowHeight: 34,
      rowKey: (row) => row.id,
      multiSelect: true,
      onSelectionChange: (selection) => { selectionState = selection; },
      sortKey: "action",
      sortDir: "asc",
      onSort: (key, direction) => sorts.push([key, direction]),
      onRowClick: () => { clickedRows++; },
      onRowContextMenu: () => {},
      format: { value: (row) => { valueFormatterCalls++; return `${row.value} KiB`; } },
    });
    const rows = Array.from({ length: 200 }, (_, index) => ({ id: index, value: index }));
    table.updateRows(rows);
    await settle();
    check("Virtual-table formatters run once for each newly rendered cell",
      valueFormatterCalls === host.querySelectorAll('.virtual-table-row [data-column-key="value"]').length,
      JSON.stringify({ formatterCalls: valueFormatterCalls,
        renderedCells: host.querySelectorAll('.virtual-table-row [data-column-key="value"]').length }));
    const defaultTableLayout = table.getLayout();
    table.setLayout({ version: 1, order: ["action", "value", "retired"], hidden: ["action"], widths: { value: 2 } });
    await settle();
    check("Virtual tables apply saved visibility, ordering, and width by column key",
      [...host.querySelectorAll('[role="columnheader"]')].map((header) => header.dataset.columnKey).join(",") === "value" &&
      host.querySelector('[role="columnheader"][data-column-key="value"]').style.flexGrow === "2" &&
      host.querySelector(".virtual-table-row [role=gridcell]").dataset.columnKey === "value" &&
      table.getVisibleColumns().map((column) => column.key).join(",") === "value");
    table.setLayout({ version: 1, order: ["action", "value"], hidden: ["action", "value"] });
    check("Corrupt layouts cannot leave a virtual table without a visible column",
      host.querySelectorAll('[role="columnheader"]').length === 1 && table.getLayout().hidden.length === 1);
    table.setLayout(defaultTableLayout);
    await settle();
    host.querySelector('[data-row-key="0"]').dispatchEvent(new MouseEvent("click", {
      bubbles: true, ctrlKey: true,
    }));
    host.querySelector('[data-row-key="2"]').dispatchEvent(new MouseEvent("click", {
      bubbles: true, ctrlKey: true,
    }));
    host.querySelector('[data-row-key="5"]').dispatchEvent(new MouseEvent("click", {
      bubbles: true, shiftKey: true,
    }));
    check("Ctrl-click toggles stable rows and Shift-click selects the sorted range",
      table.getSelectedRows().map((row) => row.id).join(",") === "2,3,4,5" && clickedRows === 0);
    host.querySelector('[data-row-key="3"]').dispatchEvent(new MouseEvent("contextmenu", {
      bubbles: true, cancelable: true,
    }));
    check("Right-click within a multi-selection preserves all selected keys",
      table.getSelectedRows().map((row) => row.id).join(",") === "2,3,4,5");
    host.querySelector('[data-row-key="9"]').dispatchEvent(new MouseEvent("contextmenu", {
      bubbles: true, cancelable: true,
    }));
    check("Right-click outside a selection replaces it with the clicked row",
      table.getSelectedRows().length === 1 && table.getSelectedRows()[0].id === 9);
    table.wrapper.dispatchEvent(new KeyboardEvent("keydown", {
      key: "a", ctrlKey: true, bubbles: true, cancelable: true,
    }));
    check("Ctrl+A selects every filtered row, including offscreen rows",
      table.getSelectedRows().length === rows.length && selectionState.visibleCount === rows.length);
    const rendered = host.querySelectorAll(".virtual-table-row").length;
    check("Custom cells render once per row", host.querySelectorAll(".virtual-table-row [data-column-key=action]").length === rendered && customCells >= rendered, `${customCells}/${rendered}`);
    const cell = host.querySelector('[role="gridcell"]');
    check("Formatters are applied", cell.textContent === "0 KiB", cell.textContent);
    check("Numeric cells align right", getComputedStyle(cell).textAlign === "right");
    check("Exact numeric values remain available", cell.title === "0");
    host.querySelector('[role="columnheader"]').click();
    check("A new sort column starts ascending", sorts[0][1] === "asc");
    table.wrapper.scrollTop = 700;
    await settle();
    table.wrapper.scrollTop = 250;
    await settle();
    const indexes = [...host.querySelectorAll(".virtual-table-row")].map((row) => Number(row.dataset.index));
    check("Upward scrolling preserves visible DOM order", indexes.every((value, index) => index === 0 || indexes[index - 1] < value), indexes.join(","));
    table.wrapper.scrollTop = 0;
    await settle();
    const topRows = [...host.querySelectorAll(".virtual-table-row")];
    check("Returning to the top renders row zero first with its matching cell value",
      Number(topRows[0]?.dataset.index) === 0 &&
      topRows[0]?.querySelector('[data-column-key="value"]')?.textContent === "0 KiB");
    table.setActive(9);
    table.updateRows(rows.slice().reverse());
    await settle();
    const reversedKeys = [...host.querySelectorAll(".virtual-table-row")].map((row) => Number(row.dataset.rowKey));
    check("Reversed input order remains reversed in rendered DOM after a data replacement",
      reversedKeys.length > 0 && reversedKeys.every((value, index) => index === 0 || reversedKeys[index - 1] > value),
      reversedKeys.join(","));
    check("Row focus follows stable identity after reorder", document.activeElement.dataset.rowKey === "9");
    const refreshedRows = rows.map((row) => ({ ...row, value: row.value + 1000 }));
    table.updateRows(refreshedRows.filter((row) => row.id % 3 === 0), undefined,
      { allRows: refreshedRows });
    table.wrapper.style.height = "200px";
    window.dispatchEvent(new Event("resize"));
    await settle();
    const filteredIds = [...host.querySelectorAll(".virtual-table-row")].map((row) => Number(row.dataset.rowKey));
    check("Filtered rows stay ordered after the viewport is resized", table.wrapper.clientHeight === 200 && filteredIds.length > 0 && filteredIds.every((value, index) => value % 3 === 0 && (index === 0 || filteredIds[index - 1] < value)));
    const filteredCount = rows.filter((row) => row.id % 3 === 0).length;
    check("Refresh and filtering retain selected keys and disclose hidden counts",
      selectionState.selectedCount === rows.length && selectionState.visibleCount === filteredCount &&
      selectionState.hiddenCount === rows.length - filteredCount && selectionState.staleCount === 0 &&
      table.getSelectedRows().find((row) => row.id === 1)?.value === 1001,
      JSON.stringify({ selected: selectionState.selectedCount, visible: selectionState.visibleCount, hidden: selectionState.hiddenCount }));
    const withoutSelectedRow = refreshedRows.filter((row) => row.id !== 1);
    table.updateRows(withoutSelectedRow.filter((row) => row.id % 3 === 0), undefined,
      { allRows: withoutSelectedRow });
    check("Removed selections are identified and excluded from current action targets",
      selectionState.staleCount === 1 && selectionState.currentCount === rows.length - 1 &&
      table.getSelectedRows().length === rows.length && table.getCurrentSelectedRows().length === rows.length - 1,
      JSON.stringify({ stale: selectionState.staleCount, current: selectionState.currentCount,
        selected: table.getSelectedRows().length, actionable: table.getCurrentSelectedRows().length }));
    table.selectAll();
    check("Select all shown targets the complete filtered dataset",
      table.getSelectedRows().length === filteredCount &&
      selectionState.visibleCount === filteredCount && selectionState.hiddenCount === 0,
      JSON.stringify({ selected: selectionState.selectedCount, visible: selectionState.visibleCount, hidden: selectionState.hiddenCount }));
    document.body.classList.add("density-compact");
    await settle();
    check("Density changes actual virtual row height", host.querySelector(".virtual-table-row").getBoundingClientRect().height === 28);
    document.body.classList.remove("density-compact");
    await settle();
    table.destroy();
    host.replaceChildren();

    const opener = document.createElement("button");
    opener.textContent = "Inspect";
    host.append(opener);
    opener.focus();
    const detail = dialog({}, "Details");
    document.body.append(detail);
    openDialog(detail);
    closeDialog(detail);
    await new Promise((done) => setTimeout(done, 0));
    check("Closing a dialog removes its node", !detail.isConnected);
    check("Closing a dialog restores its opener", document.activeElement === opener);
    let repeatedDialogsClean = true;
    for (let attempt = 0; attempt < 5; attempt++) {
      const repeated = dialog({}, `Details ${attempt + 1}`);
      document.body.append(repeated);
      openDialog(repeated);
      closeDialog(repeated);
      await new Promise((done) => setTimeout(done, 0));
      repeatedDialogsClean &&= !repeated.isConnected && document.activeElement === opener;
    }
    check("Repeated dialog open/close removes every node and restores focus", repeatedDialogsClean && document.querySelectorAll("dialog.dialog").length === 0);
    host.replaceChildren();

    const netStore = createStore({ connections: sample.connections, geoSummary: { geoIpConfigured: true, countries: { US: 100, CA: 20 }, local: 0, unknown: 2 }, lastUpdate: new Date(), networkView: "connections" });
    await renderNetwork(host, netStore);
    check("Network defaults to live rows", host.querySelector('#panel-connections [role="grid"]').getAttribute("aria-rowcount") === "4");
    const networkQuery = host.querySelector("#net-filter");
    networkQuery.value = 'process:"beta.exe" pid:20 port:443';
    networkQuery.dispatchEvent(new Event("input", { bubbles: true }));
    await new Promise((done) => setTimeout(done, 150));
    await settle();
    check("Network applies documented typed terms together to the rendered rows",
      host.querySelector('#panel-connections [role="grid"]').getAttribute("aria-rowcount") === "2" &&
      Boolean(host.querySelector('#panel-connections [data-row-key="connection:1"]')),
      `${host.querySelector('#panel-connections [role="grid"]')?.getAttribute("aria-rowcount")} rows; ${[...host.querySelectorAll('#panel-connections [data-row-key]')].map((row) => row.dataset.rowKey).join(",")}`);
    networkQuery.value = "owner:beta.exe";
    networkQuery.dispatchEvent(new Event("input", { bubbles: true }));
    await new Promise((done) => setTimeout(done, 150));
    await settle();
    check("Network shows invalid filter syntax and marks the query field",
      networkQuery.getAttribute("aria-invalid") === "true" &&
      host.querySelector(".filter-query-status")?.textContent.includes("Unsupported filter field") &&
      host.querySelector('#panel-connections [role="grid"]').getAttribute("aria-rowcount") === "1",
      `invalid=${networkQuery.getAttribute("aria-invalid")}; status=${host.querySelector(".filter-query-status")?.textContent}; rows=${host.querySelector('#panel-connections [role="grid"]')?.getAttribute("aria-rowcount")}`);
    networkQuery.value = "process:no-such-process";
    networkQuery.dispatchEvent(new Event("input", { bubbles: true }));
    await new Promise((done) => setTimeout(done, 150));
    await settle();
    check("A valid zero-match query stays distinct from invalid syntax",
      !networkQuery.hasAttribute("aria-invalid") &&
      host.querySelector('#panel-connections [role="grid"]').getAttribute("aria-rowcount") === "1" &&
      host.querySelector('#panel-connections .virtual-table-empty')?.textContent.includes("No endpoints matched"));
    networkQuery.value = "";
    networkQuery.dispatchEvent(new Event("input", { bubbles: true }));
    await new Promise((done) => setTimeout(done, 150));
    await settle();
    check("Clearing an invalid query restores the full live row set",
      !networkQuery.hasAttribute("aria-invalid") &&
      host.querySelector('#panel-connections [role="grid"]').getAttribute("aria-rowcount") === "4");
    check("Network process identity and row actions stay sticky while the table scrolls horizontally",
      getComputedStyle(host.querySelector('#panel-connections .virtual-table-row [data-column-key="process"]')).position === "sticky" &&
      getComputedStyle(host.querySelector('#panel-connections .virtual-table-row [data-column-key="actions"]')).position === "sticky");
    const pidHeader = [...host.querySelectorAll('#panel-connections [role="columnheader"]')].find((cell) => cell.textContent === "PID");
    pidHeader.click();
    check("PID sorting compares numbers", host.querySelector('#panel-connections .virtual-table-row [role="gridcell"]').textContent === "alpha.exe");
    const connectionTable = host.querySelector("#panel-connections .tab-panel-body")?._virtualTable;
    const defaultConnectionLayout = connectionTable?.getLayout();
    connectionTable?.setLayout({
      ...defaultConnectionLayout,
      order: ["pid", "process", "proto", "local", "lport", "remote", "rport", "hostname", "state", "country", "actions"],
    });
    await settle();
    check("Network copy tracks the actual reordered table layout",
      connectionTable?.getVisibleColumns().map((column) => column.key).join(",") ===
        "pid,process,proto,local,lport,remote,rport,hostname,state,country,actions");
    let remoteRow = host.querySelector('#panel-connections [data-row-key="connection:1"]');
    remoteRow.dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, cancelable: true, clientX: innerWidth - 1, clientY: innerHeight - 1 }));
    let menu = document.querySelector('[role="menu"]');
    check("Connection right-click opens an action menu", Boolean(menu));
    const menuBounds = menu.getBoundingClientRect();
    check("Context menus stay inside the viewport", menuBounds.right <= innerWidth && menuBounds.bottom <= innerHeight && menuBounds.left >= 0 && menuBounds.top >= 0);
    check("Context menu receives keyboard focus", menu.contains(document.activeElement));
    const originalClipboard = Object.getOwnPropertyDescriptor(navigator, "clipboard");
    let copiedText = "";
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: async (text) => { copiedText = text; } } });
    const copyRemote = [...menu.querySelectorAll('[role="menuitem"]')].find((item) => item.textContent === "Copy remote IP");
    copyRemote.click();
    await settle();
    check("Remote IP copying excludes the port", copiedText === "203.0.113.1", copiedText);
    check("Copying dismisses the menu and restores its row", !document.querySelector('[role="menu"]') && document.activeElement.dataset.rowKey === "connection:1");
    remoteRow.dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, cancelable: true, clientX: 20, clientY: 20 }));
    menu = document.querySelector('[role="menu"]');
    [...menu.querySelectorAll('[role="menuitem"]')].find((item) => item.textContent === "Copy row (visible columns, TSV)").click();
    await settle();
    check("Connection menu copies an exact labelled row as TSV",
      copiedText.startsWith("PID\tProcess\tProto\tLocal address\tLocal port\tRemote address\tRemote port\tHostname\tState\tCountry") &&
      copiedText.includes("20\tbeta.exe\tTCPv4\tfe80::1%12\t8000\t203.0.113.1\t443\tRemote.EXAMPLE"), copiedText);
    remoteRow.dispatchEvent(new KeyboardEvent("keydown", { key: "F10", shiftKey: true, bubbles: true, cancelable: true }));
    menu = document.querySelector('[role="menu"]');
    [...menu.querySelectorAll('[role="menuitem"]')].find((item) =>
      item.textContent === "Copy remote hostname").click();
    await settle();
    check("Resolved remote hostname copies as a hostname, not an endpoint", copiedText === "Remote.EXAMPLE", copiedText);
    remoteRow.dispatchEvent(new KeyboardEvent("keydown", { key: "F10", shiftKey: true, bubbles: true, cancelable: true }));
    menu = document.querySelector('[role="menu"]');
    [...menu.querySelectorAll('[role="menuitem"]')].find((item) =>
      item.textContent === "Copy local endpoint").click();
    await settle();
    check("Local endpoint copy preserves IPv6 brackets and scope", copiedText === "[fe80::1%12]:8000", copiedText);
    remoteRow.dispatchEvent(new KeyboardEvent("keydown", { key: "F10", shiftKey: true, bubbles: true, cancelable: true }));
    menu = document.querySelector('[role="menu"]');
    [...menu.querySelectorAll('[role="menuitem"]')].find((item) =>
      item.textContent === "Copy remote port").click();
    await settle();
    check("Remote port copy excludes address punctuation", copiedText === "443", copiedText);
    const listeningRow = host.querySelector('#panel-connections [data-row-key="connection:2"]');
    listeningRow.dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, cancelable: true, clientX: 20, clientY: 20 }));
    menu = document.querySelector('[role="menu"]');
    const listenerRemoteCopyDisabled = ["Copy remote IP", "Copy remote endpoint"]
      .every((label) => [...menu.querySelectorAll('[role="menuitem"]')]
        .find((item) => item.textContent.includes(label))?.getAttribute("aria-disabled") === "true");
    check("Listener context menu disables remote-peer copy", listenerRemoteCopyDisabled);
    let inboundInvestigation = null;
    const captureInbound = (event) => { inboundInvestigation = event.detail?.target || null; };
    document.addEventListener("wintcp:firewall-investigate", captureInbound, { once: true });
    [...menu.querySelectorAll('[role="menuitem"]')]
      .find((item) => item.textContent.includes("Find inbound firewall rules"))?.click();
    check("Listener menu opens inbound rules for the captured local port",
      inboundInvestigation?.direction === "Inbound" && inboundInvestigation?.proto === "TCPv4" &&
      inboundInvestigation?.local === "0.0.0.0" && inboundInvestigation?.lport === 80 &&
      inboundInvestigation?.remote === null && inboundInvestigation?.rport === null,
      JSON.stringify(inboundInvestigation));
    menu.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }));
    const { connectionMenu } = await import("/js/ui/connectionmenu.js");
    connectionMenu({ pid: "0", proto: "TCPv4", local: "—", lport: "0",
      remote: "—", rport: "0", path: "—", state: "UNKNOWN" }, {
      anchor: document.body, onDetails: () => {}, serializeRow: () => "",
    });
    const unknownCopyItems = [...document.querySelectorAll('[role="menuitem"]')];
    const unavailableCopyDisabled = ["Copy PID", "Copy local endpoint", "Copy local port",
      "Copy executable path"].every((label) => unknownCopyItems.find((item) =>
      item.textContent.startsWith(label))?.getAttribute("aria-disabled") === "true");
    check("Connection menu disables copy for unknown owner, endpoint and path fields",
      unavailableCopyDisabled, JSON.stringify(unknownCopyItems.map((item) =>
        [item.textContent, item.getAttribute("aria-disabled")])));
    document.querySelector('[role="menu"]')?.dispatchEvent(
      new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }));
    connectionMenu({ ...sample.connections[0], service: null }, {
      anchor: document.body, onDetails: () => {}, onBlockApplication: () => {},
      onBlockApplicationPeer: () => {}, onBlockServicePeer: () => {},
      onClose: () => {}, onBlock: () => {}, onCloseAndBlock: () => {},
    });
    const unavailableServiceAction = [...document.querySelectorAll('[role="menuitem"]')]
      .find((item) => item.textContent.startsWith("Block this service to this peer"));
    check("A service rule is disabled with a reason when the endpoint has no known service",
      unavailableServiceAction?.getAttribute("aria-disabled") === "true" &&
      unavailableServiceAction?.getAttribute("title") === "A known Windows service short name is required",
      JSON.stringify({ disabled: unavailableServiceAction?.getAttribute("aria-disabled"),
        title: unavailableServiceAction?.getAttribute("title"), row: { path: sample.connections[0].path,
          pid: sample.connections[0].pid, processInstanceId: sample.connections[0].processInstanceId,
          proto: sample.connections[0].proto, state: sample.connections[0].state,
          service: sample.connections[0].service } }));
    document.querySelector('[role="menu"]')?.dispatchEvent(
      new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }));
    host.querySelector('#panel-connections .selection-actions button:first-child')?.click();
    const selectedNetworkKeys = () => [...host.querySelectorAll('#panel-connections .virtual-table-row[aria-selected="true"]')]
      .map((row) => row.dataset.rowKey);
    const afterClearKeys = selectedNetworkKeys();
    const bulkRemoteRow = host.querySelector(`[data-row-key="${connectionKey(sample.connections[0])}"]`);
    const duplicateRemoteRow = host.querySelector(`[data-row-key="${connectionKey(sample.connections[1])}"]`);
    bulkRemoteRow?.dispatchEvent(new MouseEvent("click", { bubbles: true, ctrlKey: true }));
    const afterFirstBulkClick = selectedNetworkKeys();
    duplicateRemoteRow?.dispatchEvent(new MouseEvent("click", { bubbles: true, ctrlKey: true }));
    const selectionText = host.querySelector("#panel-connections .selection-bar")?.textContent || "";
    check("Network table exposes multi-selection with stable connection keys",
      Boolean(duplicateRemoteRow) && selectionText.includes("2 selected"),
      JSON.stringify({ key: duplicateRemoteRow?.dataset.rowKey, selectionText,
        afterClearKeys, afterFirstBulkClick, selected: selectedNetworkKeys() }));
    [...host.querySelectorAll('#panel-connections .selection-actions button')].find((button) =>
      button.textContent === "Copy remote IPs")?.click();
    await settle();
    check("Bulk remote-IP copy deduplicates selected peers",
      copiedText === "203.0.113.1", copiedText);
    [...host.querySelectorAll('#panel-connections .selection-actions button')].find((button) =>
      button.textContent === "Copy selected rows")?.click();
    await settle();
    const selectedTsvLines = copiedText.replace(/\r\n$/, "").split("\r\n");
    check("Bulk row copy includes one header and every selected row",
      selectedTsvLines.length === 3 && selectedTsvLines[0] ===
        "PID\tProcess\tProto\tLocal address\tLocal port\tRemote address\tRemote port\tHostname\tState\tCountry" &&
      selectedTsvLines.slice(1).every((line) => line.split("\t").length === 10), copiedText);
    const originalCreateObjectUrl = Object.getOwnPropertyDescriptor(URL, "createObjectURL");
    const originalRevokeObjectUrl = Object.getOwnPropertyDescriptor(URL, "revokeObjectURL");
    const originalAnchorClick = Object.getOwnPropertyDescriptor(HTMLAnchorElement.prototype, "click");
    let exportBlob = null;
    let exportName = "";
    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: (blob) => {
      exportBlob = blob;
      return "blob:workflow-export";
    } });
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: () => {} });
    Object.defineProperty(HTMLAnchorElement.prototype, "click", { configurable: true, value: function() {
      exportName = this.download;
    } });
    [...host.querySelectorAll('#panel-connections .selection-actions button')].find((button) =>
      button.textContent === "Export selected rows")?.click();
    const exportedTsv = exportBlob ? await exportBlob.text() : "";
    check("Bulk export downloads every current selected row in the visible column order",
      /^wintcp-connections-.*\.tsv$/.test(exportName) && exportedTsv ===
        "PID\tProcess\tProto\tLocal address\tLocal port\tRemote address\tRemote port\tHostname\tState\tCountry\r\n" + selectedTsvLines.slice(1).join("\r\n") + "\r\n",
      JSON.stringify({ exportName, exportedTsv }));
    if (originalCreateObjectUrl) Object.defineProperty(URL, "createObjectURL", originalCreateObjectUrl);
    else delete URL.createObjectURL;
    if (originalRevokeObjectUrl) Object.defineProperty(URL, "revokeObjectURL", originalRevokeObjectUrl);
    else delete URL.revokeObjectURL;
    if (originalAnchorClick) Object.defineProperty(HTMLAnchorElement.prototype, "click", originalAnchorClick);
    else delete HTMLAnchorElement.prototype.click;
    const originalExecCommand = Object.getOwnPropertyDescriptor(document, "execCommand");
    let fallbackCopy = "";
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: undefined });
    Object.defineProperty(document, "execCommand", { configurable: true, value: (command) => {
      if (command !== "copy") return false;
      fallbackCopy = document.querySelector(".clipboard-fallback")?.value || "";
      return true;
    } });
    remoteRow.dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, cancelable: true, clientX: 20, clientY: 20 }));
    menu = document.querySelector('[role="menu"]');
    [...menu.querySelectorAll('[role="menuitem"]')].find((item) => item.textContent === "Copy remote IP").click();
    await settle();
    check("Copy uses the accessible textarea fallback when Clipboard API is unavailable", fallbackCopy === "203.0.113.1" && !document.querySelector(".clipboard-fallback"), JSON.stringify({ fallbackCopy, textarea: Boolean(document.querySelector(".clipboard-fallback")) }));
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: async () => { throw new Error("permission denied"); } } });
    remoteRow.dispatchEvent(new KeyboardEvent("keydown", { key: "F10", shiftKey: true, bubbles: true, cancelable: true }));
    menu = document.querySelector('[role="menu"]');
    [...menu.querySelectorAll('[role="menuitem"]')].find((item) => item.textContent === "Copy remote port").click();
    await settle();
    check("Clipboard denial is reported accessibly without claiming success",
      document.querySelector('#toast-region [role="alert"]')?.textContent.includes("Could not copy remote port"),
      document.querySelector('#toast-region [role="alert"]')?.textContent || "no alert");
    if (originalExecCommand) Object.defineProperty(document, "execCommand", originalExecCommand);
    else delete document.execCommand;
    if (originalClipboard) Object.defineProperty(navigator, "clipboard", originalClipboard);
    else delete navigator.clipboard;
    remoteRow.dispatchEvent(new KeyboardEvent("keydown", { key: "F10", shiftKey: true, bubbles: true, cancelable: true }));
    menu = document.querySelector('[role="menu"]');
    check("Shift+F10 opens the same row menu", Boolean(menu));
    menu.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }));
    check("Escape dismisses the menu", !document.querySelector('[role="menu"]'));
    check("Escape restores focus to the same connection row", document.activeElement === remoteRow);
    remoteRow.dispatchEvent(new KeyboardEvent("keydown", { key: "ContextMenu", bubbles: true, cancelable: true }));
    menu = document.querySelector('[role="menu"]');
    check("The Context Menu key opens the captured row menu", Boolean(menu) && menu.contains(document.activeElement));
    menu?.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }));
    const { openContextMenu } = await import("/js/ui/contextmenu.js");
    const recycledFocusGrid = document.createElement("div");
    recycledFocusGrid.setAttribute("role", "grid");
    const recycledRow = document.createElement("div");
    recycledRow.dataset.rowKey = "captured-row";
    const recycledAction = document.createElement("button");
    recycledAction.textContent = "Row action";
    recycledRow.append(recycledAction);
    recycledFocusGrid.append(recycledRow);
    document.body.append(recycledFocusGrid);
    const recycledMenu = openContextMenu([{ label: "Recycle focus", action: () => {} }], {
      anchor: recycledAction,
      label: "Recycled focus regression",
    });
    recycledRow.dataset.rowKey = "replacement-row";
    const capturedReplacement = document.createElement("div");
    capturedReplacement.dataset.rowKey = "captured-row";
    capturedReplacement.tabIndex = -1;
    recycledFocusGrid.append(capturedReplacement);
    recycledMenu.close();
    check("Context-menu close restores focus to the captured stable key after its opener is recycled",
      document.activeElement === capturedReplacement && document.activeElement.dataset.rowKey === "captured-row");
    recycledFocusGrid.remove();
    const originalDocumentAdd = document.addEventListener;
    const originalDocumentRemove = document.removeEventListener;
    const originalWindowAdd = window.addEventListener;
    const originalWindowRemove = window.removeEventListener;
    const trackedEventTypes = new Set(["pointerdown", "scroll", "resize", "hashchange"]);
    const listenerIds = new WeakMap();
    const outstandingMenuListeners = new Set();
    let nextListenerId = 0;
    let menuListenerAdds = 0;
    let menuListenerRemoves = 0;
    const listenerKey = (target, type, listener, options) => {
      if (!listenerIds.has(listener)) listenerIds.set(listener, ++nextListenerId);
      const capture = options === true || options?.capture === true;
      return `${target}:${type}:${listenerIds.get(listener)}:${capture}`;
    };
    document.addEventListener = function (type, listener, options) {
      if (trackedEventTypes.has(type)) {
        outstandingMenuListeners.add(listenerKey("document", type, listener, options));
        menuListenerAdds++;
      }
      return originalDocumentAdd.call(this, type, listener, options);
    };
    document.removeEventListener = function (type, listener, options) {
      if (trackedEventTypes.has(type)) {
        outstandingMenuListeners.delete(listenerKey("document", type, listener, options));
        menuListenerRemoves++;
      }
      return originalDocumentRemove.call(this, type, listener, options);
    };
    window.addEventListener = function (type, listener, options) {
      if (trackedEventTypes.has(type)) {
        outstandingMenuListeners.add(listenerKey("window", type, listener, options));
        menuListenerAdds++;
      }
      return originalWindowAdd.call(this, type, listener, options);
    };
    window.removeEventListener = function (type, listener, options) {
      if (trackedEventTypes.has(type)) {
        outstandingMenuListeners.delete(listenerKey("window", type, listener, options));
        menuListenerRemoves++;
      }
      return originalWindowRemove.call(this, type, listener, options);
    };
    try {
      for (let attempt = 0; attempt < 5; attempt++) {
        openContextMenu([{ label: `Lifecycle ${attempt + 1}`, action: () => {} }], {
          anchor: remoteRow,
          label: "Lifecycle test menu",
        }).close({ restoreFocus: false });
      }
    } finally {
      document.addEventListener = originalDocumentAdd;
      document.removeEventListener = originalDocumentRemove;
      window.addEventListener = originalWindowAdd;
      window.removeEventListener = originalWindowRemove;
    }
    check("Repeated context-menu cycles remove each global listener",
      menuListenerAdds === 20 && menuListenerRemoves === 20 &&
      outstandingMenuListeners.size === 0 &&
      !document.querySelector(".context-menu"),
      `added=${menuListenerAdds}; removed=${menuListenerRemoves}; live=${outstandingMenuListeners.size}`);
    window.closePreviewCapture = null;
    const originalFetch = window.fetch;
    window.fetch = (input, options) => {
      if (String(input).includes("/api/connections/action/preview")) {
        window.closePreviewCapture = JSON.parse(options.body);
      }
      return originalFetch(input, options);
    };
    host.querySelector('#panel-connections [data-row-key="connection:1"] [aria-label="Connection actions"]').click();
    menu = document.querySelector('[role="menu"]');
    [...menu.querySelectorAll('[role="menuitem"]')].find((item) =>
      item.textContent === "Close this connection").click();
    await new Promise((done) => setTimeout(done, 50));
    check("Close opens an exact-target review dialog",
      document.querySelector("#close-preview-title")?.textContent === "Review connection close" &&
      document.querySelector(".action-preview-dialog [role='status']")?.textContent.includes("requires an elevated"),
      document.querySelector("#close-preview-title")?.textContent + " | " +
        document.querySelector(".action-preview-dialog [role='status']")?.textContent);
    const closeReview = document.querySelector(".action-preview-dialog");
    check("Close review states the elevation requirement explicitly",
      [...(closeReview?.querySelectorAll("dt") || [])].some((label) =>
        label.textContent === "Elevation" &&
        label.nextElementSibling?.textContent === "Elevated WinTCP process required"));
    check("Close preview carries exact connection and process lifetime identity",
      window.closePreviewCapture?.idExact === "1" &&
      window.closePreviewCapture?.processInstanceId === "20:1:2" &&
      window.closePreviewCapture?.lport === "8000" &&
      window.closePreviewCapture?.rport === "443",
      JSON.stringify(window.closePreviewCapture));
    window.fetch = originalFetch;
    document.querySelector(".action-preview-dialog")?.querySelector('button[aria-label="Close"]')?.click();
    await settle();
    const overflow = host.querySelector('#panel-connections [data-row-key="connection:1"] [aria-label="Connection actions"]');
    overflow.click();
    menu = document.querySelector('[role="menu"]');
    check("The visible overflow button opens connection actions", Boolean(menu));
    menu.dispatchEvent(new KeyboardEvent("keydown", { key: "End", bubbles: true, cancelable: true }));
    check("Menu End moves focus to the final action", document.activeElement.textContent === "Copy row (visible columns, TSV)");
    menu.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }));
    const udpBlock = host.querySelector('#panel-connections [data-row-key="connection:3"] [aria-label="Block remote peer"]');
    check("UDP rows cannot start a TCP-only peer-block action", udpBlock?.disabled === true);
    for (const [rowId, explanation] of [["2", "Only established TCP connections can be closed"], ["3", "Windows teardown supports TCP connections only"]]) {
      host.querySelector(`#panel-connections [data-row-key="connection:${rowId}"] [aria-label="Connection actions"]`).click();
      const unsupportedMenu = document.querySelector('[role="menu"]');
      for (const label of ["Close this connection", "Close and block this connection"]) {
        const item = [...unsupportedMenu.querySelectorAll('[role="menuitem"]')].find((candidate) => candidate.textContent.includes(label));
        check(`${label} is disabled for unsupported row ${rowId} with a reason`,
          item?.getAttribute("aria-disabled") === "true" && item.querySelector(".context-menu-reason")?.textContent === explanation,
          `${item?.getAttribute("aria-disabled")} | ${item?.querySelector(".context-menu-reason")?.textContent}`);
      }
      unsupportedMenu.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }));
    }
    const peerBlock = host.querySelector('#panel-connections [data-row-key="connection:1"] [aria-label="Block remote peer"]');
    peerBlock.click();
    await new Promise((done) => setTimeout(done, 30));
    let blockState = await (await fetch("/test-state")).json();
    const blockReview = document.querySelector("dialog");
    check("TCP peer block shows a separate reviewed firewall operation",
      Boolean(blockReview?.textContent.includes("Review TCP peer block") && blockReview.textContent.includes("does not close this connection")) &&
      blockState.blockActionRequests.length === 1 && blockState.blockActionRequests[0].body.address === "203.0.113.1" && blockState.blockActionRequests[0].body.port === "443");
    blockReview.querySelector(".dialog-footer .btn-destructive")?.click();
    await new Promise((done) => setTimeout(done, 30));
    blockState = await (await fetch("/test-state")).json();
    check("Block result reports rule creation separately and never claims connection teardown",
      blockState.blockActionRequests.length === 2 && blockState.blockActionRequests[1].path === "/api/block/commit" &&
      blockReview.textContent.includes("did not close the current connection"));
    window.openedFirewallRuleName = "";
    document.addEventListener("wintcp:firewall-open-rule", (event) => { window.openedFirewallRuleName = event.detail.name; }, { once: true });
    [...blockReview.querySelectorAll("button")].find((button) => button.textContent === "Open firewall rule")?.click();
    await settle();
    check("Successful peer block links to the exact rule identity returned by the server",
      window.openedFirewallRuleName === "WinTCP exact peer rule");
    host.querySelector('#panel-connections [data-row-key="connection:1"] [aria-label="Connection actions"]').click();
    menu = document.querySelector('[role="menu"]');
    [...menu.querySelectorAll('[role="menuitem"]')].find((item) => item.textContent === "Close and block this connection").click();
    await new Promise((done) => setTimeout(done, 40));
    const combinedReview = document.querySelector("dialog");
    blockState = await (await fetch("/test-state")).json();
    check("Combined action requires fresh independent rule and close previews",
      Boolean(combinedReview?.textContent.includes("Create rule, then close") && combinedReview.textContent.includes("preview ready")) &&
      blockState.blockActionRequests.filter((item) => item.path === "/api/block/preview").length === 2 &&
      blockState.closeActionRequests.filter((item) => item.path === "/api/connections/action/preview").length === 2);
    combinedReview.querySelector(".dialog-footer .btn-destructive")?.click();
    await new Promise((done) => setTimeout(done, 60));
    blockState = await (await fetch("/test-state")).json();
    check("Combined action reports firewall failure and connection-close success independently",
      combinedReview.textContent.includes("Firewall rule: failed") && combinedReview.textContent.includes("Connection close: succeeded") &&
      blockState.blockActionRequests.filter((item) => item.path === "/api/block/commit").length === 2 &&
      blockState.closeActionRequests.some((item) => item.path === "/api/connections/action/execute" && item.body.nonce === "c".repeat(32)));
    combinedReview.querySelector('button[aria-label="Close"]')?.click();
    await settle();
    const priorCloseExecutions = blockState.closeActionRequests.filter((item) =>
      item.path === "/api/connections/action/execute").length;
    host.querySelector('#panel-connections [data-row-key="connection:1"] [aria-label="Block remote peer"]').click();
    await new Promise((done) => setTimeout(done, 30));
    const duplicateRuleReview = document.querySelector("dialog");
    duplicateRuleReview?.querySelector(".dialog-footer .btn-destructive")?.click();
    await new Promise((done) => setTimeout(done, 40));
    blockState = await (await fetch("/test-state")).json();
    check("An existing peer rule is reported without claiming a new rule or closing the connection",
      duplicateRuleReview?.textContent.includes("already existed") &&
      duplicateRuleReview.textContent.includes("did not close the current connection") &&
      blockState.blockActionRequests.filter((item) => item.path === "/api/block/commit").length === 3 &&
      blockState.closeActionRequests.filter((item) =>
        item.path === "/api/connections/action/execute").length === priorCloseExecutions);
    duplicateRuleReview?.querySelector('button[aria-label="Close"]')?.click();
    await settle();
    host.querySelector("#tab-listening").click();
    await settle();
    const listenCells = [...host.querySelectorAll('#panel-listening .virtual-table-row [role="gridcell"]')].map((cell) => cell.textContent);
    check("Listening renders exposure and port", listenCells.includes("All interfaces") && listenCells.includes("80"), listenCells.join("|"));
    check("Listening includes UDPv6 bindings", host.querySelector('#panel-listening [role="grid"]').getAttribute("aria-rowcount") === "3");
    const listeningBuckets = Object.fromEntries([...host.querySelectorAll("#panel-listening [data-exposure-count]")]
      .map((cell) => [cell.dataset.exposureCount, Number(cell.textContent)]));
    check("Listening exposure summaries match the rendered wildcard and loopback bindings",
      listeningBuckets.wildcard === 1 && listeningBuckets.loopback === 1 &&
      listeningBuckets.private === 0 && listeningBuckets.specific === 0,
      JSON.stringify(listeningBuckets));
    const listeningPortHeader = host.querySelector('#panel-listening [role="columnheader"][data-column-key="lport"]');
    listeningPortHeader?.click();
    const renderedListeningPorts = [...host.querySelectorAll('#panel-listening .virtual-table-row')]
      .map((row) => Number(row.querySelector('[data-column-key="lport"]')?.textContent));
    check("Listening port header sorts the rendered TCP/UDP bindings numerically",
      renderedListeningPorts.length === 2 && renderedListeningPorts.every(Number.isFinite) &&
      renderedListeningPorts[0] <= renderedListeningPorts[1], renderedListeningPorts.join(","));
    host.querySelector("#tab-history").click();
    await settle();
    check("Closed history is explicit and separate", host.querySelector('#panel-history [role="grid"]').getAttribute("aria-rowcount") === "2");
    check("Closed history cannot block a live peer", host.querySelectorAll('#panel-history button[title^="Block"]').length === 0);
    const historyRow = host.querySelector('#panel-history [data-row-key="connection:4"]');
    historyRow?.dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, cancelable: true, clientX: innerWidth - 1, clientY: innerHeight - 1 }));
    const historyMenu = document.querySelector('[role="menu"]');
    for (const label of ["Close this connection", "Block remote peer", "Close and block this connection"]) {
      const item = [...(historyMenu?.querySelectorAll('[role="menuitem"]') || [])].find((candidate) => candidate.textContent.includes(label));
      check(`${label} is unavailable for a retained history row`,
        item?.getAttribute("aria-disabled") === "true" && item.querySelector(".context-menu-reason")?.textContent.includes("Retained history"),
        `${item?.getAttribute("aria-disabled")} | ${item?.querySelector(".context-menu-reason")?.textContent}`);
    }
    historyMenu?.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }));
    host.querySelector("#tab-blocked").click();
    await new Promise((done) => setTimeout(done, 30));
    const firewallText = host.querySelector("#panel-blocked").textContent;
    check("Firewall Rules uses the installed inventory instead of automation config",
      firewallText.includes("203.0.113.7") && !firewallText.includes("198.51.100.99") &&
      firewallText.includes("Enabled · outbound block"));
    const rulesLayout = host.querySelector("#panel-blocked .column-layout");
    check("Firewall inventory shares table layouts while keeping rule identity and actions required",
      Boolean(rulesLayout) && rulesLayout.querySelector('[data-layout-control="name-visible"]')?.disabled === true &&
      rulesLayout.querySelector('[data-layout-control="actions-visible"]')?.disabled === true);
    check("Non-WinTCP rules are visible but have no mutation controls",
      host.querySelectorAll('#panel-blocked button[aria-label*="Windows managed fixture"]').length === 0 &&
      host.querySelector('#panel-blocked').textContent.includes("Read only"));
    const firewallRuleRow = host.querySelector('#panel-blocked [data-row-key="WinTCP block: fixture"]');
    firewallRuleRow.focus();
    firewallRuleRow.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }));
    await settle();
    const firewallDetails = document.querySelector("dialog");
    check("Firewall rule rows open readable keyboard-accessible details",
      Boolean(firewallDetails?.textContent.includes("Remote addresses") && firewallDetails.textContent.includes("Application") && firewallDetails.textContent.includes("effective policy")),
      JSON.stringify({ dialogs: [...document.querySelectorAll("dialog")].map((item) => item.textContent) }));
    firewallDetails?.querySelector(".dialog-footer button")?.click();
    await settle();
    host.querySelector('#panel-blocked button[aria-label^="Disable"]').click();
    await settle();
    const ruleReview = document.querySelector("dialog");
    let firewallState = await (await fetch("/test-state")).json();
    check("Firewall rule change requires a scoped review before execution",
      Boolean(ruleReview?.textContent.includes("WinTCP block: fixture")) &&
      firewallState.firewallActionRequests.length === 1 && firewallState.firewallActionRequests[0].body.operation === "disable");
    ruleReview.querySelector('button[aria-label="Disable rule"]')?.click();
    await settle();
    firewallState = await (await fetch("/test-state")).json();
    check("Confirmed firewall action sends only the one-use preview token",
      firewallState.firewallActionRequests.length === 2 && firewallState.firewallActionRequests[1].path === "/api/firewall/rule/execute" &&
      firewallState.firewallActionRequests[1].body.nonce === "a".repeat(32) &&
      Object.keys(firewallState.firewallActionRequests[1].body).length === 1);
    ruleReview.querySelector(".dialog-footer .btn-outline")?.click();
    await settle();
    const networkFilter = host.querySelector("#net-filter");
    networkFilter.value = "beta.exe";
    networkFilter.dispatchEvent(new Event("input", { bubbles: true }));
    await new Promise((done) => setTimeout(done, 150));
    await settle();
    host.querySelector("#tab-flows").click();
    await settle();
    const filteredFlow = host.querySelector("#panel-flows");
    check("Flows country totals follow the filtered live rows, not global GeoIP totals",
      filteredFlow.textContent.includes("US") && !filteredFlow.textContent.includes("CA") &&
      filteredFlow.textContent.includes("1"), filteredFlow.textContent);
    host.querySelector("#tab-connections").click();
    await settle();
    const pollAnchor = host.querySelector('#panel-connections [data-row-key="connection:1"]');
    pollAnchor?.dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, cancelable: true, clientX: 30, clientY: 30 }));
    const pollingMenu = document.querySelector('[role="menu"]');
    host._netUpdate({ lastUpdate: Date.now(), connections: sample.connections.map((row) => ({ ...row })), geoSummary: {} });
    await settle();
    check("A connection action menu stays open through a same-snapshot poll", Boolean(pollingMenu?.isConnected));
    pollingMenu?.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }));
    check("Closing after a poll restores focus to the same stable connection key",
      document.activeElement?.dataset.rowKey === "connection:1");
    const removedAnchor = host.querySelector('#panel-connections [data-row-key="connection:1"]');
    removedAnchor?.dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, cancelable: true, clientX: 30, clientY: 30 }));
    const removedAnchorMenu = document.querySelector('[role="menu"]');
    host._netUpdate({ lastUpdate: Date.now(), connections: sample.connections.filter((row) => row.id !== 1), geoSummary: {} });
    await settle();
    removedAnchorMenu?.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }));
    check("Removing a menu's row restores focus to the grid, not a different row",
      document.activeElement?.getAttribute("role") === "grid");
    host._netUpdate({ lastUpdate: Date.now(), connections: sample.connections.map((row) => ({ ...row })), geoSummary: {} });
    await settle();
    host.querySelector('#panel-connections .virtual-table-row')?.click();
    await settle();
    let networkDetails = document.querySelector('[data-details-row="net"]');
    check("Network connection details open from the captured row", Boolean(networkDetails));
    document.activeElement?.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }));
    check("Escape closes the topmost connection inspector", !networkDetails?.isConnected);
    host.querySelector('#panel-connections [data-row-key="connection:1"]')?.click();
    networkDetails = document.querySelector('[data-details-row="net"]');
    check("Connection inspector groups identity and endpoint facts with per-field copy controls",
      networkDetails?.textContent.includes("Identity") && networkDetails?.textContent.includes("Endpoints") &&
      networkDetails?.textContent.includes("Activity") && networkDetails?.textContent.includes("Rules") &&
      Boolean(networkDetails?.querySelector('[aria-label="Copy Remote endpoint"]')));
    host._netUpdate({ lastUpdate: Date.now(), connections: sample.connections.map((row) =>
      row.id === 1 ? { ...row, state: "CLOSE_WAIT" } : { ...row }), geoSummary: {} });
    check("Connection inspector follows an exact matching identity across a live update",
      networkDetails?.textContent.includes("CLOSE_WAIT"));
    networkDetails?.querySelector('button[aria-pressed="false"]')?.click();
    host._netUpdate({ lastUpdate: Date.now(), connections: sample.connections.map((row) =>
      row.id === 1 ? { ...row, state: "FIN_WAIT_1" } : { ...row }), geoSummary: {} });
    check("Held connection inspection keeps captured values and announces held state",
      networkDetails?.textContent.includes("CLOSE_WAIT") && networkDetails?.textContent.includes("Held at the values"));
    networkDetails?.querySelector('button[aria-pressed="true"]')?.click();
    host._netUpdate({ lastUpdate: Date.now(), connections: sample.connections.map((row) =>
      row.id === 1 ? { ...row, state: "FIN_WAIT_1" } : { ...row }), geoSummary: {} });
    check("Resuming connection inspection returns to the same identity's latest values",
      networkDetails?.textContent.includes("FIN_WAIT_1"));
    networkDetails?.querySelector('button[aria-pressed="false"]')?.click();
    host._netUpdate({ lastUpdate: Date.now(), connections: sample.connections.filter((row) => row.id !== 1), geoSummary: {} });
    check("Held inspection reports an endpoint disappearing without replacing captured values",
      networkDetails?.textContent.includes("no longer in the latest endpoint snapshot") &&
      networkDetails?.textContent.includes("FIN_WAIT_1"), JSON.stringify({
        text: networkDetails?.textContent, inspectorKey: networkDetails?.dataset.inspectorKey,
        active: document.querySelector(".inspector-dialog")?.dataset.inspectorKey,
      }));
    networkDetails?.querySelector('button[aria-pressed="true"]')?.click();
    check("Resuming a held item that disappeared reports stale captured evidence",
      networkDetails?.textContent.includes("Showing the last captured details") &&
      networkDetails?.textContent.includes("FIN_WAIT_1"));
    host._netDestroy();
    check("Leaving Network closes its connection inspector", !networkDetails?.isConnected);
    host.replaceChildren();

    const sortConnections = [
      { id: 900, pid: 30, process: "svchost10.exe", proto: "TCP", local: "10.0.0.1", lport: 10, remote: "2001:db8::1", rport: 100, state: "TIME_WAIT" },
      { id: 901, pid: 2, process: "Chrome.exe", proto: "TCP", local: "10.0.0.2", lport: 2, remote: "192.0.2.10", rport: 10, state: "ESTABLISHED" },
      { id: 902, pid: 10, process: "svchost2.exe", proto: "TCP", local: "10.0.0.3", lport: 100, remote: "192.0.2.2", rport: 2, state: "LISTENING" },
      { id: 903, pid: 4, process: "System", proto: "TCP", local: "10.0.0.4", lport: 4, remote: "fe80::1%10", rport: 4, state: "—" },
      { id: 904, pid: 5, process: "System", proto: "TCP", local: "10.0.0.5", lport: 5, remote: "fe80::1%2", rport: 5, state: "CLOSE_WAIT" },
      { id: 905, pid: 6, process: "—", proto: "TCP", local: "10.0.0.6", lport: 6, remote: "—", rport: null, state: "—" },
    ];
    localStorage.removeItem("wintcp.network.recentViews.v1");
    const sortStore = createStore({ connections: sortConnections, geoSummary: {}, lastUpdate: new Date(), networkView: "connections" });
    await renderNetwork(host, sortStore);
    const readColumn = (key) => [...host.querySelectorAll("#panel-connections .virtual-table-row")].map((row) =>
      row.querySelector(`[data-column-key="${key}"]`)?.textContent.trim());
    const sortHeader = (key) => host.querySelector(`#panel-connections [role="columnheader"][data-column-key="${key}"]`);
    sortHeader("remote")?.click();
    await settle();
    check("Rendered remote sort follows IP bytes and family with missing addresses last",
      readColumn("remote").join(",") === "192.0.2.2,192.0.2.10,2001:db8::1,fe80::1%2,fe80::1%10,—",
      readColumn("remote").join(","));
    sortHeader("remote")?.click();
    await settle();
    check("Descending remote sort reverses known IPs but leaves missing addresses last",
      readColumn("remote").at(-1) === "—" && readColumn("remote")[0] === "fe80::1%10",
      readColumn("remote").join(","));
    sortHeader("state")?.click();
    await settle();
    check("Rendered TCP state sort uses its explicit state order and unknown last",
      readColumn("state").join(",") === "LISTENING,ESTABLISHED,CLOSE_WAIT,TIME_WAIT,—,—",
      readColumn("state").join(","));
    sortHeader("rport")?.click();
    await settle();
    check("Rendered remote-port sorting compares 2, 10, and 100 numerically",
      readColumn("rport").join(",") === "2,4,5,10,100,—", readColumn("rport").join(","));
    const columnLayout = host.querySelector("#panel-connections .column-layout");
    columnLayout.open = true;
    columnLayout.querySelector('[data-layout-control="country-visible"]')?.click();
    columnLayout.querySelector('[data-layout-control="remote-up"]')?.click();
    await new Promise((done) => setTimeout(done, 350));
    const customHeaderKeys = [...host.querySelectorAll('#panel-connections [role="columnheader"]')]
      .map((header) => header.dataset.columnKey);
    check("Column controls hide optional fields and reorder columns without replacing the grid",
      !customHeaderKeys.includes("country") && customHeaderKeys.indexOf("remote") < customHeaderKeys.indexOf("lport") &&
      columnLayout.querySelector('[role="status"]')?.textContent === "Layout saved",
      customHeaderKeys.join(","));
    host._netDestroy();
    host.replaceChildren();
    await renderNetwork(host, sortStore);
    await new Promise((done) => setTimeout(done, 40));
    const restoredHeaderKeys = [...host.querySelectorAll('#panel-connections [role="columnheader"]')]
      .map((header) => header.dataset.columnKey);
    check("Versioned column layout persists and restores after the page is rebuilt",
      !restoredHeaderKeys.includes("country") && restoredHeaderKeys.indexOf("remote") < restoredHeaderKeys.indexOf("lport"),
      restoredHeaderKeys.join(","));
    const restoredLayoutDetails = host.querySelector("#panel-connections .column-layout");
    restoredLayoutDetails.open = true;
    restoredLayoutDetails.querySelector('[data-layout-control="preset-compact"]')?.click();
    const essentialHeaderKeys = [...host.querySelectorAll('#panel-connections [role="columnheader"]')]
      .map((header) => header.dataset.columnKey);
    check("Essentials preset hides optional columns but preserves identity and actions",
      ["process", "pid", "actions"].every((key) => essentialHeaderKeys.includes(key)) &&
      ["rport", "hostname", "country"].every((key) => !essentialHeaderKeys.includes(key)),
      essentialHeaderKeys.join(","));
    restoredLayoutDetails.querySelector('[data-layout-control="preset-default"]')?.click();
    await new Promise((done) => setTimeout(done, 350));
    host._netDestroy();
    host.replaceChildren();

    await renderNetwork(host, sortStore);
    await new Promise((done) => setTimeout(done, 50));
    const savedQuery = host.querySelector("#net-filter");
    savedQuery.value = "proto:TCP";
    savedQuery.dispatchEvent(new Event("input", { bubbles: true }));
    await new Promise((done) => setTimeout(done, 180));
    await settle();
    sortStore.set({ networkPredicates: [{ field: "pid", value: 30 }] });
    savedQuery.dispatchEvent(new Event("input", { bubbles: true }));
    await new Promise((done) => setTimeout(done, 180));
    await settle();
    host.querySelector('#panel-connections [role="columnheader"][data-column-key="process"]')?.click();
    host.querySelector('#panel-connections .column-layout [data-layout-control="preset-compact"]')?.click();
    await new Promise((done) => setTimeout(done, 350));
    const recentViewConfig = JSON.parse(localStorage.getItem("wintcp.network.recentViews.v1") || "[]");
    const recentEssentials = recentViewConfig.find((view) => view.query === "proto:TCP" &&
      view.sortKey === "process" && view.tab === "connections" && view.predicates?.[0]?.field === "pid");
    check("Recent Network views persist query, predicates, sort, tab, and current layout in browser-local storage",
      recentEssentials?.layout?.version === 1 && recentEssentials?.layout?.hidden?.includes("rport") &&
      host.querySelector("#net-recent-view option[value='" + recentEssentials?.id + "']") !== null,
      JSON.stringify({ recentEssentials, storedCount: recentViewConfig.length }));
    host.querySelector("#net-view-name").value = "TCP essentials";
    host.querySelector("#net-save-view").click();
    await new Promise((done) => setTimeout(done, 100));
    const savedViewConfig = await (await fetch("/api/config")).json();
    const persistedView = savedViewConfig.networkViews?.find((view) => view.name === "TCP essentials");
    check("Saving a Network view persists query, sort, tab, and table layout without replacing unrelated config",
      persistedView?.query === "proto:TCP" && persistedView?.sortKey === "process" &&
      persistedView?.tab === "connections" && persistedView?.layout?.version === 1 &&
      persistedView?.layout?.hidden?.includes("rport") && persistedView?.predicates?.[0]?.field === "pid" &&
      persistedView?.predicates?.[0]?.value === 30 && savedViewConfig.bookmarks?.[0]?.id === "keep" &&
      savedViewConfig.rules?.[0]?.label === "Automation only" && savedViewConfig.preferences?.futurePreference === "keep",
      JSON.stringify({ persistedView, bookmarks: savedViewConfig.bookmarks, rules: savedViewConfig.rules }));
    host.querySelector("#tab-flows").click();
    await settle();
    host.querySelector("#net-view-name").value = "TCP flow view";
    host.querySelector("#net-save-view").click();
    await new Promise((done) => setTimeout(done, 100));
    const flowViewConfig = await (await fetch("/api/config")).json();
    const persistedFlowView = flowViewConfig.networkViews?.find((view) => view.name === "TCP flow view");
    host.querySelector("#tab-connections").click();
    await settle();
    host.querySelector("#net-saved-view").value = persistedFlowView?.id || "";
    host.querySelector("#net-saved-view").dispatchEvent(new Event("change", { bubbles: true }));
    await settle();
    check("Loading a saved Network view waits for and restores its chosen asynchronous tab",
      persistedFlowView?.tab === "flows" && host.querySelector("#tab-flows")?.getAttribute("aria-selected") === "true" &&
      host.querySelector("#panel-flows")?.hidden === false,
      JSON.stringify({ tab: persistedFlowView?.tab, selected: host.querySelector("#tab-flows")?.getAttribute("aria-selected") }));
    savedQuery.value = "state:ESTABLISHED";
    savedQuery.dispatchEvent(new Event("input", { bubbles: true }));
    await new Promise((done) => setTimeout(done, 180));
    host.querySelector("#net-saved-view").value = persistedView?.id || "";
    host.querySelector("#net-saved-view").dispatchEvent(new Event("change", { bubbles: true }));
    await settle();
    const loadedViewHeaders = [...host.querySelectorAll('#panel-connections [role="columnheader"]')]
      .map((header) => header.dataset.columnKey);
    check("Loading a saved Network view restores its live filter, sort, and essential-column layout",
      savedQuery.value === "proto:TCP" && sortStore.get().netSortKey === "process" &&
      sortStore.get().networkPredicates?.[0]?.field === "pid" && sortStore.get().networkPredicates?.[0]?.value === 30 &&
      !loadedViewHeaders.includes("rport") && !loadedViewHeaders.includes("hostname") &&
      host.querySelector("#net-view-status")?.textContent === 'Loaded "TCP essentials".',
      JSON.stringify({ query: savedQuery.value, sort: sortStore.get().netSortKey, headers: loadedViewHeaders }));
    savedQuery.value = "state:ESTABLISHED";
    savedQuery.dispatchEvent(new Event("input", { bubbles: true }));
    await new Promise((done) => setTimeout(done, 180));
    host.querySelector("#net-recent-view").value = recentEssentials?.id || "";
    host.querySelector("#net-recent-view").dispatchEvent(new Event("change", { bubbles: true }));
    await settle();
    const recentRestoredHeaders = [...host.querySelectorAll('#panel-connections [role="columnheader"]')]
      .map((header) => header.dataset.columnKey);
    check("Restoring a recent Network view reapplies its filter, predicates, sort, and layout",
      recentEssentials?.id && savedQuery.value === "proto:TCP" &&
      sortStore.get().netSortKey === "process" && sortStore.get().networkPredicates?.[0]?.value === 30 &&
      !recentRestoredHeaders.includes("rport") &&
      host.querySelector("#net-view-status")?.textContent.includes("Restored recent view:"),
      JSON.stringify({ query: savedQuery.value, sort: sortStore.get().netSortKey,
        predicates: sortStore.get().networkPredicates, selected: host.querySelector("#net-recent-view")?.value,
        recentId: recentEssentials?.id, optionExists: Boolean(host.querySelector("#net-recent-view option[value='" + recentEssentials?.id + "']")),
        status: host.querySelector("#net-view-status")?.textContent, headers: recentRestoredHeaders }));
    for (let index = 0; index < 12; index++) {
      savedQuery.value = "pid:" + (90 + index);
      savedQuery.dispatchEvent(new Event("input", { bubbles: true }));
      await new Promise((done) => setTimeout(done, 180));
    }
    const cappedRecentViews = JSON.parse(localStorage.getItem("wintcp.network.recentViews.v1") || "[]");
    const cappedRecentId = cappedRecentViews[0]?.id;
    check("Recent Network history deduplicates views and stays within its ten-entry limit",
      cappedRecentViews.length === 10 && cappedRecentViews[0]?.query === "pid:101" &&
      new Set(cappedRecentViews.map((view) => view.id)).size === cappedRecentViews.length,
      JSON.stringify({ count: cappedRecentViews.length, latest: cappedRecentViews[0]?.query }));
    host.querySelector("#net-delete-view").click();
    await new Promise((done) => setTimeout(done, 80));
    const deletedViewConfig = await (await fetch("/api/config")).json();
    check("Deleting a saved Network view removes only that view from config", 
      !deletedViewConfig.networkViews?.some((view) => view.name === "TCP essentials") &&
      deletedViewConfig.bookmarks?.[0]?.id === "keep" && deletedViewConfig.rules?.[0]?.label === "Automation only");
    host.querySelector("#net-saved-view").value = persistedFlowView?.id || "";
    host.querySelector("#net-saved-view").dispatchEvent(new Event("change", { bubbles: true }));
    await settle();
    host.querySelector("#net-delete-view").click();
    await new Promise((done) => setTimeout(done, 80));
    host._netDestroy();
    host.replaceChildren();
    await renderNetwork(host, sortStore);
    await settle();
    const reloadedRecentView = JSON.parse(localStorage.getItem("wintcp.network.recentViews.v1") || "[]")
      .find((view) => view.id === cappedRecentId);
    check("Recent Network views remain available after the Network route is reconstructed",
      Boolean(reloadedRecentView) &&
      host.querySelector("#net-recent-view option[value='" + cappedRecentId + "']") !== null,
      JSON.stringify({ recent: Boolean(reloadedRecentView), optionCount: host.querySelectorAll("#net-recent-view option").length }));
    host.querySelector("#net-clear-recent-views").click();
    check("Clear recent removes only browser-local Network history",
      localStorage.getItem("wintcp.network.recentViews.v1") === null &&
      host.querySelector("#net-recent-view").disabled &&
      host.querySelector("#net-view-status")?.textContent === "Recent views cleared.");
    host._netDestroy();
    host.replaceChildren();

    const retainedViewRows = Array.from({ length: 80 }, (_, index) => ({
      id: 1000 + index, pid: index + 1, process: `retained-${index}.exe`, proto: "TCP",
      local: "10.0.0.1", lport: 2000 + index, remote: "192.0.2.1", rport: 443,
      state: index === 0 ? "LISTENING" : "ESTABLISHED",
    }));
    const retainedViewStore = createStore({
      connections: retainedViewRows, geoSummary: {}, lastUpdate: new Date(), networkView: "connections",
    });
    await renderNetwork(host, retainedViewStore);
    await settle();
    const retainedViewGrid = host.querySelector("#panel-connections .virtual-table");
    retainedViewGrid.scrollTop = 800;
    retainedViewGrid.dispatchEvent(new Event("scroll"));
    await settle();
    const requestedViewScroll = retainedViewGrid.scrollTop;
    host.querySelector('[data-row-key="connection:1025"]')?.dispatchEvent(
      new MouseEvent("click", { bubbles: true, ctrlKey: true }));
    const selectedBeforeTabSwitch = retainedViewStore.get().networkTableStates?.connections?.selectedKeys;
    host.querySelector("#tab-listening").click();
    await settle();
    const savedNetworkViewState = retainedViewStore.get().networkTableStates?.connections;
    host.querySelector("#tab-connections").click();
    await settle();
    const reactivatedViewGrid = host.querySelector("#panel-connections .virtual-table");
    check("Switching Network tabs restores the captured table scroll and stable-key selection",
      Math.abs(reactivatedViewGrid.scrollTop - 800) < 2 &&
      host.querySelector('[data-row-key="connection:1025"]')?.getAttribute("aria-selected") === "true",
      JSON.stringify({ scrollTop: reactivatedViewGrid.scrollTop,
        selected: host.querySelector('[data-row-key="connection:1025"]')?.getAttribute("aria-selected"),
        requestedViewScroll, scrollHeight: reactivatedViewGrid.scrollHeight, rowCount: retainedViewRows.length,
        selectedBeforeTabSwitch, savedNetworkViewState }));
    host._netDestroy();
    host.replaceChildren();
    await renderNetwork(host, retainedViewStore);
    await settle();
    const remountedViewGrid = host.querySelector("#panel-connections .virtual-table");
    check("Network route remount restores the view's scroll and selected stable row",
      Math.abs(remountedViewGrid.scrollTop - 800) < 2 &&
      host.querySelector('[data-row-key="connection:1025"]')?.getAttribute("aria-selected") === "true",
      JSON.stringify({ scrollTop: remountedViewGrid.scrollTop,
        selected: host.querySelector('[data-row-key="connection:1025"]')?.getAttribute("aria-selected") }));
    host._netDestroy();
    host.replaceChildren();

    await renderNetwork(host, netStore);
    host.querySelector("#tab-blocked").click();
    await new Promise((done) => setTimeout(done, 30));
    const lifecycleRuleRow = host.querySelector('#panel-blocked [data-row-key="WinTCP block: fixture"]');
    lifecycleRuleRow?.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }));
    await settle();
    const firewallLifecycleDetails = [...document.querySelectorAll("dialog")].find((item) => item.textContent.includes("Firewall rule details"));
    host._netDestroy();
    check("Leaving Network closes its firewall rule inspector", !firewallLifecycleDetails?.isConnected);
    host.replaceChildren();

    const treeRows = [
      { pid: 100, instanceId: "100:1:100", name: "parent.exe", ppid: 1, cpuPct: 1, memWs: 16, connections: 0 },
      { pid: 101, instanceId: "101:1:101", name: "child.exe", ppid: 100, cpuPct: 2, memWs: 8, connections: 1 },
      { pid: 102, instanceId: "102:1:102", name: "sibling.exe", ppid: 100, cpuPct: 0, memWs: 4, connections: 0 },
      { pid: 105, instanceId: "105:1:105", name: "child.exe", path: "C:\\Apps\\child.exe", ppid: 100, cpuPct: 1, memWs: 3, connections: 0 },
      { pid: 106, instanceId: "106:1:106", name: "orphan.exe", ppid: 999, cpuPct: 0, memWs: 1, connections: 0 },
      { pid: 103, instanceId: "103:1:103", name: "cycle-a.exe", ppid: 104, cpuPct: 0, memWs: 2, connections: 0 },
      { pid: 104, instanceId: "104:1:104", name: "cycle-b.exe", ppid: 103, cpuPct: 0, memWs: 2, connections: 0 },
    ];
    const treeStore = createStore({
      processes: treeRows, processesKnown: true, lastUpdate: new Date(),
      processView: "tree", processFilter: "child.exe",
    });
    await renderProcesses(host, treeStore);
    let parentNode = host.querySelector('[role="treeitem"][data-tree-key="100:1:100"]');
    check("Filtering a process keeps and labels its ancestor context", Boolean(parentNode?.classList.contains("tree-item-context")) && parentNode?.getAttribute("aria-expanded") === "true" && Boolean(host.querySelector('[data-tree-key="101:1:101"]')));
    check("Duplicate process names keep separate process-instance nodes", host.querySelectorAll('[data-tree-key="101:1:101"], [data-tree-key="105:1:105"]').length === 2);
    parentNode?.focus();
    parentNode?.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowLeft", bubbles: true, cancelable: true }));
    check("Tree ArrowLeft collapses a branch", !host.querySelector('[data-tree-key="101:1:101"]') && host.querySelector('[data-tree-key="100:1:100"]')?.getAttribute("aria-expanded") === "false");
    treeStore.set({ processes: treeRows.slice(), lastUpdate: new Date() });
    updateProcesses(host, treeStore);
    await new Promise((done) => setTimeout(done, 30));
    parentNode = host.querySelector('[role="treeitem"][data-tree-key="100:1:100"]');
    check("Tree expansion and focus survive a process refresh", parentNode?.getAttribute("aria-expanded") === "false" && parentNode?.tabIndex === 0);
    parentNode?.focus();
    parentNode?.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowRight", bubbles: true, cancelable: true }));
    check("Tree ArrowRight expands a branch", host.querySelector('[data-tree-key="101:1:101"]')?.isConnected && host.querySelector('[data-tree-key="100:1:100"]')?.getAttribute("aria-expanded") === "true");
    parentNode = host.querySelector('[role="treeitem"][data-tree-key="100:1:100"]');
    parentNode?.dispatchEvent(new KeyboardEvent("keydown", { key: " ", bubbles: true, cancelable: true }));
    check("Tree Space collapses the focused branch", !host.querySelector('[data-tree-key="101:1:101"]'));
    parentNode = host.querySelector('[role="treeitem"][data-tree-key="100:1:100"]');
    parentNode?.dispatchEvent(new KeyboardEvent("keydown", { key: " ", bubbles: true, cancelable: true }));
    parentNode = host.querySelector('[role="treeitem"][data-tree-key="100:1:100"]');
    check("Tree Space reopens the focused branch", host.querySelector('[data-tree-key="101:1:101"]')?.isConnected);
    parentNode = host.querySelector('[role="treeitem"][data-tree-key="100:1:100"]');
    parentNode?.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true, cancelable: true }));
    const childNode = document.activeElement;
    check("Tree ArrowDown moves focus to the next visible process", childNode?.dataset.treeKey === "101:1:101");
    childNode?.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowUp", bubbles: true, cancelable: true }));
    check("Tree ArrowUp returns focus to the previous visible process", document.activeElement?.dataset.treeKey === "100:1:100");
    document.activeElement?.dispatchEvent(new KeyboardEvent("keydown", { key: "End", bubbles: true, cancelable: true }));
    check("Tree End focuses the last visible process", document.activeElement?.dataset.treeKey === "105:1:105");
    document.activeElement?.dispatchEvent(new KeyboardEvent("keydown", { key: "Home", bubbles: true, cancelable: true }));
    check("Tree Home focuses the first visible process", document.activeElement?.dataset.treeKey === "100:1:100");
    document.activeElement?.dispatchEvent(new KeyboardEvent("keydown", { key: "End", bubbles: true, cancelable: true }));
    const focusedChild = document.activeElement;
    focusedChild?.dispatchEvent(new KeyboardEvent("keydown", { key: "F10", shiftKey: true, bubbles: true, cancelable: true }));
    check("Tree process actions open from the focused node", Boolean(document.querySelector('[role="menu"]')) && [...document.querySelectorAll('[role="menuitem"]')].some((item) => item.textContent.includes("Show this process's connections")));
    document.querySelector('[role="menu"]')?.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }));
    focusedChild?.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }));
    await settle();
    const treeProcessDetails = document.querySelector('[data-details-row="proc"]');
    check("Tree Enter opens details for the exact process instance", treeProcessDetails?.querySelector(".dialog-title")?.textContent === "child.exe" && treeProcessDetails.textContent.includes("105"));
    check("Process inspector exposes lifetime identity, unknown reasons, and copyable path",
      treeProcessDetails?.textContent.includes("Process instance") &&
      treeProcessDetails?.textContent.includes("Activity") &&
      Boolean(treeProcessDetails?.querySelector('[aria-label="Copy Executable path"]')) &&
      [...treeProcessDetails.querySelectorAll(".inspector-footer button")].some((button) => button.textContent.includes("Show this process's connections")) &&
      [...treeProcessDetails.querySelectorAll(".inspector-footer button")].some((button) => button.textContent.includes("Review app firewall block")));
    const reusedChildRows = treeRows.map((row) => row.pid === 105
      ? { ...row, instanceId: "105:1:999", name: "reused-child.exe" } : row);
    treeStore.set({ processes: reusedChildRows, processFilter: "", lastUpdate: new Date() });
    updateProcesses(host, treeStore);
    await new Promise((done) => setTimeout(done, 30));
    check("Process inspector refuses to follow a reused PID and preserves captured evidence",
      treeProcessDetails?.textContent.includes("This process instance exited") &&
      treeProcessDetails?.querySelector(".dialog-title")?.textContent === "child.exe");
    treeProcessDetails?.querySelector('[aria-label="Close"]')?.click();
    const replacedTreeRows = treeRows.map((row) => row.pid === 100 ? { ...row, instanceId: "100:1:99" } : row);
    treeStore.set({ processes: replacedTreeRows, processFilter: "child.exe", lastUpdate: new Date() });
    updateProcesses(host, treeStore);
    await new Promise((done) => setTimeout(done, 30));
    check("Tree expansion state does not transfer to a reused PID", host.querySelector('[data-tree-key="100:1:99"]')?.getAttribute("aria-expanded") === "true" && !host.querySelector('[data-tree-key="100:1:100"]') && Boolean(host.querySelector('[data-tree-key="101:1:101"]')));
    host.querySelector("#proc-filter").value = "";
    treeStore.set({ processes: treeRows, processFilter: "" });
    updateProcesses(host, treeStore);
    await new Promise((done) => setTimeout(done, 30));
    check("Processes with missing parents remain visible as roots", host.querySelector('[role="treeitem"][data-tree-key="106:1:106"]')?.getAttribute("aria-level") === "1");
    check("Process parent cycles render as finite roots", host.querySelectorAll('[role="treeitem"]').length === 7 && host.querySelector('[data-tree-key="103:1:103"]') && host.querySelector('[data-tree-key="104:1:104"]'));
    const reusedParentRows = [
      { pid: 42, instanceId: "42:0:200", name: "reused-parent.exe", ppid: 1, cpuPct: 0, memWs: 1 },
      { pid: 50, instanceId: "50:0:100", name: "surviving-child.exe", ppid: 42, cpuPct: 0, memWs: 1 },
      { pid: 60, instanceId: null, name: "unverified-parent.exe", ppid: 1, cpuPct: 0, memWs: 1 },
      { pid: 61, instanceId: null, name: "unverified-child.exe", ppid: 60, cpuPct: 0, memWs: 1 },
    ];
    treeStore.set({ processes: reusedParentRows, processFilter: "", lastUpdate: new Date() });
    updateProcesses(host, treeStore);
    await new Promise((done) => setTimeout(done, 30));
    const reusedChildNode = host.querySelector('[role="treeitem"][data-tree-key="50:0:100"]');
    const unverifiedChildNode = host.querySelector('[role="treeitem"][data-tree-key="61:unknown"]');
    check("Process tree refuses a parent PID created after its surviving child",
      reusedChildNode?.getAttribute("aria-level") === "1" &&
      reusedChildNode.getAttribute("aria-description")?.includes("PID was reused") &&
      host.querySelector('[role="treeitem"][data-tree-key="42:0:200"]')?.getAttribute("aria-level") === "1");
    check("Process tree labels matching parent PIDs whose lifetimes cannot be verified",
      unverifiedChildNode?.getAttribute("aria-level") === "1" &&
      unverifiedChildNode.getAttribute("aria-description") === "Parent identity could not be verified" &&
      unverifiedChildNode.textContent.includes("Parent unverified"));
    const reparentedRows = treeRows.filter((row) => row.pid !== 100).map((row) =>
      row.pid === 101 ? { ...row, ppid: 999 } : row);
    treeStore.set({ processes: reparentedRows, processFilter: "", lastUpdate: new Date() });
    updateProcesses(host, treeStore);
    await new Promise((done) => setTimeout(done, 30));
    check("A surviving child becomes a root after its parent exits",
      !host.querySelector('[data-tree-key="100:1:100"]') &&
      host.querySelector('[role="treeitem"][data-tree-key="101:1:101"]')?.getAttribute("aria-level") === "1");
    host._procDestroy();
    host.replaceChildren();

    const sortProcesses = [
      { pid: 10, instanceId: "10:1:10", name: "svchost10.exe", ppid: 4, cpuPct: 0, memWs: 736100352, memPrivate: 736100352, ioRead: "9007199254740993", ioWrite: 0 },
      { pid: 2, instanceId: "2:1:2", name: "Chrome.exe", path: "C:\\Program Files\\Fixture\\chrome.exe", service: "FixtureSvc", ppid: 4, cpuPct: 0, memWs: 0, ioRead: 0 },
      { pid: 3, instanceId: "3:1:3", name: "svchost2.exe", ppid: 4, cpuPct: 0, memWs: null, ioRead: null },
      { pid: 4, instanceId: "4:1:4", name: "—", ppid: 0, cpuPct: 0, memWs: 1, ioRead: "9007199254740992" },
    ];
    const processStore = createStore({
      processes: sortProcesses, processesKnown: true, lastUpdate: new Date(), processView: "table",
    });
    setFormatUnits("iec");
    await renderProcesses(host, processStore);
    const processFilter = host.querySelector("#proc-filter");
    processFilter.value = "FixtureSvc";
    processFilter.dispatchEvent(new Event("input", { bubbles: true }));
    await new Promise((done) => setTimeout(done, 150));
    check("Process text filter searches service attribution and offers a clear action",
      host.querySelectorAll("#panel-table .virtual-table-row").length === 1 &&
      host.querySelector('#panel-table [data-row-key="2:1:2"]') &&
      !host.querySelector('#panel-table [data-row-key="10:1:10"]') &&
      !host.querySelector("#proc-filter-clear").hidden);
    processFilter.value = "Program Files\\Fixture";
    processFilter.dispatchEvent(new Event("input", { bubbles: true }));
    await new Promise((done) => setTimeout(done, 150));
    check("Process text filter searches executable paths without changing instance identity",
      host.querySelectorAll("#panel-table .virtual-table-row").length === 1 &&
      host.querySelector('#panel-table [data-row-key="2:1:2"]'));
    host.querySelector("#proc-filter-clear").click();
    await new Promise((done) => setTimeout(done, 150));
    check("Clearing the process filter restores all rows", host.querySelectorAll("#panel-table .virtual-table-row").length === 4);
    const memoryCell = () => host.querySelector('#panel-table [data-row-key="10:1:10"] [data-column-key="memWs"]');
    const ioReadCell = () => host.querySelector('#panel-table [data-row-key="10:1:10"] [data-column-key="ioRead"]');
    const zeroMemoryCell = host.querySelector('#panel-table [data-row-key="2:1:2"] [data-column-key="memWs"]');
    const unknownMemoryCell = host.querySelector('#panel-table [data-row-key="3:1:3"] [data-column-key="memWs"]');
    check("Processes formats working set as IEC size while retaining exact bytes and numeric alignment",
      memoryCell()?.textContent === "702 MiB" && memoryCell()?.title === "736100352" &&
      getComputedStyle(memoryCell()).textAlign === "right" &&
      ioReadCell()?.textContent.replace(/\s+/g, " ").trim() === "8,192 TiB" && ioReadCell()?.title === "9007199254740993" &&
      getComputedStyle(ioReadCell()).textAlign === "right",
      JSON.stringify({ memory: memoryCell()?.textContent, exact: memoryCell()?.title,
        ioRead: ioReadCell()?.textContent, ioExact: ioReadCell()?.title,
        align: memoryCell() ? getComputedStyle(memoryCell()).textAlign : null }));
    check("Processes distinguishes measured zero memory from an unavailable working set",
      zeroMemoryCell?.textContent === "0 B" && zeroMemoryCell?.title === "0" &&
      unknownMemoryCell?.textContent === "—" && unknownMemoryCell?.title === "—");
    setFormatUnits("si");
    updateProcesses(host, processStore);
    await settle();
    check("Live unit preference reformats existing process rows without losing raw values",
      memoryCell()?.textContent === "736.1 MB" && memoryCell()?.title === "736100352",
      JSON.stringify({ text: memoryCell()?.textContent, exact: memoryCell()?.title }));
    setFormatUnits("iec");
    updateProcesses(host, processStore);
    await settle();
    const memoryHeader = host.querySelector('#panel-table [role="columnheader"][data-column-key="memWs"]');
    const readMemoryOrder = () => [...host.querySelectorAll("#panel-table .virtual-table-row")]
      .map((row) => row.dataset.rowKey);
    memoryHeader?.click();
    await settle();
    check("Rendered working-set sort compares numeric bytes and keeps unknown values last",
      readMemoryOrder().join(",") === "2:1:2,4:1:4,10:1:10,3:1:3", readMemoryOrder().join(","));
    memoryHeader?.click();
    await settle();
    check("Descending working-set sort reverses measured sizes without promoting unknown values",
      readMemoryOrder().join(",") === "10:1:10,4:1:4,2:1:2,3:1:3", readMemoryOrder().join(","));
    const ioHeader = host.querySelector('#panel-table [role="columnheader"][data-column-key="ioRead"]');
    const readIoOrder = () => [...host.querySelectorAll("#panel-table .virtual-table-row")]
      .map((row) => row.dataset.rowKey);
    ioHeader?.click();
    await settle();
    check("Rendered I/O sort preserves adjacent counters above JavaScript's safe integer limit",
      readIoOrder().join(",") === "2:1:2,4:1:4,10:1:10,3:1:3", readIoOrder().join(","));
    ioHeader?.click();
    await settle();
    check("Descending I/O sort preserves exact counter order and leaves unknown values last",
      readIoOrder().join(",") === "10:1:10,4:1:4,2:1:2,3:1:3", readIoOrder().join(","));
    const readProcessNames = () => [...host.querySelectorAll("#panel-table .virtual-table-row [data-column-key=name]")]
      .map((cell) => cell.textContent.trim());
    const processNameHeader = host.querySelector('#panel-table [role="columnheader"][data-column-key="name"]');
    processNameHeader?.click();
    await settle();
    check("Rendered process-name sort is natural and keeps unknown names last",
      readProcessNames().join(",") === "Chrome.exe,svchost2.exe,svchost10.exe,—",
      readProcessNames().join(","));
    processNameHeader?.click();
    await settle();
    check("Descending process-name sort reverses names without moving unknowns first",
      readProcessNames().join(",") === "svchost10.exe,svchost2.exe,Chrome.exe,—",
      readProcessNames().join(","));
    const refreshedSortProcesses = [
      { pid: 41, instanceId: "41:1:41", name: "alpha.exe", ppid: 4 },
      { pid: 42, instanceId: "42:1:42", name: "svchost2.exe", ppid: 4 },
      { pid: 43, instanceId: "43:1:43", name: "SVCHOST10.exe", ppid: 4 },
      { pid: 44, instanceId: "44:1:44", name: "Chrome.exe", ppid: 4 },
      { pid: 45, instanceId: "45:1:45", name: "—", ppid: 0 },
    ];
    processStore.set({ processes: refreshedSortProcesses, processesKnown: true, lastUpdate: new Date() });
    updateProcesses(host, processStore);
    await settle();
    const refreshedProcessNameHeader = host.querySelector('#panel-table [role="columnheader"][data-column-key="name"]');
    check("Rendered descending process-name sort and header direction survive a refreshed snapshot",
      readProcessNames().join(",") === "SVCHOST10.exe,svchost2.exe,Chrome.exe,alpha.exe,—" &&
      refreshedProcessNameHeader?.getAttribute("aria-sort") === "descending",
      JSON.stringify({ names: readProcessNames(), ariaSort: refreshedProcessNameHeader?.getAttribute("aria-sort") }));
    const processColumnLayout = host.querySelector("#panel-table .column-layout");
    processColumnLayout.open = true;
    processColumnLayout.querySelector('[data-layout-control="name-down"]')?.click();
    await new Promise((done) => setTimeout(done, 350));
    const reorderedProcessHeaders = [...host.querySelectorAll('#panel-table [role="columnheader"]')]
      .map((header) => header.dataset.columnKey);
    const secondRefreshedProcesses = [
      refreshedSortProcesses[4], refreshedSortProcesses[0], refreshedSortProcesses[3],
      refreshedSortProcesses[2], refreshedSortProcesses[1],
    ];
    processStore.set({ processes: secondRefreshedProcesses, processesKnown: true, lastUpdate: new Date() });
    updateProcesses(host, processStore);
    await settle();
    const reorderedNameHeader = host.querySelector('#panel-table [role="columnheader"][data-column-key="name"]');
    check("Reordered process columns retain the selected sort and rendered row order after refresh",
      reorderedProcessHeaders.indexOf("name") > reorderedProcessHeaders.indexOf("pid") &&
      readProcessNames().join(",") === "SVCHOST10.exe,svchost2.exe,Chrome.exe,alpha.exe,—" &&
      reorderedNameHeader?.getAttribute("aria-sort") === "descending",
      JSON.stringify({ columns: reorderedProcessHeaders, names: readProcessNames(),
        ariaSort: reorderedNameHeader?.getAttribute("aria-sort") }));
    host._procDestroy();
    host.replaceChildren();

    const processPayload = await api.get("/api/processes");
    host.style.width = "540px";
    await renderProcesses(host, createStore({
      processes: processPayload.processes,
      processesKnown: true,
      lastUpdate: new Date(),
      processView: "treemap",
    }));
    await new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(done)));
    const treemapHost = host.querySelector("#panel-treemap .treemap-host");
    const treemapTiles = [...host.querySelectorAll("#panel-treemap .treemap-tile")];
    const maxTileRight = () => Math.max(0, ...[...host.querySelectorAll("#panel-treemap .treemap-tile")]
      .map((tile) => parseFloat(tile.style.left) + parseFloat(tile.style.width)));
    const treemapFitsInitialWidth = treemapHost?.clientWidth > 0 && treemapTiles.length > 0 && maxTileRight() <= treemapHost.clientWidth + 1;
    host.querySelector('#panel-treemap .treemap-tile[aria-label^="beta.exe"]')?.click();
    await settle();
    const treemapDetails = document.querySelector('[data-details-row="proc"]');
    check("Treemap tile opens details for its exact process", treemapDetails?.querySelector(".dialog-title")?.textContent === "beta.exe" && treemapDetails.textContent.includes("PID") && treemapDetails.textContent.includes("20") && Boolean(host.querySelector('#panel-treemap .treemap-tile[aria-label^="beta.exe (PID 20):"]')), treemapDetails?.textContent || "no process inspector opened");
    treemapDetails?.querySelector('[aria-label="Close"]')?.click();
    await settle();
    host.style.width = "390px";
    await new Promise((done) => setTimeout(done, 50));
    check("Process treemap waits for its mounted width and redraws responsively", treemapFitsInitialWidth && treemapHost.clientWidth > 0 && maxTileRight() <= treemapHost.clientWidth + 1);
    host.querySelector("#tab-table").click();
    await new Promise((done) => setTimeout(done, 20));
    host.style.removeProperty("width");
    host.querySelector(".virtual-table-row")?.click();
    await settle();
    const processDetails = document.querySelector('[data-details-row="proc"]');
    host._procDestroy();
    check("Leaving Processes closes its process inspector", !processDetails?.isConnected);
    host.replaceChildren();

    const groupedProcesses = [
      { pid: 2001, instanceId: "2001:1:2001", name: "browser.exe", path: "C:\\Apps\\Browser\\browser.exe", ppid: 4, cpuPct: 2, memWs: "9007199254740993" },
      { pid: 2002, instanceId: "2002:1:2002", name: "browser.exe", path: "C:\\Apps\\Browser\\browser.exe", ppid: 4, cpuPct: 3, memWs: "9007199254740995" },
      { pid: 2003, instanceId: "2003:1:2003", name: "browser.exe", path: "D:\\Portable\\browser.exe", ppid: 4, cpuPct: 1, memWs: "4503599627370496" },
      { pid: 2004, instanceId: "2004:1:2004", name: "browser.exe", path: null, ppid: 4, cpuPct: 0, memWs: "4503599627370496" },
      { pid: 2005, instanceId: "2005:1:2005", name: "browser.exe", path: "C:\\Apps\\Browser\\browser.exe", ppid: 4, cpuPct: null, memWs: null },
    ];
    host.style.width = "390px";
    const groupedStore = createStore({
      processes: groupedProcesses, processesKnown: true, lastUpdate: new Date(),
      processView: "treemap",
    });
    await renderProcesses(host, groupedStore);
    const groupButton = [...host.querySelectorAll("#panel-treemap .treemap-toolbar button")]
      .find((button) => button.textContent === "Group by executable");
    const groupToolbar = host.querySelector("#panel-treemap .treemap-toolbar");
    check("Treemap controls wrap without horizontal overflow at a narrow viewport",
      groupToolbar?.scrollWidth <= groupToolbar?.clientWidth);
    groupButton?.click();
    await settle();
    const groupedBrowserTile = [...host.querySelectorAll("#panel-treemap .treemap-tile")]
      .find((tile) => tile.getAttribute("aria-label").includes("browser.exe; 3 process instances"));
    check("Treemap groups only instances with the same known executable path",
      groupButton?.getAttribute("aria-pressed") === "true" &&
      host.querySelectorAll("#panel-treemap .treemap-tile").length === 3 &&
      Boolean(groupedBrowserTile?.getAttribute("title").includes("2 of 3 instances")) &&
      host.querySelector("#panel-treemap .treemap-note")?.textContent.includes("pathless instances stay separate"),
      JSON.stringify({ pressed: groupButton?.getAttribute("aria-pressed"),
        tiles: [...host.querySelectorAll("#panel-treemap .treemap-tile")].map((tile) => ({
          label: tile.getAttribute("aria-label"), title: tile.title })),
        note: host.querySelector("#panel-treemap .treemap-note")?.textContent }));
    const cpuMetricButton = [...host.querySelectorAll("#panel-treemap .treemap-switch button")]
      .find((button) => button.textContent === "CPU share");
    cpuMetricButton?.click();
    await settle();
    const cpuBrowserTile = [...host.querySelectorAll("#panel-treemap .treemap-tile")]
      .find((tile) => tile.getAttribute("aria-label").includes("browser.exe; 3 process instances"));
    check("Executable group CPU totals sum measured instances and mark the partial subtotal",
      cpuBrowserTile?.getAttribute("aria-label").includes("5%") &&
      cpuBrowserTile.getAttribute("aria-label").includes("2 of 3 instances"));
    [...host.querySelectorAll("#panel-treemap .treemap-switch button")]
      .find((button) => button.textContent === "Working set")?.click();
    await settle();
    updateProcesses(host, groupedStore);
    await settle();
    const refreshedGroupButton = [...host.querySelectorAll("#panel-treemap .treemap-toolbar button")]
      .find((button) => button.textContent === "Group by executable");
    check("Executable grouping stays selected when the process snapshot refreshes",
      refreshedGroupButton?.getAttribute("aria-pressed") === "true");
    const refreshedBrowserTile = [...host.querySelectorAll("#panel-treemap .treemap-tile")]
      .find((tile) => tile.getAttribute("aria-label").includes("browser.exe; 3 process instances"));
    refreshedBrowserTile?.click();
    await settle();
    const groupDialog = document.querySelector(".process-group-dialog");
    const secondBrowserInstance = [...(groupDialog?.querySelectorAll(".process-group-instance") || [])]
      .find((button) => button.textContent.includes("PID 2002"));
    secondBrowserInstance?.click();
    await settle();
    const groupedInstanceDetails = document.querySelector('[data-details-row="proc"]');
    check("Grouped treemap drilldown opens details for the selected exact process instance",
      groupedInstanceDetails?.querySelector(".inspector-title")?.textContent === "browser.exe" &&
      [...groupedInstanceDetails.querySelectorAll("dt")].some((label) =>
        label.textContent === "PID" && label.nextElementSibling?.querySelector("span")?.textContent === "2002"), JSON.stringify({
          title: groupedInstanceDetails?.querySelector(".inspector-title")?.textContent,
          fields: [...(groupedInstanceDetails?.querySelectorAll("dt") || [])].map((label) => [label.textContent, label.nextElementSibling?.textContent]),
          group: groupDialog?.textContent,
        }));
    groupedInstanceDetails?.querySelector('[aria-label="Close"]')?.click();
    host._procDestroy();
    host.style.removeProperty("width");
    host.replaceChildren();

    const tinyProcesses = Array.from({ length: 60 }, (_, index) => ({
      pid: 1000 + index, instanceId: `1000:${index}:1000`,
      name: `tiny-${index}.exe`, ppid: 4, cpuPct: 0,
      memWs: index === 0 ? 1000000 : 1,
    }));
    await renderProcesses(host, createStore({
      processes: tinyProcesses, processesKnown: true, lastUpdate: new Date(),
      processView: "treemap",
    }));
    await settle();
    const tinyTileNote = host.querySelector(".treemap-note")?.textContent || "";
    check("Treemap explains omitted tiny tiles and offers complete process views",
      tinyTileNote.includes("too small to activate") && tinyTileNote.includes("Tree or Table") &&
      Boolean(host.querySelector("#tab-tree")) && Boolean(host.querySelector("#tab-table")));
    host._procDestroy();
    host.replaceChildren();

    host.style.width = "1080px";
    const remainderProcesses = Array.from({ length: 55 }, (_, index) => ({
      pid: 3000 + index, instanceId: `3000:1:${3000 + index}`,
      name: `worker-${index}.exe`, path: `C:\\Apps\\worker-${index}.exe`,
      ppid: 4, cpuPct: 0.1, memWs: 1000000,
    }));
    await renderProcesses(host, createStore({
      processes: remainderProcesses, processesKnown: true, lastUpdate: new Date(),
      processView: "treemap",
    }));
    await settle();
    const remainderTile = host.querySelector('#panel-treemap .treemap-tile[aria-label^="7 additional processes"]');
    remainderTile?.click();
    await settle();
    const remainderDialog = document.querySelector(".process-group-dialog");
    check("Treemap remainder tile opens its exact process list instead of a dead-end button",
      remainderDialog?.querySelector(".dialog-title")?.textContent === "Additional process instances" &&
      remainderDialog.querySelectorAll(".process-group-instance").length === 7);
    remainderDialog?.querySelector(".process-group-instance")?.click();
    await settle();
    const remainderDetails = document.querySelector('[data-details-row="proc"]');
    check("Remainder drilldown opens an exact process instance",
      remainderDetails?.querySelector(".dialog-title")?.textContent.startsWith("worker-") &&
      remainderDetails?.querySelector("dt")?.nextElementSibling?.textContent !== "");
    remainderDetails?.querySelector('[aria-label="Close"]')?.click();
    host._procDestroy();
    host.style.removeProperty("width");
    host.replaceChildren();

    await renderProcesses(host, createStore({
      processes: [
        { pid: 2001, instanceId: "2001:1:1", name: "measured.exe", ppid: 4, cpuPct: 1, memWs: 4096 },
        { pid: 2002, instanceId: "2002:1:2", name: "zero.exe", ppid: 4, cpuPct: 0, memWs: 0 },
        { pid: 2003, instanceId: "2003:1:3", name: "unknown.exe", ppid: 4, cpuPct: null, memWs: null },
      ],
      processesKnown: true, lastUpdate: new Date(), processView: "treemap",
    }));
    await settle();
    const metricNote = host.querySelector(".treemap-note")?.textContent || "";
    check("Treemap distinguishes known zero values from unavailable metrics",
      metricNote.includes("1 process reported zero working set") &&
      metricNote.includes("1 process had no readable working set") &&
      !host.querySelector('.treemap-tile[aria-label*="could not be read"]'));
    host._procDestroy();
    host.replaceChildren();

    const state = createStore({ connections: [], paused: false });
    let calls = 0;
    let release;
    const sourcePaths = {
      connections: "/api/connections",
      metrics: "/api/metrics/now",
      capabilities: "/api/capabilities",
      processes: "/api/processes?sort=cpu&limit=2000",
      networkSummary: "/api/network/summary",
      geoSummary: "/api/geo/summary",
      systemInfo: "/api/system/info",
    };
    const validPayloads = {
      connections: { connections: [{ id: 1 }] },
      metrics: { _timestamp: 1, facts: {}, "sys.uptimeSeconds": 42 },
      capabilities: { elevated: false, pdh: false, perCore: false },
      processes: { processes: [{ pid: 20 }], known: true, total: 1 },
      networkSummary: {
        total: 0, byState: {}, byProto: {}, byFamily: {}, byProcess: {},
        listeners: { loopback: 0, lan: 0, wildcard: 0 }, snapshotKnown: true,
      },
      geoSummary: {
        countries: {}, asns: {}, local: 0, unknown: 0,
        geoIpConfigured: false, snapshotKnown: true,
      },
      systemInfo: { hostname: "fixture", uptime: "0d 0h 0m", os: {}, cpu: {}, memory: null },
    };
    const apiFor = (overrides = {}) => ({ get: async (path) => {
      const name = Object.keys(sourcePaths).find((key) => sourcePaths[key] === path);
      if (!name) throw new Error(`Unexpected refresh source: ${path}`);
      const override = overrides[name];
      if (override instanceof Error) throw override;
      if (Object.prototype.hasOwnProperty.call(overrides, name)) return override;
      return validPayloads[name];
    } });
    const response = (path) => {
      const name = Object.keys(sourcePaths).find((key) => sourcePaths[key] === path);
      return validPayloads[name];
    };
    const pending = new Promise((done) => { release = done; });
    const refresh = createSnapshotRefresh({ store: state, api: { get: async (path) => { calls++; await pending; return response(path); } } });
    const first = refresh.refresh();
    const second = refresh.refresh();
    check("Concurrent refresh requests coalesce", calls === 7);
    state.set({ paused: true });
    refresh.invalidate();
    release();
    await Promise.all([first, second]);
    check("Pause invalidates an in-flight snapshot", state.get().connections.length === 0);
    await refresh.refresh({ manual: true });
    check("Manual refresh works while held", state.get().paused && state.get().connections.length === 1);
    const generationState = createStore({ connections: [], paused: false });
    let firstGeneration = true;
    let oldGenerationCalls = 0;
    let releaseOldGeneration;
    const oldGenerationGate = new Promise((done) => { releaseOldGeneration = done; });
    const generationRefresh = createSnapshotRefresh({ store: generationState, api: {
      get: async (path) => {
        const old = firstGeneration;
        if (old) {
          oldGenerationCalls++;
          await oldGenerationGate;
        }
        const name = Object.keys(sourcePaths).find((key) => sourcePaths[key] === path);
        return name === "connections"
          ? { connections: [{ id: old ? "paused-generation" : "resumed-generation" }] }
          : validPayloads[name];
      },
    } });
    const oldGeneration = generationRefresh.refresh();
    generationState.set({ paused: true });
    generationRefresh.invalidate();
    generationState.set({ paused: false });
    generationRefresh.invalidate();
    const resumedGeneration = generationRefresh.refresh();
    check("Resume waits for an invalidated in-flight generation", oldGenerationCalls === 7);
    firstGeneration = false;
    releaseOldGeneration();
    await Promise.all([oldGeneration, resumedGeneration]);
    check("The resumed snapshot wins after the paused response settles",
      oldGenerationCalls === 7 && generationState.get().connections[0]?.id === "resumed-generation");
    const partial = createSnapshotRefresh({ store: state, api: apiFor({
      metrics: new Error("Metrics unavailable"),
    }) });
    await partial.refresh({ manual: true });
    check("Optional failure preserves connection updates", state.get().connections.length === 1 && state.get().status === "degraded");
    check("Optional failure has its own freshness/error state", state.get().sourceStatus.metrics.error === "Metrics unavailable" && state.get().sourceStatus.connections.updatedAt instanceof Date);

    const sourceFields = {
      metrics: "metrics", capabilities: "capabilities", processes: "processes",
      networkSummary: "networkSummary", geoSummary: "geoSummary", systemInfo: "systemInfo",
    };
    const seedStore = () => {
      const priorTimestamp = new Date("2026-01-01T00:00:00Z");
      return createStore({
        connections: [{ id: "retained" }], metrics: { marker: "retained" },
        capabilities: { marker: "retained" }, processes: [{ pid: 9 }],
        networkSummary: { marker: "retained" }, geoSummary: { marker: "retained" },
        systemInfo: { marker: "retained" }, processCount: 1, sysUptime: 9,
        lastUpdate: priorTimestamp, status: "online", paused: true,
        sourceStatus: Object.fromEntries(Object.keys(sourcePaths).map((name) =>
          [name, { updatedAt: priorTimestamp, error: null }])),
      });
    };
    for (const [name, field] of Object.entries(sourceFields)) {
      const isolatedState = seedStore();
      const priorValue = isolatedState.get()[field];
      const priorTimestamp = isolatedState.get().sourceStatus[name].updatedAt;
      const isolatedRefresh = createSnapshotRefresh({
        store: isolatedState, api: apiFor({ [name]: new Error(`${name} unavailable`) }),
      });
      await isolatedRefresh.refresh({ manual: true });
      check(`Optional ${name} failure preserves its last valid value`,
        isolatedState.get()[field] === priorValue &&
        isolatedState.get().sourceStatus[name].updatedAt === priorTimestamp &&
        isolatedState.get().sourceStatus[name].error === `${name} unavailable`);
      check(`Optional ${name} failure leaves connections fresh and usable`,
        isolatedState.get().connections[0]?.id === 1 &&
        isolatedState.get().sourceStatus.connections.error === null &&
        isolatedState.get().status === "degraded");
    }

    for (const name of Object.keys(sourceFields)) {
      const isolatedState = seedStore();
      const priorValue = isolatedState.get()[sourceFields[name]];
      const isolatedRefresh = createSnapshotRefresh({
        store: isolatedState, api: apiFor({ [name]: {} }),
      });
      await isolatedRefresh.refresh({ manual: true });
      check(`Malformed ${name} payload is rejected without losing its snapshot`,
        isolatedState.get()[sourceFields[name]] === priorValue &&
        isolatedState.get().sourceStatus[name].error?.startsWith("Invalid "));
    }

    const connectionFailureState = seedStore();
    const oldConnections = connectionFailureState.get().connections;
    const oldConnectionSample = connectionFailureState.get().lastUpdate;
    const connectionFailure = createSnapshotRefresh({
      store: connectionFailureState,
      api: apiFor({ connections: new Error("Connection snapshot unavailable") }),
    });
    let connectionRejected = false;
    try { await connectionFailure.refresh({ manual: true }); }
    catch (error) { connectionRejected = error.message === "Connection snapshot unavailable"; }
    check("Connection source failure rejects for poller backoff and preserves its snapshot",
      connectionRejected && connectionFailureState.get().connections === oldConnections &&
      connectionFailureState.get().lastUpdate === oldConnectionSample &&
      connectionFailureState.get().status === "error");

    const malformedConnectionState = seedStore();
    const malformedConnectionRefresh = createSnapshotRefresh({
      store: malformedConnectionState, api: apiFor({ connections: { rows: [] } }),
    });
    let malformedConnectionRejected = false;
    try { await malformedConnectionRefresh.refresh({ manual: true }); }
    catch (error) { malformedConnectionRejected = error.message.includes("Invalid connections response"); }
    check("Malformed connection payload rejects without inventing an empty snapshot",
      malformedConnectionRejected && malformedConnectionState.get().connections[0]?.id === "retained");

    const allFailedState = seedStore();
    const allFailedRefresh = createSnapshotRefresh({
      store: allFailedState,
      api: apiFor(Object.fromEntries(Object.keys(sourcePaths).map((name) =>
        [name, new Error(`${name} unavailable`)]))),
    });
    let allFailedRejected = false;
    try { await allFailedRefresh.refresh({ manual: true }); }
    catch (error) { allFailedRejected = error.message.includes("connections unavailable"); }
    check("All-source failure retains data, marks every source and rejects",
      allFailedRejected && allFailedState.get().status === "error" &&
      allFailedState.get().connections[0]?.id === "retained" &&
      Object.keys(sourcePaths).every((name) => allFailedState.get().sourceStatus[name].error));
    const recoveryRefresh = createSnapshotRefresh({ store: allFailedState, api: apiFor() });
    await recoveryRefresh.refresh({ manual: true });
    check("A valid sample recovers all source errors", allFailedState.get().status === "online" &&
      allFailedState.get().lastError === null &&
      Object.keys(sourcePaths).every((name) => allFailedState.get().sourceStatus[name].error === null));

    const emptyState = seedStore();
    const emptyRefresh = createSnapshotRefresh({ store: emptyState, api: apiFor({
      connections: { connections: [] },
      processes: { processes: [], known: true, total: 0, ageMs: 0, sampledAtMs: 0 },
    }) });
    await emptyRefresh.refresh({ manual: true });
    check("Valid empty connection and process snapshots remain known zeros",
      emptyState.get().connections.length === 0 && emptyState.get().processes.length === 0 &&
      emptyState.get().processesKnown === true && emptyState.get().processCount === 0);
    const unknownProcessState = seedStore();
    const unknownProcessRefresh = createSnapshotRefresh({ store: unknownProcessState, api: apiFor({
      processes: { processes: [], known: false, reason: "Sampler has not produced a sample" },
    }) });
    await unknownProcessRefresh.refresh({ manual: true });
    check("Unknown process sample is not reported as a measured zero",
      unknownProcessState.get().processes.length === 0 &&
      unknownProcessState.get().processesKnown === false &&
      unknownProcessState.get().processCount === null);

    let runningCallbacks = 0;
    let maximumCallbacks = 0;
    let pollCount = 0;
    let finishFirst;
    const firstPoll = new Promise((done) => { finishFirst = done; });
    const poller = createPoller(async () => {
      pollCount++;
      runningCallbacks++;
      maximumCallbacks = Math.max(maximumCallbacks, runningCallbacks);
      if (pollCount === 1) await firstPoll;
      runningCallbacks--;
    }, 20);
    poller.start();
    await new Promise((done) => setTimeout(done, 15));
    poller.stop();
    poller.start();
    document.dispatchEvent(new Event("visibilitychange"));
    document.dispatchEvent(new Event("visibilitychange"));
    finishFirst();
    await new Promise((done) => setTimeout(done, 50));
    poller.stop();
    check("Restart and visibility changes never overlap polls", maximumCallbacks === 1 && pollCount >= 2);
    const stoppedCount = pollCount;
    await new Promise((done) => setTimeout(done, 35));
    check("Stopped pollers do not keep polling", pollCount === stoppedCount);
    poller.destroy();

    await Promise.all([
      api.updateConfig((current) => ({ ...current, preferences: { ...current.preferences, theme: "dark" } })),
      api.updateConfig((current) => ({ ...current, preferences: { ...current.preferences, units: "si" } })),
    ]);
    const saved = await api.get("/api/config");
    check("Queued preference writes merge the latest configuration", saved.preferences.theme === "dark" && saved.preferences.units === "si");
    check("Preference writes preserve unrelated bookmarks", saved.bookmarks[0].id === "keep");
    setFormatUnits("si");
    check("SI preference reaches byte formatting", fmtBytes(1000000).includes("MB"));
    setFormatUnits("iec");
    check("IEC preference reaches byte formatting", fmtBytes(1048576).includes("MiB"));
    const settingsStore = createStore({});
    const permissionDescriptor = Object.getOwnPropertyDescriptor(Notification, "permission");
    const permissionQueryDescriptor = Object.getOwnPropertyDescriptor(navigator.permissions, "query");
    const documentAddDescriptor = Object.getOwnPropertyDescriptor(document, "addEventListener");
    const documentRemoveDescriptor = Object.getOwnPropertyDescriptor(document, "removeEventListener");
    const addDocumentListener = document.addEventListener.bind(document);
    const removeDocumentListener = document.removeEventListener.bind(document);
    const settingsVisibilityListeners = new Set();
    Object.defineProperty(document, "addEventListener", { configurable: true, value(type, listener, options) {
      if (type === "visibilitychange") settingsVisibilityListeners.add(listener);
      return addDocumentListener(type, listener, options);
    } });
    Object.defineProperty(document, "removeEventListener", { configurable: true, value(type, listener, options) {
      if (type === "visibilitychange") settingsVisibilityListeners.delete(listener);
      return removeDocumentListener(type, listener, options);
    } });
    const permissionState = { state: "granted", onchange: null };
    window.mockNotificationPermission = "granted";
    Object.defineProperty(Notification, "permission", { configurable: true, get: () => window.mockNotificationPermission });
    Object.defineProperty(navigator.permissions, "query", { configurable: true, value: async () => permissionState });
    await api.updateConfig((current) => ({ ...current, desktopNotifications: true, preferences: { ...current.preferences, desktopNotifications: true } }));
    await renderSettings(host, settingsStore);
    for (let tries = 0; tries < 20 && !permissionState.onchange; tries++) await new Promise((done) => setTimeout(done, 5));
    window.mockNotificationPermission = "denied";
    permissionState.state = "denied";
    permissionState.onchange?.();
    await new Promise((done) => setTimeout(done, 350));
    const notificationConfig = await api.get("/api/config");
    check("Revoked browser notification permission disables and persists the Settings toggle", host.querySelector('[aria-label="Desktop notifications"]')?.checked === false && notificationConfig.preferences.desktopNotifications === false);
    const unitsControl = host.querySelector('[aria-label="Units"]');
    unitsControl.value = "iec";
    unitsControl.dispatchEvent(new Event("change"));
    host.querySelector("#settings-save").click();
    await new Promise((done) => setTimeout(done, 150));
    const afterSave = await api.get("/api/config");
    check("Saving settings does not restore defaults", afterSave.preferences.theme === "dark" && afterSave.preferences.units === "iec");
    check("Settings preserve unknown nested preference fields", afterSave.preferences.futurePreference === "keep");
    unitsControl.value = "si";
    unitsControl.dispatchEvent(new Event("change"));
    host._settingsDestroy();
    check("Disposing Settings removes permission and visibility listeners",
      permissionState.onchange === null && settingsVisibilityListeners.size === 0,
      `permission=${permissionState.onchange === null}; visibility=${settingsVisibilityListeners.size}`);
    await new Promise((done) => setTimeout(done, 150));
    const afterNavigationSave = await api.get("/api/config");
    check("Disposing Settings flushes a pending preference edit", afterNavigationSave.preferences.units === "si");
    let repeatedSettingsCleanup = true;
    for (let cycle = 0; cycle < 5; cycle++) {
      await renderSettings(host, settingsStore);
      for (let tries = 0; tries < 20 && !permissionState.onchange; tries++) await new Promise((done) => setTimeout(done, 5));
      host._settingsDestroy();
      repeatedSettingsCleanup &&= permissionState.onchange === null && settingsVisibilityListeners.size === 0;
      host.replaceChildren();
    }
    check("Repeated Settings mount and teardown leaves no permission or visibility listeners",
      repeatedSettingsCleanup, `permission=${permissionState.onchange === null}; visibility=${settingsVisibilityListeners.size}`);
    if (permissionQueryDescriptor) Object.defineProperty(navigator.permissions, "query", permissionQueryDescriptor);
    else delete navigator.permissions.query;
    if (permissionDescriptor) Object.defineProperty(Notification, "permission", permissionDescriptor);
    else delete Notification.permission;
    if (documentAddDescriptor) Object.defineProperty(document, "addEventListener", documentAddDescriptor);
    else delete document.addEventListener;
    if (documentRemoveDescriptor) Object.defineProperty(document, "removeEventListener", documentRemoveDescriptor);
    else delete document.removeEventListener;
    host.replaceChildren();
    return results;
  });
  const narrowContext = await browser.newContext({ viewport: { width: 320, height: 240 } });
  const narrowPage = await narrowContext.newPage();
  await narrowPage.goto(`http://127.0.0.1:${server.address().port}/test`);
  const narrowMenu = await narrowPage.evaluate(async () => {
    const { openContextMenu } = await import("/js/ui/contextmenu.js");
    const { createVirtualTable } = await import("/js/ui/virtualtable.js");
    const host = document.createElement("div");
    host.style.cssText = "height:160px;max-width:100%;";
    document.body.append(host);
    const table = createVirtualTable(host, {
      columns: [{ key: "name", label: "Name" }],
      height: 160,
      rowHeight: 32,
      label: "Narrow viewport test grid",
      rowKey: (row) => `row:${row.id}`,
      onRowContextMenu: (row, event, anchor) => openContextMenu(
        Array.from({ length: 12 }, (_, index) => ({ label: `Action ${index + 1}`, action: () => {} })),
        { event, anchor },
      ),
    });
    table.updateRows(Array.from({ length: 40 }, (_, id) => ({ id, name: `Process ${id}` })));
    table.setActive(39);
    const anchor = document.activeElement;
    anchor.dispatchEvent(new KeyboardEvent("keydown", { key: "ContextMenu", bubbles: true, cancelable: true }));
    const menu = document.querySelector('[role="menu"]');
    const bounds = menu.getBoundingClientRect();
    const inBounds = bounds.left >= 0 && bounds.top >= 0 &&
      bounds.right <= innerWidth && bounds.bottom <= innerHeight &&
      bounds.height <= innerHeight && anchor.dataset.rowKey === "row:39" &&
      menu.contains(document.activeElement);
    menu.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }));
    const focusRestored = document.activeElement === anchor;
    table.destroy();
    host.remove();
    return { inBounds, focusRestored };
  });
  results.push({ name: "Keyboard menu on the final virtual row fits a narrow bottom-edge viewport", pass: narrowMenu.inBounds && narrowMenu.focusRestored });
  await narrowContext.close();
  const secondPage = await page.context().newPage();
  await secondPage.goto(`http://127.0.0.1:${server.address().port}/test`);
  let arrived = 0;
  let release;
  const bothWrites = new Promise((done) => { release = done; });
  const collision = async (route) => {
    if (route.request().method() === "POST" && arrived < 2) {
      arrived++;
      if (arrived === 2) release();
      await bothWrites;
    }
    await route.continue();
  };
  await page.route("**/api/config", collision);
  await secondPage.route("**/api/config", collision);
  await Promise.all([
    page.evaluate(async () => {
      const { api } = await import("/js/api.js");
      await api.updateConfig((current) => ({
        ...current,
        preferences: { ...current.preferences, theme: "dark" },
        theme: "dark",
      }));
    }),
    secondPage.evaluate(async () => {
      const { api } = await import("/js/api.js");
      const script = {
        id: "cross-tab-script",
        name: "Cross-tab script",
        templateId: "CUSTOM",
        content: "show connections",
        createdAt: "2026-10-19T00:00:00.000Z",
        updatedAt: "2026-10-19T00:00:00.000Z",
      };
      await api.updateConfig((current) => ({
        ...current,
        scripts: [...(current.scripts || []).filter((item) => item.id !== script.id), script],
      }));
    }),
  ]);
  results.push({ name: "Concurrent preference and automation edits both survive cross-tab config conflict", pass: configuration.preferences.theme === "dark" && configuration.theme === "dark" && configuration.scripts.some((item) => item.id === "cross-tab-script") });
  await page.unroute("**/api/config", collision);
  await secondPage.close();
  const settingsContext = await browser.newContext();
  const settingsTabOne = await settingsContext.newPage();
  const settingsTabTwo = await settingsContext.newPage();
  const settingsUrl = `http://127.0.0.1:${server.address().port}/index.html#/settings`;
  await Promise.all([settingsTabOne.goto(settingsUrl), settingsTabTwo.goto(settingsUrl)]);
  await Promise.all([
    settingsTabOne.getByLabel("Theme", { exact: true }).waitFor(),
    settingsTabTwo.getByLabel("Theme", { exact: true }).waitFor(),
  ]);
  await settingsTabOne.getByLabel("Theme", { exact: true }).selectOption("light");
  await settingsTabOne.getByText("Saved.", { exact: true }).waitFor();
  await settingsTabTwo.waitForFunction(() => document.querySelector('[aria-label="Theme"]')?.value === "light");
  results.push({ name: "An acknowledged preference change updates the open Settings tab", pass: await settingsTabTwo.getByLabel("Theme", { exact: true }).inputValue() === "light" });
  let themeWrites = 0;
  let releaseThemeWrites;
  const themeWriteGate = new Promise((done) => { releaseThemeWrites = done; });
  const sameFieldConflict = async (route) => {
    if (route.request().method() === "POST" && themeWrites < 2) {
      themeWrites++;
      if (themeWrites === 2) releaseThemeWrites();
      await themeWriteGate;
    }
    await route.continue();
  };
  await Promise.all([
    settingsTabOne.route("**/api/config", sameFieldConflict),
    settingsTabTwo.route("**/api/config", sameFieldConflict),
  ]);
  await Promise.all([
    settingsTabOne.getByLabel("Theme", { exact: true }).selectOption("dark"),
    settingsTabTwo.getByLabel("Theme", { exact: true }).selectOption("light"),
  ]);
  await themeWriteGate;
  await Promise.all([
    settingsTabOne.waitForFunction(() => /Saved\.|Updated from another tab\./.test(document.querySelector(".settings-status")?.textContent || ""), undefined, { timeout: 10000 }),
    settingsTabTwo.waitForFunction(() => /Saved\.|Updated from another tab\./.test(document.querySelector(".settings-status")?.textContent || ""), undefined, { timeout: 10000 }),
  ]);
  await new Promise((done) => setTimeout(done, 100));
  await Promise.all([
    settingsTabOne.unroute("**/api/config", sameFieldConflict),
    settingsTabTwo.unroute("**/api/config", sameFieldConflict),
  ]);
  const acknowledgedTheme = configuration.preferences.theme;
  await Promise.all([
    settingsTabOne.waitForFunction((theme) => document.querySelector('[aria-label="Theme"]')?.value === theme, acknowledgedTheme, { timeout: 5000 }).catch(() => {}),
    settingsTabTwo.waitForFunction((theme) => document.querySelector('[aria-label="Theme"]')?.value === theme, acknowledgedTheme, { timeout: 5000 }).catch(() => {}),
  ]);
  const visibleThemes = await Promise.all([
    settingsTabOne.getByLabel("Theme", { exact: true }).inputValue(),
    settingsTabTwo.getByLabel("Theme", { exact: true }).inputValue(),
  ]);
  results.push({ name: "Same-field cross-tab conflict converges both Settings tabs to the acknowledged server value", pass: visibleThemes.every((theme) => theme === acknowledgedTheme), detail: `server=${acknowledgedTheme}; tabs=${visibleThemes.join(",")}` });
  await Promise.all([settingsTabOne.goto(`http://127.0.0.1:${server.address().port}/index.html#/network`), settingsTabTwo.goto(`http://127.0.0.1:${server.address().port}/index.html#/network`)]);
  await Promise.all([
    settingsTabOne.getByRole("tab", { name: "Connections", exact: true }).click(),
    settingsTabTwo.getByRole("tab", { name: "Connections", exact: true }).click(),
  ]);
  await Promise.all([
    settingsTabOne.locator("#panel-connections .column-layout").evaluate((details) => { details.open = true; }),
    settingsTabTwo.locator("#panel-connections .column-layout").evaluate((details) => { details.open = true; }),
  ]);
  await Promise.all([
    settingsTabOne.locator('#panel-connections [aria-label="Show Country column"]').waitFor({ state: "attached" }),
    settingsTabTwo.locator('#panel-connections [aria-label="Show Country column"]').waitFor({ state: "attached" }),
  ]);
  const countryVisibility = await settingsTabOne.locator('#panel-connections [aria-label="Show Country column"]').isChecked();
  await settingsTabOne.locator('#panel-connections [aria-label="Show Country column"]').evaluate((input) => input.click());
  await settingsTabOne.getByText("Layout saved", { exact: true }).waitFor();
  await settingsTabTwo.waitForFunction((expected) =>
    document.querySelector('#panel-connections [aria-label="Show Country column"]')?.checked === expected,
  !countryVisibility, { timeout: 5000 });
  results.push({ name: "A saved table layout synchronizes to the other open Network tab", pass: await settingsTabTwo.locator('#panel-connections [aria-label="Show Country column"]').isChecked() !== countryVisibility });
  await settingsContext.close();
  const failureChecks = await page.evaluate(async () => {
    const { api } = await import("/js/api.js");
    const originalFetch = window.fetch;
    let conflicts = 0;
    window.fetch = async (path, options) => {
      if (path === "/api/config" && options?.method === "POST") {
        conflicts++;
        return new Response('{"error":"conflict"}', { status: 412 });
      }
      return originalFetch(path, options);
    };
    let exhausted = false;
    try { await api.updateConfig((current) => ({ ...current, shouldNotSave: true })); }
    catch (error) { exhausted = error.status === 412; }
    finally { window.fetch = originalFetch; }
    await api.updateConfig((current) => ({ ...current, recoveredQueue: true }));
    const controller = new AbortController();
    const cancelled = api.get("/api/delayed", { signal: controller.signal });
    controller.abort();
    let aborted = false;
    try { await cancelled; } catch (error) { aborted = error.name === "AbortError"; }
    let timedOut = false;
    try { await api.get("/api/delayed", { timeout: 15 }); }
    catch (error) { timedOut = error.message === "Request timed out"; }
    return [
      { name: "Config conflicts stop after three attempts with an unsaved error", pass: exhausted && conflicts === 3 },
      { name: "A failed save does not poison the config queue", pass: (await api.get("/api/config")).recoveredQueue === true },
      { name: "Caller cancellation preserves AbortError", pass: aborted },
      { name: "Request timeouts remain distinct from cancellation", pass: timedOut },
    ];
  });
  results.push(...failureChecks);
  const navigationPage = await browser.newPage();
  const navigationErrors = [];
  navigationPage.on("pageerror", (error) => navigationErrors.push(error.message));
  let releaseConfig;
  const configGate = new Promise((done) => { releaseConfig = done; });
  const delayedConfig = async (route) => {
    await configGate;
    try { await route.continue(); } catch {}
  };
  await navigationPage.route("**/api/config", delayedConfig);
  await navigationPage.goto(`http://127.0.0.1:${server.address().port}/index.html#/settings`, { waitUntil: "domcontentloaded" });
  await navigationPage.getByRole("heading", { name: "Settings", exact: true }).waitFor();
  await navigationPage.evaluate(() => { window.originalRoutePage = document.getElementById("page"); location.hash = "/processes"; });
  await navigationPage.getByRole("heading", { name: "Processes", exact: true }).waitFor();
  releaseConfig();
  await navigationPage.unroute("**/api/config", delayedConfig);
  await navigationPage.waitForTimeout(150);
  results.push({ name: "A late Settings load cannot overwrite or reuse the destination route", pass: await navigationPage.evaluate(() => !window.originalRoutePage.isConnected && document.querySelector(".page-title")?.textContent === "Processes") });
  let releaseMapData;
  let mapDataRequested;
  const mapDataGate = new Promise((done) => { releaseMapData = done; });
  const observedMapData = new Promise((done) => { mapDataRequested = done; });
  let mapLibraryRequests = 0;
  const delayedMapData = async (route) => {
    mapDataRequested();
    await mapDataGate;
    try {
      await route.fulfill({
        contentType: "application/json",
        json: { type: "Topology", transform: { scale: [1, 1], translate: [0, 0] }, arcs: [], objects: {} },
      });
    } catch {}
  };
  const countMapLibrary = async (route) => {
    mapLibraryRequests++;
    await route.continue();
  };
  await navigationPage.route("**/vendor/world-atlas/countries-110m.json", delayedMapData);
  await navigationPage.route("**/vendor/maplibre/maplibre-gl.mjs", countMapLibrary);
  await navigationPage.evaluate(() => { location.hash = "/map"; });
  await navigationPage.getByRole("heading", { name: "Map", exact: true }).waitFor();
  await navigationPage.evaluate(() => { window.disposedMapPage = document.getElementById("page"); });
  await observedMapData;
  await navigationPage.evaluate(() => { location.hash = "/processes"; });
  await navigationPage.getByRole("heading", { name: "Processes", exact: true }).waitFor();
  releaseMapData();
  await navigationPage.unroute("**/vendor/world-atlas/countries-110m.json", delayedMapData);
  await navigationPage.unroute("**/vendor/maplibre/maplibre-gl.mjs", countMapLibrary);
  await navigationPage.waitForTimeout(100);
  const mapTeardown = await navigationPage.evaluate(() => ({
    detached: !window.disposedMapPage.isConnected,
    destroyCleared: window.disposedMapPage._mapDestroy === null,
    title: document.querySelector(".page-title")?.textContent,
    canvasCount: document.querySelectorAll(".maplibregl-canvas").length,
  }));
  results.push({ name: "Disposed Map aborts delayed geography loading without mounting into the next route", pass: mapTeardown.detached && mapTeardown.destroyCleared && mapTeardown.title === "Processes" && mapTeardown.canvasCount === 0 && mapLibraryRequests === 0 && navigationErrors.length === 0, detail: JSON.stringify({ ...mapTeardown, mapLibraryRequests, pageErrors: navigationErrors }) });
  let releaseFirewallInventory;
  let firewallInventoryRequested;
  const firewallInventoryGate = new Promise((done) => { releaseFirewallInventory = done; });
  const observedFirewallInventory = new Promise((done) => { firewallInventoryRequested = done; });
  const delayedFirewallInventory = async (route) => {
    firewallInventoryRequested();
    await firewallInventoryGate;
    try {
      await route.fulfill({
        contentType: "application/json",
        json: { available: true, reason: null, rules: [{ name: "Late fixture rule", ownership: "windows", enabled: true, blocking: true, direction: 2, action: 0, protocol: 6, profiles: 7 }] },
      });
    } catch {}
  };
  await navigationPage.route("**/api/firewall", delayedFirewallInventory);
  await navigationPage.evaluate(() => { location.hash = "/blocks"; });
  await navigationPage.getByRole("heading", { name: "Firewall Rules", exact: true }).waitFor();
  await observedFirewallInventory;
  await navigationPage.evaluate(() => {
    window.disposedFirewallPage = document.getElementById("page");
    window.disposedFirewallInventory = document.querySelector(".firewall-inventory");
    window.disposedFirewallTableHost = document.querySelector(".firewall-inventory-table");
    location.hash = "/processes";
  });
  await navigationPage.getByRole("heading", { name: "Processes", exact: true }).waitFor();
  releaseFirewallInventory();
  await navigationPage.unroute("**/api/firewall", delayedFirewallInventory);
  await navigationPage.waitForTimeout(100);
  const firewallTeardown = await navigationPage.evaluate(() => ({
    pageDetached: !window.disposedFirewallPage.isConnected,
    inventoryDetached: !window.disposedFirewallInventory.isConnected,
    tableHostChildren: window.disposedFirewallTableHost.childElementCount,
    title: document.querySelector(".page-title")?.textContent,
  }));
  results.push({ name: "Disposed Firewall Inventory ignores a delayed response and leaves the destination route intact", pass: firewallTeardown.pageDetached && firewallTeardown.inventoryDetached && firewallTeardown.tableHostChildren === 0 && firewallTeardown.title === "Processes" && navigationErrors.length === 0, detail: JSON.stringify({ ...firewallTeardown, pageErrors: navigationErrors }) });
  await navigationPage.evaluate(() => { location.hash = "/blocks"; });
  await navigationPage.getByRole("heading", { name: "Firewall Rules", exact: true }).waitFor();
  const firewallRule = navigationPage.locator('[data-row-key="WinTCP block: fixture"]');
  await firewallRule.waitFor();
  await firewallRule.click();
  const firewallRuleDetails = navigationPage.locator("dialog").filter({ hasText: "Firewall rule details" });
  await firewallRuleDetails.waitFor();
  await navigationPage.evaluate(() => { window.firewallDetailsBeforeNavigation = document.querySelector("dialog"); location.hash = "/processes"; });
  await navigationPage.getByRole("heading", { name: "Processes", exact: true }).waitFor();
  results.push({ name: "Leaving Firewall Rules closes its page-owned inspector", pass: await navigationPage.evaluate(() => !window.firewallDetailsBeforeNavigation.isConnected) && navigationErrors.length === 0, detail: navigationErrors.join("; ") });
  await navigationPage.evaluate(() => { location.hash = "/blocks"; });
  await navigationPage.getByRole("heading", { name: "Firewall Rules", exact: true }).waitFor();
  await navigationPage.getByRole("button", { name: "Disable WinTCP block: fixture" }).click();
  const firewallReview = navigationPage.locator("dialog").filter({ hasText: "Review firewall change" });
  await firewallReview.waitFor();
  const reviewScope = await firewallReview.locator(".dialog-content").innerText();
  results.push({ name: "Firewall action review displays the server-verified current scope rather than stale row data", pass: reviewScope.includes("Inbound") && reviewScope.includes("Allow") && reviewScope.includes("UDP") && reviewScope.includes("192.0.2.9") && reviewScope.includes("198.51.100.22") && reviewScope.includes("C:\\Verified\\service.exe") && reviewScope.includes("Dnscache") && !reviewScope.includes("203.0.113.7"), detail: reviewScope });
  await firewallReview.getByRole("button", { name: "Close", exact: true }).click();
  let releaseMapLibrary;
  let mapLibraryRequested;
  const mapLibraryGate = new Promise((done) => { releaseMapLibrary = done; });
  const observedMapLibrary = new Promise((done) => { mapLibraryRequested = done; });
  const immediateCountryData = async (route) => route.fulfill({
    contentType: "application/json",
    json: {
      type: "Topology",
      transform: { scale: [1, 1], translate: [0, 0] },
      arcs: [],
      objects: { countries: { geometries: [{ type: "Polygon", id: "US", properties: { name: "United States of America" }, arcs: [] }] } },
    },
  });
  const delayedMapLibrary = async (route) => {
    mapLibraryRequested();
    await mapLibraryGate;
    try {
      await route.fulfill({
        contentType: "text/javascript",
        body: "globalThis.mapLibraryEvaluated = true; export class Map { constructor() { globalThis.mapConstructorCalls++; } } export class Popup {} export function setWorkerUrl() {}",
      });
    } catch {}
  };
  await navigationPage.route("**/vendor/world-atlas/countries-110m.json", immediateCountryData);
  await navigationPage.route("**/vendor/maplibre/maplibre-gl.mjs", delayedMapLibrary);
  await navigationPage.evaluate(() => {
    window.mapConstructorCalls = 0;
    window.mapLibraryEvaluated = false;
    location.hash = "/map";
  });
  await navigationPage.getByRole("heading", { name: "Map", exact: true }).waitFor();
  await observedMapLibrary;
  await navigationPage.evaluate(() => { window.disposedMapImportPage = document.getElementById("page"); location.hash = "/processes"; });
  await navigationPage.getByRole("heading", { name: "Processes", exact: true }).waitFor();
  releaseMapLibrary();
  await navigationPage.unroute("**/vendor/world-atlas/countries-110m.json", immediateCountryData);
  await navigationPage.unroute("**/vendor/maplibre/maplibre-gl.mjs", delayedMapLibrary);
  await navigationPage.waitForFunction(() => window.mapLibraryEvaluated === true);
  const delayedImportTeardown = await navigationPage.evaluate(() => ({
    detached: !window.disposedMapImportPage.isConnected,
    destroyCleared: window.disposedMapImportPage._mapDestroy === null,
    title: document.querySelector(".page-title")?.textContent,
    constructors: window.mapConstructorCalls,
    canvasCount: document.querySelectorAll(".maplibregl-canvas").length,
  }));
  results.push({ name: "Late MapLibre import is ignored after route teardown", pass: delayedImportTeardown.detached && delayedImportTeardown.destroyCleared && delayedImportTeardown.title === "Processes" && delayedImportTeardown.constructors === 0 && delayedImportTeardown.canvasCount === 0 && navigationErrors.length === 0, detail: JSON.stringify({ ...delayedImportTeardown, pageErrors: navigationErrors }) });
  await navigationPage.reload({ waitUntil: "domcontentloaded" });
  await navigationPage.getByRole("heading", { name: "Processes", exact: true }).waitFor();
  const liveMapLibrary = async (route) => route.fulfill({
    contentType: "text/javascript",
    body: `
      export function setWorkerUrl() {}
      export class Popup { remove() {} }
      export class Map {
        constructor() { this.sources = {}; this.layers = {}; this.handlers = {}; window.mapStubCreated++; }
        on(type, layerOrHandler, maybeHandler) {
          const handler = typeof layerOrHandler === "function" ? layerOrHandler : maybeHandler;
          this.handlers[type] = handler;
          if (type === "load") setTimeout(handler, 0);
        }
        addSource(name) { this.sources[name] = { setData() {} }; }
        getSource(name) { return this.sources[name] || null; }
        addLayer(layer) { this.layers[layer.id] = true; }
        getLayer(name) { return this.layers[name] || null; }
        getCanvas() { return { style: {} }; }
        fitBounds() {}
        setFeatureState() {}
        setPaintProperty() {}
        getProjection() { return { type: "globe" }; }
        setProjection() {}
        remove() { window.mapStubRemoved++; }
      }
    `,
  });
  await navigationPage.route("**/vendor/world-atlas/countries-110m.json", immediateCountryData);
  await navigationPage.route("**/vendor/maplibre/maplibre-gl.mjs", liveMapLibrary);
  await navigationPage.evaluate(() => {
    const originalSetInterval = window.setInterval;
    const originalClearInterval = window.clearInterval;
    window.originalMapSetInterval = originalSetInterval;
    window.originalMapClearInterval = originalClearInterval;
    window.mapPulseHandles = new Set();
    window.mapPulseAdds = 0;
    window.mapPulseClears = 0;
    window.mapStubCreated = 0;
    window.mapStubRemoved = 0;
    window.setInterval = function (callback, delay, ...args) {
      const handle = originalSetInterval.call(this, callback, delay, ...args);
      if (delay === 180) { window.mapPulseHandles.add(handle); window.mapPulseAdds++; }
      return handle;
    };
    window.clearInterval = function (handle) {
      if (window.mapPulseHandles.delete(handle)) window.mapPulseClears++;
      return originalClearInterval.call(this, handle);
    };
    location.hash = "/map";
  });
  await navigationPage.waitForFunction(() => window.mapPulseAdds === 1);
  await navigationPage.evaluate(() => { window.liveMapPage = document.getElementById("page"); location.hash = "/processes"; });
  await navigationPage.getByRole("heading", { name: "Processes", exact: true }).waitFor();
  const mapTimerTeardown = await navigationPage.evaluate(() => {
    window.setInterval = window.originalMapSetInterval;
    window.clearInterval = window.originalMapClearInterval;
    delete window.originalMapSetInterval;
    delete window.originalMapClearInterval;
    const result = {
      detached: !window.liveMapPage.isConnected,
      destroyed: window.liveMapPage._mapDestroy === null,
      created: window.mapStubCreated,
      removed: window.mapStubRemoved,
      adds: window.mapPulseAdds,
      clears: window.mapPulseClears,
      active: window.mapPulseHandles.size,
      title: document.querySelector(".page-title")?.textContent,
    };
    delete window.mapPulseHandles;
    return result;
  });
  await navigationPage.unroute("**/vendor/world-atlas/countries-110m.json", immediateCountryData);
  await navigationPage.unroute("**/vendor/maplibre/maplibre-gl.mjs", liveMapLibrary);
  results.push({ name: "Mounted Map clears its pulse interval and engine on route teardown", pass: mapTimerTeardown.detached && mapTimerTeardown.destroyed && mapTimerTeardown.created === 1 && mapTimerTeardown.removed === 1 && mapTimerTeardown.adds === 1 && mapTimerTeardown.clears === 1 && mapTimerTeardown.active === 0 && mapTimerTeardown.title === "Processes", detail: JSON.stringify(mapTimerTeardown) });
  await navigationPage.evaluate(() => { location.hash = "/settings"; });
  await navigationPage.getByLabel("GeoIP database path", { exact: true }).waitFor();
  let releaseUpload;
  let uploadStarted;
  const uploadGate = new Promise((done) => { releaseUpload = done; });
  const observedUpload = new Promise((done) => { uploadStarted = done; });
  await navigationPage.route("**/api/geoip/upload", async (route) => {
    uploadStarted();
    await uploadGate;
    try { await route.fulfill({ json: { path: "C:\\Test\\late.mmdb" } }); } catch {}
  });
  await navigationPage.locator("#geoip-file").setInputFiles({ name: "test.mmdb", mimeType: "application/octet-stream", buffer: Buffer.from("fixture") });
  await observedUpload;
  await navigationPage.evaluate(() => { location.hash = "/processes"; });
  await navigationPage.getByRole("heading", { name: "Processes", exact: true }).waitFor();
  await navigationPage.evaluate(() => { location.hash = "/settings"; });
  await navigationPage.getByLabel("GeoIP database path", { exact: true }).waitFor();
  releaseUpload();
  await navigationPage.waitForTimeout(150);
  results.push({ name: "An upload from a disposed Settings view cannot change a reopened form", pass: await navigationPage.getByLabel("GeoIP database path", { exact: true }).inputValue() !== "C:\\Test\\late.mmdb" && configuration.geoIpDbPath !== "C:\\Test\\late.mmdb" });
  await navigationPage.evaluate(() => { window.performanceDisposals = []; });
  for (let attempt = 0; attempt < 3; attempt++) {
    let releaseHistory;
    let historyStarted;
    const historyGate = new Promise((done) => { releaseHistory = done; });
    const observedHistory = new Promise((done) => { historyStarted = done; });
    const delayedHistory = async (route) => {
      historyStarted();
      await historyGate;
      try { await route.fulfill({ json: { t: [1, 2], series: {} } }); } catch {}
    };
    await navigationPage.route("**/api/metrics/history?**", delayedHistory);
    await navigationPage.evaluate(() => { location.hash = "/performance"; });
    await observedHistory;
    await navigationPage.evaluate(() => {
      window.performanceDisposals.push(document.getElementById("page")._perfState);
      location.hash = "/processes";
    });
    await navigationPage.getByRole("heading", { name: "Processes", exact: true }).waitFor();
    releaseHistory();
    await navigationPage.unroute("**/api/metrics/history?**", delayedHistory);
    await navigationPage.waitForTimeout(50);
  }
  results.push({ name: "Repeatedly disposed Performance views cannot mount late charts or overwrite the next page", pass: await navigationPage.evaluate(() => window.performanceDisposals.length === 3 && window.performanceDisposals.every((view) => view.disposed && view.charts.length === 0) && document.querySelector(".page-title")?.textContent === "Processes") });
  let releaseOverviewHistory;
  let overviewHistoryRequested;
  const overviewHistoryGate = new Promise((done) => { releaseOverviewHistory = done; });
  const observedOverviewHistory = new Promise((done) => { overviewHistoryRequested = done; });
  const delayedOverviewHistory = async (route) => {
    overviewHistoryRequested();
    await overviewHistoryGate;
    try { await route.fulfill({ contentType: "application/json", json: { samples: [] } }); } catch {}
  };
  await navigationPage.route("**/api/metrics/history?max=300", delayedOverviewHistory);
  await navigationPage.evaluate(() => { location.hash = "/"; });
  await navigationPage.getByRole("heading", { name: "Overview", exact: true }).waitFor();
  await observedOverviewHistory;
  await navigationPage.evaluate(() => { window.disposedOverviewState = document.getElementById("page")._overviewState; location.hash = "/processes"; });
  await navigationPage.getByRole("heading", { name: "Processes", exact: true }).waitFor();
  const overviewRequestWasAborted = await navigationPage.evaluate(() => window.disposedOverviewState.disposed && window.disposedOverviewState.requests.signal.aborted);
  releaseOverviewHistory();
  await navigationPage.unroute("**/api/metrics/history?max=300", delayedOverviewHistory);
  await navigationPage.waitForTimeout(100);
  results.push({ name: "Disposed Overview aborts delayed chart history and preserves the destination route", pass: overviewRequestWasAborted && await navigationPage.evaluate(() => document.querySelector(".page-title")?.textContent === "Processes") && navigationErrors.length === 0, detail: navigationErrors.join("; ") });
  let releaseConfigAck;
  let configSaveStarted;
  let configSaveWritten;
  const configAckGate = new Promise((done) => { releaseConfigAck = done; });
  const observedConfigSave = new Promise((done) => { configSaveStarted = done; });
  const completedConfigWrite = new Promise((done) => { configSaveWritten = done; });
  const delayedConfigAck = async (route) => {
    if (route.request().method() !== "POST") {
      await route.continue();
      return;
    }
    configSaveStarted();
    const response = await route.fetch();
    configSaveWritten();
    await configAckGate;
    try { await route.fulfill({ response }); } catch {}
  };
  await navigationPage.route("**/api/config", delayedConfigAck);
  await navigationPage.evaluate(() => { location.hash = "/settings"; });
  const navigationUnits = navigationPage.getByLabel("Units", { exact: true });
  await navigationUnits.waitFor();
  await navigationUnits.selectOption("si");
  await observedConfigSave;
  await completedConfigWrite;
  await navigationPage.evaluate(() => { window.savingSettingsPage = document.getElementById("page"); location.hash = "/processes"; });
  await navigationPage.getByRole("heading", { name: "Processes", exact: true }).waitFor();
  releaseConfigAck();
  await navigationPage.unroute("**/api/config", delayedConfigAck);
  await navigationPage.waitForTimeout(100);
  results.push({ name: "A delayed Settings save acknowledgement cannot overwrite the destination route", pass: await navigationPage.evaluate(() => !window.savingSettingsPage.isConnected && document.querySelector(".page-title")?.textContent === "Processes") && configuration.preferences.units === "si" });
  const expiredSessionWrite = async (route) => {
    if (route.request().method() === "POST") {
      await route.fulfill({ status: 403, contentType: "application/json", body: JSON.stringify({ error: "mutation authorization failed" }) });
    } else {
      await route.continue();
    }
  };
  await navigationPage.route("**/api/config", expiredSessionWrite);
  await navigationPage.evaluate(() => { location.hash = "/settings"; });
  const expiredSessionUnits = navigationPage.getByLabel("Units", { exact: true });
  await expiredSessionUnits.waitFor();
  await expiredSessionUnits.selectOption(await expiredSessionUnits.inputValue() === "si" ? "iec" : "si");
  await navigationPage.getByRole("button", { name: "Reload dashboard", exact: true }).waitFor();
  const sessionExpiredCopy = navigationPage.getByText("Your dashboard session expired. Pending changes were not saved; reload to reconnect.", { exact: true });
  const reloadDocument = navigationPage.waitForNavigation({ waitUntil: "domcontentloaded" });
  await navigationPage.getByRole("button", { name: "Reload dashboard", exact: true }).click();
  await reloadDocument;
  await navigationPage.getByRole("heading", { name: "Settings", exact: true }).waitFor();
  results.push({ name: "Expired session explains unsaved changes and reloads the dashboard", pass: !(await sessionExpiredCopy.count()) && await navigationPage.getByRole("heading", { name: "Settings", exact: true }).count() === 1 });
  await navigationPage.evaluate(() => { location.hash = "/processes"; });
  await navigationPage.getByRole("heading", { name: "Processes", exact: true }).waitFor();
  await navigationPage.unroute("**/api/config", expiredSessionWrite);
  const recoveryContext = await browser.newContext();
  const recoveryTabOne = await recoveryContext.newPage();
  const recoveryTabTwo = await recoveryContext.newPage();
  const recoveryErrors = [];
  recoveryTabOne.on("pageerror", (error) => recoveryErrors.push(error.message));
  recoveryTabTwo.on("pageerror", (error) => recoveryErrors.push(error.message));
  await recoveryTabOne.route("**/api/config", expiredSessionWrite);
  await recoveryTabTwo.route("**/api/config", expiredSessionWrite);
  const recoveryUrl = `http://127.0.0.1:${server.address().port}/index.html#/settings`;
  await Promise.all([
    recoveryTabOne.goto(recoveryUrl, { waitUntil: "domcontentloaded" }),
    recoveryTabTwo.goto(recoveryUrl, { waitUntil: "domcontentloaded" }),
  ]);
  await Promise.all([
    recoveryTabOne.getByLabel("Units", { exact: true }).waitFor(),
    recoveryTabTwo.getByLabel("Units", { exact: true }).waitFor(),
  ]);
  const recoveryUnitsOne = recoveryTabOne.getByLabel("Units", { exact: true });
  const recoveryUnitsTwo = recoveryTabTwo.getByLabel("Units", { exact: true });
  await Promise.all([
    recoveryUnitsOne.selectOption(await recoveryUnitsOne.inputValue() === "si" ? "iec" : "si"),
    recoveryUnitsTwo.selectOption(await recoveryUnitsTwo.inputValue() === "si" ? "iec" : "si"),
  ]);
  await Promise.all([
    recoveryTabOne.getByRole("button", { name: "Reload dashboard", exact: true }).waitFor(),
    recoveryTabTwo.getByRole("button", { name: "Reload dashboard", exact: true }).waitFor(),
  ]);
  const reloadTabOne = recoveryTabOne.waitForNavigation({ waitUntil: "domcontentloaded" });
  const reloadTabTwo = recoveryTabTwo.waitForNavigation({ waitUntil: "domcontentloaded" });
  await Promise.all([
    recoveryTabOne.getByRole("button", { name: "Reload dashboard", exact: true }).click(),
    recoveryTabTwo.getByRole("button", { name: "Reload dashboard", exact: true }).click(),
  ]);
  await Promise.all([reloadTabOne, reloadTabTwo]);
  await Promise.all([
    recoveryTabOne.getByRole("heading", { name: "Settings", exact: true }).waitFor(),
    recoveryTabTwo.getByRole("heading", { name: "Settings", exact: true }).waitFor(),
  ]);
  results.push({ name: "Each open tab independently recovers from an expired session", pass: await recoveryTabOne.getByRole("button", { name: "Reload dashboard", exact: true }).count() === 0 && await recoveryTabTwo.getByRole("button", { name: "Reload dashboard", exact: true }).count() === 0 && recoveryErrors.length === 0 });
  await recoveryContext.close();
  let releaseAutomationConfig;
  let automationConfigStarted;
  const automationConfigGate = new Promise((done) => { releaseAutomationConfig = done; });
  const observedAutomationConfig = new Promise((done) => { automationConfigStarted = done; });
  const delayedAutomationConfig = async (route) => {
    automationConfigStarted();
    await automationConfigGate;
    try { await route.continue(); } catch {}
  };
  await navigationPage.route("**/api/config", delayedAutomationConfig);
  await navigationPage.evaluate(() => { location.hash = "/automations"; });
  await navigationPage.getByRole("heading", { name: "Automations", exact: true }).waitFor();
  await navigationPage.getByRole("tab", { name: "Scripts", exact: true }).click();
  await observedAutomationConfig;
  await navigationPage.evaluate(() => { window.previousAutomation = document.getElementById("page"); location.hash = "/processes"; });
  await navigationPage.getByRole("heading", { name: "Processes", exact: true }).waitFor();
  releaseAutomationConfig();
  await navigationPage.unroute("**/api/config", delayedAutomationConfig);
  await navigationPage.waitForTimeout(100);
  results.push({ name: "Disposed Automations render stops after its pending initial tab", pass: await navigationPage.evaluate(() => !window.previousAutomation.isConnected && document.querySelector(".page-title")?.textContent === "Processes") });
  await navigationPage.evaluate(() => { window.automationMounts = []; });
  let automationCyclesValid = true;
  for (let attempt = 0; attempt < 3; attempt++) {
    await navigationPage.evaluate(() => { location.hash = "/automations"; });
    await navigationPage.getByRole("heading", { name: "Automations", exact: true }).waitFor();
    await navigationPage.evaluate(() => { window.automationMounts.push(document.getElementById("page")); });
    for (const tabName of ["Templates", "Scripts", "Events & audit", "Scripts", "Templates"]) {
      await navigationPage.getByRole("tab", { name: tabName, exact: true }).click();
      const tabIsCurrent = await navigationPage.getByRole("tab", { name: tabName, exact: true }).getAttribute("aria-selected");
      await navigationPage.waitForFunction(() => {
        const panel = document.querySelector('[role="tabpanel"]:not([hidden])');
        return panel?.childElementCount > 0;
      });
      const visiblePanelHasContent = await navigationPage.locator('[role="tabpanel"]:not([hidden])').evaluate((panel) => panel.childElementCount > 0);
      automationCyclesValid &&= tabIsCurrent === "true" && visiblePanelHasContent;
    }
    await navigationPage.evaluate(() => { location.hash = "/processes"; });
    await navigationPage.getByRole("heading", { name: "Processes", exact: true }).waitFor();
    automationCyclesValid &&= await navigationPage.evaluate(() => !window.automationMounts.at(-1).isConnected);
  }
  results.push({ name: "Repeated Automation tab switching and route teardown reopen cleanly", pass: automationCyclesValid && await navigationPage.evaluate(() => window.automationMounts.length === 3 && window.automationMounts.every((root) => !root.isConnected)) });
  results.push({ name: "Delayed navigation produces no uncaught page errors", pass: navigationErrors.length === 0, detail: navigationErrors.join("; ") });
  const pathlessProcessRow = navigationPage.locator('[data-row-key="3:1:2"]');
  await pathlessProcessRow.getByRole("button", { name: "Process actions", exact: true }).click();
  const pathlessApplicationAction = navigationPage.getByRole("menuitem", { name: /Block this executable/ });
  results.push({ name: "Processes without a readable full image path cannot create application rules", pass: await pathlessApplicationAction.getAttribute("aria-disabled") === "true" && await pathlessApplicationAction.getAttribute("title") === "A readable full executable path is required" });
  await navigationPage.keyboard.press("Escape");
  const processRow = navigationPage.locator('[data-row-key="20:1:2"]');
  await processRow.getByRole("button", { name: "Process actions", exact: true }).click();
  results.push({ name: "Process menus offer executable scope without choosing an arbitrary peer", pass: await navigationPage.getByRole("menuitem", { name: "Copy PID", exact: true }).count() === 1 && await navigationPage.getByRole("menuitem", { name: "Block this executable", exact: true }).isEnabled() && await navigationPage.getByTitle(/^Block /).count() === 0 });
  await navigationPage.getByRole("menuitem", { name: "Block this executable", exact: true }).click();
  await navigationPage.getByRole("heading", { name: "Review application rule", exact: true }).waitFor();
  await navigationPage.getByText("Preparing the application firewall preview…", { exact: true }).waitFor({ state: "detached" });
  const appRuleReview = navigationPage.locator(".action-preview-dialog");
  const appRuleState = await navigationPage.evaluate(async () => await (await fetch("/test-state")).json());
  const appPreview = appRuleState.blockActionRequests.filter((item) => item.path === "/api/block/preview").at(-1)?.body;
  const closeExecutionsBeforeAppRule = appRuleState.closeActionRequests.filter((item) => item.path === "/api/connections/action/execute").length;
  const appScopeDisclosure = await appRuleReview.getByText("Every current and future process using this executable path", { exact: true }).count() === 1;
  const appPathDisclosure = await appRuleReview.getByText("C:\\Apps\\beta.exe", { exact: true }).count() === 1;
  results.push({ name: "Application rule review preserves exact process identity and states all-instances scope", pass: appScopeDisclosure && appPathDisclosure && appPreview?.scope === "application" && appPreview.process === "C:\\Apps\\beta.exe" && appPreview.pid === "20" && appPreview.instanceId === "20:1:2" && appPreview.address === undefined && appPreview.port === undefined });
  await appRuleReview.getByRole("button", { name: "Create application rule", exact: true }).click();
  await navigationPage.getByText("Application block rule already existed. Existing connections remain open.", { exact: true }).waitFor();
  const appRuleFinished = await navigationPage.evaluate(async () => await (await fetch("/test-state")).json());
  results.push({ name: "Application rule uses a separate create result and never closes a connection", pass: appRuleFinished.blockActionRequests.filter((item) => item.path === "/api/block/commit").at(-1)?.body.nonce === "b".repeat(32) && appRuleFinished.closeActionRequests.filter((item) => item.path === "/api/connections/action/execute").length === closeExecutionsBeforeAppRule });
  await appRuleReview.getByRole("button", { name: "Close", exact: true }).click();
  await processRow.getByRole("button", { name: "Process actions", exact: true }).click();
  const allowApplicationItem = navigationPage.getByRole("menuitem", { name: "Allow this executable", exact: true });
  results.push({ name: "Process menu offers a separate executable-scoped allow rule", pass: await allowApplicationItem.isEnabled() });
  await allowApplicationItem.click();
  await navigationPage.getByRole("heading", { name: "Review application allow rule", exact: true }).waitFor();
  const appAllowReview = navigationPage.locator(".action-preview-dialog");
  const appAllowState = await navigationPage.evaluate(async () => await (await fetch("/test-state")).json());
  const appAllowPreview = appAllowState.blockActionRequests.filter((item) => item.path === "/api/block/preview").at(-1)?.body;
  results.push({ name: "Allow review preserves exact application identity and discloses block-rule precedence", pass: appAllowPreview?.scope === "application-allow" && appAllowPreview.process === "C:\\Apps\\beta.exe" && appAllowPreview.pid === "20" && appAllowPreview.instanceId === "20:1:2" && await appAllowReview.getByText("a matching Windows Firewall block rule can still take precedence", { exact: false }).count() === 1 && await appAllowReview.getByRole("button", { name: "Create allow rule", exact: true }).isEnabled() });
  await appAllowReview.getByRole("button", { name: "Cancel", exact: true }).click();
  await navigationPage.waitForFunction(() => !document.querySelector(".action-preview-dialog"));
  await processRow.getByRole("button", { name: "Process actions", exact: true }).click();
  await navigationPage.getByRole("menuitem", { name: "Show this process's connections", exact: true }).click();
  await navigationPage.getByRole("heading", { name: "Network", exact: true }).waitFor();
  await navigationPage.waitForFunction(() => document.querySelector(".proc-summary")?.textContent.includes("2 of 3"));
  results.push({ name: "Process investigation opens Network with exact active connections and a removable identity chip", pass: await navigationPage.getByRole("button", { name: "Remove Process instance: 20:1:2", exact: true }).count() === 1 });
  const connectionActionButton = navigationPage.locator('[data-row-key="connection:1"]').getByRole("button", { name: "Connection actions", exact: true });
  await connectionActionButton.click();
  const applicationPeerMenuItem = navigationPage.getByRole("menuitem", { name: "Block this executable to this peer", exact: true });
  const servicePeerMenuItem = navigationPage.getByRole("menuitem", { name: "Block this service to this peer", exact: true });
  results.push({ name: "Connection actions expose app-wide, app-plus-peer and known-service scopes", pass: await navigationPage.getByRole("menuitem", { name: "Block this executable", exact: true }).isEnabled() && await applicationPeerMenuItem.isEnabled() && await servicePeerMenuItem.isEnabled() });
  await applicationPeerMenuItem.click();
  await navigationPage.getByRole("heading", { name: "Review application and peer block", exact: true }).waitFor();
  const appPeerReview = navigationPage.locator(".action-preview-dialog");
  const appPeerState = await navigationPage.evaluate(async () => await (await fetch("/test-state")).json());
  const appPeerPreview = appPeerState.blockActionRequests.filter((item) => item.path === "/api/block/preview").at(-1)?.body;
  results.push({ name: "App-plus-peer review discloses executable-wide impact and sends exact connection identity", pass: await appPeerReview.getByText("every instance of this executable, but only for this remote IP and port", { exact: false }).count() === 1 && appPeerPreview?.scope === "application-peer" && appPeerPreview.process === "C:\\Apps\\beta.exe" && appPeerPreview.pid === "20" && appPeerPreview.instanceId === "20:1:2" && appPeerPreview.idExact === "1" && appPeerPreview.processInstanceId === "20:1:2" && appPeerPreview.remote === "203.0.113.1" && appPeerPreview.rport === "443" && appPeerPreview.address === undefined });
  await appPeerReview.getByRole("button", { name: "Cancel", exact: true }).click();
  await navigationPage.waitForFunction(() => !document.querySelector(".action-preview-dialog"));
  await connectionActionButton.click();
  await servicePeerMenuItem.click();
  await navigationPage.getByRole("heading", { name: "Review service and peer block", exact: true }).waitFor();
  const servicePeerReview = navigationPage.locator(".action-preview-dialog");
  const servicePeerState = await navigationPage.evaluate(async () => await (await fetch("/test-state")).json());
  const servicePeerPreview = servicePeerState.blockActionRequests.filter((item) => item.path === "/api/block/preview").at(-1)?.body;
  results.push({ name: "Service-peer review preserves the known service, app path and exact peer", pass: await servicePeerReview.getByText("known Windows service within this executable path", { exact: false }).count() === 1 && servicePeerPreview?.scope === "service-peer" && servicePeerPreview.process === "C:\\Apps\\beta.exe" && servicePeerPreview.service === "Dnscache" && servicePeerPreview.remote === "203.0.113.1" && servicePeerPreview.rport === "443" && servicePeerPreview.idExact === "1" });
  await servicePeerReview.getByRole("button", { name: "Cancel", exact: true }).click();
  await navigationPage.waitForFunction(() => !document.querySelector(".action-preview-dialog"));
  await navigationPage.goBack();
  await navigationPage.getByRole("heading", { name: "Processes", exact: true }).waitFor();
  await navigationPage.goForward();
  await navigationPage.getByRole("heading", { name: "Network", exact: true }).waitFor();
  results.push({ name: "Back and Forward restore the scoped investigation route and predicate", pass: await navigationPage.getByRole("button", { name: "Remove Process instance: 20:1:2", exact: true }).count() === 1 && await navigationPage.getByLabel("Filter endpoints", { exact: true }).inputValue() === "" });
  await navigationPage.getByLabel("Filter endpoints", { exact: true }).fill("203.0.113.1");
  await navigationPage.waitForFunction(() => document.querySelector(".proc-summary")?.textContent.includes("1 of 3"));
  await navigationPage.evaluate(async () => {
    window.savedInvestigationChip = document.querySelector(".filter-chip");
    const { store } = await import("/js/main.js");
    const { updateNetwork } = await import("/js/pages/network.js");
    updateNetwork(document.getElementById("page"), store);
  });
  results.push({ name: "Polling preserves scoped chips and combines them with typed text", pass: await navigationPage.evaluate(() => window.savedInvestigationChip === document.querySelector(".filter-chip") && document.querySelector(".proc-summary")?.textContent.includes("1 of 3")) });
  await navigationPage.getByRole("button", { name: "Clear filters", exact: true }).click();
  await navigationPage.waitForFunction(() => document.querySelector(".proc-summary")?.textContent.includes("3 of 3"));
  results.push({ name: "Clear filters removes both structured and text predicates", pass: await navigationPage.getByLabel("Filter endpoints", { exact: true }).inputValue() === "" && await navigationPage.locator(".filter-chip").count() === 0 });
  await navigationPage.locator('[data-row-key="connection:1"]').getByRole("button", { name: "Connection actions", exact: true }).click();
  await navigationPage.getByRole("menuitem", { name: "Filter by remote port", exact: true }).click();
  await navigationPage.getByRole("button", { name: "Remove Remote port: 443", exact: true }).waitFor();
  await navigationPage.locator('[data-row-key="connection:1"]').getByRole("button", { name: "Connection actions", exact: true }).click();
  await navigationPage.getByRole("menuitem", { name: "Exclude this remote IP", exact: true }).click();
  await navigationPage.getByRole("button", { name: "Remove Exclude Remote IP: 203.0.113.1", exact: true }).waitFor();
  results.push({ name: "Remote exclusions compose with existing exact port filters", pass: await navigationPage.locator(".proc-summary").textContent().then((text) => text.includes("0 of 3")) });
  await navigationPage.getByRole("button", { name: "Clear filters", exact: true }).click();
  await navigationPage.locator('[data-row-key="connection:1"]').getByRole("button", { name: "Connection actions", exact: true }).click();
  await navigationPage.getByRole("menuitem", { name: "Find related firewall rules", exact: true }).click();
  await navigationPage.getByRole("tab", { name: "Firewall rules", exact: true }).waitFor();
  await navigationPage.getByText("WinTCP candidate fixture", { exact: true }).waitFor();
  const candidateView = await navigationPage.locator(".firewall-inventory").innerText();
  const candidateRows = await navigationPage.locator(".firewall-inventory .virtual-table-row").allInnerTexts();
  const candidateCount = await navigationPage.getByText("WinTCP candidate fixture", { exact: true }).count();
  const unrelatedCount = await navigationPage.getByText("WinTCP block: fixture", { exact: true }).count();
  const wrongProfileCount = await navigationPage.getByText("Windows wrong-profile fixture", { exact: true }).count();
  results.push({ name: "Connection drilldown filters firewall candidates by tuple, executable and active profile", pass: candidateCount === 1 && unrelatedCount === 0 && wrongProfileCount === 0 && candidateView.includes("Candidate view") && candidateView.includes("Active Windows Firewall profile: Private.") && candidateRows.length === 2 && candidateRows.some((row) => row.includes("Disabled") && row.includes("Allow") && row.includes("Application: exact")), detail: JSON.stringify({ candidateCount, unrelatedCount, wrongProfileCount, candidateRows, candidateView }) });
  await navigationPage.getByRole("button", { name: "Show all rules", exact: true }).click();
  await navigationPage.getByText("Windows managed fixture", { exact: true }).waitFor();
  results.push({ name: "Firewall candidate view can be cleared to restore full inventory", pass: await navigationPage.getByText("Windows managed fixture", { exact: true }).count() === 1 });
  await navigationPage.evaluate(() => document.dispatchEvent(new CustomEvent("wintcp:firewall-open-rule", { detail: { name: "WinTCP candidate fixture" } })));
  await navigationPage.getByRole("tab", { name: "Firewall rules", exact: true }).waitFor();
  await navigationPage.getByText("WinTCP candidate fixture", { exact: true }).waitFor();
  results.push({ name: "Exact created-rule link opens only that inventory identity", pass: await navigationPage.locator(".firewall-inventory .virtual-table-row").count() === 1 && await navigationPage.getByText("WinTCP block: fixture", { exact: true }).count() === 0 });
  await navigationPage.getByRole("button", { name: "Show all rules", exact: true }).click();
  await navigationPage.getByText("Windows managed fixture", { exact: true }).waitFor();
  await navigationPage.getByRole("button", { name: "Create rule", exact: true }).click();
  const ruleEditor = navigationPage.locator(".action-preview-dialog");
  await ruleEditor.getByLabel("Direction").selectOption("inbound");
  await ruleEditor.getByLabel("Action").selectOption("allow");
  await ruleEditor.getByLabel("Protocol").selectOption("tcp");
  await ruleEditor.getByLabel("Remote addresses").fill("198.51.100.0/24");
  await ruleEditor.getByLabel("Local addresses").fill("192.0.2.10");
  await ruleEditor.getByLabel("Local ports").fill("8443");
  await ruleEditor.getByLabel("Remote ports").fill("443,8443");
  await ruleEditor.getByLabel("Executable path").fill("C:\\Program Files\\Fixture\\service.exe");
  await ruleEditor.getByLabel("Service short name").fill("FixtureSvc");
  await ruleEditor.getByLabel("Rule label").fill("Custom review fixture");
  await ruleEditor.getByLabel("Domain").uncheck();
  await ruleEditor.getByLabel("Public").uncheck();
  await ruleEditor.getByLabel("Rule label").fill("Invalid preview fixture");
  await ruleEditor.getByRole("button", { name: "Preview rule", exact: true }).click();
  await ruleEditor.getByText("Local addresses: Use a valid local address.", { exact: true }).waitFor();
  const invalidFieldState = await ruleEditor.evaluate((element) => ({
    activeName: document.activeElement?.getAttribute("name"),
    invalid: element.querySelector('[name="localAddress"]')?.getAttribute("aria-invalid"),
  }));
  results.push({ name: "Custom rule preview focuses and identifies the server-rejected field", pass: invalidFieldState.activeName === "localAddress" && invalidFieldState.invalid === "true", detail: JSON.stringify(invalidFieldState) });
  await ruleEditor.getByLabel("Rule label").fill("Custom review fixture");
  await ruleEditor.getByRole("button", { name: "Preview rule", exact: true }).click();
  await ruleEditor.getByRole("button", { name: "Create rule", exact: true }).waitFor();
  const customRuleState = await navigationPage.evaluate(async () => await (await fetch("/test-state")).json());
  const customRulePreview = customRuleState.firewallCreateRequests.at(-1);
  results.push({ name: "Custom rule preview preserves inbound allow, exact address/port/application/service scopes and Private profile", pass: customRulePreview?.direction === "inbound" && customRulePreview.action === "allow" && customRulePreview.proto === "tcp" && customRulePreview.address === "198.51.100.0/24" && customRulePreview.localAddress === "192.0.2.10" && customRulePreview.localPorts === "8443" && customRulePreview.remotePorts === "443,8443" && customRulePreview.process === "C:\\Program Files\\Fixture\\service.exe" && customRulePreview.service === "FixtureSvc" && customRulePreview.profiles === "2" && customRulePreview.label === "Custom review fixture" });
  await ruleEditor.getByRole("button", { name: "Create rule", exact: true }).click();
  await navigationPage.waitForFunction(() => {
    const status = document.querySelector(".action-preview-dialog [role=status]")?.textContent || "";
    return status.includes("created and verified") || status.includes("failed") || status.includes("could not be verified");
  });
  const customRuleFinal = await navigationPage.evaluate(async () => await (await fetch("/test-state")).json());
  const customRuleResultText = await ruleEditor.locator("[role=status]").textContent();
  results.push({ name: "Custom rule create uses the one-time reviewed token and reports read-back", pass: customRuleFinal.firewallActionRequests.some((item) => item.path === "/api/firewall/rule/execute" && item.body.nonce === "d".repeat(32)) && customRuleResultText.includes("created and verified"), detail: JSON.stringify({ result: customRuleResultText, requests: customRuleFinal.firewallActionRequests.filter((item) => item.path === "/api/firewall/rule/execute") }) });
  await ruleEditor.getByRole("button", { name: "Close", exact: true }).click();
  await navigationPage.waitForFunction(() => !document.querySelector(".action-preview-dialog"));
  await navigationPage.waitForFunction(() => document.querySelector('.firewall-inventory > [role="status"]')?.textContent.includes("Inventory generated"));
  const firewallFilter = navigationPage.getByLabel("Filter firewall rules");
  await firewallFilter.fill("WinTCP candidate fixture");
  await navigationPage.getByText("WinTCP candidate fixture", { exact: true }).waitFor();
  const initialFirewallStatus = await navigationPage.locator('.firewall-inventory > [role="status"]').textContent();
  await navigationPage.evaluate(async () => await fetch("/test-firewall-read-failure", { method: "POST" }));
  await navigationPage.getByRole("button", { name: "Refresh rules", exact: true }).click();
  await navigationPage.waitForTimeout(500);
  const staleFirewallStatus = await navigationPage.locator('.firewall-inventory > [role="status"]').textContent();
  results.push({ name: "Firewall refresh failure preserves the last inventory and filter while disclosing its timestamp and staleness", pass: initialFirewallStatus.includes("Inventory generated") && staleFirewallStatus.includes("Refresh failed") && staleFirewallStatus.includes("current rules may be stale") && await firewallFilter.inputValue() === "WinTCP candidate fixture" && await navigationPage.getByText("WinTCP candidate fixture", { exact: true }).count() === 1, detail: JSON.stringify({ initialFirewallStatus, staleFirewallStatus }) });
  await navigationPage.evaluate(() => { window.__firewallTableBeforeRefresh = document.querySelector(".firewall-inventory .net-table"); });
  await navigationPage.getByRole("button", { name: "Refresh rules", exact: true }).click();
  await navigationPage.waitForFunction(() => document.querySelector('.firewall-inventory > [role="status"]')?.textContent.includes("Inventory generated"));
  const refreshedTablePreserved = await navigationPage.evaluate(() => window.__firewallTableBeforeRefresh === document.querySelector(".firewall-inventory .net-table"));
  results.push({ name: "Successful firewall refresh updates inventory without resetting its filter or table", pass: await firewallFilter.inputValue() === "WinTCP candidate fixture" && await navigationPage.getByText("WinTCP candidate fixture", { exact: true }).count() === 1 && refreshedTablePreserved, detail: JSON.stringify({ refreshedTablePreserved }) });
  await firewallFilter.fill("");
  await navigationPage.getByRole("tab", { name: "Listening", exact: true }).click();
  results.push({ name: "Listening endpoint table has its own configurable column layout", pass: await navigationPage.locator("#panel-listening .column-layout > summary").count() === 1 });
  await navigationPage.locator('[data-row-key="connection:2"]').click({ button: "right" });
  await navigationPage.getByRole("menuitem", { name: "Find inbound firewall rules for this listening port", exact: true }).click();
  await navigationPage.getByRole("tab", { name: "Firewall rules", exact: true }).waitFor();
  await navigationPage.getByText("Inbound listener fixture", { exact: true }).waitFor();
  const inboundCandidateRows = await navigationPage.locator(".firewall-inventory .virtual-table-row").allInnerTexts();
  results.push({ name: "Listening action opens only inbound rules matching the captured local port", pass: inboundCandidateRows.length === 1 && inboundCandidateRows[0].includes("Inbound") && inboundCandidateRows[0].includes("Local port: exact") && !inboundCandidateRows[0].includes("Outbound"), detail: JSON.stringify(inboundCandidateRows) });
  await navigationPage.getByRole("button", { name: "Show all rules", exact: true }).click();
  await navigationPage.goto(`http://127.0.0.1:${server.address().port}/index.html#/network`, { waitUntil: "domcontentloaded" });
  await navigationPage.getByRole("heading", { name: "Network", exact: true }).waitFor();
  await navigationPage.getByRole("tab", { name: "Connections", exact: true }).click();
  await navigationPage.locator('#panel-connections [data-row-key="connection:1"]').waitFor();
  const responsiveResults = [];
  for (const width of [390, 768, 1366, 1920, 1152, 960, 720]) {
    await navigationPage.setViewportSize({ width, height: 760 });
    await navigationPage.waitForTimeout(40);
    const dimensions = await navigationPage.evaluate(() => ({
      viewport: window.innerWidth,
      document: document.documentElement.scrollWidth,
      body: document.body.scrollWidth,
      overflowing: [...document.body.querySelectorAll("*")]
        .map((element) => ({
          selector: `${element.tagName.toLowerCase()}${element.id ? `#${element.id}` : ""}.${String(element.className?.baseVal || element.className || "").trim().replace(/\s+/g, ".")}`,
          right: Math.round(element.getBoundingClientRect().right),
          width: Math.round(element.getBoundingClientRect().width),
        }))
        .filter((item) => item.width && item.right > window.innerWidth + 1)
        .slice(0, 8),
    }));
    responsiveResults.push({ width, fits: dimensions.document <= dimensions.viewport && dimensions.body <= dimensions.viewport, dimensions });
  }
  results.push({ name: "Network page fits mobile, tablet, laptop, wide and zoom-equivalent viewports without page-level horizontal overflow", pass: responsiveResults.every((item) => item.fits), detail: JSON.stringify(responsiveResults) });
  await navigationPage.setViewportSize({ width: 1366, height: 540 });
  const shortHeight = await navigationPage.evaluate(() => ({
    viewportHeight: window.innerHeight,
    tableHeight: document.querySelector("#panel-connections .virtual-table")?.getBoundingClientRect().height || 0,
    headerBottom: document.querySelector(".network-page-heading")?.getBoundingClientRect().bottom || 0,
  }));
  results.push({ name: "Network table remains usable at short laptop height", pass: shortHeight.tableHeight > 180 && shortHeight.headerBottom < shortHeight.viewportHeight, detail: JSON.stringify(shortHeight) });
  await navigationPage.setViewportSize({ width: 1366, height: 760 });
  await navigationPage.emulateMedia({ reducedMotion: "reduce" });
  const reducedMotion = await navigationPage.evaluate(() => {
    const duration = getComputedStyle(document.querySelector(".sidebar-item")).transitionDuration.split(",")
      .map((value) => parseFloat(value) * (value.trim().endsWith("ms") ? 1 : 1000));
    return { preference: matchMedia("(prefers-reduced-motion: reduce)").matches,
      durations: duration, respectsPreference: duration.every((value) => value <= 0.01) };
  });
  results.push({ name: "Web UI honors reduced-motion preference across shared components", pass: reducedMotion.preference && reducedMotion.respectsPreference, detail: JSON.stringify(reducedMotion) });
  await navigationPage.emulateMedia({ reducedMotion: "no-preference" });
  await navigationPage.emulateMedia({ forcedColors: "active" });
  await navigationPage.locator("#net-filter").focus();
  const forcedColors = await navigationPage.evaluate(() => ({
    active: matchMedia("(forced-colors: active)").matches,
    surfaceBackground: getComputedStyle(document.querySelector("#panel-connections .virtual-table") || document.body).backgroundColor,
  }));
  results.push({ name: "Forced-colors mode applies a system-color table surface", pass: forcedColors.active && forcedColors.surfaceBackground !== "rgba(0, 0, 0, 0)", detail: JSON.stringify(forcedColors) });
  await navigationPage.emulateMedia({ forcedColors: "none" });
  await navigationPage.setViewportSize({ width: 390, height: 760 });
  await navigationPage.locator('#panel-connections [data-row-key="connection:1"]').click();
  const mobileInspector = navigationPage.locator(".inspector-dialog");
  await mobileInspector.waitFor();
  const mobileBounds = await mobileInspector.boundingBox();
  results.push({ name: "Narrow connection inspection uses an in-bounds modal presentation", pass: await mobileInspector.evaluate((node) => node.classList.contains("is-modal")) && Boolean(mobileBounds && mobileBounds.x >= 0 && mobileBounds.x + mobileBounds.width <= 390 && mobileBounds.y >= 0), detail: JSON.stringify(mobileBounds) });
  await mobileInspector.locator(".inspector-width").evaluate((input) => {
    input.value = "352";
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await navigationPage.setViewportSize({ width: 1366, height: 760 });
  await navigationPage.waitForFunction(() => document.querySelector(".inspector-dialog")?.classList.contains("is-docked"));
  results.push({ name: "Wide connection inspection switches to a docked side panel", pass: await mobileInspector.evaluate((node) => node.classList.contains("is-docked")) });
  await mobileInspector.getByRole("button", { name: "Close inspector" }).click();
  await navigationPage.locator('#panel-connections [data-row-key="connection:1"]').click();
  const reopenedInspectorWidth = await navigationPage.locator(".inspector-width").inputValue();
  results.push({ name: "Inspector width preference persists for its view", pass: reopenedInspectorWidth === "352", detail: reopenedInspectorWidth });
  await navigationPage.locator(".inspector-dialog").getByRole("button", { name: "Close inspector" }).click();
  await navigationPage.close();
  await page.evaluate(async () => {
    const { createVirtualTable } = await import("/js/ui/virtualtable.js");
    window.workflowActions = { rows: 0, buttons: 0 };
    window.workflowTable = createVirtualTable(document.getElementById("checks"), {
      columns: [{ key: "action", label: "Action", renderCell: () => {
        const button = document.createElement("button");
        button.textContent = "Row action";
        button.onclick = () => window.workflowActions.buttons++;
        return button;
      } }],
      onRowClick: () => window.workflowActions.rows++,
    });
    window.workflowTable.updateRows([{ id: 1 }]);
  });
  await page.getByRole("button", { name: "Row action" }).press("Enter");
  await page.getByRole("button", { name: "Row action" }).press("Space");
  const actions = await page.evaluate(() => window.workflowActions);
  results.push({ name: "Embedded action buttons keep Enter and Space behavior", pass: actions.buttons === 2 && actions.rows === 0, detail: JSON.stringify(actions) });
  await page.evaluate(() => window.workflowTable.destroy());
  for (const result of results) {
    console.log(`[${result.pass ? " ok " : "FAIL"}] ${result.name}${result.pass || !result.detail ? "" : `: ${result.detail}`}`);
    checks++;
  }
  assert.equal(errors.length, 0, errors.join("\n"));
  assert.equal(results.filter((result) => !result.pass).length, 0, "Workflow regressions failed");
  console.log(`${checks} workflow checks passed.`);
} finally {
  await browser.close();
  await new Promise((done) => server.close(done));
}
