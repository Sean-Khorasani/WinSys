// pages/network.js - Network page
//
// Four real views over one connection snapshot: every endpoint, only the
// listening sockets classified by exposure, the blocked-peer inventory, and a
// process-to-country flow summary.
//
// This page used to ship a tab strip made of four buttons with no handlers and
// a single table underneath, so three of the four labels were decorative. It also
// used page.innerHTML = "", which is the one assignment pattern this project
// forbids everywhere else (BUG-3): the page had no untrusted content of its own,
// but a page that clears itself that way teaches the pattern.

import { h, clear } from "../h.js";
import { createVirtualTable } from "../ui/virtualtable.js";
import { createTabs } from "../ui/tabs.js";
import { emptyState, card, cardHeader, cardTitle, cardContent, cardFooter } from "../ui/card.js";
import { api } from "../api.js";
import { fmtInt, fmtBytes } from "../format.js";

const UNAVAILABLE = "\u2014";

// Exposure classification, matching the T08 semantics the native UI uses: what
// can actually reach a socket decides whether it is a finding.
function exposureOf(row) {
  const local = String(row.local || "");
  if (local === "0.0.0.0" || local === "::" || local === "*") {
    return { key: "wildcard", label: "Wildcard", hint: "binds every interface, so it is reachable from the network" };
  }
  if (local.startsWith("127.") || local === "::1") {
    return { key: "loopback", label: "Loopback", hint: "reachable only from this machine" };
  }
  return { key: "lan", label: "LAN", hint: "binds one specific address" };
}

export async function renderNetwork(page, store) {
  clear(page);
  const state = store.get();

  const layout = h("div", { class: "net-layout" });
  page.append(
    h("div", { class: "page-heading" },
      h("div", {},
        h("h1", { class: "page-title" }, "Network"),
        h("p", { class: "page-description" },
          "Live TCP and UDP endpoints, listening sockets, and blocked peers"),
      ),
      h("input", {
        class: "input page-filter",
        id: "net-filter",
        type: "search",
        placeholder: "Filter by process, address or state\u2026",
        "aria-label": "Filter endpoints",
      }),
    ),
    layout,
  );

  const filterInput = page.querySelector("#net-filter");
  const conns = Array.isArray(state.connections) ? state.connections.slice() : [];
  const geo = state.geoSummary || {};

  if (!state.lastUpdate) {
    layout.append(emptyState({}, "Waiting for the first sample",
      "The browser polls the server every couple of seconds. This fills in on its own."));
    return;
  }
  if (conns.length === 0) {
    layout.append(emptyState({}, "No endpoints reported",
      "The server enumerated the connection tables and they came back empty."));
    return;
  }

  let rows = conns;
  const summary = h("p", { class: "muted text-sm proc-summary" });
  const updateSummary = () => {
    summary.textContent = `${fmtInt(rows.length)} of ${fmtInt(conns.length)} endpoints` +
      (filterInput.value.trim() ? ` matching "${filterInput.value.trim()}"` : "");
  };

  // Store state, not local: the poll rebuilds this page and with it the strip, so
  // a local selection resets every couple of seconds and the non-default tabs
  // look broken even though the click handler works.
  const tabs = createTabs({
    ariaLabel: "Network views",
    initial: store.get().networkView,
    onChange: (id) => store.set({ networkView: id }),
    tabs: [
      { id: "connections", label: "Connections", render: () => renderConnections(rows) },
      { id: "listening", label: "Listening", render: () => renderListening(rows) },
      { id: "blocked", label: "Blocked", render: () => renderBlocked() },
      { id: "flows", label: "Flows", render: () => renderFlows(rows, geo) },
    ],
  });

  layout.append(summary, tabs.element);
  updateSummary();
  await tabs.select(tabs.active(), true);

  let debounce = null;
  filterInput.addEventListener("input", () => {
    if (debounce !== null) clearTimeout(debounce);
    debounce = setTimeout(() => {
      debounce = null;
      const q = filterInput.value.trim().toLowerCase();
      rows = q
        ? conns.filter((r) =>
            String(r.process || "").toLowerCase().includes(q) ||
            String(r.local || "").toLowerCase().includes(q) ||
            String(r.remote || "").toLowerCase().includes(q) ||
            String(r.state || "").toLowerCase().includes(q))
        : conns;
      updateSummary();
      tabs.select(tabs.active(), true);
    }, 120);
  });

  page._netDestroy = () => {
    if (debounce !== null) clearTimeout(debounce);
    tabs.destroy();
  };
}

// ---- Connections ------------------------------------------------------------

function renderConnections(rows) {
  const host = h("div", { class: "tab-panel-body" });
  const container = h("div", { class: "net-table" });
  host.append(container);

  const vt = createVirtualTable(container, {
    columns: [
      { key: "process", label: "Process", width: 2 },
      { key: "pid", label: "PID", width: 0.7 },
      { key: "proto", label: "Proto", width: 0.8 },
      { key: "local", label: "Local", width: 1.6 },
      { key: "remote", label: "Remote", width: 1.6 },
      { key: "state", label: "State", width: 1 },
    ],
    rowHeight: 34,
    height: 520,
    label: "Open TCP and UDP endpoints",
    emptyMessage: "No endpoint matched the filter.",
  });
  vt.updateRows(rows);

  // The traffic column reads "-" here and that is not a placeholder: the
  // per-socket SIO_TCP_INFO scan wedges the accept loop under polling, so the
  // Web UI deliberately does not run it. See the note in ConnectionsJson.
  host.append(h("p", { class: "muted text-sm proc-note" },
    "Per-socket byte counters are not collected in the Web UI. The scan that " +
    "produces them can wedge the server under polling; the CLI and the desktop " +
    "GUI still show them."));
  return host;
}

// ---- Listening ports --------------------------------------------------------

function renderListening(rows) {
  const host = h("div", { class: "tab-panel-body" });
  const listening = rows.filter(
    (r) => String(r.state || "").toUpperCase() === "LISTENING" ||
           String(r.proto || "").toUpperCase() === "UDP",
  );

  if (listening.length === 0) {
    return emptyState({}, "No listening sockets",
      "Nothing in this filter is bound to an address.");
  }

  const buckets = { wildcard: [], lan: [], loopback: [] };
  for (const row of listening) buckets[exposureOf(row).key].push(row);

  const counts = h("div", { class: "exposure-grid" });
  for (const [key, label, hint] of [
    ["wildcard", "Wildcard", "reachable from the network"],
    ["lan", "LAN", "bound to one address"],
    ["loopback", "Loopback", "this machine only"],
  ]) {
    counts.append(h("div", { class: "exposure-cell", title: hint },
      h("div", { class: "exposure-value num" }, fmtInt(buckets[key].length)),
      h("div", { class: "exposure-label" }, label),
    ));
  }

  const container = h("div", { class: "net-table" });
  const vt = createVirtualTable(container, {
    columns: [
      { key: "exposure", label: "Exposure", width: 1.2 },
      { key: "process", label: "Process", width: 2 },
      { key: "pid", label: "PID", width: 0.7 },
      { key: "proto", label: "Proto", width: 0.8 },
      { key: "local", label: "Bound address", width: 2 },
      { key: "port", label: "Port", width: 0.7, align: "right" },
    ],
    rowHeight: 34,
    height: 440,
    label: "Listening sockets by exposure",
    emptyMessage: "No listening socket matched the filter.",
    format: {
      exposure: (r) => exposureOf(r).label,
      port: (r) => {
        const p = String(r.local || "");
        const i = p.lastIndexOf(":");
        return i >= 0 ? p.slice(i + 1) : UNAVAILABLE;
      },
    },
  });
  vt.updateRows(listening);

  host.append(counts, h("div", { class: "section-gap" }), container);
  host.append(h("p", { class: "muted text-sm proc-note" },
    "Wildcard sockets are the ones worth reading first: they accept from any " +
    "interface. A loopback socket cannot be reached from off this machine at all."));
  return host;
}

// ---- Blocked peers ----------------------------------------------------------

async function renderBlocked() {
  const host = h("div", { class: "tab-panel-body" });
  let config;
  try {
    // The block list lives in the server-side config - the same rules
    // `wintcp block` writes. There is no /api/blocked endpoint, and inventing
    // one that read a different copy of the list would be worse than sharing
    // the source of truth.
    config = await api.get("/api/config");
  } catch (err) {
    return emptyState({}, "Block list unavailable", err.message);
  }
  const rules = Array.isArray(config.rules) ? config.rules : [];
  if (rules.length === 0) {
    return emptyState({}, "No peers are blocked",
      "The block list WinTCP shares with the CLI is empty. Rules added with " +
      "`wintcp block`, or from the Automations page, appear here.");
  }
  const list = h("ul", { class: "rule-list" });
  for (const rule of rules) {
    list.append(h("li", { class: "rule-row" },
      h("span", { class: "rule-proto badge" }, String(rule.proto || "tcp").toUpperCase()),
      h("span", { class: "rule-address num" }, rule.address || rule.remote || "(any)"),
      rule.remotePorts || rule.ports
        ? h("span", { class: "rule-ports num" }, rule.remotePorts || rule.ports)
        : null,
      h("span", { class: "rule-label" }, rule.label || "(no label)"),
    ));
  }
  host.append(list);
  host.append(h("p", { class: "muted text-sm proc-note" },
    "Removing a rule needs an explicit permit, so editing happens on the " +
    "Automations page rather than from this table."));
  return host;
}

// ---- Flows ------------------------------------------------------------------

function renderFlows(rows, geo) {
  const host = h("div", { class: "tab-panel-body" });
  const configured = geo.geoIpConfigured === true;

  if (!configured) {
    // This is a real gap, not a bug, and it is stated rather than papered over
    // with an empty chart. A graph of nothing would read as "no traffic".
    return h("div", { class: "flow-empty" },
      emptyState({}, "No GeoIP database installed",
        "Flows group remote peers by country, which needs a MaxMind GeoLite2 " +
        "database. WinTCP ships none: a .mmdb is licensed data, and fetching one " +
        "at run time would break the offline requirement."),
      h("p", { class: "muted text-sm" },
        "The local and unknown counts are still available: " +
        `${fmtInt(geo.local ?? 0)} local/private and ${fmtInt(geo.unknown ?? 0)} unresolved.`),
      h("p", { class: "muted text-sm" },
        "Set a database path in Settings once you have one; the Map page and this " +
        "tab pick it up with no restart."),
    );
  }

  const countries = geo.countries || {};
  const entries = Object.entries(countries)
    .map(([code, count]) => ({ code, count }))
    .sort((a, b) => b.count - a.count);

  if (entries.length === 0) {
    return emptyState({}, "No remote peers resolved",
      `A database is configured, but every remote address so far is local (${fmtInt(geo.local ?? 0)}) ` +
      `or unresolvable (${fmtInt(geo.unknown ?? 0)}).`);
  }

  // Ranked bar list rather than a Sankey: without a GeoIP database there is no
  // second axis to flow between, and a bar list is honest about that.
  const list = h("div", { class: "bar-list" });
  const max = entries[0].count;
  for (const entry of entries.slice(0, 24)) {
    list.append(h("div", { class: "bar-row" },
      h("span", { class: "bar-label", title: entry.code }, entry.code),
      h("span", { class: "bar-track", "aria-hidden": "true" },
        h("span", { class: "bar-fill", style: `width:${((entry.count / max) * 100).toFixed(1)}%` }),
      ),
      h("span", { class: "bar-value num" }, fmtInt(entry.count)),
    ));
  }
  host.append(card({},
    cardHeader({},
      cardTitle({}, "Remote peers by country"),
    ),
    cardContent({}, list),
    cardFooter({}, h("span", { class: "muted text-sm" },
      "Connection count, not bandwidth: per-socket byte counters are not collected here.")),
  ));
  return host;
}