// pages/network.js - Network page
//
// Four real views over one connection snapshot: every endpoint, only the
// listening sockets classified by exposure, the blocked-peer inventory, and a
// process-to-country flow summary.

import { h, clear } from "../h.js";
import { createVirtualTable } from "../ui/virtualtable.js";
import { createTabs } from "../ui/tabs.js";
import { emptyState, card, cardHeader, cardTitle, cardContent, cardFooter } from "../ui/card.js";
import { badge } from "../ui/badge.js";
import { dialog, openDialog, closeDialog } from "../ui/dialog.js";
import { api } from "../api.js";
import { fmtInt, fmtBytes } from "../format.js";
import { icon } from "../icons.js";

const UNAVAILABLE = "\u2014";
const SORT_ASC = "asc";
const SORT_DESC = "desc";

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

const num = (v) => (typeof v === "number" && Number.isFinite(v) ? v : null);

function sortByName(a, b, dir, keyFn) {
  const an = String(keyFn(a) || "").toLowerCase();
  const bn = String(keyFn(b) || "").toLowerCase();
  const c = an < bn ? -1 : an > bn ? 1 : 0;
  return (dir === SORT_ASC ? c : -c) || endpointTieBreak(a, b);
}

function endpointTieBreak(a, b) {
  const ak = `${a.pid || 0}|${a.proto || ""}|${a.local || a.localAddress || ""}|${a.remote || a.remoteAddress || ""}|${a.state || ""}`;
  const bk = `${b.pid || 0}|${b.proto || ""}|${b.local || b.localAddress || ""}|${b.remote || b.remoteAddress || ""}|${b.state || ""}`;
  return ak.localeCompare(bk, undefined, { sensitivity: "base" });
}

function sortByNum(a, b, dir, keyFn) {
  const av = keyFn(a), bv = keyFn(b);
  if (av === null && bv === null) return endpointTieBreak(a, b);
  if (av === null) return 1;
  if (bv === null) return -1;
  const c = av - bv;
  return (dir === SORT_ASC ? c : -c) || endpointTieBreak(a, b);
}

const connComparators = {
  process: (a, b, dir) => sortByName(a, b, dir, (r) => r.process || r.processName || ""),
  pid: (a, b, dir) => sortByNum(a, b, dir, (r) => (typeof r.pid === "number" ? r.pid : null)),
  proto: (a, b, dir) => sortByName(a, b, dir, (r) => r.proto || ""),
  local: (a, b, dir) => sortByName(a, b, dir, (r) => (r.local || r.localAddress || "")),
  remote: (a, b, dir) => sortByName(a, b, dir, (r) => (r.remote || r.remoteAddress || "")),
  state: (a, b, dir) => sortByName(a, b, dir, (r) => r.state || ""),
  country: (a, b, dir) => sortByName(a, b, dir, (r) => r.country || ""),
  exposure: (a, b, dir) => sortByName(a, b, dir, (r) => exposureOf(r).label),
  port: (a, b, dir) => sortByNum(a, b, dir, (r) => {
    const p = String(r.local || r.localAddress || "");
    const i = p.lastIndexOf(":");
    const v = i >= 0 ? parseInt(p.slice(i + 1), 10) : null;
    return Number.isNaN(v) ? null : v;
  }),
};

function defaultConnSort(rows) {
  return rows.slice().sort((a, b) => {
    const pa = (a.process || a.processName || "").toLowerCase();
    const pb = (b.process || b.processName || "").toLowerCase();
    if (pa !== pb) return pa < pb ? -1 : 1;
    return (a.pid || 0) - (b.pid || 0) || endpointTieBreak(a, b);
  });
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
  filterInput.value = store.get().networkFilter || "";
  let debounce = null;
  let applyFilterNow = null;
  const onFilterInput = () => {
    store.set({ networkFilter: filterInput.value });
    if (!applyFilterNow) return;
    if (debounce !== null) clearTimeout(debounce);
    debounce = setTimeout(() => {
      debounce = null;
      applyFilterNow();
    }, 120);
  };
  filterInput.addEventListener("input", onFilterInput);
  let conns = Array.isArray(state.connections) ? state.connections.slice() : [];
  let geo = state.geoSummary || {};

  const waitForSnapshot = (nextState) => {
    if (!nextState.lastUpdate) return;
    const nextConnections = Array.isArray(nextState.connections) ? nextState.connections : [];
    geo = nextState.geoSummary || {};
    if (nextConnections.length === 0) {
      clear(layout);
      layout.append(emptyState({}, "No endpoints reported",
        "The server enumerated the connection tables and they came back empty."));
      return;
    }
    if (typeof page._netDestroy === "function") page._netDestroy();
    page._netDestroy = null;
    return renderNetwork(page, store);
  };
  const setWaitingLifecycle = () => {
    page._netUpdate = waitForSnapshot;
    page._netDestroy = () => {
      if (debounce !== null) clearTimeout(debounce);
      filterInput.removeEventListener("input", onFilterInput);
      page._netUpdate = null;
    };
  };

  if (!state.lastUpdate) {
    layout.append(emptyState({}, "Waiting for the first sample",
      "The browser polls the server every couple of seconds. This fills in on its own."));
    setWaitingLifecycle();
    return;
  }
  if (conns.length === 0) {
    layout.append(emptyState({}, "No endpoints reported",
      "The server enumerated the connection tables and they came back empty."));
    setWaitingLifecycle();
    return;
  }

  const storedSortKey = store.get().netSortKey;
  const storedSortDir = store.get().netSortDir;
  let sortKey = storedSortKey || null;
  let sortDir = storedSortDir || null;

  const applySort = (data) => {
    if (!sortKey) return defaultConnSort(data);
    const cmp = connComparators[sortKey];
    if (!cmp) return defaultConnSort(data);
    return data.slice().sort((a, b) => cmp(a, b, sortDir));
  };

  let filteredRows = conns;
  let rows = applySort(filteredRows);
  const summary = h("p", { class: "muted text-sm proc-summary" });
  const updateSummary = () => {
    summary.textContent = `${fmtInt(rows.length)} of ${fmtInt(conns.length)} endpoints` +
      (filterInput.value.trim() ? ` matching "${filterInput.value.trim()}"` : "");
  };

  const handleSort = (key, dir) => {
    sortKey = key;
    sortDir = dir;
    store.set({ netSortKey: key, netSortDir: dir });
    applyFilter();
  };

  const applyFilter = () => {
    const q = filterInput.value.trim().toLowerCase();
    filteredRows = q
      ? conns.filter((r) =>
          String(r.process || r.processName || "").toLowerCase().includes(q) ||
          String(r.local || r.localAddress || "").toLowerCase().includes(q) ||
          String(r.remote || r.remoteAddress || "").toLowerCase().includes(q) ||
          String(r.state || "").toLowerCase().includes(q))
      : conns;
    rows = applySort(filteredRows);
    updateSummary();
    if (connectionTableController) connectionTableController.updateSort(sortKey, sortDir);
    if (listeningTableController) listeningTableController.updateSort(sortKey, sortDir);
    refreshActiveView();
  };
  applyFilterNow = applyFilter;

  let connectionTableController = null;
  let listeningTableController = null;
  let activeView = store.get().networkView;
  const renderConnectionTable = () => {
    if (connectionTableController) connectionTableController.destroy();
    const view = renderConnections(rows, sortKey, sortDir, onSortRef.current, filteredRows, filterInput, store);
    connectionTableController = view._virtualTable || null;
    return view;
  };
  const renderListeningTable = () => {
    if (listeningTableController) listeningTableController.destroy();
    const view = renderListening(rows, sortKey, sortDir, onSortRef.current, store);
    listeningTableController = view._virtualTable || null;
    return view;
  };

  const tabs = createTabs({
    ariaLabel: "Network views",
    initial: store.get().networkView,
    onChange: (id) => {
      if (activeView === "connections" && id !== "connections" && connectionTableController) {
        connectionTableController.destroy();
      }
      if (activeView === "listening" && id !== "listening" && listeningTableController) {
        listeningTableController.destroy();
      }
      activeView = id;
      store.set({ networkView: id });
    },
    tabs: [
      { id: "connections", label: "Connections", render: renderConnectionTable },
      { id: "listening", label: "Listening", render: renderListeningTable },
      { id: "blocked", label: "Blocked", render: () => renderBlocked() },
      { id: "flows", label: "Flows", render: () => renderFlows(rows, geo) },
    ],
  });

  const onSortRef = { current: handleSort };

  function refreshActiveView() {
    const active = tabs.active();
    if (active === "connections" && connectionTableController) {
      const emptyMessage = filterInput.value.trim() && rows.length === 0
        ? "No endpoints matched the filter."
        : "";
      connectionTableController.updateRows(rows, emptyMessage);
    } else if (active === "listening") {
      tabs.select(active, true);
    } else if (active === "flows") {
      tabs.select(active, true);
    }
  }

  layout.append(summary, tabs.element);
  updateSummary();
  await tabs.select(tabs.active(), true);

  page._netUpdate = (nextState) => {
    if (!nextState.lastUpdate) return;
    conns = Array.isArray(nextState.connections) ? nextState.connections.slice() : [];
    geo = nextState.geoSummary || {};
    applyFilter();
  };

  page._netDestroy = () => {
    if (debounce !== null) clearTimeout(debounce);
    filterInput.removeEventListener("input", onFilterInput);
    if (connectionTableController) connectionTableController.destroy();
    if (listeningTableController) listeningTableController.destroy();
    page._netUpdate = null;
    tabs.destroy();
  };
}

export function updateNetwork(page, store) {
  if (typeof page._netUpdate === "function") {
    page._netUpdate(store.get());
    return;
  }
  return renderNetwork(page, store);
}

function renderConnections(rows, sortKey, sortDir, onSort, filteredRows, filterInput, store) {
  const host = h("div", { class: "tab-panel-body" });
  const container = h("div", { class: "net-table" });
  host.append(container);

  const emptyMsg = filterInput.value.trim().length > 0 && rows.length === 0
    ? "No endpoints matched the filter."
    : "";

  const vt = createVirtualTable(container, {
    columns: [
      { key: "process", label: "Process", width: 2, sortable: true },
      { key: "pid", label: "PID", width: 0.7, sortable: true },
      { key: "proto", label: "Proto", width: 0.8, sortable: true },
      { key: "local", label: "Local", width: 1.6, sortable: true },
      { key: "remote", label: "Remote", width: 1.6, sortable: true },
      { key: "state", label: "State", width: 1, sortable: true },
      { key: "country", label: "Country", width: 0.8, sortable: true },
      {
        key: "actions",
        label: "Actions",
        width: 1,
        sortable: false,
        renderCell: (row) => renderConnActions(host, row),
      },
    ],
    rowHeight: 34,
    height: 520,
    minWidth: "64rem",
    scrollTop: store.get().networkTableScrollTop || 0,
    onScroll: (scrollTop) => store.set({ networkTableScrollTop: scrollTop }),
    rowKey: (row) => `${row.pid || 0}|${row.proto || ""}|${row.local || row.localAddress || ""}|${row.remote || row.remoteAddress || ""}|${row.state || ""}`,
    label: "Open TCP and UDP endpoints",
    emptyMessage: emptyMsg,
    sortKey,
    sortDir,
    onSort,
    onRowClick: (row) => showConnectionDetails(row),
  });
  host._virtualTable = vt;
  vt.updateRows(rows);

  host.append(h("p", { class: "muted text-sm proc-note" },
    "Per-socket byte counters are not collected in the Web UI. The scan that " +
    "produces them can wedge the server under polling; the CLI and the desktop " +
    "GUI still show them."));
  return host;
}

function renderConnActions(host, row) {
  const wrap = h("div", { class: "row-actions", style: "display: flex; gap: 0.25rem; justify-content: flex-end;" });
  const hasRemote = row.remote && String(row.remote) !== "0.0.0.0" && String(row.remote) !== "*" && row.rport;

  wrap.append(
    h("button", {
      class: "btn btn-ghost btn-icon btn-xs",
      type: "button",
      title: "Details",
      onclick: (e) => { e.stopPropagation(); showConnectionDetails(row); },
    }, icon("info", 14)),
  );

  if (hasRemote) {
    wrap.append(
      h("button", {
        class: "btn btn-ghost btn-icon btn-xs",
        type: "button",
        title: `Block ${row.remote || ""}`,
        onclick: (e) => { e.stopPropagation(); blockPeer(row); },
      }, icon("shield", 14)),
    );
  }

  return wrap;
}

function renderListening(rows, sortKey, sortDir, onSort, store) {
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
      { key: "exposure", label: "Exposure", width: 1.2, sortable: true },
      { key: "process", label: "Process", width: 2, sortable: true },
      { key: "pid", label: "PID", width: 0.7, sortable: true },
      { key: "proto", label: "Proto", width: 0.8, sortable: true },
      { key: "local", label: "Bound address", width: 2, sortable: true },
      { key: "port", label: "Port", width: 0.7, align: "right", sortable: true },
      {
        key: "actions",
        label: "Actions",
        width: 0.8,
        sortable: false,
        renderCell: (row) => renderListeningActions(row),
      },
    ],
    rowHeight: 34,
    height: 440,
    minWidth: "58rem",
    scrollTop: store.get().networkListeningScrollTop || 0,
    onScroll: (scrollTop) => store.set({ networkListeningScrollTop: scrollTop }),
    rowKey: (row) => `${row.pid || 0}|${row.proto || ""}|${row.local || row.localAddress || ""}|${row.remote || row.remoteAddress || ""}|${row.state || ""}`,
    label: "Listening sockets by exposure",
    emptyMessage: "No listening sockets",
    sortKey,
    sortDir,
    onSort,
    onRowClick: (row) => showConnectionDetails(row),
  });
  host._virtualTable = vt;
  vt.updateRows(listening);

  host.append(counts, h("div", { class: "section-gap" }), container);
  host.append(h("p", { class: "muted text-sm proc-note" },
    "Wildcard sockets are the ones worth reading first: they accept from any " +
    "interface. A loopback socket cannot be reached from off this machine at all."));
  return host;
}

function renderListeningActions(row) {
  const wrap = h("div", { class: "row-actions", style: "display: flex; gap: 0.25rem; justify-content: flex-end;" });
  wrap.append(
    h("button", {
      class: "btn btn-ghost btn-icon btn-xs",
      type: "button",
      title: "Details",
      onclick: () => showConnectionDetails(row),
    }, icon("info", 14)),
  );
  return wrap;
}

async function renderBlocked() {
  const host = h("div", { class: "tab-panel-body" });
  let config;
  try {
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
    const addr = rule.address || rule.remote || "(any)";
    const ports = rule.remotePorts || rule.ports || "";
    list.append(h("li", { class: "rule-row" },
      h("span", { class: "rule-proto badge" }, String(rule.proto || "tcp").toUpperCase()),
      h("span", { class: "rule-address num" }, addr),
      ports ? h("span", { class: "rule-ports num" }, ports) : null,
      h("span", { class: "rule-label" }, rule.label || "(no label)"),
    ));
  }
  host.append(list);
  host.append(h("p", { class: "muted text-sm proc-note" },
    "Removing a rule needs an explicit permit, so editing happens on the " +
    "Automations page rather than from this table."));
  return host;
}

function renderFlows(rows, geo) {
  const host = h("div", { class: "tab-panel-body" });
  const configured = geo.geoIpConfigured === true;

  if (!configured) {
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

  const list = h("div", { class: "bar-list" });
  const max = entries[0].count;
  for (const entry of entries.slice(0, 24)) {
    list.append(h("div", { class: "bar-row" },
      h("span", { class: "bar-label", title: `${entry.code} (${entry.count} peers)` }, entry.code),
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

function showConnectionDetails(row) {
  const isBlocked = row.remote && String(row.remote) !== "0.0.0.0" &&
    String(row.remote) !== "*" && row.rport;

  const d = dialog({ class: "details-dialog", "data-details-row": "net" },
    h("form", { method: "dialog", class: "dialog-form" },
       h("div", { class: "dialog-header" },
         h("h2", { class: "dialog-title" }, "Connection details"),
         h("button", { type: "submit", class: "btn btn-close btn-sm", "aria-label": "Close" }, "Close"),
       ),
      h("div", { class: "dialog-content" },
        h("dl", { class: "detail-list" },
          detailEntry("Process", row.process || row.processName || UNAVAILABLE),
          detailEntry("PID", row.pid != null ? String(row.pid) : UNAVAILABLE),
          detailEntry("Service", row.service || UNAVAILABLE),
          detailEntry("Path", row.path || UNAVAILABLE),
          detailEntry("Protocol", row.proto || UNAVAILABLE),
          detailEntry("Local", row.local || row.localAddress || UNAVAILABLE),
          detailEntry("Local port", row.lport != null ? String(row.lport) : UNAVAILABLE),
          detailEntry("Remote", row.remote || row.remoteAddress || UNAVAILABLE),
          detailEntry("Remote port", row.rport != null ? String(row.rport) : UNAVAILABLE),
          detailEntry("State", row.state || UNAVAILABLE),
          detailEntry("Country", row.country || UNAVAILABLE),
          detailEntry("Duration", row.duration || UNAVAILABLE),
        ),
      ),
       h("div", { class: "dialog-footer" },
         h("button", { type: "submit", class: "btn btn-close btn-sm" }, "Close"),
         isBlocked ? h("button", {
           type: "button",
           class: "btn btn-destructive btn-sm",
           onclick: () => { closeDialog(d); blockPeer(row); },
         }, "Block remote peer") : null,
       ),
    ),
  );

  document.body.append(d);
  openDialog(d);
}

function detailEntry(label, value) {
  return [
    h("dt", {}, label),
    h("dd", {}, value),
  ];
}

async function blockPeer(row) {
  const address = row.remote || row.remoteAddress;
  const port = row.rport;
  if (!address || !port) return;

  let plan;
  try {
    plan = await api.postForm("/api/block/preview", { address, port: String(port) });
  } catch (err) {
    alert(`Could not preview block: ${err.message}`);
    return;
  }

  const confirmed = confirm(
    `Block ${address}:${port}?\n\n` +
    `This adds a firewall rule blocking outbound traffic to this remote peer on port ${port}.\n` +
    (plan.plan ? `Plan:\n${plan.plan}\n\n` : "") +
    `This action is recorded in the audit trail.`
  );
  if (!confirmed) return;

  try {
    const result = await api.postForm("/api/block/commit", { nonce: plan.nonce });
    if (result.ok) {
      alert(`Blocked ${address}:${port}. The rule is now active.`);
    } else {
      alert(`Block failed: ${result.message || "unknown error"}`);
    }
  } catch (err) {
    alert(`Block failed: ${err.message}`);
  }
}
