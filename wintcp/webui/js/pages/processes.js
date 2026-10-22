// pages/processes.js - Processes page
//
// Three real views over the process table the server now publishes: a
// virtualised table, a parent/child tree, and a memory or CPU treemap.
//
// This page used to derive its rows from the CONNECTION store, so it showed only
// the processes that happened to own a socket - a small minority of what is
// running - and it shipped three buttons where Tree and Treemap were disabled
// and Table had no handler. Both are gone: the rows come from
// /api/processes, and every view is backed by a panel.

import { h, clear } from "../h.js";
import { createVirtualTable } from "../ui/virtualtable.js";
import { createTabs } from "../ui/tabs.js";
import { emptyState, refreshAction, card, cardHeader, cardTitle, cardContent, cardFooter } from "../ui/card.js";
import { dialog, openDialog, closeDialog } from "../ui/dialog.js";
import { api } from "../api.js";
import { renderTreemap } from "../charts/treemap.js";
import { fmtBytes, fmtInt, fmtPct, fmtNum } from "../format.js";
import { icon } from "../icons.js";
import { processKey } from "../connections.js";
import { processMenu } from "../ui/processmenu.js";
import { closeContextMenu } from "../ui/contextmenu.js";
import { investigateConnections, processConnectionFilter } from "../connectionfilters.js";
import { numberComparator, textComparator } from "../sort.js";
import { createColumnLayoutControls } from "../ui/columnlayout.js";
import { closeInspector, openInspector, updateInspector } from "../ui/inspector.js";

const UNAVAILABLE = "\u2014";
let activeProcessDetailsDialog = null;
let activeProcessBlockDialog = null;

// Reading helpers. A process whose handle cannot be opened reports null, and the
// table shows a dash. Showing 0% CPU for a process we could not measure is the
// single most misleading thing this page could do.
const num = (v) => (typeof v === "number" && Number.isFinite(v) ? v : null);
const byteValueKnown = (v) => (typeof v === "number" && Number.isFinite(v)) ||
  typeof v === "bigint" || (typeof v === "string" && /^\d+$/.test(v));
const bytes = (v) => (byteValueKnown(v) ? fmtBytes(v) : UNAVAILABLE);
const chartMetric = (v) => {
  if (typeof v === "number") return Number.isFinite(v) ? v : null;
  if (typeof v === "bigint" || (typeof v === "string" && /^\d+$/.test(v))) {
    const numeric = Number(v);
    return Number.isFinite(numeric) ? numeric : null;
  }
  return null;
};
const pct = (v) => (typeof v === "number" && Number.isFinite(v) ? fmtPct(v) : UNAVAILABLE);

function defaultSort(rows) {
  return rows.slice().sort((a, b) => {
    const av = num(a.cpuPct), bv = num(b.cpuPct);
    if (av === null && bv === null) return comparators.name(a, b, "asc");
    if (av === null) return 1;
    if (bv === null) return -1;
    if (bv - av !== 0) return bv - av;
    return comparators.name(a, b, "asc");
  });
}

const comparators = {
  name: textComparator((row) => row.name, processKey),
  pid: numberComparator((row) => row.pid, processKey),
  ppid: numberComparator((row) => row.ppid, processKey),
  cpuPct: numberComparator((row) => num(row.cpuPct), processKey),
  memWs: numberComparator((row) => row.memWs, processKey),
  memPrivate: numberComparator((row) => row.memPrivate, processKey),
  ioRead: numberComparator((row) => row.ioRead, processKey),
  ioWrite: numberComparator((row) => row.ioWrite, processKey),
  connections: numberComparator((row) => row.connections, processKey),
  listeners: numberComparator((row) => row.listeners, processKey),
};

export async function renderProcesses(page, store) {
  clear(page);

  const layout = h("div", { class: "proc-layout" });
  page.append(
    h("div", { class: "page-heading" },
      h("div", {},
        h("h1", { class: "page-title" }, "Processes"),
        h("p", { class: "page-description" },
          "Every process on this machine, with CPU, memory and I/O transfer"),
      ),
      h("div", { class: "process-filter-control" },
        h("input", {
          class: "input page-filter",
          id: "proc-filter",
          type: "search",
          placeholder: "Filter name, PID, path, or service\u2026",
          "aria-label": "Filter processes by name, PID, executable path, or service",
        }),
        h("button", {
          class: "btn btn-ghost btn-sm", id: "proc-filter-clear", type: "button",
          hidden: true, "aria-label": "Clear process filter",
          onclick: () => {
            filterInput.value = "";
            filterInput.dispatchEvent(new Event("input", { bubbles: true }));
            filterInput.focus();
          },
        }, "Clear"),
      ),
    ),
    layout,
  );

  const filterInput = page.querySelector("#proc-filter");
  const filterClear = page.querySelector("#proc-filter-clear");
  const state = store.get();
  filterInput.value = state.processFilter || "";
  filterClear.hidden = !filterInput.value.trim();
  let debounce = null;
  let applyFilterNow = null;
  const onFilterInput = () => {
    store.set({ processFilter: filterInput.value });
    filterClear.hidden = !filterInput.value.trim();
    if (!applyFilterNow) return;
    if (debounce !== null) clearTimeout(debounce);
    debounce = setTimeout(() => {
      debounce = null;
      applyFilterNow();
    }, 120);
  };
  filterInput.addEventListener("input", onFilterInput);

  const waitForSample = (nextState) => {
    if (!nextState.lastUpdate || nextState.processesKnown === false) return;
    if (Array.isArray(nextState.processes) && nextState.processes.length === 0) {
      if (!layout.querySelector(".empty-state")) {
        clear(layout);
        layout.append(emptyState({ action: refreshAction() }, "No processes reported",
          "The process source returned no rows. Refresh to sample it again."));
      }
      return;
    }
    if (!Array.isArray(nextState.processes)) return;
    if (typeof page._procDestroy === "function") page._procDestroy();
    page._procDestroy = null;
    return renderProcesses(page, store);
  };
  const setWaitingLifecycle = () => {
    page._procUpdate = waitForSample;
    page._procDestroy = () => {
      closeContextMenu();
      closeInspector({ restoreFocus: false });
      if (activeProcessDetailsDialog) closeDialog(activeProcessDetailsDialog);
      if (activeProcessBlockDialog) closeDialog(activeProcessBlockDialog);
      if (debounce !== null) clearTimeout(debounce);
      filterInput.removeEventListener("input", onFilterInput);
      page._procUpdate = null;
    };
  };

  if (!state.lastUpdate) {
    layout.append(emptyState({ action: refreshAction() }, "Waiting for the first sample",
      "The browser polls the server every couple of seconds. This fills in on its own."));
    setWaitingLifecycle();
    return;
  }
  if (state.processesKnown === false) {
    layout.append(emptyState({ action: refreshAction() }, "Process table not sampled",
      "The server has not finished its first pass. It retries every second while this page is open."));
    setWaitingLifecycle();
    return;
  }

  let all = Array.isArray(state.processes) ? state.processes.slice() : [];
  if (all.length === 0) {
    layout.append(emptyState({ action: refreshAction() }, "No processes reported",
      "The process source returned no rows. Refresh to sample it again."));
    setWaitingLifecycle();
    return;
  }

  const storedSortKey = store.get().processSortKey;
  const storedSortDir = store.get().processSortDir;
  let sortKey = storedSortKey || null;
  let sortDir = storedSortDir || null;

  const applySort = (data) => {
    if (!sortKey) return defaultSort(data);
    const cmp = comparators[sortKey];
    if (!cmp) return defaultSort(data);
    return data.slice().sort((a, b) => cmp(a, b, sortDir));
  };

  // The list is already sorted by whatever /api/processes?sort= asked for, and
  // the server pushed unmeasurable rows last. Filtering must not disturb that
  // order, so this preserves it rather than re-sorting. But if the user has
  // clicked a column header, re-sort the filtered set by that column.
  let rows = all;
  let filteredRows = all;
  const applyFilter = () => {
    const q = filterInput.value.trim().toLowerCase();
    filteredRows = q
      ? all.filter((r) => String(r.name || "").toLowerCase().includes(q) ||
                          String(r.pid) === q ||
                          String(r.path || "").toLowerCase().includes(q) ||
                          String(r.service || "").toLowerCase().includes(q))
      : all;
    rows = applySort(filteredRows);
    if (tabs.active() === "table" && tableController) {
      tableController.updateSort(sortKey, sortDir);
      tableController.updateRows(rows, filterInput.value.trim() && rows.length === 0
        ? "No process matched the filter."
        : "");
    } else {
      tabs.select(tabs.active(), true);
    }
    updateSummary();
  };
  applyFilterNow = applyFilter;

  const handleSort = (key, dir) => {
    sortKey = key;
    sortDir = dir;
    store.set({ processSortKey: key, processSortDir: dir });
    applyFilter();
  };

  const summary = h("p", { class: "muted text-sm proc-summary" });
  const updateSummary = () => {
    summary.textContent =
      `${fmtInt(rows.length)} of ${fmtInt(all.length)} processes` +
      (filterInput.value.trim() ? ` matching "${filterInput.value.trim()}"` : "");
  };

  // The active view is store state, not local state. The router re-runs this
  // renderer on every poll and rebuilds the tab strip from scratch; keeping the
  // selection in a closure meant the strip reset to "Table" every two seconds,
  // so clicking Tree appeared to do nothing at all.
  const storedView = store.get().processView;
  let tableController = null;
  let treemapDestroy = null;
  let activeView = storedView;
  const processTreeState = { expanded: new Set(), collapsed: new Set(), focusKey: "" };
  const renderTable = () => {
    if (tableController) tableController.destroy();
    const view = renderTableView(rows, sortKey, sortDir, handleSort, filteredRows, filterInput, store);
    tableController = view._virtualTable || null;
    return view;
  };
  const renderTreemap = () => {
    if (treemapDestroy) treemapDestroy();
    const view = renderTreemapView(rows, store);
    treemapDestroy = view.destroy;
    return view.element;
  };

  const tabs = createTabs({
    ariaLabel: "Process views",
    initial: storedView,
    onChange: (id) => {
      if (activeView === "table" && id !== "table" && tableController) {
        tableController.destroy();
        tableController = null;
      }
      activeView = id;
      store.set({ processView: id });
    },
    tabs: [
      { id: "table", label: "Table", render: renderTable },
      { id: "tree", label: "Tree", render: () => renderTreeView(all, filterInput.value, processTreeState) },
      { id: "treemap", label: "Treemap", render: renderTreemap },
    ],
  });

  layout.append(summary, tabs.element);
  // Apply the current filter and sort so the initial render (including poll-
  // driven re-renders) reflects any persisted sort state. applyFilter calls
  // tabs.select internally, so this replaces the bare updateSummary +
  // tabs.select pair below.
  applyFilter();

  page._procUpdate = (nextState) => {
    if (!nextState.lastUpdate || nextState.processesKnown === false) return;
    const nextRows = Array.isArray(nextState.processes) ? nextState.processes : [];
    all = nextRows.slice();
    const inspected = all.find((row) => `process:${processKey(row)}` === document.querySelector(".inspector-dialog")?.dataset.inspectorKey);
    const inspectorKey = document.querySelector(".inspector-dialog")?.dataset.inspectorKey;
    if (inspectorKey?.startsWith("process:"))
      updateInspector(inspectorKey, inspected || null, { missing: "This process instance exited or is no longer in the sampled process list." });
    applyFilter();
  };

  // The router clears this element wholesale on the next render, so tear the
  // virtual table down explicitly: it holds a ResizeObserver and a window
  // listener.
  page._procDestroy = () => {
    closeContextMenu();
    closeInspector({ restoreFocus: false });
    if (activeProcessDetailsDialog) closeDialog(activeProcessDetailsDialog);
    if (activeProcessBlockDialog) closeDialog(activeProcessBlockDialog);
    if (debounce !== null) clearTimeout(debounce);
    filterInput.removeEventListener("input", onFilterInput);
    if (tableController) tableController.destroy();
    if (treemapDestroy) treemapDestroy();
    treemapDestroy = null;
    page._procUpdate = null;
    tabs.destroy();
  };
}

export function updateProcesses(page, store) {
  if (typeof page._procUpdate === "function") {
    page._procUpdate(store.get());
    return;
  }
  return renderProcesses(page, store);
}

// ---- Table ------------------------------------------------------------------

function renderTableView(rows, sortKey, sortDir, onSort, filteredRows, filterInput, store) {
  const host = h("div", { class: "tab-panel-body" });
  const layoutHost = h("div", { class: "table-layout-host" });
  const container = h("div", { id: "proc-table-container" });
  const procState = store ? store.get() : {};
  host.append(layoutHost, container);

  const emptyMsg = (filterInput && filterInput.value.trim().length > 0 && rows.length === 0)
    ? "No process matched the filter."
    : "";

  const vt = createVirtualTable(container, {
    columns: [
      { key: "name", label: "Name", width: 3, sortable: true },
      { key: "pid", label: "PID", width: 1, sortable: true },
      { key: "ppid", label: "PPID", width: 1, sortable: true },
      { key: "cpuPct", label: "CPU %", width: 1, align: "right", sortable: true },
      { key: "memWs", label: "Working set", width: 1, align: "right", sortable: true },
      { key: "memPrivate", label: "Private", width: 1, align: "right", sortable: true },
      { key: "ioRead", label: "I/O read", width: 1, align: "right", sortable: true },
      { key: "ioWrite", label: "I/O write", width: 1, align: "right", sortable: true },
      { key: "connections", label: "Conns", width: 1, align: "right", sortable: true },
      { key: "listeners", label: "Listen", width: 1, align: "right", sortable: true },
      {
        key: "actions",
        label: "Actions",
        width: 1,
        sortable: false,
        actions: true,
        renderCell: (row) => renderProcActions(row),
      },
    ],
    rowHeight: 34,
    height: 520,
    minWidth: "78rem",
    scrollTop: procState.processTableScrollTop || 0,
    onScroll: (scrollTop) => store.set({ processTableScrollTop: scrollTop }),
    rowKey: processKey,
    label: "Processes on this machine",
    emptyMessage: emptyMsg,
    sortKey,
    sortDir,
    onSort,
    onRowClick: (row) => showProcessDetails(row),
    onRowContextMenu: (row, event, anchor) => processMenu(row, {
      event, anchor, onDetails: showProcessDetails, onBlockApplication: showProcessBlockPreview,
      onAllowApplication: showProcessAllowPreview,
    }),
    // Pre-format here so the virtualiser does no string work per visible row;
    // it also keeps the dash-for-unknown decision in one place.
    format: {
      name: (r) => r.name || "(unnamed)",
      cpuPct: (r) => pct(num(r.cpuPct)),
      memWs: (r) => bytes(r.memWs),
      memPrivate: (r) => bytes(r.memPrivate),
      ioRead: (r) => bytes(r.ioRead),
      ioWrite: (r) => bytes(r.ioWrite),
      connections: (r) => (typeof r.connections === "number" ? fmtInt(r.connections) : UNAVAILABLE),
      listeners: (r) => (typeof r.listeners === "number" ? fmtInt(r.listeners) : UNAVAILABLE),
    },
  });
  const layoutControls = createColumnLayoutControls(vt, {
    layoutKey: "processes",
    required: ["name", "pid", "actions"],
    compactHidden: ["ppid", "memPrivate", "ioRead", "ioWrite", "listeners"],
  });
  const tableDestroy = vt.destroy;
  vt.destroy = () => { layoutControls.destroy(); tableDestroy(); };
  layoutHost.append(layoutControls.element);
  host._virtualTable = vt;
  vt.updateRows(rows);

  host.append(h("p", { class: "muted text-sm proc-note" },
    "I/O is TRANSFER bytes (file, pipe and device), not disk-only. " +
    "A dash means Windows refused to open that process for the figure."));

  const previous = window.__procVtDestroy;
  window.__procVtDestroy = vt.destroy;
  if (previous) previous();
  return host;
}

// ---- Tree -------------------------------------------------------------------

function formatInstanceId(value) {
  if (!value || typeof value !== "string") return String(value ?? "—");
  const match = /^\d+:(\d+):(\d+)$/.exec(value);
  if (match) return `PID ${value.split(":")[0]} · Created ${match[1]}:${match[2]}`;
  const parts = value.split(":");
  if (parts.length === 3 && /^\d+$/.test(parts[0]) && /^\d+$/.test(parts[1]) && /^\d+$/.test(parts[2]))
    return `PID ${parts[0]} · Token ${parts[1]}:${parts[2]}`;
  return value;
}

function processCreationTime(row) {
  const match = /^(\d+):(\d+):(\d+)$/.exec(String(row.instanceId || ""));
  if (!match || Number(match[1]) !== Number(row.pid)) return null;
  const high = Number(match[2]);
  const low = Number(match[3]);
  if (!Number.isInteger(high) || !Number.isInteger(low) || high < 0 || low < 0 ||
      high > 0xffffffff || low > 0xffffffff) return null;
  return { high, low };
}

function compareProcessCreationTime(left, right) {
  return left.high - right.high || left.low - right.low;
}

function renderTreeView(allRows, query, treeState) {
  const host = h("div", { class: "tab-panel-body proc-tree" });
  const tree = h("ul", { class: "tree-list", role: "tree", "aria-label": "Process tree" });
  const byKey = new Map(allRows.map((row) => [processKey(row), row]));
  const byPid = new Map();
  const parentIdentityStatus = new Map();
  for (const row of allRows) {
    if (row.pid != null && !byPid.has(row.pid)) byPid.set(row.pid, row);
  }
  const parentOf = new Map();
  for (const row of allRows) {
    const parent = byPid.get(row.ppid);
    if (!parent || parent.pid === row.pid) continue;
    const childKey = processKey(row);
    const parentStart = processCreationTime(parent);
    const childStart = processCreationTime(row);
    if (!parentStart || !childStart) {
      parentIdentityStatus.set(childKey, "Parent identity could not be verified");
      continue;
    }
    if (compareProcessCreationTime(parentStart, childStart) > 0) {
      parentIdentityStatus.set(childKey, "Parent PID was reused; relationship omitted");
      continue;
    }
    parentOf.set(childKey, processKey(parent));
  }

  for (const startKey of byKey.keys()) {
    const path = [];
    const positions = new Map();
    let key = startKey;
    while (parentOf.has(key)) {
      if (positions.has(key)) {
        const cycle = path.slice(positions.get(key));
        const rootKey = cycle.sort((left, right) =>
          (byKey.get(left)?.pid ?? 0) - (byKey.get(right)?.pid ?? 0))[0];
        parentOf.delete(rootKey);
        break;
      }
      positions.set(key, path.length);
      path.push(key);
      key = parentOf.get(key);
    }
  }

  const normalizedQuery = String(query || "").trim().toLowerCase();
  const matchedKeys = new Set(allRows.filter((row) => !normalizedQuery ||
    String(row.name || "").toLowerCase().includes(normalizedQuery) ||
    String(row.pid) === normalizedQuery).map(processKey));
  const visibleKeys = new Set(matchedKeys);
  for (const matchedKey of matchedKeys) {
    let parentKey = parentOf.get(matchedKey);
    while (parentKey && !visibleKeys.has(parentKey)) {
      visibleKeys.add(parentKey);
      parentKey = parentOf.get(parentKey);
    }
  }

  const childrenOf = new Map();
  const roots = [];
  for (const row of allRows) {
    const key = processKey(row);
    if (!visibleKeys.has(key)) continue;
    const parentKey = parentOf.get(key);
    if (parentKey && visibleKeys.has(parentKey)) {
      if (!childrenOf.has(parentKey)) childrenOf.set(parentKey, []);
      childrenOf.get(parentKey).push(row);
    } else {
      roots.push(row);
    }
  }
  const byCpuDesc = (a, b) => {
    const av = num(a.cpuPct), bv = num(b.cpuPct);
    if (av === null && bv === null) return a.pid - b.pid;
    if (av === null) return 1;
    if (bv === null) return -1;
    return bv - av || a.pid - b.pid;
  };
  roots.sort(byCpuDesc);
  for (const children of childrenOf.values()) children.sort(byCpuDesc);

  const currentKeys = new Set(visibleKeys);
  for (const key of treeState.expanded) if (!byKey.has(key)) treeState.expanded.delete(key);
  for (const key of treeState.collapsed) if (!byKey.has(key)) treeState.collapsed.delete(key);
  for (const root of roots) {
    const key = processKey(root);
    if (!treeState.collapsed.has(key)) treeState.expanded.add(key);
  }
  for (const matchedKey of matchedKeys) {
    let parentKey = parentOf.get(matchedKey);
    while (parentKey) {
      if (!treeState.collapsed.has(parentKey)) treeState.expanded.add(parentKey);
      parentKey = parentOf.get(parentKey);
    }
  }
  if (!currentKeys.has(treeState.focusKey)) treeState.focusKey = roots.length ? processKey(roots[0]) : "";

  let visibleItems = [];
  const renderItems = () => {
    visibleItems = [];
    tree.replaceChildren();
    const addNode = (row, depth, position, setSize, parentKey = "") => {
      const key = processKey(row);
      const children = childrenOf.get(key) || [];
      const expanded = treeState.expanded.has(key);
      const contextOnly = !matchedKeys.has(key);
      const relationshipStatus = parentIdentityStatus.get(key);
      const item = h("li", {
        class: `tree-item${depth > 3 ? " tree-item-deep" : ""}${contextOnly ? " tree-item-context" : ""}`,
        role: "treeitem",
        tabindex: key === treeState.focusKey ? "0" : "-1",
        "aria-expanded": children.length ? String(expanded) : null,
        "aria-level": String(depth + 1),
        "aria-posinset": String(position + 1),
        "aria-setsize": String(setSize),
        "aria-description": relationshipStatus || null,
        dataset: { treeKey: key },
      });
      item.append(h("div", { class: "tree-row" },
        h("span", { class: "tree-disclosure", "aria-hidden": "true" }, children.length ? expanded ? "−" : "+" : ""),
        h("span", { class: "tree-name", dir: "auto", title: row.path || row.name }, row.name || "(unnamed)"),
        h("span", { class: "tree-pid num" }, String(row.pid)),
        h("span", { class: "tree-cpu num", title: "percent of total CPU" }, pct(num(row.cpuPct))),
        h("span", { class: "tree-mem num" }, bytes(row.memWs)),
        h("span", { class: "tree-count num", title: "open endpoints" },
          typeof row.connections === "number" ? fmtInt(row.connections) : UNAVAILABLE),
        relationshipStatus
          ? h("span", { class: "tree-parent-status", title: relationshipStatus },
            relationshipStatus.includes("reused") ? "Parent PID reused" : "Parent unverified")
          : contextOnly ? h("span", { class: "tree-context-label" }, "Ancestor") : null,
      ));
      visibleItems.push({ key, row, item, children, parentKey });
      item.addEventListener("focus", () => {
        treeState.focusKey = key;
        for (const entry of visibleItems) entry.item.tabIndex = entry.key === key ? 0 : -1;
      });
      item.addEventListener("click", (event) => {
        if (event.target.closest(".tree-disclosure") && children.length) {
          treeState.focusKey = key;
          toggleExpanded(key);
        }
      });
      item.addEventListener("contextmenu", (event) => {
        event.preventDefault();
        treeState.focusKey = key;
        item.focus();
        processMenu(row, { event, anchor: item, onDetails: showProcessDetails,
          onBlockApplication: showProcessBlockPreview, onAllowApplication: showProcessAllowPreview });
      });
      if (expanded && children.length) {
        const group = h("ul", { class: "tree-children", role: "group" });
        for (let index = 0; index < children.length; index++) {
          group.append(addNode(children[index], depth + 1, index, children.length, key));
        }
        item.append(group);
      }
      return item;
    };
    for (let index = 0; index < roots.length; index++) {
      tree.append(addNode(roots[index], 0, index, roots.length));
    }
    const focused = [...tree.querySelectorAll('[role="treeitem"]')]
      .find((item) => item.dataset.treeKey === treeState.focusKey);
    focused?.focus();
  };
  const toggleExpanded = (key) => {
    if (treeState.expanded.has(key)) {
      treeState.expanded.delete(key);
      treeState.collapsed.add(key);
    } else {
      treeState.collapsed.delete(key);
      treeState.expanded.add(key);
    }
    renderItems();
  };
  tree.addEventListener("keydown", (event) => {
    const item = event.target.closest('[role="treeitem"]');
    const current = visibleItems.find((entry) => entry.item === item);
    if (!current) return;
    const index = visibleItems.indexOf(current);
    const moveFocus = (next) => {
      if (next < 0 || next >= visibleItems.length) return;
      event.preventDefault();
      treeState.focusKey = visibleItems[next].key;
      visibleItems[next].item.focus();
    };
    switch (event.key) {
      case "ArrowDown": moveFocus(index + 1); break;
      case "ArrowUp": moveFocus(index - 1); break;
      case "Home": moveFocus(0); break;
      case "End": moveFocus(visibleItems.length - 1); break;
      case "ArrowRight":
        if (current.children.length && !treeState.expanded.has(current.key)) {
          event.preventDefault();
          toggleExpanded(current.key);
        } else if (current.children.length) moveFocus(index + 1);
        break;
      case "ArrowLeft":
        if (current.children.length && treeState.expanded.has(current.key)) {
          event.preventDefault();
          toggleExpanded(current.key);
        } else {
          const parentIndex = visibleItems.findIndex((entry) => entry.key === current.parentKey);
          if (parentIndex >= 0) moveFocus(parentIndex);
        }
        break;
      case " ":
        if (current.children.length) {
          event.preventDefault();
          toggleExpanded(current.key);
        }
        break;
      case "Enter":
        event.preventDefault();
        showProcessDetails(current.row);
        break;
      case "F10":
      case "ContextMenu":
        if (event.key === "ContextMenu" || event.shiftKey) {
          event.preventDefault();
          processMenu(current.row, { event, anchor: item, onDetails: showProcessDetails,
            onBlockApplication: showProcessBlockPreview, onAllowApplication: showProcessAllowPreview });
        }
        break;
      default: break;
    }
  });
  host.append(tree);
  renderItems();
  return host;
}

// ---- Treemap ----------------------------------------------------------------

function renderTreemapView(rows, store) {
  const host = h("div", { class: "tab-panel-body" });
  // The metric is store state, not a local: this renderer runs again on every
  // poll, so a local would snap the operator back to "Working set" mid-
  // comparison, which is the same class of bug as the tab selection resetting.
  const stored = store.get().processTreemapMetric;
  let metric = stored === "cpuPct" ? "cpuPct" : "memWs";
  let grouped = store.get().processTreemapGrouped === true;

  const chart = h("div", { class: "treemap-host" });
  const switcher = h("div", { class: "treemap-switch", role: "group", "aria-label": "Treemap metric" });
  const groupButton = h("button", {
    class: `btn btn-sm${grouped ? " btn-secondary" : ""}`,
    type: "button",
    "aria-pressed": grouped ? "true" : "false",
    onclick: (event) => {
      grouped = !grouped;
      store.set({ processTreemapGrouped: grouped });
      groupButton.className = `btn btn-sm${grouped ? " btn-secondary" : ""}`;
      groupButton.setAttribute("aria-pressed", grouped ? "true" : "false");
      paint();
    },
  }, "Group by executable");
  let destroyed = false;
  let omittedTileCount = 0;
  const resizeObserver = new ResizeObserver(() => {
    if (chart.clientWidth > 0) paint();
  });
  resizeObserver.observe(chart);

  const paint = () => {
    if (destroyed || chart.clientWidth <= 0) return;
    clear(chart);
    // A treemap needs positive magnitudes. A process with no working-set
    // reading contributes nothing to the picture and must not appear as a
    // zero-area tile, so it is excluded - and the count of what was excluded is
    // stated below rather than silently dropped.
    const metricValue = (row) => metric === "cpuPct"
      ? num(row.cpuPct) : chartMetric(row.memWs);
    const unknownCount = rows.filter((row) => metricValue(row) === null).length;
    const zeroCount = rows.filter((row) => metricValue(row) === 0).length;
    const invalidCount = rows.filter((row) => {
      const value = metricValue(row);
      return value !== null && value < 0;
    }).length;
    const withValue = rows.filter((row) => {
      const value = metricValue(row);
      return value !== null && value > 0;
    });
    const metricName = metric === "cpuPct" ? "CPU share" : "working set";
    const excludedNotes = [];
    if (unknownCount > 0) {
      excludedNotes.push(
        `${unknownCount} process${unknownCount === 1 ? " had" : "es had"} no readable ${metricName}`,
      );
    }
    if (zeroCount > 0) {
      excludedNotes.push(
        `${zeroCount} process${zeroCount === 1 ? " reported" : "es reported"} zero ${metricName}`,
      );
    }
    if (invalidCount > 0) {
      excludedNotes.push(
        `${invalidCount} process${invalidCount === 1 ? " had" : "es had"} an invalid negative ${metricName}`,
      );
    }

    // Only the top slices get a tile; 350 rectangles 3px wide is a texture, not
    // a chart. The rest are folded into an explicit "other" row.
    const MAX_TILES = 48;
    let tileRows;
    if (grouped) {
      const groups = new Map();
      for (const row of rows) {
        const path = typeof row.path === "string" ? row.path.trim() : "";
        const groupKey = path ? "path:" + path.toLowerCase() : "instance:" + processKey(row);
        if (!groups.has(groupKey)) groups.set(groupKey, { path, rows: [] });
        groups.get(groupKey).rows.push(row);
      }
      tileRows = [...groups.values()].map((group) => {
        const usable = group.rows.filter((row) => {
          const value = metricValue(row);
          return value !== null && value >= 0;
        });
        const measured = group.rows.filter((row) => {
          const value = metricValue(row);
          return value !== null && value > 0;
        });
        if (!measured.length) return null;
        let value;
        let displayValue;
        if (metric === "memWs") {
          const exactValues = measured.map((row) => {
            const raw = row.memWs;
            if (typeof raw === "bigint") return raw >= 0n ? raw : null;
            if (typeof raw === "string" && /^\d+$/.test(raw)) return BigInt(raw);
            if (typeof raw === "number" && Number.isSafeInteger(raw) && raw >= 0) return BigInt(raw);
            return null;
          });
          if (exactValues.every((entry) => entry !== null)) {
            const exactTotal = exactValues.reduce((sum, entry) => sum + entry, 0n);
            value = Number(exactTotal);
            displayValue = fmtBytes(exactTotal);
          } else {
            value = measured.reduce((sum, row) => sum + metricValue(row), 0);
            displayValue = "Approximately " + fmtBytes(value);
          }
        } else {
          value = measured.reduce((sum, row) => sum + metricValue(row), 0);
          displayValue = fmtPct(value);
        }
        if (!Number.isFinite(value) || value <= 0) return null;
        const representative = group.rows[0];
        const processName = representative.name || `PID ${representative.pid}`;
        const memberCount = group.rows.length;
        const unavailableCount = memberCount - usable.length;
        return {
          label: `${processName}${memberCount > 1 ? ` (${memberCount} instances)` : ""}`,
          accessibleLabel: `${processName}; ${memberCount} process ${memberCount === 1 ? "instance" : "instances"}` +
            (group.path ? `; ${group.path}` : "; executable path unavailable, kept separate"),
          value,
          displayValue,
          reason: unavailableCount > 0
            ? `Measured subtotal from ${usable.length} of ${memberCount} instances; ${unavailableCount} value(s) unavailable or invalid`
            : `Total across ${memberCount} instance(s)`,
          processes: group.rows,
          processPath: group.path,
        };
      }).filter(Boolean);
    } else {
      tileRows = withValue.map((row) => ({
        label: row.name || `pid ${row.pid}`,
        accessibleLabel: `${row.name || "(unnamed)"} (PID ${row.pid})`,
        value: metricValue(row),
        displayValue: metric === "cpuPct" ? fmtPct(metricValue(row)) : fmtBytes(row.memWs),
        process: row,
      }));
    }
    const sorted = tileRows.slice().sort((a, b) =>
      b.value - a.value || a.label.localeCompare(b.label));
    const top = sorted.slice(0, MAX_TILES);
    const tail = sorted.slice(MAX_TILES);
    const data = top;
    if (tail.length > 0) {
      const tailProcesses = tail.flatMap((row) => row.processes ||
        (row.process ? [row.process] : []));
      const tailValue = tail.reduce((sum, row) => sum + row.value, 0);
      data.push({
        label: `${tail.length} more ${grouped ? "groups" : "processes"}`,
        accessibleLabel: `${tail.length} additional ${grouped ? "executable groups" : "processes"}; select to inspect instances`,
        value: tailValue,
        displayValue: metric === "cpuPct" ? fmtPct(tailValue) : "Known subtotal: " + fmtBytes(tailValue),
        reason: "Select this tile to choose an exact process instance.",
        processes: tailProcesses,
        remainder: true,
      });
    }

    const format = metric === "cpuPct" ? ((v) => fmtPct(v)) : ((v) => fmtBytes(v));
    const painted = renderTreemap(chart, data, {
      height: 440,
      format,
      onOmittedTiles: (count) => { omittedTileCount = count; },
      onSelect: (item) => {
        if (item.process) showProcessDetails(item.process);
        else if (item.processes?.length === 1) showProcessDetails(item.processes[0]);
        else if (item.processes?.length > 1) showProcessGroupDetails(item, metric);
      },
    });
    if (!painted) {
      chart.append(emptyState({}, "Nothing to draw",
        excludedNotes.length > 0 ? `${excludedNotes.join("; ")}.` : "No positive values are available."));
      return;
    }
    const notes = [];
    notes.push(...excludedNotes);
    if (grouped) {
      notes.push("Processes are grouped by full executable path; pathless instances stay separate. Grouped totals include only readable values, so a subtotal is marked when some instances are unavailable");
    }
    if (tail.length > 0) {
      notes.push(`area is proportional to ${metric === "cpuPct" ? "CPU share" : "working set"}; the smallest tiles are grouped`);
    }
    if (omittedTileCount > 0) {
      notes.push(`${omittedTileCount} tile${omittedTileCount === 1 ? " is" : "s are"} too small to activate here; use Tree or Table to inspect every process`);
    }
    if (notes.length > 0) {
      chart.append(h("p", { class: "muted text-sm treemap-note" }, notes.join(". ") + "."));
    }
  };

  for (const [id, label] of [["memWs", "Working set"], ["cpuPct", "CPU share"]]) {
    switcher.append(h("button", {
      class: `btn btn-sm${metric === id ? " btn-secondary" : ""}`,
      type: "button",
      "aria-pressed": metric === id ? "true" : "false",
      onclick: (e) => {
        metric = id;
        store.set({ processTreemapMetric: id });
        for (const btn of switcher.children) {
          const on = btn === e.currentTarget;
          btn.className = `btn btn-sm${on ? " btn-secondary" : ""}`;
          btn.setAttribute("aria-pressed", on ? "true" : "false");
        }
        paint();
      },
    }, label));
  }

  host.append(
    h("div", { class: "treemap-toolbar" }, switcher, groupButton),
    chart,
  );
  return {
    element: host,
    destroy() {
      if (destroyed) return;
      destroyed = true;
      resizeObserver.disconnect();
    },
  };
}

function showProcessGroupDetails(group, metric) {
  if (activeProcessDetailsDialog) closeDialog(activeProcessDetailsDialog);
  const metricLabel = metric === "cpuPct" ? "CPU share" : "Working set";
  const title = group.remainder ? "Additional process instances" : "Process instances";
  const formatValue = (row) => {
    if (metric === "cpuPct") return num(row.cpuPct) === null ? UNAVAILABLE : fmtPct(row.cpuPct);
    return byteValueKnown(row.memWs) ? fmtBytes(row.memWs) : UNAVAILABLE;
  };
  const list = h("ul", { class: "process-group-list" });
  for (const row of group.processes) {
    const open = h("button", {
      class: "btn btn-outline btn-sm process-group-instance",
      type: "button",
      onclick: () => {
        closeDialog(view);
        showProcessDetails(row);
      },
    },
    h("span", {}, `${row.name || "(unnamed)"} · PID ${row.pid}`),
    h("span", { class: "muted num" }, formatValue(row)));
    list.append(h("li", {}, open));
  }
  const view = dialog({ class: "details-dialog process-group-dialog",
    "aria-labelledby": "process-group-title" },
    h("form", { method: "dialog", class: "dialog-form" },
      h("div", { class: "dialog-header" },
        h("h2", { id: "process-group-title", class: "dialog-title" }, title),
        h("button", { type: "submit", class: "btn btn-close btn-sm", "aria-label": "Close" }, "Close")),
      h("div", { class: "dialog-content" },
        h("p", { class: "dialog-description" }, group.remainder
          ? `${group.processes.length} processes are combined only to keep the treemap readable. Choose one exact process to inspect.`
          : `${group.processPath || "Executable path unavailable"} · ${group.processes.length} instances. Choose one exact process to inspect.`),
        h("p", { class: "muted text-sm" }, `${metricLabel} values are per process instance; unavailable values remain unavailable.`),
        list),
      h("div", { class: "dialog-footer" },
        h("button", { type: "submit", class: "btn btn-outline btn-sm" }, "Close"))));
  document.body.append(view);
  activeProcessDetailsDialog = view;
  view.addEventListener("close", () => {
    if (activeProcessDetailsDialog === view) activeProcessDetailsDialog = null;
  }, { once: true });
  openDialog(view);
}

// ---- Row actions (Details / Block) ----------------------------------------

function renderProcActions(row) {
  const wrap = h("div", { class: "row-actions" });

  wrap.append(
    h("button", {
      class: "btn btn-ghost btn-icon btn-xs",
      type: "button",
      title: "Details",
      onclick: (e) => { e.stopPropagation(); showProcessDetails(row); },
    }, icon("info", 14)),
  );

  wrap.append(h("button", {
    class: "btn btn-ghost btn-sm", type: "button",
    "aria-label": "Process actions", "aria-haspopup": "menu",
    onclick: (event) => {
      event.stopPropagation();
      processMenu(row, { event, anchor: event.currentTarget, onDetails: showProcessDetails,
        onBlockApplication: showProcessBlockPreview, onAllowApplication: showProcessAllowPreview });
    },
  }, "\u22ef"));

  return wrap;
}

function showProcessBlockPreview(row) {
  showProcessApplicationRulePreview(row, false);
}

function showProcessAllowPreview(row) {
  showProcessApplicationRulePreview(row, true);
}

function showProcessApplicationRulePreview(row, allow) {
  if (activeProcessBlockDialog) closeDialog(activeProcessBlockDialog);
  const controller = new AbortController();
  const status = h("p", { class: "dialog-description", role: "status", "aria-live": "polite" },
    "Preparing the application firewall preview…");
  const plan = h("pre", { class: "muted text-sm" });
  const create = h("button", { class: allow ? "btn btn-primary btn-sm" : "btn btn-destructive btn-sm", type: "button", disabled: true },
    allow ? "Create allow rule" : "Create application rule");
  const cancel = h("button", { class: "btn btn-outline btn-sm", type: "button",
    onclick: () => closeDialog(view) }, "Cancel");
  const footer = h("div", { class: "dialog-footer" }, cancel);
  const view = dialog({ class: "details-dialog action-preview-dialog",
    "aria-labelledby": "process-application-rule-title" },
    h("form", { method: "dialog", class: "dialog-form" },
      h("div", { class: "dialog-header" },
        h("h2", { id: "process-application-rule-title", class: "dialog-title" },
          allow ? "Review application allow rule" : "Review application rule"),
        h("button", { type: "submit", class: "btn btn-close btn-sm", "aria-label": "Close" }, "Close")),
      h("div", { class: "dialog-content" }, status,
        h("dl", { class: "detail-list" },
          detailEntry("Process", row.name || UNAVAILABLE),
          detailEntry("PID", row.pid != null ? String(row.pid) : UNAVAILABLE),
          detailEntry("Process instance", row.instanceId || UNAVAILABLE),
          detailEntry("Executable path", row.path || UNAVAILABLE),
          detailEntry("Rule scope", `${allow ? "Allow" : "Block"} outbound TCP; all remote addresses and ports`),
          detailEntry("Affected instances", "Every current and future process using this executable path")),
        h("p", { class: "muted text-sm" },
          allow
            ? "This allow rule applies to every instance of the executable path. It does not close existing connections, and a matching Windows Firewall block rule can still take precedence."
            : "This block rule does not close existing connections and is not limited to the selected PID."),
        plan),
      footer));
  let previewNonce = "";
  let executing = false;
  activeProcessBlockDialog = view;
  view.addEventListener("close", () => {
    controller.abort();
    if (activeProcessBlockDialog === view) activeProcessBlockDialog = null;
  }, { once: true });
  view.addEventListener("cancel", (event) => { if (executing) event.preventDefault(); });
  document.body.append(view);
  openDialog(view);
  api.postForm("/api/block/preview", {
    scope: allow ? "application-allow" : "application",
    process: String(row.path || ""),
    pid: String(row.pid ?? ""),
    instanceId: String(row.instanceId || ""),
  }, { signal: controller.signal }).then((preview) => {
    if (!view.isConnected) return;
    plan.textContent = preview.plan || "The server did not provide a textual firewall plan.";
    if (!preview.nonce) {
      status.textContent = preview.reason ||
        "The application rule cannot be prepared. Refresh the process list and retry.";
      return;
    }
    previewNonce = preview.nonce;
    status.textContent = "Review the full executable path and all-instances scope before confirming.";
    create.disabled = false;
    footer.prepend(create);
  }).catch((error) => {
    if (!view.isConnected || error.name === "AbortError") return;
    status.textContent = error.message;
  });
  create.onclick = async () => {
    if (create.disabled || !previewNonce || executing) return;
    executing = true;
    create.disabled = true;
    cancel.disabled = true;
    const closeButton = view.querySelector('.dialog-header button[aria-label="Close"]');
    if (closeButton) closeButton.disabled = true;
    status.textContent = `Creating the reviewed application ${allow ? "allow" : "block"} rule…`;
    try {
      const result = await api.postForm("/api/block/commit", { nonce: previewNonce },
        { signal: controller.signal });
      if (!view.isConnected) return;
      status.textContent = result.ok
        ? `Application ${allow ? "allow" : "block"} rule ${result.ruleStatus === "already-present" ? "already existed" : "was created"}. Existing connections remain open.`
        : `Application rule creation failed: ${result.message || "Windows Firewall refused the request."}`;
      create.remove();
      if (result.ok && result.ruleName) {
        footer.prepend(h("button", { class: "btn btn-outline btn-sm", type: "button",
          onclick: () => {
            closeDialog(view);
            document.dispatchEvent(new CustomEvent("wintcp:firewall-open-rule",
              { detail: { name: result.ruleName } }));
          },
        }, "Open firewall rule"));
      }
    } catch (error) {
      if (!view.isConnected || error.name === "AbortError") return;
      status.textContent = `Application rule creation failed: ${error.message}`;
      create.remove();
    }
    executing = false;
    cancel.disabled = false;
    if (closeButton) closeButton.disabled = false;
  };
}

function showProcessDetails(row) {
  if (activeProcessDetailsDialog) closeDialog(activeProcessDetailsDialog);
  const inspector = openInspector({
    key: `process:${processKey(row)}`,
    title: row.name || "(unnamed process)",
    subject: "process instance",
    row,
    sections: (process) => processInspectorSections(process || row),
    actions: (process) => {
      const current = process || row;
      return [
        { label: "Show this process's connections", onClick: () => {
          closeInspector({ restoreFocus: false });
          investigateConnections([processConnectionFilter(current)], "replace");
        } },
        ...(current.path ? [{
          label: "Review app firewall block", className: "btn btn-destructive btn-sm",
          title: "An executable-path rule affects every instance of this application, not only this PID.",
          onClick: () => {
            closeInspector({ restoreFocus: false });
            showProcessBlockPreview(current);
          },
        }] : []),
      ];
    },
    opener: document.activeElement,
  });
  inspector.dataset.detailsRow = "proc";
}

function processInspectorSections(row) {
  const known = (value) => value != null && value !== "";
  const field = (label, value, options = {}) => ({ label, value, copyValue: options.copy === false || !known(value) ? null : String(value), ...options });
  return [
    { title: "Identity", fields: [
      field("Process", row.name || "(unnamed)"),
      field("PID", row.pid, { mono: true }),
      field("Parent PID", row.ppid, { mono: true, reason: known(row.ppid) ? "" : "Parent identity was not supplied by this process snapshot." }),
      field("Process instance", formatInstanceId(row.instanceId), { mono: true, reason: known(row.instanceId) ? "PID lifetime token; a PID alone can be reused." : "Creation time is unknown; PID alone is not a stable identity." }),
      field("Executable path", row.path, { mono: true, reason: known(row.path) ? "" : "Windows did not provide a readable image path." }),
      field("Service", row.service, { reason: known(row.service) ? "" : "Service attribution is not included in this process snapshot." }),
    ] },
    { title: "Activity", fields: [
      field("Threads", typeof row.threads === "number" ? fmtInt(row.threads) : null, { copy: false }),
      field("CPU", num(row.cpuPct) !== null ? fmtPct(row.cpuPct) : null, { copy: false, reason: num(row.cpuPct) !== null ? "" : "Windows did not provide a CPU sample for this process." }),
      field("Working set", byteValueKnown(row.memWs) ? fmtBytes(row.memWs) : null, { copy: false, reason: byteValueKnown(row.memWs) ? "" : "Windows did not provide a working-set value." }),
      field("Private memory", byteValueKnown(row.memPrivate) ? fmtBytes(row.memPrivate) : null, { copy: false }),
      field("I/O read", byteValueKnown(row.ioRead) ? fmtBytes(row.ioRead) : null, { copy: false, reason: "Cumulative transfer bytes; not a rate." }),
      field("I/O write", byteValueKnown(row.ioWrite) ? fmtBytes(row.ioWrite) : null, { copy: false, reason: "Cumulative transfer bytes; not a rate." }),
      field("Connections", typeof row.connections === "number" ? fmtInt(row.connections) : null, { copy: false }),
      field("Listeners", typeof row.listeners === "number" ? fmtInt(row.listeners) : null, { copy: false }),
    ] },
  ];
}

function detailEntry(label, value) {
  return [
    h("dt", {}, label),
    h("dd", {}, value),
  ];
}
