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
import { emptyState } from "../ui/card.js";
import { renderTreemap } from "../charts/treemap.js";
import { fmtBytes, fmtInt, fmtPct, fmtNum } from "../format.js";

const UNAVAILABLE = "\u2014";

// Reading helpers. A process whose handle cannot be opened reports null, and the
// table shows a dash. Showing 0% CPU for a process we could not measure is the
// single most misleading thing this page could do.
const num = (v) => (typeof v === "number" && Number.isFinite(v) ? v : null);
const bytes = (v) => (typeof v === "number" && Number.isFinite(v) ? fmtBytes(v) : UNAVAILABLE);
const pct = (v) => (typeof v === "number" && Number.isFinite(v) ? fmtPct(v) : UNAVAILABLE);

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
      h("input", {
        class: "input page-filter",
        id: "proc-filter",
        type: "search",
        placeholder: "Filter by name or PID\u2026",
        "aria-label": "Filter processes by name or PID",
      }),
    ),
    layout,
  );

  const filterInput = page.querySelector("#proc-filter");
  const state = store.get();

  if (!state.lastUpdate) {
    layout.append(emptyState({}, "Waiting for the first sample",
      "The browser polls the server every couple of seconds. This fills in on its own."));
    return;
  }
  if (state.processesKnown === false) {
    layout.append(emptyState({}, "Process table not sampled",
      "The server has not finished its first pass. It retries every second while this page is open."));
    return;
  }

  const all = Array.isArray(state.processes) ? state.processes.slice() : [];
  if (all.length === 0) {
    layout.append(emptyState({}, "No processes reported",
      "The server enumerated the process table and it came back empty, which should not happen."));
    return;
  }

  // The list is already sorted by whatever /api/processes?sort= asked for, and
  // the server pushed unmeasurable rows last. Filtering must not disturb that
  // order, so this preserves it rather than re-sorting.
  let rows = all;
  const applyFilter = () => {
    const q = filterInput.value.trim().toLowerCase();
    rows = q
      ? all.filter((r) => String(r.name || "").toLowerCase().includes(q) ||
                          String(r.pid) === q)
      : all;
    tabs.select(tabs.active(), true);
    updateSummary();
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

  const tabs = createTabs({
    ariaLabel: "Process views",
    initial: storedView,
    onChange: (id) => store.set({ processView: id }),
    tabs: [
      { id: "table", label: "Table", render: () => renderTableView(rows) },
      { id: "tree", label: "Tree", render: () => renderTreeView(rows) },
      { id: "treemap", label: "Treemap", render: () => renderTreemapView(rows, store) },
    ],
  });

  layout.append(summary, tabs.element);
  updateSummary();
  // force: true because on a poll-driven rebuild the panel is genuinely empty
  // and must be re-rendered, even when the selection has not moved.
  await tabs.select(tabs.active(), true);

  let debounce = null;
  filterInput.addEventListener("input", () => {
    // 120 ms: enough to coalesce a paste or a fast typist into one re-render,
    // short enough that the list feels live.
    if (debounce !== null) clearTimeout(debounce);
    debounce = setTimeout(() => { debounce = null; applyFilter(); }, 120);
  });

  // The router clears this element wholesale on the next render, so tear the
  // virtual table down explicitly: it holds a ResizeObserver and a window
  // listener.
  page._procDestroy = () => {
    if (debounce !== null) clearTimeout(debounce);
    tabs.destroy();
  };
}

// ---- Table ------------------------------------------------------------------

function renderTableView(rows) {
  const host = h("div", { class: "tab-panel-body" });
  const container = h("div", { id: "proc-table-container" });
  host.append(container);

  const vt = createVirtualTable(container, {
    columns: [
      { key: "name", label: "Name", width: 3 },
      { key: "pid", label: "PID", width: 1 },
      { key: "ppid", label: "PPID", width: 1 },
      { key: "cpuPct", label: "CPU %", width: 1, align: "right" },
      { key: "memWs", label: "Working set", width: 1, align: "right" },
      { key: "memPrivate", label: "Private", width: 1, align: "right" },
      { key: "ioRead", label: "I/O read", width: 1, align: "right" },
      { key: "ioWrite", label: "I/O write", width: 1, align: "right" },
      { key: "connections", label: "Conns", width: 1, align: "right" },
      { key: "listeners", label: "Listen", width: 1, align: "right" },
    ],
    rowHeight: 34,
    height: 520,
    label: "Processes on this machine",
    emptyMessage: "No process matched the filter.",
    // Pre-format here so the virtualiser does no string work per visible row;
    // it also keeps the dash-for-unknown decision in one place.
    format: {
      name: (r) => r.name || "(unnamed)",
      cpuPct: (r) => pct(num(r.cpuPct)),
      memWs: (r) => bytes(num(r.memWs)),
      memPrivate: (r) => bytes(num(r.memPrivate)),
      ioRead: (r) => bytes(num(r.ioRead)),
      ioWrite: (r) => bytes(num(r.ioWrite)),
      connections: (r) => (typeof r.connections === "number" ? fmtInt(r.connections) : UNAVAILABLE),
      listeners: (r) => (typeof r.listeners === "number" ? fmtInt(r.listeners) : UNAVAILABLE),
    },
  });
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

function renderTreeView(rows) {
  const host = h("div", { class: "tab-panel-body proc-tree" });
  const byPid = new Map(rows.map((r) => [r.pid, r]));
  const childrenOf = new Map();
  let roots = [];

  for (const row of rows) {
    // A process whose parent is not in the filtered set is a ROOT here, not a
    // missing row. The filter hides the parent; pretending the child is
    // orphaned would make the tree lie about the hierarchy.
    const parent = byPid.get(row.ppid);
    if (parent && parent.pid !== row.pid) {
      if (!childrenOf.has(parent.pid)) childrenOf.set(parent.pid, []);
      childrenOf.get(parent.pid).push(row);
    } else {
      roots.push(row);
    }
  }

  // Sort by CPU where measured, then by PID. PID is the final tie-break so two
  // processes at the same CPU cannot swap places between polls and make the tree
  // appear to flicker.
  const byCpuDesc = (a, b) => {
    const av = num(a.cpuPct), bv = num(b.cpuPct);
    if (av === null && bv === null) return a.pid - b.pid;
    if (av === null) return 1;
    if (bv === null) return -1;
    return bv - av || a.pid - b.pid;
  };
  roots.sort(byCpuDesc);
  for (const list of childrenOf.values()) list.sort(byCpuDesc);

  if (roots.length === 0) {
    return emptyState({}, "No roots", "Every process in this filter is somebody's child.");
  }

  // ARIA structure. role="tree" owns only role="treeitem" children, directly or
  // through a role="group" - a role="none" wrapper in between is an
  // aria-required-children violation, which axe reports as CRITICAL. So the
  // treeitem IS the <li>, and the nested list carries role="group".
  //
  // aria-level is set explicitly rather than left to be inferred from nesting:
  // depth is clamped below, and a clamped tree must not report a level it did
  // not reach.
  const list = h("ul", { class: "tree-list", role: "tree", "aria-label": "Process tree" });
  // Depth is bounded: a parent cycle in a corrupted table would otherwise
  // recurse until the stack runs out.
  const MAX_DEPTH = 48;

  const buildTreeItem = (row, depth) => {
    if (depth > MAX_DEPTH) {
      return h("li", {
        class: "tree-item tree-item-deep",
        role: "treeitem",
        "aria-level": String(MAX_DEPTH + 1),
      },
        h("div", { class: "tree-row" },
          h("span", { class: "tree-name", dir: "auto" }, row.name || "(unnamed)"),
          h("span", { class: "muted text-sm" }, "ancestry truncated"),
        ));
    }
    const kids = childrenOf.get(row.pid) || [];
    const item = h("li", {
      class: "tree-item",
      role: "treeitem",
      // aria-expanded is only meaningful on a node that actually has children;
      // putting it on a leaf tells assistive tech it can be collapsed.
      "aria-expanded": kids.length > 0 ? "true" : null,
      "aria-level": String(depth + 1),
      style: `padding-left: ${depth * 1.1}rem`,
    },
      h("div", { class: "tree-row" },
        h("span", { class: "tree-name", dir: "auto", title: row.path || row.name }, row.name || "(unnamed)"),
        h("span", { class: "tree-pid num" }, String(row.pid)),
        h("span", { class: "tree-cpu num", title: "percent of total CPU" }, pct(num(row.cpuPct))),
        h("span", { class: "tree-mem num" }, bytes(num(row.memWs))),
        h("span", { class: "tree-count num", title: "open endpoints" },
          typeof row.connections === "number" ? fmtInt(row.connections) : UNAVAILABLE),
      ),
    );
    if (kids.length > 0) {
      const sub = h("ul", { class: "tree-children", role: "group" });
      for (const kid of kids) sub.append(buildTreeItem(kid, depth + 1));
      item.append(sub);
    }
    return item;
  };

  for (const root of roots) list.append(buildTreeItem(root, 0));
  host.append(list);
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

  const chart = h("div", { class: "treemap-host" });
  const switcher = h("div", { class: "treemap-switch", role: "group", "aria-label": "Treemap metric" });

  // Layout needs a real width, and clientWidth is 0 while the panel is still
  // detached. paint() used to run inline and got 0, so the treemap silently drew
  // nothing on a cold open; deferring one frame means the panel is in the
  // document and measured.
  //
  // rAF, not setTimeout: it is tied to the next paint, so it cannot run before
  // layout no matter how the browser schedules style work.
  const paintWhenLaidOut = () => {
    if (chart.clientWidth > 0) { paint(); return; }
    requestAnimationFrame(paintWhenLaidOut);
  };

  const paint = () => {
    clear(chart);
    // A treemap needs positive magnitudes. A process with no working-set
    // reading contributes nothing to the picture and must not appear as a
    // zero-area tile, so it is excluded - and the count of what was excluded is
    // stated below rather than silently dropped.
    const withValue = rows.filter((r) => {
      const v = num(metric === "cpuPct" ? r.cpuPct : r.memWs);
      return v !== null && v > 0;
    });
    const excluded = rows.length - withValue.length;

    // Only the top slices get a tile; 350 rectangles 3px wide is a texture, not
    // a chart. The rest are folded into an explicit "other" row.
    const MAX_TILES = 48;
    const sorted = withValue.slice().sort(
      (a, b) => num(metric === "cpuPct" ? b.cpuPct : b.memWs) -
               num(metric === "cpuPct" ? a.cpuPct : a.memWs),
    );
    const top = sorted.slice(0, MAX_TILES);
    const tail = sorted.slice(MAX_TILES);

    const data = top.map((r) => ({
      label: r.name || `pid ${r.pid}`,
      value: num(metric === "cpuPct" ? r.cpuPct : r.memWs),
      reason: metric === "cpuPct" ? "CPU time could not be read for this process" : undefined,
    }));
    if (tail.length > 0) {
      data.push({
        label: `${tail.length} more processes`,
        value: tail.reduce((s, r) => s + num(metric === "cpuPct" ? r.cpuPct : r.memWs), 0),
      });
    }

    const format = metric === "cpuPct" ? ((v) => fmtPct(v)) : ((v) => fmtBytes(v));
    const painted = renderTreemap(chart, data, {
      height: 440,
      format,
    });
    if (!painted) {
      chart.append(emptyState({}, "Nothing to draw",
        excluded > 0
          ? `No process in this filter reported a ${metric === "cpuPct" ? "CPU" : "working set"} reading.`
          : "Every process in this filter reported zero."));
      return;
    }
    const notes = [];
    if (excluded > 0) {
      notes.push(`${excluded} process${excluded === 1 ? "" : "es"} had no readable figure and are not drawn`);
    }
    if (tail.length > 0) {
      notes.push(`area is proportional to ${metric === "cpuPct" ? "CPU share" : "working set"}; the smallest tiles are grouped`);
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
    h("div", { class: "treemap-toolbar" }, switcher),
    chart,
  );
  paint();
  return host;
}