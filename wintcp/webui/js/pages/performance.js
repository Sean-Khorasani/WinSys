// pages/performance.js - Performance page
//
// Per-core CPU plus disk and network throughput. Per-core comes from
// /api/metrics/now (cpu.core.<n>); the time series comes from
// /api/metrics/history. When /api/capabilities reports perCore=false the page
// says so rather than drawing an empty chart.

import { h, clear } from "../h.js";
import { card, cardHeader, cardTitle, cardDescription, cardContent, emptyState } from "../ui/card.js";
import { api } from "../api.js";
import { fmtPct, fmtBytes } from "../format.js";
import { createTimeseries } from "../charts/timeseries.js";

const UNAVAILABLE = "\u2014";

export async function renderPerformance(page, store) {
  page._perfState = {
    charts: [],
    hosts: null,
    history: null,
    lastHistoryTs: null,
    lastCoreKeys: "",
    lastMetricsTs: null,
    disposed: false,
    loading: true,
    requests: new AbortController(),
  };
  const view = page._perfState;
  page._chartDestroy = () => {
    view.disposed = true;
    view.requests.abort();
    for (const chart of view.charts) {
      try { chart.destroy(); } catch { /* already gone */ }
    }
    view.charts = [];
  };
  clear(page);
  const exportButton = h("button", {
    class: "btn btn-sm btn-quiet",
    type: "button",
    onclick: () => {
      const state = store.get();
      const payload = {
        exportedAt: new Date().toISOString(),
        source: "Performance metrics",
        metricsTimestamp: state.metrics?._timestamp || null,
        capabilities: state.capabilities || null,
        metrics: state.metrics || null,
        note: "Performance measurements distinguish adapter/process/socket data. Unavailable counters carry null + a reason; totals are not rates.",
      };
      const text = JSON.stringify(payload, null, 2);
      const blob = new Blob([text], { type: "application/json;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = `wintcp-performance-${new Date().toISOString().replace(/[:.]/g, "-")}.json`; document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    },
    title: "Export current performance metrics as JSON evidence",
  }, "Export evidence");
  page.append(
    h("div", { class: "page-heading" },
      h("div", {},
        h("h1", { class: "page-title" }, "Performance"),
        h("p", { class: "page-description" }, "CPU, memory, disk, and network utilisation"),
      ),
      h("div", {}, exportButton),
    ),
    h("div", { class: "perf-layout" },
      h("div", { class: "perf-rail", id: "perf-rail" }),
      h("div", { class: "perf-main" },
        card({},
          cardHeader({},
            cardTitle({}, "CPU and memory"),
            cardDescription({}, "Last 15 minutes at 1 Hz"),
          ),
          cardContent({}, h("div", { id: "perf-chart" })),
        ),
        h("div", { style: "height: 1rem" }),
        card({},
          cardHeader({},
            cardTitle({}, "Disk throughput"),
            cardDescription({}, "Read and written bytes per second, summed across volumes"),
          ),
          cardContent({}, h("div", { id: "perf-disk" })),
        ),
        h("div", { style: "height: 1rem" }),
        card({},
          cardHeader({}, cardTitle({}, "Network throughput")),
          cardContent({}, h("div", { id: "perf-net" })),
        ),
      ),
    ),
  );

  renderCoreRail(page, store.get());
  try { await mountCharts(page); }
  finally { view.loading = false; }
}

// Incremental update: refetches fresh history and updates charts via setData
// without destroying the DOM tree. Preserves scroll position and avoids flicker.
export async function updatePerformance(page, store) {
  const state = store.get();
  const ov = page._perfState;
  if (!ov || ov.disposed || ov.loading) return;

  const metricsTs = state.metrics?._timestamp;

  // 1. Update per-core rail if core set changed.
  updateCoreRail(page, state, ov);

  // 2. Fetch fresh history data and update charts.
  if (metricsTs !== ov.lastHistoryTs) {
    ov.lastHistoryTs = metricsTs;
    ov.loading = true;
    try { await refreshCharts(page, ov); }
    finally { ov.loading = false; }
  }
}

function updateCoreRail(page, state, ov) {
  const rail = page.querySelector("#perf-rail");
  if (!rail) return;

  const caps = state.capabilities;
  const metrics = state.metrics || {};
  const coreKeys = Object.keys(metrics)
    .filter((k) => /^cpu\.core\.\d+$/.test(k))
    .sort((a, b) => Number(a.split(".")[2]) - Number(b.split(".")[2]));

  const keysSig = coreKeys.join(",");

  // Only rebuild the rail if the set of cores changed.
  if (keysSig === ov.lastCoreKeys) {
    // Update values in place on existing cells.
    const cells = rail.querySelectorAll(".core-cell");
    if (cells.length === coreKeys.length && coreKeys.length > 0) {
      cells.forEach((cell, i) => {
        const key = coreKeys[i];
        const value = metrics[key];
        const known = value !== null && value !== undefined;
        const pct = known ? Math.max(0, Math.min(100, value)) : 0;
        const bar = cell.querySelector(".core-fill");
        const val = cell.querySelector(".core-value");
        if (bar) bar.style.width = `${pct}%`;
        if (val) val.textContent = known ? fmtPct(value) : UNAVAILABLE;
      });
      return;
    }
  }

  // Core set changed or initial render: rebuild.
  ov.lastCoreKeys = keysSig;

  if (caps && caps.perCore === false) {
    clear(rail);
    rail.append(card({},
      cardHeader({}, cardTitle({}, "Per-core CPU")),
      cardContent({}, emptyState({}, "Not available",
        caps.perCoreReason || "This machine did not expose the per-core counter.")),
    ));
    return;
  }

  if (coreKeys.length === 0) {
    clear(rail);
    rail.append(card({},
      cardHeader({}, cardTitle({}, "Per-core CPU")),
      cardContent({}, emptyState({}, "Waiting for the first sample",
        "The sampler reports per-core utilisation about a second after start.")),
    ));
    return;
  }

  clear(rail);
  const list = h("div", { class: "core-grid", role: "list", "aria-label": "Per-core CPU utilisation" });
  for (const key of coreKeys) {
    const value = metrics[key];
    const known = value !== null && value !== undefined;
    const pct = known ? Math.max(0, Math.min(100, value)) : 0;
    list.append(
      h("div", { class: "core-cell", role: "listitem", title: known ? `${key} = ${fmtPct(value)}` : `${key}: ${metrics[`${key}.reason`] || "unavailable"}` },
        h("div", { class: "core-index" }, key.split(".")[2]),
        h("div", { class: "core-bar" },
          h("div", { class: "core-fill", style: `width: ${pct}%` }),
        ),
        h("div", { class: "core-value num" }, known ? fmtPct(value) : UNAVAILABLE),
      ),
    );
  }
  rail.append(card({},
    cardHeader({}, cardTitle({}, `Per-core CPU (${coreKeys.length})`)),
    cardContent({}, list),
  ));
}

function getHosts() {
  return [
    { sel: "#perf-chart", series: [
      { key: "cpu.total", label: "CPU %" },
      { key: "memMiB", label: "Memory (MiB)", scale: "mem" },
    ] },
    { sel: "#perf-disk", series: [
      { key: "disk.readBps", label: "Read" },
      { key: "disk.writeBps", label: "Write" },
    ] },
    { sel: "#perf-net", series: [
      { key: "net.rxBps", label: "Received" },
      { key: "net.txBps", label: "Sent" },
    ] },
  ];
}

function renderCoreRail(page, state) {
  const rail = page.querySelector("#perf-rail");
  if (!rail) return;
  clear(rail);

  const caps = state.capabilities;
  if (caps && caps.perCore === false) {
    rail.append(card({},
      cardHeader({}, cardTitle({}, "Per-core CPU")),
      cardContent({}, emptyState({}, "Not available",
        caps.perCoreReason || "This machine did not expose the per-core counter.")),
    ));
    return;
  }

  const metrics = state.metrics || {};
  const coreKeys = Object.keys(metrics)
    .filter((k) => /^cpu\.core\.\d+$/.test(k))
    .sort((a, b) => Number(a.split(".")[2]) - Number(b.split(".")[2]));

  if (coreKeys.length === 0) {
    rail.append(card({},
      cardHeader({}, cardTitle({}, "Per-core CPU")),
      cardContent({}, emptyState({}, "Waiting for the first sample",
        "The sampler reports per-core utilisation about a second after start.")),
    ));
    return;
  }

  const list = h("div", { class: "core-grid", role: "list", "aria-label": "Per-core CPU utilisation" });
  for (const key of coreKeys) {
    const value = metrics[key];
    const known = value !== null && value !== undefined;
    const pct = known ? Math.max(0, Math.min(100, value)) : 0;
    list.append(
      h("div", { class: "core-cell", role: "listitem", title: known ? `${key} = ${fmtPct(value)}` : `${key}: ${metrics[`${key}.reason`] || "unavailable"}` },
        h("div", { class: "core-index" }, key.split(".")[2]),
        h("div", { class: "core-bar" },
          h("div", { class: "core-fill", style: `width: ${pct}%` }),
        ),
        h("div", { class: "core-value num" }, known ? fmtPct(value) : UNAVAILABLE),
      ),
    );
  }
  rail.append(card({},
    cardHeader({}, cardTitle({}, `Per-core CPU (${coreKeys.length})`)),
    cardContent({}, list),
  ));
}

async function mountCharts(page) {
  const ov = page._perfState;
  if (!ov) return;
  ov.hosts = getHosts();
  const hosts = ov.hosts;

  let history;
  try {
    history = await api.get("/api/metrics/history?max=180", { signal: ov.requests.signal });
  } catch (err) {
    if (ov.disposed) return;
    for (const host of hosts) {
      const el = page.querySelector(host.sel);
      if (el) { clear(el); el.append(emptyState({}, "No history yet", err.message)); }
    }
    return;
  }

  if (ov.disposed) return;
  ov.history = history;
  const t = Array.isArray(history.t) ? history.t : [];
  const series = history.series || {};
  const toMiB = (arr) => (arr || []).map((v) => (v === null || v === undefined ? null : v / (1024 * 1024)));

  if (t.length < 2) {
    for (const host of hosts) {
      const el = page.querySelector(host.sel);
      if (el) {
        clear(el);
        el.append(emptyState({}, "Collecting samples", `${t.length} sample so far.`));
      }
    }
    return;
  }

  for (const host of hosts) {
    const el = page.querySelector(host.sel);
    if (!el) continue;
    const values = {};
    for (const def of host.series) {
      values[def.key] = def.key === "memMiB"
        ? toMiB(series["mem.usedBytes"])
        : (series[def.key] || []);
    }
    try {
      const entry = await createTimeseries(el, { height: 200, data: { t, values }, series: host.series });
      if (ov.disposed) { entry.destroy(); return; }
      el._chartEntry = entry;
      ov.charts.push(entry);
    } catch (err) {
      if (ov.disposed) return;
      clear(el);
      el.append(emptyState({}, "Chart unavailable", err.message));
    }
  }
}

async function refreshCharts(page, ov) {
  if (!ov.hosts) ov.hosts = getHosts();
  const hosts = ov.hosts;

  let history;
  try {
    history = await api.get("/api/metrics/history?max=180", { signal: ov.requests.signal });
  } catch (err) {
    return;
  }

  if (ov.disposed) return;
  const t = Array.isArray(history.t) ? history.t : [];
  const series = history.series || {};
  const toMiB = (arr) => (arr || []).map((v) => (v === null || v === undefined ? null : v / (1024 * 1024)));

  // If we have enough data and no charts mounted yet, mount them.
  if (ov.charts.length === 0 && t.length >= 2) {
    for (const host of hosts) {
      const el = page.querySelector(host.sel);
      if (!el) continue;
      const values = {};
      for (const def of host.series) {
        values[def.key] = def.key === "memMiB"
          ? toMiB(series["mem.usedBytes"])
          : (series[def.key] || []);
      }
      try {
        const entry = await createTimeseries(el, { height: 200, data: { t, values }, series: host.series });
        if (ov.disposed) { entry.destroy(); return; }
        el._chartEntry = entry;
        ov.charts.push(entry);
      } catch (err) {
        if (ov.disposed) return;
        clear(el);
        el.append(emptyState({}, "Chart unavailable", err.message));
      }
    }
    ov.history = history;
    return;
  }

  // Charts already exist — update them in place via setData.
  if (ov.charts.length === 0) return;

  ov.history = history;
  for (let i = 0; i < ov.charts.length && i < hosts.length; i++) {
    const host = hosts[i];
    const entry = ov.charts[i];
    if (!entry) continue;
    const values = {};
    for (const def of host.series) {
      values[def.key] = def.key === "memMiB"
        ? toMiB(series["mem.usedBytes"])
        : (series[def.key] || []);
    }
    try {
      entry.setData({ t, values });
    } catch (err) {
      console.warn("chart update failed", host.sel, err);
    }
  }

  // Update "Collecting samples" state if we now have enough data.
  if (t.length >= 2) {
    for (const host of hosts) {
      const el = page.querySelector(host.sel);
      if (!el) continue;
      // If the container still has the empty state child, replace it.
      const emptyStateChild = el.querySelector(".empty-state");
      if (emptyStateChild) {
        clear(el);
        try {
          const entry = await createTimeseries(el, { height: 200, data: { t, values: buildValues(host, series, toMiB) }, series: host.series });
          if (ov.disposed) { entry.destroy(); return; }
          el._chartEntry = entry;
          ov.charts.push(entry);
        } catch (err) {
          if (ov.disposed) return;
          clear(el);
          el.append(emptyState({}, "Chart unavailable", err.message));
        }
      }
    }
  }
}

function buildValues(host, series, toMiB) {
  const values = {};
  for (const def of host.series) {
    values[def.key] = def.key === "memMiB"
      ? toMiB(series["mem.usedBytes"])
      : (series[def.key] || []);
  }
  return values;
}
