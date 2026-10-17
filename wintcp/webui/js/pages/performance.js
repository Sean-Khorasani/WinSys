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
  clear(page);
  page.append(
    h("div", { class: "page-heading" },
      h("div", {},
        h("h1", { class: "page-title" }, "Performance"),
        h("p", { class: "page-description" }, "CPU, memory, disk, and network utilisation"),
      ),
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
  await mountCharts(page);
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
  const hosts = [
    { sel: "#perf-chart", series: [
      { key: "cpu.total", label: "CPU %" },
      { key: "memMiB", label: "Memory (MiB)" },
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

  let history;
  try {
    history = await api.get("/api/metrics/history?max=180");
  } catch (err) {
    for (const host of hosts) {
      const el = page.querySelector(host.sel);
      if (el) { clear(el); el.append(emptyState({}, "No history yet", err.message)); }
    }
    return;
  }

  const t = Array.isArray(history.t) ? history.t : [];
  const series = history.series || {};
  const toMiB = (arr) => (arr || []).map((v) => (v === null || v === undefined ? null : v / (1024 * 1024)));

  const charts = [];
  for (const host of hosts) {
    const el = page.querySelector(host.sel);
    if (!el) continue;
    if (t.length < 2) {
      clear(el);
      el.append(emptyState({}, "Collecting samples", `${t.length} sample so far.`));
      continue;
    }
    const values = {};
    for (const def of host.series) {
      values[def.key] = def.key === "memMiB"
        ? toMiB(series["mem.usedBytes"])
        : (series[def.key] || []);
    }
    try {
      charts.push(await createTimeseries(el, { height: 200, data: { t, values }, series: host.series }));
    } catch (err) {
      clear(el);
      el.append(emptyState({}, "Chart unavailable", err.message));
    }
  }

  page._chartDestroy = () => {
    for (const chart of charts) {
      try { chart.destroy(); } catch { /* already gone */ }
    }
  };
}