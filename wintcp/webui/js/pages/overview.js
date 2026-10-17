// pages/overview.js - Overview page
//
// Live KPIs plus two uPlot charts fed from /api/metrics/history. The history
// endpoint is a separate request on purpose: /api/metrics/now is the current
// value (cheap, polled every refresh), while the chart needs the 15-minute
// series, and the server is sequential (C-8) so the browser asks for them at
// their own cadences rather than the poll dragging a large body every 2 s.

import { h, clear } from "../h.js";
import { fmtNum, fmtBytes, fmtPct } from "../format.js";
import { card, cardHeader, cardTitle, cardDescription, cardContent, emptyState } from "../ui/card.js";
import { api } from "../api.js";
import { createTimeseries } from "../charts/timeseries.js";

const UNAVAILABLE = "\u2014";

function kpiValue(metrics, key, format) {
  if (!metrics) return UNAVAILABLE;
  const value = metrics[key];
  if (value === null || value === undefined) {
    // C-6: say WHY it is unavailable instead of showing a dash with no context.
    const reason = metrics[`${key}.reason`];
    return h("span", { class: "kpi-value-unavailable", title: reason || "unavailable" },
      UNAVAILABLE);
  }
  return format(value);
}

export async function renderOverview(page, store) {
  clear(page);
  page.append(
    h("div", { class: "page-heading" },
      h("div", {},
        h("h1", { class: "page-title" }, "Overview"),
        h("p", { class: "page-description" }, "Live system and network overview"),
      ),
      h("div", { id: "overview-updated", class: "muted text-sm" }),
    ),
    h("div", { class: "kpi-grid", id: "kpi-grid" }),
    h("div", { class: "chart-grid" },
      card({},
        cardHeader({},
          cardTitle({}, "CPU and memory"),
          cardDescription({}, "Last 15 minutes, one sample per second"),
        ),
        cardContent({}, h("div", { id: "chart-cpu-mem" })),
      ),
      card({},
        cardHeader({},
          cardTitle({}, "Network throughput"),
          cardDescription({}, "Received and sent, per second"),
        ),
        cardContent({}, h("div", { id: "chart-network" })),
      ),
    ),
  );

  const state = store.get();
  const metrics = state.metrics;
  const conns = state.connections || [];
  const processes = state.processes || [];
  const kpiGrid = page.querySelector("#kpi-grid");

  const kpis = [
    { label: "CPU", value: kpiValue(metrics, "cpu.total", (v) => fmtPct(v)) },
    { label: "Memory", value: kpiValue(metrics, "mem.usedBytes", (v) => fmtBytes(v)) },
    { label: "Disk read", value: kpiValue(metrics, "disk.readBps", (v) => `${fmtBytes(v)}/s`) },
    { label: "Disk write", value: kpiValue(metrics, "disk.writeBps", (v) => `${fmtBytes(v)}/s`) },
    { label: "Network in", value: kpiValue(metrics, "net.rxBps", (v) => `${fmtBytes(v)}/s`) },
    { label: "Network out", value: kpiValue(metrics, "net.txBps", (v) => `${fmtBytes(v)}/s`) },
    { label: "Endpoints", value: fmtNum(conns.length) },
    { label: "Processes", value: fmtNum(processes.length || new Set(conns.map((c) => c.pid)).size) },
  ];
  for (const kpi of kpis) {
    kpiGrid.append(
      h("div", { class: "kpi-card" },
        h("div", { class: "kpi-label" }, kpi.label),
        h("div", { class: "kpi-value num" }, kpi.value),
      ),
    );
  }

  const stamp = page.querySelector("#overview-updated");
  if (state.lastUpdate) {
    stamp.textContent = `Updated ${state.lastUpdate.toLocaleTimeString()}`;
  }

  await mountCharts(page);
}

async function mountCharts(page) {
  const cpuHost = page.querySelector("#chart-cpu-mem");
  const netHost = page.querySelector("#chart-network");
  if (!cpuHost || !netHost) return;

  let history;
  try {
    history = await api.get("/api/metrics/history?max=180");
  } catch (err) {
    for (const host of [cpuHost, netHost]) {
      clear(host);
      host.append(emptyState({}, "No history yet",
        "The sampler keeps 15 minutes of 1 Hz samples. This fills in shortly."));
    }
    return;
  }

  const t = Array.isArray(history.t) ? history.t : [];
  const series = history.series || {};
  const values = {
    "cpu.total": series["cpu.total"] || [],
    "mem.usedBytes": series["mem.usedBytes"] || [],
    "net.rxBps": series["net.rxBps"] || [],
    "net.txBps": series["net.txBps"] || [],
  };

  if (t.length < 2) {
    for (const host of [cpuHost, netHost]) {
      clear(host);
      host.append(emptyState({}, "Collecting samples",
        `${t.length} sample so far. The chart needs at least two.`));
    }
    return;
  }

  // Memory is a large absolute byte count; divide to MiB so it can share a
  // percentage axis with nothing else. Nulls stay null: dividing null would
  // produce 0 and turn "unknown" into "idle" (C-6).
  const toMiB = (arr) => arr.map((v) => (v === null || v === undefined ? null : v / (1024 * 1024)));

  const charts = [];
  try {
    charts.push(await createTimeseries(cpuHost, {
      height: 220,
      data: { t, values: { "cpu.total": values["cpu.total"], memoryMiB: toMiB(values["mem.usedBytes"]) } },
      series: [
        { key: "cpu.total", label: "CPU %" },
        { key: "memoryMiB", label: "Memory (MiB)" },
      ],
    }));
  } catch (err) {
    clear(cpuHost);
    cpuHost.append(emptyState({}, "Chart unavailable", err.message));
  }

  try {
    charts.push(await createTimeseries(netHost, {
      height: 220,
      data: { t, values: { "net.rxBps": values["net.rxBps"], "net.txBps": values["net.txBps"] } },
      series: [
        { key: "net.rxBps", label: "Received" },
        { key: "net.txBps", label: "Sent" },
      ],
    }));
  } catch (err) {
    clear(netHost);
    netHost.append(emptyState({}, "Chart unavailable", err.message));
  }

  // The router clears this element on the next render, so tear the charts down
  // explicitly - uPlot holds a canvas, a ResizeObserver and a window listener.
  page._chartDestroy = () => {
    for (const chart of charts) {
      try { chart.destroy(); } catch { /* already gone */ }
    }
  };
}