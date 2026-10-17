// pages/overview.js - Overview page
import { h } from "../h.js";
import { fmtNum, fmtBytes, fmtPct } from "../format.js";
import { card, cardHeader, cardTitle, cardContent } from "../ui/card.js";

export async function renderOverview(page, store) {
  page.innerHTML = "";
  page.append(
    h("div", { class: "page-heading" },
      h("div", {},
        h("h1", { class: "page-title" }, "Overview"),
        h("p", { class: "page-description" }, "Live system and network overview"),
      ),
    ),
    h("div", { class: "kpi-grid", id: "kpi-grid" }),
    h("div", { class: "chart-grid", id: "chart-grid" }),
  );

  const kpiGrid = page.querySelector("#kpi-grid");
  const state = store.get();
  const conns = state.connections || [];
  const processes = new Set(conns.map(c => c.pid)).size;

  const kpis = [
    { label: "CPU", value: state.metrics && state.metrics["cpu.total"] != null ? fmtPct(state.metrics["cpu.total"]) : "-" },
    { label: "Memory", value: state.metrics && state.metrics["mem.usedBytes"] != null ? fmtBytes(state.metrics["mem.usedBytes"]) : "-" },
    { label: "Disk Read", value: state.metrics && state.metrics["disk.readBps"] != null ? fmtBytes(state.metrics["disk.readBps"]) + "/s" : "-" },
    { label: "Network RX", value: state.metrics && state.metrics["net.rxBps"] != null ? fmtBytes(state.metrics["net.rxBps"]) + "/s" : "-" },
    { label: "Connections", value: String(conns.length) },
    { label: "Processes", value: String(processes) },
  ];

  for (const kpi of kpis) {
    kpiGrid.append(
      h("div", { class: "kpi-card" },
        h("div", { class: "kpi-label" }, kpi.label),
        h("div", { class: "kpi-value num" }, kpi.value),
      ),
    );
  }

  const chartGrid = page.querySelector("#chart-grid");
  chartGrid.append(
    h("div", { class: "card" },
      cardHeader({}, cardTitle({}, "CPU and Memory (Live)")),
      cardContent({}, h("div", { class: "chart-container", id: "chart-cpu-mem" })),
    ),
    h("div", { class: "card" },
      cardHeader({}, cardTitle({}, "Network Throughput")),
      cardContent({}, h("div", { class: "chart-container", id: "chart-network" })),
    ),
  );
}
