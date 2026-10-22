// pages/overview.js - Overview page
//
// Real data, no decoration. Every chart and every sparkline on this page is
// drawn from /api/metrics/history; every KPI card states its own unit and
// period. The old version of this page showed four bare numbers with no trend,
// no delta and no context, which is not an overview of anything.
//
// Request shape note: /api/metrics/now is the current value (cheap, polled with
// everything else) while /api/metrics/history is the 15-minute series. They are
// separate requests on purpose - the server is sequential (C-8), so a 60 KB
// history body must not ride along on every 2 s poll.

import { h, clear } from "../h.js";
import { liveConnectionSummary } from "../connections.js";
import { fmtNum, fmtInt, fmtBytes, fmtBps, fmtPct, fmtUptime, fmtDuration } from "../format.js";
import { card, cardHeader, cardTitle, cardDescription, cardContent, cardFooter, emptyState } from "../ui/card.js";
import { api } from "../api.js";
import { createTimeseries } from "../charts/timeseries.js";
import { sparkline, barList } from "../charts/sparkline.js";

function currentLiveSummary(state) {
  if (!state.lastUpdate || !Array.isArray(state.connections)) return null;
  return liveConnectionSummary(state.connections);
}

const UNAVAILABLE = "\u2014";
// How far back the "delta versus 5 minutes ago" compares. Five minutes is the
// short/medium boundary in the range picker and is long enough that a delta is
// not just the last two samples.
const DELTA_WINDOW_S = 300;

// ---- KPI card ---------------------------------------------------------------

function deltaOf(series, t, windowSeconds = DELTA_WINDOW_S) {
  // Compare the newest reading with the reading nearest `windowSeconds` ago.
  // Returns null when either end is unknown, so a delta is never computed across
  // a gap - a delta between two nulls is 0, which reads as "no change".
  if (!Array.isArray(t) || t.length < 2 || !Array.isArray(series)) return null;
  const newestT = t[t.length - 1];
  const targetT = newestT - windowSeconds;
  let bestIndex = -1;
  let bestDelta = Infinity;
  for (let i = 0; i < t.length; i += 1) {
    const d = Math.abs(t[i] - targetT);
    if (d < bestDelta) { bestDelta = d; bestIndex = i; }
  }
  // Only trust a baseline that is actually near the target time; otherwise the
  // "5 minutes ago" figure is really "90 seconds ago" wearing its label.
  if (bestIndex < 0 || bestDelta > 15) return null;
  const now = series[series.length - 1];
  const then = series[bestIndex];
  if (now == null || then == null || Number.isNaN(now) || Number.isNaN(then)) return null;
  return { now, then, thenT: t[bestIndex], secondsAgo: newestT - t[bestIndex] };
}

// Deltas on a rate/byte/gauge are shown as a percentage change; on a level like
// memory-used they are shown as an absolute difference, because "memory is up
// 4.2%" is less useful than "up 240 MiB" and the percentage of a 24 GiB working
// set hides the size of the move.
function renderDelta(delta, mode, format) {
  if (!delta) return null;
  const diff = delta.now - delta.then;
  if (Math.abs(diff) < 1e-9) {
    return h("span", { class: "kpi-delta kpi-delta-flat", title: "unchanged over the period" }, "no change");
  }
  const up = diff > 0;
  // For bytes and rates, "down" is the good direction on almost every card here
  // except memory, so the colour is deliberately neutral rather than a moral
  // judgement. A red "down" arrow on disk write rate would be a lie about what
  // the user wants.
  const tone = up ? "up" : "down";
  const sign = up ? "+" : "\u2212";
  const magnitude = mode === "absolute"
    ? format(Math.abs(diff))
    : fmtPct(Math.abs(diff / (Math.abs(delta.then) || 1)) * 100);
  return h("span",
    { class: `kpi-delta kpi-delta-${tone}`, title: `versus ${fmtDuration(delta.secondsAgo)} ago` },
    `${sign}${magnitude}`,
  );
}

function kpiCard(spec) {
  const valueNode = h("div", { class: "kpi-value num" });
  if (Array.isArray(spec.value)) {
    // Two-figure cards (disk read/write, network down/up) stack instead of
    // sharing one line. On one line the second figure was ellipsis-truncated to
    // "147...." by the single-line clamp, so the card showed half a number and
    // a full stop, which reads as a rendering fault rather than a value.
    valueNode.classList.add("kpi-value-stack");
    spec.value.forEach((part, i) => {
      const line = h("div", { class: "kpi-value-line" });
      if (part == null) {
        line.append(h("span", { class: "kpi-value-unavailable", title: spec.reason || "unavailable" }, UNAVAILABLE));
      } else {
        line.textContent = spec.format(part);
      }
      // Two bare numbers stacked are ambiguous: which is read and which is
      // written? The hint rides on the line's tooltip and is only rendered when
      // a sparkline is NOT sitting beside it, so it never crowds the card.
      if (spec.valueHints && spec.valueHints[i]) {
        line.title = spec.valueHints[i];
        if (!spec.hasSpark) line.append(h("span", { class: "kpi-line-hint muted" }, spec.valueHints[i]));
      }
      valueNode.append(line);
    });
  } else if (spec.known) {
    valueNode.textContent = spec.format(spec.value);
  } else {
    valueNode.append(
      h("span", { class: "kpi-value-unavailable", title: spec.reason || "unavailable" }, UNAVAILABLE),
    );
  }

  const cardNode = card({ class: "kpi-card" },
    h("div", { class: "kpi-head" },
      h("div", { class: "kpi-label" }, spec.label),
      spec.delta ? renderDelta(spec.delta, spec.deltaMode, spec.format) : null,
    ),
    h("div", { class: "kpi-figure" },
      valueNode,
      // The sparkline is only drawn when there is something to draw. An empty
      // frame next to a number reads as a broken chart.
      h("div", { class: "kpi-spark" }),
    ),
    h("div", { class: "kpi-foot muted text-sm" }, spec.foot),
  );
  cardNode.dataset.kpi = spec.id;
  if (!spec.known) {
    cardNode.classList.add("kpi-card-unknown");
    cardNode.setAttribute("title", spec.reason || "unavailable");
  }
  return cardNode;
}

// ---- page -------------------------------------------------------------------

export async function renderOverview(page, store) {
  clear(page);

  page.append(
    h("div", { class: "page-heading" },
      h("div", {},
        h("h1", { class: "page-title" }, "Overview"),
        h("p", { class: "page-description" },
          "Live system and network state. Every figure is measured on this machine; " +
          "anything Windows did not report is shown as \u2014 with the reason."),
      ),
      h("div", { id: "overview-updated", class: "muted text-sm" }),
    ),
    h("div", { class: "kpi-grid", id: "kpi-grid" }),
    h("div", { class: "chart-grid" },
      card({},
        cardHeader({},
          cardTitle({}, "CPU and memory"),
          cardDescription({}, "Last 15 minutes, one sample per second. Memory is the committed working set."),
        ),
        cardContent({}, h("div", { id: "chart-cpu-mem" })),
      ),
      card({},
        cardHeader({},
          cardTitle({}, "Disk throughput"),
          cardDescription({}, "Physical disk read and written bytes per second, summed across volumes"),
        ),
        cardContent({}, h("div", { id: "chart-disk" })),
      ),
      card({},
        cardHeader({},
          cardTitle({}, "Network throughput"),
          cardDescription({}, "Received and sent bytes per second across all adapters"),
        ),
        cardContent({}, h("div", { id: "chart-network" })),
      ),
    ),
    h("div", { class: "card-grid-3", id: "overview-breakdown" }),
    h("div", { class: "card-grid-2" },
      card({},
        cardHeader({},
          cardTitle({}, "Top processes by CPU"),
          cardDescription({}, "Percent of total CPU across all logical processors"),
        ),
        cardContent({}, h("div", { id: "overview-procs" })),
        cardFooter({}, h("a", { class: "link", href: "#/processes" }, "Open the process list")),
      ),
      card({},
        cardHeader({},
          cardTitle({}, "Connections by state"),
          cardDescription({}, "Counted from the live connection table"),
        ),
        cardContent({}, h("div", { id: "overview-states" })),
        cardFooter({}, h("a", { class: "link", href: "#/network" }, "Open the network view")),
      ),
    ),
  );

  // State holders for incremental updates: store references to chart instances
  // and KPI card value nodes so updateOverview can patch them without a full
  // DOM teardown. The page object carries these so main.js can reach them.
  page._overviewState = {
    charts: new Map(),
    kpiCards: new Map(),
    lastMetricsTs: null,
    lastConnectionSnapshotTs: null,
    lastHistoryTs: null,
    prevVolumeSignature: "",
    disposed: false,
    loading: true,
    requests: new AbortController(),
  };
  const view = page._overviewState;
  page._chartDestroy = () => {
    view.disposed = true;
    view.requests.abort();
    for (const info of view.charts.values()) info.entry.destroy();
    view.charts.clear();
  };

  const state = store.get();
  const stamp = page.querySelector("#overview-updated");
  if (state.lastUpdate) {
    stamp.textContent = `Updated ${state.lastUpdate.toLocaleTimeString()}`;
  } else {
    stamp.textContent = "Waiting for the first poll";
  }

  renderKpis(page, state);
  renderBreakdowns(page, state);

  try {
    await Promise.all([mountCharts(page), mountProcesses(page)]);
  } finally {
    view.loading = false;
  }
  if (view.disposed) return;

  // Render connections by state on first mount.
  renderConnectionStates(page, state);
}

// Incremental update: patches KPI values, sparklines, chart data, and breakdowns
// in place without destroying the DOM tree. Preserves scroll position, focus,
// and avoids the flicker/jump of a full re-render.
export async function updateOverview(page, store) {
  const state = store.get();
  const ov = page._overviewState;
  if (!ov || ov.disposed || ov.loading) {
    // Not yet initialized; defer to the next poll after the first render.
    return;
  }

  // 1. Update timestamp.
  const stamp = page.querySelector("#overview-updated");
  if (stamp && state.lastUpdate) {
    stamp.textContent = `Updated ${state.lastUpdate.toLocaleTimeString()}`;
  }

  // 2. Update KPI values when metrics or the connection snapshot changes.
  const metricsTs = state.metrics?._timestamp;
  const connectionSnapshotTs = state.lastUpdate instanceof Date
    ? state.lastUpdate.getTime()
    : null;
  if (metricsTs !== ov.lastMetricsTs ||
      connectionSnapshotTs !== ov.lastConnectionSnapshotTs) {
    ov.lastMetricsTs = metricsTs;
    ov.lastConnectionSnapshotTs = connectionSnapshotTs;
    updateKpiValues(page, state, ov);
  }

  // 3. Fetch fresh history data and update sparklines + deltas.
  // History is refetched on every poll so sparklines and KPI deltas track
  // live data. The previous code gated on ov.sparkData, but sparkData is
  // only set inside mountCharts when t.length >= 2 — so if the first fetch
  // had < 2 samples, the condition was never re-evaluated and the charts
  // never got data.
  ov.loading = true;
  try {
    const history = await api.get("/api/metrics/history?max=300", { signal: ov.requests.signal });
    if (ov.disposed) return;
    if (history && history.t) {
      ov.history = history;
      const t = Array.isArray(history.t) ? history.t : [];
      const raw = history.series || {};
      const tail = (key, n) => (raw[key] || []).slice(-n);
      ov.sparkData = {
        cpu: tail("cpu.total", 60),
        memory: tail("mem.usedBytes", 60),
        disk: [tail("disk.readBps", 60), tail("disk.writeBps", 60)],
        network: [tail("net.rxBps", 60), tail("net.txBps", 60)],
        connections: [],
        processes: [],
      };
      paintTrends(page, ov.sparkData, t, raw);

      // 4. Mount or update charts via setData (no destroy/recreate).
      if (t.length >= 2) {
        if (ov.charts.size === 0) {
          // Charts not yet created; mount them now.
          await mountCharts(page);
        } else {
          updateCharts(page, ov);
        }
      }
    }
  } catch (err) {
    // Network error fetching history; keep the existing sparkData.
  } finally {
    ov.loading = false;
  }
  if (ov.disposed) return;

  // 5. Update breakdowns if network summary or process data changed.
  updateBreakdowns(page, state, ov);

  // 6. Update top processes list.
  updateProcesses(page, state);

  // 7. Update connections by state.
  updateConnectionStates(page, state);
}

// Update KPIs by patching existing card nodes in place.
function updateKpiValues(page, state, ov) {
  const metrics = state.metrics || {};
  const connectionSummary = currentLiveSummary(state);
  const total = connectionSummary?.total ?? 0;
  const byState = connectionSummary?.byState || {};
  const established = byState.ESTABLISHED ?? null;
  const listening = byState.LISTENING ?? null;

  const read = (key) => ({
    known: metrics[key] !== null && metrics[key] !== undefined && !Number.isNaN(metrics[key]),
    value: metrics[key],
    reason: metrics[`${key}.reason`] || "the sampler has not reported this series yet",
  });

  // CPU
  updateKpiCard(page, "cpu", (card) => {
    const r = read("cpu.total");
    const valueNode = card.querySelector(".kpi-value");
    if (!valueNode) return;
    if (r.known) {
      valueNode.innerHTML = "";
      valueNode.textContent = fmtPct(r.value);
    } else {
      valueNode.innerHTML = "";
      valueNode.append(
        h("span", { class: "kpi-value-unavailable", title: r.reason }, UNAVAILABLE),
      );
    }
  });

  // Memory
  updateKpiCard(page, "memory", (card) => {
    const r = read("mem.usedBytes");
    const valueNode = card.querySelector(".kpi-value");
    if (!valueNode) return;
    if (r.known) {
      valueNode.innerHTML = "";
      valueNode.textContent = fmtBytes(r.value);
    } else {
      valueNode.innerHTML = "";
      valueNode.append(
        h("span", { class: "kpi-value-unavailable", title: r.reason }, UNAVAILABLE),
      );
    }
    const foot = card.querySelector(".kpi-foot");
    if (foot && metrics["mem.totalBytes"] != null) {
      foot.textContent = `of ${fmtBytes(metrics["mem.totalBytes"])} installed`;
    }
  });

  // Disk
  updateKpiCard(page, "disk", (card) => {
    const r = read("disk.readBps");
    const w = read("disk.writeBps");
    const valueNode = card.querySelector(".kpi-value");
    if (!valueNode) return;
    valueNode.innerHTML = "";
    valueNode.classList.toggle("kpi-value-stack", true);
    const lines = [r, w];
    const hints = ["read", "written"];
    lines.forEach((part, i) => {
      const line = h("div", { class: "kpi-value-line" });
      if (part == null || !part.known) {
        line.append(h("span", { class: "kpi-value-unavailable", title: part?.reason || "unavailable" }, UNAVAILABLE));
      } else {
        line.textContent = fmtBps(part.value);
      }
      if (hints[i]) {
        line.title = hints[i];
        if (!card.querySelector(".kpi-spark")) line.append(h("span", { class: "kpi-line-hint muted" }, hints[i]));
      }
      valueNode.append(line);
    });
  });

  // Network
  updateKpiCard(page, "network", (card) => {
    const d = read("net.rxBps");
    const u = read("net.txBps");
    const valueNode = card.querySelector(".kpi-value");
    if (!valueNode) return;
    valueNode.innerHTML = "";
    valueNode.classList.toggle("kpi-value-stack", true);
    const lines = [d, u];
    const hints = ["received", "sent"];
    lines.forEach((part, i) => {
      const line = h("div", { class: "kpi-value-line" });
      if (part == null || !part.known) {
        line.append(h("span", { class: "kpi-value-unavailable", title: part?.reason || "unavailable" }, UNAVAILABLE));
      } else {
        line.textContent = fmtBps(part.value);
      }
      if (hints[i]) {
        line.title = hints[i];
        if (!card.querySelector(".kpi-spark")) line.append(h("span", { class: "kpi-line-hint muted" }, hints[i]));
      }
      valueNode.append(line);
    });
  });

  // Connections
  updateKpiCard(page, "connections", (card) => {
    const valueNode = card.querySelector(".kpi-value");
    if (!valueNode) return;
    valueNode.innerHTML = "";
    if (connectionSummary) {
      valueNode.textContent = fmtInt(total);
    } else {
      valueNode.append(h("span", {
        class: "kpi-value-unavailable",
        title: "the connection snapshot has not been sampled yet",
      }, UNAVAILABLE));
    }
    card.classList.toggle("kpi-card-unknown", connectionSummary === null);
    if (connectionSummary) card.removeAttribute("title");
    else card.setAttribute("title", "the connection snapshot has not been sampled yet");
    const foot = card.querySelector(".kpi-foot");
    if (foot) {
      foot.textContent = !connectionSummary
        ? "connection snapshot not sampled yet"
        : established != null
        ? `${fmtInt(established)} established \u00b7 ${fmtInt(listening ?? 0)} listening`
        : "state breakdown not sampled yet";
    }
  });

  // Processes
  updateKpiCard(page, "processes", (card) => {
    const known = state.processCountKnown === true || (Array.isArray(state.processes) && state.processes.length > 0);
    const count = state.processCount ?? (state.processes ? state.processes.length : 0);
    const valueNode = card.querySelector(".kpi-value");
    if (!valueNode) return;
    valueNode.innerHTML = "";
    if (known) {
      valueNode.textContent = fmtInt(count);
    } else {
      valueNode.append(
        h("span", { class: "kpi-value-unavailable", title: "the process table has not been sampled yet" }, UNAVAILABLE),
      );
    }
    const foot = card.querySelector(".kpi-foot");
    if (foot) {
      foot.textContent = state.sysUptime != null
        ? `up ${fmtUptime(state.sysUptime)}`
        : "uptime not sampled yet";
    }
  });
}

function updateKpiCard(page, id, renderFn) {
  const card = page.querySelector(`[data-kpi="${id}"]`);
  if (!card) return;
  try {
    renderFn(card);
  } catch (e) {
    console.warn(`KPI update failed for ${id}`, e);
  }
}

// Update the breakdown cards in place.
function updateBreakdowns(page, state, ov) {
  const host = page.querySelector("#overview-breakdown");
  if (!host) return;

  const summary = state.networkSummary || null;
  const metrics = state.metrics || {};
  const facts = metrics.facts || {};

  // Listeners by exposure - update values in place.
  const listeners = summary ? summary.listeners : null;
  const exposureCard = host.querySelector(":scope > .card");
  if (exposureCard) {
    const existingGrid = exposureCard.querySelector(".exposure-grid");
    if (existingGrid) {
      const cells = existingGrid.querySelectorAll(".exposure-value");
      const keys = ["wildcard", "lan", "loopback"];
      keys.forEach((key, i) => {
        if (cells[i]) {
          cells[i].textContent = listeners ? fmtInt(listeners[key] ?? 0) : "—";
        }
      });
    } else if (listeners) {
      // Grid didn't exist yet (first time data arrived); build it.
      const contentBox = exposureCard.querySelector(".card-content");
      if (contentBox) {
        clear(contentBox);
        const list = h("div", { class: "exposure-grid" });
        for (const [key, label, hint] of [
          ["wildcard", "Wildcard", "binds every interface, reachable from the network"],
          ["lan", "LAN", "binds one specific address"],
          ["loopback", "Loopback", "reachable only from this machine"],
        ]) {
          list.append(h("div", { class: "exposure-cell", title: hint },
            h("div", { class: "exposure-value num" }, fmtInt(listeners[key] ?? 0)),
            h("div", { class: "exposure-label" }, label),
          ));
        }
        contentBox.append(list);
      }
    }
  }

  // Volumes - only rebuild if the volume set changed.
  const volCard = host.querySelectorAll(":scope > .card")[1];
  if (volCard && Array.isArray(facts.volumes)) {
    const volumeSignature = facts.volumes.map((vol) =>
      `${vol.label || ""}:${vol.totalBytes || 0}:${vol.freeBytes || 0}`).join("|");
    if (ov.prevVolumeSignature !== volumeSignature) {
      ov.prevVolumeSignature = volumeSignature;
      const contentBox = volCard.querySelector(".card-content");
      if (contentBox) {
        clear(contentBox);
        const volumes = facts.volumes;
        if (volumes.length === 0) {
          contentBox.append(emptyState({}, "No volumes reported",
            "GetDiskFreeSpaceEx returned nothing for any mounted drive."));
        } else {
          const list = h("div", { class: "volume-list" });
          for (const vol of volumes) {
            const total = Number(vol.totalBytes) || 0;
            const free = Number(vol.freeBytes) || 0;
            const pct = total > 0 ? Math.max(0, Math.min(100, ((total - free) / total) * 100)) : 0;
            list.append(h("div", { class: "volume-row" },
              h("span", { class: "volume-label" },
                h("strong", {}, vol.label || "?"),
                vol.volumeName ? h("span", { class: "muted" }, ` ${vol.volumeName}`) : null,
                h("span", { class: "muted text-sm" }, ` ${vol.fileSystem || "?"}`),
              ),
              h("span", { class: "volume-track", "aria-hidden": "true" },
                h("span", { class: `volume-fill${pct > 90 ? " volume-fill-warn" : ""}`, style: `width:${pct.toFixed(1)}%` }),
              ),
              h("span", { class: "volume-value num" },
                `${fmtBytes(free)} free of ${fmtBytes(total)}`),
            ));
          }
          contentBox.append(list);
        }
      }
    }
  }
}

// Update the top processes list in place.
function updateProcesses(page, state) {
  const host = page.querySelector("#overview-procs");
  if (!host) return;
  const processes = state.processes || [];
  const known = state.processesKnown !== false;
  if (!known || processes.length === 0) return;

  let listEl = host.querySelector(".proc-mini");
  if (!listEl) {
    clear(host);
    listEl = h("div", { class: "proc-mini" });
    host.append(listEl);
  }

  const usable = processes
    .filter((r) => r.cpuPct != null)
    .sort((a, b) => (b.cpuPct || 0) - (a.cpuPct || 0))
    .slice(0, 8);

  // Diff against existing rows for a targeted update.
  const existing = Array.from(listEl.querySelectorAll(".proc-mini-row"));
  const maxLen = Math.max(existing.length, usable.length);

  for (let i = 0; i < maxLen; i++) {
    const rowData = usable[i];
    if (i < existing.length && rowData) {
      // Update existing row in place.
      const row = existing[i];
      const nameEl = row.querySelector(".proc-mini-name");
      const fillEl = row.querySelector(".proc-mini-fill");
      const valEl = row.querySelector(".proc-mini-value");
      if (nameEl) {
        nameEl.textContent = rowData.name || "(unnamed)";
        nameEl.title = rowData.path || rowData.name;
      }
      if (fillEl) {
        fillEl.style.width = `${Math.max(1, Math.min(100, rowData.cpuPct)).toFixed(1)}%`;
      }
      if (valEl) {
        valEl.textContent = fmtPct(rowData.cpuPct);
      }
    } else if (rowData && i >= existing.length) {
      // Append new row.
      listEl.append(h("div", { class: "proc-mini-row" },
        h("span", { class: "proc-mini-name", dir: "auto", title: rowData.path || rowData.name }, rowData.name || "(unnamed)"),
        h("span", { class: "proc-mini-bar", "aria-hidden": "true" },
          h("span", {
            class: "proc-mini-fill",
            style: `width:${Math.max(1, Math.min(100, rowData.cpuPct)).toFixed(1)}%`,
          }),
        ),
        h("span", { class: "proc-mini-value num" }, fmtPct(rowData.cpuPct)),
      ));
    }
  }

  // Remove excess rows.
  for (let i = usable.length; i < existing.length; i++) {
    existing[i]?.remove();
  }
}

// Update connections-by-state breakdown in place.
function updateConnectionStates(page, state) {
  const host = page.querySelector("#overview-states");
  if (!host) return;
  const summary = currentLiveSummary(state);
  if (!summary) {
    clear(host);
    return;
  }
  const byState = summary.byState;
  const states = [
    { key: "ESTABLISHED", label: "Established", color: "info" },
    { key: "LISTENING", label: "Listening", color: "accent" },
    { key: "TIME_WAIT", label: "Time wait", color: "muted" },
    { key: "CLOSE_WAIT", label: "Close wait", color: "warning" },
    { key: "SYN_SENT", label: "SYN sent", color: "destructive" },
  ];

  let grid = host.querySelector(".state-grid");
  if (!grid) {
    clear(host);
    grid = h("div", { class: "state-grid" });
    host.append(grid);
  }

  const existing = Array.from(grid.children);
  // Match/reuse by state key.
  const used = new Set();
  for (const s of states) {
    const count = byState[s.key];
    if (count == null) continue;
    let cell = existing.find((el) => !used.has(el) && el.dataset.state === s.key);
    if (!cell) {
      cell = h("div", { class: `state-cell state-${s.color}`, "data-state": s.key },
        h("div", { class: "state-value num" }, ""),
        h("div", { class: "state-label" }, s.label),
      );
      grid.append(cell);
    }
    used.add(cell);
    const valEl = cell.querySelector(".state-value");
    if (valEl) valEl.textContent = fmtInt(count);
  }

  // Remove cells for states no longer present.
  for (const cell of existing) {
    if (!used.has(cell)) cell.remove();
  }
}

// Initial render of connections by state (called once after mount).
function renderConnectionStates(page, state) {
  const host = page.querySelector("#overview-states");
  if (!host) return;
  updateConnectionStates(page, state);
}

function renderKpis(page, state) {
  const grid = page.querySelector("#kpi-grid");
  clear(grid);
  const metrics = state.metrics || {};
  const connectionSummary = currentLiveSummary(state);
  const total = connectionSummary?.total ?? 0;

  const byState = connectionSummary?.byState || {};
  const established = byState.ESTABLISHED ?? null;
  const listening = byState.LISTENING ?? null;

  // Reading helper: a value plus whether it is a measurement. Absence is null,
  // and the card says why.
  const read = (key) => ({
    known: metrics[key] !== null && metrics[key] !== undefined && !Number.isNaN(metrics[key]),
    value: metrics[key],
    reason: metrics[`${key}.reason`] || "the sampler has not reported this series yet",
  });

  const cards = [
    {
      id: "cpu",
      label: "CPU",
      ...read("cpu.total"),
      format: (v) => fmtPct(v),
      foot: "\u00a0",
    },
    {
      id: "memory",
      label: "Memory in use",
      ...read("mem.usedBytes"),
      format: (v) => fmtBytes(v),
      foot: `of ${metrics["mem.totalBytes"] != null ? fmtBytes(metrics["mem.totalBytes"]) : UNAVAILABLE} installed`,
    },
    {
      id: "disk",
      label: "Disk read / write",
      ...(() => {
        const r = read("disk.readBps");
        const w = read("disk.writeBps");
        return {
          known: r.known || w.known,
          // A single scalar per line: the card stacks them, and a format
          // function that took a pair would have to know which half to print.
          value: [r.known ? r.value : null, w.known ? w.value : null],
          reason: r.reason,
          format: (v) => fmtBps(v),
          valueHints: ["read", "written"],
        };
      })(),
      foot: "physical disk bytes per second",
    },
    {
      id: "network",
      label: "Network down / up",
      ...(() => {
        const d = read("net.rxBps");
        const u = read("net.txBps");
        return {
          known: d.known || u.known,
          value: [d.known ? d.value : null, u.known ? u.value : null],
          reason: d.reason,
          format: (v) => fmtBps(v),
          valueHints: ["received", "sent"],
        };
      })(),
      foot: "observed bytes per second, not bandwidth",
    },
    {
      id: "connections",
      label: "Connections",
      known: connectionSummary !== null,
      value: total,
      reason: connectionSummary ? "" : "the connection snapshot has not been sampled yet",
      format: (v) => fmtInt(v),
      foot: established != null
        ? `${fmtInt(established)} established \u00b7 ${fmtInt(listening ?? 0)} listening`
        : connectionSummary ? "state breakdown not sampled yet" : "connection snapshot not sampled yet",
      extra: { total, established, listening },
    },
    {
      id: "processes",
      label: "Processes",
      known: state.processCountKnown === true || (Array.isArray(state.processes) && state.processes.length > 0),
      value: state.processCount ?? (state.processes ? state.processes.length : 0),
      reason: "the process table has not been sampled yet",
      format: (v) => fmtInt(v),
      foot: state.sysUptime != null
        ? `up ${fmtUptime(state.sysUptime)}`
        : "uptime not sampled yet",
    },
  ];

  const sparks = state.overviewSparklines || {};
  for (const spec of cards) {
    const series = sparks[spec.id];
    spec.hasSpark = Array.isArray(series) && series.length > 0;
    const node = kpiCard(spec);
    grid.append(node);
    const host = node.querySelector(".kpi-spark");
    if (host && Array.isArray(series)) {
      // The disk and network cards carry two series each; a single sparkline
      // would have to pick one and hide the other, so they get one line per
      // direction, each with its own chart colour.
      if (Array.isArray(series[0])) {
        series.forEach((sub, i) => {
          const row = h("div", { class: "kpi-spark-row" });
          host.append(row);
          sparkline(row, sub, { width: 96, height: 26, colorVar: `--chart-${i + 1}` });
        });
      } else {
        sparkline(host, series, { width: 108, height: 30, colorVar: "--chart-1" });
      }
    }
  }
}

function renderBreakdowns(page, state) {
  const host = page.querySelector("#overview-breakdown");
  clear(host);
  const summary = state.networkSummary || null;
  const metrics = state.metrics || {};
  const facts = metrics.facts || {};

  // ---- listeners by exposure ----
  const listeners = summary ? summary.listeners : null;
  host.append(card({},
    cardHeader({}, cardTitle({}, "Listening sockets by exposure")),
    cardContent({},
      listeners
        ? (() => {
            const list = h("div", { class: "exposure-grid" });
            for (const [key, label, hint] of [
              ["wildcard", "Wildcard", "binds every interface, reachable from the network"],
              ["lan", "LAN", "binds one specific address"],
              ["loopback", "Loopback", "reachable only from this machine"],
            ]) {
              list.append(h("div", { class: "exposure-cell", title: hint },
                h("div", { class: "exposure-value num" }, fmtInt(listeners[key] ?? 0)),
                h("div", { class: "exposure-label" }, label),
              ));
            }
            return list;
          })()
        : emptyState({}, "Not sampled yet", "The connection summary has not been taken.")),
  ));

  // ---- volumes ----
  const volumes = Array.isArray(facts.volumes) ? facts.volumes : [];
  host.append(card({},
    cardHeader({},
      cardTitle({}, "Volumes"),
      cardDescription({}, "Capacity, not throughput. Free space changes on its own schedule."),
    ),
    cardContent({},
      volumes.length === 0
        ? emptyState({}, "No volumes reported",
            "GetDiskFreeSpaceEx returned nothing for any mounted drive.")
        : (() => {
            const list = h("div", { class: "volume-list" });
            for (const vol of volumes) {
              const total = Number(vol.totalBytes) || 0;
              const free = Number(vol.freeBytes) || 0;
              const pct = total > 0 ? Math.max(0, Math.min(100, ((total - free) / total) * 100)) : 0;
              list.append(h("div", { class: "volume-row" },
                h("span", { class: "volume-label" },
                  h("strong", {}, vol.label || "?"),
                  vol.volumeName ? h("span", { class: "muted" }, ` ${vol.volumeName}`) : null,
                  h("span", { class: "muted text-sm" }, ` ${vol.fileSystem || "?"}`),
                ),
                h("span", { class: "volume-track", "aria-hidden": "true" },
                  h("span", { class: `volume-fill${pct > 90 ? " volume-fill-warn" : ""}`, style: `width:${pct.toFixed(1)}%` }),
                ),
                h("span", { class: "volume-value num" },
                  `${fmtBytes(free)} free of ${fmtBytes(total)}`),
              ));
            }
            return list;
          })()),
  ));

  // ---- system at a glance ----
  const sys = state.systemInfo || {};
  const proc = state.processes || [];
  const listenersCount = Array.isArray(proc) ? proc.reduce((n, p) => n + (p.listeners || 0), 0) : null;
  host.append(card({},
    cardHeader({},
      cardTitle({}, "System at a glance"),
      cardDescription({}, "Facts read once at start-up, not per poll."),
    ),
    cardContent({},
      (() => {
        const list = h("dl", { class: "fact-list" });
        const fact = (label, value, hint) => {
          list.append(h("dt", {}, label));
          const dd = h("dd", {}, value);
          if (hint) dd.title = hint;
          list.append(dd);
        };
        fact("Uptime", state.sysUptime != null ? fmtUptime(state.sysUptime) : UNAVAILABLE);
        fact("Logical processors", metrics["sys.threadCount"] != null ? "threads " + fmtInt(metrics["sys.threadCount"]) : UNAVAILABLE);
        fact("Processes", metrics["sys.processCount"] != null ? fmtInt(metrics["sys.processCount"]) : UNAVAILABLE);
        fact("Handles", metrics["sys.handleCount"] != null ? fmtInt(metrics["sys.handleCount"]) : UNAVAILABLE);
        if (listenersCount != null) {
          fact("Listening sockets", fmtInt(listenersCount), "across every process that owns a listener");
        }
        fact("Commit limit", metrics["mem.commitLimitBytes"] != null
          ? fmtBytes(metrics["mem.commitLimitBytes"])
          : UNAVAILABLE, "physical RAM plus pagefile; what Windows has actually promised");
        fact("Host", sys.hostname || UNAVAILABLE);
        return list;
      })()),
  ));
}

async function mountCharts(page) {
  const ov = page._overviewState;
  const hosts = [
    {
      sel: "#chart-cpu-mem",
      series: [
        { key: "cpu.total", label: "CPU %" },
        { key: "memoryMiB", label: "Memory (MiB)", scale: "mem" },
      ],
      transform: (s) => ({
        "cpu.total": s["cpu.total"] || [],
        memoryMiB: (s["mem.usedBytes"] || []).map((v) => (v == null ? null : v / (1024 * 1024))),
      }),
    },
    {
      sel: "#chart-disk",
      series: [
        { key: "disk.readBps", label: "Read B/s" },
        { key: "disk.writeBps", label: "Write B/s" },
      ],
      transform: (s) => ({
        "disk.readBps": s["disk.readBps"] || [],
        "disk.writeBps": s["disk.writeBps"] || [],
      }),
    },
    {
      sel: "#chart-network",
      series: [
        { key: "net.rxBps", label: "Received B/s" },
        { key: "net.txBps", label: "Sent B/s" },
      ],
      transform: (s) => ({
        "net.rxBps": s["net.rxBps"] || [],
        "net.txBps": s["net.txBps"] || [],
      }),
    },
  ];

  let history;
  try {
    history = await api.get("/api/metrics/history?max=300", { signal: ov.requests.signal });
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
  const raw = history.series || {};

  // Feed the sparklines and the KPI deltas. 60 samples is one minute of trend,
  // which is what fits under a number without becoming noise.
  const tail = (key, n) => (raw[key] || []).slice(-n);
  const sparkData = {
    cpu: tail("cpu.total", 60),
    memory: tail("mem.usedBytes", 60),
    disk: [tail("disk.readBps", 60), tail("disk.writeBps", 60)],
    network: [tail("net.rxBps", 60), tail("net.txBps", 60)],
    connections: [],
    processes: [],
  };
  ov.sparkData = sparkData;
  // The KPI cards were already rendered from the store; repaint just the
  // sparkline slots and deltas now that the series exists.
  paintTrends(page, sparkData, t, raw);

  if (t.length < 2) {
    for (const host of hosts) {
      const el = page.querySelector(host.sel);
      if (el) {
        clear(el);
        el.append(emptyState({}, "Collecting samples",
          `${t.length} sample so far. The chart needs two; the sampler keeps 15 minutes.`));
      }
    }
    return;
  }

  for (const host of hosts) {
    const el = page.querySelector(host.sel);
    if (!el) continue;
    // Only mount a chart if the container is still empty (no existing chart).
    if (el._chartEntry) continue;
    // Clear any placeholder (e.g. "Collecting samples") before mounting.
    clear(el);
    try {
      const entry = await createTimeseries(el, {
        height: 200,
        data: { t, values: host.transform(raw) },
        series: host.series,
      });
      if (ov.disposed) { entry.destroy(); return; }
      el._chartEntry = entry;
      // Store the transform function for future updates; key by element id.
      ov.charts.set(host.sel, { entry, transform: host.transform });
    } catch (err) {
      if (ov.disposed) return;
      clear(el);
      el.append(emptyState({}, "Chart unavailable", err.message));
    }
  }

}

// Update chart data in place using setData, avoiding chart destruction.
function updateCharts(page, ov) {
  if (!ov.history) return;
  const t = Array.isArray(ov.history.t) ? ov.history.t : [];
  const raw = ov.history.series || {};

  for (const [sel, info] of ov.charts) {
    const el = page.querySelector(sel);
    if (!el || !el._chartEntry) continue;
    try {
      const nextData = { t, values: info.transform(raw) };
      el._chartEntry.setData(nextData);
    } catch (err) {
      console.warn("chart update failed", sel, err);
    }
  }
}

function paintTrends(page, sparkData, t, raw) {
  for (const node of page.querySelectorAll("[data-kpi]")) {
    const id = node.dataset.kpi;
    const spec = sparkData[id];
    const host = node.querySelector(".kpi-spark");
    if (host && Array.isArray(spec) && spec.length > 0) {
      clear(host);
      if (Array.isArray(spec[0])) {
        spec.forEach((sub, i) => {
          const row = h("div", { class: "kpi-spark-row" });
          host.append(row);
          sparkline(row, sub, { width: 96, height: 26, colorVar: `--chart-${i + 1}` });
        });
      } else {
        sparkline(host, spec, { width: 108, height: 30, colorVar: "--chart-1" });
      }
    }
    // Deltas, where the card has a level or a rate to compare.
    const key = { cpu: "cpu.total", memory: "mem.usedBytes", disk: "disk.readBps", network: "net.rxBps" }[id];
    if (!key) continue;
    const delta = deltaOf(raw[key], t);
    if (!delta) continue;
    const head = node.querySelector(".kpi-head");
    if (!head) continue;
    const mode = id === "memory" ? "absolute" : "relative";
    const rendered = renderDelta(delta, mode, id === "memory" ? fmtBytes : (v) => fmtBps(v));
    const existing = head.querySelector(".kpi-delta");
    if (existing) existing.replaceWith(rendered);
    else head.append(rendered);
  }
}

async function mountProcesses(page) {
  const view = page._overviewState;
  const host = page.querySelector("#overview-procs");
  if (!host) return;
  let data;
  try {
    data = await api.get("/api/processes?sort=cpu&limit=8", { signal: view.requests.signal });
  } catch (err) {
    if (view.disposed) return;
    clear(host);
    host.append(emptyState({}, "Process list unavailable", err.message));
    return;
  }
  if (view.disposed) return;
  if (data.known === false) {
    clear(host);
    host.append(emptyState({}, "Process table not sampled", data.reason || "unknown"));
    return;
  }
  const rows = Array.isArray(data.processes) ? data.processes : [];
  const usable = rows.filter((r) => r.cpuPct !== null && r.cpuPct !== undefined);
  if (usable.length === 0) {
    clear(host);
    host.append(emptyState({}, "No CPU readings yet",
      `All ${data.total ?? rows.length} processes reported an unreadable CPU figure. ` +
      "Windows refuses to open most system processes for timing at a normal privilege level."));
    return;
  }
  clear(host);
  const list = h("div", { class: "proc-mini" });
  for (const row of usable) {
    list.append(h("div", { class: "proc-mini-row" },
      h("span", { class: "proc-mini-name", dir: "auto", title: row.path || row.name }, row.name || "(unnamed)"),
      h("span", { class: "proc-mini-bar", "aria-hidden": "true" },
        h("span", {
          class: "proc-mini-fill",
          style: `width:${Math.max(1, Math.min(100, row.cpuPct)).toFixed(1)}%`,
        }),
      ),
      h("span", { class: "proc-mini-value num" }, fmtPct(row.cpuPct)),
    ));
  }
  host.append(list);
  if (data.ageMs != null) {
    host.append(h("p", { class: "muted text-sm proc-mini-age" },
      `Sampled ${fmtDuration(Math.round(data.ageMs / 1000))} ago`));
  }
}
