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
import { fmtNum, fmtInt, fmtBytes, fmtBps, fmtPct, fmtUptime, fmtDuration } from "../format.js";
import { card, cardHeader, cardTitle, cardDescription, cardContent, cardFooter, emptyState } from "../ui/card.js";
import { api } from "../api.js";
import { createTimeseries } from "../charts/timeseries.js";
import { sparkline, barList } from "../charts/sparkline.js";

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

  const state = store.get();
  const stamp = page.querySelector("#overview-updated");
  if (state.lastUpdate) {
    stamp.textContent = `Updated ${state.lastUpdate.toLocaleTimeString()}`;
  } else {
    stamp.textContent = "Waiting for the first poll";
  }

  // The poller already has /api/metrics/now and /api/network/summary in the
  // store, so the KPI cards and the breakdowns render on the first frame; the
  // history fetch only adds trends.
  renderKpis(page, state);
  renderBreakdowns(page, state);

  await Promise.all([
    mountCharts(page),
    mountProcesses(page),
  ]);
}

function renderKpis(page, state) {
  const grid = page.querySelector("#kpi-grid");
  clear(grid);
  const metrics = state.metrics || {};
  const conns = state.connections || [];
  const summary = state.networkSummary || {};
  const total = typeof summary.total === "number" ? summary.total : conns.length;

  const byState = summary.byState || {};
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
      known: true,
      value: total,
      reason: "",
      format: (v) => fmtInt(v),
      foot: established != null
        ? `${fmtInt(established)} established \u00b7 ${fmtInt(listening ?? 0)} listening`
        : "state breakdown not sampled yet",
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
    // 300 samples is five minutes at 1 Hz, which is what the sparklines and the
    // deltas need. Asking for the full 900 would put a ~60 KB body on a page the
    // browser also polls every two seconds.
    history = await api.get("/api/metrics/history?max=300");
  } catch (err) {
    for (const host of hosts) {
      const el = page.querySelector(host.sel);
      if (el) { clear(el); el.append(emptyState({}, "No history yet", err.message)); }
    }
    return;
  }

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

  const charts = [];
  for (const host of hosts) {
    const el = page.querySelector(host.sel);
    if (!el) continue;
    try {
      charts.push(await createTimeseries(el, {
        height: 200,
        data: { t, values: host.transform(raw) },
        series: host.series,
      }));
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
    if (!head || head.querySelector(".kpi-delta")) continue;
    const mode = id === "memory" ? "absolute" : "relative";
    head.append(renderDelta(delta, mode, id === "memory" ? fmtBytes : (v) => fmtBps(v)));
  }
}

async function mountProcesses(page) {
  const host = page.querySelector("#overview-procs");
  if (!host) return;
  let data;
  try {
    data = await api.get("/api/processes?sort=cpu&limit=8");
  } catch (err) {
    clear(host);
    host.append(emptyState({}, "Process list unavailable", err.message));
    return;
  }
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