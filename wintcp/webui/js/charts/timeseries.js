// charts/timeseries.js - uPlot wrapper with themed colours.
//
// uPlot wants explicit pixel dimensions and hands them straight to the canvas,
// so a chart created before layout is visible gets sized to the fallback and
// never corrects itself. A ResizeObserver drives setSize on every change, which
// is what makes the charts correct inside a resizable sidebar and across the
// 1280/1440/1920 breakpoints.
//
// Colours are resolved from the design tokens at build time rather than baked
// in, so a theme switch repaints without duplicating the palette in JS.

const CSS_LINK = "/vendor/uPlot/uPlot.min.css";
const ESM_PATH = "/vendor/uPlot/uPlot.esm.js";

let uPlotPromise = null;
let cssInjected = false;

export async function loadUPlot() {
  if (!uPlotPromise) {
    if (!cssInjected) {
      const link = document.createElement("link");
      link.rel = "stylesheet";
      link.href = CSS_LINK;
      document.head.append(link);
      cssInjected = true;
    }
    uPlotPromise = import(ESM_PATH).then((mod) => mod.default || mod);
  }
  return uPlotPromise;
}

// Read a token and let the browser resolve it to something uPlot's parser
// understands. uPlot parses colours itself and does not know oklch(), so a raw
// token string would throw; going through the canvas gives sRGB bytes.
function tokenToRgb(value) {
  if (!value) return "#888888";
  const canvas = tokenToRgb.canvas || (tokenToRgb.canvas = document.createElement("canvas"));
  const ctx = canvas.getContext("2d");
  if (!ctx) return "#888888";
  ctx.fillStyle = "#000000";
  ctx.fillStyle = value;
  return ctx.fillStyle;
}

export function chartPalette() {
  const cs = getComputedStyle(document.documentElement);
  const token = (name, fallback) => tokenToRgb(cs.getPropertyValue(name).trim()) || fallback;
  return {
    axis: token("--muted-foreground", "#737373"),
    grid: token("--border", "#e5e5e5"),
    text: token("--foreground", "#111111"),
    primary: token("--primary", "#2563eb"),
    series: [
      token("--chart-1", "#2563eb"),
      token("--chart-2", "#16a34a"),
      token("--chart-3", "#ea580c"),
      token("--chart-4", "#9333ea"),
      token("--chart-5", "#0891b2"),
    ],
  };
}

function baseOptions(up, height, seriesDefs) {
  const palette = chartPalette();
  const options = {
    width: 600,
    height,
    // Transparent background: the card behind the canvas supplies it, so a
    // theme change does not need the canvas repainted to match.
    plugins: [],
    legend: { show: true },
    cursor: { drag: { x: false, y: false } },
    scales: {
      x: { time: true },
      y: { auto: true },
    },
    axes: [
      {
        stroke: palette.axis,
        grid: { stroke: palette.grid, width: 1 },
        ticks: { stroke: palette.grid },
        font: "11px system-ui, sans-serif",
      },
      {
        stroke: palette.axis,
        grid: { stroke: palette.grid, width: 1 },
        ticks: { stroke: palette.grid },
        font: "11px system-ui, sans-serif",
      },
    ],
    series: [
      {},
      ...seriesDefs.map((def, i) => ({
        label: def.label,
        // Null (not 0) for an unavailable sample, so uPlot draws a gap and the
        // reader can tell "no data" from "idle".
        value: def.value ?? ((self, raw) => raw),
        stroke: def.stroke || palette.series[i % palette.series.length],
        width: 1.5,
        points: { show: false },
      })),
    ],
  };
  return options;
}

/**
 * Create a time-series chart inside `container`.
 *
 * @param {HTMLElement} container
 * @param {object} opts
 * @param {number} [opts.height=200]
 * @param {Array<{key: string, label: string, unit?: string, scale?: number}>} [opts.series]
 * @param {object} [opts.data] {t: number[], values: Record<string, (number|null)[]>}
 */
export async function createTimeseries(container, opts = {}) {
  const up = await loadUPlot();
  const el = document.createElement("div");
  el.className = "chart-host";
  el.style.height = `${opts.height || 200}px`;
  container.append(el);

  const defs = opts.series || [];
  const data = buildData(opts.data, defs);
  const options = baseOptions(up, opts.height || 200, defs);
  const chart = new up(el, options, data);

  // uPlot writes the canvas size once. Everything that can change the box has to
  // push a new size, or the chart is stretched / clipped.
  const resize = () => {
    const width = el.clientWidth;
    if (width > 0 && Math.abs(width - chart.width) > 1) chart.setSize({ width });
  };
  const observer = new ResizeObserver(resize);
  observer.observe(el);
  // clientWidth is 0 until the element has been laid out.
  requestAnimationFrame(resize);

  const entry = {
    chart,
    el,
    up,
    opts: { data, series: defs },
    // Replace the data in place. uPlot requires the same array shape, and
    // replacing the x array re-scales the axis.
    setData(next) {
      const built = buildData(next, defs);
      chart.setData(built, true);
    },
    destroy() {
      observer.disconnect();
      liveCharts.delete(entry);
      chart.destroy();
    },
  };
  liveCharts.add(entry);
  return entry;
}

function buildData(data, defs) {
  const t = data && Array.isArray(data.t) ? data.t : [];
  const values = (data && data.values) || {};
  return [t.slice(), ...defs.map((def) => (values[def.key] || []).slice())];
}

  // Repaint every live chart after a theme switch. Charts hold resolved colours,
// not tokens, so a theme change needs an explicit redraw.
const liveCharts = new Set();

export function registerChart(chart) {
  liveCharts.add(chart);
  return () => liveCharts.delete(chart);
}

export function repaintCharts() {
  for (const entry of Array.from(liveCharts)) {
    const palette = chartPalette();
    if (!entry || !entry.chart || !entry.opts) continue;
    const axes = entry.chart.axes;
    axes.forEach((axis) => {
      axis.stroke = palette.axis;
      if (axis.grid) axis.grid.stroke = palette.grid;
      if (axis.ticks) axis.ticks.stroke = palette.grid;
    });
    entry.chart.series.forEach((s, i) => {
      if (i === 0) return;
      s.stroke = palette.series[i % palette.series.length];
    });
    entry.chart.redraw();
  }
}