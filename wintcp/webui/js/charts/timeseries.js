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

// Build uPlot options for a set of series defs.
//
// A def may name a `scale`. Anything without one shares the left-hand axis; a
// def with `scale: "x"` gets its own right-hand axis. This is not cosmetic: CPU
// (0-100) plotted against memory (30,000 MiB) on one axis flattens the CPU line
// onto the baseline and makes the chart useless.
function baseOptions(height, seriesDefs) {
  const palette = chartPalette();

  // Collect the extra scales, preserving first-seen order.
  const extraScales = [];
  for (const def of seriesDefs) {
    if (def.scale && !extraScales.includes(def.scale)) extraScales.push(def.scale);
  }

  const scales = { x: { time: true } };
  for (const name of extraScales) scales[name] = {};

  const axisCommon = {
    stroke: palette.axis,
    grid: { stroke: palette.grid, width: 1 },
    ticks: { stroke: palette.grid },
    font: "11px system-ui, sans-serif",
  };
  const axes = [
    { ...axisCommon, ticks: { ...axisCommon.ticks, show: false } },
    { ...axisCommon },
  ];
  extraScales.forEach((name, i) => {
    // First extra scale goes on the right; any further ones are stacked left.
    const side = i === 0 ? 1 : 0;
    axes.push({
      ...axisCommon,
      scale: name,
      side,
      // Only the first extra axis on a side gets a grid, or the plot fills with
      // overlapping lines.
      grid: i === 0 ? axisCommon.grid : { stroke: palette.grid, width: 0 },
      ticks: { ...axisCommon.ticks, show: i === 0 },
    });
  });

  return {
    width: 600,
    height,
    // uPlot's legend is a per-series render hook, so the x series can be dropped
    // outright. `label: ""` alone was not enough: uPlot fell back to its default
    // "Time" heading and printed an empty value beside it, so every chart carried
    // a "Time: --" entry that names the axis rather than any data. Returning
    // false from the hook hides the row completely.
    legend: {
      show: seriesDefs.length > 1,
      live: true,
      markers: (u, seriesIdx) => ({
        fill: u.series[seriesIdx].stroke || "#888888",
        stroke: "#ffffff",
        width: 7,
        height: 7,
      }),
    },
    cursor: { drag: { x: false, y: false } },
    scales,
    axes,
    // A null sample stays null: uPlot draws a gap, so "no data" is visibly
    // different from a flat line at zero (C-6).
    series: [
      // The x series carries no stroke and must not appear in the legend.
      { label: "", ...{ live: false }, legend: false },
      ...seriesDefs.map((def, i) => ({
        label: def.label,
        ...(def.scale ? { scale: def.scale } : {}),
        stroke: def.stroke || palette.series[i % palette.series.length],
        width: 1.5,
        points: { show: false },
      })),
    ],
  };
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
  if (!container.isConnected) throw new DOMException("Chart view was closed", "AbortError");
  const el = document.createElement("div");
  el.className = "chart-host";
  el.style.height = `${opts.height || 200}px`;
  container.append(el);

  const defs = opts.series || [];
  const data = buildData(opts.data, defs);
  const options = baseOptions(opts.height || 200, defs);
  // uPlot's signature is new uPlot(opts, data, target) - the ELEMENT IS LAST.
  // Passing it first is a TypeError deep inside the constructor ("then is not a
  // function"), because the third argument is expected to be either an element
  // or an on-ready callback.
  const chart = new up(options, data, el);

  // uPlot writes the canvas size once. Everything that can change the box has to
  // push a new size, or the chart is stretched / clipped.
  //
  // BOTH dimensions must be supplied. setSize({ width }) makes uPlot re-derive
  // height, and it re-derives it as 0 here - the canvas ends up with a real
  // width and a zero-height backing store, so nothing is ever painted and the
  // chart shows only its legend.
  let destroyed = false;
  const resize = () => {
    if (destroyed) return;
    const width = el.clientWidth;
    const height = el.clientHeight || opts.height || 200;
    if (width > 0 && (Math.abs(width - chart.width) > 1 || chart.height !== height)) {
      chart.setSize({ width, height });
    }
  };
  const observer = new ResizeObserver(resize);
  observer.observe(el);
  // clientWidth is 0 until the element has been laid out.
  const frame = requestAnimationFrame(resize);

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
      if (destroyed) return;
      destroyed = true;
      cancelAnimationFrame(frame);
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
    const chart = entry.chart;

    // Use uPlot's own setters. Writing `axis.stroke = ...` looks equivalent and
    // is not: uPlot's axes are class instances whose render functions are
    // methods, so replacing `stroke` deletes a method and the very next redraw
    // throws "axis.stroke is not a function". That is what broke every chart on
    // the Performance page the first time the theme was switched.
    //
    // setAxisColor(side, key, value) is keyed by SIDE AND SLOT (0 = x, 1 = the
    // first y, 2 = the second y ...), not by the order of chart.axes.
    for (const scale of Object.keys(chart.scales || {})) {
      const slot = scale === "x" ? 0 : Object.keys(chart.scales).indexOf(scale);
      for (const side of [0, 1]) {
        safeSet(() => chart.setAxisColor(side, slot, palette.axis));
        safeSet(() => chart.setAxisColor(side, slot, palette.grid, 1));
        safeSet(() => chart.setAxisColor(side, slot, palette.grid, 2));
        safeSet(() => chart.setAxisColor(side, slot, palette.grid, 3));
      }
    }

    // Index 0 of uPlot's series array is the x axis, which is not a data series
    // and has no stroke. The FIRST DATA series is at index 1 and must take
    // palette.series[0] - mapping on the raw index made every chart start at the
    // second colour, which is why a two-line chart showed the same hue for both
    // lines after a theme switch while the initial paint was correct.
    for (let i = 1; i < (chart.series || []).length; i += 1) {
      safeSet(() => chart.setSeriesColor(i, palette.series[(i - 1) % palette.series.length]));
    }

    safeSet(() => chart.redraw());
  }
}

// A theme repaint must not be able to throw. If a uPlot version renames or
// removes one of these methods, the worst outcome should be a chart that keeps
// its previous colours - not an uncaught error that blanks the page.
function safeSet(fn) {
  try {
    fn();
  } catch (err) {
    console.warn("chart repaint step skipped", err);
  }
}
