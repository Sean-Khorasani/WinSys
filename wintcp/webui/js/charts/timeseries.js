// charts/timeseries.js - uPlot wrapper with themed colours
import { icon } from "../icons.js";

let uPlot = null;

export async function loadUPlot() {
  if (uPlot) return uPlot;
  const css = document.createElement("link");
  css.rel = "stylesheet";
  css.href = "/vendor/uPlot/uPlot.min.css";
  document.head.append(css);
  const mod = await import("/vendor/uPlot/uPlot.esm.js");
  uPlot = mod.default || mod;
  return uPlot;
}

export async function createTimeseries(container, opts = {}) {
  const up = await loadUPlot();
  const el = document.createElement("div");
  el.className = "chart-container";
  container.append(el);

  const data = [opts.t || [], opts.series ? opts.series.map(() => []) : []];
  const series = [{ label: opts.label || "" }];
  if (opts.series) {
    for (const s of opts.series) series.push({ label: s.label });
  }

  const chart = new up(el, {
    width: el.clientWidth || 600,
    height: el.clientHeight || 200,
    series,
    scales: { x: { time: true } },
  }, data);

  return { chart, el, up };
}
