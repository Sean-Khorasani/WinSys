// charts/echarts.js - ECharts factory (bundle loaded on demand)

let echarts = null;

export async function loadECharts() {
  if (echarts) return echarts;
  const mod = await import("/vendor/echarts/echarts.custom.js");
  echarts = mod.default || mod;
  return echarts;
}

export async function createChart(container, option) {
  const ec = await loadECharts();
  const el = document.createElement("div");
  el.style.width = "100%";
  el.style.height = "100%";
  container.append(el);
  const chart = ec.init(el);
  chart.setOption(option);
  return { chart, el };
}

export function donut(container, data, opts = {}) {
  return createChart(container, {
    series: [{
      type: "pie",
      radius: ["40%", "70%"],
      data,
      label: { show: false },
    }],
    ...opts,
  });
}

export function treemap(container, data, opts = {}) {
  return createChart(container, {
    series: [{ type: "treemap", data, ...opts }],
  });
}

export function heatmap(container, data, opts = {}) {
  return createChart(container, {
    series: [{ type: "heatmap", data, ...opts }],
  });
}

export function sankey(container, data, opts = {}) {
  return createChart(container, {
    series: [{ type: "sankey", data, ...opts }],
  });
}

export function worldMap(container, data, opts = {}) {
  return createChart(container, {
    series: [{ type: "map", map: "world", data, ...opts }],
  });
}
