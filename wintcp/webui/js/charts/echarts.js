// charts/echarts.js - ECharts factory (bundle loaded on demand)

let echarts = null;

export async function loadECharts() {
  if (echarts) return echarts;
  // echarts.min.js is a UMD bundle, not an ES module. A dynamic import of a UMD
  // file executes it and populates window.echarts; there is no default export
  // to read off the namespace, which is why the old
  //   const mod = await import("/vendor/echarts/echarts.custom.js")
  //   echarts = mod.default || mod;
  // resolved to the module namespace object and then failed on ec.init.
  await import("/vendor/echarts/echarts.min.js");
  echarts = globalThis.echarts;
  if (!echarts || typeof echarts.init !== "function") {
    throw new Error(
      "ECharts loaded but window.echarts is not the library. " +
      "Is /vendor/echarts/echarts.min.js the UMD build?",
    );
  }
  return echarts;
}

export async function createChart(container, option) {
  const ec = await loadECharts();
  const el = document.createElement("div");
  el.className = "chart-host";
  el.style.height = "100%";
  container.append(el);
  const chart = ec.init(el, null, { renderer: "canvas" });
  chart.setOption(option);
  // ECharts reads its container size once; a resize without a setSize leaves it
  // stretched or clipped, same as uPlot.
  const observer = new ResizeObserver(() => chart.resize());
  observer.observe(el);
  return {
    chart,
    el,
    destroy() {
      observer.disconnect();
      chart.dispose();
    },
  };
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
