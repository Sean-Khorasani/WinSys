// charts/sparkline.js - Inline SVG sparkline (no library needed)

export function sparkline(container, values, opts = {}) {
  const w = opts.width || 120;
  const h = opts.height || 32;
  const max = Math.max(...values, 0);
  const min = Math.min(...values, 0);
  const range = max - min || 1;
  const step = w / Math.max(values.length - 1, 1);

  const points = values.map((v, i) => {
    const x = i * step;
    const y = h - ((v - min) / range) * h;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="${points}" /></svg>`;
  const span = document.createElement("span");
  span.innerHTML = svg;
  const el = span.firstElementChild;
  el.style.color = opts.color || "var(--primary)";
  container.append(el);
  return el;
}
