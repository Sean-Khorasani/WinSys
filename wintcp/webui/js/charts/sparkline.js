// charts/sparkline.js - Inline SVG sparkline built with DOM calls.
//
// Pure geometry, no innerHTML: every point string is composed of numbers that
// this module produced from Number() casts, and the nodes are built with
// createElementNS. Nothing server-derived is ever parsed as markup, which is
// what keeps this inside the S-10 rule even though the input is numeric.
//
// UNKNOWN IS NOT ZERO. A gap in the series draws a break in the line, and the
// card shows the reason. Interpolating across a gap would draw a slope the
// sampler never measured, and clamping the gap to zero would draw a dip to the
// baseline - both are claims about the machine that nobody took.

const NS = "http://www.w3.org/2000/svg";

// Resolved through the CSSOM rather than hard-coded, so a theme change needs no
// second copy of the palette. If the token is missing or unparseable the
// element simply inherits currentColor, which is still visible.
function resolveColor(token, fallback) {
  if (typeof getComputedStyle !== "function") return fallback;
  const value = getComputedStyle(document.documentElement).getPropertyValue(token);
  return value && value.trim() ? value.trim() : fallback;
}

/**
 * Downsample `values` to at most `width` points.
 *
 * Buckets rather than striding: a stride can land only on the peaks, so the
 * sparkline would show spikes that the data does not contain. Taking the mean of
 * each bucket is the one reduction a 120-pixel-wide line can honestly display.
 * Nulls are counted out of the bucket rather than averaged as zero.
 */
export function downsample(values, width) {
  if (values.length <= width || width <= 0) return values.slice();
  const out = [];
  const bucket = values.length / width;
  for (let i = 0; i < width; i += 1) {
    const start = Math.floor(i * bucket);
    const end = Math.max(start + 1, Math.floor((i + 1) * bucket));
    let sum = 0;
    let count = 0;
    for (let j = start; j < end && j < values.length; j += 1) {
      const v = values[j];
      if (v === null || v === undefined || Number.isNaN(v)) continue;
      sum += v;
      count += 1;
    }
    out.push(count === 0 ? null : sum / count);
  }
  return out;
}

/**
 * Turn a series into an SVG polyline `points` string, or null when there is
 * nothing plottable.
 *
 * Contiguous runs become separate polylines, which is how a gap stays visible:
 * one run is one line. Exported separately from the DOM work so it can be
 * covered by `node --test` without a browser.
 */
export function polylineSegments(values, width, height) {
  const known = values.filter((v) => v !== null && v !== undefined && !Number.isNaN(v));
  if (known.length === 0) return null;

  let min = Math.min(...known);
  let max = Math.max(...known);
  // A flat series (every sample identical) would divide by zero here. Give it a
  // band of its own so it draws through the middle instead of collapsing onto an
  // edge, which reads as "off scale".
  if (max === min) { min -= 0.5; max += 0.5; }
  // Percentages and percentages-of-something are the common cases, so clamp the
  // axis to zero when the data allows it: a CPU chart whose baseline is not zero
  // exaggerates every wiggle.
  if (min >= 0) min = 0;

  const step = values.length > 1 ? width / (values.length - 1) : 0;
  const segments = [];
  let current = [];
  for (let i = 0; i < values.length; i += 1) {
    const v = values[i];
    if (v === null || v === undefined || Number.isNaN(v)) {
      if (current.length > 0) segments.push(current.join(" "));
      current = [];
      continue;
    }
    const x = (i * step).toFixed(1);
    const y = (height - ((v - min) / (max - min)) * height).toFixed(1);
    current.push(`${x},${y}`);
  }
  if (current.length > 0) segments.push(current.join(" "));
  return segments.length > 0 ? segments : null;
}

/**
 * Render a sparkline into `container`.
 *
 * Returns the <svg>, or null when the series has no readings at all - the
 * caller shows "-" with a reason instead of an empty box.
 */
export function sparkline(container, values, opts = {}) {
  if (!container) return null;
  const width = opts.width || 120;
  const height = opts.height || 32;
  const list = Array.isArray(values) ? values : [];
  const segments = polylineSegments(downsample(list, width), width, height);
  if (segments === null) return null;

  const color = resolveColor(opts.colorVar || "--chart-1", "currentColor");

  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("width", String(width));
  svg.setAttribute("height", String(height));
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", color);
  svg.setAttribute("stroke-width", opts.strokeWidth || "1.5");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("preserveAspectRatio", "none");
  // Decorative by default: the card's text already states the value, so a screen
  // reader hearing "polyline, 3 points" adds noise without information. Callers
  // that want it read out pass a label.
  svg.setAttribute("aria-hidden", opts.label ? "false" : "true");
  svg.setAttribute("focusable", "false");
  if (opts.label) {
    const title = document.createElementNS(NS, "title");
    title.textContent = opts.label;
    svg.append(title);
  }

  for (const points of segments) {
    const line = document.createElementNS(NS, "polyline");
    line.setAttribute("points", points);
    svg.append(line);
  }

  container.append(svg);
  return svg;
}

/**
 * Horizontal bar list - the shape most "top N" cards need.
 *
 * A table of divs rather than a chart library: it needs no canvas, it inherits
 * the theme's CSS variables for free, and every cell is real text, so it is
 * readable by a screen reader and selectable by the user. The bar is an
 * aria-hidden decoration; the number beside it is the accessible content.
 */
export function barList(container, rows, opts = {}) {
  if (!container || !Array.isArray(rows) || rows.length === 0) return null;
  const max = opts.max ?? Math.max(...rows.map((r) => Number(r.value) || 0), 0);
  const format = opts.format || ((v) => String(v));
  const list = h2("ul", { class: "bar-list" });

  for (const row of rows) {
    const value = Number(row.value);
    const known = Number.isFinite(value);
    const pct = known && max > 0 ? Math.max(0, Math.min(100, (value / max) * 100)) : 0;
    const item = h2("li", { class: "bar-row" },
      h2("span", { class: "bar-label", dir: "auto", title: row.label || "" }, row.label || ""),
      h2("span", { class: "bar-track", "aria-hidden": "true" },
        h2("span", { class: "bar-fill", style: `width:${pct.toFixed(1)}%` }),
      ),
      h2("span", { class: "bar-value num" }, known ? format(value) : "—"),
    );
    if (!known && row.reason) {
      item.setAttribute("title", row.reason);
      item.classList.add("bar-row-unknown");
    }
    list.append(item);
  }
  container.append(list);
  return list;
}

// Local import-free element factory so this module has no dependency cycle with
// h.js (h.js imports nothing, but keeping the chart helpers leaf nodes means the
// node --test suite can load the geometry above without a DOM).
function h2(tag, props, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (key === "class") el.className = value;
    else if (key === "style" && typeof value === "string") el.style.cssText = value;
    else if (value === true) el.setAttribute(key, "");
    else if (value !== false && value != null) el.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child == null) continue;
    el.append(child.nodeType ? child : document.createTextNode(String(child)));
  }
  return el;
}