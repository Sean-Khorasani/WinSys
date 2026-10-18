// charts/treemap.js - Squarified treemap of process memory or CPU.
//
// WHY SQUARIFIED AND NOT THE NAIVE ALGORITHM
// The naive "slice and alternate" treemap gives rectangles whose aspect ratios
// are driven by input order, so a process at the end of a sorted list can end up
// as a 200x4 sliver. For a memory view that is actively misleading: the biggest
// bar in the picture is not the biggest process. Squarify (Bruls, Huizing & van
// Wijk, 2000) packs each row to maximise the worst aspect ratio instead, so
// area stays proportional to value AND the shapes stay readable.
//
// No canvas and no ECharts: the treemap is absolutely-positioned divs. That
// keeps it inside the CSP with no style attributes in markup, needs no 1 MB
// bundle, and every tile is real DOM text - which means it is selectable and
// screen-reader legible, and a tile's tooltip is a title attribute rather than a
// canvas hit-test.
//
// The layout half is a pure function over numbers and is exported separately so
// `node --test` can check that areas are proportional - the one property that
// makes a treemap a treemap rather than a coloured grid.

const TREEMAP_MARGIN = 1;

/**
 * Squarified treemap layout.
 *
 * @param {Array<{value: number, key?: string}>} items - positive values only.
 * @param {number} width
 * @param {number} height
 * @returns {Array<{item: object, x: number, y: number, width: number, height: number}>}
 */
export function squarify(items, width, height) {
  const out = [];
  const usable = (items || []).filter(
    (it) => it && Number.isFinite(it.value) && it.value > 0,
  );
  if (usable.length === 0 || width <= 0 || height <= 0) return out;

  const total = usable.reduce((sum, it) => sum + it.value, 0);
  if (total <= 0) return out;

  // Sort by value, largest first, and break ties on the caller's label.
  //
  // Squarify packs in INPUT ORDER, so without this the same data laid out in a
  // different order produces a visibly different picture: reorder the rows in
  // the table and the treemap rearranges itself for no reason the user did.
  // Sorting makes the layout a function of the VALUES alone, which is the only
  // property that lets a reader compare two screenshots and trust them.
  // Ties need the label because values 1 and 1 would otherwise pack in whatever
  // order the sort engine happened to produce - stable, but arbitrary.
  const sorted = usable.slice().sort((a, b) =>
    b.value - a.value || String(a.label || "").localeCompare(String(b.label || "")));

  // Scale so the whole set exactly fills the box. Doing the arithmetic in
  // normalised units and multiplying at the end keeps the row-packing loop free
  // of rounding drift, which otherwise shows up as sub-pixel gaps along an edge.
  const scale = (width * height) / total;
  let rest = sorted.map((item) => ({ item, area: item.value * scale }));
  // let, not const: each row consumes one edge of the remaining box, and these
  // are the box bounds. (They were const via array destructuring, which threw
  // "Assignment to constant variable" the moment a second row was laid out -
  // so every treemap with more than one row was broken. The unit test found it
  // on the first run.)
  let x0 = 0, y0 = 0, x1 = width, y1 = height;

  // Worst aspect ratio in a row: the ratio that squarify exists to minimise.
  const worst = (row, length) => {
    if (row.length === 0 || length <= 0) return Infinity;
    const sum = row.reduce((s, r) => s + r.area, 0);
    const max = Math.max(...row.map((r) => r.area));
    const min = Math.min(...row.map((r) => r.area));
    const s2 = sum * sum;
    const l2 = length * length;
    return Math.max((l2 * max) / s2, s2 / (l2 * min));
  };

  while (rest.length > 0) {
    // Lay the next row along the SHORTER side, which is what keeps the aspect
    // ratios near 1 as the box is consumed.
    const horizontal = (x1 - x0) >= (y1 - y0);
    const length = horizontal ? y1 - y0 : x1 - x0;
    const row = [];
    let i = 0;
    for (; i < rest.length; i += 1) {
      const candidate = [...row, rest[i]];
      // Adding this rectangle makes the row worse than stopping here: close the
      // row and let the next one start fresh.
      if (row.length > 0 && worst(candidate, length) > worst(row, length)) break;
      row.push(rest[i]);
    }
    rest = rest.slice(i);

    const rowArea = row.reduce((s, r) => s + r.area, 0);
    let thickness = length > 0 ? rowArea / length : 0;

    // Clamp the row to the space actually left. Floating-point drift in the
    // running sum makes the final row's computed thickness a fraction of a
    // pixel wider than the box, and that fraction is enough to draw an overlap:
    // the next row then starts outside the rectangle it belongs to.
    const available = horizontal ? (x1 - x0) : (y1 - y0);
    if (thickness > available) thickness = available;

    // Cells advance along the row's LONG side: y for a horizontal row, x for a
    // vertical one.
    let offset = horizontal ? y0 : x0;
    const start = horizontal ? y0 : x0;
    for (const entry of row) {
      let extent = thickness > 0 ? entry.area / thickness : 0;
      // The last cell in the row absorbs whatever rounding is left, so the row
      // ends exactly at the boundary rather than a rounding error past it.
      if (offset + extent > start + length + 0.001) {
        extent = Math.max(0, start + length - offset);
      }
      // A "horizontal" row is packed along the SHORTER side, which is the
      // vertical extent; the row itself is a column of constant thickness at
      // x0. (These two branches were transposed, which made every treemap with
      // more than one cell per row draw overlapping rectangles - the unit test
      // caught it on the first run.)
      if (horizontal) {
        out.push({
          item: entry.item,
          x: x0, y: offset, width: thickness, height: extent,
        });
      } else {
        out.push({
          item: entry.item,
          x: offset, y: y0, width: extent, height: thickness,
        });
      }
      offset += extent;
    }

    if (horizontal) x0 += thickness; else y0 += thickness;
    // A box with no area left would loop forever on `length <= 0`; break rather
    // than spin.
    if (available - thickness <= 0.001 && rest.length > 0) {
      for (const entry of rest) {
        out.push({ item: entry.item, x: x0, y: y0, width: 0, height: 0 });
      }
      rest = [];
    }
  }

  return out;
}

/**
 * Render a treemap into `container`.
 *
 * @param {HTMLElement} container
 * @param {Array<{label: string, value: number, reason?: string}>} rows
 * @param {object} [opts] {height, format, colorVar, onSelect}
 * @returns {HTMLElement|null} the host element, or null when nothing is plottable.
 */
export function renderTreemap(container, rows, opts = {}) {
  if (!container || !Array.isArray(rows)) return null;
  const height = opts.height || 420;
  const format = opts.format || ((v) => String(v));
  const width = container.clientWidth || 900;
  if (width <= 0) return null;

  // Without a width there is nothing to lay out; returning null lets the caller
  // show an honest empty state instead of a zero-height box.
  const placed = squarify(rows, width, height);
  if (placed.length === 0) return null;

  const host = document.createElement("div");
  host.className = "treemap";
  host.style.height = `${height}px`;

  for (let index = 0; index < placed.length; index++) {
    const cell = placed[index];
    // A tile too small to hold its label is dropped from the drawing but not
    // from the data: the caller still reports the total. Drawing a 3x2 tile with
    // clipped text is noise.
    if (cell.width < 24 || cell.height < 14) continue;

    const drawable = Math.max(0, cell.width - TREEMAP_MARGIN * 2);
    const drawableHeight = Math.max(0, cell.height - TREEMAP_MARGIN * 2);

    const tile = document.createElement("button");
    tile.type = "button";
    tile.className = "treemap-tile";
    tile.style.left = `${cell.x + TREEMAP_MARGIN}px`;
    tile.style.top = `${cell.y + TREEMAP_MARGIN}px`;
    tile.style.width = `${drawable}px`;
    tile.style.height = `${drawableHeight}px`;
    // Vary hue across tiles. A single flat colour is what the first version did,
    // and it made the picture read as one solid block with text on it - the
    // boundaries were only visible because of the 1px margin, which is a much
    // weaker signal than the shape itself.
    //
    // The lightness is held roughly constant and only the hue rotates, so no
    // tile can become too light for the white label or too dark to see. HSL
    // rather than a token per tile: the palette has five entries and this can
    // draw fifty rectangles.
    const hue = (index * 47) % 360;
    tile.style.background =
      `linear-gradient(to top, hsl(${hue} 62% 26%), hsl(${hue} 70% 44%))`;

    // Only label a tile that can hold the label. Truncating "WhatsApp.exe" to
    // "WhatsApp R..." in a 40px tile is worse than drawing the rectangle
    // unlabelled: the shape still carries the information, and the tooltip and
    // the accessible name still carry the exact text.
    if (tileFits(cell)) {
      const name = document.createElement("span");
      name.className = "treemap-label";
      // textContent, never innerHTML: a process name is attacker-influenced.
      name.textContent = cell.item.label;
      tile.append(name);

      const value = document.createElement("span");
      value.className = "treemap-value num";
      value.textContent = format(cell.item.value);
      tile.append(value);
    }

    // The accessible name carries the exact text even when the label is not drawn,
    // so an unlabelled tile is not an unlabelled tile to a screen reader.
    tile.setAttribute("aria-label",
      `${cell.item.label}: ${format(cell.item.value)}` +
      (cell.item.reason ? `, ${cell.item.reason}` : ""));
    tile.title = `${cell.item.label}: ${format(cell.item.value)}` +
      (cell.item.reason ? ` (${cell.item.reason})` : "");
    if (opts.onSelect) tile.addEventListener("click", () => opts.onSelect(cell.item));
    host.append(tile);
  }

  container.append(host);
  return host;
}

/**
 * Choose a readable foreground for a tile given its area fraction.
 *
 * Small tiles are drowned by their own text at the default weight, so the label
 * is dropped rather than shrunk to illegibility.
 */
export function tileFits(cell) {
  return cell.width >= 72 && cell.height >= 34;
}