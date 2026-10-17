// ui/virtualtable.js - Virtualised table with fixed row height
// Handles 10,000+ rows with window + spacer rows, diffed updates.

import { h } from "../h.js";

export function createVirtualTable(container, opts = {}) {
  const {
    columns = [],
    rowHeight = 40,
    height = 400,
    onRowClick = null,
  } = opts;

  const state = {
    rows: [],
    scrollTop: 0,
    viewportH: height,
    startIdx: 0,
    endIdx: 0,
  };

  const wrapper = h("div", {
    class: "virtual-table",
    style: `height: ${height}px; overflow-y: auto; position: relative;`,
  });

  const inner = h("div", {
    class: "virtual-table-inner",
    style: "position: relative;",
  });

  const spacerTop = h("div", { style: "height: 0px;" });
  const spacerBottom = h("div", { style: "height: 0px;" });
  const content = h("div", { class: "virtual-table-content" });

  inner.append(spacerTop, content, spacerBottom);
  wrapper.append(inner);

  // Header
  const header = h("div", { class: "virtual-table-header", style: "display: flex; border-bottom: 1px solid var(--border); background: var(--muted);" });
  for (const col of columns) {
    header.append(h("div", {
      style: `flex: ${col.width || 1}; padding: 0.5rem 0.75rem; font-size: 0.75rem; font-weight: 500; color: var(--muted-foreground); text-transform: uppercase; letter-spacing: 0.05em; white-space: nowrap;`,
    }, col.label));
  }

  container.append(header, wrapper);

  function updateRows(newRows) {
    state.rows = newRows;
    render();
  }

  function render() {
    const total = state.rows.length;
    const scrollTop = wrapper.scrollTop;
    const viewportH = wrapper.clientHeight || height;

    const startIdx = Math.max(0, Math.floor(scrollTop / rowHeight) - 5);
    const endIdx = Math.min(total, Math.ceil((scrollTop + viewportH) / rowHeight) + 5);

    spacerTop.style.height = `${startIdx * rowHeight}px`;
    spacerBottom.style.height = `${(total - endIdx) * rowHeight}px`;

    content.innerHTML = "";
    for (let i = startIdx; i < endIdx; i++) {
      const row = state.rows[i];
      const rowEl = h("div", {
        class: "virtual-table-row",
        style: `display: flex; height: ${rowHeight}px; border-bottom: 1px solid var(--border); align-items: center;`,
        onclick: onRowClick ? () => onRowClick(row, i) : null,
      });
      for (const col of columns) {
        const val = row[col.key] != null ? String(row[col.key]) : "-";
        rowEl.append(h("div", {
          style: `flex: ${col.width || 1}; padding: 0 0.75rem; font-size: 0.875rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;`,
        }, val));
      }
      content.append(rowEl);
    }
  }

  wrapper.addEventListener("scroll", () => {
    requestAnimationFrame(render);
  });

  window.addEventListener("resize", () => {
    state.viewportH = wrapper.clientHeight;
    render();
  });

  render();

  return { updateRows, render, wrapper };
}
