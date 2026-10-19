// ui/virtualtable.js - Virtualised table with fixed row height
// Handles 10,000+ rows with window + spacer rows, diffed updates.
//
// Accessibility is not optional here: a virtualised grid is the one table shape
// that gets thrown together as bare <div>s, and a bare scrollable <div> with no
// tabindex cannot be scrolled from the keyboard at all. So this builds a real
// grid: role=grid on the scroller, columnheader/row/gridcell on the parts, an
// accessible name, and full arrow-key / page-key / home-end navigation.

import { h } from "../h.js";

export function createVirtualTable(container, opts = {}) {
  const {
    columns = [],
    rowHeight = 40,
    height = 400,
    onRowClick = null,
    onSort = null,
    sortKey = null,
    sortDir = null,
    label = "Data table",
    emptyMessage = "No rows",
  } = opts;

  const state = {
    rows: [],
    scrollTop: 0,
    viewportH: height,
    startIdx: 0,
    endIdx: 0,
    activeIndex: -1,
  };

  // tabindex="0" is what makes the scroller keyboard-reachable: without it the
  // region scrolls with the mouse wheel only (axe: scrollable-region-focusable).
  const wrapper = h("div", {
    class: "virtual-table",
    role: "grid",
    tabindex: "0",
    "aria-label": label,
    "aria-rowcount": "0",
    style: `height: ${height}px; overflow-y: auto; position: relative;`,
  });

  // The header MUST live inside the role=grid element. It used to be a sibling
  // of the scroller, which made its role="row" an orphan and tripped axe's
  // critical aria-required-parent. Sticky positioning keeps it pinned while the
  // body scrolls underneath.
  const headerGroup = h("div", { role: "rowgroup" });
  const header = h("div", {
    class: "virtual-table-header",
    role: "row",
    "aria-rowindex": "1",
    style:
      "display: flex; border-bottom: 1px solid var(--border); background: var(--muted); " +
      "position: sticky; top: 0; z-index: 1;",
  });
  columns.forEach((col, index) => {
    const isSorted = col.sortable && sortKey === col.key;
    const indicator = col.sortable
      ? (isSorted ? (sortDir === "asc" ? " \u25B2" : " \u25BC") : "")
      : "";
    const headerStyle = isSorted
      ? `flex: ${col.width || 1}; padding: 0.5rem 0.75rem; font-size: 0.75rem; ` +
        "font-weight: 600; color: var(--primary); text-transform: uppercase; " +
        "letter-spacing: 0.05em; white-space: nowrap; cursor: pointer;"
      : `flex: ${col.width || 1}; padding: 0.5rem 0.75rem; font-size: 0.75rem; ` +
        "font-weight: 500; color: var(--muted-foreground); text-transform: uppercase; " +
        "letter-spacing: 0.05em; white-space: nowrap;" +
        (col.sortable ? " cursor: pointer;" : "");
    header.append(
      h("div", {
        role: "columnheader",
        "aria-colindex": String(index + 1),
        "aria-sort": isSorted
          ? (sortDir === "asc" ? "ascending" : "descending")
          : (col.sortable ? "none" : undefined),
        style: headerStyle,
        tabindex: col.sortable ? "0" : undefined,
        onclick: col.sortable && onSort
          ? () => onSort(col.key, sortDir === "asc" ? "desc" : "asc")
          : null,
        onkeydown: (col.sortable && onSort)
          ? (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onSort(col.key, sortDir === "asc" ? "desc" : "asc"); } }
          : null,
      }, col.label + indicator),
    );
  });
  headerGroup.append(header);

  const inner = h("div", { class: "virtual-table-inner", role: "rowgroup" });
  const spacerTop = h("div", { role: "presentation", "aria-hidden": "true", style: "height: 0px;" });
  const spacerBottom = h("div", { role: "presentation", "aria-hidden": "true", style: "height: 0px;" });

  inner.append(spacerTop, spacerBottom);
  wrapper.append(headerGroup, inner);

  // The empty state is a role="row" like any other, so it needs a role="gridcell"
  // child: a row containing bare text violates aria-required-children, which axe
  // reports as CRITICAL. It is also given the full column span so a screen reader
  // announces it as occupying the table rather than as a stray cell.
  //
  // A gridcell is a required child, but a bare role="gridcell" with no role="row"
  // above it would fail the same rule in reverse, so the pairing matters.
  const emptyRow = h("div", {
    class: "virtual-table-empty muted",
    role: "row",
    "aria-rowindex": "2",
    style: `height: ${rowHeight}px; display: flex; align-items: center; padding: 0 0.75rem;`,
  }, h("div", { role: "gridcell", "aria-colspan": String(columns.length) }, emptyMessage));

  container.append(wrapper);

  // Row nodes are keyed by row index and REUSED across renders.
//
// Rebuilding every row on every render is not just wasteful, it is what broke
// the keyboard: setting scrollTop queues a scroll event whose rAF callback
// re-renders, which removed the very node that had just been focused, and the
// browser dropped focus to <body>. After that no key reached the widget, so
// "press End, then Home" silently did nothing. Keeping the nodes means the
// focused one survives its own re-render.
const rowNodes = new Map();

function buildRow(index) {
  const row = state.rows[index];
  const isActive = index === state.activeIndex;
  const rowEl = h("div", {
    class: `virtual-table-row${isActive ? " is-active" : ""}`,
    role: "row",
    tabindex: "-1",
    "aria-rowindex": String(index + 2),   // +1 for the header row, 1-based
    "data-index": String(index),
    style:
      `display: flex; height: ${rowHeight}px; border-bottom: 1px solid var(--border); ` +
      "align-items: center; cursor: pointer;",
    onclick: () => {
      setActive(index);
      if (onRowClick) onRowClick(row, index);
    },
    onkeydown: (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        setActive(index);
        if (onRowClick) onRowClick(row, index);
      }
    },
  });
  columns.forEach((col, colIndex) => {
    const cellStyle = col.actions
      ? `flex: ${col.width || 0.8}; padding: 0 0.375rem; display: flex; gap: 0.25rem; align-items: center; justify-content: flex-end;`
      : `flex: ${col.width || 1}; padding: 0 0.75rem; font-size: 0.875rem; ` +
        "white-space: nowrap; overflow: hidden; text-overflow: ellipsis;";
    if (col.renderCell && col.renderCell(row) !== undefined) {
      const cell = h("div", {
        role: "gridcell",
        "aria-colindex": String(colIndex + 1),
        style: cellStyle,
      });
      cell.append(col.renderCell(row, rowEl));
      rowEl.append(cell);
    } else {
    const val = row[col.key] != null ? String(row[col.key]) : "-";
    rowEl.append(
      h("div", {
        role: "gridcell",
        "aria-colindex": String(colIndex + 1),
        title: val,
        style: cellStyle,
      }, val),
    );
    }
  });
  return rowEl;
}

  function rowCount() {
    return state.rows.length;
  }

  // Keep the active row inside the rendered window so the DOM node exists.
  function ensureRendered(index) {
    const viewportH = wrapper.clientHeight || height;
    if (index * rowHeight < wrapper.scrollTop) {
      wrapper.scrollTop = index * rowHeight;
    } else if ((index + 1) * rowHeight > wrapper.scrollTop + viewportH) {
      wrapper.scrollTop = (index + 1) * rowHeight - viewportH;
    }
    render();
  }

  function setActive(index) {
    const total = rowCount();
    if (total === 0) {
      state.activeIndex = -1;
      render();
      return;
    }
    state.activeIndex = Math.max(0, Math.min(index, total - 1));
    ensureRendered(state.activeIndex);
    const node = rowNodes.get(state.activeIndex);
    if (node) node.focus();
  }

  function updateRows(newRows) {
    state.rows = Array.isArray(newRows) ? newRows : [];
    wrapper.setAttribute("aria-rowcount", String(state.rows.length + 1));
    if (state.activeIndex >= state.rows.length) state.activeIndex = -1;
    // The rows themselves changed, so the cached nodes are stale - their text
    // still shows the previous data. Drop them, but remember where focus was so
    // it can be handed back after the rebuild.
    const keepFocus = document.activeElement;
    const wasRow = keepFocus && keepFocus.dataset && keepFocus.dataset.index !== undefined;
    const restoreTo = wasRow ? keepFocus.dataset.index : null;
    for (const node of rowNodes.values()) node.remove();
    rowNodes.clear();
    render();
    if (restoreTo !== null && rowNodes.has(Number(restoreTo))) {
      rowNodes.get(Number(restoreTo)).focus();
    }
  }

  function render() {
    const total = rowCount();
    const scrollTop = wrapper.scrollTop;
    const viewportH = wrapper.clientHeight || height;

    const startIdx = Math.max(0, Math.floor(scrollTop / rowHeight) - 5);
    const endIdx = Math.min(total, Math.ceil((scrollTop + viewportH) / rowHeight) + 5);

    state.startIdx = startIdx;
    state.endIdx = endIdx;
    state.scrollTop = scrollTop;
    state.viewportH = viewportH;

    spacerTop.style.height = `${startIdx * rowHeight}px`;
    spacerBottom.style.height = `${Math.max(0, total - endIdx) * rowHeight}px`;

    if (total === 0) {
      for (const node of rowNodes.values()) node.remove();
      rowNodes.clear();
      if (!emptyRow.isConnected) inner.insertBefore(emptyRow, spacerBottom);
      return;
    }
    if (emptyRow.isConnected) emptyRow.remove();

    // Drop rows that scrolled out of the window; add rows that scrolled in.
    // Everything in between keeps its node, which is what preserves focus.
    for (const [index, node] of Array.from(rowNodes)) {
      if (index < startIdx || index >= endIdx) {
        node.remove();
        rowNodes.delete(index);
      }
    }
    for (let i = startIdx; i < endIdx; i++) {
      if (rowNodes.has(i)) {
        const existing = rowNodes.get(i);
        existing.classList.toggle("is-active", i === state.activeIndex);
        continue;
      }
      const node = buildRow(i);
      inner.insertBefore(node, spacerBottom);
      rowNodes.set(i, node);
    }
  }

  // Keyboard navigation on the scroller. Without this a virtualised grid is
  // mouse-only, and the scrollbar cannot be reached either.
  wrapper.addEventListener("keydown", (event) => {
    const total = rowCount();
    if (total === 0) return;
    const pageRows = Math.max(1, Math.floor((wrapper.clientHeight || height) / rowHeight) - 1);
    const current = state.activeIndex < 0 ? -1 : state.activeIndex;
    let next = null;
    switch (event.key) {
      case "ArrowDown": next = current < 0 ? 0 : current + 1; break;
      case "ArrowUp": next = current < 0 ? 0 : current - 1; break;
      case "PageDown": next = current < 0 ? 0 : current + pageRows; break;
      case "PageUp": next = current < 0 ? 0 : current - pageRows; break;
      case "Home": next = 0; break;
      case "End": next = total - 1; break;
      default: return;
    }
    event.preventDefault();
    setActive(next);
  });

  wrapper.addEventListener("scroll", () => {
    requestAnimationFrame(render);
  });

  const onResize = () => {
    state.viewportH = wrapper.clientHeight;
    render();
  };
  window.addEventListener("resize", onResize);

  // Consumers that re-render the page throw the old table away; drop the
  // listener so a long session does not accumulate one per page view.
  const destroy = () => window.removeEventListener("resize", onResize);

  render();

  return { updateRows, render, wrapper, destroy, setActive };
}