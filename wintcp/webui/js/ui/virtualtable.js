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
    rowHeight: baseRowHeight = 40,
    height = 400,
    onRowClick = null,
    onRowContextMenu = null,
    onSort = null,
    sortKey = null,
    sortDir = null,
    label = "Data table",
    emptyMessage: initialEmptyMessage = "No rows",
    minWidth = null,
    scrollTop = 0,
    onScroll = null,
    rowKey = null,
    format = {},
    multiSelect = false,
    onSelectionChange = null,
  } = opts;
  const allColumns = columns.map((column) => ({ ...column }));
  let activeColumns = allColumns;
  let columnOrder = allColumns.map((column) => column.key);
  let hiddenColumns = new Set();
  let columnWidths = new Map(allColumns.map((column) => [column.key, column.width || 1]));
  let rowHeight = document.body.classList.contains("density-compact")
    ? Math.max(24, baseRowHeight - 6) : baseRowHeight;
  let destroyed = false;
  let frame = null;
  let restoreFrame = null;
  let emptyMessage = initialEmptyMessage;
  let currentSortKey = sortKey;
  let currentSortDir = sortDir;
  let currentScrollTop = scrollTop;

  const state = {
    rows: [],
    knownRows: [],
    scrollTop: 0,
    viewportH: height,
    startIdx: 0,
    endIdx: 0,
    activeIndex: -1,
  };
  const selectedRows = new Map();
  let selectionAnchorKey = null;

  function keyOf(row, index) {
    return rowKey ? String(rowKey(row)) : String(index);
  }

  function selectedRowsInViewOrder() {
    const ordered = [];
    const found = new Set();
    for (let index = 0; index < state.rows.length; index++) {
      const row = state.rows[index];
      const key = keyOf(row, index);
      if (!selectedRows.has(key)) continue;
      ordered.push(selectedRows.get(key));
      found.add(key);
    }
    for (const [key, row] of selectedRows) {
      if (!found.has(key)) ordered.push(row);
    }
    return ordered;
  }

  function notifySelection() {
    if (!onSelectionChange) return;
    const visible = new Set(state.rows.map((row, index) => keyOf(row, index)));
    const current = new Map(state.knownRows.map((row, index) => [keyOf(row, index), row]));
    const rows = selectedRowsInViewOrder();
    let visibleCount = 0;
    let currentCount = 0;
    let staleCount = 0;
    for (const [key] of selectedRows) {
      const latest = current.get(key);
      if (latest) {
        currentCount++;
        selectedRows.set(key, latest);
        if (visible.has(key)) visibleCount++;
      } else {
        staleCount++;
      }
    }
    onSelectionChange({
      rows,
      selectedCount: rows.length,
      currentCount,
      visibleCount,
      hiddenCount: currentCount - visibleCount,
      staleCount,
    });
  }

  function selectedCurrentRows() {
    const currentKeys = new Set(state.knownRows.map((row, index) => keyOf(row, index)));
    return selectedRowsInViewOrder().filter((row) => currentKeys.has(String(rowKey(row))));
  }

  function selectSingle(index) {
    const row = state.rows[index];
    if (!row || !multiSelect) return;
    const key = keyOf(row, index);
    selectedRows.clear();
    selectedRows.set(key, row);
    selectionAnchorKey = key;
    notifySelection();
    render();
  }

  function toggleSelection(index) {
    const row = state.rows[index];
    if (!row || !multiSelect) return;
    const key = keyOf(row, index);
    if (selectedRows.has(key)) selectedRows.delete(key);
    else selectedRows.set(key, row);
    selectionAnchorKey = key;
    notifySelection();
    render();
  }

  function selectRange(index, additive = false) {
    const row = state.rows[index];
    if (!row || !multiSelect) return;
    const key = keyOf(row, index);
    let anchor = state.rows.findIndex((item, itemIndex) =>
      keyOf(item, itemIndex) === selectionAnchorKey);
    if (anchor < 0) {
      selectionAnchorKey = key;
      anchor = index;
    }
    if (!additive) selectedRows.clear();
    for (let current = Math.min(anchor, index); current <= Math.max(anchor, index); current++) {
      const selected = state.rows[current];
      selectedRows.set(keyOf(selected, current), selected);
    }
    notifySelection();
    render();
  }

  function clearSelection() {
    if (!selectedRows.size) return;
    selectedRows.clear();
    selectionAnchorKey = null;
    notifySelection();
    render();
  }

  function selectAll() {
    if (!multiSelect) return;
    selectedRows.clear();
    for (let index = 0; index < state.rows.length; index++) {
      selectedRows.set(keyOf(state.rows[index], index), state.rows[index]);
    }
    selectionAnchorKey = state.rows.length ? keyOf(state.rows[0], 0) : null;
    notifySelection();
    render();
  }

  function getViewState() {
    return { selectedKeys: [...selectedRows.keys()], scrollTop: currentScrollTop };
  }

  function restoreViewState(viewState) {
    if (destroyed || !viewState || typeof viewState !== "object") return false;
    selectedRows.clear();
    const currentRows = new Map(state.knownRows.map((row, index) => [keyOf(row, index), row]));
    if (multiSelect && rowKey && Array.isArray(viewState.selectedKeys)) {
      for (const key of viewState.selectedKeys) {
        if (typeof key === "string" && currentRows.has(key))
          selectedRows.set(key, currentRows.get(key));
      }
    }
    selectionAnchorKey = selectedRows.keys().next().value || null;
    notifySelection();
    render();
    const applyScroll = () => {
      restoreFrame = null;
      if (destroyed) return;
      if (!wrapper.isConnected || wrapper.clientHeight === 0) {
        restoreFrame = requestAnimationFrame(applyScroll);
        return;
      }
      const maxScroll = Math.max(0, wrapper.scrollHeight - wrapper.clientHeight);
      currentScrollTop = Number.isFinite(viewState.scrollTop)
        ? Math.max(0, Math.min(maxScroll, viewState.scrollTop)) : 0;
      wrapper.scrollTop = currentScrollTop;
      render();
    };
    if (restoreFrame !== null) cancelAnimationFrame(restoreFrame);
    restoreFrame = requestAnimationFrame(applyScroll);
    return true;
  }

  // tabindex="0" is what makes the scroller keyboard-reachable: without it the
  // region scrolls with the mouse wheel only (axe: scrollable-region-focusable).
  const wrapper = h("div", {
    class: "virtual-table",
    role: "grid",
    tabindex: "0",
    "aria-label": label,
    "aria-multiselectable": multiSelect ? "true" : undefined,
    "aria-rowcount": "0",
    style: minWidth ? `--virtual-table-min-width: ${minWidth}; position: relative;` : "position: relative;",
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
      `position: sticky; top: 0; z-index: 1; min-width: var(--virtual-table-min-width, 0);`,
  });
  const headerCells = new Map();
  function buildHeaderCells() {
    header.replaceChildren();
    headerCells.clear();
    activeColumns.forEach((col, index) => {
    const isSorted = col.sortable && currentSortKey === col.key;
    const indicator = col.sortable
      ? (isSorted ? (currentSortDir === "asc" ? " \u25B2" : " \u25BC") : "")
      : "";
    const headerStyle = isSorted
      ? `flex: ${col.width || 1}; padding: 0.5rem 0.75rem; font-size: 0.75rem; ` +
        "font-weight: 600; color: var(--primary); text-transform: uppercase; " +
        "letter-spacing: 0.05em; white-space: nowrap; cursor: pointer;"
      : `flex: ${col.width || 1}; padding: 0.5rem 0.75rem; font-size: 0.75rem; ` +
        "font-weight: 500; color: var(--muted-foreground); text-transform: uppercase; " +
        "letter-spacing: 0.05em; white-space: nowrap;" +
        (col.sortable ? " cursor: pointer;" : "");
    const cell = h("div", {
        role: "columnheader",
        "aria-colindex": String(index + 1),
        "data-column-key": col.key,
        "aria-sort": isSorted
          ? (currentSortDir === "asc" ? "ascending" : "descending")
          : (col.sortable ? "none" : undefined),
        style: headerStyle + ` text-align: ${col.align || "left"};` +
          (col.actions ? " padding: 0.5rem 0.375rem;" : ""),
        tabindex: col.sortable ? "0" : undefined,
        onclick: col.sortable && onSort
          ? () => onSort(col.key, currentSortKey === col.key && currentSortDir === "asc" ? "desc" : (currentSortKey === col.key ? "asc" : (col.initialSort || "asc")))
          : null,
        onkeydown: (col.sortable && onSort)
          ? (event) => {
            if (event.key !== "Enter" && event.key !== " ") return;
            event.preventDefault();
            event.stopPropagation();
            onSort(col.key, currentSortKey === col.key && currentSortDir === "asc"
              ? "desc" : (currentSortKey === col.key ? "asc" : (col.initialSort || "asc")));
          }
          : null,
      }, col.label + indicator);
    headerCells.set(col.key, { col, cell });
      header.append(cell);
    });
  }
  buildHeaderCells();
  function updateSort(nextKey, nextDir) {
    currentSortKey = nextKey;
    currentSortDir = nextDir;
    for (const { col, cell } of headerCells.values()) {
      if (!col.sortable) continue;
      const isSorted = currentSortKey === col.key;
      cell.textContent = col.label + (isSorted
        ? (currentSortDir === "asc" ? " \u25B2" : " \u25BC")
        : "");
      cell.setAttribute("aria-sort", isSorted
        ? (currentSortDir === "asc" ? "ascending" : "descending")
        : "none");
      cell.style.color = isSorted ? "var(--primary)" : "var(--muted-foreground)";
      cell.style.fontWeight = isSorted ? "600" : "500";
    }
  }

  function getLayout() {
    return {
      version: 1,
      order: columnOrder.slice(),
      hidden: allColumns.filter((column) => hiddenColumns.has(column.key)).map((column) => column.key),
      widths: Object.fromEntries(columnWidths),
    };
  }

  function setLayout(layout = {}) {
    const knownKeys = new Set(allColumns.map((column) => column.key));
    const order = [];
    for (const key of Array.isArray(layout.order) ? layout.order : []) {
      if (knownKeys.has(key) && !order.includes(key)) order.push(key);
    }
    for (const column of allColumns) if (!order.includes(column.key)) order.push(column.key);
    const hidden = new Set((Array.isArray(layout.hidden) ? layout.hidden : [])
      .filter((key) => knownKeys.has(key)));
    const widths = new Map(allColumns.map((column) => [column.key, column.width || 1]));
    for (const column of allColumns) {
      const width = Number(layout.widths?.[column.key]);
      if (Number.isFinite(width) && width >= 0.5 && width <= 4) widths.set(column.key, width);
    }
    let nextColumns = order.filter((key) => !hidden.has(key)).map((key) => {
      const column = allColumns.find((candidate) => candidate.key === key);
      return {
        ...column,
        width: widths.get(key),
      };
    });
    if (!nextColumns.length && allColumns.length) {
      hidden.delete(allColumns[0].key);
      nextColumns = [{ ...allColumns[0], width: widths.get(allColumns[0].key) }];
    }
    columnOrder = order;
    hiddenColumns = hidden;
    columnWidths = widths;
    activeColumns = nextColumns;
    buildHeaderCells();
    for (const node of rowNodes.values()) node.remove();
    rowNodes.clear();
    render();
  }
  headerGroup.append(header);

  const inner = h("div", { class: "virtual-table-inner", role: "rowgroup" });
  const spacerTop = h("div", { role: "presentation", "aria-hidden": "true", style: "height: 0px;" });
  const spacerBottom = h("div", { role: "presentation", "aria-hidden": "true", style: "height: 0px;" });

  inner.append(spacerTop, spacerBottom);
  wrapper.append(headerGroup, inner);
  if (currentScrollTop > 0) wrapper.scrollTop = currentScrollTop;

  // The empty state is a role="row" like any other, so it needs a role="gridcell"
  // child: a row containing bare text violates aria-required-children, which axe
  // reports as CRITICAL. It is also given the full column span so a screen reader
  // announces it as occupying the table rather than as a stray cell.
  //
  // A gridcell is a required child, but a bare role="gridcell" with no role="row"
  // above it would fail the same rule in reverse, so the pairing matters.
  const emptyCell = h("div", { role: "gridcell", "aria-colspan": String(columns.length) }, emptyMessage);
  const emptyRow = h("div", {
    class: "virtual-table-empty muted",
    role: "row",
    "aria-rowindex": "2",
    style: `height: ${rowHeight}px; display: flex; align-items: center; padding: 0 0.75rem;`,
  }, emptyCell);

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
  const key = keyOf(row, index);
  const isActive = index === state.activeIndex;
  const isSelected = selectedRows.has(key);
  const rowEl = h("div", {
    class: `virtual-table-row${isActive ? " is-active" : ""}${isSelected ? " is-selected" : ""}${row.removed ? " is-closed" : ""}`,
    role: "row",
    tabindex: "-1",
    "aria-selected": multiSelect ? String(isSelected) : undefined,
    "aria-rowindex": String(index + 2),   // +1 for the header row, 1-based
    "data-index": String(index),
    "data-row-key": rowKey ? String(rowKey(row)) : undefined,
    style:
      `display: flex; height: ${rowHeight}px; border-bottom: 1px solid var(--border); ` +
      "align-items: center; cursor: pointer; min-width: var(--virtual-table-min-width, 0);",
    onclick: (event) => {
      if (event.target.closest("button, a, input, select, textarea, [contenteditable=true]")) return;
      setActive(index);
      if (multiSelect && event.shiftKey) {
        selectRange(index, event.ctrlKey || event.metaKey);
        return;
      }
      if (multiSelect && (event.ctrlKey || event.metaKey)) {
        toggleSelection(index);
        return;
      }
      selectSingle(index);
      if (onRowClick) onRowClick(row, index);
    },
    oncontextmenu: onRowContextMenu ? (event) => {
      event.preventDefault();
      setActive(index);
      if (multiSelect && !selectedRows.has(key)) selectSingle(index);
      onRowContextMenu(row, event, rowEl);
    } : null,
    onkeydown: (event) => {
      if (event.target !== rowEl) return;
      if (onRowContextMenu && (event.key === "ContextMenu" || (event.shiftKey && event.key === "F10"))) {
        event.preventDefault();
        event.stopPropagation();
        onRowContextMenu(row, event, rowEl);
        return;
      }
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        event.stopPropagation();
        setActive(index);
        if (multiSelect && event.key === " ") toggleSelection(index);
        else {
          selectSingle(index);
          if (onRowClick) onRowClick(row, index);
        }
      }
    },
  });
  activeColumns.forEach((col, colIndex) => {
    const cellStyle = col.actions
      ? `flex: ${col.width || 0.8}; padding: 0 0.375rem; display: flex; gap: 0.25rem; align-items: center; justify-content: flex-end;`
      : `flex: ${col.width || 1}; padding: 0 0.75rem; font-size: 0.875rem; ` +
        "white-space: nowrap; overflow: hidden; text-overflow: ellipsis;";
    const raw = row[col.key];
    const value = col.renderCell ? col.renderCell(row, rowEl)
      : format[col.key] ? format[col.key](row)
      : raw != null && raw !== "" ? String(raw) : "—";
    const title = col.title ? col.title(row)
      : typeof raw === "number" || typeof raw === "bigint" ||
        (typeof raw === "string" && /^\d+$/.test(raw)) ? String(raw)
      : typeof value === "string" ? value : "";
    rowEl.append(h("div", {
      role: "gridcell",
      "aria-colindex": String(colIndex + 1),
      "data-column-key": col.key,
      title,
      style: cellStyle + ` text-align: ${col.align || "left"}; min-width: ${col.actions ? "6rem" : "0"};`,
    }, value));
  });
  return rowEl;
}

  function rowCount() {
    return state.rows.length;
  }

  // Keep the active row inside the rendered window so the DOM node exists.
  function ensureRendered(index) {
    const headerHeight = header.getBoundingClientRect().height;
    const viewportH = (wrapper.clientHeight || height) - headerHeight;
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
    if (node) node.focus({ preventScroll: true });
  }

  function updateRows(newRows, nextEmptyMessage = undefined, options = {}) {
    if (destroyed) return;
    const previousRows = state.rows;
    const activeKey = rowKey && state.activeIndex >= 0 && previousRows[state.activeIndex]
      ? rowKey(previousRows[state.activeIndex])
      : null;
    const keepFocus = document.activeElement;
    const focusedRow = wrapper.contains(keepFocus) ? keepFocus?.closest(".virtual-table-row") : null;
    const focusedIndex = focusedRow ? Number(focusedRow.dataset.index) : -1;
    const controls = focusedRow ? [...focusedRow.querySelectorAll("button, a, input, select")] : [];
    const focusedControl = controls.indexOf(keepFocus);
    const focusedKey = rowKey && focusedIndex >= 0 && previousRows[focusedIndex]
      ? rowKey(previousRows[focusedIndex])
      : null;
    state.rows = Array.isArray(newRows) ? newRows : [];
    state.knownRows = Array.isArray(options.allRows) ? options.allRows : state.rows;
    if (multiSelect && rowKey) {
      for (const row of state.knownRows) {
        const key = keyOf(row, 0);
        if (selectedRows.has(key)) selectedRows.set(key, row);
      }
      notifySelection();
    }
    if (typeof nextEmptyMessage === "string") emptyMessage = nextEmptyMessage;
    wrapper.setAttribute("aria-rowcount", String(state.rows.length + 1));
    let restoreTo = focusedIndex >= 0 ? String(focusedIndex) : null;
    if (rowKey) {
      state.activeIndex = activeKey == null
        ? -1
        : state.rows.findIndex((row) => rowKey(row) === activeKey);
      const focusedRowIndex = focusedKey == null
        ? -1
        : state.rows.findIndex((row) => rowKey(row) === focusedKey);
      restoreTo = focusedRowIndex >= 0 ? String(focusedRowIndex) : null;
    } else if (state.activeIndex >= state.rows.length) {
      state.activeIndex = -1;
    }
    // The rows themselves changed, so the cached nodes are stale - their text
    // still shows the previous data. Drop them, but remember where focus was so
    // it can be handed back after the rebuild.
    for (const node of rowNodes.values()) node.remove();
    rowNodes.clear();
    render();
    if (currentScrollTop > 0) {
      scheduleRender(() => {
        wrapper.scrollTop = currentScrollTop;
        render();
        if (onScroll) onScroll(wrapper.scrollTop);
      });
    }
    if (restoreTo !== null) {
      const focusIndex = Number(restoreTo);
      if (!rowNodes.has(focusIndex)) ensureRendered(focusIndex);
      if (rowNodes.has(focusIndex)) {
        const row = rowNodes.get(focusIndex);
        const control = focusedControl >= 0 ? row.querySelectorAll("button, a, input, select")[focusedControl] : null;
        (control || row).focus({ preventScroll: true });
      }
    }
  }

  function render() {
    if (destroyed) return;
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
      emptyCell.textContent = emptyMessage;
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
    let anchor = spacerBottom;
    for (let index = endIdx - 1; index >= startIdx; index--) {
      let node = rowNodes.get(index);
      if (!node) {
        node = buildRow(index);
        rowNodes.set(index, node);
      }
      node.classList.toggle("is-active", index === state.activeIndex);
      node.classList.toggle("is-selected", selectedRows.has(keyOf(state.rows[index], index)));
      if (multiSelect) node.setAttribute("aria-selected",
        String(selectedRows.has(keyOf(state.rows[index], index))));
      if (node.nextSibling !== anchor) inner.insertBefore(node, anchor);
      anchor = node;
    }
  }

  // Keyboard navigation on the scroller. Without this a virtualised grid is
  // mouse-only, and the scrollbar cannot be reached either.
  wrapper.addEventListener("keydown", (event) => {
    if (event.target.closest("button, a, input, select, textarea, [role=columnheader]")) return;
    const total = rowCount();
    if (total === 0) return;
    if (multiSelect && (event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "a") {
      event.preventDefault();
      selectAll();
      return;
    }
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

  function scheduleRender(callback = render) {
    if (destroyed) return;
    if (frame !== null) cancelAnimationFrame(frame);
    frame = requestAnimationFrame(() => {
      frame = null;
      if (!destroyed) callback();
    });
  }

  wrapper.addEventListener("scroll", () => {
    currentScrollTop = wrapper.scrollTop;
    if (onScroll) onScroll(wrapper.scrollTop);
    scheduleRender();
  });

  const onResize = () => {
    state.viewportH = wrapper.clientHeight;
    render();
  };
  window.addEventListener("resize", onResize);

  // Consumers that re-render the page throw the old table away; drop the
  // listener so a long session does not accumulate one per page view.
  const resizeObserver = new ResizeObserver(() => scheduleRender());
  resizeObserver.observe(wrapper);
  const densityObserver = new MutationObserver(() => {
    const nextHeight = document.body.classList.contains("density-compact")
      ? Math.max(24, baseRowHeight - 6) : baseRowHeight;
    if (rowHeight === nextHeight) return;
    const topRow = wrapper.scrollTop / rowHeight;
    rowHeight = nextHeight;
    for (const node of rowNodes.values()) node.remove();
    rowNodes.clear();
    emptyRow.style.height = `${rowHeight}px`;
    wrapper.scrollTop = topRow * rowHeight;
    currentScrollTop = wrapper.scrollTop;
    render();
  });
  densityObserver.observe(document.body, { attributes: true, attributeFilter: ["class"] });
  const destroy = () => {
    destroyed = true;
    if (frame !== null) cancelAnimationFrame(frame);
    if (restoreFrame !== null) cancelAnimationFrame(restoreFrame);
    resizeObserver.disconnect();
    densityObserver.disconnect();
    window.removeEventListener("resize", onResize);
  };

  render();

  return {
    updateRows, updateSort, render, wrapper, destroy, setActive,
    clearSelection, selectAll,
    getViewState, restoreViewState,
    getLayout, setLayout,
    getColumns: () => allColumns.map((column) => ({ ...column })),
    getVisibleColumns: () => activeColumns.map((column) => ({ ...column })),
    getSelectedRows: selectedRowsInViewOrder,
    getCurrentSelectedRows: selectedCurrentRows,
  };
}
