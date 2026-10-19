import { h } from "../h.js";
import { api } from "../api.js";

export function createColumnLayoutControls(table, {
  columns = table.getColumns(),
  layoutKey,
  required = [],
  compactHidden = [],
}) {
  const defaults = table.getLayout();
  const requiredKeys = new Set(required);
  const compactKeys = new Set(compactHidden);
  const loadController = new AbortController();
  const details = h("details", { class: "column-layout" });
  const summary = h("summary", { class: "btn btn-sm btn-ghost" }, "Columns");
  const panel = h("div", { class: "column-layout-panel", role: "group", "aria-label": "Table column layout" });
  const status = h("span", { class: "column-layout-status muted", role: "status", "aria-live": "polite" });
  details.append(summary, panel);

  let disposed = false;
  let editGeneration = 0;
  let configReadGeneration = 0;
  let locallyEdited = false;
  let saveTimer = null;
  let layout = defaults;

  function normalized(next) {
    const hidden = Array.isArray(next.hidden) ? next.hidden.filter((key) => !requiredKeys.has(key)) : [];
    table.setLayout({ ...next, hidden });
    layout = table.getLayout();
  }

  async function persist() {
    const snapshot = layout;
    if (!disposed) status.textContent = "Saving layout…";
    try {
      await api.updateConfig((current) => ({
        ...current,
        preferences: {
          ...(current.preferences || {}),
          tableLayouts: {
            ...(current.preferences?.tableLayouts || {}),
            [layoutKey]: snapshot,
          },
        },
      }));
      if (!disposed && snapshot === layout) {
        locallyEdited = false;
        status.textContent = "Layout saved";
      }
    } catch (error) {
      if (!disposed) status.textContent = `Layout not saved: ${error.message}`;
    }
  }

  function saveSoon() {
    if (saveTimer !== null) clearTimeout(saveTimer);
    status.textContent = "Unsaved layout changes";
    saveTimer = setTimeout(() => {
      saveTimer = null;
      persist();
    }, 250);
  }

  function focusControl(key) {
    if (!key) return;
    panel.querySelector(`[data-layout-control="${CSS.escape(key)}"]`)?.focus();
  }

  function apply(next, focusKey = "") {
    editGeneration++;
    locallyEdited = true;
    normalized(next);
    renderPanel(focusKey);
    saveSoon();
    details.dispatchEvent(new CustomEvent("tablelayoutchange", { bubbles: true }));
  }

  function renderPanel(focusKey = "") {
    const actions = h("div", { class: "column-layout-presets" },
      h("button", {
        class: "btn btn-ghost btn-xs", type: "button", "data-layout-control": "preset-default",
        onclick: () => apply(defaults, "preset-default"),
      }, "Default"),
      h("button", {
        class: "btn btn-ghost btn-xs", type: "button", "data-layout-control": "preset-compact",
        onclick: () => apply({ ...layout, hidden: [...compactKeys] }, "preset-compact"),
      }, "Essentials"),
      h("button", {
        class: "btn btn-ghost btn-xs", type: "button", "data-layout-control": "preset-all",
        onclick: () => apply({ ...layout, hidden: [] }, "preset-all"),
      }, "All columns"),
    );
    const ordered = layout.order.map((key) => columns.find((column) => column.key === key)).filter(Boolean);
    const rows = ordered.map((column, index) => {
      const hidden = layout.hidden.includes(column.key);
      const width = Number(layout.widths[column.key]) || 1;
      const key = column.key;
      const label = column.label || key;
      return h("div", { class: "column-layout-row", "data-layout-key": key },
        h("label", { class: "column-layout-label" },
          h("input", {
            type: "checkbox", checked: !hidden, disabled: requiredKeys.has(key),
            "aria-label": `Show ${label} column`,
            "data-layout-control": `${key}-visible`,
            onchange: (event) => apply({ ...layout, hidden: event.target.checked
              ? layout.hidden.filter((item) => item !== key)
              : [...layout.hidden, key] }, `${key}-visible`),
          }),
          h("span", {}, label)),
        h("div", { class: "column-layout-actions" },
          h("button", {
            class: "btn btn-ghost btn-xs", type: "button", disabled: index === 0,
            "aria-label": `Move ${label} column earlier`, "data-layout-control": `${key}-up`,
            onclick: () => {
              const order = layout.order.slice();
              const position = order.indexOf(key);
              if (position > 0) [order[position - 1], order[position]] = [order[position], order[position - 1]];
              apply({ ...layout, order }, `${key}-up`);
            },
          }, "↑"),
          h("button", {
            class: "btn btn-ghost btn-xs", type: "button", disabled: index === ordered.length - 1,
            "aria-label": `Move ${label} column later`, "data-layout-control": `${key}-down`,
            onclick: () => {
              const order = layout.order.slice();
              const position = order.indexOf(key);
              if (position >= 0 && position < order.length - 1) [order[position], order[position + 1]] = [order[position + 1], order[position]];
              apply({ ...layout, order }, `${key}-down`);
            },
          }, "↓"),
          h("button", {
            class: "btn btn-ghost btn-xs", type: "button", disabled: width <= 0.5,
            "aria-label": `Narrow ${label} column`, "data-layout-control": `${key}-narrower`,
            onclick: () => apply({ ...layout, widths: { ...layout.widths, [key]: Math.max(0.5, width - 0.25) } }, `${key}-narrower`),
          }, "−"),
          h("button", {
            class: "btn btn-ghost btn-xs", type: "button", disabled: width >= 4,
            "aria-label": `Widen ${label} column`, "data-layout-control": `${key}-wider`,
            onclick: () => apply({ ...layout, widths: { ...layout.widths, [key]: Math.min(4, width + 0.25) } }, `${key}-wider`),
          }, "+"),
        ));
    });
    panel.replaceChildren(actions, ...rows, status);
    focusControl(focusKey);
  }

  renderPanel();
  async function loadSavedLayout(remote = false) {
    const generation = ++configReadGeneration;
    try {
      const config = await api.get("/api/config", { signal: loadController.signal });
      if (disposed || generation !== configReadGeneration || locallyEdited) return;
      const saved = config.preferences?.tableLayouts?.[layoutKey];
      if (saved && saved.version === 1) {
        normalized(saved);
        renderPanel();
        status.textContent = remote ? "Layout synchronized from another tab" : "Saved layout loaded";
      }
    } catch (error) {
      if (!disposed && error.name !== "AbortError") status.textContent = "Using current layout; saved layout could not be read";
    }
  }
  const unsubscribeConfig = api.subscribeConfigChanges(() => {
    if (!disposed && !locallyEdited && saveTimer === null) loadSavedLayout(true);
  });
  loadSavedLayout();

  return {
    element: details,
    applySavedLayout(next) {
      if (disposed || !next || next.version !== 1) return false;
      editGeneration++;
      normalized(next);
      renderPanel();
      status.textContent = "Saved view layout loaded";
      return true;
    },
    destroy() {
      disposed = true;
      unsubscribeConfig();
      loadController.abort();
      if (saveTimer !== null) {
        clearTimeout(saveTimer);
        persist();
      }
      saveTimer = null;
    },
  };
}
