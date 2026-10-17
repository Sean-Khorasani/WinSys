// pages/processes.js - Processes page
import { h, clear } from "../h.js";
import { createVirtualTable } from "../ui/virtualtable.js";
import { emptyState } from "../ui/card.js";

export async function renderProcesses(page, store) {
  clear(page);
  page.append(
    h("div", { class: "page-heading" },
      h("h1", { class: "page-title" }, "Processes"),
      h("p", { class: "page-description" }, "Process list, tree, and resource usage"),
    ),
    h("div", { class: "proc-layout" },
      h("div", { class: "proc-toolbar" },
        h("div", { class: "proc-views", role: "group", "aria-label": "Process view" },
          h("button", { class: "proc-view is-active", type: "button" }, "Table"),
          h("button", { class: "proc-view", type: "button", disabled: "" }, "Tree"),
          h("button", { class: "proc-view", type: "button", disabled: "" }, "Treemap"),
        ),
        h("input", {
          class: "input",
          id: "proc-filter",
          type: "search",
          placeholder: "Filter processes...",
          "aria-label": "Filter processes by name or PID",
        }),
      ),
      h("div", { id: "proc-table-container" }),
    ),
  );

  const container = page.querySelector("#proc-table-container");
  const filter = page.querySelector("#proc-filter");
  const conns = store.get().connections || [];

  // Distinguish "no first poll yet" from "genuinely nothing". An empty table
  // with no explanation reads as "this machine has no processes", which is both
  // wrong and untestable.
  if (!store.get().lastUpdate) {
    container.append(
      emptyState({}, "Waiting for the first sample",
        "The browser polls the server every couple of seconds. This fills in on its own."),
    );
    return;
  }

  const byPid = {};
  for (const c of conns) {
    if (!byPid[c.pid]) byPid[c.pid] = { pid: c.pid, name: c.process || "-", connections: 0 };
    byPid[c.pid].connections++;
  }
  let rows = Object.values(byPid);

  // The Tree and Treemap views are not built yet. A disabled control with an
  // explanation beats a button that silently does nothing.
  for (const label of ["Tree", "Treemap"]) {
    const button = Array.from(page.querySelectorAll(".proc-view"))
      .find((b) => b.textContent.trim() === label);
    if (button) button.title = "Not implemented yet";
  }

  const vt = createVirtualTable(container, {
    columns: [
      { key: "name", label: "Name", width: 3 },
      { key: "pid", label: "PID", width: 1 },
      { key: "connections", label: "Connections", width: 1 },
    ],
    rowHeight: 36,
    height: 500,
    label: "Processes with open endpoints",
    emptyMessage: "No processes hold open TCP or UDP endpoints.",
  });
  vt.updateRows(rows);

  filter.addEventListener("input", () => {
    const q = filter.value.trim().toLowerCase();
    rows = q
      ? Object.values(byPid).filter(
          (r) => String(r.name).toLowerCase().includes(q) || String(r.pid) === q)
      : Object.values(byPid);
    vt.updateRows(rows);
  });

  if (rows.length === 0) {
    // The table shows its own empty message; nothing further to do.
  }
  // The router clears this element wholesale on the next render, so hand the
  // previous table's teardown a chance to drop its resize listener first.
  page._procDestroy = vt.destroy;
}
