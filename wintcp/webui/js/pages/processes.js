// pages/processes.js - Processes page
import { h } from "../h.js";
import { createVirtualTable } from "../ui/virtualtable.js";

export async function renderProcesses(page, store) {
  page.innerHTML = "";
  page.append(
    h("div", { class: "page-heading" },
      h("h1", { class: "page-title" }, "Processes"),
      h("p", { class: "page-description" }, "Process list, tree, and resource usage"),
    ),
    h("div", { class: "proc-layout" },
      h("div", { class: "proc-toolbar" },
        h("div", { class: "proc-views" },
          h("button", { class: "proc-view is-active" }, "Table"),
          h("button", { class: "proc-view" }, "Tree"),
          h("button", { class: "proc-view" }, "Treemap"),
        ),
        h("input", { class: "input", type: "search", placeholder: "Filter processes...", style: "max-width: 20rem" }),
      ),
      h("div", { id: "proc-table-container" }),
    ),
  );

  const container = page.querySelector("#proc-table-container");
  const conns = store.get().connections || [];
  const byPid = {};
  for (const c of conns) {
    if (!byPid[c.pid]) byPid[c.pid] = { pid: c.pid, name: c.process || "-", connections: 0 };
    byPid[c.pid].connections++;
  }
  const rows = Object.values(byPid);

  const vt = createVirtualTable(container, {
    columns: [
      { key: "name", label: "Name", width: 2 },
      { key: "pid", label: "PID", width: 1 },
      { key: "connections", label: "Connections", width: 1 },
    ],
    rowHeight: 36,
    height: 500,
  });

  vt.updateRows(rows);
}
