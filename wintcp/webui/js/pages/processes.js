// pages/processes.js - Processes page
import { h } from "../h.js";
import { table, thead, tbody, tr, th, td } from "../ui/table.js";

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
      h("div", { class: "table-container" },
        table({},
          thead({},
            tr({},
              th({}, "Name"), th({}, "PID"), th({}, "CPU %"),
              th({}, "Memory"), th({}, "I/O"), th({}, "Connections"),
            ),
          ),
          tbody({ id: "proc-rows" }),
        ),
      ),
    ),
  );
}
