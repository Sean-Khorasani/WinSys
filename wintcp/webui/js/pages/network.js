// pages/network.js - Network page
import { h } from "../h.js";
import { badge } from "../ui/badge.js";
import { table, thead, tbody, tr, th, td } from "../ui/table.js";

export async function renderNetwork(page, store) {
  page.innerHTML = "";
  page.append(
    h("div", { class: "page-heading" },
      h("h1", { class: "page-title" }, "Network"),
      h("p", { class: "page-description" }, "Connections, listeners, and blocked peers"),
    ),
    h("div", { class: "tabs", role: "tablist" },
      h("button", { class: "tab is-active", role: "tab" }, "Connections"),
      h("button", { class: "tab", role: "tab" }, "Listening"),
      h("button", { class: "tab", role: "tab" }, "Blocked"),
      h("button", { class: "tab", role: "tab" }, "Flows"),
    ),
    h("div", { class: "table-container", style: "margin-top: 1rem" },
      table({},
        thead({},
          tr({},
            th({}, "Process"), th({}, "PID"), th({}, "Proto"),
            th({}, "Local"), th({}, "Remote"), th({}, "State"),
          ),
        ),
        tbody({ id: "network-rows" }),
      ),
    ),
  );

  const tbodyEl = page.querySelector("#network-rows");
  const conns = store.get().connections || [];
  for (const c of conns.slice(0, 250)) {
    tbodyEl.append(
      tr({},
        td({}, c.process || "-"),
        td({ class: "num" }, String(c.pid)),
        td({}, c.proto),
        td({ class: "mono" }, c.local),
        td({ class: "mono" }, c.remote),
        td({}, badge({ variant: c.state === "ESTABLISHED" ? "success" : c.state === "LISTENING" ? "info" : "secondary" }, c.state)),
      ),
    );
  }
}
