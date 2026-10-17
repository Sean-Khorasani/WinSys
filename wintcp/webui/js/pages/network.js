// pages/network.js - Network page
import { h } from "../h.js";
import { badge } from "../ui/badge.js";
import { createVirtualTable } from "../ui/virtualtable.js";

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
    h("div", { id: "network-table-container", style: "margin-top: 1rem;" }),
  );

  const container = page.querySelector("#network-table-container");
  const conns = store.get().connections || [];

  const vt = createVirtualTable(container, {
    columns: [
      { key: "process", label: "Process", width: 2 },
      { key: "pid", label: "PID", width: 0.8 },
      { key: "proto", label: "Proto", width: 0.8 },
      { key: "local", label: "Local", width: 1.5 },
      { key: "remote", label: "Remote", width: 1.5 },
      { key: "state", label: "State", width: 1 },
    ],
    rowHeight: 36,
    height: 500,
  });

  vt.updateRows(conns);
}
