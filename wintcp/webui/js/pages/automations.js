// pages/automations.js - Automations page
import { h } from "../h.js";

export async function renderAutomations(page, store) {
  page.innerHTML = "";
  page.append(
    h("div", { class: "page-heading" },
      h("h1", { class: "page-title" }, "Automations"),
      h("p", { class: "page-description" }, "Scripts, monitors, and events"),
    ),
    h("div", { class: "tabs", role: "tablist" },
      h("button", { class: "tab is-active", role: "tab" }, "Scripts"),
      h("button", { class: "tab", role: "tab" }, "Templates"),
      h("button", { class: "tab", role: "tab" }, "Events"),
    ),
    h("div", { class: "card", style: "margin-top: 1rem" },
      h("div", { class: "card-content" },
        h("p", { class: "empty-state" }, "Automation workbench - see legacy views"),
      ),
    ),
  );
}
