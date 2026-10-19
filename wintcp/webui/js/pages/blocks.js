// pages/blocks.js - Blocked peers.
//
// The block list lives in the server-side config (the same rules the CLI's
// `wintcp block` writes), so this page reads /api/config rather than keeping a
// second copy. Removal goes through the existing permit flow, exactly as the
// pre-upgrade dashboard does it: nothing is mutated from a single click.

import { h, clear } from "../h.js";
import { api } from "../api.js";
import { emptyState } from "../ui/card.js";

function ruleRows(config) {
  const rules = Array.isArray(config.rules) ? config.rules : [];
  return rules.map((rule, index) => ({
    index,
    address: rule.address || rule.remote || "(any)",
    proto: (rule.proto || "tcp").toUpperCase(),
    ports: rule.remotePorts || rule.ports || "",
    label: rule.label || "",
  }));
}

export async function renderBlocks(page, store) {
  clear(page);
  page.append(
    h("div", { class: "page-heading" },
      h("h1", { class: "page-title" }, "Blocked Peers"),
      h("p", { class: "page-description" },
        "Firewall rules applied by WinTCP. Removing one goes through the permit flow."),
    ),
    h("div", { class: "card" },
      h("div", { class: "card-content" },
        h("div", { id: "blocks-body" }, h("p", { class: "muted" }, "Loading rules...")),
      ),
    ),
  );

  const body = page.querySelector("#blocks-body");
  let config;
  try {
    config = await api.get("/api/config");
  } catch (err) {
    clear(body);
    body.append(h("p", { class: "text-danger" }, "Could not load rules: " + err.message));
    return;
  }

  const rows = ruleRows(config);
  clear(body);
  if (rows.length === 0) {
    body.append(emptyState({}, "No peers are blocked.", "Rules created by wintcp block, or from Automations, appear here."));
    return;
  }

  const list = h("ul", { class: "rule-list" });
  for (const rule of rows) {
    list.append(
      h("li", { class: "rule-row" },
        h("span", { class: "rule-proto badge" }, rule.proto),
        h("span", { class: "rule-address num" }, rule.address),
        rule.ports ? h("span", { class: "rule-ports num" }, rule.ports) : null,
        h("span", { class: "rule-label" }, rule.label || "(no label)"),
        h("a", {
          class: "btn btn-ghost btn-sm",
          href: "#/automations",
          title: "Manage and remove rules on the Automations page",
        }, "Manage"),
      ),
    );
  }
  body.append(list);
  body.append(h("p", { class: "muted text-sm" },
    `${rows.length} rule${rows.length === 1 ? "" : "s"}. Removing a rule needs an explicit permit, so editing happens on the Automations page.`));
}