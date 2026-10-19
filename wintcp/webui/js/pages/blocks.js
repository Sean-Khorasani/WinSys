import { h } from "../h.js";
import { createFirewallInventoryView } from "../firewallinventory.js";

export async function renderBlocks(page) {
  const inventory = createFirewallInventoryView();
  page.append(
    h("div", { class: "page-heading" },
      h("h1", { class: "page-title" }, "Firewall Rules"),
      h("p", { class: "page-description" },
        "Windows Firewall rules returned by the local policy API, supplemented by readable WinTCP-owned rules. This inventory is not an effective-policy or reachability verdict."),
    ),
    inventory.element,
  );
  page._blocksDestroy = inventory.destroy;
  await inventory.ready;
}
