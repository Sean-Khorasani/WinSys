// pages/system.js - System page
import { h } from "../h.js";
import { card, cardHeader, cardTitle, cardContent } from "../ui/card.js";

export async function renderSystem(page, store) {
  page.innerHTML = "";
  page.append(
    h("div", { class: "page-heading" },
      h("h1", { class: "page-title" }, "System"),
      h("p", { class: "page-description" }, "Hardware, OS, and capabilities"),
    ),
    h("div", { class: "settings-grid", id: "system-grid" }),
  );

  const info = store.get().systemInfo;
  const grid = page.querySelector("#system-grid");
  if (info) {
    grid.append(
      card({},
        cardHeader({}, cardTitle({}, "Operating System")),
        cardContent({},
          h("p", {}, info.os.name),
          h("p", { class: "settings-description" }, "Build " + info.os.build),
        ),
      ),
      card({},
        cardHeader({}, cardTitle({}, "Processor")),
        cardContent({},
          h("p", {}, info.cpu.model),
          h("p", { class: "settings-description" }, info.cpu.cores + " cores, " + info.cpu.threads + " threads"),
        ),
      ),
    );
  }
}
