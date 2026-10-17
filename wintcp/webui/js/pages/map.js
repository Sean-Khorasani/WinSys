// pages/map.js - Map page
import { h } from "../h.js";

export async function renderMap(page, store) {
  page.innerHTML = "";
  page.append(
    h("div", { class: "page-heading" },
      h("h1", { class: "page-title" }, "Map"),
      h("p", { class: "page-description" }, "Geographic distribution of remote peers"),
    ),
    h("div", { class: "map-layout" },
      h("div", { class: "map-container", id: "map-container" }),
      h("div", { class: "map-sidebar" },
        h("div", { class: "card" },
          h("div", { class: "card-header" },
            h("h3", { class: "card-title" }, "Top Countries"),
          ),
          h("div", { class: "card-content", id: "map-countries" }),
        ),
      ),
    ),
  );
}
