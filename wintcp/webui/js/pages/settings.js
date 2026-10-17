// pages/settings.js - Settings page
import { h } from "../h.js";
import { card, cardHeader, cardTitle, cardContent } from "../ui/card.js";

export async function renderSettings(page, store) {
  page.innerHTML = "";
  page.append(
    h("div", { class: "page-heading" },
      h("h1", { class: "page-title" }, "Settings"),
      h("p", { class: "page-description" }, "Preferences and audit trail"),
    ),
    h("div", { class: "settings-grid" },
      card({},
        cardHeader({}, cardTitle({}, "Preferences")),
        cardContent({},
          h("div", { class: "settings-row" },
            h("div", {},
              h("div", { class: "settings-label" }, "Refresh interval"),
              h("div", { class: "settings-description" }, "How often to poll for updates"),
            ),
            h("select", { class: "select", style: "max-width: 10rem" },
              h("option", { value: "1" }, "1s"),
              h("option", { value: "2", selected: "" }, "2s"),
              h("option", { value: "5" }, "5s"),
              h("option", { value: "10" }, "10s"),
              h("option", { value: "30" }, "30s"),
            ),
          ),
        ),
      ),
    ),
  );
}
