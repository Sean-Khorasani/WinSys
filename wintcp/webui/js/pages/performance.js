// pages/performance.js - Performance page
import { h } from "../h.js";

export async function renderPerformance(page, store) {
  page.innerHTML = "";
  page.append(
    h("div", { class: "page-heading" },
      h("h1", { class: "page-title" }, "Performance"),
      h("p", { class: "page-description" }, "CPU, memory, disk, and network utilization"),
    ),
    h("div", { class: "perf-layout" },
      h("div", { class: "perf-rail", id: "perf-rail" }),
      h("div", { class: "perf-main" },
        h("div", { class: "card" },
          h("div", { class: "card-content" },
            h("div", { class: "chart-container", id: "perf-chart" }),
          ),
        ),
      ),
    ),
  );
}
