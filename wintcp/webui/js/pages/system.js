// pages/system.js - System page
//
// Every field is treated as optional. The endpoint already reports an absent
// value as null plus a reason; this page must render that as "—" rather than
// throwing, because a throw here blanks the page the operator is trying to read
// when something like ProductName is unavailable.

import { h, clear } from "../h.js";
import { card, cardHeader, cardTitle, cardContent } from "../ui/card.js";
import { emptyState } from "../ui/card.js";
import { fmtBytes } from "../format.js";

const UNAVAILABLE = "\u2014";   // em dash, the codebase's "not available" mark

// value may be null/undefined; reason is the endpoint's explanation.
function orUnavailable(value, reason) {
  if (value === null || value === undefined || value === "") return UNAVAILABLE;
  return String(value);
}

function definition(term, value, hint) {
  return h("div", { class: "stat-row" },
    h("dt", { class: "stat-term" }, term),
    h("dd", { class: "stat-value num" }, orUnavailable(value), hint ? h("span", { class: "stat-hint" }, hint) : null),
  );
}

export async function renderSystem(page, store) {
  clear(page);
  page.append(
    h("div", { class: "page-heading" },
      h("h1", { class: "page-title" }, "System"),
      h("p", { class: "page-description" }, "Hardware, OS, and capabilities"),
    ),
    h("div", { class: "settings-grid", id: "system-grid" }),
  );

  const grid = page.querySelector("#system-grid");
  const info = store.get().systemInfo;
  if (!info) {
    grid.append(card({}, cardContent({},
      emptyState({}, "System information is not available yet",
        "The first poll has not completed. It refreshes automatically."))));
    return;
  }

  const os = info.os || {};
  const cpu = info.cpu || {};
  const memory = info.memory;

  grid.append(
    card({},
      cardHeader({}, cardTitle({}, "Operating System")),
      cardContent({},
        h("dl", { class: "stat-list" },
          definition("Name", os.name, os.nameReason || undefined),
          definition("Version", os.version),
          definition("Build", os.build),
          definition("Architecture", os.architecture),
          definition("Host name", info.hostname),
          definition("Uptime", info.uptime),
        ),
      ),
    ),
    card({},
      cardHeader({}, cardTitle({}, "Processor")),
      cardContent({},
        h("dl", { class: "stat-list" },
          definition("Model", cpu.model || cpu.brand, cpu.brandReason || undefined),
          definition("Logical processors", cpu.threads),
          definition("Processor groups", cpu.processorGroups),
          definition("Architecture", cpu.architecture),
        ),
      ),
    ),
    card({},
      cardHeader({}, cardTitle({}, "Memory")),
      cardContent({},
        memory
          ? h("dl", { class: "stat-list" },
              definition("Installed", fmtBytes(memory.installed)),
              definition("Used", fmtBytes(memory.used)),
              definition("Available", fmtBytes(memory.available)),
              definition("In use", `${memory.pct}%`),
            )
          : emptyState({}, "Memory information is unavailable",
              info.memoryReason || "The OS did not report memory totals."),
      ),
    ),
  );

  const caps = store.get().capabilities;
  if (caps) {
    const rows = [
      ["Performance counters (PDH)", caps.pdh, caps.pdhReason],
      ["Per-core CPU", caps.perCore, caps.perCoreReason],
      ["GeoIP database", caps.geoIp && caps.geoIp.configured,
        caps.geoIp && !caps.geoIp.configured ? "No GeoIP database is installed" : undefined],
      ["GPU engine counters", caps.gpu, "Not implemented"],
    ];
    grid.append(card({},
      cardHeader({}, cardTitle({}, "Capabilities")),
      cardContent({},
        h("dl", { class: "stat-list" },
          rows.map(([label, ok, reason]) => h("div", { class: "stat-row" },
            h("dt", { class: "stat-term" }, label),
            h("dd", { class: "stat-value" },
              h("span", { class: ok ? "badge badge-ok" : "badge badge-muted" },
                ok ? "Available" : "Unavailable"),
              reason ? h("span", { class: "stat-hint" }, reason) : null),
          ))),
      ),
    ));
  }
}