// pages/settings.js - Settings page.
//
// Preferences are written back to the server-side config (%LOCALAPPDATA%\WinTCP\
// WebUi\config.json) so they survive a restart and stay in step with the CLI.
// Every write is a POST, which the server gates behind the Origin + session
// token checks - the same guard the rest of the UI relies on.

import { h, clear } from "../h.js";
import { api } from "../api.js";
import { card, cardHeader, cardTitle, cardContent, emptyState } from "../ui/card.js";

const THEMES = [
  { value: "system", label: "Match system" },
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
];

const ACCENTS = ["neutral", "blue", "green", "orange", "rose", "teal"];

const DENSITIES = [
  { value: "comfortable", label: "Comfortable" },
  { value: "compact", label: "Compact" },
];

const REFRESH_SECONDS = [1, 2, 5, 10, 30, 60];

const UNITS = [
  { value: "iec", label: "IEC (KiB, MiB)" },
  { value: "si", label: "SI (kB, MB)" },
];

// Read a preference, tolerating both the v2 shape (bare) and the v3 shape
// (nested under preferences), so an older config keeps working unchanged.
function readPref(config, key, fallback) {
  if (config && config.preferences && config.preferences[key] !== undefined) {
    return config.preferences[key];
  }
  if (config && config[key] !== undefined) return config[key];
  return fallback;
}

function row(label, description, control) {
  return h("div", { class: "settings-row" },
    h("div", {},
      h("div", { class: "settings-label" }, label),
      description ? h("div", { class: "settings-description" }, description) : null,
    ),
    control,
  );
}

function select(props, options, current) {
  return h("select", { class: "select", ...props },
    options.map((option) => h("option", {
      value: String(option.value),
      ...(String(option.value) === String(current) ? { selected: "" } : {}),
    }, option.label)),
  );
}

export async function renderSettings(page, store) {
  clear(page);
  page.append(
    h("div", { class: "page-heading" },
      h("h1", { class: "page-title" }, "Settings"),
      h("p", { class: "page-description" }, "Appearance, polling, and the audit trail"),
    ),
    h("div", { class: "settings-grid", id: "settings-grid" }),
  );
  const grid = page.querySelector("#settings-grid");

  let config;
  try {
    config = await api.get("/api/config");
  } catch (err) {
    clear(grid);
    grid.append(h("p", { class: "text-danger" }, "Could not load settings: " + err.message));
    return;
  }

  const prefs = {
    theme: readPref(config, "theme", "system"),
    accent: readPref(config, "accent", "neutral"),
    density: readPref(config, "density", "comfortable"),
    refreshSeconds: readPref(config, "refreshSeconds", 2),
    units: readPref(config, "units", "iec"),
    geoIpDbPath: readPref(config, "geoIpDbPath", ""),
    desktopNotifications: readPref(config, "desktopNotifications", false),
  };
  const schemaVersion = config.version || 2;

  const status = h("p", { class: "settings-status muted", role: "status" }, "");

  // Writes are debounced so dragging a control does not fire a POST per change.
  let pending = null;
  async function persist(patch) {
    clearTimeout(pending);
    pending = setTimeout(async () => {
      status.textContent = "Saving...";
       try {
         await api.post("/api/config", {
           ...config,
           version: 3,
           preferences: { ...prefs, ...patch },
         });
         status.textContent = "Saved.";
      } catch (err) {
        status.textContent = "Not saved: " + err.message;
        status.className = "settings-status text-danger";
      }
    }, 250);
  }

  function applyAndSave(patch) {
    for (const [key, value] of Object.entries(patch)) prefs[key] = value;
    if (patch.theme !== undefined) document.documentElement.setAttribute("data-theme", patch.theme);
    if (patch.accent !== undefined) document.documentElement.setAttribute("data-accent", patch.accent);
    if (patch.density !== undefined) document.body.classList.toggle("density-compact", patch.density === "compact");
    persist(patch);
  }

  const appearance = card({},
    cardHeader({}, cardTitle({}, "Appearance")),
    cardContent({},
      row("Theme", "Match the system, or pin light or dark", select({
        "aria-label": "Theme",
        onchange: (e) => applyAndSave({ theme: e.target.value }),
      }, THEMES, prefs.theme)),
      row("Accent", "Highlight colour for charts and focus rings",
        select({
          "aria-label": "Accent",
          onchange: (e) => applyAndSave({ accent: e.target.value }),
        }, ACCENTS.map((a) => ({ value: a, label: a[0].toUpperCase() + a.slice(1) })), prefs.accent)),
      row("Density", "Row height and padding across tables",
        select({
          "aria-label": "Density",
          onchange: (e) => applyAndSave({ density: e.target.value }),
        }, DENSITIES, prefs.density)),
      row("Units", "Byte prefixes used by every size readout",
        select({
          "aria-label": "Units",
          onchange: (e) => applyAndSave({ units: e.target.value }),
        }, UNITS, prefs.units)),
    ),
  );

  const polling = card({},
    cardHeader({}, cardTitle({}, "Polling")),
    cardContent({},
      row("Refresh interval", "How often the browser asks the server for a new sample",
        select({
          "aria-label": "Refresh interval",
          onchange: (e) => applyAndSave({ refreshSeconds: Number(e.target.value) }),
        }, REFRESH_SECONDS.map((s) => ({ value: s, label: `${s}s` })), prefs.refreshSeconds)),
      h("p", { class: "settings-description" },
        "The server samples on its own timer at 1 Hz and stores 15 minutes of history; " +
        "this only controls how often the browser redraws."),
    ),
  );

  const notifications = card({},
    cardHeader({}, cardTitle({}, "Notifications")),
    cardContent({},
      row("Desktop notifications", "Show browser notifications for new connections or alerts",
        h("input", {
          class: "toggle",
          type: "checkbox",
          "aria-label": "Desktop notifications",
          checked: prefs.desktopNotifications ? "" : null,
          onchange: (e) => applyAndSave({ desktopNotifications: e.target.checked }),
        })),
      h("p", { class: "settings-description" },
        "Requires notification permission. The browser will prompt the first time this is enabled."),
    ),
  );

  const geoIp = card({},
    cardHeader({}, cardTitle({}, "GeoIP database")),
    cardContent({},
      row("Database path", "Path to a local GeoLite2-Country.mmdb (or GeoLite2-ASN.mmdb) for country/ASN enrichment. Empty = disabled.",
        h("input", {
          class: "input",
          type: "text",
          value: prefs.geoIpDbPath,
          placeholder: "C:\\\\path\\\\to\\\\GeoLite2-Country.mmdb",
          "aria-label": "GeoIP database path",
          onchange: (e) => applyAndSave({ geoIpDbPath: e.target.value }),
        }),
      ),
      h("p", { class: "settings-description" },
        "WinTCP ships no database. Download GeoLite2 from MaxMind and enter the .mmdb path here. " +
        "The Map page and Flows tab will pick it up immediately."),
    ),
  );

  const configCard = card({},
    cardHeader({}, cardTitle({}, "Configuration")),
    cardContent({},
      row("Schema version", "Config file schema in use",
        h("span", { class: "settings-value num" }, String(schemaVersion))),
      row("Config path", "Stored outside the executable directory",
        h("code", { class: "settings-path" }, "%LOCALAPPDATA%\\WinTCP\\WebUi\\config.json")),
      status,
    ),
  );

  grid.append(appearance, polling, notifications, geoIp, configCard);

  try {
    const audit = await api.get("/api/audit");
    const entries = Array.isArray(audit) ? audit : Array.isArray(audit.entries) ? audit.entries : [];
    grid.append(card({},
      cardHeader({}, cardTitle({}, "Audit trail")),
      cardContent({},
        entries.length === 0
          ? emptyState({}, "No audit events yet",
              "Every mutation is written here before it runs.")
          : h("ul", { class: "rule-list" },
              entries.slice(-20).reverse().map((entry) => h("li", { class: "rule-row" },
                h("span", { class: "rule-label num" }, entry.time || entry.at || entry.timestamp || ""),
                h("span", { class: "rule-address" },
                  (entry.event?.type || entry.action || entry.command || entry.type || "").slice(0, 60)),
              ))),
      ),
    ));
  } catch {
    grid.append(card({},
      cardHeader({}, cardTitle({}, "Audit trail")),
      cardContent({}, emptyState({}, "Audit trail unavailable",
        "The server did not return audit entries.")),
    ));
  }
}