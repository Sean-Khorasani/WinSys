// pages/settings.js - Settings page.
//
// Preferences are written back to the server-side config (%LOCALAPPDATA%\WinTCP\
// WebUi\config.json) so they survive a restart and stay in step with the CLI.
// Every write is a POST, which the server gates behind the Origin + session
// token checks - the same guard the rest of the UI relies on.

import { h, clear } from "../h.js";
import { api } from "../api.js";
import { fmtBytes } from "../format.js";
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

const DEFAULT_PREFS = {
  theme: "system",
  accent: "neutral",
  density: "comfortable",
  refreshSeconds: 2,
  units: "iec",
  geoIpDbPath: "",
  desktopNotifications: false,
};

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

// Build the POST body: save preferences at the top level so that main.js's
// startup config loader (which reads top-level fields) sees them after restart.
// The preferences object is also kept for backward compatibility.
function buildConfigBody(config, prefs) {
  const base = config || {};
  return {
    version: 3,
    theme: prefs.theme,
    accent: prefs.accent,
    density: prefs.density,
    refreshSeconds: prefs.refreshSeconds,
    units: prefs.units,
    geoIpDbPath: prefs.geoIpDbPath,
    desktopNotifications: prefs.desktopNotifications,
    preferences: { ...prefs },
    rules: base.rules || [],
    scripts: base.scripts || [],
    presets: base.presets || [],
    bookmarks: base.bookmarks || [],
    scriptRuns: base.scriptRuns || [],
    lastScriptRun: base.lastScriptRun || null,
    view: base.view || {
      protocol: "all", state: "all", groupByProcess: false, frozen: false,
      columns: ["process", "pid", "proto", "local", "remote", "state", "traffic"],
    },
  };
}

export async function renderSettings(page, store) {
  page._settingsState = { prefs: { ...DEFAULT_PREFS }, config: null };
  clear(page);
  page.append(
    h("div", { class: "page-heading" },
      h("div", {},
        h("h1", { class: "page-title" }, "Settings"),
        h("p", { class: "page-description" }, "Appearance, polling, and the audit trail"),
      ),
      h("div", { class: "settings-actions" },
        h("button", {
          id: "settings-save",
          class: "btn btn-sm btn-primary",
          type: "button",
          onclick: () => saveSettings(page),
        }, "Save"),
        h("button", {
          id: "settings-restore",
          class: "btn btn-sm btn-ghost",
          type: "button",
          onclick: () => restoreDefaults(page),
        }, "Restore defaults"),
      ),
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

  page._settingsState.config = config;
  const prefs = {
    theme: readPref(config, "theme", DEFAULT_PREFS.theme),
    accent: readPref(config, "accent", DEFAULT_PREFS.accent),
    density: readPref(config, "density", DEFAULT_PREFS.density),
    refreshSeconds: readPref(config, "refreshSeconds", DEFAULT_PREFS.refreshSeconds),
    units: readPref(config, "units", DEFAULT_PREFS.units),
    geoIpDbPath: readPref(config, "geoIpDbPath", DEFAULT_PREFS.geoIpDbPath),
    desktopNotifications: readPref(config, "desktopNotifications", DEFAULT_PREFS.desktopNotifications),
  };
  page._settingsState.prefs = prefs;
  const schemaVersion = config.version || 2;

  const status = h("p", { class: "settings-status muted", role: "status" }, "");

  // Debounced auto-save for live controls (selects, toggles).
  let pending = null;
  function scheduleSave(patch) {
    clearTimeout(pending);
    pending = setTimeout(() => {
      doSave(patch);
    }, 250);
  }

  async function doSave(patch) {
    const ov = page._settingsState;
    if (!ov) return;
    // Merge patch into prefs
    const merged = { ...ov.prefs, ...patch };
    ov.prefs = merged;
    status.textContent = "Saving...";
    status.className = "settings-status muted";
    try {
      await api.post("/api/config", buildConfigBody(ov.config, merged));
      ov.config = { ...ov.config, ...merged, preferences: { ...merged } };
      status.textContent = "Saved.";
      status.className = "settings-status muted";
      // Apply immediately for appearance settings
      applyPrefs(merged);
    } catch (err) {
      status.textContent = "Not saved: " + err.message;
      status.className = "settings-status text-danger";
    }
  }

  function applyPrefs(p) {
    if (p.theme !== undefined) {
      const resolved = p.theme === "system"
        ? (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")
        : p.theme;
      document.documentElement.setAttribute("data-theme", resolved);
    }
    if (p.accent !== undefined) document.documentElement.setAttribute("data-accent", p.accent);
    if (p.density !== undefined) document.body.classList.toggle("density-compact", p.density === "compact");
  }

  function applyAndSchedule(patch) {
    const ov = page._settingsState;
    ov.prefs = { ...ov.prefs, ...patch };
    applyPrefs(patch);
    scheduleSave(patch);
  }

  // Save all current prefs immediately (triggered by Save button).
  async function saveSettings(page) {
    const ov = page._settingsState;
    if (!ov) return;
    await doSave({});
  }

  // Restore defaults and persist (triggered by Restore defaults button).
  async function restoreDefaults(page) {
    const ov = page._settingsState;
    if (!ov) return;
    ov.prefs = { ...DEFAULT_PREFS };
    // Re-render the form with defaults
    await doSave({});
    // Trigger a re-render to reflect defaults in the form
    const evt = new Event("settings:restored", { bubbles: true });
    page.dispatchEvent(evt);
  }

  const appearance = card({},
    cardHeader({}, cardTitle({}, "Appearance")),
    cardContent({},
      row("Theme", "Match the system, or pin light or dark", select({
        "aria-label": "Theme",
        onchange: (e) => applyAndSchedule({ theme: e.target.value }),
      }, THEMES, prefs.theme)),
      row("Accent", "Highlight colour for charts and focus rings",
        select({
          "aria-label": "Accent",
          onchange: (e) => applyAndSchedule({ accent: e.target.value }),
        }, ACCENTS.map((a) => ({ value: a, label: a[0].toUpperCase() + a.slice(1) })), prefs.accent)),
      row("Density", "Row height and padding across tables",
        select({
          "aria-label": "Density",
          onchange: (e) => applyAndSchedule({ density: e.target.value }),
        }, DENSITIES, prefs.density)),
      row("Units", "Byte prefixes used by every size readout",
        select({
          "aria-label": "Units",
          onchange: (e) => applyAndSchedule({ units: e.target.value }),
        }, UNITS, prefs.units)),
    ),
  );

  const polling = card({},
    cardHeader({}, cardTitle({}, "Polling")),
    cardContent({},
      row("Refresh interval", "How often the browser asks the server for a new sample",
        select({
          "aria-label": "Refresh interval",
          onchange: (e) => applyAndSchedule({ refreshSeconds: Number(e.target.value) }),
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
          onchange: (e) => applyAndSchedule({ desktopNotifications: e.target.checked }),
        })),
      h("p", { class: "settings-description" },
        "Requires notification permission. The browser will prompt the first time this is enabled."),
    ),
  );

  const geoIp = card({},
    cardHeader({}, cardTitle({}, "GeoIP database")),
    cardContent({},
      row("Database path", "Path to a local GeoLite2-Country.mmdb (or GeoLite2-ASN.mmdb) for country/ASN enrichment. Empty = disabled.",
        h("div", { class: "geoip-input-group" },
          h("input", {
            class: "input",
            type: "text",
            value: prefs.geoIpDbPath,
            placeholder: "C:\\path\\to\\GeoLite2-Country.mmdb",
            "aria-label": "GeoIP database path",
            oninput: (e) => {
              const ov = page._settingsState;
              if (ov) ov.prefs.geoIpDbPath = e.target.value;
            },
            onchange: (e) => applyAndSchedule({ geoIpDbPath: e.target.value }),
          }),
           h("input", {
             id: "geoip-file",
             class: "geoip-file-input",
             type: "file",
             accept: ".mmdb,application/octet-stream",
             class: "geoip-file-input",
             onchange: async (e) => {
               const file = e.target.files[0];
               if (!file) return;
               const input = page.querySelector('[aria-label="GeoIP database path"]');
               try {
                 status.textContent = `Uploading "${file.name}" (${fmtBytes(file.size)})...`;
                 status.className = "settings-status";
                 const result = await api.upload("/api/geoip/upload", file, file.name);
                 if (result.path) {
                   input.value = result.path;
                   applyAndSchedule({ geoIpDbPath: result.path });
                   status.textContent = `Uploaded "${file.name}" to ${result.path}`;
                 } else {
                   status.textContent = `Upload failed: ${result.error || "unknown error"}`;
                   status.className = "settings-status error";
                 }
               } catch (err) {
                 status.textContent = `Upload failed: ${err.message}`;
                 status.className = "settings-status error";
               }
             },
           }),
          h("button", {
            class: "btn btn-sm btn-ghost",
            type: "button",
            "aria-label": "Browse for GeoIP database",
            onclick: () => {
              const fileInput = page.querySelector("#geoip-file");
              if (fileInput) fileInput.click();
            },
          }, "Browse"),
        ),
      ),
       h("p", { class: "settings-description" },
         "WinTCP ships no database. Download GeoLite2 from MaxMind, then enter the " +
         "full path to the .mmdb file above, or use the Browse button to upload one. " +
         "The file is saved to %LOCALAPPDATA%\\WinTCP\\WebUi\\db\\ and its path is " +
         "written here automatically. The Map page and Flows tab pick up changes immediately."),
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

  // Auto-save after a short idle period so manual edits are not lost.
  page.addEventListener("settings:restored", () => {
    renderSettings(page, store).catch((err) => {
      clear(grid);
      grid.append(h("p", { class: "text-danger" }, "Could not reload settings: " + err.message));
    });
  });

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
