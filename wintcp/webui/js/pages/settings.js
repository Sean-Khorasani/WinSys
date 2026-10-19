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
    ...base,
    version: 3,
    theme: prefs.theme,
    accent: prefs.accent,
    density: prefs.density,
    refreshSeconds: prefs.refreshSeconds,
    units: prefs.units,
    geoIpDbPath: prefs.geoIpDbPath,
    desktopNotifications: prefs.desktopNotifications,
    preferences: { ...base.preferences, ...prefs },
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
  const settingsState = page._settingsState;
  let disposed = false;
  const requests = new AbortController();
  let pending = null;
  let dirty = {};
  let saving = {};
  let configSyncGeneration = 0;
  let unsubscribeConfigChanges = () => {};
  let notificationPermissionStatus = null;
  let onPermissionChange = null;
  let onRestored = null;
  page._settingsDestroy = () => {
    disposed = true;
    configSyncGeneration++;
    unsubscribeConfigChanges();
    document.removeEventListener("visibilitychange", reconcileNotificationPermission);
    if (notificationPermissionStatus && onPermissionChange) {
      notificationPermissionStatus.onchange = null;
    }
    requests.abort();
    if (pending !== null) clearTimeout(pending);
    if (Object.keys(dirty).length) doSave({});
    if (onRestored) page.removeEventListener("settings:restored", onRestored);
  };
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
    config = await api.get("/api/config", { signal: requests.signal });
  } catch (err) {
    if (disposed) return;
    clear(grid);
    grid.append(h("p", { class: "text-danger" }, "Could not load settings: " + err.message));
    return;
  }
  if (disposed) return;

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
  if (prefs.desktopNotifications &&
      (!("Notification" in window) || Notification.permission !== "granted")) {
    prefs.desktopNotifications = false;
    status.textContent = "Desktop notifications need browser permission before they can be enabled.";
  }

  // Debounced auto-save for live controls (selects, toggles).
  function scheduleSave(patch) {
    Object.assign(dirty, patch);
    clearTimeout(pending);
    pending = setTimeout(() => {
      pending = null;
      doSave({});
    }, 250);
  }

  async function doSave(patch) {
    const ov = settingsState;
    if (!ov) return;
    if (pending !== null) clearTimeout(pending);
    pending = null;
    // Merge patch into prefs
    const merged = { ...ov.prefs, ...patch };
    ov.prefs = merged;
    Object.assign(dirty, patch);
    const savePatch = { ...dirty };
    dirty = {};
    Object.assign(saving, savePatch);
    status.textContent = "Saving...";
    status.className = "settings-status muted";
    try {
      ov.config = await api.updateConfig((current) => {
        const latest = Object.fromEntries(Object.keys(DEFAULT_PREFS).map((key) =>
          [key, readPref(current, key, DEFAULT_PREFS[key])]));
        return buildConfigBody(current, { ...latest, ...savePatch });
      });
      for (const [key, value] of Object.entries(savePatch)) {
        if (Object.is(saving[key], value)) delete saving[key];
      }
      const acknowledged = Object.fromEntries(Object.keys(DEFAULT_PREFS).map((key) =>
        [key, readPref(ov.config, key, DEFAULT_PREFS[key])]));
      const synced = {};
      for (const [key, value] of Object.entries(acknowledged)) {
        if (!Object.hasOwn(dirty, key) && !Object.hasOwn(saving, key) &&
            !Object.is(ov.prefs[key], value)) {
          synced[key] = value;
        }
      }
      ov.prefs = { ...ov.prefs, ...synced };
      if (Object.keys(synced).length) applyPrefs(synced);
      if (disposed) return;
      status.textContent = "Saved.";
      status.className = "settings-status muted";
      // Apply immediately for appearance settings
    } catch (err) {
      for (const [key, value] of Object.entries(savePatch)) {
        if (Object.is(saving[key], value)) delete saving[key];
      }
      dirty = { ...savePatch, ...dirty };
      if (disposed) return;
      status.textContent = "Not saved: " + err.message;
      status.className = "settings-status text-danger";
    }
  }

  function applyPrefs(p) {
    store.set(p);
    document.dispatchEvent(new CustomEvent("wintcp:preferences", { detail: p }));
  }

  function applyAndSchedule(patch) {
    if (disposed) return;
    const ov = page._settingsState;
    ov.prefs = { ...ov.prefs, ...patch };
    applyPrefs(patch);
    scheduleSave(patch);
  }

  function reconcileNotificationPermission() {
    if (disposed || !("Notification" in window) || Notification.permission === "granted") return;
    const toggle = page.querySelector('[aria-label="Desktop notifications"]');
    if (!toggle?.checked) return;
    toggle.checked = false;
    status.textContent = "Desktop notifications were turned off because browser permission is no longer granted.";
    status.className = "settings-status text-danger";
    applyAndSchedule({ desktopNotifications: false });
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
    applyPrefs(DEFAULT_PREFS);
    await doSave(DEFAULT_PREFS);
    if (disposed) return;
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
          onchange: async (event) => {
            const enabled = event.target.checked;
            if (enabled) {
              let permission;
              try {
                permission = "Notification" in window
                  ? await Notification.requestPermission() : "unsupported";
              } catch (error) {
                if (disposed) return;
                event.target.checked = false;
                status.textContent = "Notification permission could not be requested: " + error.message;
                return;
              }
              if (disposed) return;
              if (permission !== "granted") {
                event.target.checked = false;
                status.textContent = permission === "unsupported"
                  ? "Desktop notifications are unavailable in this browser."
                  : "Notification permission was not granted. Enable it in the browser's site settings.";
                return;
              }
            }
            applyAndSchedule({ desktopNotifications: enabled });
          },
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
             onchange: async (e) => {
               const file = e.target.files[0];
               if (!file) return;
               const input = page.querySelector('[aria-label="GeoIP database path"]');
               try {
                 status.textContent = `Uploading "${file.name}" (${fmtBytes(file.size)})...`;
                 status.className = "settings-status";
                 const result = await api.upload("/api/geoip/upload", file, file.name,
                   { signal: requests.signal });
                 if (disposed) return;
                 if (result.path) {
                   input.value = result.path;
                   applyAndSchedule({ geoIpDbPath: result.path });
                   status.textContent = `Uploaded "${file.name}" to ${result.path}`;
                 } else {
                   status.textContent = `Upload failed: ${result.error || "unknown error"}`;
                   status.className = "settings-status error";
                 }
               } catch (err) {
                 if (disposed) return;
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

  onPermissionChange = reconcileNotificationPermission;
  document.addEventListener("visibilitychange", reconcileNotificationPermission);
  if (navigator.permissions?.query) {
    navigator.permissions.query({ name: "notifications" }).then((permission) => {
      if (disposed) return;
      notificationPermissionStatus = permission;
      permission.onchange = onPermissionChange;
      reconcileNotificationPermission();
    }).catch(() => {});
  }

  const controlLabels = {
    theme: "Theme",
    accent: "Accent",
    density: "Density",
    refreshSeconds: "Refresh interval",
    units: "Units",
    geoIpDbPath: "Database path",
    desktopNotifications: "Desktop notifications",
  };
  unsubscribeConfigChanges = api.subscribeConfigChanges(async () => {
    const generation = ++configSyncGeneration;
    try {
      const fresh = await api.get("/api/config", { signal: requests.signal });
      if (disposed || generation !== configSyncGeneration) return;
      settingsState.config = fresh;
      const remotePrefs = Object.fromEntries(Object.keys(DEFAULT_PREFS).map((key) =>
        [key, readPref(fresh, key, DEFAULT_PREFS[key])]));
      const patch = {};
      for (const [key, value] of Object.entries(remotePrefs)) {
        if (!Object.hasOwn(dirty, key) && !Object.hasOwn(saving, key) &&
            !Object.is(settingsState.prefs[key], value)) {
          patch[key] = value;
        }
      }
      if (Object.keys(patch).length === 0) return;
      settingsState.prefs = { ...settingsState.prefs, ...patch };
      for (const [key, value] of Object.entries(patch)) {
        const control = page.querySelector(`[aria-label="${controlLabels[key]}"]`);
        if (!control) continue;
        if (control.type === "checkbox") control.checked = Boolean(value);
        else control.value = String(value);
      }
      applyPrefs(patch);
      if (Object.keys(dirty).length === 0 && Object.keys(saving).length === 0) {
        status.textContent = "Updated from another tab.";
        status.className = "settings-status muted";
      }
    } catch (error) {
      if (!disposed && error.name !== "AbortError") {
        status.textContent = "Could not sync settings from another tab: " + error.message;
        status.className = "settings-status text-danger";
      }
    }
  });

  // Auto-save after a short idle period so manual edits are not lost.
  onRestored = () => {
    page._settingsDestroy?.();
    renderSettings(page, store).catch((err) => {
      clear(grid);
      grid.append(h("p", { class: "text-danger" }, "Could not reload settings: " + err.message));
    });
  };
  page.addEventListener("settings:restored", onRestored);

  try {
    const audit = await api.get("/api/audit", { signal: requests.signal });
    if (disposed) return;
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
    if (disposed) return;
    grid.append(card({},
      cardHeader({}, cardTitle({}, "Audit trail")),
      cardContent({}, emptyState({}, "Audit trail unavailable",
        "The server did not return audit entries.")),
    ));
  }
}
