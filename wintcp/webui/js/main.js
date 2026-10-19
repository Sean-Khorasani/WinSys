// main.js - Entry point for the WinTCP Web UI

import { startRouter, route, navigate, setNotFound } from "./router.js";
import { api } from "./api.js";
import { createStore } from "./store.js";
import { createPoller } from "./poller.js";
import { h, clear } from "./h.js";
import { icon } from "./icons.js";
import { fmtNum, fmtBytes, fmtPct, fmtDuration } from "./format.js";
import { renderOverview, updateOverview } from "./pages/overview.js";
import { renderPerformance, updatePerformance } from "./pages/performance.js";
import { renderProcesses, updateProcesses } from "./pages/processes.js";
import { renderNetwork, updateNetwork } from "./pages/network.js";
import { renderMap, updateMap } from "./pages/map.js";
import { renderAutomations } from "./pages/automations.js";
import { renderBlocks } from "./pages/blocks.js";
import { renderSystem } from "./pages/system.js";
import { renderSettings } from "./pages/settings.js";
import { createCommandPalette } from "./ui/commandpalette.js";
import { installCspReporter } from "./csp.js";
import { repaintCharts } from "./charts/timeseries.js";

// Global store
export const store = createStore({
  connections: [],
  metrics: null,
  capabilities: null,
  systemInfo: null,
  processes: [],
  networkSummary: null,
  geoSummary: null,
  status: "connecting",
  lastUpdate: null,
  theme: "system",
  accent: "neutral",
  density: "comfortable",
  units: "iec",
  sidebarOpen: true,
  sidebarCollapsed: false,
  refreshInterval: 2000,
  timeRange: "live",
  paused: false,
  processView: "table",
  processTreemapMetric: "memWs",
  processSortKey: null,
  processSortDir: null,
  processFilter: "",
  processTableScrollTop: 0,
  networkFilter: "",
  networkTableScrollTop: 0,
  networkListeningScrollTop: 0,
});

// Apply theme. Charts resolve design tokens into canvas colours at build time,
// so a theme switch has to tell them to re-resolve - otherwise the series keep
// the colours of the previous theme.
function applyTheme(theme) {
  const resolved = theme === "system"
    ? (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")
    : theme;
  document.documentElement.setAttribute("data-theme", resolved);
  repaintCharts();
}

// Apply density
function applyDensity(density) {
  document.body.classList.toggle("density-compact", density === "compact");
}

// Apply accent colour
function applyAccent(accent) {
  document.documentElement.setAttribute("data-accent", accent || "neutral");
}

// The sidebar is built once and never rebuilt, so its active state has to be
// re-synced on navigation. Baking `is-active` into the markup at build time is
// what left "Overview" highlighted while the Performance page was showing: the
// class was computed from the hash at boot and then never revisited.
let sidebarNav = null;

function syncSidebarActive() {
  if (!sidebarNav) return;
  const path = (window.location.hash || "#/").slice(1) || "/";
  for (const link of sidebarNav.querySelectorAll("a.sidebar-item")) {
    const target = link.getAttribute("href").slice(1) || "/";
    const active = target === path;
    link.classList.toggle("is-active", active);
    // aria-current is what a screen reader announces on the active nav item.
    // The visual class alone leaves the sidebar looking right and reading wrong.
    if (active) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
}

// Render sidebar
function renderSidebar(container) {
  const groups = [
    {
      label: "Monitor",
      items: [
        { path: "/", icon: "home", label: "Overview" },
        { path: "/performance", icon: "activity", label: "Performance" },
        { path: "/processes", icon: "layers", label: "Processes" },
        { path: "/network", icon: "network", label: "Network" },
        { path: "/map", icon: "globe", label: "Map" },
      ],
    },
    {
      label: "Respond",
      items: [
        { path: "/automations", icon: "zap", label: "Automations" },
        { path: "/blocks", icon: "shield", label: "Blocked Peers" },
      ],
    },
    {
      label: "System",
      items: [
        { path: "/system", icon: "server", label: "System" },
        { path: "/settings", icon: "settings", label: "Settings" },
      ],
    },
  ];

  const nav = h("nav", { "aria-label": "Main navigation" });
  for (const group of groups) {
    const groupEl = h("div", { class: "sidebar-group" },
      h("div", { class: "sidebar-group-label" }, group.label),
    );
    for (const item of group.items) {
      const isActive = window.location.hash === `#${item.path}` ||
        (item.path === "/" && (window.location.hash === "" || window.location.hash === "#"));
      groupEl.append(
        h("a", {
          class: `sidebar-item${isActive ? " is-active" : ""}`,
          href: `#${item.path}`,
          onclick: (e) => { e.preventDefault(); navigate(item.path); },
        }, icon(item.icon, 16), h("span", { class: "sidebar-label" }, item.label)),
      );
    }
    nav.append(groupEl);
  }

  sidebarNav = nav;

  container.append(
    h("aside", { class: "sidebar", id: "sidebar" },
      h("div", { class: "sidebar-header" },
        h("a", { class: "brand", href: "#/" },
          h("span", { class: "brand-mark" }, h("span"), h("span"), h("span")),
          h("span", { class: "sidebar-label" }, "WinTCP"),
        ),
        h("button", {
          class: "btn btn-ghost btn-sm",
          onclick: () => store.set({ sidebarCollapsed: !store.get().sidebarCollapsed }),
          "aria-label": "Toggle sidebar",
        }, icon("menu", 16)),
      ),
      nav,
      h("div", { class: "sidebar-footer" },
        h("div", { class: "status-pill online" },
          h("span", { class: "dot" }),
          h("span", { class: "sidebar-label" }, "Loopback only"),
        ),
      ),
    ),
  );
}

// Mirror the current route into the breadcrumb.
//
// Like the sidebar, the top bar is built once, so the crumb is a placeholder
// that gets rewritten on every navigation rather than a value baked in at boot.
function syncBreadcrumb() {
  const el = document.querySelector(".breadcrumb-current");
  if (!el) return;
  const path = (window.location.hash || "#/").slice(1) || "/";
  el.textContent = pageMap[path] ? PAGE_LABELS[path] : "Not found";
}

// Render top bar. The handlers are injected rather than closed over, because
// the poller and the palette do not exist yet when this first runs - they used
// to be empty comment bodies, i.e. two buttons that looked live and did nothing.
function renderTopbar(container, handlers = {}) {
  const currentPath = (window.location.hash || "#/").slice(1) || "/";
  const crumb = pageMap[currentPath] ? PAGE_LABELS[currentPath] : "Not found";
  container.append(
    h("header", { class: "topbar" },
      h("div", { class: "topbar-left" },
        h("button", {
          class: "btn btn-ghost btn-icon btn-sm",
          onclick: () => {
            const next = !store.get().sidebarCollapsed;
            store.set({ sidebarCollapsed: next });
            document.body.classList.toggle("sidebar-collapsed", next);
          },
          "aria-label": "Toggle sidebar",
        }, icon("menu", 16)),
        h("div", { class: "breadcrumb" },
          h("a", { href: "#/" }, "WinTCP"),
          h("span", { class: "breadcrumb-sep" }, "/"),
          h("span", { class: "breadcrumb-current", "aria-current": "page" }, crumb),
        ),
      ),
      h("div", { class: "topbar-right" },
        h("span", { class: "topbar-status", id: "topbar-status" }, ""),
        h("button", {
          class: "btn btn-ghost btn-sm",
          type: "button",
          onclick: () => handlers.onPalette && handlers.onPalette(),
        }, icon("search", 14), "Ctrl+K"),
        h("button", {
          class: "btn btn-ghost btn-icon btn-sm",
          type: "button",
          onclick: () => handlers.onRefresh && handlers.onRefresh(),
          "aria-label": "Refresh now",
          title: "Refresh now",
        }, icon("refresh", 16)),
        h("button", {
          class: "btn btn-ghost btn-icon btn-sm",
          id: "topbar-pause",
          type: "button",
          onclick: () => handlers.onTogglePause && handlers.onTogglePause(),
          "aria-label": store.get().paused ? "Resume live updates" : "Pause live updates",
          title: store.get().paused ? "Resume live updates" : "Pause live updates",
        }, store.get().paused ? "Resume" : "Pause"),
        h("button", {
          class: "btn btn-ghost btn-icon btn-sm",
          type: "button",
          onclick: () => {
            const current = store.get().theme;
            const next = current === "dark" ? "light" : current === "light" ? "system" : "dark";
            store.set({ theme: next });
            applyTheme(next);
            savePreferences({ theme: next });
          },
          "aria-label": "Toggle theme",
          title: "Theme: " + store.get().theme,
        }, icon("sun", 16)),
      ),
    ),
  );
}

// Render page container
function renderMain(container) {
  container.append(
    h("div", { class: "main-content", id: "main-content" },
      h("main", { class: "page", id: "page" }),
    ),
  );
}

// Route handlers - delegate to page modules
const pageMap = {
  "/": renderOverview,
  "/performance": renderPerformance,
  "/processes": renderProcesses,
  "/network": renderNetwork,
  "/map": renderMap,
  "/automations": renderAutomations,
  "/blocks": renderBlocks,
  "/system": renderSystem,
  "/settings": renderSettings,
};

const PAGE_LABELS = {
  "/": "Overview",
  "/performance": "Performance",
  "/processes": "Processes",
  "/network": "Network",
  "/map": "Map",
  "/automations": "Automations",
  "/blocks": "Blocked Peers",
  "/system": "System",
  "/settings": "Settings",
};

// Optional incremental update functions. When registered, the poller calls these
// instead of tearing down and rebuilding the whole page DOM on every data change.
// Pages without an entry fall back to the full re-render.
const pageUpdateFns = {
  "/": updateOverview,
  "/performance": updatePerformance,
  "/processes": updateProcesses,
  "/network": updateNetwork,
};

// Release anything a page registered for teardown before the element is reused.
// This MUST live at module scope: the router handlers below are closures that
// run long after their enclosing block would have ended, so a helper declared
// inside the registration loop is simply not in scope where it is called. That
// mistake produced a silent ReferenceError on every poll, which the poller's
// bare catch swallowed - the page just stopped updating.
function disposePage() {
  const page = document.getElementById("page");
  if (!page) return;
  if (typeof page._chartDestroy === "function") {
    page._chartDestroy();
    page._chartDestroy = null;
  }
  if (typeof page._procDestroy === "function") {
    page._procDestroy();
    page._procDestroy = null;
  }
  if (typeof page._netDestroy === "function") {
    page._netDestroy();
    page._netDestroy = null;
  }
  if (typeof page._mapDestroy === "function") {
    page._mapDestroy();
    page._mapDestroy = null;
  }
}

for (const [path, renderFn] of Object.entries(pageMap)) {
  route(path, async () => {
    const page = document.getElementById("page");
    disposePage();
    clear(page);
    // A navigation is a fresh render, so the next poll must not skip it.
    pageSignatures.delete(path);
    try {
      await renderFn(page, store);
    } catch (err) {
      // A page that throws must not leave the operator staring at a blank shell.
      clear(page);
      page.append(
        h("div", { class: "page-heading" },
          h("h1", { class: "page-title" }, PAGE_LABELS[path] || "Page"),
          h("p", { class: "page-description text-danger" },
            "This page failed to render: " + (err && err.message ? err.message : String(err))),
        ),
      );
      console.error(`page ${path} failed to render`, err);
    }
    updateTopbarStatus();
  });
}

// A hash with no route must say so. Without a handler the sidebar link for
// /blocks silently did nothing at all.
setNotFound(async () => {
  const page = document.getElementById("page");
  clear(page);
  const path = (window.location.hash || "").slice(1) || "/";
  page.append(
    h("div", { class: "page-heading" },
      h("h1", { class: "page-title" }, "Page not found"),
      h("p", { class: "page-description" }, "No page is registered at " + path),
    ),
  );
});

// Preferences live in the existing server-side config so they survive a restart
// and stay in step with the CLI. A failed write is not fatal: the UI keeps
// working, it just forgets.
async function savePreferences(patch) {
  try {
    const current = await api.get("/api/config");
    await api.post("/api/config", { ...current, ...patch });
  } catch (err) {
    console.warn("could not persist preferences", err);
  }
}

// Initialize
function init() {
  const app = document.getElementById("app-shell");
  clear(app);
  renderSidebar(app);
  renderTopbar(app, {});
  renderMain(app);

  // Apply saved preferences
  const state = store.get();
  applyTheme(state.theme);
  applyDensity(state.density);
  document.body.classList.toggle("sidebar-collapsed", !!state.sidebarCollapsed);

  // Start router
  startRouter();
  syncSidebarActive();
  // Registered AFTER startRouter so the page has rendered before the breadcrumb
  // and the sidebar catch up; hashchange fires once per listener in
  // registration order.
  window.addEventListener("hashchange", () => {
    syncSidebarActive();
    syncBreadcrumb();
  });

  // Command palette
  const palette = createCommandPalette([
    { label: "Go to Overview", icon: "home", handler: () => navigate("/") },
    { label: "Go to Performance", icon: "activity", handler: () => navigate("/performance") },
    { label: "Go to Processes", icon: "layers", handler: () => navigate("/processes") },
    { label: "Go to Network", icon: "network", handler: () => navigate("/network") },
    { label: "Go to Map", icon: "globe", handler: () => navigate("/map") },
    { label: "Go to Automations", icon: "zap", handler: () => navigate("/automations") },
    { label: "Go to Blocked Peers", icon: "shield", handler: () => navigate("/blocks") },
    { label: "Go to System", icon: "server", handler: () => navigate("/system") },
    { label: "Go to Settings", icon: "settings", handler: () => navigate("/settings") },
    { label: "Refresh now", icon: "refresh", handler: () => refresh() },
  ]);

  // Start poller. One poll fans out to every read-only endpoint the pages draw
  // from, so a page switch never has to wait on the network to paint.
  const refresh = async () => {
    if (store.get().paused) return;
    try {
      const [connections, metrics, capabilities, processes, networkSummary, geoSummary, systemInfo] =
        await Promise.all([
          api.get("/api/connections"),
          api.get("/api/metrics/now"),
          api.get("/api/capabilities"),
          api.get("/api/processes?sort=cpu&limit=2000"),
          api.get("/api/network/summary"),
          api.get("/api/geo/summary"),
          api.get("/api/system/info"),
        ]);
      if (store.get().paused) return;
      const processRows = processes.processes || [];
      store.set({
        connections: connections.connections || [],
        metrics,
        capabilities,
        processes: processRows,
        // Whether the process list is a real reading or "not sampled yet". The
        // Overview shows an empty state rather than a zero when it is false.
        processesKnown: processes.known !== false,
        processCount: processes.total ?? null,
        processSampleAgeMs: processes.ageMs ?? null,
        processSampledAtMs: processes.sampledAtMs ?? null,
        networkSummary,
        geoSummary,
        systemInfo,
        // Lifted out of the metrics payload so a page does not have to reach
        // into metrics["sys.uptimeSeconds"] to label itself.
        sysUptime: metrics["sys.uptimeSeconds"] ?? null,
        status: "online",
        lastUpdate: new Date(),
      });
    } catch (err) {
      // Keep the last good data on screen and say the poll failed. Blanking the
      // dashboard on one transient error is worse than showing stale numbers.
      store.set({ status: "error", lastError: err.message });
      console.warn("poll failed", err);
    }
    updateTopbarStatus();
    // Pages that only read once at render time still need to follow the data.
    rerenderCurrentPage();
  };

  const poller = createPoller(refresh, state.refreshInterval);
  poller.start();

   // Now that the handlers exist, wire the top bar to them.
  const header = app.querySelector(".topbar");
   if (header) header.replaceWith(renderTopbarFragment({
     onPalette: () => palette.open(),
     onRefresh: () => refresh(),
     onTogglePause: () => {
       if (store.get().paused) {
         store.set({ paused: false });
         poller.start();
       } else {
         store.set({ paused: true });
         poller.stop();
       }
       updateTopbarStatus();
     },
   }));

  // Load the persisted preferences (theme, density, refresh cadence) once.
   // Reads from config.preferences (v3) first, falling back to top-level (v2).
   api.get("/api/config").then((config) => {
     const prefs = config.preferences || config;
     const patch = {};
     if (prefs.theme) patch.theme = prefs.theme;
     if (prefs.accent) patch.accent = prefs.accent;
     if (prefs.density) patch.density = prefs.density;
     if (prefs.units) patch.units = prefs.units;
     if (Number.isFinite(prefs.refreshSeconds)) {
       // The server stores seconds; the poller wants milliseconds. Clamp so a
       // hand-edited config cannot turn the dashboard into a request storm.
       const seconds = Math.min(Math.max(prefs.refreshSeconds, 1), 60);
       patch.refreshInterval = seconds * 1000;
       poller.setInterval(seconds * 1000);
     }
     store.set(patch);
     applyTheme(patch.theme || store.get().theme);
     applyAccent(patch.accent || store.get().accent);
     applyDensity(patch.density || store.get().density);
    }).catch(() => { /* defaults already applied */ });
}

// Mirror connection status into the top bar and the live region.
function updateTopbarStatus() {
  const el = document.getElementById("topbar-status");
  const status = store.get().status;
  if (el) {
    const held = store.get().paused;
    el.textContent = held ? "Paused" : status === "online" ? "Live" : "Reconnecting";
    el.className = `topbar-status is-${held ? "paused" : status}`;
  }
  const pauseButton = document.getElementById("topbar-pause");
  if (pauseButton) {
    pauseButton.textContent = store.get().paused ? "Resume" : "Pause";
    pauseButton.setAttribute("aria-label", store.get().paused ? "Resume live updates" : "Pause live updates");
    pauseButton.title = store.get().paused ? "Resume live updates" : "Pause live updates";
  }
  const live = document.getElementById("snapshot-status");
  const at = store.get().lastUpdate;
  if (live && at) live.textContent = `Snapshot updated at ${at.toLocaleTimeString()}`;
}

// Re-run the current page's renderer so polled data reaches the DOM.
//
// Two rules this has to obey, both learned the hard way:
//
//  1. SKIP when the page's data has not changed. Rebuilding a page every 2 s is
//     not just wasteful, it is hostile: it throws away the operator's scroll
//     position, their text selection, and - the bug a keyboard walkthrough found
//     - keyboard focus. Pressing End and then Home did nothing, because the poll
//     that landed in between had replaced the table and moved focus to <body>.
//  2. RESTORE focus across the rebuild, for the cases where a re-render is
//     genuinely needed.
const pageSignatures = new Map();

// A cheap identity for the slice of state a page renders from.
function pageSignature(path, state) {
  const slice = {
    "/": { n: state.connections?.length, m: state.metrics?._timestamp },
    "/performance": { m: state.metrics?._timestamp },
    "/map": { g: state.geoSummary, n: state.connections?.length },
    "/automations": { c: state.configVersion },
    "/blocks": { c: state.configVersion },
    "/system": { i: state.systemInfo, c: state.capabilities },
    "/settings": { c: state.configVersion },
  }[path];
  return slice ? JSON.stringify(slice) : null;
}

// Identify the focused element well enough to find it again after a rebuild.
function captureFocus() {
  const el = document.activeElement;
  if (!el || el === document.body || !el.closest) return null;
  return {
    tag: el.tagName.toLowerCase(),
    id: el.id || null,
    dataIndex: el.dataset ? (el.dataset.index ?? null) : null,
    className: typeof el.className === "string" ? el.className : null,
    text: (el.textContent || "").trim().slice(0, 40),
  };
}

function restoreFocus(snapshot) {
  if (!snapshot) return;
  let target = snapshot.id ? document.getElementById(snapshot.id) : null;
  if (!target && snapshot.dataIndex != null) {
    target = document.querySelector(`[data-index="${snapshot.dataIndex}"]`);
  }
  if (!target && snapshot.className) {
    const candidates = Array.from(document.querySelectorAll(snapshot.tag));
    target = candidates.find(
      (c) =>
        typeof c.className === "string" &&
        c.className === snapshot.className &&
        (c.textContent || "").trim().slice(0, 40) === snapshot.text,
    );
  }
  if (target && typeof target.focus === "function") target.focus();
}

function rerenderCurrentPage() {
  const path = (window.location.hash || "#/").slice(1) || "/";
  const renderFn = pageMap[path];
  const page = document.getElementById("page");
  if (!renderFn || !page) return;
  // Skip the first poll's empty state: it would clear and rebuild every chart
  // before there is anything to draw.
  if (!store.get().lastUpdate) return;

  if (path === "/map") {
    Promise.resolve(updateMap(page, store))
      .catch((err) => console.error("page update failed", err));
    return;
  }

  const updateFn = pageUpdateFns[path];
  if (updateFn && typeof updateFn === "function") {
    // Incremental update: patch the existing DOM in place.
    Promise.resolve(updateFn(page, store))
      .catch((err) => console.error("page update failed", err));
    return;
  }

  // Full re-render path (used by pages without an incremental update function).
  const signature = pageSignature(path, store.get());
  if (signature !== null && pageSignatures.get(path) === signature) return;
  pageSignatures.set(path, signature);

  const scroll = page.scrollTop;
  const focus = captureFocus();
  disposePage();
  clear(page);
  Promise.resolve(renderFn(page, store))
    .then(() => {
      page.scrollTop = scroll;
      restoreFocus(focus);
    })
    .catch((err) => console.error("page refresh failed", err));
}

// Render the top bar once its handlers exist. Split out because the fragment
// needs the palette/poller, which are built after the first paint.
function renderTopbarFragment(handlers) {
  const holder = document.createElement("div");
  renderTopbar(holder, handlers);
  return holder.firstElementChild;
}

// Wait for DOM
function boot() {
  // First, so a CSP violation during the first paint is not missed.
  installCspReporter();
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
}

boot();
