// main.js - Entry point for the WinTCP Web UI

import { startRouter, route, navigate, setNotFound, resolve as resolveRoute } from "./router.js";
import { api } from "./api.js";
import { createStore } from "./store.js";
import { createPoller } from "./poller.js";
import { h, clear } from "./h.js";
import { icon } from "./icons.js";
import { fmtNum, fmtBytes, fmtPct, fmtDuration, setFormatUnits } from "./format.js";
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
import { createSnapshotRefresh } from "./refresh.js";
import { createRecipeNotificationDelivery } from "./recipe-notification-delivery.js";
import { normalizeConnectionFilters } from "./connectionfilters.js";
import { notify } from "./ui/feedback.js";

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
  networkPredicates: [],
  networkTableScrollTop: 0,
  networkListeningScrollTop: 0,
});

let sessionExpiredToast = null;
window.addEventListener("wintcp:session-expired", () => {
  if (sessionExpiredToast?.isConnected) return;
  sessionExpiredToast = notify("Your dashboard session expired. Pending changes were not saved; reload to reconnect.", {
    error: true,
    action: { label: "Reload dashboard", onClick: () => window.location.reload() },
  });
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
        { path: "/blocks", icon: "shield", label: "Firewall Rules" },
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
        h("span", { class: "topbar-status", id: "topbar-status", role: "status", "aria-live": "polite" }, ""),
        h("button", {
          class: "btn btn-ghost btn-icon btn-sm topbar-palette",
          type: "button",
          "aria-label": "Open command palette",
          onclick: () => handlers.onPalette && handlers.onPalette(),
        }, icon("search", 14), h("span", { class: "sr-only" }, "Open command palette")),
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
        }, icon(store.get().paused ? "play" : "pause", 16)),
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
  "/blocks": "Firewall Rules",
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
let routeGeneration = 0;

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
  if (typeof page._settingsDestroy === "function") {
    page._settingsDestroy();
    page._settingsDestroy = null;
  }
  if (typeof page._autoDestroy === "function") {
    page._autoDestroy();
    page._autoDestroy = null;
  }
  if (typeof page._blocksDestroy === "function") {
    page._blocksDestroy();
    page._blocksDestroy = null;
  }
}

function replacePage() {
  disposePage();
  const previous = document.getElementById("page");
  const page = previous.cloneNode(false);
  // Per-page layout classes (such as the Map page's full-width mode) must not
  // leak into the next route's cloned shell.
  page.className = "page";
  previous.replaceWith(page);
  return page;
}

for (const [path, renderFn] of Object.entries(pageMap)) {
  route(path, async () => {
    const mine = ++routeGeneration;
    const page = replacePage();
    page._rendering = true;
    // A navigation is a fresh render, so the next poll must not skip it.
    pageSignatures.delete(path);
    try {
      await renderFn(page, store);
      if (mine !== routeGeneration) return;
      pageSignatures.set(path, pageSignature(path, store.get()));
    } catch (err) {
      if (mine !== routeGeneration) return;
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
    } finally {
      page._rendering = false;
    }
    updateTopbarStatus();
  });
}

// A hash with no route must say so. Without a handler the sidebar link for
// /blocks silently did nothing at all.
setNotFound(async () => {
  routeGeneration++;
  const page = replacePage();
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
    await api.updateConfig((current) => ({
      ...current, ...patch, preferences: { ...current.preferences, ...patch },
    }));
  } catch (err) {
    console.warn("could not persist preferences", err);
  }
}

// Initialize
function init() {
  document.addEventListener("wintcp:investigate", (event) => {
    try {
      const detail = event.detail || {};
      const predicates = normalizeConnectionFilters(detail.filters);
      const filters = detail.mode === "add" ? [...(store.get().networkPredicates || []), ...predicates] : predicates;
      const unique = [...new Map(filters.map((filter) => [JSON.stringify(filter), filter])).values()];
      store.set({ networkPredicates: unique, networkFilter: "", networkView: "connections", networkTableScrollTop: 0 });
      if (window.location.hash === "#/network") resolveRoute();
      else navigate("/network");
    } catch (error) {
      notify(error.message, { error: true });
    }
  });
  document.addEventListener("wintcp:firewall-investigate", (event) => {
    const target = event.detail?.target;
    if (!target || typeof target !== "object") return;
    store.set({ firewallTarget: target, firewallRuleName: null, networkView: "blocked", networkTableScrollTop: 0 });
    if (window.location.hash === "#/network") resolveRoute();
    else navigate("/network");
  });
  document.addEventListener("wintcp:firewall-open-rule", (event) => {
    const name = event.detail?.name;
    if (typeof name !== "string" || !name || name.length > 2048) return;
    store.set({ firewallTarget: null, firewallRuleName: name, networkView: "blocked", networkTableScrollTop: 0 });
    if (window.location.hash === "#/network") resolveRoute();
    else navigate("/network");
  });
  document.addEventListener("wintcp:inspect-connection", (event) => {
    const key = event.detail?.key;
    if (typeof key !== "string" || !key.startsWith("connection:") || key.length > 512) return;
    store.set({ pendingConnectionInspectorKey: key, networkView: "connections" });
    if (window.location.hash === "#/network") resolveRoute();
    else navigate("/network");
  });
  document.addEventListener("wintcp:refresh-now", () => {
    refresh({ manual: true }).catch(() => {});
  });
  document.addEventListener("wintcp:retry-map", () => {
    if (window.location.hash === "#/map") rerenderCurrentPage();
  });
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
    { label: "Go to Firewall Rules", icon: "shield", handler: () => navigate("/blocks") },
    { label: "Go to System", icon: "server", handler: () => navigate("/system") },
    { label: "Go to Settings", icon: "settings", handler: () => navigate("/settings") },
    { label: "Refresh now", icon: "refresh", handler: () => refresh({ manual: true }).catch(() => {}) },
  ]);

  // Start poller. One poll fans out to every read-only endpoint the pages draw
  // from, so a page switch never has to wait on the network to paint.
  let observedConnections = null;
  const recipeNotificationDelivery = createRecipeNotificationDelivery({
    api,
    enabled: () => store.get().desktopNotifications === true,
    permitted: () => "Notification" in window && Notification.permission === "granted",
    notify: (notice) => {
      const notification = new Notification(notice.recipeName || "WinTCP monitor", {
        body: String(notice.message || "A monitoring recipe fired.").slice(0, 400),
        tag: `wintcp-recipe-${notice.id}`,
      });
      notification.onclick = () => {
        window.focus();
        navigate("/automations");
        notification.close();
      };
      setTimeout(() => notification.close(), 12000);
    },
  });
  let lastRecipeNotificationPoll = 0;
  const refreshController = createSnapshotRefresh({
    api,
    store,
    onUpdate: () => {
      const current = store.get();
      const now = Date.now();
      if (now - lastRecipeNotificationPoll >= 15000) {
        lastRecipeNotificationPoll = now;
        void recipeNotificationDelivery.poll();
      }
      const liveConnections = (current.connections || []).filter((row) => !row.removed && row.rport > 0 && row.state !== "LISTENING");
      const identities = new Set(liveConnections.map((row) => row.id));
      const added = observedConnections ? liveConnections.filter((row) => !observedConnections.has(row.id)) : [];
      observedConnections = identities;
      if (!current.paused && current.desktopNotifications && added.length &&
          "Notification" in window && Notification.permission === "granted") {
        try {
          const notice = new Notification(`${added.length} new remote connection${added.length === 1 ? "" : "s"}`, {
            body: [...new Set(added.map((row) => row.process || "Unknown process"))].slice(0, 3).join(", "),
            tag: "wintcp-connections",
          });
          notice.onclick = () => { window.focus(); navigate("/network"); notice.close(); };
          setTimeout(() => notice.close(), 10000);
        } catch (error) {
          console.warn("Connection notification could not be displayed", error);
        }
      }
      updateTopbarStatus();
      rerenderCurrentPage();
    },
  });
  const refresh = refreshController.refresh;

  const poller = createPoller(refresh, state.refreshInterval);
  poller.start();
  const applyPreferences = (preferences) => {
    const patch = { ...preferences };
    if (Number.isFinite(preferences.refreshSeconds)) {
      patch.refreshInterval = Math.min(60, Math.max(1, preferences.refreshSeconds)) * 1000;
      poller.setInterval(patch.refreshInterval);
    }
    store.set(patch);
    applyTheme(store.get().theme);
    applyAccent(store.get().accent);
    applyDensity(store.get().density);
    setFormatUnits(store.get().units);
    const currentPage = window.location.hash.slice(1) || "/";
    if (currentPage !== "/settings" && currentPage !== "/automations") rerenderCurrentPage();
  };
  document.addEventListener("wintcp:preferences", (event) => applyPreferences(event.detail));
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
    if (store.get().theme === "system") applyTheme("system");
  });
  setInterval(updateTopbarStatus, 1000);

   // Now that the handlers exist, wire the top bar to them.
  const header = app.querySelector(".topbar");
   if (header) header.replaceWith(renderTopbarFragment({
     onPalette: () => palette.open(),
     onRefresh: () => refresh({ manual: true }).catch(() => {}),
     onTogglePause: () => {
       refreshController.invalidate();
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
     const prefs = { ...config, ...config.preferences };
     const patch = {};
     if (prefs.theme) patch.theme = prefs.theme;
     if (prefs.accent) patch.accent = prefs.accent;
     if (prefs.density) patch.density = prefs.density;
     if (prefs.units) patch.units = prefs.units;
     patch.desktopNotifications = prefs.desktopNotifications === true;
     if (Number.isFinite(prefs.refreshSeconds)) {
       // The server stores seconds; the poller wants milliseconds. Clamp so a
       // hand-edited config cannot turn the dashboard into a request storm.
       const seconds = Math.min(Math.max(prefs.refreshSeconds, 1), 60);
       patch.refreshSeconds = seconds;
     }
     applyPreferences(patch);
    }).catch(() => { /* defaults already applied */ });
}

// Mirror connection status into the top bar and the live region.
function updateTopbarStatus() {
  const el = document.getElementById("topbar-status");
  const status = store.get().status;
  if (el) {
    const held = store.get().paused;
    const sampledAt = store.get().lastUpdate;
    const age = sampledAt ? Math.max(0, Math.floor((Date.now() - sampledAt.getTime()) / 1000)) : null;
    el.textContent = held ? `Paused${age == null ? "" : ` · ${age}s old`}`
      : status === "online" ? "Live" : status === "degraded" ? "Partial data" : "Reconnecting";
    el.title = store.get().lastError || (sampledAt ? `Snapshot: ${sampledAt.toLocaleTimeString()}` : "Waiting for a snapshot");
    el.className = `topbar-status is-${held ? "paused" : status}`;
  }
  const pauseButton = document.getElementById("topbar-pause");
  if (pauseButton) {
    pauseButton.replaceChildren(icon(store.get().paused ? "play" : "pause", 16));
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
  if (page._rendering) return;
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
  const mine = ++routeGeneration;
  const replacement = replacePage();
  replacement._rendering = true;
  Promise.resolve(renderFn(replacement, store))
    .then(() => {
      if (mine !== routeGeneration) return;
      replacement.scrollTop = scroll;
      restoreFocus(focus);
    })
    .catch((err) => {
      if (mine === routeGeneration) console.error("page refresh failed", err);
    }).finally(() => { replacement._rendering = false; });
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
