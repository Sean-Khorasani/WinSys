// main.js - Entry point for the WinTCP Web UI

import { startRouter, route, navigate } from "./router.js";
import { api } from "./api.js";
import { createStore } from "./store.js";
import { createPoller } from "./poller.js";
import { h, clear } from "./h.js";
import { icon } from "./icons.js";
import { fmtNum, fmtBytes, fmtPct, fmtDuration } from "./format.js";
import { renderOverview } from "./pages/overview.js";
import { renderPerformance } from "./pages/performance.js";
import { renderProcesses } from "./pages/processes.js";
import { renderNetwork } from "./pages/network.js";
import { renderMap } from "./pages/map.js";
import { renderAutomations } from "./pages/automations.js";
import { renderSystem } from "./pages/system.js";
import { renderSettings } from "./pages/settings.js";
import { createCommandPalette } from "./ui/commandpalette.js";

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
  density: "comfortable",
  sidebarOpen: true,
  sidebarCollapsed: false,
  refreshInterval: 2000,
  timeRange: "live",
  paused: false,
});

// Apply theme
function applyTheme(theme) {
  if (theme === "system") {
    const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    document.documentElement.setAttribute("data-theme", prefersDark ? "dark" : "light");
  } else {
    document.documentElement.setAttribute("data-theme", theme);
  }
}

// Apply density
function applyDensity(density) {
  document.body.classList.toggle("density-compact", density === "compact");
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

  container.append(
    h("aside", { class: "sidebar", id: "sidebar" },
      h("div", { class: "sidebar-header" },
        h("a", { class: "brand", href: "#/" },
          h("span", { class: "brand-mark" }, h("span"), h("span"), h("span")),
          h("span", { class: "sidebar-label" }, "WinTCP"),
        ),
        h("button", {
          class: "btn btn-ghost btn-icon btn-sm",
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

// Render top bar
function renderTopbar(container) {
  container.append(
    h("header", { class: "topbar" },
      h("div", { class: "topbar-left" },
        h("button", {
          class: "btn btn-ghost btn-icon btn-sm",
          onclick: () => store.set({ sidebarOpen: !store.get().sidebarOpen }),
          "aria-label": "Toggle sidebar",
        }, icon("menu", 16)),
        h("div", { class: "breadcrumb" },
          h("a", { href: "#/" }, "WinTCP"),
          h("span", { class: "breadcrumb-sep" }, "/"),
          h("span", { class: "breadcrumb-current" }, "Control Room"),
        ),
      ),
      h("div", { class: "topbar-right" },
        h("button", {
          class: "btn btn-ghost btn-sm",
          onclick: () => { /* command palette */ },
        }, icon("search", 14), "Ctrl+K"),
        h("button", {
          class: "btn btn-ghost btn-icon btn-sm",
          onclick: () => { /* refresh */ },
          "aria-label": "Refresh",
        }, icon("refresh", 16)),
        h("button", {
          class: "btn btn-ghost btn-icon btn-sm",
          onclick: () => {
            const current = store.get().theme;
            const next = current === "dark" ? "light" : current === "light" ? "system" : "dark";
            store.set({ theme: next });
            applyTheme(next);
          },
          "aria-label": "Toggle theme",
        }, icon("sun", 16)),
      ),
    ),
  );
}

// Render page container
function renderMain(container) {
  container.append(
    h("div", { class: "main-content", id: "main-content" },
      h("main", { class: "page", id="page" }),
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
  "/system": renderSystem,
  "/settings": renderSettings,
};

for (const [path, renderFn] of Object.entries(pageMap)) {
  route(path, async () => {
    const page = document.getElementById("page");
    clear(page);
    await renderFn(page, store);
  });
}

// Initialize
function init() {
  const app = document.getElementById("app-shell");
  clear(app);
  renderSidebar(app);
  renderTopbar(app);
  renderMain(app);

  // Apply saved preferences
  const state = store.get();
  applyTheme(state.theme);
  applyDensity(state.density);

  // Start router
  startRouter();

  // Command palette
  const palette = createCommandPalette([
    { label: "Go to Overview", icon: "home", handler: () => navigate("/") },
    { label: "Go to Performance", icon: "activity", handler: () => navigate("/performance") },
    { label: "Go to Processes", icon: "layers", handler: () => navigate("/processes") },
    { label: "Go to Network", icon: "network", handler: () => navigate("/network") },
    { label: "Go to Map", icon: "globe", handler: () => navigate("/map") },
    { label: "Go to Automations", icon: "zap", handler: () => navigate("/automations") },
    { label: "Go to System", icon: "server", handler: () => navigate("/system") },
    { label: "Go to Settings", icon: "settings", handler: () => navigate("/settings") },
  ]);

  // Start poller
  const poller = createPoller(async () => {
    try {
      const [connections, metrics, capabilities] = await Promise.all([
        api.get("/api/connections"),
        api.get("/api/metrics/now"),
        api.get("/api/capabilities"),
      ]);
      store.set({
        connections: connections.connections || [],
        metrics,
        capabilities,
        status: "online",
        lastUpdate: new Date(),
      });
    } catch (err) {
      store.set({ status: "error" });
    }
  }, state.refreshInterval);
  poller.start();
}

// Wait for DOM
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
