// pages/network.js - Network page
//
// Four real views over one connection snapshot: every endpoint, only the
// listening sockets classified by exposure, the blocked-peer inventory, and a
// process-to-country flow summary.

import { h, clear } from "../h.js";
import { createVirtualTable } from "../ui/virtualtable.js";
import { createTabs } from "../ui/tabs.js";
import { emptyState, refreshAction, card, cardHeader, cardTitle, cardContent, cardFooter } from "../ui/card.js";
import { badge } from "../ui/badge.js";
import { dialog, openDialog, closeDialog } from "../ui/dialog.js";
import { api } from "../api.js";
import { fmtInt, fmtBytes } from "../format.js";
import { icon } from "../icons.js";
import { connectionKey, connectionRowsTsv, endpoint, exposureOf, hostnameLabel, remoteEndpointValue, remoteHostnameValue, remoteIpValue, resolvedHostname } from "../connections.js";
import { connectionMenu } from "../ui/connectionmenu.js";
import { closeContextMenu } from "../ui/contextmenu.js";
import { matchesConnectionQuery, parseConnectionQuery } from "../filterquery.js";
import { copyText } from "../ui/feedback.js";
import { matchesConnectionFilters, connectionFilterLabel, normalizeConnectionFilters } from "../connectionfilters.js";
import { createFirewallInventoryView } from "../firewallinventory.js";
import { addressComparator, numberComparator, stateComparator, textComparator } from "../sort.js";
import { createColumnLayoutControls } from "../ui/columnlayout.js";
import { closeInspector, formatProcessInstance, openInspector, updateInspector } from "../ui/inspector.js";

const UNAVAILABLE = "\u2014";
const num = (value) => (typeof value === "number" && Number.isFinite(value) ? value : null);
const NETWORK_VIEW_TABS = new Set(["connections", "history", "listening", "flows"]);
const NETWORK_VIEW_FILTER_FIELDS = new Set([
  "pid", "lport", "rport", "processInstanceId", "remote", "local", "country", "proto", "state",
]);
const MAX_SAVED_NETWORK_VIEWS = 30;
const MAX_RECENT_NETWORK_VIEWS = 10;
const RECENT_NETWORK_VIEWS_KEY = "wintcp.network.recentViews.v1";
let activeCloseDialog = null;
let activeBlockDialog = null;

function copyValues(rows, select) {
  const values = [];
  const seen = new Set();
  for (const row of rows) {
    const raw = select(row);
    if (raw == null) continue;
    const value = String(raw);
    if (!value || value === UNAVAILABLE || value === "-" || value === "...pending...") continue;
    const key = value.toLocaleLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    values.push(value);
  }
  return values.join("\n");
}
function normalizeSavedNetworkViews(value) {
  if (!Array.isArray(value)) return [];
  const views = [];
  const seenIds = new Set();
  for (const item of value) {
    if (!item || typeof item !== "object" || item.version !== 1 ||
        typeof item.id !== "string" || !item.id || seenIds.has(item.id) ||
        typeof item.name !== "string" || !item.name.trim()) continue;
    if (typeof item.query === "string" && item.query.length > 1024) continue;
    const query = typeof item.query === "string" ? item.query : "";
    if (parseConnectionQuery(query).error) continue;
    let predicates = [];
    try {
      predicates = normalizeConnectionFilters(item.predicates || []);
      if (predicates.some((predicate) => !NETWORK_VIEW_FILTER_FIELDS.has(predicate.field))) continue;
    } catch {
      continue;
    }
    const layout = item.layout?.version === 1 && Array.isArray(item.layout.order) &&
      Array.isArray(item.layout.hidden) && item.layout.widths && typeof item.layout.widths === "object"
      ? {
        version: 1,
        order: item.layout.order.filter((key) => typeof key === "string"),
        hidden: item.layout.hidden.filter((key) => typeof key === "string"),
        widths: Object.fromEntries(Object.entries(item.layout.widths)
          .filter(([key, width]) => typeof key === "string" && Number.isFinite(Number(width)) &&
            Number(width) >= 0.5 && Number(width) <= 4)
          .map(([key, width]) => [key, Number(width)])),
      } : null;
    views.push({
      version: 1,
      id: item.id,
      name: item.name.trim().slice(0, 60),
      query,
      predicates,
      sortKey: Object.hasOwn(connComparators, item.sortKey) ? item.sortKey : "",
      sortDir: item.sortDir === "asc" || item.sortDir === "desc" ? item.sortDir : "",
      tab: NETWORK_VIEW_TABS.has(item.tab) ? item.tab : "connections",
      layout,
    });
    seenIds.add(item.id);
    if (views.length >= MAX_SAVED_NETWORK_VIEWS) break;
  }
  return views;
}

function endpointTieBreak(a, b) {
  const ak = connectionKey(a);
  const bk = connectionKey(b);
  return ak.localeCompare(bk, undefined, { sensitivity: "base" });
}

const connComparators = {
  process: textComparator((row) => row.process || row.processName, connectionKey,
    (a, b) => numberComparator((row) => row.pid, connectionKey)(a, b, "asc")),
  pid: numberComparator((row) => row.pid, connectionKey),
  proto: textComparator((row) => row.proto, connectionKey),
  local: addressComparator((row) => row.local || row.localAddress, connectionKey),
  remote: addressComparator((row) => row.remote || row.remoteAddress, connectionKey),
  state: stateComparator((row) => row.state, connectionKey),
  country: textComparator((row) => row.country, connectionKey),
  exposure: textComparator((row) => exposureOf(row).label, connectionKey),
  port: numberComparator((row) => row.lport, connectionKey),
  lport: numberComparator((row) => row.lport, connectionKey),
  rport: numberComparator((row) => row.rport, connectionKey),
  hostname: textComparator((row) => row.hostname, connectionKey),
};

function defaultConnSort(rows) {
  return rows.slice().sort((a, b) => {
    return connComparators.process(a, b, "asc") || endpointTieBreak(a, b);
  });
}

export async function renderNetwork(page, store) {
  clear(page);
  const state = store.get();

  const layout = h("div", { class: "net-layout" });
  const savedViewName = h("input", {
    class: "input", id: "net-view-name", type: "text", maxlength: "60",
    placeholder: "Name this view", "aria-label": "Saved view name",
  });
  const savedViewSelect = h("select", {
    class: "input", id: "net-saved-view", "aria-label": "Saved Network views",
    disabled: true,
  }, h("option", { value: "" }, "Saved views"));
  const recentViewSelect = h("select", {
    class: "input", id: "net-recent-view", "aria-label": "Recent Network views",
    disabled: true,
  }, h("option", { value: "" }, "Recent views"));
  const savedViewSave = h("button", {
    class: "btn btn-outline btn-sm", id: "net-save-view", type: "button", disabled: true,
  }, "Save view");
  const savedViewDelete = h("button", {
    class: "btn btn-ghost btn-sm", id: "net-delete-view", type: "button", disabled: true,
  }, "Delete view");
  const recentViewClear = h("button", {
    class: "btn btn-ghost btn-sm", id: "net-clear-recent-views", type: "button", disabled: true,
    "aria-label": "Clear recent Network views",
  }, "Clear recent");
  const savedViewStatus = h("span", {
    class: "muted text-sm", id: "net-view-status", role: "status", "aria-live": "polite",
  });
  const savedViewControls = h("div", { class: "network-saved-views" },
    savedViewName, savedViewSave, savedViewSelect, savedViewDelete,
    recentViewSelect, recentViewClear, savedViewStatus);
  const savedViewAbort = new AbortController();
  let savedViews = [];
  let savedViewsReady = false;
  let savedViewSaving = false;
  let configRefreshGeneration = 0;
  let recentViews = [];
  let recentViewTimer = null;
  let restoringNetworkView = false;
  try {
    recentViews = normalizeSavedNetworkViews(
      JSON.parse(globalThis.localStorage?.getItem(RECENT_NETWORK_VIEWS_KEY) || "[]"),
    ).slice(0, MAX_RECENT_NETWORK_VIEWS);
  } catch {
    recentViews = [];
  }
  page.append(
    h("div", { class: "page-heading network-page-heading" },
      h("div", {},
        h("h1", { class: "page-title" }, "Network"),
        h("p", { class: "page-description" },
          "Live TCP and UDP endpoints, listening sockets, and blocked peers"),
      ),
      h("div", { class: "network-filter-control" },
        h("input", {
          class: "input page-filter",
          id: "net-filter",
          type: "search",
          maxlength: "1024",
          placeholder: "Filter: process, pid:123, port:443\u2026",
          "aria-label": "Filter endpoints",
          "aria-describedby": "net-filter-help",
        }),
        h("small", { class: "network-filter-help muted text-sm", id: "net-filter-help" },
          "Use field:value; spaces combine as AND. Example: pid:123 port:443"),
      ),
    ),
    savedViewControls,
    layout,
  );

  const filterInput = page.querySelector("#net-filter");
  const filterStatus = h("p", { class: "filter-query-status", role: "status", hidden: true });
  page.querySelector(".page-heading")?.after(filterStatus);
  filterInput.value = store.get().networkFilter || "";
  let debounce = null;
  let applyFilterNow = null;
  const onFilterInput = () => {
    store.set({ networkFilter: filterInput.value });
    if (!applyFilterNow) return;
    if (debounce !== null) clearTimeout(debounce);
    debounce = setTimeout(() => {
      debounce = null;
      applyFilterNow();
      recordRecentNetworkView();
    }, 120);
  };
  filterInput.addEventListener("input", onFilterInput);
  const selectedSavedView = () => savedViews.find((view) => view.id === savedViewSelect.value) || null;
  const renderSavedViewOptions = (selectedId = savedViewSelect.value) => {
    savedViewSelect.replaceChildren(h("option", { value: "" }, "Saved views"));
    for (const view of savedViews) savedViewSelect.append(h("option", { value: view.id }, view.name));
    if (savedViews.some((view) => view.id === selectedId)) savedViewSelect.value = selectedId;
    savedViewDelete.disabled = !savedViewsReady || !selectedSavedView() || savedViewSaving;
  };
  const renderRecentViewOptions = (selectedId = recentViewSelect.value) => {
    recentViewSelect.replaceChildren(h("option", { value: "" }, "Recent views"));
    for (const view of recentViews)
      recentViewSelect.append(h("option", { value: view.id }, view.name));
    if (recentViews.some((view) => view.id === selectedId)) recentViewSelect.value = selectedId;
    recentViewSelect.disabled = recentViews.length === 0;
    recentViewClear.disabled = recentViews.length === 0;
  };
  renderRecentViewOptions("");
  const refreshSavedViews = async (remote = false) => {
    const generation = ++configRefreshGeneration;
    const selectedId = savedViewSelect.value;
    try {
      const config = await api.get("/api/config", { signal: savedViewAbort.signal });
      if (savedViewAbort.signal.aborted || generation !== configRefreshGeneration) return;
      savedViews = normalizeSavedNetworkViews(config.networkViews);
      savedViewsReady = true;
      renderSavedViewOptions(selectedId);
      savedViewSelect.disabled = false;
      savedViewSave.disabled = false;
      setSavedViewStatus(remote ? "Saved views synchronized from another tab."
        : savedViews.length ? savedViews.length + " saved view(s)." : "No saved views yet.");
    } catch (error) {
      if (error.name !== "AbortError") setSavedViewStatus("Saved views unavailable: " + error.message);
    }
  };
  const onRecentStorage = (event) => {
    if (event.key !== RECENT_NETWORK_VIEWS_KEY) return;
    try {
      recentViews = normalizeSavedNetworkViews(JSON.parse(event.newValue || "[]"))
        .slice(0, MAX_RECENT_NETWORK_VIEWS);
    } catch {
      recentViews = [];
    }
    renderRecentViewOptions(recentViewSelect.value);
  };
  window.addEventListener("storage", onRecentStorage);
  const unsubscribeConfig = api.subscribeConfigChanges(() => {
    if (!savedViewSaving && !savedViewAbort.signal.aborted) refreshSavedViews(true);
  });
  const setSavedViewStatus = (message) => {
    if (!savedViewAbort.signal.aborted) savedViewStatus.textContent = message;
  };
  const restoreNetworkView = async (view, statusMessage, setName = false) => {
    restoringNetworkView = true;
    try {
      filterInput.value = view.query;
      sortKey = view.sortKey || null;
      sortDir = view.sortDir || null;
      store.set({
        networkFilter: view.query,
        networkPredicates: view.predicates,
        netSortKey: sortKey,
        netSortDir: sortDir,
      });
      if (tabs.active() !== view.tab) await tabs.select(view.tab);
      if (savedViewAbort.signal.aborted) return;
      applyFilter();
      const table = view.tab === "listening" ? listeningTableController
        : (view.tab === "connections" || view.tab === "history") ? connectionTableController : null;
      if (view.layout && table?.applySavedLayout) table.applySavedLayout(view.layout);
      if (setName) savedViewName.value = view.name;
      setSavedViewStatus(statusMessage);
    } finally {
      restoringNetworkView = false;
    }
    recordRecentNetworkView();
  };
  const onSavedViewChange = async () => {
    const view = selectedSavedView();
    savedViewDelete.disabled = !view || savedViewSaving;
    if (!view) return;
    await restoreNetworkView(view, 'Loaded "' + view.name + '".', true);
  };
  const onRecentViewChange = async () => {
    const view = recentViews.find((item) => item.id === recentViewSelect.value);
    if (!view) return;
    await restoreNetworkView(view, 'Restored recent view: ' + view.name + '.');
  };
  const onClearRecentViews = () => {
    recentViews = [];
    renderRecentViewOptions("");
    try {
      const storage = globalThis.localStorage;
      if (!storage) throw new Error("Browser storage is unavailable");
      storage.removeItem(RECENT_NETWORK_VIEWS_KEY);
      setSavedViewStatus("Recent views cleared.");
    } catch {
      setSavedViewStatus("Recent views cleared for this page; browser storage could not be updated.");
    }
  };
  const onSaveSavedView = async () => {
    const name = savedViewName.value.trim();
    if (!name) {
      setSavedViewStatus("Enter a name before saving this view.");
      savedViewName.focus();
      return;
    }
    const query = filterInput.value.trim();
    if (query.length > 1024) {
      setSavedViewStatus("Filter queries can contain at most 1,024 characters.");
      filterInput.focus();
      return;
    }
    if (parseConnectionQuery(query).error) {
      setSavedViewStatus("Fix the filter query before saving this view.");
      filterInput.focus();
      return;
    }
    if (!savedViewsReady || savedViewSaving) return;
    const existing = savedViews.find((view) => view.name.toLocaleLowerCase() === name.toLocaleLowerCase());
    const table = activeView === "listening" ? listeningTableController
      : (activeView === "connections" || activeView === "history") ? connectionTableController : null;
    const view = {
      version: 1,
      id: existing?.id || globalThis.crypto?.randomUUID?.() ||
        ("network-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 10)),
      name: name.slice(0, 60),
      query,
      predicates: store.get().networkPredicates || [],
      sortKey: sortKey || "",
      sortDir: sortDir || "",
      tab: activeView,
      layout: table?.getLayout?.() || null,
    };
    savedViewSaving = true;
    savedViewSave.disabled = true;
    savedViewDelete.disabled = true;
    setSavedViewStatus("Saving view…");
    try {
      const updated = await api.updateConfig((current) => {
        const currentViews = normalizeSavedNetworkViews(current.networkViews);
        const duplicate = currentViews.findIndex((item) => item.id === view.id);
        if (duplicate < 0 && currentViews.length >= MAX_SAVED_NETWORK_VIEWS)
          throw new Error("A maximum of " + MAX_SAVED_NETWORK_VIEWS + " views can be saved.");
        const nextViews = duplicate < 0
          ? [...currentViews, view]
          : currentViews.map((item, index) => index === duplicate ? view : item);
        return { ...current, networkViews: nextViews };
      });
      savedViews = normalizeSavedNetworkViews(updated.networkViews);
      savedViewsReady = true;
      renderSavedViewOptions(view.id);
      savedViewSelect.value = view.id;
      recordRecentNetworkView();
      setSavedViewStatus((existing ? "Updated " : "Saved ") + '"' + view.name + '".');
    } catch (error) {
      setSavedViewStatus("View not saved: " + error.message);
    } finally {
      savedViewSaving = false;
      savedViewSave.disabled = !savedViewsReady;
      savedViewDelete.disabled = !selectedSavedView();
    }
  };
  const onDeleteSavedView = async () => {
    const view = selectedSavedView();
    if (!view || savedViewSaving) return;
    savedViewSaving = true;
    savedViewDelete.disabled = true;
    savedViewSave.disabled = true;
    setSavedViewStatus('Deleting "' + view.name + '"…');
    try {
      const updated = await api.updateConfig((current) => ({
        ...current,
        networkViews: normalizeSavedNetworkViews(current.networkViews)
          .filter((item) => item.id !== view.id),
      }));
      savedViews = normalizeSavedNetworkViews(updated.networkViews);
      renderSavedViewOptions("");
      savedViewName.value = "";
      setSavedViewStatus('Deleted "' + view.name + '".');
    } catch (error) {
      setSavedViewStatus("View not deleted: " + error.message);
    } finally {
      savedViewSaving = false;
      savedViewSave.disabled = !savedViewsReady;
      savedViewDelete.disabled = !selectedSavedView();
    }
  };
  savedViewSelect.addEventListener("change", onSavedViewChange);
  savedViewSave.addEventListener("click", onSaveSavedView);
  savedViewDelete.addEventListener("click", onDeleteSavedView);
  recentViewSelect.addEventListener("change", onRecentViewChange);
  recentViewClear.addEventListener("click", onClearRecentViews);
  refreshSavedViews();
  let snapshotRows = Array.isArray(state.connections) ? state.connections.slice() : [];
  let conns = snapshotRows.filter((row) => !row.removed);
  let geo = state.geoSummary || {};

  const waitForSnapshot = (nextState) => {
    if (!nextState.lastUpdate) return;
    const nextConnections = Array.isArray(nextState.connections) ? nextState.connections : [];
    geo = nextState.geoSummary || {};
    if (nextConnections.length === 0) {
      clear(layout);
      layout.append(emptyState({ action: refreshAction() }, "No endpoints reported",
        "The server enumerated the connection tables and they came back empty."));
      return;
    }
    if (typeof page._netDestroy === "function") page._netDestroy();
    page._netDestroy = null;
    return renderNetwork(page, store);
  };
  const setWaitingLifecycle = () => {
    page._netUpdate = waitForSnapshot;
    page._netDestroy = () => {
      if (debounce !== null) clearTimeout(debounce);
      savedViewAbort.abort();
      unsubscribeConfig();
      window.removeEventListener("storage", onRecentStorage);
      filterInput.removeEventListener("input", onFilterInput);
      savedViewSelect.removeEventListener("change", onSavedViewChange);
      savedViewSave.removeEventListener("click", onSaveSavedView);
      savedViewDelete.removeEventListener("click", onDeleteSavedView);
      recentViewSelect.removeEventListener("change", onRecentViewChange);
      recentViewClear.removeEventListener("click", onClearRecentViews);
      page._netUpdate = null;
    };
  };

  if (!state.lastUpdate) {
    layout.append(emptyState({ action: refreshAction() }, "Waiting for the first sample",
      "The browser polls the server every couple of seconds. This fills in on its own."));
    setWaitingLifecycle();
    return;
  }
  if (snapshotRows.length === 0) {
    layout.append(emptyState({ action: refreshAction() }, "No endpoints reported",
      "The server enumerated the connection tables and they came back empty."));
    setWaitingLifecycle();
    return;
  }

  const storedSortKey = store.get().netSortKey;
  const storedSortDir = store.get().netSortDir;
  let sortKey = storedSortKey || null;
  let sortDir = storedSortDir || null;

  const applySort = (data) => {
    if (!sortKey) return defaultConnSort(data);
    const cmp = connComparators[sortKey];
    if (!cmp) return defaultConnSort(data);
    return data.slice().sort((a, b) => cmp(a, b, sortDir));
  };

  let filteredRows = conns;
  let rows = applySort(filteredRows);
  const summary = h("p", { class: "muted text-sm proc-summary" });
  const chips = h("div", { class: "filter-chips", role: "group", "aria-label": "Active connection filters" });
  let lastFilterSignature = "";
  const renderChips = () => {
    const filters = store.get().networkPredicates || [];
    const signature = JSON.stringify(filters);
    if (signature === lastFilterSignature) return;
    lastFilterSignature = signature;
    clear(chips);
    filters.forEach((filter, index) => {
      const label = connectionFilterLabel(filter);
      chips.append(h("button", {
        type: "button", class: "btn btn-outline btn-sm filter-chip", title: label,
        "aria-label": `Remove ${label}`,
        onclick: () => {
          store.set({ networkPredicates: filters.filter((_, position) => position !== index) });
          applyFilter();
          recordRecentNetworkView();
          filterInput.focus();
        },
      }, `${label} \u00d7`));
    });
    if (filters.length) chips.append(h("button", {
      type: "button", class: "btn btn-ghost btn-sm",
      onclick: () => {
        store.set({ networkPredicates: [], networkFilter: "" });
        filterInput.value = "";
        applyFilter();
        filterInput.focus();
      },
    }, "Clear filters"));
  };
  const updateSummary = () => {
    renderChips();
    const history = activeView === "history";
    const total = history ? snapshotRows.filter((row) => row.removed).length : conns.length;
    const retentionNote = history ? " (bounded retention: closed endpoints kept for a limited time)" : "";
    summary.textContent = `${fmtInt(rows.length)} of ${fmtInt(total)} ${history ? "retained closed endpoints" : "live endpoints"}` + retentionNote +
      (filterInput.value.trim() ? ` matching "${filterInput.value.trim()}"` : "");
  };

  const handleSort = (key, dir) => {
    sortKey = key;
    sortDir = dir;
    store.set({ netSortKey: key, netSortDir: dir });
    applyFilter();
    recordRecentNetworkView();
  };

  const filterRows = (sourceRows) => {
    const query = parseConnectionQuery(filterInput.value.trim());
    filterStatus.hidden = !query.error;
    filterStatus.textContent = query.error || "";
    if (query.error) filterInput.setAttribute("aria-invalid", "true");
    else filterInput.removeAttribute("aria-invalid");
    const matchesText = query.error ? [] : sourceRows.filter((row) =>
      matchesConnectionQuery(row, query));
    return matchesText.filter((row) => matchesConnectionFilters(row, store.get().networkPredicates || []));
  };
  const applyFilter = () => {
    const sourceRows = activeView === "history" ? snapshotRows.filter((row) => row.removed) : conns;
    filteredRows = filterRows(sourceRows);
    rows = applySort(filteredRows);
    updateSummary();
    if (connectionTableController) connectionTableController.updateSort(sortKey, sortDir);
    if (listeningTableController) listeningTableController.updateSort(sortKey, sortDir);
    refreshActiveView();
  };
  applyFilterNow = applyFilter;

  let connectionTableController = null;
  let listeningTableController = null;
  let firewallView = null;
  let activeView = store.get().networkView || "connections";
  const recentViewSignature = (view) => JSON.stringify({
    query: view.query,
    predicates: view.predicates,
    sortKey: view.sortKey,
    sortDir: view.sortDir,
    tab: view.tab,
    layout: view.layout,
  });
  const recordRecentNetworkView = (includeLayoutOnly = false) => {
    if (restoringNetworkView) return;
    if (!NETWORK_VIEW_TABS.has(activeView)) return;
    const query = filterInput.value.trim();
    if (query.length > 1024 || parseConnectionQuery(query).error) return;
    let predicates;
    try {
      predicates = normalizeConnectionFilters(store.get().networkPredicates || []);
      if (predicates.some((predicate) => !NETWORK_VIEW_FILTER_FIELDS.has(predicate.field))) return;
    } catch {
      return;
    }
    const table = activeView === "listening" ? listeningTableController
      : (activeView === "connections" || activeView === "history") ? connectionTableController : null;
    const view = {
      version: 1,
      query,
      predicates,
      sortKey: sortKey || "",
      sortDir: sortDir || "",
      tab: activeView,
      layout: table?.getLayout?.() || null,
    };
    const meaningful = query || predicates.length || view.sortKey ||
      activeView !== "connections";
    if (!meaningful && !includeLayoutOnly) return;
    const signature = recentViewSignature(view);
    if (recentViews.length && recentViewSignature(recentViews[0]) === signature) return;
    const tabName = activeView === "history" ? "Closed history"
      : activeView === "listening" ? "Listening"
        : activeView === "flows" ? "Flows" : "Connections";
    const description = query || predicates.map(connectionFilterLabel).join(" ") ||
      (view.sortKey ? "Sorted by " + view.sortKey : "Custom layout");
    const name = (tabName + " · " + description +
      (view.sortKey ? " · " + view.sortKey + (view.sortDir === "desc" ? " ↓" : " ↑") : ""))
      .slice(0, 60);
    const existingRecent = recentViews.find((item) => recentViewSignature(item) === signature);
    const recent = {
      ...view,
      id: existingRecent?.id ||
        ("recent-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 8)),
      name,
    };
    recentViews = [recent, ...recentViews.filter((item) =>
      recentViewSignature(item) !== signature)].slice(0, MAX_RECENT_NETWORK_VIEWS);
    renderRecentViewOptions(recent.id);
    try {
      const storage = globalThis.localStorage;
      if (!storage) throw new Error("Browser storage is unavailable");
      storage.setItem(RECENT_NETWORK_VIEWS_KEY, JSON.stringify(recentViews));
    } catch {
      setSavedViewStatus("Recent views are available until this page closes; browser storage is unavailable.");
    }
  };
  const saveTableViewState = (view, controller) => {
    if (!controller?.getViewState) return;
    store.set({
      networkTableStates: {
        ...(store.get().networkTableStates || {}),
        [view]: controller.getViewState(),
      },
    });
  };
  const renderConnectionTable = () => {
    if (connectionTableController) connectionTableController.destroy();
    const allRows = activeView === "history" ? snapshotRows.filter((row) => row.removed) : conns;
    const view = renderConnections(rows, sortKey, sortDir, onSortRef.current, filteredRows,
      filterInput, store, allRows, store.get().networkTableStates?.[activeView] || null, activeView);
    connectionTableController = view._virtualTable || null;
    return view;
  };
  const renderListeningTable = () => {
    if (listeningTableController) listeningTableController.destroy();
    const view = renderListening(rows, sortKey, sortDir, onSortRef.current, store,
      store.get().networkTableStates?.listening || null);
    listeningTableController = view._virtualTable || null;
    return view;
  };
  const onTableLayoutChange = () => {
    if (recentViewTimer !== null) clearTimeout(recentViewTimer);
    recentViewTimer = setTimeout(() => {
      recentViewTimer = null;
      recordRecentNetworkView(true);
    }, 300);
  };
  page.addEventListener("tablelayoutchange", onTableLayoutChange);

  const tabs = createTabs({
    ariaLabel: "Network views",
    initial: store.get().networkView,
    onChange: (id) => {
      if ((activeView === "connections" || activeView === "history") && connectionTableController) {
        saveTableViewState(activeView, connectionTableController);
        connectionTableController.destroy();
        connectionTableController = null;
      }
      if (activeView === "listening" && id !== "listening" && listeningTableController) {
        saveTableViewState(activeView, listeningTableController);
        listeningTableController.destroy();
        listeningTableController = null;
      }
      if (activeView === "blocked" && firewallView) {
        firewallView.destroy();
        firewallView = null;
      }
      activeView = id;
      store.set({ networkView: id });
      const sourceRows = id === "history" ? snapshotRows.filter((row) => row.removed) : conns;
      filteredRows = filterRows(sourceRows);
      rows = applySort(filteredRows);
      updateSummary();
      queueMicrotask(recordRecentNetworkView);
    },
    tabs: [
      { id: "connections", label: "Connections", render: renderConnectionTable },
      { id: "listening", label: "Listening", render: renderListeningTable },
      { id: "history", label: "Closed history (bounded, retained)", render: renderConnectionTable },
        { id: "blocked", label: "Firewall rules", render: () => {
        firewallView = createFirewallInventoryView({
          target: store.get().firewallTarget || null,
          ruleName: store.get().firewallRuleName || null,
          onClearTarget: () => store.set({ firewallTarget: null, firewallRuleName: null }),
        });
        return firewallView.element;
      } },
      { id: "flows", label: "Flows", render: () => renderFlows(rows, geo) },
    ],
  });

  const onSortRef = { current: handleSort };

  function refreshActiveView() {
    const active = tabs.active();
    if ((active === "connections" || active === "history") && connectionTableController) {
      const emptyMessage = filterInput.value.trim() && rows.length === 0
        ? "No endpoints matched the filter."
        : "";
      const allRows = active === "history" ? snapshotRows.filter((row) => row.removed) : conns;
      connectionTableController.updateRows(rows, emptyMessage, { allRows });
    } else if (active === "listening") {
      if (listeningTableController) {
        const listening = rows.filter(isListening);
        listeningTableController.updateRows(listening, "No listening sockets match this view");
        for (const cell of layout.querySelectorAll("[data-exposure-count]")) {
          cell.textContent = fmtInt(listening.filter((row) => exposureOf(row).key === cell.dataset.exposureCount).length);
        }
      } else {
        tabs.select(active, true);
      }
    } else if (active === "flows") {
      tabs.select(active, true);
    }
  }

  layout.append(chips, summary, tabs.element);
  if (activeView === "history") {
    rows = applySort(snapshotRows.filter((row) => row.removed));
  }
  updateSummary();

  page._netUpdate = (nextState) => {
    if (!nextState.lastUpdate) return;
    snapshotRows = Array.isArray(nextState.connections) ? nextState.connections.slice() : [];
    conns = snapshotRows.filter((row) => !row.removed);
    geo = nextState.geoSummary || {};
    const inspectorKey = document.querySelector(".inspector-dialog")?.dataset.inspectorKey || "";
    if (inspectorKey.startsWith("connection:")) {
      const inspected = snapshotRows.find((row) => `connection:${connectionKey(row)}` === inspectorKey);
      updateInspector(inspectorKey, inspected || null, {
        missing: "This connection identity is no longer in the latest endpoint snapshot.",
        status: inspected?.removed ? "This endpoint is closed; showing its retained evidence." : "",
      });
    }
    applyFilter();
  };

  page._netDestroy = () => {
    closeContextMenu();
    closeInspector({ restoreFocus: false });
    if (activeCloseDialog) closeDialog(activeCloseDialog);
    if (activeBlockDialog) closeDialog(activeBlockDialog);
    if (debounce !== null) clearTimeout(debounce);
    savedViewAbort.abort();
    unsubscribeConfig();
    window.removeEventListener("storage", onRecentStorage);
    filterInput.removeEventListener("input", onFilterInput);
    savedViewSelect.removeEventListener("change", onSavedViewChange);
    savedViewSave.removeEventListener("click", onSaveSavedView);
    savedViewDelete.removeEventListener("click", onDeleteSavedView);
    recentViewSelect.removeEventListener("change", onRecentViewChange);
    recentViewClear.removeEventListener("click", onClearRecentViews);
    page.removeEventListener("tablelayoutchange", onTableLayoutChange);
    if (recentViewTimer !== null) clearTimeout(recentViewTimer);
    if (activeView === "connections" || activeView === "history")
      saveTableViewState(activeView, connectionTableController);
    else if (activeView === "listening")
      saveTableViewState(activeView, listeningTableController);
    if (connectionTableController) connectionTableController.destroy();
    if (listeningTableController) listeningTableController.destroy();
    if (firewallView) firewallView.destroy();
    firewallView = null;
    page._netUpdate = null;
    tabs.destroy();
  };
  const destroy = page._netDestroy;
  await tabs.select(tabs.active(), true);
  if (page._netDestroy !== destroy || !page.isConnected) return;
  const pendingInspectorKey = store.get().pendingConnectionInspectorKey;
  if (pendingInspectorKey) {
    store.set({ pendingConnectionInspectorKey: null });
    const target = snapshotRows.find((row) => `connection:${connectionKey(row)}` === pendingInspectorKey && !row.removed);
    if (target) showConnectionDetails(target);
  }
  applyFilter();
}

export function updateNetwork(page, store) {
  if (typeof page._netUpdate === "function") {
    page._netUpdate(store.get());
    return;
  }
  return renderNetwork(page, store);
}

function renderConnections(rows, sortKey, sortDir, onSort, filteredRows, filterInput, store,
  allRows = rows, viewState = null, viewKey = "connections") {
  const host = h("div", { class: "tab-panel-body" });
  let vt = null;
  const exportTimers = new Map();
  const selectionCount = h("span", { class: "selection-count", "aria-live": "polite" });
  const selectionActions = h("div", { class: "selection-actions" });
  const selectionBar = h("div", { class: "selection-bar", hidden: true },
    selectionCount, selectionActions);
  const layoutHost = h("div", { class: "table-layout-host" });
  const container = h("div", { class: "net-table" });
  const selectAllButton = h("button", {
    class: "btn btn-ghost btn-sm",
    type: "button",
    onclick: () => vt?.selectAll(),
  }, "Select all shown");
  const saveSnapshotButton = h("button", {
    class: "btn btn-ghost btn-sm",
    type: "button",
    title: "Save the current filtered endpoint set as a named snapshot",
    onclick: () => {
      const snapshot = { savedAt: new Date().toISOString(), keys: rows.map(connectionKey) };
      localStorage.setItem("wintcp.network.snapshot.v1", JSON.stringify(snapshot));
      setSavedViewStatus(`Snapshot saved with ${snapshot.keys.length} endpoint(s).`);
    },
  }, "Save snapshot");
  const compareSnapshotButton = h("button", {
    class: "btn btn-ghost btn-sm",
    type: "button",
    title: "Compare the current filtered view with the saved snapshot",
    onclick: () => {
      const raw = localStorage.getItem("wintcp.network.snapshot.v1");
      if (!raw) {
        setSavedViewStatus("No saved snapshot. Use Save snapshot first.");
        return;
      }
      let snapshot;
      try { snapshot = JSON.parse(raw); } catch (err) {
        setSavedViewStatus("Saved snapshot is unreadable.");
        return;
      }
      const previous = new Set(Array.isArray(snapshot.keys) ? snapshot.keys : []);
      const current = new Set(rows.map(connectionKey));
      const added = [...current].filter((key) => !previous.has(key));
      const removed = [...previous].filter((key) => !current.has(key));
      const d = dialog({ class: "details-dialog action-preview-dialog", "aria-labelledby": "snapshot-compare-title" },
        dialogHeader({},
          dialogTitle({ id: "snapshot-compare-title" }, "Snapshot comparison"),
          dialogDescription({}, `${snapshot.savedAt || "saved snapshot"} to ${new Date().toISOString()}`)),
        dialogContent({},
          h("p", {}, `Added endpoints: ${added.length}`),
          h("p", {}, `Removed endpoints: ${removed.length}`),
          h("p", { class: "muted text-sm" }, "Counts use exact connection identity. Review the current filtered table for details."),
        ),
        dialogFooter({},
          h("button", { type: "button", class: "btn btn-primary", onclick: () => closeDialog(d) }, "Close")),
      );
      openDialog(d);
    },
  }, "Compare snapshot");
  const selectionHeader = h("div", { class: "selection-header" },
    selectAllButton,
    saveSnapshotButton,
    compareSnapshotButton,
    h("span", { class: "muted text-sm" },
      "Ctrl/Command-click toggles a row; Shift-click selects a range; use Select all shown for every visible row."));
  const clearSelectionButton = h("button", {
    class: "btn btn-ghost btn-sm",
    type: "button",
    onclick: () => vt?.clearSelection(),
  }, "Clear selection");
  const copyRemoteButton = h("button", {
    class: "btn btn-ghost btn-sm",
    type: "button",
    onclick: () => copySelected("remote IP addresses", remoteIpValue),
  }, "Copy remote IPs");
  const copyHostButton = h("button", {
    class: "btn btn-ghost btn-sm",
    type: "button",
    onclick: () => copySelected("hostnames", remoteHostnameValue),
  }, "Copy hostnames");
  const copyEndpointButton = h("button", {
    class: "btn btn-ghost btn-sm",
    type: "button",
    onclick: () => copySelected("endpoints", remoteEndpointValue),
  }, "Copy endpoints");
  const copyRowsButton = h("button", {
    class: "btn btn-ghost btn-sm",
    type: "button",
    onclick: () => {
      const text = connectionRowsTsv(vt?.getSelectedRows() || [],
        vt?.getVisibleColumns());
      if (text) copyText(text, "connection rows");
    },
  }, "Copy selected rows");
  const exportRowsButton = h("button", {
    class: "btn btn-ghost btn-sm",
    type: "button",
    title: "Export selected rows that are still present in this table",
    onclick: () => {
      const selectedRows = vt?.getCurrentSelectedRows() || [];
      const text = connectionRowsTsv(selectedRows, vt?.getVisibleColumns());
      if (!text) return;
      const blob = new Blob([text], { type: "text/tab-separated-values;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const link = h("a", { href: url, download: `wintcp-connections-${new Date().toISOString().replace(/[:.]/g, "-")}.tsv` });
      document.body.append(link);
      link.click();
      link.remove();
      const timer = window.setTimeout(() => {
        URL.revokeObjectURL(url);
        exportTimers.delete(timer);
      }, 1000);
      exportTimers.set(timer, url);
    },
  }, "Export selected rows (TSV)");
  const exportJsonButton = h("button", {
    class: "btn btn-ghost btn-sm",
    type: "button",
    title: "Export selected rows as JSON evidence",
    onclick: () => {
      const selectedRows = vt?.getCurrentSelectedRows() || [];
      if (!selectedRows.length) return;
      const payload = {
        exportedAt: new Date().toISOString(),
        rowCount: selectedRows.length,
        rows: selectedRows,
      };
      const text = JSON.stringify(payload, null, 2);
      const blob = new Blob([text], { type: "application/json;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const link = h("a", { href: url, download: `wintcp-connections-${new Date().toISOString().replace(/[:.]/g, "-")}.json` });
      document.body.append(link);
      link.click();
      link.remove();
      const timer = window.setTimeout(() => {
        URL.revokeObjectURL(url);
        exportTimers.delete(timer);
      }, 1000);
      exportTimers.set(timer, url);
    },
  }, "Export selected rows (JSON)");
  const copyIncidentSummaryButton = h("button", {
    class: "btn btn-ghost btn-sm",
    type: "button",
    title: "Copy a concise incident summary for the selected rows",
    onclick: () => {
      const selectedRows = vt?.getCurrentSelectedRows() || [];
      if (!selectedRows.length) return;
      const filter = store.get().networkFilter || "";
      const predicates = store.get().networkPredicates || [];
      const lines = [
        `WinTCP incident summary`,
        `Exported: ${new Date().toISOString()}`,
        `Selected rows: ${selectedRows.length} of ${rows.length} visible`,
        `Filter: ${filter || "(none)"}`,
        `Predicates: ${predicates.length ? predicates.map((p) => p.field + ":" + p.value).join(", ") : "(none)"}`,
        `Snapshot age: ${store.get().lastUpdate ? new Date(store.get().lastUpdate).toISOString() : "unknown"}`,
        `Unknown values are shown as “—” and are not zero or measured values.`,
      ];
      copyText(lines.join("\\n"), "incident summary");
    },
  }, "Copy incident summary");
  const copyVpnExceptionButton = h("button", {
    class: "btn btn-ghost btn-sm",
    type: "button",
    title: "Copy unique remote IPs and observed hostnames for VPN exceptions",
    onclick: () => {
      const selectedRows = vt?.getCurrentSelectedRows() || [];
      if (!selectedRows.length) return;
      const ips = copyValues(selectedRows, remoteIpValue);
      const hosts = copyValues(selectedRows, remoteHostnameValue);
      const lines = [
        "WinTCP VPN exception data",
        `Observed: ${new Date().toISOString()}`,
        "",
        "Unique remote IPs:",
        ...(ips.length ? ips : ["(none)"]),
        "",
        "Observed hostnames (reverse DNS estimates):",
        ...(hosts.length ? hosts : ["(none)"]),
        "",
        "Reverse DNS is an estimate; WinTCP does not invent domains or subnets.",
      ];
      copyText(lines.join("\\n"), "VPN exception data");
    },
  }, "Copy VPN exception data");
  const clearHistoryButton = h("button", {
    class: "btn btn-sm btn-quiet",
    type: "button",
    onclick: () => {
      if (store) {
        store.set({ automationDraft: null, networkPredicates: [], networkFilter: "" });
        filterInput.value = "";
        applyFilter();
      }
    },
    title: "Clear retained history filter and reset to all live endpoints",
  }, "Reset to live view");
  selectionActions.append(clearSelectionButton, clearHistoryButton, copyRemoteButton,
    copyHostButton, copyEndpointButton, copyRowsButton, exportRowsButton, exportJsonButton,
    copyIncidentSummaryButton, copyVpnExceptionButton);
  const updateSelection = ({ rows: selected, selectedCount, visibleCount, hiddenCount, staleCount }) => {
    selectionBar.hidden = selectedCount === 0;
    const details = [];
    if (visibleCount > 0) details.push(`${visibleCount} shown`);
    if (hiddenCount > 0) details.push(`${hiddenCount} outside the filter`);
    if (staleCount > 0) details.push(`${staleCount} no longer current; copies use last seen data`);
    selectionCount.textContent = `${selectedCount} selected${details.length ? ` · ${details.join(" · ")}` : ""}`;
    clearSelectionButton.disabled = selectedCount === 0;
    copyRemoteButton.disabled = !copyValues(selected, remoteIpValue);
    copyHostButton.disabled = !copyValues(selected, remoteHostnameValue);
    copyEndpointButton.disabled = !copyValues(selected, remoteEndpointValue);
    copyRowsButton.disabled = selectedCount === 0;
    exportRowsButton.disabled = !vt?.getCurrentSelectedRows().length;
  exportJsonButton.disabled = !vt?.getCurrentSelectedRows().length;
  copyIncidentSummaryButton.disabled = !vt?.getCurrentSelectedRows().length;
  copyVpnExceptionButton.disabled = !vt?.getCurrentSelectedRows().length;
  };
  function copySelected(label, select) {
    const text = copyValues(vt?.getSelectedRows() || [], select);
    if (text) copyText(text, label);
  }
  host.append(selectionHeader, selectionBar, layoutHost, container);

  const emptyMsg = filterInput.value.trim().length > 0 && rows.length === 0
    ? "No endpoints matched the filter."
    : "";

  vt = createVirtualTable(container, {
    columns: [
      { key: "process", label: "Process", width: 2, sortable: true },
      { key: "pid", label: "PID", width: 0.7, sortable: true },
      { key: "proto", label: "Proto", width: 0.8, sortable: true },
      { key: "local", label: "Local address", width: 1.6, sortable: true },
      { key: "lport", label: "Local port", width: 0.8, align: "right", sortable: true },
      { key: "remote", label: "Remote address", width: 1.6, sortable: true },
      { key: "rport", label: "Remote port", width: 0.8, align: "right", sortable: true },
      { key: "hostname", label: "Hostname", width: 1.6, sortable: true },
      { key: "state", label: "State", width: 1, sortable: true },
      { key: "country", label: "Country", width: 0.8, sortable: true },
      {
        key: "actions",
        label: "Actions",
        actions: true,
        width: 1,
        sortable: false,
        renderCell: (row) => renderConnActions(host, row, () => vt?.getVisibleColumns(), store),
      },
    ],
    rowHeight: 34,
    height: 520,
    minWidth: "84rem",
    scrollTop: viewState?.scrollTop ?? store.get().networkTableScrollTop ?? 0,
    onScroll: (scrollTop) => {
      const states = store.get().networkTableStates || {};
      store.set({
        networkTableScrollTop: scrollTop,
        networkTableStates: { ...states, [viewKey]: { ...(states[viewKey] || {}), scrollTop } },
      });
    },
    rowKey: connectionKey,
    multiSelect: true,
    onSelectionChange: updateSelection,
    label: "Open TCP and UDP endpoints",
    emptyMessage: emptyMsg,
    sortKey,
    sortDir,
    onSort,
    onRowClick: (row) => showConnectionDetails(row),
    onRowContextMenu: (row, event, anchor) => connectionMenu(row, { event, anchor, store, onDetails: showConnectionDetails, onClose: showConnectionClosePreview, onBlock: showBlockPeerPreview, onBlockApplication: showApplicationBlockPreview, onBlockApplicationPeer: showApplicationPeerBlockPreview, onBlockServicePeer: showServicePeerBlockPreview, onCloseAndBlock: showCloseAndBlockPreview, blockReason: blockPeerReason(row), serializeRow: (target) => connectionRowsTsv([target], vt.getVisibleColumns()) }),
    format: { hostname: (row) => hostnameLabel(row.hostname) },
  });
  const layoutControls = createColumnLayoutControls(vt, {
    layoutKey: "network",
    required: ["process", "pid", "actions"],
    compactHidden: ["rport", "hostname", "country"],
  });
  vt.applySavedLayout = layoutControls.applySavedLayout;
  const tableDestroy = vt.destroy;
  vt.destroy = () => {
    for (const [timer, url] of exportTimers) {
      window.clearTimeout(timer);
      URL.revokeObjectURL(url);
    }
    exportTimers.clear();
    layoutControls.destroy();
    tableDestroy();
  };
  layoutHost.append(layoutControls.element);
  host._virtualTable = vt;
  vt.updateRows(rows, undefined, { allRows });
  if (viewState) vt.restoreViewState(viewState);

  host.append(h("p", { class: "muted text-sm proc-note" },
    "Per-connection traffic counters are unavailable in the Web UI. Use the desktop application or CLI for connection-level traffic measurements."));
  return host;
}

function renderConnActions(host, row, visibleColumns, store) {
  const wrap = h("div", { class: "row-actions", style: "display: flex; gap: 0.25rem; justify-content: flex-end;" });
  const hasRemote = !row.removed && row.remote && String(row.remote) !== "0.0.0.0" && String(row.remote) !== "*" && row.rport;

  wrap.append(
    h("button", {
      class: "btn btn-ghost btn-sm",
      type: "button",
      "aria-label": "Connection actions",
      "aria-haspopup": "menu",
      title: "Connection actions (right-click or Shift+F10)",
      onclick: (event) => {
        event.stopPropagation();
        connectionMenu(row, { event, anchor: event.currentTarget, store, onDetails: showConnectionDetails, onClose: showConnectionClosePreview, onBlock: showBlockPeerPreview, onBlockApplication: showApplicationBlockPreview, onBlockApplicationPeer: showApplicationPeerBlockPreview, onBlockServicePeer: showServicePeerBlockPreview, onCloseAndBlock: showCloseAndBlockPreview, blockReason: blockPeerReason(row), serializeRow: (target) => connectionRowsTsv([target], visibleColumns?.()) });
      },
    }, "⋯"),
    h("button", {
      class: "btn btn-ghost btn-icon btn-xs",
      type: "button",
      title: "Details",
      onclick: (e) => { e.stopPropagation(); showConnectionDetails(row); },
    }, icon("info", 14)),
  );

  if (hasRemote) {
    const blockReason = blockPeerReason(row);
    wrap.append(
      h("button", {
        class: "btn btn-ghost btn-icon btn-xs",
        type: "button",
        "aria-label": "Block remote peer",
        title: blockReason || `Review TCP block for ${row.remote}:${row.rport}`,
        disabled: Boolean(blockReason),
        onclick: (e) => { e.stopPropagation(); showBlockPeerPreview(row); },
      }, icon("shield", 14)),
    );
  }

  return wrap;
}

function isListening(row) {
  return !row.removed && (String(row.state || "").toUpperCase() === "LISTENING" ||
    String(row.proto || "").toUpperCase().startsWith("UDP"));
}

function renderListening(rows, sortKey, sortDir, onSort, store, viewState = null) {
  const host = h("div", { class: "tab-panel-body" });
  const layoutHost = h("div", { class: "table-layout-host" });
  const listening = rows.filter(isListening);

  // P3-06 focused port-owner input
  const portInput = h("input", {
    class: "input input-sm",
    type: "text",
    placeholder: "Port (e.g. 443) — find listening socket owner",
    "aria-label": "Find which process owns a listening port",
    maxlength: "5",
  });
  const portResult = h("div", { class: "port-owner-summary", hidden: true });
  const portSearchRow = h("div", { class: "port-owner-search" },
    h("label", { for: portInput.id || "port-owner-input" }, h("strong", {}, "Port owner"),
      h("span", { class: "muted text-xs" }, "Find the process, interface and rules for a listening port")),
    portInput,
    portResult,
  );
  portInput.id = portInput.id || "port-owner-input-" + Math.random().toString(36).slice(2);
  portInput.addEventListener("input", () => {
    const val = String(portInput.value || "").trim();
    if (!/^\d{1,5}$/.test(val)) { portResult.hidden = true; return; }
    const portNum = parseInt(val, 10);
    if (portNum < 1 || portNum > 65535) { portResult.hidden = true; return; }
    const matches = listening.filter((r) => Number(r.lport) === portNum);
    if (matches.length === 0) {
      portResult.hidden = false;
      portResult.innerHTML = "";
      portResult.append(
        h("p", { class: "muted text-sm" }, `No listening socket found for port ${portNum}. Check the current filter and that the service is running.`),
        h("button", { type: "button", class: "btn btn-sm btn-quiet", onclick: () => {
          document.dispatchEvent(new CustomEvent("wintcp:firewall-investigate", {
            detail: { target: { direction: "Inbound", proto: "TCP", local: null, lport: portNum, remote: null, rport: null, path: null, service: null } },
          }));
        } }, "Investigate firewall rules for this port"),
      );
      return;
    }
    const first = matches[0];
    const exposureLabel = exposureOf(first).label;
    const exposureHint = exposureOf(first).hint;
    portResult.hidden = false;
    portResult.innerHTML = "";
    portResult.append(
      h("div", { class: "card card-compact" },
        h("div", { class: "card-header" },
          h("h4", {}, `Port ${portNum}`),
          h("span", { class: "badge badge-secondary" }, exposureLabel),
        ),
        h("div", { class: "card-content" },
          h("p", { class: "muted text-sm" }, `Protocol: ${first.proto || "—"} · Bind: ${first.local || first.localAddress || "—"} · Process: ${first.process || first.processName || "—"} (PID ${first.pid ?? "—"})`),
          h("p", { class: "muted text-sm", title: exposureHint }, `Exposure: ${exposureLabel} — ${exposureHint}`),
        ),
        h("div", { class: "card-footer" },
          h("button", { type: "button", class: "btn btn-sm btn-quiet", onclick: () => { if (first) showConnectionDetails(first); } }, "Connection details"),
          h("button", { type: "button", class: "btn btn-sm btn-quiet", onclick: () => {
            if (store) {
              store.set({ automationDraft: {
                name: `Port ${portNum} owner`,
                source: `# Listening port ${portNum}\n# Protocol ${first.proto || ""}\n# Process ${first.process || first.processName || ""}\n# PID ${first.pid ?? ""}\n`,
              } });
              window.location.hash = "#/automations";
            }
          } }, "Create automation for this port"),
          h("button", { type: "button", class: "btn btn-sm btn-quiet", onclick: () => {
            document.dispatchEvent(new CustomEvent("wintcp:firewall-investigate", {
              detail: { target: {
                direction: "Inbound",
                proto: first.proto || "TCP",
                local: first.local || first.localAddress || null,
                lport: Number(first.lport) || portNum,
                remote: null,
                rport: null,
                path: first.path || null,
                service: first.service || null,
              } },
            }));
          } }, "Find inbound firewall rules"),
        ),
      ),
    );
  });
  host.append(portSearchRow);

  if (listening.length === 0) {
    return emptyState({}, "No listening sockets",
      "Nothing in this filter is bound to an address.");
  }

  const buckets = { wildcard: [], private: [], specific: [], loopback: [] };
  for (const row of listening) buckets[exposureOf(row).key].push(row);

  const counts = h("div", { class: "exposure-grid" });
  for (const [key, label, hint] of [
    ["wildcard", "All interfaces", "firewall and routing determine reachability"],
    ["private", "Private / link-local", "bound to one private or link-local address"],
    ["specific", "Specific address", "bound to one address"],
    ["loopback", "Loopback", "this machine only"],
  ]) {
    counts.append(h("div", { class: "exposure-cell", title: hint },
      h("div", { class: "exposure-value num", dataset: { exposureCount: key } }, fmtInt(buckets[key].length)),
      h("div", { class: "exposure-label" }, label),
    ));
  }

  const container = h("div", { class: "net-table" });
  const vt = createVirtualTable(container, {
    columns: [
      { key: "exposure", label: "Exposure", width: 1.2, sortable: true, renderCell: (row) => h("span", { title: exposureOf(row).hint }, exposureOf(row).label) },
      { key: "process", label: "Process", width: 2, sortable: true },
      { key: "pid", label: "PID", width: 0.7, sortable: true },
      { key: "proto", label: "Proto", width: 0.8, sortable: true },
      { key: "local", label: "Bound address", width: 2, sortable: true },
      { key: "lport", label: "Port", width: 0.7, align: "right", sortable: true },
      {
        key: "actions",
        label: "Actions",
        actions: true,
        width: 0.8,
        sortable: false,
        renderCell: (row) => renderListeningActions(row, () => vt?.getVisibleColumns(), store),
      },
    ],
    rowHeight: 34,
    height: 440,
    minWidth: "58rem",
    scrollTop: viewState?.scrollTop ?? store.get().networkListeningScrollTop ?? 0,
    onScroll: (scrollTop) => {
      const states = store.get().networkTableStates || {};
      store.set({
        networkListeningScrollTop: scrollTop,
        networkTableStates: { ...states, listening: { ...(states.listening || {}), scrollTop } },
      });
    },
    rowKey: connectionKey,
    label: "Listening sockets by exposure",
    emptyMessage: "No listening sockets",
    sortKey,
    sortDir,
    onSort,
    onRowClick: (row) => showConnectionDetails(row),
    onRowContextMenu: (row, event, anchor) => connectionMenu(row, { event, anchor, store, onDetails: showConnectionDetails, onClose: showConnectionClosePreview, onBlock: showBlockPeerPreview, onCloseAndBlock: showCloseAndBlockPreview, blockReason: blockPeerReason(row), serializeRow: (target) => connectionRowsTsv([target], vt.getVisibleColumns()) }),
  });
  vt.applySavedLayout = (next) => {
    if (!next || next.version !== 1) return false;
    vt.setLayout(next);
    return true;
  };
  const layoutControls = createColumnLayoutControls(vt, {
    layoutKey: "network-listening",
    required: ["process", "pid", "proto", "local", "lport", "actions"],
    compactHidden: ["exposure", "pid"],
  });
  const tableDestroy = vt.destroy;
  vt.destroy = () => { layoutControls.destroy(); tableDestroy(); };
  layoutHost.append(layoutControls.element);
  host._virtualTable = vt;
  vt.updateRows(listening);
  if (viewState) vt.restoreViewState(viewState);

  host.append(layoutHost, counts, h("div", { class: "section-gap" }), container);
  host.append(h("p", { class: "muted text-sm proc-note" },
    "Binding describes where a socket listens. Firewall policy and routing also determine reachability."));
  return host;
}

function renderListeningActions(row, visibleColumns, store) {
  const wrap = h("div", { class: "row-actions", style: "display: flex; gap: 0.25rem; justify-content: flex-end;" });
  wrap.append(
    h("button", {
      class: "btn btn-ghost btn-sm", type: "button", "aria-label": "Connection actions", "aria-haspopup": "menu",
      onclick: (event) => {
        event.stopPropagation();
        connectionMenu(row, { event, anchor: event.currentTarget, store, onDetails: showConnectionDetails, onClose: showConnectionClosePreview, onBlock: showBlockPeerPreview, onCloseAndBlock: showCloseAndBlockPreview, blockReason: blockPeerReason(row), serializeRow: (target) => connectionRowsTsv([target], visibleColumns?.()) });
      },
    }, "⋯"),
    h("button", {
      class: "btn btn-ghost btn-icon btn-xs",
      type: "button",
      title: "Details",
      onclick: () => showConnectionDetails(row),
    }, icon("info", 14)),
  );
  return wrap;
}

function renderFlows(rows, geo) {
  const host = h("div", { class: "tab-panel-body" });
  const configured = geo.geoIpConfigured === true;
  const remoteRows = rows.filter((row) => !row.removed &&
    String(row.state || "").toUpperCase() !== "LISTENING" &&
    row.remote && !["*", "0.0.0.0", "::", UNAVAILABLE].includes(String(row.remote)) &&
    num(row.rport) !== null);

  if (!configured) {
    return h("div", { class: "flow-empty" },
      emptyState({}, "No GeoIP database installed",
        "Flows group remote peers by country, which needs a MaxMind GeoLite2 " +
        "database. WinTCP ships none: a .mmdb is licensed data, and fetching one " +
        "at run time would break the offline requirement."),
      h("p", { class: "muted text-sm" },
        `${fmtInt(remoteRows.length)} remote peers are in the current filtered live view.`),
      h("p", { class: "muted text-sm" },
        "Set a database path in Settings once you have one; the Map page and this " +
        "tab pick it up with no restart."),
    );
  }

  const countryCounts = new Map();
  for (const row of remoteRows) {
    const code = String(row.country || "").trim().toUpperCase();
    if (/^[A-Z]{2}$/.test(code)) countryCounts.set(code, (countryCounts.get(code) || 0) + 1);
  }
  const entries = [...countryCounts]
    .map(([code, count]) => ({ code, count }))
    .sort((a, b) => b.count - a.count);

  if (entries.length === 0) {
    return emptyState({}, "No remote peers resolved",
      `A database is configured, but none of the ${fmtInt(remoteRows.length)} remote peers in this filtered live view has a country match.`);
  }

  const list = h("div", { class: "bar-list" });
  const max = entries[0].count;
  for (const entry of entries.slice(0, 24)) {
    list.append(h("div", { class: "bar-row" },
      h("span", { class: "bar-label", title: `${entry.code} (${entry.count} peers)` }, entry.code),
      h("span", { class: "bar-track", "aria-hidden": "true" },
        h("span", { class: "bar-fill", style: `width:${((entry.count / max) * 100).toFixed(1)}%` }),
      ),
      h("span", { class: "bar-value num" }, fmtInt(entry.count)),
    ));
  }
  host.append(card({},
    cardHeader({},
      cardTitle({}, "Remote peers by country"),
    ),
    cardContent({}, list),
    cardFooter({}, h("span", { class: "muted text-sm" },
      "Connection count, not bandwidth: per-socket byte counters are not collected here.")),
  ));
  return host;
}

function showConnectionDetails(row) {
  const remote = row.remote || row.remoteAddress;
  const canOfferBlock = remote && String(remote) !== "0.0.0.0" &&
    String(remote) !== "*" && row.rport;
  const blockReason = blockPeerReason(row);
  const key = `connection:${connectionKey(row)}`;
  const inspector = openInspector({
    key, title: "Connection details", subject: "connection identity", row,
    opener: document.activeElement,
    sections: (current) => connectionInspectorSections(current || row),
    actions: (current) => [
      { label: "Related firewall rules", onClick: () => {
        closeInspector({ restoreFocus: false });
        openFirewallRuleResult("", current || row);
      } },
      ...(canOfferBlock ? [{
        label: "Review TCP peer block", className: "btn btn-destructive btn-sm",
        disabled: Boolean(blockReason),
        title: blockReason || "Review an outbound TCP peer rule; this does not close the connection.",
        onClick: () => {
          closeInspector({ restoreFocus: false });
          showBlockPeerPreview(current || row);
        },
      }] : []),
    ],
  });
  inspector.dataset.detailsRow = "net";
}

function connectionInspectorSections(row) {
  const known = (value) => value != null && value !== "" && value !== UNAVAILABLE;
  const field = (label, value, options = {}) => {
    const source = Object.prototype.hasOwnProperty.call(options, "copyValue")
      ? options.copyValue : value;
    const { copy = true, copyValue, ...metadata } = options;
    return { label, value, copyValue: copy && known(source) ? String(source) : null, ...metadata };
  };
  const local = row.local || row.localAddress;
  const remote = row.remote || row.remoteAddress;
  const hostname = resolvedHostname(row.hostname);
  const rx = row.socketRxBytesExact ?? row.socketRxBytes;
  const tx = row.socketTxBytesExact ?? row.socketTxBytes;
  return [
    { title: "Identity", fields: [
      field("Process", row.process || row.processName),
      field("PID", row.pid, { mono: true }),
      field("Process identity", formatProcessInstance(row.processInstanceId, row.pid), {
        copyValue: row.processInstanceId, reason: row.processInstanceId
          ? "Verified using the PID and process creation time; this prevents PID-reuse mistakes."
          : "Process creation time is unknown, so the owner cannot be verified by lifetime." }),
      field("Executable path", row.path, { mono: true,
        reason: row.path ? "" : "Windows did not provide a readable image path." }),
      field("Service", row.service, { reason: row.service ? "" : "No service attribution is available for this endpoint." }),
      field("Snapshot state", row.removed ? "Closed — retained history" : "Live endpoint", { copy: false }),
    ] },
    { title: "Endpoints", fields: [
      field("Protocol", row.proto),
      field("Local endpoint", known(local) ? endpoint(local, row.lport) : null,
        { mono: true, copyValue: known(local) ? endpoint(local, row.lport) : null }),
      field("Remote endpoint", known(remote) ? endpoint(remote, row.rport) : null,
        { mono: true, copyValue: known(remote) && remote !== "*" ? endpoint(remote, row.rport) : null }),
      field("DNS / reverse name", hostnameLabel(row.hostname), { copyValue: hostname,
        reason: hostname ? "Reverse DNS is an estimate and may not name the application." : "No resolved reverse name is currently available." }),
      field("Country estimate", row.country, { copy: false,
        reason: row.country ? "GeoIP is a country-level estimate, not a precise IP location." : "No country estimate is available." }),
      field("State", row.state),
    ] },
    { title: "Activity", fields: [
      field("First-observed duration", row.duration, { copy: false,
        reason: "Duration begins when WinTCP first observed this tuple; it is not the kernel socket creation time." }),
      field("Last observed", null, { copy: false,
        reason: "The Web API does not expose a per-row last-observed timestamp." }),
      field("Received bytes", known(rx) ? fmtBytes(rx) : null, { copy: false,
        reason: known(rx) ? "Cumulative total, not a rate." : "Per-connection receive counters are unavailable in this snapshot." }),
      field("Sent bytes", known(tx) ? fmtBytes(tx) : null, { copy: false,
        reason: known(tx) ? "Cumulative total, not a rate." : "Per-connection send counters are unavailable in this snapshot." }),
      field("TCP round-trip time", row.rttMs != null ? `${row.rttMs} ms` : null, { copy: false }),
      field("Retransmitted bytes", row.retransBytes != null ? fmtBytes(row.retransBytes) : null, { copy: false }),
    ] },
    { title: "Rules", fields: [
      field("Firewall interpretation", "Candidate rules do not prove effective reachability.", { copy: false }),
    ] },
  ];
}

function showConnectionClosePreview(row) {
  if (activeCloseDialog) closeDialog(activeCloseDialog);
  const status = h("p", { class: "dialog-description", role: "status", "aria-live": "polite" },
    "Checking the captured endpoint…");
  const snapshotAge = h("dd", {}, "Checking…");
  const elevation = h("dd", {}, "Checking…");
  const actionButton = h("button", {
    type: "button", class: "btn btn-destructive btn-sm", disabled: true,
  }, "Close connection");
  const footer = h("div", { class: "dialog-footer" },
    h("button", { type: "button", class: "btn btn-outline btn-sm", onclick: () => closeDialog(d) }, "Cancel"));
  const d = dialog({ class: "details-dialog action-preview-dialog", "aria-labelledby": "close-preview-title" },
    h("form", { method: "dialog", class: "dialog-form" },
      h("div", { class: "dialog-header" },
        h("h2", { id: "close-preview-title", class: "dialog-title" }, "Review connection close"),
        h("button", { type: "submit", class: "btn btn-close btn-sm", "aria-label": "Close" }, "Close")),
      h("div", { class: "dialog-content" },
        status,
        h("dl", { class: "detail-list" },
          detailEntry("Process", row.process || row.processName || UNAVAILABLE),
          detailEntry("PID", row.pid ?? UNAVAILABLE),
          detailEntry("Process instance", row.processInstanceId || "Lifetime unknown"),
          detailEntry("Protocol", row.proto || UNAVAILABLE),
          detailEntry("Local", endpoint(row.local || row.localAddress, row.lport)),
          detailEntry("Remote", endpoint(row.remote || row.remoteAddress, row.rport)),
          detailEntry("State", row.state || UNAVAILABLE),
          detailEntry("Snapshot age", snapshotAge),
          detailEntry("Elevation", elevation)),
        h("p", { class: "muted text-sm" },
          "The application may reconnect after this endpoint closes. The server rechecks the exact endpoint and process lifetime before acting.")),
      footer));
  let requestController = new AbortController();
  activeCloseDialog = d;
  d.addEventListener("close", () => {
    requestController.abort();
    if (activeCloseDialog === d) activeCloseDialog = null;
  }, { once: true });
  document.body.append(d);
  openDialog(d);

  const target = connectionCloseTarget(row);
  if (!/^\d+$/.test(target.idExact)) {
    status.textContent = "This endpoint has no exact server identity. Refresh the Network page before trying again.";
    snapshotAge.textContent = "Unavailable";
    elevation.textContent = "Unavailable";
    return;
  }

  api.post("/api/connections/action/preview", target, { signal: requestController.signal })
    .then((preview) => {
      if (!d.isConnected) return;
      snapshotAge.textContent = preview.snapshotKnown
        ? String(Math.max(0, Math.round(preview.snapshotAgeMs / 1000))) + " seconds"
        : "Unknown";
      elevation.textContent = preview.requiresElevation === true
        ? "Elevated WinTCP process required"
        : preview.requiresElevation === false ? "Not required" : "Unknown";
      if (!preview.canExecute) {
        status.textContent = preview.reason || "This endpoint cannot be closed.";
        return;
      }
      if (!preview.nonce) {
        status.textContent = "A one-time close preview could not be created. Refresh the endpoint and retry.";
        return;
      }
      status.textContent = "The exact endpoint is eligible for close. The preview expires in " +
        String(Math.ceil(preview.expiresInMs / 1000)) + " seconds.";
      actionButton.disabled = false;
      actionButton.onclick = async () => {
        actionButton.disabled = true;
        status.textContent = "Rechecking the endpoint and closing it…";
        try {
          const result = await api.post("/api/connections/action/execute",
            { nonce: preview.nonce }, { signal: requestController.signal });
          if (!d.isConnected) return;
          status.textContent = result.ok
            ? "The captured connection was closed. The application may create another connection."
            : result.connection?.reason || "The connection could not be closed.";
          actionButton.remove();
        } catch (error) {
          if (!d.isConnected || error.name === "AbortError") return;
          status.textContent = error.message;
          actionButton.remove();
        }
      };
      footer.insertBefore(actionButton, footer.firstChild);
    })
    .catch((error) => {
      if (!d.isConnected || error.name === "AbortError") return;
      status.textContent = error.message;
      snapshotAge.textContent = "Unavailable";
      elevation.textContent = "Unavailable";
    });
}

function connectionCloseTarget(row) {
  return {
    idExact: String(row.idExact ?? ""),
    processInstanceId: String(row.processInstanceId ?? ""),
    pid: String(row.pid ?? ""),
    proto: String(row.proto ?? ""),
    local: String(row.local || row.localAddress || ""),
    lport: String(row.lport ?? ""),
    remote: String(row.remote || row.remoteAddress || ""),
    rport: String(row.rport ?? ""),
    state: String(row.state ?? ""),
  };
}

function showCloseAndBlockPreview(row) {
  if (activeCloseDialog) closeDialog(activeCloseDialog);
  if (activeBlockDialog) closeDialog(activeBlockDialog);
  const address = row.remote || row.remoteAddress;
  const port = row.rport;
  const controller = new AbortController();
  const status = h("p", { class: "dialog-description", role: "status", "aria-live": "polite" }, "Preparing both action previews…");
  const firewallStatus = h("p", { class: "muted text-sm", role: "status" }, "Firewall rule: checking…");
  const closeStatus = h("p", { class: "muted text-sm", role: "status" }, "Connection close: checking…");
  const plan = h("pre", { class: "muted text-sm" });
  const execute = h("button", { class: "btn btn-destructive btn-sm", type: "button", disabled: true }, "Create rule, then close");
  const cancel = h("button", { class: "btn btn-outline btn-sm", type: "button", onclick: () => closeDialog(view) }, "Cancel");
  const footer = h("div", { class: "dialog-footer" }, cancel);
  const view = dialog({ class: "details-dialog action-preview-dialog", "aria-labelledby": "close-block-review-title" },
    h("form", { method: "dialog", class: "dialog-form" },
      h("div", { class: "dialog-header" },
        h("h2", { id: "close-block-review-title", class: "dialog-title" }, "Review close and block"),
        h("button", { type: "submit", class: "btn btn-close btn-sm", "aria-label": "Close" }, "Close")),
      h("div", { class: "dialog-content" }, status,
        h("dl", { class: "detail-list" },
          detailEntry("Process", row.process || row.processName || UNAVAILABLE),
          detailEntry("PID", row.pid ?? UNAVAILABLE),
          detailEntry("Process instance", row.processInstanceId || "Lifetime unknown"),
          detailEntry("Protocol", row.proto || UNAVAILABLE),
          detailEntry("Local", endpoint(row.local || row.localAddress, row.lport)),
          detailEntry("Remote", endpoint(address, port)),
          detailEntry("State", row.state || UNAVAILABLE)),
        h("p", { class: "muted text-sm" },
          "The firewall rule applies to outbound TCP traffic for this remote IP and port; it is not scoped to this process. Rule creation and connection close are separate operations. The rule is attempted first; closing is still attempted if rule creation fails."),
        firewallStatus, closeStatus, plan),
      footer));
  let blockNonce = "";
  let blockRuleName = "";
  let closeNonce = "";
  let executing = false;
  activeBlockDialog = view;
  view.addEventListener("close", () => {
    controller.abort();
    if (activeBlockDialog === view) activeBlockDialog = null;
  }, { once: true });
  view.addEventListener("cancel", (event) => { if (executing) event.preventDefault(); });
  document.body.append(view);
  openDialog(view);
  const blockReason = blockPeerReason(row);
  if (blockReason) {
    status.textContent = blockReason;
    firewallStatus.textContent = `Firewall rule: unavailable — ${blockReason}`;
    return;
  }
  const target = connectionCloseTarget(row);
  if (!/^\d+$/.test(target.idExact)) {
    closeStatus.textContent = "Connection close: unavailable — no exact server identity";
    return;
  }
  Promise.allSettled([
    api.postForm("/api/block/preview", { address, port: String(port) }, { signal: controller.signal }),
    api.post("/api/connections/action/preview", target, { signal: controller.signal }),
  ]).then(([blockPreviewResult, closePreviewResult]) => {
    if (!view.isConnected) return;
    if (blockPreviewResult.status === "fulfilled" && blockPreviewResult.value.nonce) {
      blockNonce = blockPreviewResult.value.nonce;
      blockRuleName = blockPreviewResult.value.ruleName || "";
      firewallStatus.textContent = "Firewall rule: preview ready for outbound TCP peer scope.";
      plan.textContent = blockPreviewResult.value.plan || "The server did not provide a textual firewall plan.";
    } else {
      firewallStatus.textContent = `Firewall rule: unavailable — ${blockPreviewResult.status === "rejected" ? blockPreviewResult.reason.message : blockPreviewResult.value.reason || "preview token missing"}`;
    }
    if (closePreviewResult.status === "fulfilled" && closePreviewResult.value.canExecute === true && closePreviewResult.value.nonce) {
      closeNonce = closePreviewResult.value.nonce;
      closeStatus.textContent = "Connection close: preview ready for the captured endpoint and process lifetime.";
    } else {
      const reason = closePreviewResult.status === "rejected" ? closePreviewResult.reason.message
        : closePreviewResult.value.reason || "the endpoint is not currently eligible";
      closeStatus.textContent = `Connection close: unavailable — ${reason}`;
    }
    const ready = Boolean(blockNonce && closeNonce);
    status.textContent = ready ? "Review both previews. Confirming attempts each operation independently." : "Both operations must be available before this combined action can run.";
    execute.disabled = !ready;
    if (ready) footer.prepend(execute);
  });
  execute.onclick = async () => {
    if (execute.disabled || executing) return;
    executing = true;
    execute.disabled = true;
    cancel.disabled = true;
    const closeButton = view.querySelector('.dialog-header button[aria-label="Close"]');
    if (closeButton) closeButton.disabled = true;
    status.textContent = "Applying the two reviewed steps independently…";
    let firewallSucceeded = false;
    let createdRuleName = blockRuleName;
    try {
      const result = await api.postForm("/api/block/commit", { nonce: blockNonce }, { signal: controller.signal });
      firewallSucceeded = result.ok === true;
      createdRuleName = result.ruleName || createdRuleName;
      firewallStatus.textContent = firewallSucceeded
        ? `Firewall rule: ${result.ruleStatus === "already-present" ? "already existed" : "created"} for ${address}:${port}.`
        : `Firewall rule: failed — ${result.message || "Windows Firewall refused the request."}`;
    } catch (error) {
      if (error.name === "AbortError") return;
      firewallStatus.textContent = `Firewall rule: failed — ${error.message}`;
    }
    try {
      const result = await api.post("/api/connections/action/execute", { nonce: closeNonce }, { signal: controller.signal });
      closeStatus.textContent = result.ok === true
        ? "Connection close: succeeded. The application may reconnect."
        : `Connection close: failed — ${result.connection?.reason || "the endpoint could not be closed."}`;
    } catch (error) {
      if (error.name === "AbortError") return;
      closeStatus.textContent = `Connection close: failed — ${error.message}`;
    }
    status.textContent = "Both steps have independent results above; one operation does not roll back the other.";
    execute.remove();
    executing = false;
    cancel.disabled = false;
    if (closeButton) closeButton.disabled = false;
    if (firewallSucceeded) {
      footer.prepend(h("button", { class: "btn btn-outline btn-sm", type: "button",
        onclick: () => {
          closeDialog(view);
          openFirewallRuleResult(createdRuleName, row);
        },
      }, createdRuleName ? "Open firewall rule" : "Review matching firewall rules"));
    }
  };
}

function detailEntry(label, value) {
  return [
    h("dt", {}, label),
    h("dd", {}, value),
  ];
}

function openFirewallRuleResult(ruleName, row) {
  if (typeof ruleName === "string" && ruleName) {
    document.dispatchEvent(new CustomEvent("wintcp:firewall-open-rule", { detail: { name: ruleName } }));
    return;
  }
  document.dispatchEvent(new CustomEvent("wintcp:firewall-investigate", { detail: { target: {
    proto: row.proto || "TCP", local: row.local || row.localAddress || null,
    lport: row.lport ?? null, remote: row.remote || row.remoteAddress || null,
    rport: row.rport ?? null, path: row.path || null, service: row.service || null,
  } } }));
}

function blockPeerReason(row) {
  if (row.removed) return "Retained history is no longer a live endpoint";
  const protocol = String(row.proto || "").toUpperCase();
  if (!protocol.startsWith("TCP")) return "This peer-block action creates a TCP firewall rule; UDP is not supported here";
  if (String(row.state || "").toUpperCase() === "LISTENING") return "A listener has no remote peer to block";
  const address = String(row.remote || row.remoteAddress || "");
  if (!address || address === "*" || address === "0.0.0.0" || address === "::") return "A remote IP address is unavailable";
  const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(address) && address.split(".").every((part) => Number(part) <= 255);
  const ipv6 = address.includes(":") && /^[0-9a-f:.%]+$/i.test(address);
  if (!ipv4 && !ipv6) return "Peer blocking requires a literal IP address";
  if (!Number.isInteger(row.rport) || row.rport < 1 || row.rport > 65535) return "A valid remote TCP port is unavailable";
  return null;
}

function showApplicationBlockPreview(row) {
  showApplicationRulePreview(row, false);
}

function showApplicationPeerBlockPreview(row) {
  showApplicationRulePreview(row, "application-peer");
}

function showServicePeerBlockPreview(row) {
  showApplicationRulePreview(row, "service-peer");
}

function showApplicationRulePreview(row, scope) {
  if (activeBlockDialog) closeDialog(activeBlockDialog);
  const peerScoped = scope !== "application";
  const serviceScoped = scope === "service-peer";
  const path = typeof row.path === "string" ? row.path.trim() : "";
  const address = row.remote || row.remoteAddress || "";
  const port = Number(row.rport);
  const status = h("p", { class: "dialog-description", role: "status", "aria-live": "polite" },
    "Preparing the firewall-rule preview…");
  const plan = h("pre", { class: "muted text-sm" });
  let previewNonce = "";
  let previewRuleName = "";
  const apply = h("button", { class: "btn btn-destructive btn-sm", type: "button", disabled: true,
    onclick: async () => {
      if (apply.disabled || !previewNonce) return;
      apply.disabled = true;
      status.textContent = "Installing the reviewed outbound TCP firewall rule…";
      try {
        const result = await api.postForm("/api/block/commit", { nonce: previewNonce }, { signal: controller.signal });
        if (!view.isConnected) return;
        status.textContent = result.ok
          ? `Firewall rule ${result.ruleStatus === "already-present" ? "already existed" : "was created"}. Existing connections remain open.`
          : `Firewall rule creation failed: ${result.message || "Windows Firewall refused the request."}`;
        apply.remove();
        if (result.ok) {
          const ruleName = result.ruleName || previewRuleName;
          footer.prepend(h("button", { class: "btn btn-outline btn-sm", type: "button",
            onclick: () => { closeDialog(view); openFirewallRuleResult(ruleName, row); },
          }, "Open firewall rule"));
        }
      } catch (error) {
        if (!view.isConnected || error.name === "AbortError") return;
        status.textContent = `Firewall rule creation failed: ${error.message}`;
        apply.remove();
      }
    },
  }, "Create firewall rule");
  const footer = h("div", { class: "dialog-footer" },
    h("button", { class: "btn btn-outline btn-sm", type: "button", onclick: () => closeDialog(view) }, "Cancel"));
  const details = [
    detailEntry("Process", row.process || row.processName || UNAVAILABLE),
    detailEntry("Executable path", path || UNAVAILABLE),
    detailEntry("PID", row.pid ?? UNAVAILABLE),
  ];
  if (peerScoped) details.push(
    ...(serviceScoped ? [detailEntry("Windows service", row.service || UNAVAILABLE)] : []),
    detailEntry("Remote IP", address || UNAVAILABLE),
    detailEntry("Remote port", Number.isInteger(port) ? String(port) : UNAVAILABLE),
  );
  const view = dialog({ class: "details-dialog action-preview-dialog", "aria-labelledby": "application-block-review-title" },
    h("form", { method: "dialog", class: "dialog-form" },
      h("div", { class: "dialog-header" },
        h("h2", { id: "application-block-review-title", class: "dialog-title" },
          serviceScoped ? "Review service and peer block" : peerScoped ? "Review application and peer block" : "Review application block"),
        h("button", { type: "submit", class: "btn btn-close btn-sm", "aria-label": "Close" }, "Close")),
      h("div", { class: "dialog-content" }, status,
        h("dl", { class: "detail-list" }, ...details),
        h("p", { class: "muted text-sm" }, serviceScoped
          ? "This outbound TCP rule targets the known Windows service within this executable path, and only for this remote IP and port. It does not close this connection."
          : peerScoped
          ? "This outbound TCP rule applies to every instance of this executable, but only for this remote IP and port. It does not close this connection."
          : "This outbound TCP rule applies to every instance of this executable for all remote addresses and ports. It does not close this connection."),
        plan),
      footer));
  const controller = new AbortController();
  activeBlockDialog = view;
  view.addEventListener("close", () => {
    controller.abort();
    if (activeBlockDialog === view) activeBlockDialog = null;
  }, { once: true });
  document.body.append(view);
  openDialog(view);
  if (!path || !path.includes("\\") || path.toLowerCase() === "system" ||
      !(Number(row.pid) > 0) || !row.processInstanceId) {
    status.textContent = "A verified process lifetime and readable full executable path are required.";
    return;
  }
  const fields = { scope,
    process: path, pid: String(row.pid), instanceId: String(row.processInstanceId) };
  if (peerScoped) Object.assign(fields, {
    idExact: String(row.idExact ?? ""), processInstanceId: String(row.processInstanceId),
    proto: String(row.proto ?? ""), local: String(row.local || row.localAddress || ""),
    lport: String(row.lport ?? ""), remote: String(address), rport: String(row.rport ?? ""),
    state: String(row.state ?? ""),
  });
  if (serviceScoped) fields.service = String(row.service ?? "");
  api.postForm("/api/block/preview", fields, { signal: controller.signal })
    .then((preview) => {
      if (!view.isConnected) return;
      if (!preview.nonce) {
        status.textContent = preview.reason || "A one-time firewall preview could not be prepared. Refresh the endpoint and retry.";
        plan.textContent = preview.plan || "";
        return;
      }
      previewNonce = preview.nonce;
      previewRuleName = preview.ruleName || "";
      status.textContent = serviceScoped
        ? "The exact connection, process lifetime, executable path and Windows service were revalidated. Review this service and peer scope before confirming."
        : peerScoped
        ? "The exact connection and process lifetime were revalidated. Review the executable and peer scope before confirming."
        : "The process lifetime and executable path were revalidated. Review the all-instance scope before confirming.";
      plan.textContent = preview.plan || "The server did not provide a textual plan.";
      apply.disabled = false;
      footer.prepend(apply);
    })
    .catch((error) => {
      if (!view.isConnected || error.name === "AbortError") return;
      status.textContent = `Firewall rule preview failed: ${error.message}`;
    });
}

function showBlockPeerPreview(row) {
  if (activeBlockDialog) closeDialog(activeBlockDialog);
  const address = row.remote || row.remoteAddress;
  const port = row.rport;
  const reason = blockPeerReason(row);
  const status = h("p", { class: "dialog-description", role: "status", "aria-live": "polite" },
    reason || "Preparing the firewall-rule preview…");
  const plan = h("pre", { class: "muted text-sm" });
  const apply = h("button", { class: "btn btn-destructive btn-sm", type: "button", disabled: true,
    onclick: async () => {
      if (apply.disabled || !previewNonce) return;
      apply.disabled = true;
      status.textContent = "Installing the reviewed outbound TCP firewall rule…";
      try {
        const result = await api.postForm("/api/block/commit", { nonce: previewNonce }, { signal: controller.signal });
        if (!view.isConnected) return;
        status.textContent = result.ok
          ? `Firewall rule ${result.ruleStatus === "already-present" ? "already existed" : "was created"} for ${address}:${port}. This operation did not close the current connection.`
          : `Firewall rule creation failed: ${result.message || "Windows Firewall refused the request."}`;
        apply.remove();
        if (result.ok) {
          const ruleName = result.ruleName || previewRuleName;
          const inspect = h("button", { class: "btn btn-outline btn-sm", type: "button",
            onclick: () => {
              closeDialog(view);
              openFirewallRuleResult(ruleName, row);
            },
          }, ruleName ? "Open firewall rule" : "Review matching firewall rules");
          view.querySelector(".dialog-footer").prepend(inspect);
        }
      } catch (error) {
        if (!view.isConnected || error.name === "AbortError") return;
        status.textContent = `Firewall rule creation failed: ${error.message}`;
        apply.remove();
      }
    },
  }, "Create firewall rule");
  const footer = h("div", { class: "dialog-footer" },
    h("button", { class: "btn btn-outline btn-sm", type: "button", onclick: () => closeDialog(view) }, "Cancel"));
  const view = dialog({ class: "details-dialog action-preview-dialog", "aria-labelledby": "peer-block-review-title" },
    h("form", { method: "dialog", class: "dialog-form" },
      h("div", { class: "dialog-header" },
        h("h2", { id: "peer-block-review-title", class: "dialog-title" }, "Review TCP peer block"),
        h("button", { type: "submit", class: "btn btn-close btn-sm", "aria-label": "Close" }, "Close")),
      h("div", { class: "dialog-content" }, status,
        h("dl", { class: "detail-list" },
          detailEntry("Process", row.process || row.processName || UNAVAILABLE),
          detailEntry("Protocol", row.proto || UNAVAILABLE),
          detailEntry("Remote IP", address || UNAVAILABLE),
          detailEntry("Remote port", port != null ? String(port) : UNAVAILABLE)),
        h("p", { class: "muted text-sm" },
          "This creates an outbound TCP peer rule for the remote IP and port. It does not close this connection or scope the rule to this process."),
        plan),
      footer));
  const controller = new AbortController();
  let previewNonce = "";
  let previewRuleName = "";
  activeBlockDialog = view;
  view.addEventListener("close", () => {
    controller.abort();
    if (activeBlockDialog === view) activeBlockDialog = null;
  }, { once: true });
  document.body.append(view);
  openDialog(view);
  if (reason) return;
  api.postForm("/api/block/preview", { address, port: String(port) }, { signal: controller.signal })
    .then((preview) => {
      if (!view.isConnected) return;
      if (!preview.nonce) {
        status.textContent = preview.reason ||
          "A one-time firewall preview could not be prepared. Refresh the endpoint and retry.";
        plan.textContent = preview.plan || "";
        return;
      }
      previewNonce = preview.nonce;
      previewRuleName = preview.ruleName || "";
      status.textContent = "Review the exact peer and scope before confirming. The current connection remains open.";
      plan.textContent = preview.plan || "The server did not provide a textual plan.";
      apply.disabled = false;
      footer.prepend(apply);
    })
    .catch((error) => {
      if (!view.isConnected || error.name === "AbortError") return;
      status.textContent = `Firewall rule preview failed: ${error.message}`;
    });
}
