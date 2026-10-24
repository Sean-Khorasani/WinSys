// pages/automations.js - Automations page.
//
// Three views with real panels: CLI playbooks, the audit/event trail, and the
// script workbench where scripts are written, validated, run, and saved.
//
// The script engine (parseScript, executeScriptNodes, etc.) lives in
// js/scriptengine.js, extracted from the legacy dashboard so the language
// and its security bounds are the same everywhere.

import { h, clear } from "../h.js";
import { createTabs } from "../ui/tabs.js";
import { emptyState, card, cardHeader, cardTitle, cardDescription, cardContent, cardFooter } from "../ui/card.js";
import { badge } from "../ui/badge.js";
import { api } from "../api.js";
import {
  parseScript,
  scriptCommandNodes,
  interpolateScript,
  evaluateScriptCondition,
  isSensitiveCli,
  cliForm,
  scriptCommandDisplay,
  displayCliArg,
  escapeHtml,
  STARTER_SCRIPT,
  MAX_STEPS,
} from "../scriptengine.js";

const MAX_SAVED_SCRIPTS = 40;
const MAX_RUN_STEPS = 100;

function recipeFile(items) {
  const hex = (text) => Array.from(new TextEncoder().encode(text),
    (byte) => byte.toString(16).padStart(2, "0")).join("");
  return "WinTCP-Recipes:1\n" + items.map((item) => [
    item.id, item.revision, item.enabled ? "1" : "0",
    item.trigger.type, item.cooldownSeconds,
    hex(item.name), hex(item.target.imagePaths[0]),
  ].join("|") + "\n").join("");
}

function timeText(iso) {
  if (!iso) return "";
  try {
    const d = new Date(iso);
    const now = new Date();
    const diff = (now - d) / 1000;
    if (diff < 86400) return d.toLocaleTimeString();
    return d.toLocaleDateString();
  } catch {
    return "";
  }
}

export async function renderAutomations(page, store) {
  let disposed = false;
  const requests = new AbortController();
  clear(page);
  page.append(
    h("div", { class: "page-heading" },
      h("div", {},
        h("h1", { class: "page-title" }, "Automations"),
        h("p", { class: "page-description" },
          "CLI playbooks, monitoring engine, audit trail, and scripts"),
      ),
    ),
    h("div", { class: "auto-layout" }),
  );

  const layout = page.querySelector(".auto-layout");
  const tabs = createTabs({
    ariaLabel: "Automation views",
    initial: store.get().automationView,
    onChange: (id) => store.set({ automationView: id }),
    tabs: [
      { id: "templates", label: "Templates", render: renderTemplates },
      { id: "engine", label: "Engine", render: renderEngine },
      { id: "lifecycle", label: "Event history", render: renderLifecycle },
      { id: "monitors", label: "Monitors", render: renderMonitors },
      { id: "restrictions", label: "Restrictions", render: renderRestrictions },
      { id: "scripts", label: "Scripts", render: renderScripts },
      { id: "events", label: "Events & audit", render: renderEvents },
    ],
  });
  layout.append(tabs.element);
  page._autoDestroy = () => {
    disposed = true;
    requests.abort();
    tabs.destroy();
  };

  // Shared state for the Scripts tab workbench.
  const draft = store.get().automationDraft || null;
  if (draft) store.set({ automationDraft: null });
  const scriptsState = {
    config: null,
    templates: [],
    currentScriptId: "",
    currentTemplateId: "CUSTOM",
    editName: "",
    editSource: "",
    scriptRun: {
      running: false,
      variables: Object.create(null),
      steps: [],
      output: "",
      status: "Not run",
      failed: false,
    },
  };
  page._autoState = scriptsState;
  if (draft) {
    scriptsState.editName = draft.name || "Selected connection automation";
    scriptsState.editSource = draft.source || "";
  }

  // ---- Scripts tab workbench ----
  // Declared before the initial render to avoid a temporal dead zone:
  // tabs.select below may call renderScripts, whose ref callbacks write to these.
  let editorEl;
  let nameInput;
  let validationEl;
  let statusEl;
  let outputEl;
  let runStatusEl;
  let stepListEl;
  let variableListEl;
  let runHistoryEl;

  await tabs.select(tabs.active(), true);
  if (disposed) return page;

  // ---- Templates tab ----
  async function renderTemplates() {
    let data;
    try {
      data = await api.get("/api/templates", { signal: requests.signal });
    } catch (err) {
      return emptyState({}, "Template catalogue unavailable", err.message);
    }
    const templates = Array.isArray(data) ? data : Array.isArray(data.templates) ? data.templates : [];
    if (templates.length === 0) {
      return emptyState({}, "No templates", "The catalogue file did not load.");
    }

    const host = h("div", { class: "tab-panel-body" });
    host.append(h("p", { class: "muted text-sm proc-note" },
      "These are on-demand CLI playbooks, not active detectors or saved monitor rules. " +
      "Open a script to review, edit, and run it. For background connection-change logging, " +
      "use the CLI monitor command; this page does not evaluate monitor rules."));
    host.append(templateCardList(templates, scriptsState));
    return host;
  }

  function templateCardList(templates, state) {
    const list = h("div", { class: "template-grid" });
    for (const t of templates) {
      const cardEl = h("div", { class: "template-card", tabindex: 0 },
        h("div", { class: "template-card-head" },
          h("div", {},
            h("span", { class: "template-id num" }, `${t.id || "-"} · ${t.category || ""}`),
            h("h3", {}, t.title || "(unnamed)"),
          ),
          h("span", { class: "catalog-badge" }, "CLI PLAYBOOK"),
        ),
        t.summary ? h("p", {}, t.summary) : null,
        h("div", { class: "template-actions" },
          h("button", {
            class: "btn btn-sm btn-quiet",
            type: "button",
            onclick: () => loadTemplateScript(t, true, state),
          }, "Open script"),
        ),
      );
      list.append(cardEl);
    }
    return list;
  }

  function loadTemplateScript(template, makeCopy, state) {
    state.currentScriptId = "";
    state.currentTemplateId = template.id;
    state.editName = makeCopy ? `${template.title} (copy)` : template.title;
    state.editSource = template.script || template.source || template.command || "# No source";
    state._template = template;
    // Switch to the Scripts tab and load the editor.
    tabs.select("scripts", true);
  }

  // ---- Events & audit tab ----
  async function renderEvents() {
    let data;
    try {
      data = await api.get("/api/audit", { signal: requests.signal });
    } catch (err) {
      return emptyState({}, "Audit trail unavailable", err.message);
    }
     const entries = Array.isArray(data) ? data : Array.isArray(data.entries) ? data.entries : [];
     if (entries.length === 0) {
       return emptyState({}, "No events recorded",
         "The audit trail is empty. Every block, permit and script run appends to it.");
     }
     const list = h("ul", { class: "event-list" });
     for (const entry of entries.slice(0, 200)) {
       const evt = entry.event || entry;
       const isOk = evt.result === "ok" || entry.event?.type?.includes("ok");
       const badgeEl = isOk
         ? badge({ variant: "success" }, "ok")
         : badge({ variant: "destructive" }, evt.result || evt.type || entry.type || "entry");
       const action = evt.action || evt.command || entry.event?.type || entry.type || "";
       list.append(h("li", { class: "event-row" },
         h("span", { class: "event-time num" }, entry.time || entry.at || entry.timestamp || ""),
         badgeEl,
         h("span", { class: "event-action", dir: "auto" }, action),
         evt.detail ? h("span", { class: "event-detail muted" }, evt.detail) : null,
       ));
    }
    const host = h("div", { class: "tab-panel-body" }, list);
    if (entries.length > 200) {
      host.append(h("p", { class: "muted text-sm proc-note" },
        `Showing the newest 200 of ${entries.length}. The full trail is on disk.`));
    }
    return host;
  }

  // ---- Scripts tab workbench ----
  async function renderMonitors() {
    const message = h("p", { class: "muted text-sm", role: "status" });
    const engineMessage = h("p", { class: "muted text-sm", role: "status" });
    const catalog = h("div", { class: "template-grid" });
    const list = h("div", { class: "engine-events" });
    const testResults = h("div", { class: "engine-events", role: "status" });
    const inbox = h("div", { class: "engine-events" });
    const name = h("input", { required: true, maxlength: "120", placeholder: "Torrent client" });
    const imagePath = h("input", { required: true, maxlength: "1024",
      placeholder: "C:\\Program Files\\App\\app.exe" });
    const trigger = h("select", {},
      h("option", { value: "outbound_activity" }, "New remote TCP endpoint"),
      h("option", { value: "new_listener" }, "New TCP listener"));
    const cooldown = h("input", { type: "number", min: "0", max: "86400", value: "60", required: true });
    let current = null;
    let notificationCursor = "";
    let saving = false;
    let editingId = "";
    const formTitle = h("h3", {}, "Add monitor");
    const submitButton = h("button", { class: "btn btn-outline", type: "submit" },
      "Add disabled monitor");
    const cancelEdit = h("button", { class: "btn btn-quiet", type: "button",
      hidden: true, onclick: () => { resetEdit(); } }, "Cancel edit");
    function resetEdit() {
      editingId = "";
      formTitle.textContent = "Add monitor";
      submitButton.textContent = "Add disabled monitor";
      cancelEdit.hidden = true;
      name.value = "";
      imagePath.value = "";
      trigger.value = "outbound_activity";
      cooldown.value = "60";
    }
    async function saveItems(items, successMessage) {
      if (saving || !current) return false;
      saving = true;
      message.textContent = "Saving monitor definitions…";
      try {
        const submitted = await api.postForm("/api/engine/recipes", {
          requestId: crypto.randomUUID().replaceAll("-", ""),
          expectedRevision: current.revision,
          recipesText: recipeFile(items),
        });
        let operation;
        for (let attempt = 0; attempt < 15; attempt++) {
          operation = await api.get(`/api/engine/operations/${submitted.operationId}`);
          if (operation.status === "succeeded" || operation.status === "failed") break;
          await new Promise((resolve) => setTimeout(resolve, 200));
        }
        if (operation?.status !== "succeeded")
          throw new Error(operation?.error?.code || "Save pending; refresh to check its result.");
        await loadRecipes();
        if (!disposed) message.textContent = successMessage;
        return true;
      } catch (error) {
        if (!disposed) message.textContent = error.status === 409
          ? "Monitors changed in another window. Refresh and review before saving."
          : (error.message || "Could not save monitor definitions.");
        return false;
      } finally {
        saving = false;
      }
    }
    async function loadRecipes() {
      try {
        const result = await api.get("/api/engine/recipes", { signal: requests.signal });
        if (disposed) return;
        current = result;
        clear(list);
        if (!result.items.length) list.append(h("p", { class: "muted text-sm" },
          "No saved monitors. Add one below; new monitors start disabled."));
        for (const item of result.items) {
          const path = item.target?.imagePaths?.[0] || "";
          list.append(h("div", { class: "engine-event-row" },
            h("span", { class: `badge ${item.enabled ? "badge-success" : "badge-muted"}` },
              item.enabled ? "ON" : "OFF"),
            h("span", { class: "engine-event-target", title: path },
              h("strong", {}, item.name), h("small", {}, ` ${path}`)),
            h("span", { class: "muted" }, item.trigger?.type === "new_listener"
              ? "TCP listener" : "Remote TCP endpoint"),
            h("button", { class: "btn btn-sm btn-outline", type: "button",
              onclick: () => {
                editingId = item.id;
                formTitle.textContent = `Edit ${item.name}`;
                submitButton.textContent = "Save changes (disabled)";
                cancelEdit.hidden = false;
                name.value = item.name;
                imagePath.value = path;
                trigger.value = item.trigger.type;
                cooldown.value = String(item.cooldownSeconds);
                form.scrollIntoView({ behavior: "smooth", block: "center" });
                name.focus();
              },
            }, "Edit"),
            h("button", { class: "btn btn-sm btn-outline", type: "button",
              onclick: async () => {
                testResults.textContent = "Replaying retained observations without effects…";
                try {
                  const result = await api.postForm(
                    `/api/engine/recipes/${item.id}/test`, {});
                  if (disposed) return;
                  clear(testResults);
                  testResults.append(h("strong", {}, `${item.name}: ${result.wouldNotify} simulated notification(s)`),
                    h("p", { class: "muted text-sm" },
                      `${result.matched} matching observations among ${result.examined} recent retained events. No notifications or actions were created. Snapshots cannot prove attempted or outbound connections.`));
                  for (const example of result.examples || []) {
                    testResults.append(h("p", { class: "muted text-sm" },
                      `${example.reason}: ${example.event?.eventId || "unknown event"}`));
                  }
                } catch (error) {
                  if (!disposed) testResults.textContent = error.message || "Simulation failed.";
                }
              },
            }, "Test"),
            h("button", { class: "btn btn-sm btn-outline", type: "button",
              onclick: () => { void saveItems(current.items.map((row) => row.id === item.id
                ? { ...row, revision: String(BigInt(row.revision) + 1n), enabled: !row.enabled }
                : row), item.enabled ? "Monitor disabled." : "Monitor enabled."); },
            }, item.enabled ? "Disable" : "Enable"),
            h("button", { class: "btn btn-sm btn-quiet", type: "button",
              onclick: () => { if (confirm(`Delete monitor “${item.name}”?`))
                void saveItems(current.items.filter((row) => row.id !== item.id), "Monitor deleted."); },
            }, "Delete")));
        }
      } catch (error) {
        if (!disposed) {
          current = null;
          list.textContent = "Engine unavailable. Start it with wintcp.exe engine start.";
          message.textContent = error.message || "Could not load monitors.";
        }
      }
    }
    async function loadNotifications() {
      try {
        const query = notificationCursor
          ? `?limit=30&cursor=${encodeURIComponent(notificationCursor)}` : "?limit=30";
        const result = await api.get(`/api/engine/notifications${query}`,
          { signal: requests.signal });
        if (disposed) return;
        notificationCursor = result.nextCursor || "";
        clear(inbox);
        if (!result.items.length) inbox.append(h("p", { class: "muted text-sm" },
          "No notifications in this page."));
        for (const notice of result.items) {
          const ackState = h("span", { class: "badge badge-outline" },
            notice.acknowledged ? "Acknowledged" : "Unacknowledged");
          const ack = h("button", { class: "btn btn-sm btn-outline", type: "button",
            disabled: notice.acknowledged,
            onclick: async () => {
              ack.disabled = true;
              try {
                const submitted = await api.postForm(
                  `/api/engine/notifications/${notice.id}/acknowledge`,
                  { requestId: crypto.randomUUID().replaceAll("-", "") });
                let operation;
                for (let attempt = 0; attempt < 15; attempt++) {
                  operation = await api.get(`/api/engine/operations/${submitted.operationId}`);
                  if (operation.status === "succeeded" || operation.status === "failed") break;
                  await new Promise((resolve) => setTimeout(resolve, 200));
                }
                if (operation?.status !== "succeeded")
                  throw new Error(operation?.error?.code || "Acknowledgment still pending.");
                ackState.textContent = "Acknowledged";
              } catch (error) {
                ack.disabled = false;
                engineMessage.textContent = error.message || "Could not acknowledge notification.";
              }
            },
          }, "Acknowledge");
          inbox.append(h("div", { class: "engine-event-row" },
            h("time", { class: "muted", datetime: notice.occurredAtUtc || "" },
              notice.occurredAtUtc ? new Date(notice.occurredAtUtc).toLocaleString() : "Time unknown"),
            h("span", { class: "engine-event-target" }, notice.message || "Monitor fired"),
            ackState, ack));
        }
        next.textContent = "Next inbox page";
      } catch (error) {
        if (!disposed) {
          if (error.status === 410) notificationCursor = "";
          inbox.textContent = error.status === 410
            ? "Older notifications rotated out. Reload from the first retained page."
            : (error.message || "Inbox unavailable.");
        }
      }
    }
    async function controlEngine(action) {
      engineStart.disabled = true;
      engineStop.disabled = true;
      engineMessage.textContent = action === "start" ? "Starting engine…" : "Stopping engine…";
      try {
        await api.postForm("/api/engine/control", { action });
        if (disposed) return;
        engineMessage.textContent = action === "start"
          ? "Engine running as your current user; no administrator permission needed."
          : "Engine stopped; saved recipes remain available for its next start.";
        if (action === "start") await loadRecipes();
        else {
          current = null;
          list.textContent = "Engine stopped. Start it to manage or run monitors.";
        }
      } catch (error) {
        if (!disposed) engineMessage.textContent = error.message || "Engine control failed.";
      } finally {
        if (!disposed) { engineStart.disabled = false; engineStop.disabled = false; }
      }
    }
    const engineStart = h("button", { class: "btn btn-outline", type: "button",
      onclick: () => { void controlEngine("start"); } }, "Start engine");
    const engineStop = h("button", { class: "btn btn-quiet", type: "button",
      onclick: () => { if (confirm("Stop monitoring? Saved recipes will remain, but no new events will be collected until the engine starts again."))
        void controlEngine("stop"); } }, "Stop engine");
    const next = h("button", { class: "btn btn-outline", type: "button",
      onclick: () => { void loadNotifications(); } }, "Load inbox");
    const form = h("form", { class: "engine-config-form", onsubmit: (event) => {
      event.preventDefault();
      if (!current) return;
      const fields = {
        name: name.value.trim(), enabled: false,
        target: { imagePaths: [imagePath.value.trim()] },
        trigger: { type: trigger.value }, cooldownSeconds: Number(cooldown.value),
      };
      if (editingId) {
        const existing = current.items.find((row) => row.id === editingId);
        if (!existing) { message.textContent = "Monitor changed; refresh before editing."; return; }
        if (!existing.enabled && existing.name === fields.name &&
            existing.target.imagePaths[0] === fields.target.imagePaths[0] &&
            existing.trigger.type === fields.trigger.type &&
            existing.cooldownSeconds === fields.cooldownSeconds) {
          message.textContent = "No changes to save.";
          return;
        }
        const updated = { ...existing, ...fields,
          revision: String(BigInt(existing.revision) + 1n) };
        void saveItems(current.items.map((row) => row.id === editingId ? updated : row),
          "Changes saved disabled. Review and enable this monitor when ready.")
          .then((ok) => { if (ok) resetEdit(); });
      } else {
        const item = { id: crypto.randomUUID().replaceAll("-", "").slice(0, 24),
          revision: "1", ...fields };
        void saveItems([...current.items, item],
          "Monitor saved (disabled). Review and enable it when ready.")
          .then((ok) => { if (ok) resetEdit(); });
      }
    } },
      h("label", {}, "Name", name),
      h("label", {}, "Exact executable path", imagePath),
      h("label", {}, "Observe", trigger),
      h("label", {}, "Cooldown (seconds)", cooldown),
      submitButton, cancelEdit);
    try {
      const presets = await api.get("/data/monitor-recipes.json", { signal: requests.signal });
      if (disposed) return h("div");
      for (const preset of presets.recipes || []) {
        catalog.append(h("article", { class: "template-card" },
          h("div", { class: "template-card-head" },
            h("div", {}, h("span", { class: "template-id num" }, preset.id),
              h("h3", {}, preset.title)),
            h("span", { class: "catalog-badge" },
              preset.snapshotReady ? "PASSIVE · TCP SNAPSHOT" : "NEEDS CAPABILITY")),
          h("p", {}, preset.summary),
          h("p", { class: "muted text-sm" }, `Input or dependency: ${preset.requires}`),
          h("div", { class: "template-actions" },
            h("button", { class: "btn btn-sm btn-outline", type: "button",
              disabled: !preset.snapshotReady,
              onclick: () => {
                resetEdit();
                name.value = preset.title;
                trigger.value = preset.trigger;
                cooldown.value = String(preset.cooldownSeconds);
                message.textContent = `${preset.id} selected. Choose the exact executable path, then save it disabled for review.`;
                imagePath.focus();
              },
            }, preset.snapshotReady ? "Configure passive monitor" : "Not yet available"))));
      }
    } catch (error) {
      if (!disposed) catalog.textContent = error.message || "Recipe catalog unavailable.";
    }
    const host = h("div", { class: "tab-panel-body" },
      card({}, cardHeader({}, cardTitle({}, "Passive monitors"),
        cardDescription({}, "Saved in the optional per-user engine; run while this page is closed.")),
        cardContent({}, h("p", { class: "muted text-sm" },
          "Snapshot observations can miss short connections and cannot prove outbound direction or blocked attempts. No actions or network restrictions are applied."),
          h("div", { class: "template-actions" }, engineStart, engineStop),
          engineMessage, list, testResults,
          h("h3", {}, "Practical monitoring presets"), catalog,
          formTitle, form, message),
        cardFooter({}, h("button", { class: "btn btn-outline", type: "button",
          onclick: () => { void loadRecipes(); } }, "Refresh monitors"))),
      card({}, cardHeader({}, cardTitle({}, "Notification inbox")),
        cardContent({}, inbox), cardFooter({}, next)));
    await loadRecipes();
    return host;
  }

  async function renderRestrictions() {
    const status = h("p", { class: "muted text-sm", role: "status" });
    const auditNotice = h("p", { class: "muted text-sm", role: "status" });
    const previewBox = h("div", { class: "engine-events", role: "status" });
    const leases = h("div", { class: "engine-events" });
    const historyList = h("div", { class: "engine-events" });
    let historyCursor = "";
    const historySeen = new Set();
    async function loadHistory() {
      try {
        const query = historyCursor ? `&cursor=${encodeURIComponent(historyCursor)}` : "";
        const page = await api.get(`/api/restrictions/history?limit=30${query}`,
          { signal: requests.signal });
        if (disposed) return;
        historyCursor = page.nextCursor || "";
        clear(historyList);
        for (const item of page.items || []) {
          if (historySeen.has(item.id)) continue;
          if (historySeen.size >= 2048) historySeen.delete(historySeen.values().next().value);
          historySeen.add(item.id);
          historyList.append(h("div", { class: "engine-event-row" },
            h("span", { class: "badge badge-outline" }, item.state || "Coverage gap"),
            h("span", { class: "engine-event-target" },
              h("strong", {}, item.lease?.imagePath || item.action || "Collector coverage"),
              h("small", {}, ` ${item.reason || "Unknown outcome"}`)),
            h("time", { class: "muted" }, item.occurredAtUtc ||
              (item.occurredUtcMs ? new Date(Number(item.occurredUtcMs)).toLocaleString() : "Time unknown"))));
        }
        if (!historyList.childNodes.length) historyList.append(
          h("p", { class: "muted text-sm" }, "No additional retained outcomes in this page."));
        historyNext.textContent = "Next outcomes page";
      } catch (error) {
        if (!disposed) {
          if (error.status === 410) { historyCursor = ""; historySeen.clear(); }
          historyList.textContent = error.status === 410
            ? "Older history rotated out. Load again from the first retained page."
            : error.message || "Outcome history unavailable.";
        }
      }
    }
    const historyNext = h("button", { class: "btn btn-outline", type: "button",
      onclick: () => { void loadHistory(); } }, "Load retained outcomes");
    async function runOperation(path, body) {
      const submitted = await api.postForm(path, {
        ...body, requestId: crypto.randomUUID().replaceAll("-", ""),
      }, { signal: requests.signal });
      const until = performance.now() + 120000;
      while (!disposed && performance.now() < until) {
        const operation = await api.get(
          `/api/engine/operations/${submitted.operationId}`, { signal: requests.signal });
        if (operation.status === "succeeded" || operation.status === "failed")
          auditNotice.textContent = operation.audit?.recorded === false
            ? "The action result is available, but its command audit could not be fully retained."
            : "";
        if (operation.status === "succeeded") return operation.result;
        if (operation.status === "failed") {
          const code = operation.error?.code;
          throw new Error(code === "collector_restart_required"
            ? "The collector belongs to the previous engine session. Stop it, then start it again."
            : code === "collector_stopped_audit_incomplete"
              ? "Collector stopped, but some final outcomes could not be retained."
            : code || "Operation failed.");
        }
        await new Promise((resolve) => setTimeout(resolve, 400));
      }
      throw new Error(`Operation ${submitted.operationId} is still pending. Refresh to reconcile the collector's current state.`);
    }
    const startCollector = h("button", { class: "btn btn-outline", type: "button",
      onclick: async () => {
        startCollector.disabled = true;
        status.textContent = "Requesting Windows administrator approval…";
        try {
          await runOperation("/api/collector/control", { action: "start" });
          if (!disposed) { status.textContent = "Collector running."; await loadLeases(); }
        } catch (error) {
          if (!disposed) status.textContent = error.message || "Collector did not start.";
        } finally { if (!disposed) startCollector.disabled = false; }
      },
    }, "Start collector (UAC)");
    const stopCollector = h("button", { class: "btn btn-quiet", type: "button",
      onclick: async () => {
        if (!confirm("Stop the collector? All of its temporary restrictions will be released.")) return;
        stopCollector.disabled = true;
        try {
          await runOperation("/api/collector/control", { action: "stop" });
          if (!disposed) {
            clear(leases);
            leases.append(h("p", { class: "muted text-sm" }, "Collector stop requested. Refresh to confirm its current state."));
            status.textContent = "Collector is stopping and releasing its temporary restrictions.";
          }
        } catch (error) {
          if (!disposed) status.textContent = error.message || "Collector did not stop.";
        } finally { if (!disposed) stopCollector.disabled = false; }
      },
    }, "Stop collector");
    const imagePath = h("input", { required: true, maxlength: "1024",
      placeholder: "C:\\Program Files\\App\\app.exe" });
    const remoteAddress = h("input", { maxlength: "45",
      placeholder: "Optional literal IPv4 or IPv6 address" });
    const remotePort = h("input", { type: "number", min: "0", max: "65535",
      value: "0" });
    const protocol = h("select", {},
      h("option", { value: "both" }, "TCP and UDP"),
      h("option", { value: "tcp" }, "TCP only"),
      h("option", { value: "udp" }, "UDP only"));
    const minutes = h("input", { type: "number", min: "1", max: "1440",
      value: "15", required: true });
    let confirmationToken = "";
    let previewAt = 0;
    let reviewed = null;
    const applyButton = h("button", { class: "btn btn-destructive", type: "button",
      disabled: true, onclick: async () => {
        if (!confirmationToken || Date.now() - previewAt >= 30000) {
          applyButton.disabled = true;
          status.textContent = "Preview expired. Review the scope again.";
          return;
        }
        if (!confirm(`Temporarily block outbound traffic for ${reviewed.imagePath} for ${reviewed.durationSeconds / 60} minutes? Existing flows may continue.`)) return;
        const token = confirmationToken;
        confirmationToken = "";
        applyButton.disabled = true;
        try {
          const result = await runOperation("/api/restrictions/apply",
            { confirmationToken: token });
          if (disposed) return;
          previewBox.textContent = "Restriction applied. It expires automatically or can be released below.";
          status.textContent = `Active lease ${result.lease.id}.`;
          await loadLeases();
        } catch (error) {
          if (!disposed) status.textContent = error.message || "Restriction was not applied.";
        }
      },
    }, "Apply reviewed restriction");
    async function loadLeases() {
      try {
        const result = await api.get("/api/restrictions", { signal: requests.signal });
        if (disposed) return;
        clear(leases);
        if (!result.items?.length) leases.append(h("p", { class: "muted text-sm" },
          "No temporary restrictions are active."));
        for (const item of result.items || []) {
          const deadline = Number(item.deadlineUtcMs);
          const timeLeft = h("span", { class: "muted" });
          timeLeft.textContent = Number.isFinite(deadline)
            ? `${Math.max(0, Math.ceil((deadline - Date.now()) / 1000))}s remaining`
            : "Expiry unknown";
          const updateTime = () => {
            if (disposed || !timeLeft.isConnected) return;
            timeLeft.textContent = Number.isFinite(deadline)
              ? `${Math.max(0, Math.ceil((deadline - Date.now()) / 1000))}s remaining`
              : "Expiry unknown";
            setTimeout(updateTime, 1000);
          };
          leases.append(h("div", { class: "engine-event-row" },
            h("span", { class: "engine-event-target", title: item.imagePath },
              h("strong", {}, item.imagePath),
              h("small", {}, ` ${item.protocol.toUpperCase()} ${item.remoteAddress || "all peers"}${item.remotePort ? `:${item.remotePort}` : ""}`)),
            timeLeft,
            h("span", { class: "muted", title: (item.filterIds || []).join(", ") },
              `${(item.filterIds || []).length} WFP filter(s)`),
            h("button", { class: "btn btn-sm btn-outline", type: "button",
              onclick: async () => {
                if (!confirm(`Release temporary restriction for ${item.imagePath}?`)) return;
                try {
                  await runOperation("/api/restrictions/release", { id: item.id });
                  if (!disposed) { status.textContent = "Restriction released."; await loadLeases(); }
                } catch (error) {
                  if (!disposed) status.textContent = error.message || "Release failed.";
                }
              },
            }, "Release now")));
          setTimeout(updateTime, 1000);
        }
        status.textContent = `${result.items?.length || 0} active temporary restriction(s).`;
      } catch (error) {
        if (!disposed) {
          leases.textContent = "Collector unavailable. Start the engine, then explicitly run `wintcp.exe collector run` from an elevated terminal for the same user.";
          status.textContent = error.message || "Cannot read restrictions.";
        }
      }
    }
    const form = h("form", { class: "engine-config-form", onsubmit: async (event) => {
      event.preventDefault();
      confirmationToken = "";
      applyButton.disabled = true;
      clear(previewBox);
      status.textContent = "Reviewing exact target and scope…";
      try {
        const result = await runOperation("/api/restrictions/preview", {
          imagePath: imagePath.value.trim(),
          remoteAddress: remoteAddress.value.trim(),
          remotePort: remotePort.value || "0",
          protocol: protocol.value,
          minutes: minutes.value,
        });
        if (disposed) return;
        reviewed = result;
        confirmationToken = result.confirmationToken;
        previewAt = Date.now();
        previewBox.append(h("p", {}, "Executable: ", h("strong", {}, result.imagePath)),
          h("p", {}, "Windows user: ", result.userSid),
          h("p", {}, "Destination: ", result.remoteAddress || "All peers",
            result.remotePort ? `, port ${result.remotePort}` : ", all ports"),
          h("p", {}, `Protocol: ${result.protocol}; duration: ${result.durationSeconds / 60} minutes.`),
          h("p", { class: "muted text-sm" }, result.warning),
          h("p", { class: "muted text-sm" }, "Approval expires after 30 seconds and can be used once."));
        applyButton.disabled = false;
        status.textContent = "Review the scope, then apply within 30 seconds.";
      } catch (error) {
        if (!disposed) status.textContent = error.message || "Preview failed.";
      }
    } },
      h("label", {}, "Exact executable path", imagePath),
      h("label", {}, "Remote peer (optional literal IP)", remoteAddress),
      h("label", {}, "Remote port (requires peer)", remotePort),
      h("label", {}, "Protocol", protocol),
      h("label", {}, "Duration in minutes", minutes),
      h("button", { class: "btn btn-outline", type: "submit" }, "Preview restriction"));
    const host = h("div", { class: "tab-panel-body" },
      card({}, cardHeader({}, cardTitle({}, "Temporary outbound restrictions"),
        cardDescription({}, "Separate from permanent Firewall Rules. The elevated collector is optional and never starts automatically.")),
        cardContent({}, h("p", { class: "muted text-sm" },
          "Preview and approve a single exact-app scope. Blocking new outbound authorization may not terminate existing flows, and collector exit removes its filters."),
          h("div", { class: "template-actions" }, startCollector, stopCollector),
          form, previewBox, applyButton, status, auditNotice)),
      card({}, cardHeader({}, cardTitle({}, "Active leases")),
        cardContent({}, leases), cardFooter({},
          h("button", { class: "btn btn-outline", type: "button",
            onclick: () => { void loadLeases(); } }, "Refresh"),
          h("button", { class: "btn btn-quiet", type: "button",
            onclick: async () => {
              if (!confirm("Release all temporary restrictions owned by this collector?")) return;
              try {
                await runOperation("/api/restrictions/release-all",
                  { confirm: "release-all" });
                if (!disposed) { status.textContent = "All temporary restrictions released."; await loadLeases(); }
              } catch (error) {
                if (!disposed) status.textContent = error.message || "Release all failed.";
              }
            } }, "Release all temporary restrictions"))),
      card({}, cardHeader({}, cardTitle({}, "Restriction outcomes"),
        cardDescription({}, "Bounded history retained by the monitoring engine, including expiry and coverage gaps.")),
        cardContent({}, historyList), cardFooter({}, historyNext)));
    await loadLeases();
    return host;
  }

  async function renderLifecycle() {
    const status = h("p", { class: "muted text-sm", role: "status" });
    const history = h("div", { class: "engine-events" });
    const buttons = [];
    let cursor = "";
    const seen = new Set();
    async function control(action) {
      buttons.forEach((button) => { button.disabled = true; });
      status.textContent = action === "start" ? "Waiting for Windows approval…" : "Updating event collection…";
      try {
        if (action === "engine-start") {
          await api.postForm("/api/engine/control", { action: "start" });
          status.textContent = "Monitoring engine running. Start the optional collector to enable event tracking.";
          return;
        }
        const submitted = await api.postForm("/api/collector/control", {
          action, requestId: crypto.randomUUID().replaceAll("-", ""),
        });
        const until = performance.now() + 120000;
        while (!disposed && performance.now() < until) {
          const operation = await api.get(`/api/engine/operations/${submitted.operationId}`,
            { signal: requests.signal });
          if (operation.status === "failed") throw new Error(operation.error?.code || "Collector operation failed.");
          if (operation.status === "succeeded") {
            status.textContent = action === "events-start"
              ? "Event tracking enabled. Load retained evidence after activity occurs."
              : action === "events-stop" ? "Event tracking stopped. Retained history remains available."
                : "Collector running. Enable event tracking when ready.";
            if (operation.audit?.recorded === false)
              status.textContent += " Command audit could not be fully retained.";
            return;
          }
          await new Promise((resolve) => setTimeout(resolve, 400));
        }
        throw new Error(`Operation ${submitted.operationId} is still pending.`);
      } catch (error) {
        if (!disposed) status.textContent = error.message || "Collector operation failed.";
      } finally { if (!disposed) buttons.forEach((button) => { button.disabled = false; }); }
    }
    const controlButton = (label, action) => {
      const button = h("button", { class: "btn btn-outline", type: "button",
        onclick: () => { void control(action); } }, label);
      buttons.push(button);
      return button;
    };
    const endpoint = (value) => !value ? "unknown" :
      `${value.address.includes(":") ? `[${value.address}]` : value.address}:${value.port}`;
    const load = h("button", { class: "btn btn-outline", type: "button",
      onclick: async () => {
        load.disabled = true;
        try {
          const query = cursor ? `&cursor=${encodeURIComponent(cursor)}` : "";
          const page = await api.get(`/api/engine/lifecycle?limit=30${query}`,
            { signal: requests.signal });
          if (disposed) return;
          cursor = page.nextCursor || "";
          clear(history);
          for (const item of page.items || []) {
            if (seen.has(item.eventId)) continue;
            if (seen.size >= 2048) seen.delete(seen.values().next().value);
            seen.add(item.eventId);
            history.append(h("article", { class: "lifecycle-event" },
              h("header", {}, badge({ variant: "outline" }, item.kind || "Unknown event"),
                item.derived?.flowGeneration ? badge({ variant: "secondary" }, `Flow ${item.derived.flowGeneration}`) : null,
                item.derived?.lateArrival ? badge({ variant: "warning" }, "Late") : null,
                item.derived?.incompleteChronology ? badge({ variant: "warning" }, "Incomplete chronology") : null,
                h("strong", {}, item.process?.imagePath || (item.process ? `PID ${item.process.pid}` : "Collector coverage"))),
              h("p", {}, item.sourceEndpoint && item.destinationEndpoint
                ? `Source ${endpoint(item.sourceEndpoint)} → destination ${endpoint(item.destinationEndpoint)}`
                : item.reason || "No network tuple in this event"),
              item.derived?.local && item.derived?.remote
                ? h("p", { class: "muted text-sm" },
                  `Source-based roles: ${endpoint(item.derived.local)} ↔ ${endpoint(item.derived.remote)} (${item.derived.direction || "direction unknown"})`)
                : null,
              h("p", { class: "muted text-sm" }, item.receivedUtcMs
                ? `Received ${new Date(Number(item.receivedUtcMs)).toLocaleString()}; ${item.process?.creationTimeFileTime
                  ? `verified process instance (PID ${item.process.pid})`
                  : `identity unverified: ${item.process?.identityReason || "unknown"}`}`
                : item.occurredAtUtc || "Time unknown"),
              h("details", {}, h("summary", {}, "Source evidence"),
                h("pre", { class: "lifecycle-evidence" }, JSON.stringify(item, null, 2)))));
          }
          if (!history.childNodes.length) history.append(h("p", { class: "muted text-sm" },
            "No additional retained lifecycle evidence in this page."));
          load.textContent = "Next events page";
        } catch (error) {
          if (!disposed) {
            if (error.status === 410) { cursor = ""; seen.clear(); }
            status.textContent = error.status === 410
              ? "Older records rotated out. Load again from the first retained page."
              : error.message || "Lifecycle history unavailable.";
          }
        } finally { if (!disposed) load.disabled = false; }
      },
    }, "Load retained events");
    return h("div", { class: "tab-panel-body" },
      card({}, cardHeader({}, cardTitle({}, "Event-based connection evidence"),
        cardDescription({}, "Optional metadata collection can retain activity between endpoint snapshots.")),
        cardContent({}, h("p", { class: "muted text-sm" },
          "This experimental view preserves decoded source events and their derived flow correlations. Verified identities and mapped times are included when available. Source-based endpoint roles and incomplete chronology are marked explicitly; these records cannot authorize automated restrictions."),
          h("div", { class: "template-actions" },
            controlButton("Start engine", "engine-start"),
            controlButton("Start collector (UAC)", "start"),
            controlButton("Enable event tracking", "events-start"),
            controlButton("Stop event tracking", "events-stop")), status)),
      card({}, cardHeader({}, cardTitle({}, "Retained lifecycle history")),
        cardContent({}, history), cardFooter({}, load)));
  }

  async function renderEngine() {
    const status = h("div", { class: "engine-status", role: "status" }, "Checking engine…");
    const events = h("div", { class: "engine-events" });
    const persisted = h("div", { class: "engine-events" },
      h("p", { class: "muted text-sm" }, "Load a page to inspect bounded history retained across engine restarts."));
    let historyCursor = "";
    const historyNext = h("button", { class: "btn btn-outline", type: "button",
      onclick: async () => {
        historyNext.disabled = true;
        try {
          const query = historyCursor
            ? `?limit=20&cursor=${encodeURIComponent(historyCursor)}` : "?limit=20";
          const page = await api.get(`/api/engine/history${query}`);
          if (disposed) return;
          historyCursor = page.nextCursor || "";
          clear(persisted);
          const items = Array.isArray(page.items) ? page.items : [];
          if (!items.length) {
            persisted.append(h("p", { class: "muted text-sm" },
              "No more persisted observations in this page."));
          } else {
            const list = h("ul", { class: "engine-event-list" });
            for (const item of items) {
              list.append(h("li", { class: "engine-event-row" },
                h("span", { class: "badge badge-outline" }, item.kind || "unknown"),
                h("span", { class: "engine-event-target", title: item.process?.imagePath || "" },
                  item.process?.imagePath || `PID ${item.process?.pid ?? "unknown"}`),
                h("span", { class: "muted" }, item.remote?.address
                  ? `${item.remote.address}:${item.remote.port}` : "No remote peer observed"),
                h("time", { class: "muted", datetime: item.occurredAtUtc || "" },
                  item.occurredAtUtc ? new Date(item.occurredAtUtc).toLocaleString() : "Time unknown")));
            }
            persisted.append(list);
          }
          historyNext.textContent = "Next persisted page";
        } catch (error) {
          if (disposed) return;
          if (error.status === 410) historyCursor = "";
          persisted.textContent = error.status === 410
            ? "Older records rotated out. Load again from the first retained page."
            : (error.message || "Persisted history is unavailable.");
          historyNext.textContent = "Load first persisted page";
        } finally {
          if (!disposed) historyNext.disabled = false;
        }
      },
    }, "Load first persisted page");
    const configStatus = h("p", { class: "muted text-sm", role: "status" });
    let configRevision = "";
    let intervalInput;
    let recordsInput;
    let bytesInput;
    const save = h("button", { class: "btn btn-outline", type: "submit" }, "Save engine settings");
    const configForm = h("form", { class: "engine-config-form", onsubmit: async (event) => {
      event.preventDefault();
      if (!configRevision || save.disabled) return;
      save.disabled = true;
      configStatus.textContent = "Saving…";
      try {
        const submitted = await api.postForm("/api/engine/config", {
          requestId: crypto.randomUUID().replaceAll("-", ""),
          expectedRevision: configRevision,
          snapshotIntervalMs: intervalInput.value,
          maxEventRecords: recordsInput.value,
          maxEventBytes: bytesInput.value,
        });
        let operation;
        for (let attempt = 0; attempt < 12; attempt++) {
          operation = await api.get(`/api/engine/operations/${submitted.operationId}`);
          if (operation.status === "succeeded" || operation.status === "failed") break;
          await new Promise((resolve) => setTimeout(resolve, 200));
        }
        if (operation?.status !== "succeeded") {
          throw new Error(operation?.error?.code || "Save is still pending; refresh to check its result.");
        }
        if (!disposed) {
          await load();
          configStatus.textContent = operation.result?.restartRequired
            ? "Saved. Restart the engine to apply these settings."
            : "Settings saved; no restart needed.";
        }
      } catch (error) {
        if (!disposed) configStatus.textContent = error.message || "Could not save settings.";
      } finally {
        if (!disposed) save.disabled = false;
      }
    } },
      h("label", {}, "Snapshot interval (ms)", h("input", {
        type: "number", min: "250", max: "60000", required: true,
        ref: (element) => { intervalInput = element; },
      })),
      h("label", {}, "Maximum live records", h("input", {
        type: "number", min: "1", max: "50000", required: true,
        ref: (element) => { recordsInput = element; },
      })),
      h("label", {}, "Maximum live bytes", h("input", {
        type: "number", min: "1048576", max: "67108864", required: true,
        ref: (element) => { bytesInput = element; },
      })), save);
    save.disabled = true;
    const refresh = h("button", {
      class: "btn btn-outline", type: "button", onclick: () => { void load(); },
    }, "Refresh");
    const controlStatus = h("p", { class: "muted text-sm", role: "status" });
    async function controlEngine(action) {
      start.disabled = true;
      stop.disabled = true;
      controlStatus.textContent = action === "start" ? "Starting engine…" : "Stopping engine…";
      try {
        await api.postForm("/api/engine/control", { action });
        if (!disposed) {
          controlStatus.textContent = action === "start"
            ? "Engine started as your current user." : "Engine stopped.";
          await load();
        }
      } catch (error) {
        if (!disposed) controlStatus.textContent = error.message || "Engine control failed.";
      } finally {
        if (!disposed) { start.disabled = false; stop.disabled = false; }
      }
    }
    const start = h("button", { class: "btn btn-outline", type: "button",
      onclick: () => { void controlEngine("start"); } }, "Start engine");
    const stop = h("button", { class: "btn btn-quiet", type: "button",
      onclick: () => { if (confirm("Stop monitoring? Saved recipes remain, but no new events will be collected."))
        void controlEngine("stop"); } }, "Stop engine");
    const host = h("div", { class: "tab-panel-body" },
      card({},
        cardHeader({},
          cardTitle({}, "Monitoring engine"),
          cardDescription({},
            "The optional per-user process keeps sampled endpoint history while this page and the native window are closed."),
        ),
        cardContent({}, status,
          h("div", { class: "template-actions" }, start, stop), controlStatus,
          h("p", { class: "muted text-sm" },
            "Runs without administrator rights. It remains active when the browser closes; starting the Web UI alone does not start it."),
          h("p", { class: "muted text-sm" },
            "A snapshot sighting does not prove a connection attempt, failure, or denial."),
          h("h3", {}, "Engine settings"),
          configForm, configStatus,
          h("h3", {}, "Recent live observations"), events,
          h("h3", {}, "Persisted observations"), persisted, historyNext,
        ),
        cardFooter({}, refresh),
      ),
    );
    async function load() {
      refresh.disabled = true;
      try {
        const current = await api.get("/api/engine", { signal: requests.signal });
        const history = await api.get("/api/engine/events?limit=20", { signal: requests.signal });
        const config = await api.get("/api/engine/config", { signal: requests.signal });
        if (disposed) return;
        configRevision = config.revision;
        intervalInput.value = config.snapshotIntervalMs;
        recordsInput.value = config.maxEventRecords;
        bytesInput.value = config.maxEventBytes;
        save.disabled = false;
        if (config.restartRequired)
          configStatus.textContent = "Saved settings will apply after an engine restart.";
        const snapshot = current.capabilities?.find((capability) => capability.id === "snapshots");
        clear(status);
        status.append(
          badge({ variant: snapshot?.available ? "success" : "warning" },
            snapshot?.available ? "Running" : "Degraded"),
          h("span", {}, `${current.samples || "0"} samples · ${current.eventsRetained || 0} retained events`),
          h("span", { class: "muted text-sm" },
            snapshot?.lastSampleUtc ? `Last sample: ${new Date(snapshot.lastSampleUtc).toLocaleString()}`
              : snapshot?.reason || "Waiting for first sample"),
        );
        clear(events);
        const items = Array.isArray(history.items) ? history.items : [];
        if (!items.length) {
          events.append(h("p", { class: "muted text-sm" }, "No observations retained yet."));
        } else {
          const list = h("ul", { class: "engine-event-list" });
          for (const item of items.slice().reverse()) {
            const peer = item.remote?.address
              ? `${item.remote.address}:${item.remote.port}` : "No remote peer observed";
            list.append(h("li", { class: "engine-event-row" },
              h("span", { class: "badge badge-outline" }, item.kind || "unknown"),
              h("span", { class: "engine-event-target", title: item.process?.imagePath || "" },
                item.process?.imagePath || `PID ${item.process?.pid ?? "unknown"}`),
              h("span", { class: "muted" }, peer),
              h("time", { class: "muted", datetime: item.occurredAtUtc || "" },
                item.occurredAtUtc ? new Date(item.occurredAtUtc).toLocaleTimeString() : "Time unknown"),
            ));
          }
          events.append(list);
        }
      } catch (error) {
        if (disposed || requests.signal.aborted) return;
        clear(status);
        status.append(badge({ variant: "muted" }, "Stopped"),
          h("span", {}, "The optional monitoring engine is unavailable."));
        configRevision = "";
        save.disabled = true;
        clear(events);
        events.append(h("p", { class: "muted text-sm" },
          "Start the engine to collect new snapshot observations."));
      } finally {
        if (!disposed) refresh.disabled = false;
      }
    }
    await load();
    return host;
  }

  // ---- Scripts tab workbench ----
  async function renderScripts() {
    // Load config + templates on first entry.
    if (!scriptsState.config) {
      try {
        scriptsState.config = await api.get("/api/config", { signal: requests.signal });
        if (disposed) return h("div");
        scriptsState.templates = [];
        const td = await api.get("/api/templates", { signal: requests.signal });
        if (disposed) return h("div");
        scriptsState.templates = Array.isArray(td) ? td : Array.isArray(td.templates) ? td.templates : [];
      } catch (err) {
        if (disposed) return h("div");
        scriptsState.config = { scripts: [], version: 2 };
      }
    }

    const host = h("div", { class: "tab-panel-body" });

    // Workbench header
    host.append(card({},
      cardHeader({},
        cardTitle({}, "Script workbench"),
        cardDescription({},
          "Inspect any built-in template, create editable copies, or manage your local script library. " +
          "Scripts invoke only the sibling wintcp.exe CLI using separate arguments: no shell, " +
          "PowerShell, JavaScript evaluation, or network requests."),
      ),
      cardContent({},
        h("div", { class: "script-workspace" },
          h("aside", { class: "script-library", "aria-label": "Automation script library" },
            h("label", { class: "search-box" },
              h("span", { "aria-hidden": "true" }, "⌕"),
              h("input", {
                type: "search",
                placeholder: "Find a template or script…",
                autocomplete: "off",
                "aria-label": "Search scripts and templates",
                oninput: (e) => filterScriptLibrary(e.target.value),
              }),
            ),
            h("h3", {}, "My scripts ", h("span", { class: "num" }, String(getSavedScripts().length))),
            h("div", { id: "my-script-list", class: "script-list" },
              renderScriptLibrary(getSavedScripts(), scriptsState)),
            h("h3", {}, "Built-in templates"),
            h("div", { id: "script-template-list", class: "script-list" },
              renderTemplateLibrary(scriptsState.templates, scriptsState)),
          ),
          h("div", { class: "script-editor" },
            h("div", { class: "script-editor-head" },
              h("div", {},
                h("label", { for: "script-name" }, "Script name"),
                 h("input", {
                   id: "script-name",
                   type: "text",
                   maxlength: 120,
                   placeholder: "Name this editable script",
                   value: scriptsState.editName,
                   ref: (el) => { nameInput = el; },
                   onchange: (e) => { scriptsState.editName = e.target.value; },
                   oninput: (e) => { scriptsState.editName = e.target.value; },
                 }),
              ),
              h("span", { id: "script-source-badge", class: "planned-badge" },
                scriptsState.currentTemplateId === "CUSTOM"
                  ? "Custom local CLI script"
                  : `${scriptsState.currentTemplateId} · editable CLI copy`),
            ),
            h("label", { for: "automation-content" }, "WinTCP Script source"),
            h("textarea", {
              id: "automation-content",
              ref: (el) => { editorEl = el; },
              spellcheck: "false",
              autocapitalize: "off",
              autocomplete: "off",
              autocorrect: "off",
              rows: 12,
              "aria-describedby": "script-validation",
              placeholder: "Choose a template, paste a script, or start a new draft.",
              value: scriptsState.editSource,
              oninput: (e) => { scriptsState.editSource = e.target.value; },
            }),
            h("div", { class: "script-toolbar" },
              h("button", {
                id: "script-validate",
                class: "btn btn-sm",
                type: "button",
                onclick: validateAndShow,
              }, "Validate"),
              h("button", {
                id: "script-run",
                class: "btn btn-primary btn-sm",
                type: "button",
                onclick: () => runCurrentScript(),
              }, "Run script"),
              h("button", {
                id: "script-copy",
                class: "btn btn-sm",
                type: "button",
                onclick: copyCurrentScript,
              }, "Copy source"),
              h("button", {
                id: "script-import-file",
                class: "btn btn-sm",
                type: "button",
                onclick: () => document.getElementById("script-file").click(),
              }, "Import file"),
              h("input", {
                id: "script-file",
                type: "file",
                accept: ".wtscript,.txt,text/plain",
                hidden: true,
                onchange: (e) => importScriptFile(e.target.files?.[0]),
              }),
              h("button", {
                id: "script-export",
                class: "btn btn-sm",
                type: "button",
                onclick: exportCurrentScript,
              }, "Export script"),
              h("button", {
                id: "script-save",
                class: "btn btn-primary btn-sm",
                type: "button",
                onclick: () => saveManagedScript(),
              }, "Save script"),
              h("button", {
                id: "script-remove",
                class: "btn btn-danger btn-sm",
                type: "button",
                disabled: !scriptsState.currentScriptId,
                onclick: () => removeManagedScript(),
              }, "Remove"),
            ),
           h("p", {
             id: "script-validation",
             class: "script-validation",
             "role": "status",
             "aria-live": "polite",
             ref: (el) => { validationEl = el; },
           },
             getValidationText()),
          ),
        ),
      ),
    ));

    // Console: execution trace, variables, history
    host.append(card({},
      cardHeader({},
        cardTitle({}, "Run results & debugger"),
        cardDescription({},
          "Review every command, exit code, captured output, and variable value from the last run."),
      ),
      cardContent({},
        h("div", { class: "script-run-status-line" },
           h("span", {
             id: "script-run-status",
             class: "catalog-badge",
             "role": "status",
             "aria-live": "polite",
             ref: (el) => { runStatusEl = el; },
           },
             scriptsState.scriptRun.status),
          h("button", {
            id: "script-clear-output",
            class: "btn btn-sm btn-quiet",
            type: "button",
            onclick: clearScriptResults,
          }, "Clear results"),
        ),
        h("div", { class: "script-debug-grid" },
          h("section", { class: "script-debug-pane" },
            h("h3", {}, "Execution trace"),
            h("ol", {
              id: "script-step-list",
              class: "script-step-list",
              ref: (el) => { stepListEl = el; },
            },
              renderStepList(scriptsState.scriptRun.steps)),
          ),
          h("section", { class: "script-debug-pane" },
            h("h3", {}, "Variables"),
            h("div", {
              id: "script-variable-list",
              class: "script-variable-list",
              ref: (el) => { variableListEl = el; },
            },
              renderVariables(scriptsState.scriptRun.variables, scriptsState.scriptRun.steps)),
          ),
        ),
        h("section", { class: "script-run-history-block" },
          h("h3", {}, "Recent runs"),
          h("div", {
            id: "script-run-history",
            class: "script-run-history",
            ref: (el) => { runHistoryEl = el; },
          },
            renderRunHistory(scriptsState.config)),
        ),
      ),
      cardFooter({},
        h("details", { class: "script-raw-output" },
          h("summary", {}, "Combined stdout / stderr"),
          h("pre", {
            id: "script-output",
            ref: (el) => { outputEl = el; },
          }, scriptsState.scriptRun.output || "No command output yet."),
        ),
      ),
    ));

    return host;
  }

  // -- Script library / templates --
  function getSavedScripts() {
    if (!scriptsState.config) return [];
    return Array.isArray(scriptsState.config.scripts) ? scriptsState.config.scripts : [];
  }

  function renderScriptLibrary(scripts, state) {
    if (!scripts.length) {
      return h("div", { class: "empty-state" },
        "No saved scripts yet. Open one of the built-in templates or create a custom script.");
    }
    const list = h("div");
    for (const item of scripts) {
      const template = state.templates.find((t) => t.id === item.templateId);
      const label = !item.templateId || item.templateId === "CUSTOM"
        ? "Custom CLI script"
        : `${item.templateId} CLI script`;
      list.append(h("button", {
        class: "script-list-item",
        type: "button",
        onclick: () => openSavedScript(item, state),
      },
        h("span", {},
          h("strong", {}, item.name || "(unnamed)"),
          h("small", {}, `${label} · local source`),
        ),
        h("span", { "aria-hidden": "true" }, "›"),
      ));
    }
    return list;
  }

  function renderTemplateLibrary(templates, state) {
    if (!templates.length) {
      return h("div", { class: "empty-state" }, "Templates are loading…");
    }
    const list = h("div");
    for (const template of templates) {
      list.append(h("button", {
        class: "script-list-item",
        type: "button",
        onclick: (e) => { e.preventDefault(); loadTemplateScript(template, true, state); },
      },
        h("span", {},
          h("strong", {}, template.id + " · " + (template.title || template.name || "(unnamed)")),
          h("small", {}, `${template.category || "template"} · local CLI playbook`),
        ),
        h("span", { "aria-hidden": "true" }, "›"),
      ));
    }
    return list;
  }

  function filterScriptLibrary(query) {
    const q = query.toLowerCase().trim();
    const saved = getSavedScripts().filter((item) =>
      `${item.name || ""} ${item.templateId || ""} ${item.content || ""}`.toLowerCase().includes(q));
    const templates = scriptsState.templates.filter((t) =>
      `${t.id || ""} ${t.category || ""} ${t.title || ""} ${t.summary || ""} ${t.script || ""}`.toLowerCase().includes(q));
    const savedList = page.querySelector("#my-script-list");
    const tmplList = page.querySelector("#script-template-list");
    if (savedList) {
      clear(savedList);
      savedList.append(renderScriptLibrary(saved, scriptsState));
    }
    if (tmplList) {
      clear(tmplList);
      tmplList.append(renderTemplateLibrary(templates, scriptsState));
    }
  }

  function openSavedScript(item, state) {
    const template = state.templates.find((t) => t.id === item.templateId) || null;
    state.currentScriptId = item.id;
    state.currentTemplateId = item.templateId || "CUSTOM";
    state.editName = item.name || "";
    state.editSource = item.content || "";
    state._template = template;
    setScriptSourceBadge(template, true);
  }

  function setScriptSourceBadge(template, editable) {
    const badge = page.querySelector("#script-source-badge");
    if (!badge) return;
    if (!template) {
      badge.textContent = editable ? "Custom local CLI script" : "No script selected";
      badge.className = "planned-badge";
    } else {
      badge.textContent = editable
        ? `${template.id} · editable CLI copy`
        : `${template.id} · built-in CLI script`;
      badge.className = "ready-badge";
    }
  }

  function getValidationText() {
    if (!scriptsState.editSource) return "Choose a template or write a script.";
    try {
      const parsed = parseScript(scriptsState.editSource);
      return `Valid · ${parsed.commands} local CLI call(s), ${parsed.statements} statement(s). No shell or JavaScript is evaluated.`;
    } catch (e) {
      return e.message;
    }
  }

  function validateAndShow() {
    try {
      const parsed = parseScript(scriptsState.editSource);
      statusEl = page.querySelector(".script-status");
      const v = page.querySelector("#script-validation");
      if (v) {
        v.textContent = `Valid · ${parsed.commands} local CLI call(s), ${parsed.statements} statement(s). No shell or JavaScript is evaluated.`;
        v.className = "script-validation is-valid";
      }
      return parsed;
    } catch (error) {
      const v = page.querySelector("#script-validation");
      const removeBtn = page.querySelector("#script-remove");
      if (v) {
        v.textContent = error.message;
        v.className = "script-validation is-invalid";
      }
      if (removeBtn) removeBtn.disabled = !scriptsState.currentScriptId;
      return null;
    }
  }

  // -- Script save/remove --
  async function saveManagedScript() {
    const parsed = validateAndShow();
    if (!parsed) return;
    const name = (scriptsState.editName || "").trim();
    if (!name || name.length > 120) {
      alert("Enter a name with 1 to 120 characters.");
      return;
    }
    const content = scriptsState.editSource;
    const templateId = scriptsState.currentTemplateId || "CUSTOM";
    const existing = (scriptsState.config.scripts || []).find(
      (item) => item.id === scriptsState.currentScriptId,
    );
    const record = existing ? {
      ...existing, templateId, name, content, updatedAt: new Date().toISOString(),
    } : {
        id: crypto.randomUUID(),
        templateId,
        name,
        content,
        ruleId: "",
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
    // Persist to server config.
    try {
      scriptsState.config = await api.updateConfig((current) => {
        const scripts = [...(current.scripts || [])];
        const index = scripts.findIndex((item) => item.id === record.id);
        if (existing && index < 0) throw new Error("This script was removed in another session. Save it as a new script instead.");
        if (index >= 0) scripts[index] = { ...scripts[index], templateId, name, content, updatedAt: record.updatedAt };
        else {
          if (scripts.length >= MAX_SAVED_SCRIPTS) throw new Error("Script library is full. Remove a saved script before adding another.");
          scripts.push(record);
        }
        return { ...current, scripts };
      });
      scriptsState.currentScriptId = record.id;
      scriptsState.currentTemplateId = templateId;
      if (disposed) return;
      const v = page.querySelector("#script-validation");
      if (v) v.textContent = `Saved locally · ${templateId} · ${timeText(record.updatedAt)}.`;
      const savedList = page.querySelector("#my-script-list");
      if (savedList) {
        clear(savedList);
        savedList.append(renderScriptLibrary(getSavedScripts(), scriptsState));
      }
      renderSaveState();
    } catch (err) {
      const v = page.querySelector("#script-validation");
      if (v) v.textContent = `Save failed: ${err.message}`;
    }
  }

  async function removeManagedScript() {
    if (!scriptsState.currentScriptId) return;
    if (!confirm("Remove this saved script from My scripts? Built-in templates are not affected.")) return;
    const removedId = scriptsState.currentScriptId;
    try {
      scriptsState.config = await api.updateConfig((current) => ({
        ...current, scripts: (current.scripts || []).filter((item) => item.id !== removedId),
      }));
      if (disposed) return;
      scriptsState.currentScriptId = "";
      scriptsState.currentTemplateId = "CUSTOM";
      scriptsState.editName = "";
      scriptsState.editSource = STARTER_SCRIPT;
      setScriptSourceBadge(null, true);
      const savedList = page.querySelector("#my-script-list");
      if (savedList) {
        clear(savedList);
        savedList.append(renderScriptLibrary(getSavedScripts(), scriptsState));
      }
      renderSaveState();
    } catch (err) {
      console.warn("could not persist script removal", err);
    }
  }

  function copyCurrentScript() {
    const text = scriptsState.editSource || "";
    if (!text.trim()) {
      alert("Choose a template or paste WinTCP Script source first.");
      return;
    }
    try {
      navigator.clipboard.writeText(text);
      alert("Source copied to clipboard.");
    } catch {
      editorEl?.focus();
      editorEl?.select();
      alert("Clipboard unavailable. The script source is selected; press Ctrl+C to copy it.");
    }
  }

  function importScriptFile(file) {
    if (!file) return;
    if (file.size > 8192) {
      alert("WinTCP Script files are limited to 8 KiB.");
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      const text = reader.result;
      scriptsState.editSource = text;
      scriptsState.currentScriptId = "";
      scriptsState.currentTemplateId = "CUSTOM";
      scriptsState.editName = (file.name || "Imported script")
        .replace(/\.(wtscript|txt)$/i, "")
        .slice(0, 120);
      setScriptSourceBadge(null, true);
      validateAndShow();
    };
    reader.readAsText(file);
  }

  function exportCurrentScript() {
    if (!validateAndShow()) return;
    const source = scriptsState.editSource || "";
    const blob = new Blob(
      [source.endsWith("\n") ? source : `${source}\n`],
      { type: "text/plain;charset=utf-8" },
    );
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    const safeName = (scriptsState.editName || "automation")
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "") || "automation";
    link.download = `wintcp-${safeName}.wtscript`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    alert("A validated WinTCP Script source file was downloaded.");
  }

  // -- Script execution --
  async function runCurrentScript() {
    if (scriptsState.scriptRun.running) return;
    try {
      var parsed = parseScript(scriptsState.editSource);
    } catch (error) {
      const v = page.querySelector("#script-validation");
      if (v) {
        v.textContent = error.message;
        v.className = "script-validation is-invalid";
      }
      return;
    }

    // Check for sensitive commands and confirm.
    const sens = scriptCommandNodes(parsed.program).filter((node) =>
      isSensitiveCli([node.verb, ...node.args]));
    if (sens.length) {
      const exact = sens.map((node) => `  ${scriptCommandDisplay(node)}`).join("\n");
      if (!confirm(
        `This script includes local commands that can change firewall, process, ` +
        `capture, bookmark, preset, or alert state, or write output files.\n\n` +
        `Review the exact command(s):\n\n${exact}\n\nContinue? Each action ` +
        `receives a separate one-use permit.`,
      )) {
        scriptsState.scriptRun.status = "Cancelled before execution";
        renderRunState();
        return;
      }
    }

    scriptsState.scriptRun = {
      running: true,
      variables: Object.create(null),
      steps: [],
      output: "",
      status: "Running",
      failed: false,
      stepsExecuted: 0,
    };
    renderRunState();

    try {
      await executeScriptNodes(
        parsed.program,
        scriptsState.scriptRun.variables,
        scriptsState.scriptRun,
      );
      scriptsState.scriptRun.status = "Completed";
      scriptsState.scriptRun.failed = false;
      scriptsState.scriptRun.steps.push({
        kind: "done",
        line: 0,
        title: "Script completed",
        detail: `${scriptsState.scriptRun.steps.length} trace entries`,
      });
    } catch (error) {
      scriptsState.scriptRun.status = "Stopped · error";
      scriptsState.scriptRun.failed = true;
      scriptsState.scriptRun.steps.push({
        kind: "error",
        line: 0,
        title: "Script stopped",
        detail: error.message,
      });
      scriptsState.scriptRun.output += `[script error] ${error.message}\n`;
      const v = page.querySelector("#script-validation");
      if (v) {
        v.textContent = error.message;
        v.className = "script-validation is-invalid";
      }
      alert("Script stopped: " + error.message);
    } finally {
      scriptsState.scriptRun.running = false;
      renderRunState();
      recordScriptRun();
    }
  }

  async function executeScriptNodes(nodes, variables, run) {
    for (const node of nodes) {
      if (++run.stepsExecuted > MAX_STEPS)
        throw new Error("Execution stopped at the 100-step limit.");
      if (node.type === "if") {
        const passed = evaluateScriptCondition(node.condition, variables);
        run.steps.push({
          kind: "branch",
          line: node.line,
          title: `if ${node.condition.variable}.${node.condition.property} ${node.condition.operator} ${JSON.stringify(node.condition.value)}`,
          detail: passed ? "condition true" : "condition false",
        });
        await executeScriptNodes(passed ? node.then : (node.otherwise || []), variables, run);
      } else if (node.type === "set") {
        variables[node.name] = interpolateScript(node.value, variables);
        run.steps.push({
          kind: "set",
          line: node.line,
          title: `set ${node.name}`,
          detail: "string assigned",
        });
      } else if (node.type === "print") {
        const text = interpolateScript(node.value, variables);
        run.steps.push({
          kind: "print",
          line: node.line,
          title: "print",
          detail: text.slice(0, 220),
        });
        run.output += `${text}\n`;
      } else if (node.type === "command") {
        const args = node.args.map((v) => interpolateScript(v, variables));
        run.steps.push({
          kind: "command",
          line: node.line,
          title: scriptCommandDisplay({ verb: node.verb, args }),
          detail: "running sibling wintcp.exe",
        });
        const result = await runCliCommand(node.verb, args);
        variables[node.assign || "last"] = result;
        const outcome = result.timedOut ? "timed out" : `exit ${result.exitCode}`;
        const last = run.steps[run.steps.length - 1];
        if (last) last.detail = `${outcome} · ${result.durationMs} ms`;
        const outputBlock = [
          `$ ${scriptCommandDisplay({ verb: node.verb, args })}`,
          `exit ${result.exitCode} · ${result.durationMs} ms`,
          result.stdout ? `stdout:\n${result.stdout}` : "",
          result.stderr ? `stderr:\n${result.stderr}` : "",
          result.truncated ? "[captured output truncated]" : "",
        ].filter(Boolean).join("\n");
        run.output += `${outputBlock}\n\n`;
      }
      run.steps = run.steps.slice(-200);
    }
  }

  async function runCliCommand(verb, args) {
    const sensitive = isSensitiveCli([verb, ...args]);
    let nonce = "";
    if (sensitive) {
      const permit = await api.postForm("/api/cli/authorize", {
        verb,
        argc: String(args.length),
        ...Object.fromEntries(args.map((v, i) => [`arg${i}`, v])),
        confirmed: "1",
      });
      nonce = permit.nonce;
      if (!nonce) throw new Error("permit authorization failed: no nonce returned");
    }
    const form = {
      verb,
      argc: String(args.length),
      ...Object.fromEntries(args.map((v, i) => [`arg${i}`, v])),
    };
    if (nonce) form.nonce = nonce;
    return await api.postForm("/api/cli/run", form);
  }

  function renderRunState() {
    const run = scriptsState.scriptRun;
    if (runStatusEl) {
      runStatusEl.textContent = run.status;
      runStatusEl.className = `catalog-badge ${
        run.running ? "script-status-running" :
        run.failed ? "script-status-failed" :
        run.steps.length ? "script-status-done" : ""
      }`;
    }
    if (stepListEl) {
      clear(stepListEl);
      stepListEl.append(renderStepList(run.steps));
    }
    if (variableListEl) {
      clear(variableListEl);
      variableListEl.append(renderVariables(run.variables, run.steps));
    }
    if (outputEl) outputEl.textContent = run.output || "No command output yet.";
    const runEl = page.querySelector("#script-run");
    if (runEl) runEl.disabled = run.running;

    // Update validation badge to reflect run outcome.
    if (run.failed && run.steps.length > 0) {
      const v = page.querySelector("#script-validation");
      if (v) {
        v.textContent = scriptsState.scriptRun.steps
          .find((s) => s.kind === "error")?.detail || "Script stopped";
        v.className = "script-validation is-invalid";
      }
    }
  }

  function renderSaveState() {
    const removeBtn = page.querySelector("#script-remove");
    if (removeBtn) removeBtn.disabled = !scriptsState.currentScriptId;
  }

  function renderStepList(steps) {
    const ol = h("ol", { class: "script-step-list" });
    if (!steps.length) {
      ol.append(h("li", { class: "empty-state" }, "Run a script to see its steps."));
      return ol;
    }
    for (const step of steps) {
      const kindClass = `script-step script-step-${step.kind}`;
      ol.append(h("li", { class: kindClass },
        h("span", { class: "script-step-line" }, step.line ? `L${step.line}` : "RUN"),
        h("span", { class: "script-step-copy" },
          h("strong", {}, step.title),
          h("small", {}, step.detail || ""),
        ),
      ));
    }
    return ol;
  }

  function renderVariables(variables, steps) {
    const entries = Object.entries(variables);
    const list = h("div");
    if (!entries.length) {
      list.append(h("div", { class: "empty-state" },
        "Variables appear as steps assign them."));
      return list;
    }
    for (const [name, value] of entries) {
      const detail = value && typeof value === "object"
        ? `exit ${value.exitCode ?? "?"} · ${value.durationMs ?? 0} ms`
        : "string";
      const preview = value && typeof value === "object"
        ? `${value.stdout || ""}${value.stderr ? `\n[stderr] ${value.stderr}` : ""}`.slice(0, 1200)
        : String(value);
      list.append(h("article", { class: "script-variable" },
        h("div", {},
          h("strong", {}, name),
          h("small", {}, detail),
        ),
        h("pre", {}, preview || "(empty)"),
      ));
    }
    return list;
  }

  function renderRunHistory(config) {
    const box = h("div");
    const runs = Array.isArray(config?.scriptRuns) ? config.scriptRuns : [];
    if (!runs.length) {
      box.append(h("div", { class: "empty-state" },
        "No runs yet. Run a script and its outcome is recorded here, and survives a refresh."));
      return box;
    }
    for (const run of runs) {
      const when = timeText(run.ts);
      const exit = run.exit === null || run.exit === undefined ? "—" : String(run.exit);
      const cls = run.ok ? "is-ok" : "is-bad";
      const steps = run.steps === 1 ? "1 step" : `${run.steps} steps`;
      box.append(h("article", { class: `script-run-item ${cls}` },
        h("span", { class: "script-run-dot", "aria-hidden": "true" }),
        h("div", { class: "script-run-copy" },
          h("strong", {}, run.name || "(unnamed)"),
          h("small", {}, `${run.status || (run.ok ? "Completed" : "Stopped")} · exit ${exit} · ${steps} · ${when}`),
        ),
        h("small", { class: "script-run-template" }, run.templateId || "CUSTOM"),
      ));
    }
    return box;
  }

  function recordScriptRun() {
    const run = scriptsState.scriptRun;
    const name = (scriptsState.editName || "").trim() ||
      (scriptsState.currentTemplateId && scriptsState.currentTemplateId !== "CUSTOM"
        ? `${scriptsState.currentTemplateId} playbook`
        : "Untitled script");
    const exit = run.steps
      .filter((s) => s.kind === "command")
      .find((s) => /exit \d+/.test(s.detail || ""))
      ? Number(/exit (\d+)/.exec(run.steps
        .filter((s) => s.kind === "command")
        .find((s) => /exit \d+/.test(s.detail || ""))?.detail || "")?.[1])
      : null;
    const summary = {
      id: crypto.randomUUID(),
      ts: new Date().toISOString(),
      name,
      templateId: scriptsState.currentTemplateId || "CUSTOM",
      ok: !run.failed,
      status: run.status || (run.failed ? "Stopped · error" : "Completed"),
      exit,
      steps: run.steps.length,
    };
    const lastScriptRun = {
      ...summary,
      output: (run.output || "").slice(0, 6000),
    };
    // Persist to server config so history survives a refresh.
    api.updateConfig((current) => ({
      ...current,
      scriptRuns: [summary, ...(current.scriptRuns || []).filter((item) => item.id !== summary.id)].slice(0, 25),
      lastScriptRun,
    })).then((saved) => { scriptsState.config = saved; }).catch((err) =>
      console.warn("could not persist script run", err));
  }

  function clearScriptResults() {
    if (scriptsState.scriptRun.running) return;
    scriptsState.scriptRun = {
      running: false,
      variables: Object.create(null),
      steps: [],
      output: "",
      status: "Not run",
      failed: false,
      stepsExecuted: 0,
    };
    renderRunState();
  }

  // Initialize the editor content if starting fresh.
  if (!scriptsState.editSource) {
    scriptsState.editSource = STARTER_SCRIPT;
    scriptsState.editName = "New local script";
  }
}
