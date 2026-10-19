// pages/automations.js - Automations page.
//
// Three views with real panels: the template catalogue (40 templates, only the
// ones with an evaluator can actually run), the audit/event trail, and the
// script workbench where scripts are written, validated, run, and saved.
//
// The script engine (parseScript, executeScriptNodes, etc.) lives in
// js/scriptengine.js, extracted from the legacy dashboard so the language
// and its security bounds are the same everywhere.

import { h, clear } from "../h.js";
import { createTabs } from "../ui/tabs.js";
import { emptyState, card, cardHeader, cardTitle, cardDescription, cardContent, cardFooter } from "../ui/card.js";
import { badge } from "../ui/badge.js";
import { dialog } from "../ui/dialog.js";
import { api } from "../api.js";
import { isTemplateReady } from "../monitors.js";
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
  clear(page);
  page.append(
    h("div", { class: "page-heading" },
      h("div", {},
        h("h1", { class: "page-title" }, "Automations"),
        h("p", { class: "page-description" },
          "Monitor templates, the audit trail, and the script workbench"),
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
      { id: "scripts", label: "Scripts", render: renderScripts },
      { id: "events", label: "Events & audit", render: renderEvents },
    ],
  });
  layout.append(tabs.element);

  // Shared state for the Scripts tab workbench.
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
  page._autoDestroy = () => tabs.destroy();

  // ---- Templates tab ----
  async function renderTemplates() {
    let data;
    try {
      data = await api.get("/api/templates");
    } catch (err) {
      return emptyState({}, "Template catalogue unavailable", err.message);
    }
    const templates = Array.isArray(data) ? data : Array.isArray(data.templates) ? data.templates : [];
    if (templates.length === 0) {
      return emptyState({}, "No templates", "The catalogue file did not load.");
    }

    const ready = templates.filter((t) => isTemplateReady(t.id));
    const pending = templates.filter((t) => !isTemplateReady(t.id));

    const host = h("div", { class: "tab-panel-body" });

    host.append(h("p", { class: "muted text-sm proc-note" },
      `${ready.length} of ${templates.length} templates have an evaluator and can run today. ` +
      `The rest are prepared: the template exists, the capability it needs is not wired up, ` +
      `and WinTCP says so rather than accepting it and quietly doing nothing.`));

    host.append(h("h3", { class: "card-title", style: "margin-top: 1rem" },
      `Ready (${ready.length})`));
    if (ready.length === 0) {
      host.append(emptyState({}, "No template can run",
        "This build exposes the catalogue but no evaluator."));
    } else {
      host.append(templateCardList(ready, templates, scriptsState));
    }

    if (pending.length > 0) {
      host.append(h("h3", { class: "card-title", style: "margin-top: 1.5rem" },
        `Prepared, capability pending (${pending.length})`));
      host.append(templateCardList(pending, templates, scriptsState));
    }
    return host;
  }

  function templateCardList(templates, allTemplates, state) {
    const list = h("div", { class: "template-grid" });
    for (const t of templates) {
      const isReady = isTemplateReady(t.id);
      const cardEl = h("div", { class: "template-card", tabindex: 0 },
        h("div", { class: "template-card-head" },
          h("div", {},
            h("span", { class: "template-id num" }, `${t.id || "-"} · ${t.category || ""}`),
            h("h3", {}, t.title || "(unnamed)"),
          ),
          h("span", { class: isReady ? "ready-badge" : "planned-badge" },
            isReady ? "MONITOR READY" : "PREPARED"),
        ),
        t.summary ? h("p", {}, t.summary) : null,
        h("div", { class: "template-meta" },
          t.data ? h("span", { class: "muted text-sm" }, t.data) : null,
          t.risk ? h("span", { class: "muted text-sm" }, t.risk) : null,
        ),
        h("div", { class: "template-actions" },
          t.response ? h("small", { class: "template-response" }, t.response) : null,
          h("div", { class: "template-action-buttons" },
            h("button", {
              class: "btn btn-sm btn-quiet",
              type: "button",
              onclick: () => loadTemplateScript(t, true, state),
            }, "Open script"),
            h("button", {
              class: `btn btn-sm ${isReady ? "" : "btn-quiet"}`,
              type: "button",
              disabled: !isReady,
              onclick: () => addMonitorRule(t, state),
            }, isReady ? "Add monitor" : "No monitor evaluator"),
          ),
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

  function addMonitorRule(template, state) {
    // In the new UI, monitors are a config-level concept. For now, show a notice.
    // The legacy addRule() logic would go here when monitors are fully migrated.
    const d = dialog({
      class: "notice-dialog",
      "aria-label": "Monitor configuration",
    },
      h("p", {},
        `Template ${template.id} (${template.title}) is monitor-ready. ` +
        "Adding a monitor rule persists it to the local config and starts evaluation " +
        "on the next poll. This feature is being migrated to the control room."),
    );
    page.append(d);
    if (d.showModal) d.showModal();
  }

  // ---- Events & audit tab ----
  async function renderEvents() {
    let data;
    try {
      data = await api.get("/api/audit");
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
  async function renderScripts() {
    // Load config + templates on first entry.
    if (!scriptsState.config) {
      try {
        scriptsState.config = await api.get("/api/config");
        scriptsState.templates = [];
        const td = await api.get("/api/templates");
        scriptsState.templates = Array.isArray(td) ? td : Array.isArray(td.templates) ? td.templates : [];
      } catch (err) {
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
      `${t.id || ""} ${t.category || ""} ${t.title || ""} ${t.data || ""} ${t.script || ""}`.toLowerCase().includes(q));
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
    if (!Array.isArray(scriptsState.config.scripts)) scriptsState.config.scripts = [];
    let record = scriptsState.config.scripts.find(
      (item) => item.id === scriptsState.currentScriptId,
    );
    if (!record && scriptsState.config.scripts.length >= MAX_SAVED_SCRIPTS) {
      alert("Script library is full. Remove a saved script before adding another.");
      return;
    }
    if (record) {
      Object.assign(record, { templateId, name, content, updatedAt: new Date().toISOString() });
    } else {
      record = {
        id: crypto.randomUUID(),
        templateId,
        name,
        content,
        ruleId: "",
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      scriptsState.config.scripts.push(record);
    }
     scriptsState.currentScriptId = record.id;
    scriptsState.currentTemplateId = templateId;
    // Persist to server config.
    try {
       await api.post("/api/config", scriptsState.config);
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
    scriptsState.config.scripts = scriptsState.config.scripts.filter(
      (item) => item.id !== scriptsState.currentScriptId,
    );
     scriptsState.currentScriptId = "";
    scriptsState.currentTemplateId = "CUSTOM";
    scriptsState.editName = "";
    scriptsState.editSource = STARTER_SCRIPT;
    setScriptSourceBadge(null, true);
    try {
       await api.post("/api/config", scriptsState.config);
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
      ts: new Date().toISOString(),
      name,
      templateId: scriptsState.currentTemplateId || "CUSTOM",
      ok: !run.failed,
      status: run.status || (run.failed ? "Stopped · error" : "Completed"),
      exit,
      steps: run.steps.length,
    };
    if (!Array.isArray(scriptsState.config.scriptRuns)) scriptsState.config.scriptRuns = [];
    scriptsState.config.scriptRuns = [summary, ...scriptsState.config.scriptRuns].slice(0, 25);
    scriptsState.config.lastScriptRun = {
      ...summary,
      output: (run.output || "").slice(0, 6000),
    };
    // Persist to server config so history survives a refresh.
    api.post("/api/config", scriptsState.config).catch((err) =>
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
    };
    renderRunState();
  }

  // Initialize the editor content if starting fresh.
  if (!scriptsState.editSource) {
    scriptsState.editSource = STARTER_SCRIPT;
    scriptsState.editName = "New local script";
  }
}
