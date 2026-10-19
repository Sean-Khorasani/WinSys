import { api } from "./api.js";
import { h, clear } from "./h.js";
import { emptyState } from "./ui/card.js";
import { dialog, dialogContent, dialogDescription, dialogFooter, dialogHeader, dialogTitle, openDialog, closeDialog } from "./ui/dialog.js";
import { createVirtualTable } from "./ui/virtualtable.js";
import { createColumnLayoutControls } from "./ui/columnlayout.js";

export function normalizeFirewallInventory(data) {
  if (!data || typeof data !== "object" || !Array.isArray(data.rules)) {
    return { available: false, reason: "The firewall inventory response was invalid.", rules: [] };
  }
  const available = data.available === true;
  const activeProfileKnown = data.activeProfileKnown === true && Number.isInteger(data.activeProfileTypes);
  return {
    available,
    generatedAt: typeof data.generatedAt === "string" && Number.isFinite(Date.parse(data.generatedAt))
      ? data.generatedAt : null,
    reason: available ? null : String(data.reason || "Windows Firewall rules could not be read."),
    activeProfileTypes: activeProfileKnown ? data.activeProfileTypes : null,
    activeProfileReason: activeProfileKnown && data.activeProfileTypes !== 0
      ? null : String(data.activeProfileReason || (activeProfileKnown
        ? "Windows reported no active firewall profile." : "The active firewall profile is unknown.")),
    warnings: Array.isArray(data.warnings) ? data.warnings.filter((warning) => typeof warning === "string") : [],
    rules: available ? data.rules.filter((rule) => rule && typeof rule === "object").map((rule) => ({
      name: String(rule.name || ""),
      ownership: rule.ownership === "wintcp" ? "WinTCP-managed" : rule.ownership === "windows" ? "Windows-managed" : "Unknown",
      wintcpOwned: rule.ownership === "wintcp",
      enabled: typeof rule.enabled === "boolean" ? rule.enabled : null,
      blocking: typeof rule.blocking === "boolean" ? rule.blocking : null,
      direction: Number.isInteger(rule.direction) ? (rule.direction === 1 ? "Inbound" : rule.direction === 2 ? "Outbound" : `Unknown (${rule.direction})`) : null,
      action: Number.isInteger(rule.action) ? (rule.action === 0 ? "Block" : rule.action === 1 ? "Allow" : `Unknown (${rule.action})`) : null,
      protocol: Number.isInteger(rule.protocol) ? (rule.protocol === 6 ? "TCP" : rule.protocol === 17 ? "UDP" : rule.protocol === 256 ? "Any" : String(rule.protocol)) : null,
      profiles: Number.isInteger(rule.profiles) ? [rule.profiles & 1 ? "Domain" : "", rule.profiles & 2 ? "Private" : "", rule.profiles & 4 ? "Public" : ""].filter(Boolean).join(", ") || "None" : null,
      profileTypes: Number.isInteger(rule.profiles) ? rule.profiles : null,
      localAddresses: typeof rule.localAddrs === "string" ? rule.localAddrs : null,
      remoteAddresses: typeof rule.remoteAddrs === "string" ? rule.remoteAddrs : null,
      localPorts: typeof rule.localPorts === "string" ? rule.localPorts : null,
      remotePorts: typeof rule.remotePorts === "string" ? rule.remotePorts : null,
      application: typeof rule.application === "string" ? rule.application : null,
      service: typeof rule.service === "string" ? rule.service : null,
    })) : [],
  };
}

function scopedMatch(scope, value, kind) {
  if (scope == null || scope === "Unknown") return "unknown";
  const normalized = scope.trim().toLowerCase();
  if (normalized === "*" || normalized === "any") return "broad";
  if (!value) return "unknown";
  if (kind === "port") {
    const port = Number(value);
    if (!Number.isInteger(port)) return "unknown";
    let uncertain = false;
    for (const entry of normalized.split(",").map((part) => part.trim())) {
      const range = /^(\d+)-(\d+)$/.exec(entry);
      if (range) {
        if (port >= Number(range[1]) && port <= Number(range[2])) return "exact";
      } else if (/^\d+$/.test(entry)) {
        if (Number(entry) === port) return "exact";
      } else uncertain = true;
    }
    return uncertain ? "unknown" : "no";
  }
  if (kind === "address") {
    const entries = normalized.split(",").map((part) => part.trim());
    if (entries.includes(String(value).toLowerCase())) return "exact";
    if (entries.every((entry) => entry === "*" || entry === "any")) return "broad";
    return entries.every((entry) => /^(?:\d{1,3}\.){3}\d{1,3}$/.test(entry) || /^[0-9a-f:.%]+$/.test(entry))
      ? "no" : "unknown";
  }
  return normalized === String(value).trim().toLowerCase() ? "exact" : "no";
}

export function explainFirewallRuleMatch(rule, target, activeProfileTypes = null) {
  const proto = String(target?.proto || "").toUpperCase();
  const protocol = proto.startsWith("TCP") ? "TCP" : proto.startsWith("UDP") ? "UDP" : null;
  const direction = target?.direction === "Inbound" ? "Inbound" : "Outbound";
  const inbound = direction === "Inbound";
  const remoteScope = (scope, value, kind) => {
    if (!inbound || value != null) return scopedMatch(scope, value, kind);
    if (scope == null || scope === "Unknown") return "unknown";
    const normalized = scope.trim().toLowerCase();
    return normalized === "*" || normalized === "any" ? "broad" : "unknown";
  };
  const activeProfileMatch = Number.isInteger(activeProfileTypes) && activeProfileTypes > 0 &&
    Number.isInteger(rule.profileTypes)
    ? ((rule.profileTypes & activeProfileTypes) === 0 ? "no"
      : (rule.profileTypes & activeProfileTypes) === activeProfileTypes ? "exact" : "partial")
    : "unknown";
  const fields = [
    ["Direction", rule.direction === direction ? "exact" : rule.direction === (inbound ? "Outbound" : "Inbound") ? "no" : "unknown"],
    ["Protocol", rule.protocol === "Any" ? "broad" : protocol && rule.protocol === protocol ? "exact" : protocol ? "no" : "unknown"],
    ["Remote address", remoteScope(rule.remoteAddresses, target?.remote, "address")],
    ["Remote port", remoteScope(rule.remotePorts, target?.rport, "port")],
    ["Local address", scopedMatch(rule.localAddresses, target?.local, "address")],
    ["Local port", scopedMatch(rule.localPorts, target?.lport, "port")],
    ["Application", scopedMatch(rule.application, target?.path, "text")],
    ["Service", scopedMatch(rule.service, target?.service, "text")],
    ["Active profile", activeProfileMatch],
  ];
  const mismatch = fields.some(([, result]) => result === "no");
  const unknown = fields.some(([, result]) => result === "unknown");
  const partial = fields.some(([, result]) => result === "partial");
  const kind = mismatch ? "Does not match" : unknown || partial ? "Partial / unknown"
    : fields.every(([, result]) => result === "broad") ? "Broad candidate" : "Exact candidate";
  return {
    kind,
    candidate: !mismatch,
    explanation: fields.map(([label, result]) => `${label}: ${result}`).join("; "),
    caveat: "Candidate matching is not effective policy or proof of reachability.",
  };
}

function showRuleDetails(rule, openDialogs) {
  const detail = (label, value) => [h("dt", {}, label), h("dd", {}, value ?? "Unknown")];
  const view = dialog({ class: "details-dialog", "aria-labelledby": "firewall-rule-details-title" },
    h("form", { method: "dialog", class: "dialog-form" },
      h("div", { class: "dialog-header" },
        h("h2", { id: "firewall-rule-details-title", class: "dialog-title" }, "Firewall rule details"),
        h("button", { type: "submit", class: "btn btn-close btn-sm", "aria-label": "Close" }, "Close")),
      h("div", { class: "dialog-content" },
        h("p", { class: "muted text-sm" }, "Rule scope and configured state only; this does not evaluate effective policy or prove reachability."),
        h("dl", { class: "detail-list" },
          detail("Name", rule.name), detail("Ownership", rule.ownership),
          detail("Status", rule.status), detail("Direction", rule.direction),
          detail("Action", rule.action), detail("Protocol", rule.protocol),
          detail("Profiles", rule.profiles), detail("Local addresses", rule.localAddresses),
          detail("Remote addresses", rule.remoteAddresses), detail("Local ports", rule.localPorts),
          detail("Remote ports", rule.remotePorts), detail("Application", rule.application),
          detail("Service", rule.service),
          rule.match ? detail("Connection candidate", rule.match.kind) : null,
          rule.match ? detail("Compared scope", rule.match.explanation) : null,
          rule.match ? detail("Candidate limitation", rule.match.caveat) : null)),
      h("div", { class: "dialog-footer" },
        h("button", { type: "submit", class: "btn btn-outline btn-sm" }, "Done"))));
  document.body.append(view);
  if (openDialogs) {
    openDialogs.add(view);
    view.addEventListener("close", () => openDialogs.delete(view), { once: true });
  }
  openDialog(view);
}

export function createFirewallInventoryView({ target: initialTarget = null, ruleName: initialRuleName = null, onClearTarget = null } = {}) {
  let target = initialTarget;
  let exactRuleName = initialRuleName;
  const root = h("section", { class: "firewall-inventory" });
  const filter = h("input", {
    class: "input", type: "search", placeholder: "Filter firewall rules",
    "aria-label": "Filter firewall rules",
  });
  const refreshButton = h("button", {
    class: "btn btn-outline btn-sm", type: "button",
    onclick: () => refresh(),
  }, "Refresh rules");
  const createRuleButton = h("button", {
    class: "btn btn-primary btn-sm", type: "button",
    onclick: () => openCreateRuleEditor(),
  }, "Create rule");
  const clearTargetButton = target || exactRuleName ? h("button", {
    class: "btn btn-outline btn-sm", type: "button",
    onclick: () => {
      target = null;
      exactRuleName = null;
      onClearTarget?.();
      rows = rows.map((row) => ({ ...row, match: null, matchLabel: "" }));
      status.textContent = "Showing all rules subject to the current filter. Candidate matches are not effective policy or proof of reachability.";
      clearTargetButton.remove();
      updateTable();
    },
  }, "Show all rules") : null;
  const status = h("p", { class: "muted text-sm", role: "status", "aria-live": "polite" });
  const tableHost = h("div", { class: "firewall-inventory-table" });
  root.append(h("div", { class: "firewall-inventory-toolbar" }, filter, refreshButton, createRuleButton, clearTargetButton), status, tableHost);

  let rows = [];
  let table = null;
  let layoutControls = null;
  let requestController = null;
  let destroyed = false;
  let hasSuccessfulRead = false;
  let lastInventoryReadAt = null;
  const actionControllers = new Set();
  const openDialogs = new Set();

  function openCreateRuleEditor() {
    const field = (label, element) => h("label", { class: "firewall-rule-editor-field" },
      h("span", { class: "muted text-sm" }, label), element);
    const textInput = (name, value, placeholder = "") => h("input", {
      class: "input", name, value, placeholder, autocomplete: "off",
    });
    const selectInput = (name, options, value) => h("select", { class: "select", name, value },
      options.map(([optionValue, label]) => h("option", { value: optionValue }, label)));
    const direction = selectInput("direction", [["outbound", "Outbound"], ["inbound", "Inbound"]], "outbound");
    const action = selectInput("action", [["block", "Block"], ["allow", "Allow"]], "block");
    const protocol = selectInput("proto", [["tcp", "TCP"], ["udp", "UDP"], ["any", "Any"]], "tcp");
    const address = textInput("address", "*", "* or IP, list, CIDR");
    const localAddress = textInput("localAddress", "*", "* or local IP, list, CIDR");
    const localPorts = textInput("localPorts", "*", "* or port/list/range");
    const remotePorts = textInput("remotePorts", "*", "* or port/list/range");
    const process = textInput("process", "", "Full executable path (optional)");
    const service = textInput("service", "", "Windows service short name (optional)");
    const label = textInput("label", "", "Optional rule label");
    const profileInputs = [
      ["Domain", 1], ["Private", 2], ["Public", 4],
    ].map(([name, bit]) => h("label", { class: "firewall-rule-profile" },
      h("input", { type: "checkbox", name: "profiles", value: String(bit), checked: true }), name));
    const status = h("p", { class: "dialog-description", role: "status", "aria-live": "polite" },
      "Complete the rule scope, then preview the exact Windows Firewall plan.");
    const plan = h("pre", { class: "muted text-sm", hidden: true });
    const previewButton = h("button", { class: "btn btn-outline btn-sm", type: "button" }, "Preview rule");
    const footer = h("div", { class: "dialog-footer" },
      h("button", { class: "btn btn-outline btn-sm", type: "button", onclick: () => closeDialog(view) }, "Cancel"),
      previewButton);
    const form = h("form", { class: "dialog-form", onsubmit: (event) => event.preventDefault() },
      h("div", { class: "dialog-header" },
        h("h2", { id: "firewall-create-rule-title", class: "dialog-title" }, "Create firewall rule"),
        h("button", { type: "button", class: "btn btn-close btn-sm", "aria-label": "Close", onclick: () => closeDialog(view) }, "Close")),
      h("div", { class: "dialog-content" },
        h("p", { class: "muted text-sm" }, "Any is explicit. Port restrictions require TCP or UDP. Allow rules do not override matching block rules."),
        h("div", { class: "firewall-rule-editor-grid" },
          field("Direction", direction), field("Action", action), field("Protocol", protocol),
          field("Remote addresses", address), field("Local addresses", localAddress),
          field("Local ports", localPorts), field("Remote ports", remotePorts),
          field("Executable path", process), field("Service short name", service),
          field("Rule label", label),
          h("fieldset", { class: "firewall-rule-profiles" },
            h("legend", { class: "muted text-sm" }, "Profiles"), ...profileInputs)),
        status, plan),
      footer);
    const view = dialog({ class: "details-dialog action-preview-dialog", "aria-labelledby": "firewall-create-rule-title" }, form);
    const controller = new AbortController();
    let nonce = "";
    let submitted = false;
    let refreshAfterClose = false;
    form.addEventListener("input", (event) => event.target.removeAttribute("aria-invalid"));
    form.addEventListener("change", (event) => event.target.removeAttribute("aria-invalid"));
    previewButton.addEventListener("click", async () => {
      nonce = "";
      form.querySelectorAll('[aria-invalid="true"]').forEach((control) => control.removeAttribute("aria-invalid"));
      const values = new FormData(form);
      const selectedProfiles = values.getAll("profiles").map(Number).reduce((all, bit) => all | bit, 0);
      const rule = Object.fromEntries(["direction", "action", "proto", "address", "localAddress",
        "localPorts", "remotePorts", "process", "service", "label"].map((key) =>
        [key, String(values.get(key) || "").trim()]));
      if (!rule.address || !rule.localAddress || !rule.localPorts || !rule.remotePorts || selectedProfiles === 0) {
        status.textContent = "Remote/local addresses, both port scopes and at least one profile are required; use * for any.";
        return;
      }
      if (rule.proto === "any" && (rule.localPorts !== "*" || rule.remotePorts !== "*")) {
        status.textContent = "Protocol Any cannot be combined with port restrictions. Choose TCP or UDP, or set both ports to *.";
        return;
      }
      if (rule.process && !rule.process.includes("\\")) {
        status.textContent = "Application scope requires a full executable path, not a process name.";
        return;
      }
      if (rule.service && !/^[A-Za-z0-9_.-]{1,256}$/.test(rule.service)) {
        status.textContent = "Use a valid Windows service short name.";
        return;
      }
      previewButton.disabled = true;
      status.textContent = "Preparing the exact firewall rule preview…";
      try {
        const preview = await api.postForm("/api/firewall/rule/create/preview", {
          ...rule, profiles: String(selectedProfiles),
        }, { signal: controller.signal });
        if (destroyed || !view.isConnected) return;
        plan.textContent = preview.plan || "The server did not provide a rule plan.";
        plan.hidden = false;
        if (preview.canExecute !== true || typeof preview.nonce !== "string") {
          status.textContent = preview.reason || "The rule cannot be created in this session.";
          return;
        }
        nonce = preview.nonce;
        status.textContent = "Review every scope field and the generated rule identity before creating it.";
        const createButton = h("button", { class: "btn btn-destructive btn-sm", type: "button",
          onclick: async () => {
            if (!nonce || submitted) return;
            submitted = true;
            createButton.disabled = true;
            previewButton.disabled = true;
            status.textContent = "Creating the reviewed firewall rule and verifying its Windows Firewall read-back…";
            try {
              const outcome = await api.post("/api/firewall/rule/execute", { nonce }, { signal: controller.signal });
              if (destroyed || !view.isConnected) return;
              status.textContent = outcome.ok
                ? `Rule ${outcome.status === "already-present" ? "already existed" : "was created and verified"}: ${outcome.ruleName || outcome.name}.`
                : `Rule creation could not be verified: ${outcome.reason || outcome.status}.`;
              refreshAfterClose = true;
              createButton.remove();
            } catch (error) {
              if (error.name !== "AbortError" && !destroyed)
                status.textContent = `Rule creation failed: ${error.message}`;
              createButton.remove();
            }
          },
        }, "Create rule");
        footer.insertBefore(createButton, previewButton);
      } catch (error) {
        if (error.name !== "AbortError" && !destroyed) {
          const invalidField = error.body?.field;
          const fieldNames = { address: "Remote addresses", localAddress: "Local addresses",
            ports: "Port scopes", proto: "Protocol", process: "Executable path",
            service: "Service short name", profiles: "Profiles" };
          const controls = invalidField === "ports"
            ? [form.elements.namedItem("localPorts"), form.elements.namedItem("remotePorts")]
            : invalidField === "profiles"
              ? [...form.querySelectorAll('input[name="profiles"]')]
              : [form.elements.namedItem(invalidField)];
          const invalidControl = controls.find((control) => control instanceof HTMLElement);
          if (invalidControl) {
            invalidControl.setAttribute("aria-invalid", "true");
            invalidControl.focus();
          }
          const message = error.body?.message || error.message;
          status.textContent = fieldNames[invalidField]
            ? `${fieldNames[invalidField]}: ${message}`
            : `Could not prepare the rule: ${message}`;
        }
      } finally {
        if (!destroyed && view.isConnected && !nonce) previewButton.disabled = false;
      }
    });
    view.addEventListener("close", () => {
      controller.abort();
      openDialogs.delete(view);
      if (refreshAfterClose && !destroyed) refresh();
    }, { once: true });
    openDialogs.add(view);
    document.body.append(view);
    openDialog(view);
  }

  const filteredRows = () => {
    const query = filter.value.trim().toLowerCase();
    return rows.filter((row) => {
      if (exactRuleName && row.name.toLowerCase() !== exactRuleName.toLowerCase()) return false;
      if (target && !row.match?.candidate) return false;
      if (!query) return true;
      return [...Object.values(row)].some((value) => String(value ?? "").toLowerCase().includes(query));
    });
  };
  const updateTable = () => {
    if (table) table.updateRows(filteredRows(), "No firewall rules match this filter.");
  };
  filter.addEventListener("input", updateTable);

  async function reviewRuleAction(row, operation, opener) {
    const controller = new AbortController();
    actionControllers.add(controller);
    const finishController = () => actionControllers.delete(controller);
    try {
      status.textContent = "Preparing a current-rule review…";
      const preview = await api.post("/api/firewall/rule/preview", {
        name: row.name,
        operation,
      }, { signal: controller.signal });
      if (destroyed) return;
      const review = dialog({ "aria-labelledby": "firewall-rule-review-title" });
      const result = h("p", { class: "muted text-sm", role: "status", "aria-live": "polite" });
      const profileNames = Number.isInteger(preview.profiles)
        ? [[1, "Domain"], [2, "Private"], [4, "Public"]]
          .filter(([bit]) => preview.profiles & bit).map(([, name]) => name).join(", ") || "None"
        : "Unknown";
      const protocolName = Number.isInteger(preview.protocol)
        ? ({ 6: "TCP", 17: "UDP", 256: "Any" }[preview.protocol] || String(preview.protocol))
        : "Unknown";
      const directionName = preview.direction === 1 ? "Inbound"
        : preview.direction === 2 ? "Outbound"
          : Number.isInteger(preview.direction) ? `Unknown (${preview.direction})` : "Unknown";
      const actionName = preview.action === 0 ? "Block"
        : preview.action === 1 ? "Allow"
          : Number.isInteger(preview.action) ? `Unknown (${preview.action})` : "Unknown";
      let submitted = false;
      let refreshAfterClose = false;
      const execute = h("button", {
        class: operation === "enable" ? "btn btn-primary" : "btn btn-destructive", type: "button",
        "aria-label": `${operation === "remove" ? "Remove" : operation === "enable" ? "Enable" : "Disable"} rule`,
        disabled: preview.canExecute !== true || typeof preview.nonce !== "string",
        onclick: async () => {
          if (execute.disabled) return;
          execute.disabled = true;
          submitted = true;
          result.textContent = "Applying the reviewed firewall change…";
          try {
            const outcome = await api.post("/api/firewall/rule/execute", { nonce: preview.nonce }, { signal: controller.signal });
            result.textContent = outcome.ok
              ? "Windows Firewall confirmed the change."
              : `The change could not be verified: ${outcome.reason || outcome.status}.`;
            refreshAfterClose = true;
          } catch (error) {
            if (error.name !== "AbortError" && !destroyed) {
              result.textContent = `The rule action failed: ${error.message}`;
              refreshAfterClose = true;
            }
          } finally {
            if (!destroyed && !submitted) execute.disabled = false;
          }
        },
      }, operation === "remove" ? "Remove rule" : operation === "enable" ? "Enable rule" : "Disable rule");
      const close = h("button", {
        class: "btn btn-outline", type: "button",
        onclick: () => {
          closeDialog(review);
          if (refreshAfterClose) refresh();
        },
      }, "Close");
      review.append(
        dialogHeader({}, dialogTitle({ id: "firewall-rule-review-title" }, "Review firewall change")),
        dialogContent({},
          dialogDescription({}, `You are about to ${operation} this WinTCP-managed rule. The server will re-read its full state before applying the change.`),
          h("dl", { class: "detail-list" },
            h("dt", {}, "Rule"), h("dd", {}, preview.name),
            h("dt", {}, "Current status"), h("dd", {}, preview.enabled === null ? "Unknown" : preview.enabled ? "Enabled" : "Disabled"),
            h("dt", {}, "Direction"), h("dd", {}, directionName),
            h("dt", {}, "Action"), h("dd", {}, actionName),
            h("dt", {}, "Protocol"), h("dd", {}, protocolName),
            h("dt", {}, "Profiles"), h("dd", {}, profileNames),
            h("dt", {}, "Local addresses"), h("dd", {}, preview.localAddresses ?? "Unknown"),
            h("dt", {}, "Remote addresses"), h("dd", {}, preview.remoteAddresses ?? "Unknown"),
            h("dt", {}, "Local ports"), h("dd", {}, preview.localPorts ?? "Unknown"),
            h("dt", {}, "Remote ports"), h("dd", {}, preview.remotePorts ?? "Unknown"),
            h("dt", {}, "Application"), h("dd", {}, preview.application ?? "Unknown"),
            h("dt", {}, "Service"), h("dd", {}, preview.service ?? "Unknown"),
          ),
          preview.reason ? h("p", { class: "text-sm text-warning" }, preview.reason) : null,
          operation === "remove" ? h("p", { class: "text-sm text-destructive" }, "Removal is permanent. The rule can only be recreated if its complete original configuration is known.") : null,
          preview.warning ? h("p", { class: "muted text-sm" }, preview.warning) : null,
          result,
        ),
        dialogFooter({}, close, execute),
      );
      review.addEventListener("close", () => {
        openDialogs.delete(review);
        controller.abort();
        finishController();
        opener?.focus?.({ preventScroll: true });
      }, { once: true });
      openDialogs.add(review);
      document.body.append(review);
      openDialog(review);
    } catch (error) {
      if (error.name !== "AbortError" && !destroyed)
        status.textContent = `Could not prepare the rule action: ${error.message}`;
      finishController();
    } finally {
      if (destroyed || controller.signal.aborted) finishController();
    }
  }

  const destroyTable = () => {
    if (!table) return;
    layoutControls?.destroy();
    layoutControls = null;
    table.destroy();
    table = null;
  };

  async function refresh() {
    if (destroyed) return;
    requestController?.abort();
    requestController = new AbortController();
    refreshButton.disabled = true;
    status.textContent = "Reading Windows Firewall rules…";
    try {
      const inventory = normalizeFirewallInventory(
        await api.get("/api/firewall", { signal: requestController.signal }),
      );
      if (destroyed) return;
      if (!inventory.available) {
        if (hasSuccessfulRead) {
          const lastRead = lastInventoryReadAt
            ? new Date(lastInventoryReadAt).toLocaleString()
            : "an unknown time";
          status.textContent = `Refresh unavailable. Showing the last successful firewall inventory from ${lastRead}; current rules may be stale. ${inventory.reason}`;
          return;
        }
        destroyTable();
        clear(tableHost);
        rows = [];
        status.textContent = "Firewall inventory unavailable.";
        tableHost.append(emptyState({}, "Could not read firewall rules", inventory.reason));
        return;
      }
      hasSuccessfulRead = true;
      lastInventoryReadAt = inventory.generatedAt;
      rows = inventory.rules.map((rule) => ({
        ...rule,
        match: target ? explainFirewallRuleMatch(rule, target, inventory.activeProfileTypes) : null,
        matchLabel: target ? (() => {
          const match = explainFirewallRuleMatch(rule, target, inventory.activeProfileTypes);
          return `${match.kind}: ${match.explanation}`;
        })() : "",
        direction: rule.direction ?? "Unknown",
        action: rule.action ?? "Unknown",
        protocol: rule.protocol ?? "Unknown",
        profiles: rule.profiles ?? "Unknown",
        localAddresses: rule.localAddresses ?? "Unknown",
        remoteAddresses: rule.remoteAddresses ?? "Unknown",
        localPorts: rule.localPorts ?? "Unknown",
        remotePorts: rule.remotePorts ?? "Unknown",
        application: rule.application ?? "Unknown",
        service: rule.service ?? "Unknown",
        status: rule.enabled === null
          ? "Status unknown"
          : !rule.enabled
            ? "Disabled"
            : rule.blocking === true
              ? "Enabled · outbound block"
              : rule.blocking === false
                ? "Enabled · not an outbound block"
                : "Enabled · action unknown",
      }));
      const candidateCount = filteredRows().length;
      const activeProfileNames = [
        inventory.activeProfileTypes & 1 ? "Domain" : "",
        inventory.activeProfileTypes & 2 ? "Private" : "",
        inventory.activeProfileTypes & 4 ? "Public" : "",
      ].filter(Boolean);
      const profileStatus = activeProfileNames.length
        ? `Active Windows Firewall profile: ${activeProfileNames.join(", ")}.`
        : "Active Windows Firewall profile is unknown.";
      const readAtStatus = inventory.generatedAt
        ? `Inventory generated ${new Date(inventory.generatedAt).toLocaleString()}.`
        : "Inventory generation time is unavailable.";
      status.textContent = exactRuleName
        ? `Showing the exact rule “${exactRuleName}” when exposed by the inventory. ${readAtStatus}`
        : (target ? `Candidate view: ${candidateCount} candidate rules from ` : `Showing ${candidateCount} rules from `) +
          "Windows Firewall COM, plus readable WinTCP-owned rules. " + profileStatus + " " + readAtStatus + " Candidate matching is not effective policy or a reachability verdict." +
          (inventory.warnings.length ? " " + inventory.warnings.join(" ") : "");
      const exactRuleVisible = !exactRuleName || rows.some((row) => row.name.toLowerCase() === exactRuleName.toLowerCase());
      if (rows.length === 0 || (target && !rows.some((row) => row.match?.candidate)) || !exactRuleVisible) {
        destroyTable();
        clear(tableHost);
        tableHost.append(emptyState({}, exactRuleName ? "The selected rule is not currently visible" : target ? "No related firewall candidates" : "No firewall rules were returned",
          exactRuleName ? "The firewall inventory is best effort; refresh or return to all rules to continue." :
            target ? "No candidate could be identified from the available rule fields. Unknown scope and effective policy are not treated as a match." : "Windows Firewall returned no rules. This does not prove that the effective policy has no restrictions."));
        return;
      }
      if (table) {
        updateTable();
        return;
      }
      const wrapper = h("div", { class: "net-table" });
      table = createVirtualTable(wrapper, {
        columns: [
          { key: "name", label: "Rule", width: 2.2, sortable: true },
          { key: "ownership", label: "Owner", width: 1.1, sortable: true },
          { key: "status", label: "Status", width: 1.7, sortable: true },
          ...(target ? [{ key: "matchLabel", label: "Candidate match", width: 1.4, sortable: true }] : []),
          { key: "direction", label: "Direction", width: 0.9, sortable: true },
          { key: "action", label: "Action", width: 0.8, sortable: true },
          { key: "protocol", label: "Protocol", width: 0.8, sortable: true },
          { key: "profiles", label: "Profiles", width: 1.2, sortable: true },
          { key: "localAddresses", label: "Local addresses", width: 1.5, sortable: true },
          { key: "remoteAddresses", label: "Remote addresses", width: 1.8, sortable: true },
          { key: "localPorts", label: "Local ports", width: 1, sortable: true },
          { key: "remotePorts", label: "Remote ports", width: 1, sortable: true },
          { key: "application", label: "Application", width: 1.8, sortable: true },
          { key: "service", label: "Service", width: 1.2, sortable: true },
          { key: "actions", label: "Actions", width: 1.8, actions: true, renderCell: (row, rowEl) => row.wintcpOwned
            ? h("div", { class: "table-actions" },
              row.enabled === null ? null : h("button", {
                class: "btn btn-outline btn-xs", type: "button",
                "aria-label": `${row.enabled ? "Disable" : "Enable"} ${row.name}`,
                onclick: (event) => { event.stopPropagation(); reviewRuleAction(row, row.enabled ? "disable" : "enable", event.currentTarget); },
              }, row.enabled ? "Disable" : "Enable"),
              h("button", {
                class: "btn btn-outline btn-xs", type: "button",
                "aria-label": `Review removal of ${row.name}`,
                onclick: (event) => { event.stopPropagation(); reviewRuleAction(row, "remove", event.currentTarget); },
              }, "Remove"))
            : h("span", { class: "muted text-sm" }, "Read only"),
          },
        ],
        rowHeight: 38,
        height: 460,
        minWidth: "110rem",
        rowKey: (row) => row.name,
        label: "Windows Firewall rule inventory",
        emptyMessage: "No firewall rules match this filter.",
        onRowClick: (rule) => showRuleDetails(rule, openDialogs),
      });
      layoutControls = createColumnLayoutControls(table, {
        layoutKey: "firewallInventory",
        required: ["name", "actions"],
        compactHidden: ["matchLabel", "profiles", "localAddresses", "remoteAddresses",
          "localPorts", "remotePorts", "application", "service"],
      });
      tableHost.append(layoutControls.element, wrapper);
      updateTable();
    } catch (error) {
      if (destroyed || error.name === "AbortError") return;
      if (hasSuccessfulRead) {
        const lastRead = lastInventoryReadAt
          ? new Date(lastInventoryReadAt).toLocaleString()
          : "an unknown time";
        status.textContent = `Refresh failed. Showing the last successful firewall inventory from ${lastRead}; current rules may be stale. ${error.message}`;
      } else {
        destroyTable();
        clear(tableHost);
        rows = [];
        status.textContent = "Firewall inventory unavailable.";
        tableHost.append(emptyState({}, "Could not read firewall rules", error.message));
      }
    } finally {
      if (!destroyed) refreshButton.disabled = false;
    }
  }

  return {
    element: root,
    ready: refresh(),
    refresh,
    destroy() {
      if (destroyed) return;
      destroyed = true;
      requestController?.abort();
      for (const controller of actionControllers) controller.abort();
      for (const review of openDialogs) closeDialog(review);
      actionControllers.clear();
      openDialogs.clear();
      filter.removeEventListener("input", updateTable);
      destroyTable();
    },
  };
}
