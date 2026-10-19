import { h, clear } from "../h.js";
import { copyText } from "./feedback.js";

const DESKTOP_QUERY = "(min-width: 1100px)";
let activeInspector = null;

export function openInspector({ key, title, row, sections, actions = [], subject = "item", opener = document.activeElement }) {
  closeInspector({ restoreFocus: false });
  const headingId = "inspector-title";
  const subtitle = h("p", { class: "inspector-identity" });
  const status = h("p", { class: "inspector-status", role: "status", "aria-live": "polite" });
  const content = h("div", { class: "inspector-content" });
  const footer = h("div", { class: "inspector-footer" });
  const follow = h("button", {
    type: "button", class: "btn btn-outline btn-sm", "aria-pressed": "false",
    onclick: () => setHeld(!activeInspector.held),
  });
  const close = h("button", {
    type: "button", class: "btn btn-ghost btn-icon btn-sm", "aria-label": "Close inspector",
    onclick: () => closeInspector(),
  }, "×");
  const width = h("input", {
    type: "range", min: "320", max: "640", step: "16", value: "448",
    class: "inspector-width", "aria-label": "Inspector width", title: "Resize inspector",
  });
  const dialog = h("dialog", {
    class: "inspector-dialog", "aria-labelledby": headingId,
    "data-inspector-key": key,
  },
  h("header", { class: "inspector-header" },
    h("div", { class: "inspector-heading" },
      h("h2", { id: headingId, class: "inspector-title dialog-title" }, title), subtitle),
    h("div", { class: "inspector-controls" },
      h("label", { class: "inspector-width-control" },
        h("span", { class: "sr-only" }, "Inspector width"), width),
      follow, close)),
  status, content, footer);

  const widthKey = `wintcp.inspector.width.${key.startsWith("connection:") ? "network" : "processes"}.v1`;
  try {
    const saved = Number(localStorage.getItem(widthKey));
    if (Number.isFinite(saved) && saved >= 320 && saved <= 640) width.value = String(saved);
  } catch { }
  const setWidth = () => {
    const next = Math.max(320, Math.min(640, Number(width.value) || 448));
    dialog.style.setProperty("--inspector-width", `${next}px`);
    document.documentElement.style.setProperty("--inspector-reserve", `${next}px`);
    try { localStorage.setItem(widthKey, String(next)); } catch { }
  };
  width.addEventListener("input", setWidth);

  const canFollow = subject === "process instance"
    ? Boolean(row?.instanceId)
    : subject === "connection identity"
      ? row?.idExact != null || row?.id != null
      : true;
  activeInspector = { key, title, row, sections, actions, subject, opener, dialog, subtitle, status,
    content, footer, width, widthKey, held: !canFollow, canFollow,
    heldReason: !canFollow ? "Stable lifetime identity is unavailable; live following is disabled." : "",
    mode: null, resize: null, hasPendingUpdate: false, pendingRow: null,
    pendingMissing: "", pendingStatus: "" };
  renderActive();
  document.body.append(dialog);
  const onClose = () => {
    if (dialog.open) return;
    if (activeInspector?.dialog === dialog) closeInspector();
  };
  const onKeydown = (event) => {
    if (event.key !== "Escape" || event.defaultPrevented || !activeInspector ||
        activeInspector.dialog !== dialog || document.querySelector('dialog[open]:not(.inspector-dialog)')) return;
    event.preventDefault();
    closeInspector();
  };
  activeInspector.onClose = onClose;
  activeInspector.onKeydown = onKeydown;
  dialog.addEventListener("close", onClose);
  dialog.addEventListener("cancel", (event) => {
    event.preventDefault();
    closeInspector();
  });
  activeInspector.resize = syncPresentation;
  window.addEventListener("resize", syncPresentation);
  document.addEventListener("keydown", onKeydown, true);
  setWidth();
  syncPresentation();
  (dialog.querySelector("button") || dialog).focus({ preventScroll: true });
  return dialog;
}

export function updateInspector(key, row, { missing = "The selected item is no longer present in the latest sample.", status = "" } = {}) {
  if (!activeInspector || activeInspector.key !== key) return false;
  if (activeInspector.held) {
    activeInspector.hasPendingUpdate = true;
    activeInspector.pendingRow = row || null;
    activeInspector.pendingMissing = row ? "" : missing;
    activeInspector.pendingStatus = row ? status : "";
    renderActive();
    return true;
  }
  if (row) {
    activeInspector.row = row;
    activeInspector.missing = "";
    activeInspector.liveStatus = status;
  } else {
    activeInspector.missing = missing;
    activeInspector.liveStatus = "";
  }
  renderActive();
  return true;
}

export function closeInspector({ restoreFocus = true } = {}) {
  const current = activeInspector;
  if (!current) return;
  activeInspector = null;
  window.removeEventListener("resize", current.resize);
  document.removeEventListener("keydown", current.onKeydown, true);
  current.dialog.removeEventListener("close", current.onClose);
  if (current.dialog.open) current.dialog.close();
  current.dialog.remove();
  document.body.classList.remove("inspector-open");
  document.querySelector(".main-content")?.classList.remove("inspector-reserved");
  document.documentElement.style.removeProperty("--inspector-reserve");
  if (restoreFocus && current.opener?.isConnected) current.opener.focus({ preventScroll: true });
}

function setHeld(held) {
  if (!activeInspector || (!held && !activeInspector.canFollow)) return;
  const current = activeInspector;
  if (held) {
    current.heldAt = new Date();
    current.hasPendingUpdate = false;
  } else if (current.hasPendingUpdate) {
    if (current.pendingRow) {
      current.row = current.pendingRow;
      current.missing = "";
      current.liveStatus = current.pendingStatus;
    } else {
      current.missing = current.pendingMissing;
      current.liveStatus = "";
    }
    current.hasPendingUpdate = false;
    current.pendingRow = null;
    current.pendingMissing = "";
    current.pendingStatus = "";
  }
  current.held = held;
  renderActive();
}

function syncPresentation() {
  const current = activeInspector;
  if (!current) return;
  const desktop = window.matchMedia(DESKTOP_QUERY).matches;
  if (current.mode === desktop && current.dialog.open) return;
  const focused = current.dialog.contains(document.activeElement)
    ? document.activeElement : null;
  current.mode = desktop;
  if (current.dialog.open) current.dialog.close();
  current.dialog.classList.toggle("is-docked", desktop);
  current.dialog.classList.toggle("is-modal", !desktop);
  if (desktop) {
    current.dialog.removeAttribute("aria-modal");
    document.body.classList.add("inspector-open");
    document.querySelector(".main-content")?.classList.add("inspector-reserved");
    current.dialog.show ? current.dialog.show() : current.dialog.setAttribute("open", "");
  } else {
    document.body.classList.remove("inspector-open");
    document.querySelector(".main-content")?.classList.remove("inspector-reserved");
    current.dialog.setAttribute("aria-modal", "true");
    current.dialog.showModal ? current.dialog.showModal() : current.dialog.setAttribute("open", "");
  }
  if (focused?.isConnected) focused.focus({ preventScroll: true });
}

function renderActive() {
  const current = activeInspector;
  if (!current) return;
  const scrollTop = current.content.scrollTop;
  const focusedKey = current.dialog.contains(document.activeElement)
    ? document.activeElement.dataset?.copyKey : null;
  current.subtitle.textContent = identityText(current.row);
  current.status.textContent = current.held
    ? current.heldReason || `Held at the values captured${current.heldAt ? ` at ${current.heldAt.toLocaleTimeString()}` : " when this inspector opened"}.` +
      (current.hasPendingUpdate
        ? current.pendingRow
          ? current.pendingStatus || (current.pendingRow.removed ? " The item is now closed; captured values are unchanged." : " Newer values are available; resume to follow them.")
          : ` ${current.pendingMissing} Captured values are unchanged.`
        : "")
    : current.missing
      ? `${current.missing} Showing the last captured details.`
      : current.liveStatus || `Following this exact ${current.subject}.`;
  const follow = current.dialog.querySelector(".inspector-controls > .btn");
  if (follow) {
    follow.textContent = current.canFollow ? current.held ? "Resume live" : "Hold values" : "Identity unknown";
    follow.disabled = !current.canFollow;
    follow.setAttribute("aria-pressed", String(current.held));
  }
  clear(current.content);
  for (const section of current.sections(current.row)) {
    const list = h("dl", { class: "inspector-fields" });
    for (const field of section.fields) {
      const value = field.value == null || field.value === "" ? "Unavailable" : String(field.value);
      const copyable = field.copyValue != null && String(field.copyValue) !== "";
      const copyKey = `${section.title}:${field.label}`;
      list.append(
        h("dt", {}, field.label),
        h("dd", { class: field.mono ? "inspector-value mono" : "inspector-value" },
          h("span", { title: field.reason || "" }, value),
          copyable ? h("button", {
            type: "button", class: "btn btn-ghost btn-xs inspector-copy",
            "aria-label": `Copy ${field.label}`, dataset: { copyKey },
            title: `Copy ${field.label}`,
            onclick: () => copyText(field.copyValue, field.label),
          }, "Copy") : null),
        field.reason ? h("dd", { class: "inspector-reason" }, field.reason) : null,
      );
    }
    current.content.append(h("section", { class: "inspector-section" },
      h("h3", {}, section.title), list));
  }
  clear(current.footer);
  for (const action of current.actions(current.row)) {
    current.footer.append(h("button", {
      type: "button", class: action.className || "btn btn-outline btn-sm",
      disabled: Boolean(action.disabled), title: action.title || "",
      onclick: action.onClick,
    }, action.label));
  }
  current.content.scrollTop = scrollTop;
  if (focusedKey) current.content.querySelector(`[data-copy-key="${CSS.escape(focusedKey)}"]`)?.focus({ preventScroll: true });
}

function identityText(row) {
  if (row?.instanceId || row?.processInstanceId) return row.instanceId || row.processInstanceId;
  if (row?.idExact != null || row?.id != null) {
    const id = row.idExact ?? row.id;
    const local = row.local || row.localAddress || "?";
    const remote = row.remote || row.remoteAddress || "?";
    return `${row.proto || "Connection"} #${id} · ${local}:${row.lport ?? "?"} → ${remote}:${row.rport ?? "?"}`;
  }
  return row?.pid != null ? `PID ${row.pid}` : "Identity unavailable";
}
