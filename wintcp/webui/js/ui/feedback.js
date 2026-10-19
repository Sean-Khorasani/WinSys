import { h } from "../h.js";

export function notify(message, { error = false, action = null } = {}) {
  let region = document.getElementById("toast-region");
  if (!region) {
    region = h("div", { id: "toast-region", class: "toast-region", "aria-label": "Notifications" });
    document.body.append(region);
  }
  const toast = h("div", { class: `toast${error ? " is-error" : ""}`, role: error ? "alert" : "status" },
    h("span", {}, message),
    action && typeof action.onClick === "function"
      ? h("button", { class: "btn btn-outline btn-sm", type: "button", onclick: () => { action.onClick(); toast.remove(); } }, action.label || "Continue")
      : null,
    h("button", { class: "btn btn-ghost btn-sm", type: "button", "aria-label": "Dismiss notification", onclick: () => toast.remove() }, "Dismiss"),
  );
  region.append(toast);
  while (region.childElementCount > 4) region.firstElementChild.remove();
  if (!action) setTimeout(() => toast.remove(), error ? 10000 : 4500);
  return toast;
}

export async function copyText(value, label = "Value") {
  if (value == null || value === "") {
    notify(`${label} is unavailable`, { error: true });
    return false;
  }
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(String(value));
    } else {
      const previous = document.activeElement;
      const input = h("textarea", { class: "clipboard-fallback", readonly: true, "aria-label": "Copy value" }, String(value));
      document.body.append(input);
      try {
        input.select();
        if (!document.execCommand("copy")) throw new Error("Clipboard access was refused");
      } finally {
        input.remove();
        if (previous?.isConnected) previous.focus({ preventScroll: true });
      }
    }
    notify(`${label} copied`);
    return true;
  } catch (error) {
    notify(`Could not copy ${label.toLowerCase()}: ${error.message}`, { error: true });
    return false;
  }
}
