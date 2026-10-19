import { h } from "../h.js";
import { notify } from "./feedback.js";

let currentMenu = null;

export function closeContextMenu() {
  currentMenu?.close();
}

export function openContextMenu(items, { event = null, anchor = document.activeElement, label = "Actions" } = {}) {
  closeContextMenu();
  const row = anchor?.closest?.("[data-row-key]");
  const rowKey = row?.dataset.rowKey;
  const table = row?.closest("[role=grid]");
  const menu = h("div", { class: "context-menu", role: "menu", "aria-label": label });
  const buttons = [];
  let closed = false;
  const close = ({ restoreFocus = true } = {}) => {
    if (closed) return;
    closed = true;
    menu.remove();
    document.removeEventListener("pointerdown", onOutside, true);
    window.removeEventListener("resize", onResize);
    window.removeEventListener("hashchange", onResize);
    document.removeEventListener("scroll", onScroll, true);
    if (currentMenu?.element === menu) currentMenu = null;
    if (!restoreFocus) return;
    const currentAnchorRow = anchor?.closest?.("[data-row-key]");
    const anchorStillTargetsRow = rowKey == null || currentAnchorRow?.dataset.rowKey === rowKey;
    const target = anchor?.isConnected && anchorStillTargetsRow ? anchor
      : table?.isConnected && rowKey != null ? table.querySelector(`[data-row-key="${CSS.escape(rowKey)}"]`) || table : null;
    target?.focus({ preventScroll: true });
  };
  const onOutside = (pointer) => {
    if (!menu.contains(pointer.target)) close({ restoreFocus: false });
  };
  const onResize = () => close({ restoreFocus: false });
  const onScroll = (scroll) => {
    if (!menu.contains(scroll.target)) close({ restoreFocus: false });
  };
  for (const item of items) {
    if (item.separator) {
      menu.append(h("div", { class: "context-menu-separator", role: "separator" }));
      continue;
    }
    const button = h("button", {
      class: `context-menu-item${item.destructive ? " is-destructive" : ""}`,
      type: "button",
      role: "menuitem",
      tabindex: "-1",
      "aria-disabled": item.disabled ? "true" : undefined,
      title: item.reason || undefined,
      onclick: async (click) => {
        click.stopPropagation();
        if (item.disabled) return;
        close();
        try {
          await item.action();
        } catch (error) {
          notify(error.message || "The action could not be completed", { error: true });
        }
      },
    }, h("span", {}, item.label), item.disabled && item.reason
      ? h("small", { class: "context-menu-reason" }, item.reason) : null);
    buttons.push(button);
    menu.append(button);
  }
  menu.addEventListener("keydown", (key) => {
    const index = buttons.indexOf(document.activeElement);
    let next = null;
    if (key.key === "ArrowDown") next = (index + 1) % buttons.length;
    if (key.key === "ArrowUp") next = (index - 1 + buttons.length) % buttons.length;
    if (key.key === "Home") next = 0;
    if (key.key === "End") next = buttons.length - 1;
    if (key.key === "Escape" || key.key === "Tab") {
      if (key.key === "Escape") key.preventDefault();
      close();
    } else if (next !== null && buttons[next]) {
      key.preventDefault();
      buttons[next].focus();
    }
  });
  document.body.append(menu);
  const bounds = anchor?.getBoundingClientRect?.();
  const pointer = event?.type === "contextmenu" && (event.clientX || event.clientY);
  const desiredX = pointer ? event.clientX : bounds?.left || 8;
  const desiredY = pointer ? event.clientY : bounds?.bottom || 8;
  const width = menu.getBoundingClientRect().width;
  const height = menu.getBoundingClientRect().height;
  menu.style.left = `${Math.max(8, Math.min(desiredX, innerWidth - width - 8))}px`;
  menu.style.top = `${Math.max(8, Math.min(desiredY, innerHeight - height - 8))}px`;
  document.addEventListener("pointerdown", onOutside, true);
  window.addEventListener("resize", onResize);
  window.addEventListener("hashchange", onResize);
  document.addEventListener("scroll", onScroll, true);
  currentMenu = { element: menu, close };
  buttons[0]?.focus({ preventScroll: true });
  return currentMenu;
}
