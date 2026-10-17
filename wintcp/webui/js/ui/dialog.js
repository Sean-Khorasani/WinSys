// ui/dialog.js - Dialog component (native <dialog>)

import { h } from "../h.js";

export function dialog(props = {}, ...children) {
  const el = h("dialog", { class: "dialog", ...props }, ...children);
  return el;
}

export function dialogHeader(props = {}, ...children) {
  return h("div", { class: "dialog-header", ...props }, ...children);
}

export function dialogTitle(props = {}, ...children) {
  return h("h2", { class: "dialog-title", ...props }, ...children);
}

export function dialogDescription(props = {}, ...children) {
  return h("p", { class: "dialog-description", ...props }, ...children);
}

export function dialogContent(props = {}, ...children) {
  return h("div", { class: "dialog-content", ...props }, ...children);
}

export function dialogFooter(props = {}, ...children) {
  return h("div", { class: "dialog-footer", ...props }, ...children);
}

export function openDialog(el) {
  if (el.showModal) el.showModal();
  else el.setAttribute("open", "");
}

export function closeDialog(el) {
  if (el.close) el.close();
  else el.removeAttribute("open");
}
