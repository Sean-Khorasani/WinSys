// ui/card.js - Card component

import { h } from "../h.js";

export function card(props = {}, ...children) {
  return h("div", { class: "card", ...props }, ...children);
}

export function cardHeader(props = {}, ...children) {
  return h("div", { class: "card-header", ...props }, ...children);
}

export function cardTitle(props = {}, ...children) {
  return h("h3", { class: "card-title", ...props }, ...children);
}

export function cardDescription(props = {}, ...children) {
  return h("p", { class: "card-description", ...props }, ...children);
}

export function cardContent(props = {}, ...children) {
  return h("div", { class: "card-content", ...props }, ...children);
}

export function cardFooter(props = {}, ...children) {
  return h("div", { class: "card-footer", ...props }, ...children);
}

// Empty-state block. Used instead of an empty container so "nothing here" is
// never mistaken for a failed load.
export function emptyState(props = {}, title = "Nothing to show", detail = "") {
  const { action = null, ...attributes } = props;
  const actionElement = action?.label
    ? action.href
      ? h("a", { class: "btn btn-outline btn-sm", href: action.href }, action.label)
      : h("button", {
        class: "btn btn-outline btn-sm", type: "button", disabled: Boolean(action.disabled),
        onclick: action.onClick, title: action.title || "",
      }, action.label)
    : null;
  return h("div", { class: "empty-state", role: "status", "aria-live": "polite", ...attributes },
    h("p", { class: "empty-state-title" }, title),
    detail ? h("p", { class: "empty-state-detail muted" }, detail) : null,
    actionElement,
  );
}

export function refreshAction(label = "Refresh now") {
  return {
    label,
    onClick: () => document.dispatchEvent(new Event("wintcp:refresh-now")),
  };
}
