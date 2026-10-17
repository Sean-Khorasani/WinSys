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
