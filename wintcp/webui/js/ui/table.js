// ui/table.js - Table component

import { h } from "../h.js";

export function table(props = {}, ...children) {
  return h("div", { class: "table-container" },
    h("table", { class: "table", ...props }, ...children),
  );
}

export function thead(...children) {
  return h("thead", {}, ...children);
}

export function tbody(...children) {
  return h("tbody", {}, ...children);
}

export function tr(props = {}, ...children) {
  return h("tr", props, ...children);
}

export function th(props = {}, ...children) {
  return h("th", props, ...children);
}

export function td(props = {}, ...children) {
  return h("td", props, ...children);
}
