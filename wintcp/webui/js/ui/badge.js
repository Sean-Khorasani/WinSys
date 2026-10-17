// ui/badge.js - Badge component

import { h } from "../h.js";

export function badge(props = {}, ...children) {
  const { variant = "default", ...rest } = props;
  return h("span", { class: `badge badge-${variant}`, ...rest }, ...children);
}
