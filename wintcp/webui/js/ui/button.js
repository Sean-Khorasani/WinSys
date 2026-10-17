// ui/button.js - Button component

import { h } from "../h.js";

export function button(props = {}, ...children) {
  const { variant = "default", size = "default", ...rest } = props;
  const cls = ["btn", `btn-${variant}`];
  if (size !== "default") cls.push(`btn-${size}`);
  return h("button", { class: cls.join(" "), ...rest }, ...children);
}
