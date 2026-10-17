// ui/toast.js - Toast notifications

import { h } from "../h.js";

export function toastRegion() {
  let region = document.querySelector(".toast-region");
  if (!region) {
    region = h("div", { class: "toast-region", role: "status", "aria-live": "polite" });
    document.body.append(region);
  }
  return region;
}

export function toast(props = {}, ...children) {
  const { title, description, variant = "default", duration = 5000 } = props;
  const region = toastRegion();
  const el = h("div", { class: `toast toast-${variant}` },
    title ? h("div", { class: "toast-title" }, title) : null,
    description ? h("div", { class: "toast-description" }, description) : null,
    ...children,
  );
  region.append(el);
  if (duration > 0) {
    setTimeout(() => el.remove(), duration);
  }
  return el;
}
