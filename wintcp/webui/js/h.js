// h.js - DOM helper: createElement + textContent (no innerHTML)
// CSP-safe: never concatenates untrusted strings into HTML.

export function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === "class") el.className = value;
    else if (key === "dataset") Object.assign(el.dataset, value);
    else if (key === "ref" && typeof value === "function") value(el);
    else if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
    else if (key === "style" && typeof value === "string") el.style.cssText = value;
    else if (key === "value" && typeof value !== "undefined" && value !== null) {
      if ("value" in el) el.value = String(value);
      else el.setAttribute(key, String(value));
    }
    else if (key === "checked" && ("checked" in el)) {
      if (value === "" || value === true) el.checked = true;
      else if (value === false || value === null) el.checked = false;
    }
    else if (key === "selected" && ("selected" in el)) {
      if (value === "" || value === true) el.selected = true;
      else if (value === false || value === null) el.selected = false;
    }
    else if (value === true) el.setAttribute(key, "");
    else if (value !== false && value != null) el.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child == null) continue;
    el.append(child.nodeType ? child : document.createTextNode(String(child)));
  }
  return el;
}

export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}
