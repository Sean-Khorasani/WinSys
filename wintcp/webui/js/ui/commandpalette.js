// ui/commandpalette.js - Command palette (Ctrl+K)
import { h } from "../h.js";
import { icon } from "../icons.js";

export function createCommandPalette(actions = []) {
  let isOpen = false;
  let selectedIdx = 0;
  let filtered = [];

  const overlay = h("div", {
    class: "command-palette-overlay",
    style: "position: fixed; inset: 0; background: rgb(0 0 0 / 0.5); z-index: 60; display: none; align-items: center; justify-content: center;",
  });

  const palette = h("div", { class: "command-palette" });

  const input = h("input", {
    class: "command-input",
    type: "text",
    placeholder: "Search pages, actions, processes...",
    "aria-label": "Command palette search",
  });

  const list = h("div", { class: "command-list" });

  palette.append(
    h("div", { class: "command-input" }, icon("search", 16), input),
    list,
  );
  overlay.append(palette);

  function open() {
    isOpen = true;
    overlay.style.display = "flex";
    input.value = "";
    selectedIdx = 0;
    filtered = actions;
    renderList();
    input.focus();
  }

  function close() {
    isOpen = false;
    overlay.style.display = "none";
  }

  function toggle() {
    if (isOpen) close();
    else open();
  }

  function renderList() {
    list.innerHTML = "";
    filtered.forEach((action, i) => {
      list.append(
        h("div", {
          class: `command-item${i === selectedIdx ? " is-selected" : ""}`,
          onclick: () => { close(); action.handler(); },
        }, icon(action.icon || "chevron-right", 16), h("span", {}, action.label)),
      );
    });
  }

  function onKey(e) {
    if (!isOpen) return;
    if (e.key === "Escape") { close(); e.preventDefault(); }
    else if (e.key === "ArrowDown") {
      selectedIdx = Math.min(selectedIdx + 1, filtered.length - 1);
      renderList();
      e.preventDefault();
    }
    else if (e.key === "ArrowUp") {
      selectedIdx = Math.max(selectedIdx - 1, 0);
      renderList();
      e.preventDefault();
    }
    else if (e.key === "Enter") {
      if (filtered[selectedIdx]) {
        close();
        filtered[selectedIdx].handler();
      }
      e.preventDefault();
    }
  }

  input.addEventListener("input", () => {
    const q = input.value.toLowerCase();
    filtered = actions.filter(a => a.label.toLowerCase().includes(q));
    selectedIdx = 0;
    renderList();
  });

  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "k") {
      e.preventDefault();
      toggle();
    }
    onKey(e);
  });

  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) close();
  });

  document.body.append(overlay);

  return { open, close, toggle };
}
