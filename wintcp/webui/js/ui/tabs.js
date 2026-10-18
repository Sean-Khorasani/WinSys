// ui/tabs.js - ARIA tab strip with real panel switching.
//
// SELECTION MUST LIVE OUTSIDE THE COMPONENT
// The router re-runs a page's renderer on every poll (~2 s), which rebuilds the
// whole page including this strip. A tab that keeps its selection in a local
// variable therefore resets to its first tab every couple of seconds: you click
// Tree, it renders, and a moment later you are back on Table. That is not a
// cosmetic glitch - it makes the non-default tabs unusable, because no click
// survives long enough to be read.
//
// So callers pass their selection in as `initial` and are told about changes
// through `onChange`, and are expected to keep it wherever their state lives.
// See pages/processes.js for the pattern.
//
// WHY THIS EXISTS
// Three pages shipped markup that looked like a tab strip and was not one:
//
//     h("button", { class: "tab is-active", role: "tab" }, "Connections")
//     h("button", { class: "tab",              role: "tab" }, "Listening")
//
// No handler, no panel, and `role="tab"` on an element that controls nothing.
// The first one rendered as selected forever. role="tab" is not decoration - it
// is a promise to assistive technology that pressing this control reveals a
// specific panel, and a promise that is not kept is worse than no role at all.
//
// This module keeps that promise or refuses to make it: a tab with no panel
// cannot be constructed here.
//
// ARIA PATTERN (WAI-ARIA Authoring Practices, tabs with manual activation)
// - Arrow Left / Right move focus between tabs. Focus moves, the panel does
//   NOT: automatic activation would fire a render on every arrow key, which for
//   a tab that kicks off a request means a request per keypress.
// - Home / End jump to the first and last tab.
// - Enter / Space activate the focused tab.
// - aria-selected carries the state; the visual class follows it.
// - Only the active tab is in the tab order (roving tabindex). Ten tabs that are
//   all in the tab order is ten stops between the page and the panel.
//
// `hidden` on an inactive panel is deliberate and not a lazy-load shortcut: it
// keeps an unmounted panel out of the accessibility tree, so a screen reader
// cannot read content the sighted user cannot see.

import { h, clear } from "../h.js";

/**
 * Build a tab strip.
 *
 * @param {object} opts
 * @param {Array<{id: string, label: string, render: () => Node | Promise<Node>}>} opts.tabs
 * @param {string} [opts.ariaLabel] - accessible name for the tablist.
 * @param {string} [opts.initial] - id of the tab to show first. Pass the caller's
 *   persisted selection, not a hardcoded literal: this component is rebuilt on
 *   every poll, and a literal resets the operator's choice every two seconds.
 * @param {(id: string) => void} [opts.onChange] - called when the selection
 *   changes, so the caller can persist it.
 * @returns {{element: HTMLElement, select: (id: string, force?: boolean) => Promise<void>, active: () => string, destroy: () => void}}
 */
export function createTabs({ tabs, ariaLabel = "Sections", initial = null, onChange = null }) {
  if (!Array.isArray(tabs) || tabs.length === 0) {
    throw new Error("createTabs needs at least one tab");
  }
  // Every tab must have a panel. A tab that cannot render is a dead control, and
  // the whole point of this module is that there are none.
  for (const tab of tabs) {
    if (!tab || !tab.id || !tab.label || typeof tab.render !== "function") {
      throw new Error(`createTabs: tab ${JSON.stringify(tab && tab.id)} has no render()`);
    }
  }

  const first = initial && tabs.some((t) => t.id === initial) ? initial : tabs[0].id;
  let activeId = first;
  let generation = 0;

  const list = h("div", { class: "tabs", role: "tablist", "aria-label": ariaLabel });
  const panels = h("div", { class: "tab-panels" });

  const buttons = new Map();
  for (const tab of tabs) {
    const button = h("button", {
      class: `tab${tab.id === activeId ? " is-active" : ""}`,
      type: "button",
      role: "tab",
      id: `tab-${tab.id}`,
      "aria-controls": `panel-${tab.id}`,
      "aria-selected": tab.id === activeId ? "true" : "false",
      tabindex: tab.id === activeId ? "0" : "-1",
      onclick: () => { focusedId = tab.id; select(tab.id); },
    }, tab.label);
    buttons.set(tab.id, button);
    list.append(button);

    const panel = h("div", {
      class: "tab-panel",
      role: "tabpanel",
      id: `panel-${tab.id}`,
      "aria-labelledby": `tab-${tab.id}`,
      tabindex: "0",
    });
    // A hidden panel must not be reachable by Tab, so hidden (not a class) is
    // the mechanism - it removes the element from the accessibility tree too.
    if (tab.id !== activeId) panel.hidden = true;
    panels.append(panel);
  }

  // Focus and selection are DIFFERENT pieces of state.
  //
  // Conflating them is what made arrow keys appear broken: moving focus also
  // painted the tab as selected, so aria-selected tracked the arrow keys rather
  // than the operator's actual choice, and Enter then "activated" the tab that
  // focus had already selected - so the visible selection never moved off the
  // first tab. `focusedId` drives the roving tabindex; `activeId` drives the
  // selected panel. Under the WAI-ARIA manual-activation pattern they only
  // coincide once the operator presses Enter.
  let focusedId = first;

  list.addEventListener("keydown", (event) => {
    const ids = tabs.map((t) => t.id);
    const index = ids.indexOf(focusedId);
    let next = null;
    switch (event.key) {
      case "ArrowRight": next = ids[(index + 1) % ids.length]; break;
      case "ArrowLeft":  next = ids[(index - 1 + ids.length) % ids.length]; break;
      case "Home":        next = ids[0]; break;
      case "End":         next = ids[ids.length - 1]; break;
      case "Enter":
      case " ":
        event.preventDefault();
        select(focusedId);
        return;
      default: return;
    }
    event.preventDefault();
    const button = buttons.get(next);
    if (!button) return;
    focusedId = next;
    button.focus();
    paintFocus();
  });

  // Roving tabindex: only the focused tab is in the tab order, so a strip of
  // four tabs is one stop rather than four between the page and the panel.
  function paintFocus() {
    for (const [id, button] of buttons) {
      button.tabIndex = id === focusedId ? 0 : -1;
    }
  }

  function paintSelection() {
    for (const [id, button] of buttons) {
      const active = id === activeId;
      button.classList.toggle("is-active", active);
      button.setAttribute("aria-selected", active ? "true" : "false");
    }
    for (const tab of tabs) {
      panels.querySelector(`#panel-${CSS.escape(tab.id)}`).hidden = tab.id !== activeId;
    }
  }

  async function select(id, force = false) {
    if (!buttons.has(id)) return;
    const changed = id !== activeId;
    activeId = id;
    focusedId = id;
    paintFocus();
    paintSelection();
    // Tell the caller even when the poll is what triggered the call: the caller
    // uses this to know the strip is showing the tab it asked for.
    if (changed && onChange) onChange(id);
    // Skip the re-render when nothing changed AND the panel already has content.
    // The caller passes force=true to refresh the current tab with new data
    // without the component having to infer intent from child counts.
    if (!changed && !force && panels.querySelector(`#panel-${CSS.escape(id)}`).childElementCount > 0) return;
    const panel = panels.querySelector(`#panel-${CSS.escape(id)}`);
    const mine = ++generation;
    const tab = tabs.find((t) => t.id === id);
    try {
      const node = await tab.render();
      // A slow first panel must not overwrite a panel the user has already
      // moved on to. Compare the generation, not the id.
      if (mine !== generation) return;
      clear(panel);
      if (node) panel.append(node);
    } catch (err) {
      if (mine !== generation) return;
      clear(panel);
      panel.append(h("div", { class: "empty-state" },
        h("p", { class: "empty-state-title" }, "This view could not be loaded"),
        h("p", { class: "empty-state-detail muted" }, err.message),
      ));
      console.error(`tab ${id} failed to render`, err);
    }
  }

  const element = h("div", { class: "tab-host" }, list, panels);

  return {
    element,
    // select(id, force) - force re-renders an already-selected tab.
    select,
    active: () => activeId,
    destroy() { generation++; },
  };
}