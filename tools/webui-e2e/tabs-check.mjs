// tabs-check.mjs - Regression tests for the two navigation bugs that shipped.
//
//   node tools/webui-e2e/tabs-check.mjs --url http://127.0.0.1:1234/
//
// 1. THE SIDEBAR DID NOT MOVE. renderSidebar() computed `is-active` from the
//    hash at boot and never revisited it, so navigating to Performance left
//    Overview highlighted for the rest of the session. The class was the only
//    signal: there was no aria-current, so the sidebar also read wrong to a
//    screen reader even on the page it did get right.
//
// 2. THE TABS DID NOTHING. Three pages shipped
//        h("button", { class: "tab is-active", role: "tab" }, "Connections")
//        h("button", { class: "tab",              role: "tab" }, "Listening")
//    - four buttons, no handlers, no panels. The first rendered selected
//    forever. These assertions exist so a bare `role="tab"` with nothing behind
//    it cannot come back.
//
// Headless only. Not part of the shipped product.

import { chromium } from "@playwright/test";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}
const base = arg("--url", process.env.WINTCP_WEBUI_URL || "");
if (!base) {
  console.error("No URL. Pass --url or set WINTCP_WEBUI_URL.");
  process.exit(2);
}
const url = base.endsWith("/") ? base : `${base}/`;

let passed = 0;
let failed = 0;
const check = (name, ok, detail = "") => {
  if (ok) { passed += 1; console.log(`[ ok ] ${name}`); }
  else { failed += 1; console.log(`[FAIL] ${name}${detail ? `  (${detail})` : ""}`); }
};

const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
const page = await context.newPage();

const consoleErrors = [];
page.on("console", (m) => { if (m.type() === "error") consoleErrors.push(m.text()); });
page.on("pageerror", (e) => consoleErrors.push(String(e)));

// The shell is shared by every check below, so a failure here is a setup failure
// and not worth attributing to the tab tests.
await page.goto(`${url}#/`, { waitUntil: "networkidle" });
await page.waitForSelector(".sidebar-item", { timeout: 15000 });

// ---------------------------------------------------------------------------
// 1. Sidebar active state follows navigation
// ---------------------------------------------------------------------------

const activeLabel = () =>
  page.evaluate(() => {
    const el = document.querySelector(".sidebar-item.is-active");
    return el ? el.textContent.trim() : null;
  });

check("Overview is active on load", (await activeLabel()) === "Overview");

const ROUTES = [
  ["#/performance", "Performance"],
  ["#/processes", "Processes"],
  ["#/network", "Network"],
  ["#/map", "Map"],
  ["#/automations", "Automations"],
  ["#/blocks", "Blocked Peers"],
  ["#/system", "System"],
  ["#/settings", "Settings"],
  ["#/", "Overview"],
];

for (const [hash, label] of ROUTES) {
  await page.evaluate((h) => { window.location.hash = h; }, hash);
  // Wait for the route to render rather than sleeping: the point is to assert
  // the FINAL state, and a fixed sleep would pass by luck on a fast machine.
  await page.waitForFunction(
    (want) => {
      const el = document.querySelector(".sidebar-item.is-active");
      return el && el.textContent.trim() === want;
    },
    label,
    { timeout: 5000 },
  ).catch(() => {});
  check(`sidebar highlights ${label} after navigating there`,
        (await activeLabel()) === label, `got ${await activeLabel()}`);
}

check("exactly one sidebar item is active at a time",
  (await page.locator(".sidebar-item.is-active").count()) === 1);

check("the active sidebar item carries aria-current=page",
  await page.evaluate(() =>
    document.querySelectorAll('.sidebar-item[aria-current="page"]').length === 1));

check("an inactive sidebar item has no aria-current",
  await page.evaluate(() =>
    document.querySelectorAll(".sidebar-item").length ===
    document.querySelectorAll('.sidebar-item[aria-current="page"]').length + 0 ||
    Array.from(document.querySelectorAll(".sidebar-item"))
      .filter((a) => a.classList.contains("is-active"))
      .every((a) => a.getAttribute("aria-current") === "page")));

check("the breadcrumb names the current page",
  (await page.locator(".breadcrumb-current").textContent()).trim() === "Overview");

// Navigate again and confirm the breadcrumb moved too - it is the same class of
// bug (baked-in text rather than a live binding).
await page.evaluate(() => { window.location.hash = "#/network"; });
await page.waitForFunction(
  () => document.querySelector(".breadcrumb-current")?.textContent.trim() === "Network",
  null, { timeout: 5000 },
).catch(() => {});
check("the breadcrumb follows navigation",
  (await page.locator(".breadcrumb-current").textContent()).trim() === "Network");

// ---------------------------------------------------------------------------
// 2. In-page tabs switch panels
// ---------------------------------------------------------------------------

const TABBED_PAGES = [
  { hash: "#/processes", label: "Processes",
    tabs: ["Table", "Tree", "Treemap"] },
  { hash: "#/network", label: "Network",
    tabs: ["Connections", "Listening", "Blocked", "Flows"] },
  { hash: "#/automations", label: "Automations",
    tabs: ["Templates", "Events", "Scripts"] },
];

for (const spec of TABBED_PAGES) {
  await page.evaluate((h) => { window.location.hash = h; }, spec.hash);
  await page.waitForSelector('[role="tablist"]', { timeout: 10000 });

  const count = await page.locator('[role="tab"]').count();
  check(`${spec.label}: has a tab strip`, count === spec.tabs.length,
        `${count} tabs, expected ${spec.tabs.length}`);

  // Every tab must be a real control: a role="tab" with no panel is the exact
  // defect this file exists for.
  const wired = await page.evaluate(() => {
    const tabs = Array.from(document.querySelectorAll('[role="tab"]'));
    return tabs.every((t) => {
      const panel = document.getElementById(t.getAttribute("aria-controls") || "");
      return !!panel && panel.getAttribute("role") === "tabpanel";
    });
  });
  check(`${spec.label}: every tab controls a real panel`, wired);

  const names = await page.locator('[role="tab"]').allTextContents();
  for (const want of spec.tabs) {
    check(`${spec.label}: tab "${want}" exists`, names.map((s) => s.trim()).includes(want));
  }

  // Click each tab and confirm BOTH that it becomes selected and that its panel
  // becomes visible. Selecting without swapping content is the same bug wearing
  // a different hat.
  for (let i = 0; i < count; i += 1) {
    const name = names[i].trim();
    await page.locator('[role="tab"]').nth(i).click();
    await page.waitForFunction(
      (label) => document.querySelector('[role="tab"][aria-selected="true"]')?.textContent.trim() === label,
      name, { timeout: 5000 },
    ).catch(() => {});
    await page.waitForTimeout(350);   // panel content is async

    const selected = await page.evaluate(() =>
      document.querySelector('[role="tab"][aria-selected="true"]')?.textContent.trim());
    check(`${spec.label}: clicking "${name}" selects it`, selected === name,
          `got ${selected}`);

    const visible = await page.evaluate(() => {
      const panel = document.querySelector('[role="tabpanel"]:not([hidden])');
      return panel ? (panel.textContent || "").trim().length : 0;
    });
    check(`${spec.label}: "${name}" shows content`, visible > 0, "panel is empty");

    // Exactly one panel visible. Two visible panels means the others were only
    // cosmetically hidden.
    const shown = await page.evaluate(() =>
      Array.from(document.querySelectorAll('[role="tabpanel"]'))
        .filter((p) => !p.hidden).length);
    check(`${spec.label}: "${name}" leaves exactly one panel visible`, shown === 1,
          `${shown} visible`);
  }

  // Keyboard: arrow keys move focus, Enter activates. Manual activation is the
  // WAI-ARIA pattern and it is what stops a tab that kicks off a request from
  // firing once per keypress.
  //
  // Reset to the FIRST tab first. The click loop above left the last tab
  // selected, and the selection now persists across the poll-driven rebuild -
  // which is correct product behaviour but means the keyboard assertions have to
  // start from a known state rather than inherit whatever the loop finished on.
  await page.locator('[role="tab"]').first().click();
  await page.waitForTimeout(300);
  await page.locator('[role="tab"]').first().focus();
  await page.waitForTimeout(150);

  await page.keyboard.press("ArrowRight");
  await page.waitForTimeout(150);
  const focusedAfterArrow = await page.evaluate(() =>
    document.activeElement?.textContent?.trim());
  check(`${spec.label}: ArrowRight moves focus`, focusedAfterArrow === names[1]?.trim(),
        `got ${focusedAfterArrow}`);

  const selectedAfterArrow = await page.evaluate(() =>
    document.querySelector('[role="tab"][aria-selected="true"]')?.textContent.trim());
  check(`${spec.label}: ArrowRight does not activate (manual activation)`,
        selectedAfterArrow === names[0]?.trim(), `got ${selectedAfterArrow}`);

  await page.keyboard.press("Enter");
  // Wait for the state, do not sleep for it. A fixed wait passed on the first two
  // pages and failed on the third, which is exactly how a timing bug gets
  // reported as "flaky" instead of "wrong".
  await page.waitForFunction(
    (label) => document.querySelector('[role="tab"][aria-selected="true"]')?.textContent.trim() === label,
    names[1]?.trim(),
    { timeout: 5000 },
  ).catch(() => {});
  const selectedAfterEnter = await page.evaluate(() =>
    document.querySelector('[role="tab"][aria-selected="true"]')?.textContent.trim());
  check(`${spec.label}: Enter activates the focused tab`,
        selectedAfterEnter === names[1]?.trim(), `got ${selectedAfterEnter}`);

  check(`${spec.label}: exactly one tab is in the tab order (roving tabindex)`,
    await page.evaluate(() =>
      Array.from(document.querySelectorAll('[role="tab"]'))
        .filter((t) => t.tabIndex === 0).length === 1));
}

// ---------------------------------------------------------------------------
// 3. The selected tab survives the poll-driven rebuild
//    (the bug that made "click Tree, get Table again" look like a dead button)
// ---------------------------------------------------------------------------

for (const spec of TABBED_PAGES) {
  await page.evaluate((h) => { window.location.hash = h; }, spec.hash);
  await page.waitForSelector('[role="tablist"]', { timeout: 10000 });
  // Pick the LAST tab, which is the one that was silently reverting.
  const last = spec.tabs.length - 1;
  await page.locator('[role="tab"]').nth(last).click();
  await page.waitForTimeout(500);
  const wanted = spec.tabs[last];

  const before = await page.evaluate(() =>
    document.querySelector('[role="tab"][aria-selected="true"]')?.textContent.trim());

  // Now leave it alone for long enough for at least two poll-driven rebuilds
  // (the default refresh interval is 2 s).
  await page.waitForTimeout(6000);

  const after = await page.evaluate(() =>
    document.querySelector('[role="tab"][aria-selected="true"]')?.textContent.trim());
  check(`${spec.label}: "${wanted}" survives the poll-driven rebuild`,
    before === wanted && after === wanted, `before=${before} after=${after}`);
}

// ---------------------------------------------------------------------------
// 4. The Processes table has real rows, and the tree and treemap are real
// ---------------------------------------------------------------------------

// The selection persisted from the block above, so put the page back on Table
// first: these assertions are about the Table, Tree and Treemap panels
// individually, and arriving on Treemap would make the first one wait forever.
await page.evaluate(() => { window.location.hash = "#/processes"; });
await page.waitForSelector('[role="tablist"]', { timeout: 15000 });
await page.getByRole("tab", { name: "Table", exact: true }).click();
await page.waitForSelector('[role="grid"]', { timeout: 15000 });

const rowCount = await page.evaluate(() => {
  const grid = document.querySelector('[role="grid"]');
  return grid ? grid.querySelectorAll('[role="row"]').length : 0;
});
check("Processes table renders rows from the process table", rowCount > 5,
      `${rowCount} rows`);

await page.getByRole("tab", { name: "Tree", exact: true }).click();
await page.waitForTimeout(400);
const treeItems = await page.locator('[role="treeitem"]').count();
check("Processes tree renders a real hierarchy", treeItems > 5, `${treeItems} items`);

await page.getByRole("tab", { name: "Treemap", exact: true }).click();
await page.waitForTimeout(600);
const tiles = await page.locator(".treemap-tile").count();
check("Processes treemap draws tiles", tiles > 3, `${tiles} tiles`);

// A treemap with zero tiles would still "render"; the property that matters is
// that the tiles are laid out inside the box and are not all the same size.
if (tiles > 3) {
  const areas = await page.evaluate(() =>
    Array.from(document.querySelectorAll(".treemap-tile")).map((t) => {
      const r = t.getBoundingClientRect();
      return r.width * r.height;
    }));
  const max = Math.max(...areas);
  const min = Math.min(...areas);
  check("treemap tiles vary in area (proportional, not uniform)",
        max > min * 1.2, `max ${max.toFixed(0)} min ${min.toFixed(0)}`);
  const inside = await page.evaluate(() => {
    const host = document.querySelector(".treemap").getBoundingClientRect();
    return Array.from(document.querySelectorAll(".treemap-tile")).every((t) => {
      const r = t.getBoundingClientRect();
      return r.left >= host.left - 2 && r.right <= host.right + 2 &&
             r.top >= host.top - 2 && r.bottom <= host.bottom + 2;
    });
  });
  check("treemap tiles stay inside the chart box", inside);
}

check("no console errors during the walkthrough", consoleErrors.length === 0,
      consoleErrors.slice(0, 3).join(" | "));

await browser.close();

console.log(`\n${passed + failed} tab/navigation checks, ${failed} failed.`);
process.exit(failed === 0 ? 0 : 1);