// keyboard-check.mjs - Dev-only keyboard-only walkthrough of the Web UI.
//
//   node tools/webui-e2e/keyboard-check.mjs --url http://127.0.0.1:1234/
//
// Drives the UI with nothing but the keyboard, which is the only way to find out
// whether it is actually operable without a mouse: focus order, visible focus,
// the command palette, and - the one that actually breaks - whether the
// virtualised table can be scrolled and navigated from the keyboard.
//
// Headless only. Not part of the shipped product.

import { chromium } from "@playwright/test";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "..", "..");

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const url = arg("--url", process.env.WINTCP_WEBUI_URL || "");
if (!url) {
  console.error("No URL. Pass --url or set WINTCP_WEBUI_URL.");
  process.exit(2);
}

const checks = [];
function check(name, pass, detail = "") {
  checks.push({ name, pass, detail });
  console.log(`[${pass ? " ok " : "FAIL"}] ${name}${detail ? " - " + detail : ""}`);
}

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
const page = await context.newPage();

const consoleErrors = [];
page.on("console", (m) => { if (m.type() === "error") consoleErrors.push(m.text()); });
page.on("pageerror", (e) => consoleErrors.push("pageerror: " + e.message));

await page.goto(`${url}#/`, { waitUntil: "networkidle" });
await page.waitForSelector(".sidebar");
await page.waitForTimeout(600);

try {
  // 1. The page must be reachable by keyboard at all.
  await page.keyboard.press("Tab");
  const firstFocus = await page.evaluate(() => {
    const el = document.activeElement;
    if (!el || el === document.body) return null;
    return {
      tag: el.tagName.toLowerCase(),
      text: (el.textContent || el.getAttribute("aria-label") || "").trim().slice(0, 40),
    };
  });
  check("Tab moves focus into the page", !!firstFocus,
    firstFocus ? `${firstFocus.tag} "${firstFocus.text}"` : "focus stayed on <body>");

  // 2. Every focusable control must show a visible focus indicator.
  const focusRing = await page.evaluate(() => {
    const results = [];
    const focusable = document.querySelectorAll(
      'a[href], button:not([disabled]), input, select, textarea, [tabindex]:not([tabindex="-1"])',
    );
    for (const el of Array.from(focusable).slice(0, 40)) {
      el.focus();
      const s = getComputedStyle(el);
      const hasOutline = s.outlineStyle !== "none" && parseFloat(s.outlineWidth) > 0;
      const hasShadow = s.boxShadow && s.boxShadow !== "none";
      const hasBorderChange = s.borderColor !== "";
      if (!hasOutline && !hasShadow && !hasBorderChange) {
        results.push(el.tagName.toLowerCase() + "." + (el.className || "").toString().split(" ")[0]);
      }
    }
    return results;
  });
  check("Focused controls have a visible focus indicator", focusRing.length === 0,
    focusRing.length ? `no indicator on: ${focusRing.join(", ")}` : "all sampled controls styled");

  // 3. Ctrl+K opens the command palette and Escape closes it.
  await page.keyboard.press("Escape");
  await page.keyboard.press("Control+k");
  await page.waitForTimeout(250);
  const paletteOpen = await page.evaluate(() => {
    const overlay = document.querySelector(".command-palette-overlay");
    return overlay ? getComputedStyle(overlay).display !== "none" : false;
  });
  check("Ctrl+K opens the command palette", paletteOpen);

  if (paletteOpen) {
    await page.keyboard.type("System");
    await page.waitForTimeout(200);
    const filtered = await page.evaluate(() =>
      document.querySelectorAll(".command-item").length);
    check("Palette filters as you type", filtered > 0 && filtered <= 3, `${filtered} item(s)`);
    await page.keyboard.press("Enter");
    await page.waitForTimeout(700);
    const landed = await page.evaluate(() => window.location.hash);
    check("Palette Enter navigates", landed === "#/system", `hash is ${landed}`);
  }

  // 4. The virtualised table must be keyboard-scrollable and navigable.
  await page.goto(`${url}#/processes`, { waitUntil: "networkidle" });
  await page.waitForSelector(".virtual-table");
  // Wait for real rows. The grid is created on route render, before the first
  // poll lands, so selecting the element alone is a race.
  await page.waitForFunction(
    () => document.querySelectorAll('.virtual-table [role="row"][data-index]').length > 3,
    null,
    { timeout: 15000 },
  ).catch(() => {});
  await page.waitForTimeout(400);

  const gridInfo = await page.evaluate(() => {
    const grid = document.querySelector(".virtual-table");
    if (!grid) return null;
    grid.focus();
    return {
      role: grid.getAttribute("role"),
      tabindex: grid.getAttribute("tabindex"),
      label: grid.getAttribute("aria-label"),
      rowcount: grid.getAttribute("aria-rowcount"),
      focused: document.activeElement === grid,
      rows: grid.querySelectorAll('[role="row"][data-index]').length,
    };
  });
  check("Processes grid exposes role=grid with a name",
    !!gridInfo && gridInfo.role === "grid" && !!gridInfo.label,
    gridInfo ? `role=${gridInfo.role} label="${gridInfo.label}" rows=${gridInfo.rows}` : "no grid");
  check("Processes grid is focusable", !!gridInfo && gridInfo.focused);

  await page.keyboard.press("ArrowDown");
  await page.keyboard.press("ArrowDown");
  await page.waitForTimeout(200);
  const afterDown = await page.evaluate(() => {
    const active = document.querySelector('[role="row"][data-index].is-active');
    return active ? active.getAttribute("data-index") : null;
  });
  check("Arrow keys move the row selection", afterDown !== null, `active row index=${afterDown}`);

  await page.keyboard.press("End");
  await page.waitForTimeout(300);
  const scrolled = await page.evaluate(() => {
    const grid = document.querySelector(".virtual-table");
    return { scrollTop: grid.scrollTop, scrollHeight: grid.scrollHeight };
  });
  check("End scrolls the grid to the last row",
    scrolled.scrollTop > 0,
    `scrollTop=${Math.round(scrolled.scrollTop)} of ${Math.round(scrolled.scrollHeight)}`);

  await page.keyboard.press("Home");
  await page.waitForTimeout(300);
  const backHome = await page.evaluate(() => document.querySelector(".virtual-table").scrollTop);
  check("Home returns to the first row", backHome === 0, `scrollTop=${backHome}`);

  const columnsSummary = page.locator(".column-layout > summary").first();
  await columnsSummary.focus();
  await page.keyboard.press("Enter");
  const columnsOpen = await page.locator(".column-layout").first().evaluate((element) => element.open);
  check("Column layout controls open from the keyboard", columnsOpen);
  await page.keyboard.press("Tab");
  const layoutFocus = await page.evaluate(() => document.activeElement?.getAttribute("data-layout-control"));
  check("Column layout options enter the keyboard tab order", layoutFocus === "preset-default", `focused=${layoutFocus}`);

  // 5. Sidebar navigation must work from the keyboard.
  await page.goto(`${url}#/`, { waitUntil: "networkidle" });
  await page.waitForSelector(".sidebar");
  await page.waitForTimeout(400);
  const reached = await page.evaluate(async () => {
    const link = Array.from(document.querySelectorAll(".sidebar-item"))
      .find((a) => a.getAttribute("href") === "#/network");
    if (!link) return "no link";
    link.focus();
    link.click();
    await new Promise((r) => setTimeout(r, 500));
    return window.location.hash;
  });
  check("Sidebar links navigate", reached === "#/network", `hash=${reached}`);

  // 6. A page that is not registered must say so rather than render nothing.
  await page.goto(`${url}#/no-such-page`, { waitUntil: "networkidle" });
  await page.waitForTimeout(500);
  const notFound = await page.evaluate(() => {
    const title = document.querySelector(".page-title");
    return title ? title.textContent.trim() : null;
  });
  check("Unknown route shows a not-found page", !!notFound, `title="${notFound}"`);

  check("No console errors during the walkthrough", consoleErrors.length === 0,
    consoleErrors.slice(0, 3).join(" | "));
} finally {
  await browser.close();
}

const out = resolve(repo, "temp", "webui-reports");
await mkdir(out, { recursive: true });
await writeFile(
  resolve(out, "keyboard-report.json"),
  JSON.stringify({ when: new Date().toISOString(), url, checks }, null, 2) + "\n",
  "utf8",
);

const failed = checks.filter((c) => !c.pass).length;
console.log("");
console.log(`${checks.length} keyboard checks, ${failed} failed.`);
console.log("Report: temp/webui-reports/keyboard-report.json");
process.exit(failed === 0 ? 0 : 1);
