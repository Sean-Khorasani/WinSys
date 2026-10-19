// axe-check.mjs - Dev-only accessibility audit of the WinTCP Web UI.
//
//   node tools/webui-e2e/axe-check.mjs --url http://127.0.0.1:1234/
//
// Runs axe-core against every page in both themes and fails on any 'serious' or
// 'critical' violation. Also reports the muted-text contrast ratio explicitly,
// because that is the token pair most likely to fail and the one the design
// guide cares about.
//
// Headless only. Not part of the shipped product.

import { chromium } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { auditContrastInPage } from "./contrast.mjs";
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

const PAGES = [
  ["#/", "Overview"],
  ["#/performance", "Performance"],
  ["#/processes", "Processes"],
  ["#/network", "Network"],
  ["#/map", "Map"],
  ["#/automations", "Automations"],
  ["#/blocks", "Blocked Peers"],
  ["#/system", "System"],
  ["#/settings", "Settings"],
];

const THEMES = ["light", "dark"];
const onlyProcessDialog = process.argv.includes("--only-process-dialog");
const report = { when: new Date().toISOString(), url, pages: [] };
let failures = 0;

const browser = await chromium.launch({ headless: true });
try {
  for (const theme of THEMES) {
    for (const [hash, name] of (onlyProcessDialog ? [] : PAGES)) {
      const context = await browser.newContext({
        viewport: { width: 1440, height: 900 },
        colorScheme: theme,
      });
      const page = await context.newPage();
      await page.goto(`${url}${hash}`, { waitUntil: "networkidle", timeout: 20000 });
      await page.waitForSelector(".sidebar", { timeout: 10000 });
      await page.waitForTimeout(500);

      // axe's own color-contrast rule is DISABLED. Chrome returns oklch() from
      // getComputedStyle and axe's parser only understands rgb()/hex, so it walks
      // up the tree, measures the wrong background, and reports 18 bogus serious
      // violations. contrast.mjs measures the same property correctly by letting
      // the BROWSER resolve the colour first; see that file for the full story.
      const results = await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
        .disableRules(["color-contrast"])
        .analyze();

      const contrast = await page.evaluate(auditContrastInPage, {
        minRatio: 4.5,
        largeTextMinRatio: 3,
      });
      const contrastFailures = contrast.filter((c) => !c.passes);

      const blocking = results.violations.filter(
        (v) => v.impact === "serious" || v.impact === "critical",
      );
      const entry = {
        theme,
        page: hash,
        name,
        violations: results.violations.map((v) => ({
          id: v.id,
          impact: v.impact,
          help: v.help,
          nodes: v.nodes.length,
          sample: v.nodes.slice(0, 2).map((n) => n.html.slice(0, 160)),
        })),
        contrast: {
          checked: contrast.length,
          failures: contrastFailures.length,
          worst: contrast
            .slice()
            .sort((a, b) => a.ratio - b.ratio)
            .slice(0, 6),
        },
        blocking: blocking.length,
        passes: results.passes.length,
      };
      report.pages.push(entry);

      const tag = blocking.length === 0 && contrastFailures.length === 0 ? " ok " : "FAIL";
      if (blocking.length > 0 || contrastFailures.length > 0) failures++;
      const minor = results.violations.length - blocking.length;
      const worst = contrast.slice().sort((a, b) => a.ratio - b.ratio)[0];
      console.log(
        `[${tag}] ${theme.padEnd(5)} ${name.padEnd(14)} ` +
          `${blocking.length} serious/critical, ${minor} minor, ${results.passes.length} passed, ` +
          `contrast ${contrastFailures.length}/${contrast.length} fail (worst ` +
          `${worst ? `${worst.ratio}:1 ${worst.selector}` : "n/a"})`,
      );
      for (const c of contrastFailures.slice(0, 5)) {
        console.log(
          `         - contrast ${c.ratio}:1 (needs ${c.required}:1) ` +
            `${c.selector} ${c.foreground} on ${c.background} "${c.text}"`,
        );
      }
      for (const v of blocking) {
        console.log(`         - [${v.impact}] ${v.id}: ${v.help} (${v.nodes.length} node(s))`);
        for (const node of v.nodes.slice(0, 2)) console.log(`           ${node.html.slice(0, 140)}`);
      }

      await context.close();
    }

    const dialogContext = await browser.newContext({
      viewport: { width: 1440, height: 900 },
      colorScheme: theme,
    });
    await dialogContext.route("**/api/connections*", (route) => route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ connections: [] }),
    }));
    await dialogContext.route("**/api/processes*", (route) => route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ known: true, total: 2, processes: [
        { pid: 4101, ppid: 4, instanceId: "4101:1:4101", name: "fixture.exe", path: "C:\\Apps\\fixture.exe", cpuPct: 2, memWs: 1048576 },
        { pid: 4102, ppid: 4, instanceId: "4102:1:4102", name: "fixture.exe", path: "C:\\Apps\\fixture.exe", cpuPct: 3, memWs: 2097152 },
      ] }),
    }));
    const dialogPage = await dialogContext.newPage();
    const processResponses = [];
    const pageErrors = [];
    dialogPage.on("response", (response) => {
      if (new URL(response.url()).pathname === "/api/processes")
        processResponses.push(`${response.status()} ${response.url()}`);
    });
    dialogPage.on("pageerror", (error) => pageErrors.push(error.message));
    await dialogPage.goto(`${url}#/processes`, { waitUntil: "networkidle", timeout: 20000 });
    await dialogPage.locator("#tab-treemap").waitFor({ timeout: 10000 }).catch(async () => {
      throw new Error("Process views did not mount: " + JSON.stringify({
        text: (await dialogPage.locator("#page").innerText()).slice(0, 500),
        processResponses,
        pageErrors,
      }));
    });
    await dialogPage.locator("#tab-treemap").click();
    await dialogPage.getByRole("button", { name: "Group by executable" }).click();
    await dialogPage.locator('.treemap-tile[aria-label*="fixture.exe; 2 process instances"]').click();
    await dialogPage.locator(".process-group-dialog").waitFor();
    const dialogResults = await new AxeBuilder({ page: dialogPage })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .disableRules(["color-contrast"])
      .analyze();
    const dialogContrast = await dialogPage.evaluate(auditContrastInPage, {
      minRatio: 4.5,
      largeTextMinRatio: 3,
    });
    const dialogContrastFailures = dialogContrast.filter((entry) => !entry.passes);
    const dialogBlocking = dialogResults.violations.filter((entry) =>
      entry.impact === "serious" || entry.impact === "critical");
    const dialogFailure = dialogBlocking.length > 0 || dialogContrastFailures.length > 0;
    report.pages.push({
      theme,
      page: "#/processes/grouped-instance-dialog",
      name: "Grouped process instance dialog",
      violations: dialogResults.violations.map((entry) => ({
        id: entry.id, impact: entry.impact, help: entry.help, nodes: entry.nodes.length,
        sample: entry.nodes.slice(0, 2).map((node) => node.html.slice(0, 160)),
      })),
      contrast: {
        checked: dialogContrast.length,
        failures: dialogContrastFailures.length,
        worst: dialogContrast.slice().sort((a, b) => a.ratio - b.ratio).slice(0, 6),
      },
      blocking: dialogBlocking.length,
      passes: dialogResults.passes.length,
    });
    if (dialogFailure) failures++;
    console.log(`[${dialogFailure ? "FAIL" : " ok "}] ${theme.padEnd(5)} grouped process chooser ` +
      `${dialogBlocking.length} serious/critical, contrast ${dialogContrastFailures.length}/${dialogContrast.length} fail`);
    await dialogContext.close();
  }

  // Explicit contrast measurement for the muted-text token pair. axe reports
  // contrast as a violation only when it fails WCAG AA; recording the actual
  // ratio makes a regression visible before it becomes a violation.
  console.log("");
  console.log("Muted-text contrast (WCAG AA needs 4.5:1 for body text):");
  if (!onlyProcessDialog) for (const theme of THEMES) {
    const context = await browser.newContext({
      viewport: { width: 1440, height: 900 },
      colorScheme: theme,
    });
    const page = await context.newPage();
    await page.goto(`${url}#/settings`, { waitUntil: "networkidle" });
    await page.waitForSelector(".sidebar");
    await page.waitForTimeout(400);
    const probe = await page.evaluate(() => {
      const resolved = getComputedStyle(document.documentElement);
      const px = (name) => resolved.getPropertyValue(name).trim();
      const sample = document.createElement("p");
      sample.className = "muted";
      sample.textContent = "contrast sample";
      document.body.append(sample);
      const color = getComputedStyle(sample).color;
      sample.remove();
      return { background: px("--background"), foreground: px("--muted-foreground"), color };
    });
    console.log(`  ${theme.padEnd(5)} fg=${probe.foreground || probe.color} bg=${probe.background}`);
    await context.close();
  }
} finally {
  await browser.close();
}

const out = resolve(repo, "temp", "webui-reports");
await mkdir(out, { recursive: true });
await writeFile(resolve(out, "a11y-report.json"), JSON.stringify(report, null, 2) + "\n", "utf8");
console.log("");
console.log(`Report: temp/webui-reports/a11y-report.json`);
console.log(`${report.pages.length} page/theme audits, ${failures} with serious or critical issues.`);
process.exit(failures === 0 ? 0 : 1);
