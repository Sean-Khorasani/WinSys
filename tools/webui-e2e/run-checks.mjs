// run-checks.mjs - Dev-only headless checks for the WinTCP Web UI.
//
//   node tools/webui-e2e/run-checks.mjs [--url http://127.0.0.1:1234/]
//
// Walks every page in both themes and fails on:
//   * any console error or page error
//   * any CSP violation (recorded by wintcp/webui/js/csp.js)
//   * any failed request (404/500/CSP-blocked/net error)
//   * any page that does not render its heading
//
// Headless only. Never opens a visible browser and never touches the user's
// default browser. Not part of the shipped product.

import { chromium } from "@playwright/test";
import { mkdir } from "node:fs/promises";
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
  console.error(
    "No URL. Start the UI first:\n" +
    "  cmd.exe /c webui-service.bat start   (it prints the URL)\n" +
    "then:  node tools/webui-e2e/run-checks.mjs --url <that url>\n",
  );
  process.exit(2);
}

const PAGES = [
  { hash: "#/", expect: "Overview" },
  { hash: "#/performance", expect: "Performance" },
  { hash: "#/processes", expect: "Processes" },
  { hash: "#/network", expect: "Network" },
  { hash: "#/map", expect: "Map" },
  { hash: "#/automations", expect: "Automations" },
  { hash: "#/blocks", expect: "Blocked Peers" },
  { hash: "#/system", expect: "System" },
  { hash: "#/settings", expect: "Settings" },
];

const THEMES = ["light", "dark"];
const results = [];
let hardFailures = 0;

function record(entry) {
  results.push(entry);
  const bad = entry.problems.length > 0;
  if (bad) hardFailures++;
  const tag = bad ? "FAIL" : " ok ";
  console.log(
    `[${tag}] ${entry.theme.padEnd(5)} ${entry.page.padEnd(13)} ${entry.heading || "(no heading)"}`,
  );
  for (const p of entry.problems) console.log(`         - ${p}`);
}

const browser = await chromium.launch({ headless: true });
try {
  for (const theme of THEMES) {
    for (const page of PAGES) {
      const context = await browser.newContext({
        viewport: { width: 1440, height: 900 },
        colorScheme: theme,
        deviceScaleFactor: 1,
      });
      const tab = await context.newPage();
      const problems = [];

      tab.on("console", (msg) => {
        if (msg.type() === "error") problems.push(`console.error: ${msg.text()}`);
      });
      tab.on("pageerror", (err) => problems.push(`pageerror: ${err.message}`));
      tab.on("requestfailed", (req) => {
        problems.push(`requestfailed: ${req.url()} ${req.failure()?.errorText ?? ""}`);
      });
      tab.on("response", (res) => {
        if (res.status() >= 400) problems.push(`http ${res.status()}: ${res.url()}`);
      });

      let heading = "";
      try {
        await tab.goto(`${url}${page.hash}`, { waitUntil: "networkidle", timeout: 20000 });
        // The shell paints the sidebar + topbar before the router settles.
        await tab.waitForSelector(".sidebar", { timeout: 10000 });
        await tab.waitForTimeout(600);
        heading = (await tab.locator(".page-title").first().textContent().catch(() => "")) ?? "";
        if (!heading.trim()) problems.push("no .page-title rendered");

        const csp = await tab.evaluate(() => globalThis.__wintcpCspViolations || []);
        for (const v of csp) {
          problems.push(
            `CSP: ${v.violatedDirective || v.effectiveDirective} blocked "${v.blockedURI}"`,
          );
        }
      } catch (err) {
        problems.push(`navigation failed: ${err.message}`);
      }

      record({ theme, page: page.hash, heading: heading.trim(), problems });
      await context.close();
    }
  }
} finally {
  await browser.close();
}

const consoleDir = resolve(repo, "docs", "img");
await mkdir(consoleDir, { recursive: true });

console.log("");
console.log(`${results.length} page/theme combinations, ${hardFailures} with problems.`);

await import("node:fs/promises").then((fs) =>
  fs.writeFile(
    resolve(consoleDir, "e2e-report.json"),
    JSON.stringify({ url, when: new Date().toISOString(), results }, null, 2) + "\n",
    "utf8",
  ),
);
console.log(`Report: docs/img/e2e-report.json`);

process.exit(hardFailures === 0 ? 0 : 1);