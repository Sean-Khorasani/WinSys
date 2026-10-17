// soak.mjs - Dev-only soak test for the WinTCP Web UI.
//
//   node tools/webui-e2e/soak.mjs --url http://127.0.0.1:1234/ --minutes 10
//
// Two soak questions, answered separately:
//
//   UI   - does the browser-side page survive continuous polling and repeated
//          navigation? Counts console errors, CSP violations, failed requests,
//          and heap growth in the page.
//
//   BACK - does the SERVER survive it? Samples its working set, handle count,
//          thread count and private bytes over the run and reports the slope.
//          A leak shows up as a steady climb that does not flatten.
//
// Headless only. Not part of the shipped product.

import { chromium } from "@playwright/test";
import { mkdir, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "..", "..");

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const url = arg("--url", process.env.WINTCP_WEBUI_URL || "");
const minutes = Number(arg("--minutes", "10"));
if (!url) {
  console.error("No URL. Pass --url or set WINTCP_WEBUI_URL.");
  process.exit(2);
}

const PAGES = ["#/", "#/performance", "#/processes", "#/network", "#/map",
               "#/automations", "#/blocks", "#/system", "#/settings"];

function serverPids() {
  const out = execFileSync("powershell.exe", [
    "-NoProfile", "-Command",
    "Get-Process wintcp -ErrorAction SilentlyContinue | " +
    "Select-Object -ExpandProperty Id",
  ], { encoding: "utf8" });
  return out.split(/\r?\n/).map((s) => Number(s.trim())).filter((n) => n > 0);
}

function serverStats(pids) {
  if (pids.length === 0) return null;
  const script = `
$ErrorActionPreference='SilentlyContinue'
$p = Get-Process -Id ${pids.join(",")}
[pscustomobject]@{
  Handles    = ($p | Measure-Object Handles -Sum).Sum
  Threads    = ($p | ForEach-Object { $_.Threads.Count } | Measure-Object -Sum).Sum
  WorkingSet = [math]::Round((($p | Measure-Object WorkingSet64 -Sum).Sum)/1MB,1)
  PrivateMB  = [math]::Round((($p | Measure-Object PrivateMemorySize64 -Sum).Sum)/1MB,1)
} | ConvertTo-Json -Compress`;
  const out = execFileSync("powershell.exe", ["-NoProfile", "-Command", script],
                           { encoding: "utf8" });
  return JSON.parse(out);
}

const consoleErrors = [];
const cspViolations = [];
const failedRequests = [];

const pids = serverPids();
if (pids.length === 0) {
  console.error("No wintcp.exe process found. Start the service first.");
  process.exit(2);
}
const before = serverStats(pids);
console.log(`Soak: ${minutes} min against ${url}`);
console.log(`Server PIDs: ${pids.join(", ")}`);
console.log(`Baseline: ${JSON.stringify(before)}`);

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
const page = await context.newPage();
page.on("console", (m) => { if (m.type() === "error") consoleErrors.push(m.text()); });
page.on("pageerror", (e) => consoleErrors.push("pageerror: " + e.message));
page.on("requestfailed", (r) => failedRequests.push(`${r.url()} ${r.failure()?.errorText ?? ""}`));

await page.goto(`${url}#/`, { waitUntil: "networkidle" });
await page.waitForSelector(".sidebar");

const heap0 = await page.evaluate(() => performance.memory?.usedJSHeapSize ?? 0);
const started = Date.now();
const samples = [];
const tickMs = 30000;

process.stdout.write("  ");
while (Date.now() - started < minutes * 60000) {
  // Rotate pages: the interesting failures are the ones a single page never hits.
  const hash = PAGES[Math.floor((Date.now() - started) / tickMs) % PAGES.length];
  await page.evaluate((h) => { window.location.hash = h; }, hash).catch(() => {});
  await page.waitForTimeout(4000);

  const heap = await page.evaluate(() => performance.memory?.usedJSHeapSize ?? 0);
  const csp = await page.evaluate(() => (globalThis.__wintcpCspViolations || []).length);
  const stat = serverStats(pids);
  samples.push({
    atSeconds: Math.round((Date.now() - started) / 1000),
    heapMB: Math.round(heap / 1048576),
    cspViolations: csp,
    consoleErrors: consoleErrors.length,
    failedRequests: failedRequests.length,
    server: stat,
  });
  process.stdout.write(".");
}
process.stdout.write("\n");

const after = serverStats(pids);
const heapEnd = await page.evaluate(() => performance.memory?.usedJSHeapSize ?? 0);

await browser.close();
await context.close();

// Slope over the last two thirds, to ignore start-up ramp.
function slope(series) {
  const tail = series.slice(Math.floor(series.length / 3));
  if (tail.length < 2) return 0;
  const first = tail[0];
  const last = tail[tail.length - 1];
  const span = last.atSeconds - first.atSeconds || 1;
  return (last.server.PrivateMB - first.server.PrivateMB) / (span / 60);
}

const report = {
  when: new Date().toISOString(),
  url,
  minutes,
  samples,
  consoleErrors,
  cspViolations: cspViolations.length,
  failedRequests,
  server: { before, after, privateMbPerMinute: Number(slope(samples).toFixed(3)) },
  pageHeap: { startMB: Math.round(heap0 / 1048576), endMB: Math.round(heapEnd / 1048576) },
};

const out = resolve(repo, "docs", "img");
await mkdir(out, { recursive: true });
await writeFile(resolve(out, "soak-report.json"), JSON.stringify(report, null, 2) + "\n", "utf8");

console.log("");
console.log(`Samples:          ${samples.length}`);
console.log(`Console errors:   ${consoleErrors.length}`);
console.log(`CSP violations:   ${cspViolations.length}`);
console.log(`Failed requests:  ${failedRequests.length}`);
console.log(`Page heap:        ${report.pageHeap.startMB} MB -> ${report.pageHeap.endMB} MB`);
console.log(`Server private:   ${before.PrivateMB} MB -> ${after.PrivateMB} MB ` +
            `(${report.server.privateMbPerMinute} MB/min)`);
console.log(`Server handles:   ${before.Handles} -> ${after.Handles}`);
console.log(`Server threads:   ${before.Threads} -> ${after.Threads}`);
console.log("Report: docs/img/soak-report.json");

const problems = [];
if (consoleErrors.length) problems.push(`${consoleErrors.length} console errors`);
if (cspViolations.length) problems.push(`${cspViolations.length} CSP violations`);
if (failedRequests.length) problems.push(`${failedRequests.length} failed requests`);
if (report.server.privateMbPerMinute > 2) {
  problems.push(`server grew ${report.server.privateMbPerMinute} MB/min`);
}
if (after.Handles > before.Handles * 1.1 + 32) {
  problems.push(`handles ${before.Handles} -> ${after.Handles}`);
}
if (problems.length) {
  console.log("");
  console.log("SOAK FAILED: " + problems.join("; "));
  process.exit(1);
}
console.log("");
console.log("SOAK PASSED");