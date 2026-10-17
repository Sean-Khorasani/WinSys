// screenshots.mjs - Dev-only screenshots of the WinTCP Web UI.
//
//   node tools/webui-e2e/screenshots.mjs --url http://127.0.0.1:1234/ [--all]
//
// Default: the 8 representative shots that go into docs/img/ and the README.
// With --all: every page at 1280x720, 1440x900 and 1920x1080 in both themes.
//
// Headless only. Not part of the shipped product.

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
const hasFlag = (name) => process.argv.includes(name);

const url = arg("--url", process.env.WINTCP_WEBUI_URL || "");
if (!url) {
  console.error("No URL. Pass --url or set WINTCP_WEBUI_URL.");
  process.exit(2);
}

const PAGES = [
  ["#/", "overview", "Overview"],
  ["#/performance", "performance", "Performance"],
  ["#/processes", "processes", "Processes"],
  ["#/network", "network", "Network"],
  ["#/map", "map", "Map"],
  ["#/automations", "automations", "Automations"],
  ["#/blocks", "blocks", "Blocked peers"],
  ["#/system", "system", "System"],
  ["#/settings", "settings", "Settings"],
];

const SIZES = hasFlag("--all")
  ? [
      { w: 1280, h: 720, label: "1280x720" },
      { w: 1440, h: 900, label: "1440x900" },
      { w: 1920, h: 1080, label: "1920x1080" },
    ]
  : [{ w: 1440, h: 900, label: "1440x900" }];

const THEMES = hasFlag("--all") ? ["light", "dark"] : ["dark"];
const outDir = resolve(repo, "docs", "img");
await mkdir(outDir, { recursive: true });

const browser = await chromium.launch({ headless: true });
const written = [];
try {
  for (const theme of THEMES) {
    for (const size of SIZES) {
      for (const [hash, slug, name] of PAGES) {
        const context = await browser.newContext({
          viewport: { width: size.w, height: size.h },
          colorScheme: theme,
          deviceScaleFactor: 1,
        });
        const page = await context.newPage();
        await page.goto(`${url}${hash}`, { waitUntil: "networkidle", timeout: 25000 });
        await page.waitForSelector(".sidebar", { timeout: 10000 });
        // Let the first poll land and the charts get real numbers to draw.
        await page.waitForTimeout(1200);

        const suffix = THEMES.length > 1 ? `-${theme}` : "";
        const sizeSuffix = SIZES.length > 1 ? `-${size.label}` : "";
        const file = resolve(outDir, `webui-${slug}${suffix}${sizeSuffix}.png`);
        await page.screenshot({ path: file, fullPage: false });
        written.push(file);
        console.log(`  ${name.padEnd(14)} ${theme.padEnd(5)} ${size.label.padEnd(9)} -> ${file.replace(repo + "\\", "")}`);
        await context.close();
      }
    }
  }
} finally {
  await browser.close();
}

console.log("");
console.log(`${written.length} screenshot(s) written to docs/img/.`);