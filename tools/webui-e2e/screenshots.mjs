import { chromium } from "@playwright/test";
import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "..", "..");
const url = process.argv[process.argv.indexOf("--url") + 1] || process.env.WINTCP_WEBUI_URL || "";
if (!url) {
  console.error("No URL. Pass --url or set WINTCP_WEBUI_URL.");
  process.exit(2);
}

const countries = ["US", "US", "US", "CA", "CA", "GB", "DE", "DE", "NL", "JP", "AU"];
const names = ["Browser.exe", "Editor.exe", "SyncAgent.exe", "UpdateService.exe", "MailClient.exe", "CloudDrive.exe"];
const processes = names.map((name, index) => ({
  name,
  pid: 4100 + index * 37,
  ppid: index < 2 ? 1200 : 4100,
  cpuPct: [18.4, 12.2, 7.8, 4.6, 2.1, 1.2][index],
  memWs: [620 * 1024 ** 2, 410 * 1024 ** 2, 238 * 1024 ** 2, 164 * 1024 ** 2, 128 * 1024 ** 2, 92 * 1024 ** 2][index],
  memPrivate: [480, 325, 180, 120, 86, 64][index] * 1024 ** 2,
  ioRead: [142, 98, 76, 62, 35, 20][index] * 1024 ** 2,
  ioWrite: [52, 44, 28, 16, 12, 8][index] * 1024 ** 2,
  connections: [4, 2, 2, 1, 1, 1][index],
  listeners: index === 2 ? 1 : 0,
}));

const connections = countries.map((country, index) => ({
  id: `demo-${index + 1}`,
  process: names[index % names.length],
  pid: processes[index % processes.length].pid,
  proto: "TCPv4",
  local: "192.0.2.25",
  lport: 52000 + index,
  remote: `203.0.113.${20 + index}`,
  rport: [443, 443, 443, 5228, 443, 443, 443, 5228, 443, 443, 443][index],
  state: "ESTABLISHED",
  country,
  hostname: ["cdn.example", "updates.example", "sync.example"][index % 3],
}));

const seriesKeys = ["cpu.total", "mem.usedBytes", "disk.readBps", "disk.writeBps", "net.rxBps", "net.txBps"];
const now = Math.floor(Date.now() / 1000);
const times = Array.from({ length: 180 }, (_, index) => now - 179 + index);
const historySeries = Object.fromEntries(seriesKeys.map((key, seriesIndex) => [
  key,
  times.map((_, index) => {
    const base = [28, 6 * 1024 ** 3, 2.2 * 1024 ** 2, 0.8 * 1024 ** 2, 3.4 * 1024 ** 2, 1.1 * 1024 ** 2][seriesIndex];
    return base * (1 + 0.12 * Math.sin((index + seriesIndex * 9) / 12));
  }),
]));

const metrics = {
  _timestamp: now,
  "cpu.total": 31.6,
  "mem.usedBytes": 6.2 * 1024 ** 3,
  "mem.totalBytes": 16 * 1024 ** 3,
  "disk.readBps": 2.3 * 1024 ** 2,
  "disk.writeBps": 0.9 * 1024 ** 2,
  "net.rxBps": 3.1 * 1024 ** 2,
  "net.txBps": 1.2 * 1024 ** 2,
  "sys.threadCount": 12,
  "sys.processCount": 126,
  "sys.handleCount": 28400,
  "sys.uptimeSeconds": 86400 * 3 + 3600 * 6,
  "mem.commitLimitBytes": 24 * 1024 ** 3,
  facts: { volumes: [{ label: "C:", volumeName: "System", fileSystem: "NTFS", totalBytes: 512 * 1024 ** 3, freeBytes: 284 * 1024 ** 3 }] },
};
for (let core = 0; core < 8; core += 1) metrics[`cpu.core.${core}`] = 16 + ((core * 13) % 44);

const demoGeo = {
  geoIpConfigured: true,
  local: 3,
  unknown: 0,
  countries: { US: 3, CA: 2, DE: 2, GB: 1, NL: 1, JP: 1, AU: 1 },
};
const fixture = {
  "/api/config": { schema: 3, preferences: { theme: "light", accent: "neutral", density: "comfortable", units: "iec" } },
  "/api/connections": { connections },
  "/api/metrics/now": metrics,
  "/api/metrics/history": { t: times, series: historySeries },
  "/api/capabilities": { perCore: true, geoIp: { configured: true } },
  "/api/processes": { processes, total: processes.length, known: true, ageMs: 250 },
  "/api/network/summary": { total: connections.length, listeners: { wildcard: 1, lan: 1, loopback: 2 }, states: { ESTABLISHED: 11, LISTENING: 4 } },
  "/api/geo/summary": demoGeo,
  "/api/system/info": {
    hostname: "Example workstation",
    os: { name: "Windows 11 Pro", version: "23H2", build: "22631", architecture: "x64" },
    cpu: { model: "12-core desktop processor", threads: 12, processorGroups: 1, architecture: "x64" },
    memory: { installed: 16 * 1024 ** 3, used: 6.2 * 1024 ** 3, available: 9.8 * 1024 ** 3, pct: 39 },
    uptime: "3 days, 6 hours",
  },
  "/api/templates": { templates: [] },
  "/api/audit": { entries: [] },
};

async function installFixtures(page) {
  await page.addInitScript((responses) => {
    const liveFetch = window.fetch.bind(window);
    window.fetch = (input, options) => {
      const rawUrl = typeof input === "string" ? input : input.url;
      const path = new URL(rawUrl, location.href).pathname;
      if (!path.startsWith("/api/")) return liveFetch(input, options);
      const key = Object.keys(responses).find((candidate) => path.startsWith(candidate));
      const payload = key ? responses[key] : {};
      return Promise.resolve(new Response(JSON.stringify(payload), {
        status: 200,
        headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
      }));
    };
  }, fixture);
}

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: "light", deviceScaleFactor: 1 });
const output = resolve(repo, "docs", "img");
await mkdir(output, { recursive: true });

async function capture(route, file, prepare) {
  const page = await context.newPage();
  await installFixtures(page);
  await page.goto(`${url}${route}`, { waitUntil: "networkidle", timeout: 30000 });
  await page.waitForSelector(".sidebar", { timeout: 10000 });
  await page.waitForTimeout(800);
  await page.evaluate(() => {
    const badge = document.createElement("span");
    badge.className = "badge badge-outline";
    badge.textContent = "Illustrative sample data";
    document.querySelector(".topbar-right")?.append(badge);
  });
  if (prepare) await prepare(page);
  await page.screenshot({ path: resolve(output, file), fullPage: false });
  console.log(`Captured ${file}`);
  await page.close();
}

try {
  for (const [route, file] of [
    ["#/", "webui-overview.png"],
    ["#/processes", "webui-processes.png"],
    ["#/network", "webui-network.png"],
    ["#/map", "webui-map.png"],
  ]) await capture(route, file);

  await capture("#/network", "webui-network-flows.png", async (page) => {
    await page.getByText("Flows", { exact: true }).click();
    await page.waitForSelector(".bar-list .bar-row");
    await page.waitForTimeout(200);
  });
  await capture("#/processes", "webui-processes-treemap.png", async (page) => {
    await page.getByText("Treemap", { exact: true }).click();
    await page.waitForSelector(".treemap");
    await page.waitForTimeout(200);
  });
  await capture("#/map", "webui-map-globe.png", async (page) => {
    await page.waitForSelector("#map-projection:enabled");
    if ((await page.locator("#map-projection").textContent()).includes("Globe")) {
      await page.locator("#map-projection").click();
    }
    await page.mouse.move(680, 450);
    await page.mouse.wheel(0, -220);
    await page.waitForTimeout(900);
  });
  await capture("#/map", "webui-map-2d.png", async (page) => {
    await page.waitForSelector("#map-projection:enabled");
    if ((await page.locator("#map-projection").textContent()).includes("2D")) {
      await page.locator("#map-projection").click();
    }
    await page.waitForTimeout(900);
  });
} finally {
  await context.close();
  await browser.close();
}
