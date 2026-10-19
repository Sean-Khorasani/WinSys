import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../..");
const urlIndex = process.argv.indexOf("--url");
const url = urlIndex >= 0 ? process.argv[urlIndex + 1] : "";
if (!url) {
  console.error("No isolated dashboard URL. Run through isolated-checks.mjs.");
  process.exit(2);
}

const suites = [
  "check-webui.mjs",
  "workflow-checks.mjs",
  "run-checks.mjs",
  "automation-checks.mjs",
  "keyboard-check.mjs",
  "tabs-check.mjs",
  "axe-check.mjs",
  "screenshots.mjs",
];
const results = [];

function run(label, command, args) {
  console.log(`\n=== ${label} ===`);
  const result = spawnSync(command, args, { cwd: root, stdio: "inherit", windowsHide: true });
  const code = result.error ? 1 : result.status ?? 1;
  results.push({ label, passed: code === 0, code, error: result.error?.message || "" });
  if (result.error) console.error(result.error.message);
}

for (const suite of suites) {
  run(suite, process.execPath, [join(here, suite), "--url", url]);
}

const configuredDevExe = process.env.WINTCP_DEV_EXE;
const candidates = configuredDevExe
  ? [resolve(root, configuredDevExe)]
  : [join(root, "build-cmake", "dev", "wintcp-dev.exe"), join(root, "build", "dev", "wintcp-dev.exe")];
const devExe = candidates.find(existsSync);
if (!devExe) {
  results.push({ label: "native dev executable", passed: false, code: 1,
    error: "Build wintcp-dev.exe or set WINTCP_DEV_EXE before running the regression suite." });
  console.error("\n=== native dev executable ===\nBuild wintcp-dev.exe or set WINTCP_DEV_EXE before running the regression suite.");
} else {
  run("native unit suite", devExe, ["unit"]);
  run("native UI suite", devExe, ["ui"]);
}

const out = join(root, "temp", "webui-reports");
await mkdir(out, { recursive: true });
const passed = results.filter((item) => item.passed).length;
const failed = results.length - passed;
await writeFile(join(out, "regression-summary.json"), JSON.stringify({
  url,
  completedAt: new Date().toISOString(),
  passed,
  failed,
  suites: results,
}, null, 2) + "\n", "utf8");
console.log(`\nRegression suite: ${passed}/${results.length} suites passed. Report: temp/webui-reports/regression-summary.json`);
process.exit(failed === 0 ? 0 : 1);
