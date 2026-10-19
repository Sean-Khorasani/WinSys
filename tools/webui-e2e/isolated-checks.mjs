import { spawn } from "node:child_process";
import { once } from "node:events";
import { copyFile, cp, mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../..");
const suite = resolve(here, process.argv[2] || "automation-checks.mjs");
if (dirname(suite) !== here || !suite.endsWith(".mjs")) throw new Error("Choose a check script from tools/webui-e2e");
const executable = process.env.WINTCP_TEST_EXE || join(root, "build", "wintcp.exe");
const scratch = await mkdtemp(join(tmpdir(), "wintcp-webui-checks-"));
const profile = join(scratch, "profile");
const stagedExecutable = join(scratch, "app", "wintcp.exe");
let service;
try {
  await mkdir(dirname(stagedExecutable), { recursive: true });
  await copyFile(executable, stagedExecutable);
  await cp(join(root, "wintcp", "webui"), join(dirname(stagedExecutable), "webui"), { recursive: true });
  service = spawn(stagedExecutable, ["webui", "serve"], {
    cwd: root,
    windowsHide: true,
    env: { ...process.env, WINTCP_WEBUI_OPEN_BROWSER: "0", WINTCP_WEBUI_DATA_DIR: profile,
      WINTCP_WEBUI_LOG_FILE: join(profile, "webui.log") },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const url = await new Promise((ready, fail) => {
    let output = "";
    let errors = "";
    const timeout = setTimeout(() => fail(new Error("The isolated dashboard did not start within 30 seconds")), 30000);
    service.on("error", (error) => { clearTimeout(timeout); fail(error); });
    service.once("exit", (code) => { clearTimeout(timeout); fail(new Error(`Dashboard exited (${code}): ${errors}`)); });
    service.stderr.on("data", (chunk) => { errors = (errors + chunk).slice(-2000); });
    service.stdout.on("data", (chunk) => {
      output += chunk;
      const match = /http:\/\/127\.0\.0\.1:\d+\//.exec(output);
      if (match && output.includes(profile)) {
        clearTimeout(timeout);
        ready(match[0]);
      } else if (match && output.includes("Press Ctrl+C")) {
        clearTimeout(timeout);
        fail(new Error("This binary does not support an isolated dashboard profile; rebuild it before running checks"));
      }
    });
  });
  console.log(`Isolated dashboard: ${url}`);
  const check = spawn(process.execPath, [suite, "--url", url, ...process.argv.slice(3)], {
    cwd: root,
    windowsHide: true,
    env: { ...process.env, WINTCP_TEST_PROFILE: profile },
    stdio: "inherit",
  });
  const [code] = await once(check, "exit");
  process.exitCode = code ?? 1;
} finally {
  if (service && service.exitCode === null && service.pid) {
    const stopped = once(service, "exit");
    service.kill();
    await stopped;
  }
  if (dirname(scratch) !== resolve(tmpdir()) || !basename(scratch).startsWith("wintcp-webui-checks-")) {
    throw new Error("Refusing to remove an unexpected profile directory");
  }
  await rm(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}
