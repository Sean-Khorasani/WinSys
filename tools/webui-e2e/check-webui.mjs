// check-webui.mjs - Dev-only syntax gate for the Web UI front end.
//
//   node tools/webui-e2e/check-webui.mjs
//
// Parses every .js the browser will load as an ES module. This exists because
// the shipped module graph once contained a literal `id="page"` inside an object
// literal: a syntax error that no C++ build can catch, no browser reports until
// the page stays blank, and `node --check file.js` did not catch it either - it
// parses a bare .js as CommonJS, where top-level `import` is itself an error and
// the reported line number is nonsense.
//
// Fix: hand node a copy under .mjs in a directory whose package.json declares
// "type": "module", so the parse happens with the real module goal.

import { mkdtemp, mkdir, readdir, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, resolve, dirname, extname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const run = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const webuiRoot = resolve(here, "..", "..", "wintcp", "webui");

async function collectJs(dir, acc = []) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "vendor" || entry.name === "legacy") continue;
      await collectJs(full, acc);
    } else if (extname(entry.name) === ".js") {
      acc.push(full);
    }
  }
  return acc;
}

const files = await collectJs(webuiRoot);
if (files.length === 0) {
  console.error("no .js found under", webuiRoot);
  process.exit(2);
}

const scratch = await mkdtemp(join(tmpdir(), "wintcp-webui-check-"));
let failures = 0;

try {
  for (const file of files) {
    const dest = join(scratch, relative(webuiRoot, file) + ".mjs");
    await mkdir(dirname(dest), { recursive: true });
    await writeFile(dest, await readFile(file));
  }

  for (const file of files) {
    const dest = join(scratch, relative(webuiRoot, file) + ".mjs");
    try {
      await run(process.execPath, ["--check", dest]);
    } catch (err) {
      failures++;
      console.error(`FAIL ${relative(webuiRoot, file)}`);
      console.error(String(err.stderr || err.message).trim());
    }
  }
} finally {
  await rm(scratch, { recursive: true, force: true });
}

if (failures === 0) {
  console.log(`[webui] ${files.length} module(s) parsed clean.`);
  process.exit(0);
}
console.error(`[webui] ${failures} of ${files.length} module(s) failed to parse.`);
process.exit(1);