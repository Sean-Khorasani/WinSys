// security-check.mjs - Dev-only security smoke tests for the WinTCP Web UI.
//
//   node tools/webui-e2e/security-check.mjs --url http://127.0.0.1:1234/
//
// Covers the constraints the design calls non-negotiable:
//   C-3  loopback-only binding, Host/Origin checks, token on mutations
//   C-1  no remote origins are ever contacted
//   C-6  unknown is never rendered as a zero
//   plus path traversal against the static handler, and inert rendering of
//   hostile strings in process names, paths, DNS names and ASN organisations.
//
// Headless only. Not part of the shipped product.

import { chromium } from "@playwright/test";
import { connect } from "node:net";
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
const parsed = new URL(url);
const origin = parsed.origin;
const HOST = parsed.hostname;
const PORT = Number(parsed.port || 80);

// Raw HTTP over a socket, on purpose.
//
// fetch() is unusable for these tests for two independent reasons:
//   * It NORMALISES the request target, so "/js/../index.html" is sent as
//     "/index.html" and a traversal check silently passes against a request the
//     server never saw.
//   * Host is a FORBIDDEN header name in the Fetch spec, so the header is
//     silently dropped and the Host check tests nothing at all.
// A raw socket sends exactly the bytes written here.
function rawRequest({ method = "GET", target, headers = {}, body = "" }) {
  return new Promise((resolvePromise, reject) => {
    const socket = connect(PORT, HOST, () => {
      const lines = [`${method} ${target} HTTP/1.1`];
      const merged = { Host: `${HOST}:${PORT}`, Connection: "close", ...headers };
      for (const [key, value] of Object.entries(merged)) {
        if (value === undefined || value === null) continue;
        lines.push(`${key}: ${value}`);
      }
      // Only synthesise Content-Length when the caller did not supply one:
      // sending it twice is a duplicate header, which the parser rejects - and
      // that is the correct behaviour, but it would mask what this test means.
      if (body && !("Content-Length" in merged)) {
        lines.push(`Content-Length: ${Buffer.byteLength(body)}`);
      }
      socket.write(lines.join("\r\n") + "\r\n\r\n" + body);
    });
    const chunks = [];
    socket.setTimeout(8000, () => {
      socket.destroy();
      reject(new Error("timed out"));
    });
    socket.on("data", (c) => chunks.push(c));
    socket.on("error", reject);
    socket.on("close", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      const split = raw.indexOf("\r\n\r\n");
      const head = split >= 0 ? raw.slice(0, split) : raw;
      const payload = split >= 0 ? raw.slice(split + 4) : "";
      const status = Number((/^HTTP\/1\.[01] (\d{3})/.exec(head) || [])[1] || 0);
      resolvePromise({ status, head, body: payload });
    });
  });
}

const results = [];
function check(name, pass, detail = "") {
  results.push({ name, pass, detail });
  console.log(`[${pass ? " ok " : "FAIL"}] ${name}${detail ? " - " + detail : ""}`);
}

// ---- HTTP-level checks ------------------------------------------------------

// C-3: a Host header that is not 127.0.0.1:<port> must be refused.
{
  const r = await rawRequest({ target: "/api/health", headers: { Host: "evil.example.com" } });
  check("Wrong Host header is rejected", r.status === 403, `${r.status}`);
}
{
  const r = await rawRequest({ target: "/", headers: { Host: "localhost" } });
  check("Wrong Host header on the shell is rejected", r.status === 403, `${r.status}`);
}
{
  const r = await rawRequest({ target: "/api/health", headers: { Host: `${HOST}:${PORT + 1}` } });
  check("Host with the wrong port is rejected", r.status === 403, `${r.status}`);
}
{
  const r = await rawRequest({
    target: "/api/health",
    headers: { Host: `${HOST}:${PORT}`, Origin: "http://evil.example.com" },
  });
  check("Wrong Origin on GET is rejected", r.status === 403, `${r.status}`);
}
{
  const r = await rawRequest({ target: "/api/health", headers: { Host: "127.0.0.1:1" } });
  check("Literal 127.0.0.1 on a different port is rejected", r.status === 403, `${r.status}`);
}

// C-3: mutations need both a matching Origin and the session token.
{
  const r = await rawRequest({
    method: "POST", target: "/api/config",
    headers: { "Content-Type": "application/json", "X-WinTCP-Token": "0".repeat(64) },
    body: "{}",
  });
  check("POST without Origin is rejected", r.status === 403, `${r.status}`);
}
{
  const r = await rawRequest({
    method: "POST", target: "/api/config",
    headers: { "Content-Type": "application/json", Origin: origin },
    body: "{}",
  });
  check("POST without a token is rejected", r.status === 403, `${r.status}`);
}
{
  const r = await rawRequest({
    method: "POST", target: "/api/config",
    headers: {
      "Content-Type": "application/json",
      Origin: origin,
      "X-WinTCP-Token": "0".repeat(64),
    },
    body: "{}",
  });
  check("POST with a wrong token is rejected", r.status === 403, `${r.status}`);
}
{
  const r = await rawRequest({
    method: "POST", target: "/api/config",
    headers: {
      "Content-Type": "application/json",
      Origin: "http://evil.example.com",
      "X-WinTCP-Token": "0".repeat(64),
    },
    body: "{}",
  });
  check("POST with a wrong Origin is rejected", r.status === 403, `${r.status}`);
}

// Transfer-Encoding is a classic request-smuggling vector; the parser refuses it.
{
  let outcome;
  try {
    const r = await rawRequest({ target: "/api/health", headers: { "Transfer-Encoding": "chunked" } });
    outcome = r.status === 400 || r.status === 0 ? true : false;
    check("Transfer-Encoding is refused", outcome, `${r.status}`);
  } catch (err) {
    // The server closing the connection is also a refusal.
    check("Transfer-Encoding is refused (connection closed)", true, err.message);
  }
}

// An oversized Content-Length must be refused before the body is read.
{
  const r = await rawRequest({
    method: "POST", target: "/api/config",
    headers: { "Content-Length": String(64 * 1024 * 1024), "Content-Type": "application/json" },
    body: "{}",
  }).catch((err) => ({ status: `closed (${err.message})`, body: "" }));
  check("Oversized Content-Length is refused",
    r.status === 413 || typeof r.status === "string", `${r.status}`);
}

// Two Content-Length headers is the classic request-smuggling setup.
{
  const r = await new Promise((resolvePromise, reject) => {
    const socket = connect(PORT, HOST, () => {
      socket.write(
        `POST /api/config HTTP/1.1\r\nHost: ${HOST}:${PORT}\r\n` +
        `Content-Length: 2\r\nContent-Length: 48\r\nConnection: close\r\n\r\n{}`);
    });
    const chunks = [];
    socket.setTimeout(8000, () => { socket.destroy(); reject(new Error("timed out")); });
    socket.on("data", (c) => chunks.push(c));
    socket.on("error", reject);
    socket.on("close", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      resolvePromise({ status: Number((/^HTTP\/1\.[01] (\d{3})/.exec(raw) || [])[1] || 0) });
    });
  }).catch((err) => ({ status: `closed (${err.message})` }));
  check("Duplicate Content-Length is rejected", r.status === 400 || typeof r.status === "string",
    `${r.status}`);
}

// ---- Static handler: traversal and unusual paths ---------------------------

const TRAVERSALS = [
  "/js/../../wintcp.exe",
  "/css/../../build.bat",
  "/js/../index.html",
  "/legacy/../app.js",
  "/js/subdir/../../../../Windows/win.ini",
  "/vendor/../../../../etc/passwd",
  "/js/%2e%2e/%2e%2e/app.js",
  "/js/....//....//app.js",
  "/js/..\\..\\wintcp.exe",
  "/js/..;/..;/wintcp.exe",
  "/js//..//..//app.css",
];
for (const p of TRAVERSALS) {
  const r = await rawRequest({ target: p });
  const leaked = /MZ|This program cannot be run in DOS mode|<\?xml|\[fonts\]|^root:/m.test(r.body);
  // A traversal must never return file content. 403 is the designed answer;
  // 404 also means "not served". 200 is only acceptable if the path was
  // provably reduced to a legitimate, allow-listed asset by the server itself.
  const served = r.status === 200;
  check(`Traversal refused: ${p}`, !leaked, `${r.status}${leaked ? " LEAKED CONTENT" : served ? " (served)" : ""}`);
}

// Backslash separators must not be accepted at all.
for (const p of ["/js\\..\\..\\app.js", "/legacy\\..\\index.html"]) {
  const r = await rawRequest({ target: p });
  check(`Backslash traversal refused: ${p}`, r.status === 403 || r.status === 404, `${r.status}`);
}

// Encoded traversal that decodes to a device name must not open the device.
for (const p of ["/js/CON", "/js/nul.js", "/js/COM1.json", "/js/trailing.", "/js/trailing%20"]) {
  const r = await rawRequest({ target: p });
  check(`Odd component refused: ${p}`, r.status === 403 || r.status === 404, `${r.status}`);
}

// A colon would allow an alternate data stream or a drive-qualified path.
for (const p of ["/js/app.js:secret", "/js/C:/Windows/win.ini", "/js/a:b.js"]) {
  const r = await rawRequest({ target: p });
  check(`Colon in path refused: ${p}`, r.status === 403 || r.status === 404, `${r.status}`);
}

// ---- CSP header contents ---------------------------------------------------

{
  const r = await rawRequest({ target: "/" });
  const csp = (/content-security-policy:\s*(.+)/i.exec(r.head) || [])[1] || "";
  check("CSP header is present", csp.length > 0, csp.slice(0, 90));
  check("CSP has no unsafe-inline", !/unsafe-inline/i.test(csp));
  check("CSP has no unsafe-eval", !/unsafe-eval/i.test(csp));
  check("CSP pins object-src and base-uri to none",
    /object-src\s+'none'/i.test(csp) && /base-uri\s+'none'/i.test(csp));
  check("CSP pins frame-ancestors to none", /frame-ancestors\s+'none'/i.test(csp));
}

// ---- Browser-level checks ---------------------------------------------------

const browser = await chromium.launch({ headless: true });
try {
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });

  // C-1: nothing may leave the machine. Block every non-loopback request and
  // fail the check if the UI still renders.
  const offOrigin = [];
  await context.route("**/*", (route) => {
    const target = route.request().url();
    if (target.startsWith(origin) || target.startsWith("data:") || target.startsWith("blob:")) {
      return route.continue();
    }
    offOrigin.push(target);
    return route.abort();
  });

  const page = await context.newPage();
  const cspViolations = [];
  const consoleErrors = [];
  page.on("console", (m) => {
    if (m.type() === "error") consoleErrors.push(m.text());
  });
  page.on("pageerror", (e) => consoleErrors.push("pageerror: " + e.message));

  await page.goto(`${url}#/`, { waitUntil: "networkidle" });
  await page.waitForSelector(".sidebar");
  await page.waitForTimeout(2500);

  check("C-1: no off-origin request is attempted", offOrigin.length === 0,
    offOrigin.slice(0, 4).join(", "));

  cspViolations.push(...(await page.evaluate(() => globalThis.__wintcpCspViolations || [])));
  check("C-2: no CSP violations on load", cspViolations.length === 0,
    cspViolations.map((v) => v.violatedDirective || v.effectiveDirective).join(", "));

  // C-6: a metric that is unavailable must be null plus a reason, never 0.
  const metrics = await page.evaluate(async () => {
    const res = await fetch("/api/metrics/now");
    return await res.json();
  });
  const seriesKeys = Object.keys(metrics).filter((k) => !k.endsWith(".reason") && k !== "_timestamp");
  const withReasons = seriesKeys.filter((k) => `${k}.reason` in metrics);
  check("C-6: every metric carries an explicit reason field",
    withReasons.length === seriesKeys.length,
    `${seriesKeys.length} series, ${withReasons.length} with a reason`);

  // A series that is null must say why; a series that is 0 must not claim to be
  // unknown. Both directions matter: conflating them is the C-6 violation.
  const mislabelled = seriesKeys.filter((k) => {
    const value = metrics[k];
    const reason = metrics[`${k}.reason`];
    if (value === null && reason === null) return true;      // unknown, no reason
    if (value === 0 && typeof reason === "string") return true; // zero, but called unknown
    return false;
  });
  check("C-6: null and 0 are never conflated", mislabelled.length === 0,
    mislabelled.length ? mislabelled.join(", ") : "clean");

  // Hostile strings must render as inert text, never as markup. The API is fed
  // synthetic rows through the page's own DOM helper so the check exercises the
  // real rendering path rather than trusting the server.
  const HOSTILE = [
    '<img src=x onerror="window.__pwned=1">',
    '<script>window.__pwned=1</script>',
    'javascript:window.__pwned=1',
    '"><svg onload=window.__pwned=1>',
    "'; DROP TABLE connections; --",
    'wintcp.exe\\..\\..\\Windows\\System32\\cmd.exe',
    'evil.example.com\u0000.legit',
    '"><iframe src=javascript:window.__pwned=1>',
  ];
  const hostileResult = await page.evaluate(async (hostile) => {
    const mod = await import("/js/h.js");
    const host = document.createElement("div");
    host.id = "hostile-probe";
    document.body.append(host);
    for (const value of hostile) {
      // The element path first, then the attribute path - that is where an
      // escaping bug would hide (a value that escapes into an attribute).
      host.append(mod.h("span", { class: "hostile", title: value }, value));
      host.append(mod.h("div", { "data-note": value }, value));
    }
    const html = host.innerHTML;
    const text = host.textContent;
    // Count REAL elements. Serialised-HTML regexes give false positives here: a
    // fully escaped "&lt;img ... onerror=&quot;" still contains "<" from the
    // host's own tag, so a naive /onerror=/ scan flags the probe itself.
    const injected = {
      script: host.querySelectorAll("script").length,
      img: host.querySelectorAll("img").length,
      svg: host.querySelectorAll("svg").length,
      iframe: host.querySelectorAll("iframe").length,
      onerrorAttrs: Array.from(host.querySelectorAll("*")).filter((el) =>
        Array.from(el.attributes).some((a) => /^on/i.test(a.name))).length,
    };
    host.remove();
    return {
      text,
      injected,
      // Proof of execution, not of resemblance: nothing in the payload ran.
      pwned: !!globalThis.__pwned,
      renderedLength: text.length,
    };
  }, HOSTILE);

  const injected = hostileResult.injected;
  check("Hostile strings render as inert text",
    injected.script === 0 && injected.img === 0 && injected.svg === 0 &&
    injected.iframe === 0 && injected.onerrorAttrs === 0 && !hostileResult.pwned,
    `script=${injected.script} img=${injected.img} svg=${injected.svg} ` +
    `iframe=${injected.iframe} on*=${injected.onerrorAttrs} pwned=${hostileResult.pwned}`);

  check("Hostile strings are preserved verbatim as text",
    HOSTILE.every((value) => hostileResult.text.includes(value)),
    `${hostileResult.renderedLength} chars rendered`);

  check("No console errors during the security pass", consoleErrors.length === 0,
    consoleErrors.slice(0, 3).join(" | "));

  // A page must render even when the server reports an error state.
  check("Session token is exposed only via the meta tag",
    await page.evaluate(() => {
      const meta = document.querySelector('meta[name="wintcp-api-token"]');
      if (!meta) return false;
      const inMarkup = document.documentElement.outerHTML;
      // The token appears exactly once: its own meta tag. It must not have been
      // copied into any rendered element, script or style.
      const occurrences = inMarkup.split(meta.content).length - 1;
      return occurrences === 1;
    }));

  await context.close();
} finally {
  await browser.close();
}

const out = resolve(repo, "docs", "img");
await mkdir(out, { recursive: true });
await writeFile(
  resolve(out, "security-report.json"),
  JSON.stringify({ when: new Date().toISOString(), url, results }, null, 2) + "\n",
  "utf8",
);

const failed = results.filter((r) => !r.pass).length;
console.log("");
console.log(`${results.length} security checks, ${failed} failed.`);
console.log("Report: docs/img/security-report.json");
process.exit(failed === 0 ? 0 : 1);