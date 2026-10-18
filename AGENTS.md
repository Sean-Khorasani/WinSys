# AGENTS.md

WinTCP is a dependency-free native Win32 C++17 application that lists live TCP/UDP
endpoints with their owning processes. It ships as `wintcp.exe` (console CLI),
`wintcp-gui.exe` (native GUI), plus an optional loopback Web UI (static assets
in `wintcp/webui`). Three build paths must stay in step: `build.bat`,
`fast-build.bat`/`fast-build.ps1`, and `CMakeLists.txt` (the .vcxproj files
mirror them).

## Dev environment

- Windows 10/11 + Visual Studio 2022 (or later) with the "Desktop development with
  C++" workload (MSVC + Windows SDK). No third-party dependencies, no package
  manager, no admin rights needed.
- The shell here is MSYS/bash, not PowerShell or cmd.exe; `cl.exe` is not on PATH.
  `build.bat` and `fast-build.ps1` self-locate vcvars64.bat, so they run from any
  shell. For direct `cl`/`link` calls from bash, discover the toolset with
  vswhere and prepend `.../VC/Tools/MSVC/<ver>/bin/Hostx64/x64` to PATH.
- When a .bat wrapper exists, drive it via `cmd.exe /c "<wrapper>.bat"` — never
  invoke `cl.exe`/`link.exe` straight from bash. Quote the whole path: unquoted
  backslashes are stripped by bash and mangle the filename.

## Build & test

Exact commands, from the repo root:

- `build.bat` — the shipped-binary gate. Full rebuild, /W4 /WX, /GL /LTCG,
  re-embeds web assets. Outputs: `build/wintcp.exe`, `build/wintcp-gui.exe`,
  `build/dev/wintcp-dev.exe`. `build.bat clean` wipes `build/`.
- `cmd.exe /c fast-build.bat -Test` — the dev loop: incremental parallel compile,
  CLI smoke gate, harness self-check, unit driver. Exit codes: 0 ok,
  1 build failed, 2 tests failed, 3 setup. Other flags: `-TestOnly`, `-Force`,
  `-Clean`.
- CMake: `cmake -S . -B build-cmake -G "Visual Studio 17 2022" -A x64 &&
  cmake --build build-cmake --config Release` (single-config Ninja also works).
- Unit tests: `build\dev\wintcp-dev.exe unit` (exit 0 = all checks pass). Also
  `bench [rows] [iters]` and `ui` (needs an interactive desktop). Not shipped;
  running it bare prints usage.
- Web UI assets have no compiled gate: run `node --check wintcp/webui/app.js`
  from the repo root for a basic syntax check. For full module validation
  (which catches ES module `import` errors and inline element bugs), use
  `node tools/webui-e2e/check-webui.mjs --url http://127.0.0.1:PORT/`.
- Background dashboard: `webui-service.bat start|status|stop` (logs to
  `%LOCALAPPDATA%\WinTCP\WebUi\webui.log`); foreground: `wintcp.exe webui serve`.

## Conventions

- Every build path compiles with `/W4 /WX` (warnings are errors), `/permissive-`,
  `/Zc:__cplusplus`, `/utf-8`, static CRT (`/MT`), `/guard:cf`, `/MANIFEST:NO`
  (`wintcp.rc` already embeds the manifest). Keep all paths in step.
- Adding a source file: `build.bat` and `wintcp.vcxproj` list it by hand;
  `CMakeLists.txt` and `fast-build.ps1` glob. Never edit anything under `build\`,
  `build-fast\`, or `build-cmake\`.
- The product carries no test code. Tests/benchmarks/UI harness live only in
  `wintcp-dev.exe` (entry `wintcp/tests/TestMain.cpp`); `wintcp.exe` rejects
  `selftest`/`bench`/`--uiharness` as unknown commands.
- The column set is frozen at 32 (UINT32 mask): a `static_assert` in
  `ColumnsWin.h` fails the build at 33. Reuse an existing column instead.
- Naming: PascalCase types and methods, `kCamelCase` constants, `UPPER_CASE` macros,
  `#pragma once`, UTF-8 without BOM.
- CLI contract: exit 0 ok, 1 failure/empty, 2 bad arguments, 3 refused. A switch a
  command does not honour exits 2 naming the switch — never silently ignored.
- Docs are the contract: user-facing command changes must update `docs/` and the
  CLI example corpus `wintcp/tests/examples.txt` (it carries `;expect=` exit-code
  annotations).
- Commits follow `Add <path>: <description>` (see git log). Commit only files you
  authored — this checkout routinely contains other uncommitted work.

## Web UI Development Guide

The Web UI is in `wintcp/webui/`. It is a vanilla ES module + CSS project with
no framework, no bundler, and no build step for assets (the binary embeds them).

### File layout

```text
wintcp/webui/
  index.html              # Shell (token meta tag, module script)
  app.css                 # Entry: imports css/*.css
  templates.json          # 40-template catalog (shipped, not editable)
  config.default.json     # Default config used on first run
  css/
    tokens.css            # shadcn-style design tokens (OKLCH colors, light+dark)
    base.css              # Reset, typography, focus rings
    components.css        # Buttons, badges, cards, dialogs, tables
    pages.css             # Page-specific layouts
  js/
    main.js               # Entry point, theme application
    router.js             # Hash routes (#/, #/performance, #/automations, ...)
    api.js                # Fetch wrapper with X-WinTCP-Token header
    store.js              # Tiny observable state
    poller.js             # Visibility-aware polling with backoff
    format.js             # Intl.* formatters (fmtBytes, fmtPct, etc.)
    h.js                  # DOM helper: h(tag, props, ...children)
    scriptengine.js       # WinTCP Script parser/interpreter
    icons.js              # Lucide icons as inline SVG
    ui/                   # Component wrappers: button.js, badge.js, dialog.js
    charts/               # uPlot, sparkline, barList wrappers
    pages/                # Page implementations: overview.js, automations.js, ...
    legacy/               # Pre-upgrade dashboard logic (served at /legacy)
  vendor/                 # Third-party static assets (ECharts, uPlot)
  data/                   # Vendored map data (Natural Earth)
```

### CSS architecture

The design system follows a shadcn/ui aesthetic:

- **`css/tokens.css`** — Design tokens using OKLCH color space. Defines
  `--background`, `--foreground`, `--card`, `--primary`, `--muted`, `--border`,
  `--radius`, `--ring`, `--accent-*`, `--success`, `--warning`, `--info`,
  `--destructive`, chart palette (`--chart-1` through `--chart-5`), and more.
  Light and dark themes via `[data-theme="light"]` / `[data-theme="dark"]`.

- **`css/base.css`** — CSS reset, typography scale, focus ring styles.

- **`css/components.css`** — Reusable component styles: `.btn`, `.badge`,
  `.card`, `.dialog`, etc. Badge variants: `.badge-default`, `.badge-secondary`,
  `.badge-outline`, `.badge-destructive`, `.badge-success`, `.badge-warning`,
  `.badge-info`, `.badge-ok`, `.badge-muted`.

- **`css/pages.css`** — Page-specific layouts organized by page. Each section
  is clearly delimited with `/* ---- Page Name ---- */` comments.

**Design principles:** local only (no CDN/remote fonts), OKLCH color space,
small radii, subtle borders, no shadows. Light and dark themes.

### The `h()` DOM helper

```js
import { h, clear } from "../h.js";

h("div", { class: "card", onclick: () => handler(), ref: (el) => { myEl = el; } },
  h("h3", {}, "Card title"),
  h("p", {}, "Card content"),
);
```

Key behaviors:
- `children` are flattened (`.flat()`), so you can pass arrays directly
- `null`, `undefined`, and `false` children are skipped (no "null" text)
- DOM nodes are appended directly; strings become `Text` nodes
- `ref` callback fires after element creation and property assignment
- `dataset` prop merges via `Object.assign(el.dataset, value)`
- Boolean `true` → `setAttribute(key, "")`; `false`/`null` → attribute removed
- Event handlers via `on*` props (e.g., `onclick` → `addEventListener("click", ...)`)
- `value` prop uses property assignment if the element supports it, otherwise `setAttribute`

### Common pitfalls

- **Never interpolate `h()` inside template literals.** A DOM node passed to
  `` `${domNode}` `` stringifies to `[object HTMLDivElement]`. Pass children
  directly to `h()` instead:
  ```js
  // WRONG: h("h3", {}, `My scripts ${h("span", {}, count)}`)
  // RIGHT:  h("h3", {}, "My scripts ", h("span", {}, count))
  ```

- **Never pass a bare `{}` as a child to `h()`.** An empty object renders as
  `[object Object]`. Use `h("div")` instead.
- **Web UI assets are served from `build/webui/` or `build-fast/webui/`.**
  After editing `wintcp/webui/*`, copy to the build output:
  ```bat
  xcopy /E /I /Y wintcp\webui\* build-fast\webui\
  ```
  Or just restart the service with `webui-service.bat restart` (if it supports
  restart). `build.bat` (full build) embeds assets automatically.

### Adding a page

1. Create `js/pages/my-page.js` exporting a `render()` function.
2. Add a route in `js/router.js`.
3. Add a sidebar link in `index.html`.
4. Add any page-specific CSS to `css/pages.css` under a `/* ---- My Page ---- */` section.
5. Add a test case to `tools/webui-e2e/automation-checks.mjs` if applicable.

### Adding a metric / endpoint

1. Add the field and its `*Known` flag to `MetricsSample` in `WebMetrics.h`.
2. Collect it in `CollectSample` (sampler thread only — never in a request).
3. Emit it in `/api/metrics/now` with `null` + a reason when unknown.
4. Add a `KnownSeriesIds()` entry so `/api/metrics/history` accepts it.

Unknown is never zero — a null metric carries a reason string.

## Testing the Web UI

The dev-only test harness lives in `tools/webui-e2e/`. It requires Node.js plus
Playwright with Chromium. None of it is needed to build or run the product.

### Prerequisites

```bat
npm install
npx playwright install chromium
```

### Starting the service for testing

```bat
cmd.exe /c webui-service.bat start
REM The start command prints the URL, e.g.:
REM   WinTCP Web UI started in the background (PID 12345).
REM   URL: http://127.0.0.1:39170/
```

The service manager sets `WINTCP_WEBUI_OPEN_BROWSER=0` so it will NOT open your
browser. **Never** run `wintcp.exe webui serve` bare during testing — it will
hijack the user's desktop.

### Running tests

From the repo root, pass the service URL:

```bat
node tools\webui-e2e\automation-checks.mjs --url http://127.0.0.1:PORT/
```

Available test suites:

| Script | Purpose |
|---|---|
| `check-webui.mjs` | Static module validation — parses every `.js` as an ES module to catch import/syntax errors. Run with `--url http://127.0.0.1:PORT/` |
| `automation-checks.mjs` | Full E2E tests for the script engine, automations workbench, GeoIP settings, notifications, and audit flow. **This is the comprehensive test suite.** |
| `run-checks.mjs` | Connection table, overview, performance page checks |
| `axe-check.mjs` | Accessibility audit (axe-core) |
| `keyboard-check.mjs` | Keyboard navigation and focus trap checks |
| `security-check.mjs` | CSP, security headers, and token handling |
| `contrast.mjs` | WCAG color contrast measured through canvas |
| `screenshots.mjs` | Full-page screenshots for visual regression |
| `tabs-check.mjs` | Multi-tab state isolation |
| `soak.mjs` | Long-running stability check (use `--minutes N`) |

Each test suite writes a JSON report to `docs/img/`. `check-webui.mjs` is
especially important — it validates that every shipped JS file parses correctly
as an ES module, which `node --check` cannot do (Node parses `.js` as CommonJS,
making `import` statements error with misleading line numbers).

### Writing / modifying tests

Tests in `automation-checks.mjs` follow a simple pattern:

```js
// Browser-side tests use page.evaluate():
const results = await page.evaluate(async () => {
  const mod = await import("./js/scriptengine.js");
  // ... test logic using the module ...
  return { passCount, failCount, results: [...] };
});

// Browser interaction tests use page.click(), page.fill(), etc.:
await page.click("#script-save");
const saved = await page.textContent(".script-list-item strong");
check("Saved script appears in library", saved.includes("My Script"));
```

The `check(name, condition, detail?)` helper logs `[ ok ]` or `[FAIL]` and tracks
count. At the end, a JSON report is written to `docs/img/automation-report.json`.

To add a new test:
1. Find the appropriate `async function run*Tests(page, url)` section.
2. Add `check("description", assertion)` calls.
3. Update the summary line if test counts are asserted.

## Pitfalls

- After any source edit, `fast-build.bat -Test` first reports "gated binary is
  STALE" (exit 2) until `build.bat` rebuilds `build/wintcp.exe`. Expected, not a
  regression. Do not "fix" it with `-TestOnly`; rebuild first.
- Only `build.bat` embeds web assets into the shipped binary. Editing
  `wintcp/webui/*` and fast-building leaves `build/wintcp.exe` carrying the old
  dashboard. Copy assets to `build-fast/webui/` for fast iteration, or run
  `build.bat` for a production-accurate binary.
- `build.bat` takes minutes (full /GL /LTCG). Run it in the background and do not
  edit sources while it compiles — a header change mid-pass fails the run.
- `fast-build.ps1`'s header still references `docs/development.md` and
  `wintcp/dev/cli.bat`; neither exists. The real gates are `fast-build.bat -Test`
  and `wintcp-dev.exe unit`.
- A bash/MSYS `link` on PATH can shadow MSVC's linker; check `link /?` prints the
  Microsoft banner before diagnosing link errors.
- The Web UI binds an ephemeral port on 127.0.0.1 only; 7 of the 40 monitor
  templates have evaluators (unsupported templates stay disabled).
- `wintcp.exe webui serve` OPENS THE USER'S DEFAULT BROWSER (ShellExecuteW) unless
  `WINTCP_WEBUI_OPEN_BROWSER` is `0`/`false`/`no`/`off`. Never launch it bare
  while testing - it hijacks the user's desktop. Use
  `cmd.exe /c webui-service.bat start`, which sets the flag for the child and
  prints the URL. Drive the UI with curl or headless Playwright instead.
- Playwright/Chromium is dev-only (`tools/webui-e2e`); always run it headless.
- After editing WebUI source, restart the service (`webui-service.bat stop`
  then `start`) or the old assets remain served from the running process.
  If `stop` fails, force-kill with `taskkill /f /im wintcp.exe` before restarting.
- The Web UI is CSP-locked: no inline scripts, no inline styles, no `eval`,
  no `javascript:` URLs. Violations are caught by the e2e security check.
- Template literal interpolation of `h()` results renders `[object ...]` —
  always pass DOM nodes as children to `h()`, not as string interpolations.
- An empty object `{}` passed as a child to `h()` renders `[object Object]` —
  use `h("div")` instead.