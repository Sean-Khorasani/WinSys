# Web UI upgrade - implementation report

Date: 2026-10-17. Branch `main`. Commits `2db13f3`, `403d8b5`, `ce19264`.

---

## 1. Headline: the crash

The reported symptom was "the server dies after serving one request". The
crash is real and reproducible, but the trigger was not the one in the brief:

```
GET /api/metrics/history?since=abc
```

`MetricsHistoryJson` called `std::stoull(params["since"])`. `std::stoull`
throws `std::invalid_argument` on a non-numeric string and `std::out_of_range`
on overflow. Nothing caught it, so the exception unwound through
`WebUiAcceptLoop` and terminated the process:

```
fatal: unhandled exception 0xE06D7363; minidump: ...\wintcp-<ts>-<pid>.dmp
```

Exit code `-529697949`. `since=-1`, `since=99999999999999999999` and
`max=abc` all triggered it.

Fixed three ways:

1. `ParseUint64Strict` - digits only, no sign, no overflow, never throws.
2. A malformed parameter is a **client error**: 400 with a message.
3. `ServeClient` wraps `HandleRequest` in a catch-all, so **no** handler can
   ever terminate the server again. A future escaping exception returns 500 and
   is logged.

The same defect class was audited across the tree. `Script.cpp` has five
unchecked `std::sto*` calls; they sit behind the script runner's own handling
and were left alone (C-9, existing semantics).

## 2. There was no crash on the request you tested

For the record, because it matters for interpreting the brief: `/` and
`/app.css` never crashed anything. Both binaries were hammered with 184
sequential requests across every route with zero failures. The blank page had
four independent causes, none of them a crash.

## 3. Why the page was blank - four separate defects

| Defect | Effect | Fix |
|---|---|---|
| The static route passed an **already-resolved absolute path** to `ReadAsset()`, which prepends `<exedir>\webui\`. It asked for `<exedir>\webui\<exedir>\webui\js\main.js`. | **Every** `/js/`, `/css/`, `/vendor/`, `/data/` asset 404'd. No CSS, no JS. | Read the resolved path directly; delegate the allow-list entirely to `WebStatic`. |
| `index.html` loaded `/app.js`, the **pre-upgrade 1513-line dashboard monolith**, written against markup the upgrade had deleted. | The module threw on its first DOM access. | The shell loads `/js/main.js`; the monolith is preserved and served at `/legacy`. |
| `main.js` never parsed: `id="page"` - **HTML syntax inside a JS object literal**. | Whole module rejected. | Fixed, plus `tools/webui-e2e/check-webui.mjs` as a permanent gate. |
| `icon()` returned a **markup string**, which `h()` renders as a text node. | Every icon displayed as literal `<svg>` source. | `icon()` returns real DOM elements. |

The third is worth emphasising: `node --check wintcp/webui/app.js` (the gate
recorded in `AGENTS.md`) parses a bare `.js` as CommonJS, where top-level
`import` is itself an error and the reported line number is meaningless. It
cannot see this class of bug. `check-webui.mjs` parses every module with the
real module goal.

## 4. The upgrade had deleted the product's dashboard

`git show 5d11c03~1:wintcp/webui/` - the last pre-upgrade state - had a 207-line
`index.html` carrying all the dashboard markup. The upgrade replaced it with a
17-line shell and left the 1513-line monolith orphaned. **97 functions of
working product became unreachable.** `webui/legacy/` restores that state
verbatim and `/legacy` serves it, linked from the top bar, so no feature is lost
while the control room reaches parity.

## 5. Requirement status

| ID | Requirement | Status | Notes |
|---|---|---|---|
| C-1 | Local only, no CDN/remote fonts/analytics | **DONE** | `security-check.mjs` aborts every off-origin request; the page still renders. 0 off-origin attempts. |
| C-2 | CSP unchanged or stricter | **DONE** | Header byte-identical. No `unsafe-inline`/`unsafe-eval` asserted. `js/csp.js` reports violations; 0 across all 18 page runs. |
| C-3 | Loopback binding, Host/Origin, token, permit, audit | **DONE** | 46 security checks. Also added: duplicate headers 400, `Transfer-Encoding` 400, oversized `Content-Length` 413. |
| C-4 | No runtime installer; vendored assets; dev tools in `tools/` | **DONE** | `wintcp/webui/vendor/` + `tools/webui-e2e/`. No product dependency added. |
| C-5 | No front-end build step | **DONE** | Vanilla ES modules + plain CSS. `js/` is served as-is. |
| C-6 | Unknown is never zero | **DONE** | Every series carries `<id>.reason`. Security suite asserts null/0 are never conflated in either direction. |
| C-7 | Never self-elevate | **DONE** | Unchanged. |
| C-8 | Sequential server; handlers return in ms | **DONE** | Measured 9-28 ms per request including `/api/connections` at ~300 endpoints. |
| C-9 | Preserve every existing feature | **PARTIAL** | Nothing lost (`/legacy`), but the control room does not yet reach parity. Listed in §10. |
| C-10 | README/docs state the vendoring with a licence table | **DONE** | README asset table + `THIRD_PARTY_NOTICES.md` + `vendor/LICENSES/`. |
| 1 | Fix the server crash | **DONE** | §1. |
| 2 | Verify the browser renders | **DONE** | 18 page/theme runs, 0 problems. Screenshots in §9. |
| 3 | e2e tests, both themes, 3 viewports | **DONE** | `tools/webui-e2e/`. 12 curated screenshots in `docs/img/`. |
| 4 | Accessibility (axe) + keyboard + contrast | **DONE** | 18 audits, 0 serious/critical, 0 contrast failures, 13 keyboard checks. |
| 5 | Security smoke tests | **DONE** | 46 checks, §7. |
| 6 | Documentation | **DONE** | `docs/webui.md` (rewritten sections), `docs/architecture.md`, `README.md`. |
| 7 | Config schema v3 | **DONE** | Additive - `preferences` nested, v2 keys still read. Settings page persists all of it. |
| 8 | CSP violation listener | **DONE** | `js/csp.js`; every e2e run fails on any violation. |
| 9 | Soak tests | **DONE** | 10 min, §8. |
| 10 | This report | **DONE** | |

## 6. Also fixed along the way

None of these were in the brief; all were found by the new checks and all
would have shipped as silent breakage.

**Back end**

- `MetricsCollector` was **never started**. Every metric read as `null`. Now
  started in `RunWebUiServer`, with failure reported as `pdh:false` + reason.
- The sampler ran at **10 Hz**, not 1 Hz: the loop slept 100 ms. The 900-slot
  ring covered 90 seconds, not 15 minutes. Now 1 Hz active / 0.1 Hz idle
  (measured: 8 consecutive 1 s samples with a client, 10 s spacing idle).
- `Reenumerate()` mutated the sampler's counter vectors **from a request
  thread**, racing `CollectSample()`. It now only raises a flag.
- Wildcard counters were re-enumerated every **30 s**, destroying each rate
  baseline and injecting a null artifact twice a minute. Now 5 min, and the
  post-re-enumeration sample is discarded.
- `pdhCpuCore_` was never added, so per-core CPU was always empty while
  `/api/capabilities` advertised `perCore:true`. Now collected via
  `PdhGetFormattedCounterArray`, sorted numerically by `(group, core)`.
- `trafficScan:true` was hardcoded while `ConnectionsJson` deliberately does
  **not** scan traffic. Now `false`.
- `std::ostringstream` default formatting printed 33277400000 bytes as
  `3.32774e+10`. Added `JsonNumber`: classic locale, no scientific notation,
  integrals as integers, non-finite as `null`.
- `/api/system/info` had no `os` key at all; the page read `info.os.name` and
  threw. Now reads the registry through the existing `RegReadBoundedString`
  policy, with every field independently optional.
- `/api/metrics/now` emitted only 3 of 7 catalogued series, so the UI showed
  `-` for disk and network. Now emits all of them.
- The static route duplicated the prefix allow-list inline, and it had already
  drifted from `WebStatic`. Removed; `IsSafeStaticPath` is the only gate.
- `IsRejectedStaticPath` added so traversal attempts answer **403** (and log as
  rejections) instead of 404.
- Reparse points inside `webui/` were not rejected despite the header comment
  claiming they were.
- Two broken vendored files: `lucide/home.svg` was a **saved 404 page**, and
  `echarts.custom.js` imported a UMD bundle as an ES module. Both removed.

**Front end**

- `.app-shell` was a flex **row**, but the sidebar is `position:fixed` and
  contributes no width. The top bar became a content sibling, shrank to its
  intrinsic width, and the page rendered in the **right-hand half of the
  window** with a 445 px gap. Now a column with the offset as padding.
- The virtual table had no `tabindex`, so it **could not be scrolled from the
  keyboard**, and every render destroyed the focused row - so
  <kbd>End</kbd> then <kbd>Home</kbd> did nothing. Now a real
  `role="grid"` with reused row nodes and full arrow/page/home/end navigation.
- uPlot was called as `new uPlot(element, opts, data)`. The signature is
  `new uPlot(opts, data, target)` - the element is **last** - so it failed
  inside the constructor as `then is not a function`. Then
  `setSize({width})` zeroed the canvas backing-store height, so even correct
  construction painted nothing. Charts had never worked.
- CPU % and memory MiB shared one axis, flattening the CPU line to the
  baseline. Series can now request their own scale.
- The poller's `catch {}` **silently swallowed a `ReferenceError`** for an
  entire session: the UI reported "Live" and simply stopped updating, with
  nothing in the console. That is how a misplaced function declaration went
  unnoticed.
- Two top-bar buttons and the command palette entry point were empty comment
  bodies.
- The `/blocks` sidebar link had no route and the router had no not-found
  handler, so it silently did nothing.
- `--muted-foreground` measured **4.31:1** against `--muted`; `.breadcrumb-sep`
  measured **1.26:1**. Now 5.04:1 and 5.49:1.

## 7. Verification results

All green. Reports in `docs/img/`.

| Gate | Result |
|---|---|
| `fast-build.bat -Test` | **17/17** |
| `build.bat` (full `/GL /LTCG` gate) | **exit 0**; `gated binary current` |
| `check-webui.mjs` | **35/35** modules parse |
| `run-checks.mjs` | **18/18** page+theme, 0 console errors, 0 CSP violations, 0 failed requests |
| `axe-check.mjs` | **18/18** audits, 0 serious, 0 critical, **0 contrast failures** (worst 5.04:1 light, 5.86:1 dark) |
| `keyboard-check.mjs` | **13/13** |
| `security-check.mjs` | **46/46** |
| `soak.mjs --minutes 10` | **PASS** |

### An axe false positive worth knowing about

axe-core's own `color-contrast` rule is **disabled** in `axe-check.mjs`. Chrome
returns `oklch(0.205 0 0)` from `getComputedStyle`, axe's parser only
understands `rgb()`/hex, so it walks up the tree and measures the wrong
background - reporting 18 bogus "serious" findings, including `#fafafa` text on
a background it read as `#ffffff` when the truth was `oklch(0.205 0 0)`, a
ratio of **16.9:1**.

`contrast.mjs` measures the same property correctly by letting the *browser*
resolve the colour through a 1x1 canvas and then computing luminance itself.
Removing that finding required fixing the two genuine contrast failures it was
sitting next to.

### Security checks worth calling out

Raw sockets, not `fetch`. Node's `fetch` **normalises** the request target
(`/js/../index.html` is sent as `/index.html`, so a traversal check passes
against a request the server never saw) and treats `Host` as a **forbidden
header name**, so the Host check tested nothing at all. Both of those
"failures" were test bugs, not server bugs - the server was correct.

- Wrong `Host` (name, port, literal `127.0.0.1:1`), wrong `Origin`, `POST`
  without `Origin`, without a token, with a wrong token, with a wrong `Origin`
  - all 403.
- 11 traversal variants - none return file content.
- Odd components (`CON`, `nul.js`, `COM1.json`, `trailing.`, `trailing%20`) and
  colons (`app.js:secret`, `C:/Windows/win.ini`, `a:b.js`) - all refused.
- Duplicate `Content-Length` 400, oversized 413, `Transfer-Encoding` 400.
- 8 hostile strings (script/img/svg/iframe tags, `javascript:`, SQL, path with
  `..`, NUL) render as inert text: 0 elements created, 0 `on*` attributes,
  nothing executed, text preserved verbatim.

## 8. Soak

10 minutes, 139 samples, pages rotated every cycle.

| | Start | End |
|---|---|---|
| Console errors | 0 | 0 |
| CSP violations | 0 | 0 |
| Failed requests | 0 | 0 |
| Page JS heap | 10 MB | 10 MB |
| Server private bytes | 10.6 MB | 12.8 MB (**0.045 MB/min**) |
| Server handles | 282 | **282** |
| Server threads | 8 | 7 |

Handles flat and private bytes essentially flat. The 2.2 MB rise is the
sampler's ring buffer filling plus the browser's connection churn, not a leak.

## 9. Measured numbers

| Measurement | Value |
|---|---|
| `wintcp.exe` | 1,459,712 B |
| `wintcp-gui.exe` | 1,159,168 B |
| Initial shell + Overview module graph (uncompressed) | **272.7 KiB** / 36 requests |
| `/api/connections` (~300 endpoints) | 496,649 B in **19.6 ms** |
| `/api/metrics/history?max=180` | 8,623 B in **1.9 ms** |
| Other endpoints | 9-10 ms each |
| Ring buffer | 900 samples = 15 min at 1 Hz |
| Screenshots | 12 files, 726 KB total |

### Vendored assets

| Asset | Size | SHA-256 | Licence |
|---|---|---|---|
| `uPlot/uPlot.esm.js` | 142,629 | `4e3fcbd80c804f295d7a732872d322600e81b324d6512ecbdd7f436986692160` | MIT |
| `uPlot/uPlot.min.css` | 1,857 | `df630c6a8d6f8eeaff264b50f73ce5b114f646ffd9a0bb74f049b0a00135fa04` | MIT |
| `echarts/echarts.min.js` | 1,030,855 | `e84270bd0cd5bdf60fefc26d00c2a391cb2e81f4d26a7a9ee16185a54773a3cf` | Apache-2.0 |
| `world-atlas/countries-110m.json` | 107,761 | `2516c915867c7baf18ddec727aec46c315541a07cfb3d79a6559b05d5e94eee8` | ISC |
| Lucide icons | - | inlined in `js/icons.js` | ISC |
| Inter font | **not vendored** | - | OFL-1.1 (text only) |

## 10. Deviations from the brief

| Deviation | Reason |
|---|---|
| ECharts is the **full build**, 1,030,855 B, against a 450 KB target | No esbuild available as a dev tool. Forces the `/vendor/` cap to 2 MiB. No chart currently uses it. |
| Inter font **not vendored** | The download 404'd from both unpkg and jsDelivr. The UI uses the system stack; only the licence text is retained. |
| The pre-upgrade dashboard is preserved at `/legacy` rather than deleted | Deleting it during a partial port would violate C-9. It is the strangler's fallback. |
| Config v3 is **additive** - no migration step | `preferences` is nested and every v2 key still reads. A file-migration routine would be a new failure mode for no benefit. |
| Tier B (6 h) history is **not implemented** | Only the 900-sample tier exists. The plan lists it; the brief does not require it. |
| No ECharts chart is wired | Donut/treemap/sankey/map need the geography and category data plumbed through first. uPlot covers the live charts the brief actually asks for. |
| Contrast audited by a custom auditor, not axe's rule | See §7. axe's rule mis-measures `oklch()` tokens. |

## 11. Known limitations

**Feature parity (C-9 is only partially met).** These live at `/legacy` and
are **not yet** in the control room: connection filter/sort/group/freeze, CSV
export, the firewall permit flow UI, the script runner, template selection,
presets, bookmarks, browser alerts, saved views, column chooser, connection
details, row copy.

Also outstanding:

- **Processes derives rows from the connection store**, not by enumerating
  processes: a process with no open endpoint does not appear.
- **Tree and Treemap views are disabled.**
- **Traffic is not scanned in the Web UI** - the per-socket `SIO_TCP_INFO`
  probe wedges under polling. The traffic column reads `-` here; the CLI and
  GUI still show it.
- **GPU counters are not collected** (`gpu:false`).
- **GeoIP is not configured on the test machine**, so the Map page has no data.
- **The dark chart palette is low-contrast between series 1 and 2** (both
  reddish). Legible, but a design-token change would help.
- 7 of 40 monitor templates still have evaluators; 33 are CLI playbooks only.

## 12. Exact commands

```bat
REM build (dev loop, ~2 s incremental)
cmd.exe /c fast-build.bat -Test

REM build (shipped-binary gate, /GL /LTCG, minutes)
cmd.exe /c build.bat

REM unit tests
build\dev\wintcp-dev.exe unit

REM Web UI - background, does NOT open a browser, prints the URL
cmd.exe /c webui-service.bat start
cmd.exe /c webui-service.bat status
cmd.exe /c webui-service.bat stop

REM Web UI - foreground (OPENS YOUR BROWSER unless you set this)
set WINTCP_WEBUI_OPEN_BROWSER=0
wintcp.exe webui serve
```

```bat
REM front-end checks (dev-only; needs node + npx playwright install chromium)
cd tools\webui-e2e
npm install
npx playwright install chromium

cd ..\..
node tools\webui-e2e\check-webui.mjs
node tools\webui-e2e\run-checks.mjs     --url http://127.0.0.1:PORT/
node tools\webui-e2e\axe-check.mjs      --url http://127.0.0.1:PORT/
node tools\webui-e2e\keyboard-check.mjs --url http://127.0.0.1:PORT/
node tools\webui-e2e\security-check.mjs --url http://127.0.0.1:PORT/
node tools\webui-e2e\screenshots.mjs    --url http://127.0.0.1:PORT/ [--all]
node tools\webui-e2e\soak.mjs           --url http://127.0.0.1:PORT/ --minutes 10
```

## 13. One process note

While this work was in progress, another session repeatedly edited
`wintcp/src/WebUi.cpp` to bisect the crash, inserting
`// TEMP: bisect crash` markers that hardcoded `pdh = false`,
`perCore = false` and `have = false`. Three separate times those markers
silently overwrote correct code and I had to restore them - once producing a
working `/api/metrics/history` alongside a broken `/api/metrics/now`, which is
a confusing pair of symptoms.

I have committed the work so it cannot be lost again. If that session is still
running, it should be stopped, or it will undo the fixes.