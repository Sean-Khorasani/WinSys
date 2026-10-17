# Web UI Upgrade Plan

## Architecture decisions

### Front end
- **Vanilla ES modules + plain CSS.** No framework, no build step. The product
  stays dependency-free; the Web UI is static assets served by the existing
  loopback HTTP server.
- **shadcn/ui design tokens.** Light and dark themes via CSS custom properties.
  Accent presets (Neutral, Blue, Green, Orange, Rose, Teal) change `--primary`
  and chart colours.
- **uPlot for time series.** Canvas 2D, built for streaming, small (~50 KB min).
  Used for all live charts (CPU, memory, disk, network, per-process history).
- **ECharts for complex charts.** One custom ESM bundle (esbuild, dev-only) with
  donut, treemap, sankey, heatmap, map. Target < 450 KB.
- **Virtualised tables.** Own implementation, fixed row height, window + spacer
  rows. Handles 10,000 rows without the 250-row cap.
- **Polling, not push.** The server is sequential; a long-lived stream would
  block the accept loop. The browser polls at a configurable cadence.

### Back end
- **New sampler thread.** `WebMetrics.h/.cpp` runs on a `CreateThread` worker
  (not `std::thread`, per the code comment). Owns its own PDH query and samplers.
  Samples at 1 Hz while the UI polls, drops to idle after 60 s.
- **Ring buffers.** Tier A: 1 s x 900 points (15 min). Tier B: 10 s x 2160
  points (6 h). Bounded memory; unit-tested wraparound.
- **New endpoints.** All `GET`, JSON, from cache, `Cache-Control: no-store`.
  Unknown values are `null` plus `reason`. See `docs/webui.md` for the table.
- **Safe static handler.** `WebStatic.h/.cpp` with allow-list prefixes and
  extensions, path traversal protection, per-file 1 MiB cap.

### Security
- CSP unchanged: `default-src 'self'; connect-src 'self'; style-src 'self';
  script-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none';
  frame-ancestors 'none'`.
- Loopback only, Host/Origin checks, token on mutations, permit flow,
  write-ahead audit. No weakening.
- No new mutating routes. All new endpoints are read-only.

## Asset budget

| Asset | Source | Licence | Target size |
|---|---|---|---|
| uPlot | https://github.com/leeoniya/uPlot | MIT | ~50 KB min |
| ECharts custom | https://github.com/apache/echarts | Apache-2.0 | < 450 KB |
| Natural Earth map | https://github.com/topojson/world-atlas | ISC / public domain | < 300 KB |
| Lucide icons | https://lucide.dev | ISC | ~20 KB |
| Inter font | https://github.com/rsms/inter | SIL OFL 1.1 | < 120 KB |

Total initial transfer target: < 1.5 MB uncompressed.

## Risks

| Risk | Mitigation |
|---|---|
| ECharts bundle too large | Tree-shake to needed charts only; fall back to splitting by family |
| Sampler thread blocks server | Lock-protected snapshot copy; short critical sections; sampler owns its own objects |
| CSP violation from ECharts | Canvas renderer only (no SVG style attributes); verify with Playwright |
| Virtualised table performance | Fixed row height; window + spacer; diffed updates |
| Theme flash on load | Inline script in `<head>` sets `data-theme` before first paint |
| Font not worth its weight | Measure; fall back to Segoe UI Variable stack |

## Dev-only tools

- `tools/webui-mock/server.mjs` — Node built-ins only, serves fixtures for
  visual iteration without admin rights.
- `tools/webui-e2e/` — Playwright screenshots and CSP/console checks.
- `tools/vendor/` — esbuild recipe for the ECharts bundle.

None of these are required to build or run the product.
