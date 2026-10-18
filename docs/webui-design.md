# Web UI Design Guide

This document describes the WinTCP Web UI's design system, component catalogue,
and how to extend it. It replaces the missing `gui-webui-design.md` that
`docs/webui.md` linked to.

## Design principles

- **Local only.** No CDN, no remote fonts, no analytics, no external requests.
  Everything is served from the same origin.
- **shadcn/ui aesthetic.** Neutral design tokens, subtle borders, small radii,
  no shadows. Light and dark themes.
- **No build step.** Vanilla ES modules + plain CSS. No framework, no bundler
  in the product.
- **CSP-safe.** No inline scripts, no inline styles, no `eval`, no `blob:`.
  All styles come from stylesheets; all behaviour from module scripts.

## File layout

```text
wintcp/webui/
  index.html              # Shell (token meta tag, module script)
  app.css                 # Entry: imports css/*.css
  css/
    tokens.css            # shadcn design tokens (light + dark)
    base.css              # Reset, typography, focus rings
    components.css        # Button, Badge, Card, Dialog, Table, ...
    pages.css             # Page-specific layouts
  js/
    main.js               # Entry point
    router.js             # Hash routes (#overview, #automations, #settings)
    api.js                # Token header, errors, abort/timeouts
    store.js              # Tiny observable state
    poller.js             # Visibility-aware polling with backoff
    format.js             # Intl.* formatters
    h.js                  # DOM helper (createElement + textContent)
    icons.js              # Lucide icons as inline SVG
    ui/*.js               # Component implementations
    charts/*.js           # uPlot, ECharts, sparkline wrappers
    pages/*.js            # Page implementations
    legacy/*              # Automation, monitor, script, audit logic
  vendor/                 # Third-party static assets (see THIRD_PARTY_NOTICES.md)
  data/                   # Vendored map data (Natural Earth)
```

## Design tokens

See `css/tokens.css`. The token set follows shadcn/ui's neutral theme:

- Light: `--background: oklch(1 0 0)`, `--card: oklch(1 0 0)`, `--muted: oklch(0.97 0 0)`
- Dark: `--background: oklch(0.145 0 0)`, `--card: oklch(0.205 0 0)`, `--muted: oklch(0.269 0 0)`
- Accent presets: Neutral (default), Blue, Green, Orange, Rose, Teal (brand)

### One documented deviation: the dark chart palette

shadcn's dark chart tokens are:

```
1 = oklch(0.488 0.233 27.325)   red
2 = oklch(0.696 0.169 16.384)   red
3 = oklch(0.769 0.188 70.08)    amber
4 = oklch(0.627 0.235 27.325)   red
5 = oklch(0.769 0.188 70.08)    amber
```

Four of five are red or amber. The Overview's CPU-and-memory chart draws exactly
two lines, so it rendered as two shades of the same red — a palette that cannot
distinguish its own series is not a palette. The dark five are therefore
re-hued, keeping shadcn's lightness and chroma character while separating the
hues:

```
1 = oklch(0.696 0.169 16.384)   rose
2 = oklch(0.749 0.128 205.0)   cyan
3 = oklch(0.722 0.152 145.0)   green
4 = oklch(0.714 0.161 300.0)   violet
5 = oklch(0.769 0.164 85.0)    amber
```

The **light** palette is unchanged. Every other token — including all of shadcn's
neutrals, radii and dark surface values — is copied exactly.

### Charts and colour

uPlot parses colours itself and does not understand `oklch()`, so
`js/charts/timeseries.js` resolves every token through a 1x1 canvas fill and
hands uPlot sRGB bytes. `chartPalette()` is the single place that mapping lives.

Two bugs live here and are worth knowing about if you touch it:

- `repaintCharts()` must map series colours on `index - 1`. uPlot's series
  array has the x axis at index 0; mapping on the raw index makes every chart
  start at the *second* colour after a theme switch, while the initial paint is
  correct. The two disagree until the next theme toggle, which is a
  particularly annoying bug to see.
- The x series carries `legend: false`. uPlot otherwise renders it as
  `Time: --` — its default label plus an empty value — on every chart.

## Adding a page

1. Create `js/pages/my-page.js` exporting a `render()` function.
2. Add a route in `js/router.js`.
3. Add a sidebar link in `index.html`.
4. Add any page-specific CSS to `css/pages.css`.

## Adding a chart

- **Time series:** Use `js/charts/timeseries.js` (uPlot wrapper).
- **Sparkline:** `sparkline(container, values, opts)` in
  `js/charts/sparkline.js`. Built with `createElementNS`, never `innerHTML`.
- **Ranked "top N" lists:** `barList(container, rows, opts)` in the same module.
  Prefer it to a chart library for anything that is a ranked list — it needs no
  canvas, it inherits the theme's CSS variables for free, and every cell is real
  text, so it is screen-reader legible and user-selectable.
- **Donut / treemap / sankey / map:** `js/charts/echarts.js`. Not yet wired to
  any page; the Overview deliberately uses CSS bars instead so it does not pay
  for the 1 MB bundle.

All charts resolve tokens to `rgb()` at runtime and rebuild on theme change.

### Sparkline rules that are not obvious

- **A gap is a gap.** `polylineSegments()` emits one polyline per contiguous run
  of known values. Interpolating across a null would draw a slope nobody
  measured; clamping it to zero would draw a dip to the baseline. Both are
  claims about the machine.
- **Downsample by mean, never by stride.** A stride can land only on the peaks,
  so the line shows spikes the data does not contain.
- **Zero-baseline where possible.** The axis is clamped to 0 whenever the data
  allows it; a CPU chart with a floating baseline exaggerates every wiggle. A
  flat series gets a band of its own rather than dividing by zero and
  collapsing onto an edge.
- `downsample()` and `polylineSegments()` are exported separately from the DOM
  code precisely so `node --test` can cover the geometry in `wintcp/tests/webui/`
  without a browser.

## Adding a metric

1. Add the field and its `*Known` flag to `MetricsSample` in `WebMetrics.h`.
2. Collect it in `CollectSample` (sampler thread only — never in a request).
3. Emit it in `/api/metrics/now` with `null` + a reason when unknown.
4. Add a `KnownSeriesIds()` entry so `/api/metrics/history` accepts it, and a
   case in `ExtractSeries` so it resolves.

`/api/metrics/catalog` needs no edit: it is built from a live sample precisely so
it cannot drift from what the sampler actually produces.

## Adding an endpoint

1. Add a route in `WebUi.cpp` (or the new `WebStatic.cpp` for static files).
2. All endpoints are `GET` unless they reuse the existing permit flow.
3. Unknown values are `null` plus a `reason` — never zero.

## CSP rules for contributors

- No inline `<script>` or `<style>` elements.
- No `style=` attributes in HTML; use `el.style.setProperty()` from JS.
- No `eval`, `new Function`, `setTimeout(string)`.
- No `javascript:` URLs.
- All assets are same-origin. No `blob:` or `data:` for scripts.

## Rebuilding vendored assets

See `tools/vendor/README.md` for the ECharts bundle and map data recipes.
