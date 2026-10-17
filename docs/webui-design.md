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

## Adding a page

1. Create `js/pages/my-page.js` exporting a `render()` function.
2. Add a route in `js/router.js`.
3. Add a sidebar link in `index.html`.
4. Add any page-specific CSS to `css/pages.css`.

## Adding a chart

- **Time series:** Use `js/charts/timeseries.js` (uPlot wrapper).
- **Donut / bar / treemap / sankey / map:** Use `js/charts/echarts.js`.
- **Sparkline:** Use `js/charts/sparkline.js`.

All charts resolve tokens to `rgb()` at runtime and rebuild on theme change.

## Adding a metric

1. Add the series to `WebMetrics.cpp` (sampler thread).
2. Add it to `/api/metrics/catalog`.
3. The chart or KPI card picks it up automatically.

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
