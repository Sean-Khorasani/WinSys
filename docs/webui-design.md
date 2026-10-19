# Web UI design guide

This guide describes the structure and conventions for extending the WinTCP Web UI. The application is built from native browser modules and CSS; the shipped UI has no framework, bundler, or remote asset dependency.

## Design principles

- Keep assets local and same-origin. Do not add CDNs, remote fonts, analytics, or runtime downloads.
- Use the shared light/dark design tokens in `css/tokens.css`; avoid one-off colors and decorative shadows.
- Keep the Content Security Policy strict: no inline scripts, `eval`, `javascript:` URLs, or HTML injection for data.
- Render untrusted values as text. Use the `h()` helper and pass DOM nodes as children rather than interpolating them into strings.
- Preserve accessible names, keyboard operation, visible focus, and semantic status for interactive controls.

## File layout

```text
wintcp/webui/
  index.html              # document shell and module entry point
  app.css                 # imports the shared stylesheets
  css/                    # tokens, base styles, reusable components, page layouts
  js/
    main.js               # application shell, state, polling, and navigation
    api.js                # same-origin API client and session token
    router.js             # hash routes
    h.js                  # DOM construction helper
    pages/                 # one module per dashboard page
    charts/                # uPlot, sparklines, heatmaps, maps, and treemaps
    ui/                    # reusable buttons, tables, cards, tabs, and dialogs
  vendor/                 # locally served libraries, data, and licence notices
```

## Styling and components

`css/tokens.css` defines the surfaces, text, borders, accents, and chart palette. Theme variants use `[data-theme="light"]` and `[data-theme="dark"]`; page styles belong in `css/pages.css`, grouped by page. Reuse the component classes and wrappers in `js/ui/` before adding a new variant.

Use the `h()` helper for DOM creation:

```js
import { h } from "../h.js";

const card = h("section", { class: "card" },
  h("h2", {}, "Connections"),
  h("p", {}, "Current endpoint snapshot"),
);
```

The helper flattens child arrays, skips `null` and `false`, appends DOM nodes directly, and turns strings into text nodes. Event handlers use `on*` properties such as `onclick`; use `ref` when a component needs a direct element reference.

## Adding a page or chart

1. Add a page module under `js/pages/` and export a `render()` function.
2. Register its route in `js/router.js` and navigation item in `js/main.js`.
3. Add page-specific layout rules in `css/pages.css`.
4. Reuse a chart wrapper under `js/charts/`; provide accessible labels and meaningful empty states.
5. Update `docs/webui.md` when the user-visible behavior changes.

For metrics, keep unknown values distinct from zero. The API should return `null` with a reason when a measurement is unavailable; UI labels should not imply that an unavailable reading is zero.

## Security and validation

The Web UI is served from loopback and uses a per-process token for state-changing requests. Preserve same-origin checks and avoid routes that expose arbitrary file paths or shell commands.

Third-party files and their licences are listed in `THIRD_PARTY_NOTICES.md` and `wintcp/webui/vendor/LICENSES/`.
