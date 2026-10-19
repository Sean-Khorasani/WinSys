# Changelog

## 1.0.4 — 2026-10-19

- Refined the desktop Details window with consistent typography, clearer tabs, and a full-width command-line view for long values.
- Added responsive Web UI inspectors for processes and connections, with precise field copying, held snapshots, and stable identity tracking as samples update.
- Improved the native blocked-peer manager with filtering, resizable layout, and a selected-rule scope summary.
- Improved process and network exploration with responsive table layouts, more resilient saved column settings, and map markers linked to the exact connection details.
- Expanded browser and native regression coverage for inspectors, responsive layouts, map identity, and blocked-peer management.

## 1.0.2 — 2026-10-18

- Corrected process sampling and ownership details, including safer handling of PID reuse and more complete process metadata.
- Kept process and network filters, sorting, selection, and scroll position stable while live samples refresh.
- Made Web UI tables and detail panels adapt to available screen space.
- Reworked the map page to show country boundaries, connection activity, and globe/flat-map views.
- Clarified that automation catalog entries are on-demand CLI playbooks, not background monitors; improved their examples and validation.
- Allowed address enrichment for concrete remote endpoints regardless of TCP state or process ownership.
- Updated the CLI cookbook and Web UI guide to match current behavior.

### Windows x64 package

The release archive contains `wintcp.exe`, `wintcp-gui.exe`, the local Web UI assets, the Web UI service helper scripts, and the project documentation and license. No installer or third-party runtime is required.
