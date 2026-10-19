# Changelog

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
