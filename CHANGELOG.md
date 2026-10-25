# Changelog

## 1.0.8 — 2026-10-24

- Added a per-user engine for persistent, exact-application monitoring recipes, durable notifications, retained event history, and Web UI management. Passive snapshot recipes work without elevation; event-based collection and Active restrictions remain optional, explicitly enabled, and require the elevated collector.
- Added reviewed, temporary network restrictions with explicit application/peer scope, bounded grants and leases, owner-aware release, expiry, and visible collector/WFP status. Active actions require verified lifecycle evidence and are never restored automatically after restart.
- Added optional ETW lifecycle visibility for short TCP flows, UDP activity, and process start/exit evidence, with bounded queues/history, process-instance safeguards, ETW ownership checks, and explicit loss/coverage reporting.
- Added an opt-in incident flight recorder with bounded pre/post-trigger capture, snapshot checkpoints, integrity-checked local archives, retention/pinning, privacy-filtered or confirmed full export, safe local import, and offline read-only replay.
- Added weekly time-zone-aware recipe schedules and best-effort browser notifications for new inbox entries. The durable local inbox remains authoritative; browser permission and an open dashboard are required for toast delivery.
- Expanded native, CMake, and headless Web UI coverage for schedules, restrictions, event retention, incident archives, import/export, replay, and notification delivery.

### Windows x64 package

`WinTCP-1.0.8-Windows-x64.zip` contains the CLI and desktop executables,
local Web UI assets, service helper scripts, user documentation, screenshots
referenced by the README, and license notices. It excludes the optional GeoIP
database and development/test artifacts. No installer or third-party runtime
is required. ETW collection and temporary WFP restrictions remain optional
and require explicit user action (and administrator rights).

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
