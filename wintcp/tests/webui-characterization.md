# Web UI Characterization Checklist

Re-run after the front-end migration (Phase 2+) to verify no regression.

## Navigation
- [ ] Hash routes `#overview`, `#automations`, `#settings` work
- [ ] Sidebar nav items switch views
- [ ] Browser back/forward navigates between views

## Overview page
- [ ] Connection table loads with data
- [ ] Filter box accepts WinTCP filter syntax (e.g. `port:443`, `state:estab`)
- [ ] Filter box accepts ordinary text (substring match)
- [ ] Sort by column works (process, PID, proto, local, remote, state, RX, TX)
- [ ] Sort direction toggle works
- [ ] Protocol filter (all/TCP/UDP) works
- [ ] State filter works
- [ ] Group by process toggle works
- [ ] Freeze display toggle works
- [ ] Column picker shows/hides columns
- [ ] Saved views: save, load, delete
- [ ] Row selection: select visible, clear selection
- [ ] Bookmark selected rows
- [ ] Copy rows to clipboard
- [ ] Export CSV/TSV/JSON (all matching rows, not just visible 250)
- [ ] Connection details dialog opens on row click
- [ ] Block flow: preview → confirm → commit
- [ ] KPI cards show real data (connections, established, processes, coverage)
- [ ] "Stale snapshot" label appears after failed refresh
- [ ] Last-updated timestamp refreshes

## Automations page
- [ ] Template library loads 40 templates
- [ ] Template search filters list
- [ ] Script editor: validate, run, copy, import, export, save, remove
- [ ] Script console shows execution trace, variables, output
- [ ] Monitor rules: add, enable, disable, delete
- [ ] Events list shows monitor alerts
- [ ] T01 monitor: threshold alert fires
- [ ] T06 monitor: new peer alert fires
- [ ] T07 monitor: new listener alert fires
- [ ] T08 monitor: wildcard listener detection
- [ ] T11 monitor: too many listeners
- [ ] T12 monitor: fan-out detection
- [ ] T29 monitor: RTT threshold
- [ ] Block preview from T01 event

## Settings page
- [ ] Refresh interval selector (2/5/10/30s)
- [ ] Theme selector (system/dark/light)
- [ ] Desktop notifications toggle
- [ ] Audit trail loads
- [ ] Audit search filters
- [ ] Audit export

## Global
- [ ] Service status pill updates (connecting/online/stale/error)
- [ ] Refresh button triggers manual refresh
- [ ] Toast notifications appear
- [ ] Confirm dialog works
- [ ] Keyboard: Esc closes dialogs
