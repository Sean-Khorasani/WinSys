# WinTCP Quality Pass

## Audit Findings

- [x] Inspect process collection, GUI refresh/freeze flow, Web UI polling, table rendering, details dialogs, CLI sort paths, and available tests.
- [x] Confirm the Web UI requests only 200 processes despite the API supporting up to 2,000.
- [x] Confirm the Processes page signature ignores process-sample changes, leaving CPU, memory, and I/O values stale between first render and later polls.
- [x] Confirm `ProcStatsSampler` requests `PROCESS_VM_READ` although its queries do not need module memory access, causing avoidable access-denied rows.
- [x] Confirm Web UI process sampling reports thread count as unknown despite `PROCESSENTRY32W::cntThreads` being available.
- [x] Confirm process name sorting violates comparator requirements when names tie; numeric sorts also lack stable PID tiebreaks.
- [x] Confirm the shared virtual table hard-codes a 520 px viewport and details dialogs have no small-screen layout treatment.
- [x] Confirm Web UI state has a `paused` field but exposes no pause/hold control; GUI has a separate Freeze view command.
- [x] Reproduce poll-driven page remounts that could interrupt active Processes/Network filters and cancel their pending debounce timers.
- [x] Find that in-place row refreshes also need to update sortable header arrows/ARIA state, not only row order.
- [x] Find that virtual-table row focus also needs stable process/endpoint identity when live samples reorder rows.
- [x] Audit table refresh teardown: keep restored scroll positions user-adjustable and release resize listeners when table tabs become hidden.

## Implementation Plan

1. **Process data quality** — use least-privilege query handles, populate thread counts, exclude the idle pseudo-process, make cached paths PID-lifetime-safe, and request the full supported process page. Add focused tests.
2. **Live process updates and sorting** — refresh process and network data in place without remounting filter controls, preserve table state, and update row data, sort order, header state, and accessible sort metadata together.
3. **Snapshot hold controls** — add an explicit Web UI pause/resume control that preserves the last complete snapshot, ignores in-flight results after pause, and clearly labels held data. Verify the GUI Freeze command and improve discoverability if needed.
4. **Responsive tables and detail views** — size virtual tables to the available viewport, retain usable horizontal scrolling on narrow screens, and make process/connection detail dialogs readable and correctly positioned across screen sizes.
5. **Cross-surface polish** — audit CLI/table empty and unavailable states, sort semantics, keyboard interactions, and user-facing help/docs for consistency.
6. **Validation** — run native build and unit/smoke tests, Web UI module validation, targeted Playwright coverage, and responsive/interaction checks; record remaining limitations here.

## Progress

- [x] Phase 1: Process data quality (query rights, threads, idle PID, PID-safe image paths, full process limit; focused sort/snapshot tests added).
- [x] Phase 2: Live process updates and deterministic sorting (Processes and Network now update in place; active filters stay mounted through polling; table rows, accessible sort indicators, and row focus update by stable identity; process scroll, view, and filter state persist).
- [x] Phase 3: Snapshot hold controls (Web UI pause/resume stops polling and discards an in-flight result; GUI Freeze was verified in source).
- [x] Phase 4: Responsive tables and details dialogs (viewport-based virtual table height, horizontal overflow, constrained mobile dialog layout).
- [x] Phase 5: CLI and cross-surface polish (CLI contract smoke tests pass; GUI Freeze retains the visible rows while sampling continues; user-facing Web UI guide updated).
- [x] Phase 6: Validation and final review (native build/smoke gate, 1,204 unit checks, 38-module parse, 182 Playwright automation checks, 20 page/theme browser checks, first-sample and active filter stability, restored scroll retention, pause polling, and mobile detail bounds verified).

## Remaining Limitations

- Windows may deny CPU, memory, I/O, or image-path access for protected processes; those readings remain unknown rather than being fabricated as zero.
- The local Processes API caps each response at 2,000 rows; the Web UI requests the maximum supported page.
- Country-level map results still require the user to configure a local GeoIP database.
