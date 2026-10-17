# Architecture

WinTCP is one native Win32 process with no third-party dependencies. This document is how it is put together: the principles the code enforces, the threads it runs on, what makes a connection row *the same row* from one refresh to the next, and where each file lives.

User-facing behaviour is in the [GUI guide](gui.md) and the [CLI reference](cli.md).

## Contents

- [Design principles](#design-principles)
- [Concurrency model](#concurrency-model)
- [Row identity and diffing](#row-identity-and-diffing)
- [Model and view are separate](#model-and-view-are-separate)
- [Data flow](#data-flow)
- [Source layout](#source-layout)

## Design principles

### One snapshot pipeline, and no HWND in it

`Snapshot.h` states the rule and why it exists: *there is exactly one place that produces a snapshot, and no `HWND` appears anywhere in it.* There used to be two - the body of `RefreshEngine::Run` and a private copy called `BuildSnapshot` in `Cli.cpp` - and they had already drifted: the GUI sampled per-process stats and joined traffic, the CLI copy did neither, so `--format full` printed an em-dash for every enriched column. A second copy of anything is a second thing to forget to update.

Two consequences are enforced by the type rather than by convention. `SnapshotSource` is **not thread-safe** - it holds the process resolver and the CPU-baseline sampler, both of which carry state between passes by design - and it is **not copyable**, so nothing can pass one across a thread boundary by value. Give each thread its own instance: `RefreshEngine` owns one on its worker thread, the CLI owns one on its own thread.

Enrichment failures are not fatal. If enumeration itself fails the pass reports an error; if a later step fails, the affected fields stay unknown, because a missing country code is not a reason to show the user an empty list.

### A silent answer is the worst answer

Three rules, each enforced in code and pinned by `wintcp-dev.exe unit`, because each started life as a real defect:

- a stat reading that could not be taken matches **no** threshold, so `mem:0` never selects a process that was never measured;
- a byte total that cannot be attributed to one socket is **never** split across a process's connections to fabricate a rate;
- a count nobody measured (`Columns shown`, `Connections` in `version`) is **omitted** rather than printed as a confident `0`.

The em-dash is the same rule at cell level: `-` means *unknown* and is never a hidden zero. What the traffic counters can and cannot honestly answer is in [Traffic counters](traffic.md).

### A swallowed switch is worse than a wrong one

A misspelled or misplaced switch used to be accepted and silently dropped, handing a script a successful run and the wrong answer. Every verb now declares which switches it acts on and refuses the rest with **exit 2**, naming both the offending switch and the verb it belongs on. The exit-code contract (`0` ok, `1` failure/empty, `2` bad arguments, `3` refused) is in the [CLI reference](cli.md).

### The product carries no test code

`selftest`, `bench` and `--uiharness` were compiled into `wintcp.exe` until 2026-10-02; all three now live in `wintcp-dev.exe`, and all three return *unknown command* from the product today. The one deliberate exception is the **hidden `crashtest` verb**, which exists so `the CLI test suite` can drive the crash path against a real process and assert that the breadcrumb, the minidump and the failure reason all reach disk.

### Zero dependencies

Every helper - RAII handles, UTF-8/UTF-16 conversion, `FormatSystemError`, DPI and error-text helpers - is in-tree under `Utils.*`. ETW comes straight from `evntrace.h` and `evntcons.h`. Nothing is vendored, so there is no package manager, no submodule and no third-party licence to re-read at release time.

## Concurrency model

### The threads

| Thread | Created in | What it does |
|---|---|---|
| UI / main | `main.cpp` | Window, message pump, painting, `ApplyView`, and every `SetTimer` tick. Nothing below runs here. |
| Refresh worker | `RefreshEngine.cpp` | One pass per interval: enumerate endpoints, resolve processes and services, sample stats, join traffic. Posts a complete `RefreshResult` back to the UI. |
| DNS worker | `DnsResolver.cpp` | Pops one remote address at a time, `getnameinfo(NI_NAMEREQD)`, caches, delivers. Reverse DNS is slow and blocking, so it never runs on the UI thread. |
| DNS answer cache | `DnsCache.cpp` | Persists the answers the worker earns to `%APPDATA%\WinTCP\dns-cache.txt`, so a peer seen by an earlier run costs a file read instead of a query. Positive answers only, 24 h TTL. |
| ETW session | `EtwTraffic.cpp` | The kernel-logger session's event callback. Elevated only; when it cannot start the UI arms the non-admin fallback instead. |
| Probe workers (x16) | `SocketTraffic.cpp` | The non-admin fallback: one `SIO_TCP_INFO` ioctl per socket, farmed out across `kProbeWorkers` threads. |
| Thread sampler | `ProcessInfo.cpp` | Enumerates one process's threads for the Details window. `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)` walks every thread on the machine and costs ~48 ms, so it runs here rather than on the UI thread, which rebuilds the Details model on every refresh tick. `ProcessThreads` never blocks: it publishes the last sample and asks for a refresh. |

Process resolution, per-PID stat sampling and GeoIP lookup all happen *inside* a refresh pass on the refresh worker. They are work, not threads.

### The payload registry

A worker cannot hand a `RefreshResult` to the UI by reference: by the time the UI reads it the worker may already be building the next pass, and by the time the worker posts it the window may be gone.

The mechanism is a registry of **heap payloads** held in a refcounted block that neither side owns alone:

```text
WorkerSink.h
struct WorkerSink {
    std::mutex m;
    std::set<RefreshResult*>      pendingRefresh;
    std::set<DnsResolver::Result*> pendingDns;
    bool shuttingDown;
    HWND hwnd;
};
std::shared_ptr<WorkerSink> sink_;
```

1. The worker inserts the payload into the set **under the lock**.
2. Then it calls `PostMessageW`.
3. If the post fails, it erases and deletes the payload itself.
4. The receiver erases on receipt. **If the erase finds nothing, the payload is not ours** - shutdown already drained it - and the handler returns without touching it.
5. At shutdown the window deletes everything still pending.

Because `sink_` is a `shared_ptr`, a worker that `Stop()` detached still holds a live registry. Its late callback completes against freed-window-*safe* state, and its `PostMessage` to a dead `hwnd` simply fails. That is what makes the bounded-join detach provably harmless rather than hopefully so.

### Shutdown order

Workers are stopped before anything they could touch is freed. `RefreshEngine::Stop()` polls for the thread handle up to a deadline and only then detaches. Two mechanisms cover the remaining race: `Run()` checks `stop_` before invoking the callback, and the callback only ever touches the refcounted `WorkerSink` and heap-owned state - never a `MainWindow` member.

### The refresh watchdog

A dead refresh worker is a frozen list that *looks* alive, which is the most misleading failure this UI has. `RefreshEngine.h` keeps the entire policy in one pure decision function, `RefreshWatchdogNext`, with all three bounds declared beside it:

| Constant | Value | Meaning |
|---|---|---|
| `kWatchdogIntervalFactor` | 4 | missed intervals before the view is declared stale |
| `kWatchdogFloorMs` | 15000 | the same rule on a fast cadence, whichever is longer |
| `kMaxWatchdogRestarts` | 3 | then auto-refresh switches off, loudly |

The floor dominates on fast cadences (4 x 2 s = 8 s would false-positive on two consecutive slow passes) and the factor dominates on slow ones (a 60 s cadence missing 4 ticks is 4 minutes of dead UI). Restart history is forgiven by a healthy tick, so restarts accumulate only across consecutive stale periods - and past the cap auto-refresh disables itself rather than looping forever.

### The probe pool

`SIO_TCP_INFO` has no timeout you can ask for, and one socket whose ioctl never returns must not stop the scan. The fallback therefore runs the ioctls on `kProbeWorkers` detached threads and abandons a worker after `kNoProgressMs` of no progress.

| Constant | Value | File |
|---|---|---|
| `kProbeWorkers` | 16 | `SocketTraffic.h` |
| `kNoProgressMs` | 250 | `SocketTraffic.h` |

Neither is a guess. They come from a measurement probe that walked 391 sockets one at a time on the design machine: 4 answered, 387 failed at once, one call took 28,281 ms, and the next was still running after 90 s. Re-run that probe on the machine you care about before changing them.

## Row identity and diffing

### The key

`ConnectionStore::KeyOf` builds a fixed-width `ConnectionKey` from:

```text
protocol + address family + local address + local port
       + remote address + remote port + PID
```

That is 46 bytes at its widest (IPv6), asserted to fit at compile time.

### State is deliberately not in the key

A connection moving `ESTABLISHED -> TIME_WAIT` must stay **one** row and produce a STATE event. Including state would turn every transition into a close followed by a new row, which would break the change feed exactly where it is busiest.

The PID *is* in the key, because of a measured failure. Keyed without it, 62 rows sharing `UDPv4|0.0.0.0:5353|*|*` (mDNS) collapsed into a single previous row, so every refresh reported 61 DISAPPEAR ghosts and 62 brand-new rows - forever.

### Duplicates pair in order, they never collapse

The 4-tuple is not unique on a real machine: mDNS makes dozens of identical rows the *normal* case. A single-entry map would keep only the last row of a repeated key, so `ReplaceSnapshot` keys previous rows into a **queue per key** - the N-th fresh row of a key pairs with the N-th previous row of it. Rows sharing a key are interchangeable to the user (same endpoint, same owner, same state - that is why they share a key), so pairing in order is both stable and invisible.

The alternative was measured rather than assumed. A single-index lookup turned each refresh into N-1 false closes followed by N "new" rows, which is what made the change feed useless exactly where the table is busiest.

### Ghosts

A row that disappeared flashes red for one refresh, then lingers as a **grey retained ghost** so the table keeps a short history of recently closed sockets. Ghosts are bounded at `ConnectionStore::kMaxRetainedGhosts` (500); the oldest are aged out first, their final byte counters frozen at the moment of death. `DISAPPEAR` still fires exactly once, so the change feed is unchanged.

## Model and view are separate

`ConnectionStore` owns the rows (`Rows()`) and a separate view index (`View()`, read through `ViewRow()`). `SetView(ViewQuery)` applies filter and grouping; `SetSort(column, ascending)` orders it. Neither mutates the model.

That is why the GUI can re-apply a view on every debounced keystroke, why the CLI can ask for a filtered, grouped, sorted projection in a single pass, and why `the CLI test suite` can assert *shapes* instead of row counts: the view pipeline is deterministic, the machine is not.

## Data flow

```text
  TcpTable / ProcessInfo / ProcStats / GeoIp        one pass, refresh worker
                         |
                         v
               SnapshotSource::Build          the only producer; no HWND
                         |
                         v
                ReplaceSnapshot               identity diff: match, ghost, appear
                         |
                         v
                 SetView + SetSort            filter, group, project
                         |
          +--------------+---------------+
          |                              |
          v                              v
   UI: list view              CLI: RenderList -> table | csv | tsv | json | jsonl
```

The CLI builds the same `Snapshot` through the same `SnapshotSource`, so a command is testable without creating a window and the two front ends cannot drift apart.

## Source layout

```text
./
  README.md                 entry point to this document set
  CMakeLists.txt            CMake build (cl + rc + link)
  wintcp.sln                Visual Studio solution
  docs/                     this document set
  wintcp/
    wintcp.vcxproj (+.filters)
    res/                    app.ico, wintcp.manifest
    tests/                  everything that is not the product
    src/                    61 .cpp + 68 .h - the product, and nothing else
```

### `wintcp\src` by responsibility

**Entry and dispatch** - `main.cpp` (wmain, CLI dispatch, message loop), `Cli.*` (CLI entry and single-mode dispatch), `CliCommands.*` (subcommand verbs), `BuildInfo.*` (embedded build metadata).

**Model** - `Connection.h` (row struct and highlight flags), `Columns.h` and `ColumnsWin.h` (column set and masks), `ConnectionStore.*` (stable-id diff, filter, sort, group, columns), `ViewState.*` (what the user had selected and shown), `Grouping.*`.

**The 32-column ceiling is a decision, not a limit that ran into.** The visible
set, order, widths and sort all persist, and the visible set is a `UINT32` mask -
one bit per `ColumnId` - in `Settings.h`, in the registry, and in the Columns menu's
`IDM_COL_BASE + n` range in `resource.h`. `COL_COUNT` was taken from 29 to
exactly 32, so the mask is now full. `ColumnsWin.h` carries a `static_assert` that
fails the build at 33, which is the point: the failure is meant to be loud and to
name what has to widen first. **The decision taken on 2026-10-06 is to freeze at
32**, not to widen. The reasons are that a 33rd column does not exist today, that
widening is not one change but eight (`UINT64` mask, `REG_BINARY` at 8 bytes, a
`kCurrentColVersion` 6 migration with the v4 and v5 precedents to follow, the
`IDM_COL` range, `ColumnTitle` / `GetColumnText` / `CompareRows` / `JsonKeyFor`,
`GroupedDefaultColumns`, the `help list --columns` prose and its golden asserts),
and that a persisted-mask widening which gets one of those wrong shows up as a
user's saved layout silently changing. A column that is genuinely needed should
raise this deliberately, not arrive as a side effect of a feature. Where a feature
wanted a column that would not fit - ASN is the live case - it reuses the
Country column rather than growing the mask.

**ASN is that case, and it now reuses `country`**. The cell renders both
answers as `US · AS15169 Google LLC`, with the separator appearing only when both
are known, so a row that has only a country looks exactly as it always did. The AS
number is placed *before* the operator name on purpose: the cell ellipsises on
overflow in a narrow window, and a truncation that hid the number would leave a
row looking unidentified. `Details` separates the two into their own rows.

The two answers come from two different MaxMind products - GeoLite2-Country and
GeoLite2-ASN - which is why the CLI has `--db` and `--asn-db` and the window has
two pickers, and why neither is required for the other.

**The shared pipeline** - `Snapshot.*` (the only snapshot producer), `RefreshEngine.*` (background worker and watchdog), `DnsResolver.*` (reverse DNS), `Commands.*` (the abstract command layer both front ends call).

**Enumeration and enrichment** - `TcpTable.*` (IP Helper table, including scope IDs), `ProcessInfo.*` (Toolhelp / OpenProcess / SCM cache), `ProcStats.*` (per-PID CPU, memory and IO), `SysStats.*` (system CPU, memory, disk, net), `GeoIp.*` (MaxMind DB reader), `WinCaps.*` (Windows capability report).

**Handshake parsing** - `TlsDecode.*` (TLS record framing, ClientHello/ServerHello parsing, cipher-suite names). `capture --text` calls it on the reassembled stream and reports the handshake it found, which is its one production caller. The `tls` *column* is a separate matter and is deliberately **not offered**: a socket-level TLS source would be needed over every row, and neither of the two real sources can supply one (`SIO_TLS_INFO` is not declared in this SDK, `TCP_INFO_v0` has no TLS field). The `ColumnId`, its mask bit and its stored width are all kept so nothing renumbers, and the single place it is excluded is the display-order list.

**Traffic** - `EtwTraffic.*` and `EtwTrafficTypes.h` (kernel-logger counters, elevated), `SocketTraffic.*` (non-admin `SIO_TCP_INFO` fallback).

**Capture and reassembly** - `StreamCapture.*`, `Pcapng.*`, `TcpReasm.*`.

**Persistence** - `Settings.*` (HKCU), `Presets.*`, `Bookmarks.*`.

**Blocking** - `BlockConn.*` (firewall rules and their ledger), `Elevate.*`.

**Windows** - `MainWindow.*` (the window, its controls, menus, settings, and the message routing), `MainWindowInternal.h` (the shared constants and free helpers every window unit uses), `ConnectionsList.*` with `ConnectionsListOwner.*` (the list control, its cell text, its painting and its selection, and the sink it reports through), `ListViewColumns.*` (column geometry: mask, widths, order), `RowEnrichment.*` (DNS, country, ASN), `WorkerSink.h` (the worker mailbox), `AlertMonitor.*` (the alert engine's wiring), `ViewPresets.*` and `BookmarkActions.*` (the preset and bookmark dialogs), `DetailsDialog.*` with `DetailModel.*`, `ChartsWindow.*` with `ChartExport.*`, `ChangeLogWindow.*`, `PromptDialog.*`, `Alerts.*`, `TypeToJump.*`, `Freeze.*`, `RowAccessible.*`, `ProcessTreeView.*`, `Theme.h`, `FontCache.*`.

There is deliberately no hex window. `HexTextWindow.*` was the view behind the GUI's *Follow TCP stream* action, and it was deleted on 2026-10-05: the action was removed first (it re-elevated the whole application, then blocked modally on a capture that can legitimately return nothing), which left the class unreachable, and an unreachable window is worse than no window - it still compiles, still appears in the project file, and reads as a feature that works. The capability lives in the CLI instead (`capture --text` prints the reassembled stream, `capture --out FILE` keeps the pcapng), and `MainWindow.cpp` keeps the removal note that explains why, because the chain of reasons is the argument for the CLI having the feature at all.

**Infrastructure** - `Utils.*` (UTF-8, formatting, DPI, error text), `CrashDump.*`, `Version.h` (the single source of truth for the version), `resource.h` and `wintcp.rc` (menu, accelerator, manifest, icon, version).

### `wintcp\tests` by purpose

| File | Role |
|---|---|
| `TestMain.cpp` | entry point for `wintcp-dev.exe` (the product's `main.cpp` is excluded) |
| `Bench.cpp`, `Bench.h` | `unit` and `bench`: real production code, fixed inputs |
| `UiHarness.cpp`, `UiHarness.h` | `ui`: drives the real window's `WndProc` |
| `wintcp-dev.vcxproj` | the Visual Studio project for the test driver |
| `d2probe.cpp` | the measurement probe behind `kProbeWorkers` - **not a gate** |

`wintcp-dev.exe` links the *same* product sources as `wintcp.exe`, minus `main.cpp`. That is the point: a test that exercised a copy of the logic would prove nothing.
