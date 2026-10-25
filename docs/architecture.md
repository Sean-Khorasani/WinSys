# Architecture

WinTCP is a native Win32 application written in C++17. The command-line and desktop executables have separate entry points and share the connection, process, enrichment, and action layers. The optional Web UI is served by the CLI executable and uses local static assets.

## Design principles

- **One snapshot model.** The GUI and CLI use the same endpoint enumeration and enrichment logic so their results stay consistent.
- **Unknown is not zero.** If Windows cannot provide a value, the model preserves that state and the interface shows it as unavailable.
- **Views do not own data.** Filtering, sorting, grouping, and display order operate on a snapshot or view index rather than rewriting connection identity.
- **Actions are explicit.** Mutating commands require confirmation and validate the selected live target before acting.
- **Keep the runtime local.** The native programs use Windows APIs; the Web UI assets are served from the same machine.
- **Privilege is optional and visible.** Snapshot inspection and Passive recipe evaluation use the per-user engine; only explicitly requested WFP restrictions and ETW lifecycle collection use the elevated helper.

## Data flow

```text
Windows networking tables ─┐
Process and system APIs ────┼─> SnapshotSource ─> connection/process records
Optional GeoIP and DNS ────┘                          │
                                                     ├─> CLI output
                                                     ├─> GUI connection store and views
                                                     └─> loopback Web UI API
```

`SnapshotSource` owns endpoint enumeration and enrichment. The CLI builds a snapshot for a command and exits. The GUI refresh worker builds snapshots on a timer and returns completed results to the window thread. The Web UI exposes connection, process, and metrics data through a loopback HTTP server; its browser client polls for updates.

The optional per-user engine owns snapshot sampling, Passive recipe evaluation, bounded event history, notification acknowledgment, and revision-checked configuration operations. It runs independently from the GUI and Web UI, so closing both interfaces does not stop enabled Passive monitoring. A same-user/session elevated collector is a separate optional process: it owns temporary WFP leases and starts its ETW lifecycle trace only after an explicit request. Its pipe is SID/session checked and heartbeat loss releases its temporary restrictions. A successful collector-start operation waits until the helper confirms the current engine epoch and heartbeat; WFP availability is reported separately, so degraded firewall support does not prevent trace-only use. Recipe invalidation checks broker reachability separately from WFP readiness, so an already-owned lease can still be released while new restrictions are degraded; an unreachable broker remains responsible for heartbeat-loss and lease-expiry cleanup. The trace uses a deterministic logger name and owner GUID scoped to that SID/session; startup stops a leftover logger only after querying and matching that GUID, and refuses a same-name session with a different owner. Clean shutdown stops only the exact trace created by the current collector.

Engine IPC is local-only and rejects remote named-pipe clients. The server checks the connecting process identity after reading a bounded first frame, then requires a fresh per-connection challenge before dispatching a versioned request. Frames are limited to 256 KiB and partial reads have a deadline; malformed greetings, lengths, and challenges are disconnected without dispatch. `tools/webui-e2e/engine-ipc-check.ps1` exercises machine-name remote rejection plus wrong-version, oversized, mismatched-challenge, and truncated-frame cases against an already-running engine and verifies it remains responsive; run it with `powershell -NoProfile -File tools/webui-e2e/engine-ipc-check.ps1`.

The engine's bounded operation journal reserves separate capacity for ordinary configuration/recipe work, collector work, and safety control (stop and lease releases). Safety control is selected ahead of queued previews or reactive actions; exhaustion returns an explicit queue-full result rather than silently dropping a request. Broker-owned expiry and heartbeat cleanup remain independent of this UI operation journal.

The snapshot engine compares successive endpoint tables only within a continuous sampling window. A long pause (more than five seconds and five configured intervals) emits a `sampling_gap`, resets the comparison baseline, and prevents the first post-pause table from being interpreted as a new connection or listener. Wall-clock discontinuities have a separate `clock_adjusted` gap and mapping ID; neither clock correction nor a sleep/resume gap rewrites prior event order.

Snapshot sightings and ETW lifecycle events retain separate provenance. TCP connect/close events can be normalized into a bounded flow history without re-inserting them as live endpoints; UDP records represent activity, not a complete connection lifecycle. Process-start `ImageFileName` text may be only a basename, so it is stored as `observedImageName`, not an executable `imagePath`. A flow-correlated name remains non-actionable. Active recipe actions require a currently verified process instance with an exact path and creation time, plus a separately approved bounded grant.

## Native application

The GUI separates the connection model from its visible view. `ConnectionStore` retains endpoint rows, pairs repeated endpoint identities across refreshes, and tracks recently closed rows. `ViewQuery` applies filtering and grouping; sorting and column visibility determine presentation without changing the underlying snapshot.

The GUI thread owns windows and controls. Background workers handle refresh, DNS resolution, and optional traffic collection so slow system calls do not block painting or input. Worker messages carry owned results back to the window; shutdown stops workers before releasing state they can access. Engine status and management are optional: the portable snapshot UI remains usable if the engine or elevated collector is unavailable.

The CLI follows a strict command contract. Each command accepts only its supported switches and reports distinct exit codes for success, empty/failure results, invalid arguments, and refused actions. Machine-readable output is generated from the same model as the table output.

## Web UI

`wintcp.exe webui serve` starts an HTTP server bound to `127.0.0.1`. It serves the static modules and styles alongside same-origin JSON endpoints. The Automations workbench reads and manages engine recipes, notifications, retained history, and collector controls through the local engine API; it does not own those services. A metrics sampler collects system readings independently of request handling and retains a bounded history for the browser charts. The browser polls while visible and pauses its work when the tab is hidden.

The server validates local requests, checks a per-process token and origin for state changes, and serves only approved static assets. Read-only endpoints are intentionally unauthenticated loopback endpoints; the token protects state-changing requests against cross-origin web pages, not against other local processes. Sensitive commands run through the sibling CLI with bounded arguments and explicit confirmation. The Web UI does not fetch remote map tiles, fonts, or scripts; its country geometry and libraries are bundled under `wintcp/webui/vendor/` with their licence notices.

The user-facing pages and service controls are described in the [Web UI guide](webui.md); UI conventions are in the [Web UI design guide](webui-design.md).

## Source organization

| Path | Responsibility |
|---|---|
| `wintcp/src/` | Native entry points, snapshot and process models, Windows API adapters, CLI commands, GUI windows, and Web UI server. |
| `wintcp/tests/` | Unit, CLI, benchmark, and UI harness code used by the development test executable. |
| `wintcp/webui/js/` | Browser entry point, state, API client, page modules, charts, and reusable UI components. |
| `wintcp/webui/css/` | Design tokens, shared styles, and page layouts. |
| `wintcp/webui/vendor/` | Locally served third-party libraries, map data, and licence texts. |
| `docs/` | User guides and architecture/design documentation. |

For commands and observable behavior, see the [CLI reference](cli.md) and [GUI guide](gui.md).
