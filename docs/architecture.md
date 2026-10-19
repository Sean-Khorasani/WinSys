# Architecture

WinTCP is a native Win32 application written in C++17. The command-line and desktop executables have separate entry points and share the connection, process, enrichment, and action layers. The optional Web UI is served by the CLI executable and uses local static assets.

## Design principles

- **One snapshot model.** The GUI and CLI use the same endpoint enumeration and enrichment logic so their results stay consistent.
- **Unknown is not zero.** If Windows cannot provide a value, the model preserves that state and the interface shows it as unavailable.
- **Views do not own data.** Filtering, sorting, grouping, and display order operate on a snapshot or view index rather than rewriting connection identity.
- **Actions are explicit.** Mutating commands require confirmation and validate the selected live target before acting.
- **Keep the runtime local.** The native programs use Windows APIs; the Web UI assets are served from the same machine.

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

## Native application

The GUI separates the connection model from its visible view. `ConnectionStore` retains endpoint rows, pairs repeated endpoint identities across refreshes, and tracks recently closed rows. `ViewQuery` applies filtering and grouping; sorting and column visibility determine presentation without changing the underlying snapshot.

The GUI thread owns windows and controls. Background workers handle refresh, DNS resolution, and traffic collection so slow system calls do not block painting or input. Worker messages carry owned results back to the window; shutdown stops workers before releasing state they can access.

The CLI follows a strict command contract. Each command accepts only its supported switches and reports distinct exit codes for success, empty/failure results, invalid arguments, and refused actions. Machine-readable output is generated from the same model as the table output.

## Web UI

`wintcp.exe webui serve` starts an HTTP server bound to `127.0.0.1`. It serves the static modules and styles alongside same-origin JSON endpoints. A metrics sampler collects system readings independently of request handling and retains a bounded history for the browser charts. The browser polls while visible and pauses its work when the tab is hidden.

The server validates local requests, checks a per-process token and origin for state changes, and serves only approved static assets. Sensitive commands run through the sibling CLI with bounded arguments and explicit confirmation. The Web UI does not fetch remote map tiles, fonts, or scripts; its country geometry and libraries are bundled under `wintcp/webui/vendor/` with their licence notices.

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
