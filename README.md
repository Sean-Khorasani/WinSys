# WinTCP

**Live TCP/UDP connections with their owning processes: a standalone scriptable CLI, a standalone native GUI, and an optional local Web UI.**

![Platform: Windows](https://img.shields.io/badge/platform-Windows-0078D6)
![Language: C++17](https://img.shields.io/badge/C%2B%2B-17-00599C)
![API: Win32](https://img.shields.io/badge/API-Win32-informational)
![Dependencies: none](https://img.shields.io/badge/dependencies-none-brightgreen)
![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue)

WinTCP lists every TCP and UDP endpoint (IPv4 and IPv6) on a Windows machine together with the process that owns it, in the tradition of Sysinternals TCPView and NirSoft CurrPorts. On top of that it adds a command-line mode with strict exit codes, per-process traffic counters that work **without administrator rights**, kernel TCP health metrics (RTT, congestion window, retransmits), and process-aware actions (close one socket, kill the owner of a port, block a peer) that refuse to run without explicit confirmation.

It is written against the plain Win32 API: no MFC, ATL, Qt or other third-party library. The C runtime is linked statically. `wintcp.exe` is a console-only CLI; `wintcp-gui.exe` contains and runs the native GUI directly. Neither executable launches or requires the other. Both are built for x64 Windows and use only Windows system libraries at runtime. The optional Web UI command additionally needs the `webui` static-asset folder beside `wintcp.exe`.


```text
Process     CPU %  Traffic (rx/tx)   Proto  Local         LPort  Remote       RPort  State         PID
chrome.exe  3.2 %  18.0 MB / 1.2 MB  TCPv4  192.168.1.10  51752  203.0.113.9    443  ESTABLISHED    42
System          —  —                 TCPv4  0.0.0.0         443  *:*              —  LISTENING       4
mdns.exe    0.1 %  0 B / 4.0 KB      UDPv4  0.0.0.0        5353  *:*              —  —            1234
```

*Illustrative layout of the default columns.*

## Contents

- [Highlights](#highlights)
- [Quick start](#quick-start)
- [Requirements and permissions](#requirements-and-permissions)
- [GeoIP database](#geoip-database)
- [Command-line overview](#command-line-overview)
- [The filter language](#the-filter-language)
- [Safety model](#safety-model)
- [How it compares with the built-in tools](#how-it-compares-with-the-built-in-tools)
- [Documentation](#documentation)
- [Building from source](#building-from-source)
- [Troubleshooting](#troubleshooting)
- [Known limitations](#known-limitations)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgements](#acknowledgements)

## Highlights

- **No installer or third-party runtime.** `wintcp.exe` is the console-subsystem CLI; `wintcp-gui.exe` is the standalone Windows-subsystem GUI. Each starts without the other executable beside it. Six optional Windows system libraries are delay-loaded, so an install missing one still starts and only the matching feature is disabled.
- **As much as possible works without admin.** Per-PID byte totals, connection age, per-socket rate and RTT/cwnd/retransmit figures come from the kernel's own per-socket TCP counters (`SIO_TCP_INFO`) and need no privileges. Elevation adds ETW-based totals that include UDP.
- **Scriptable by contract.** One command takes one snapshot and exits. Exit codes are documented, data goes to stdout and advice to stderr, `--quiet` turns any filter into a zero-output predicate, and output is table, CSV, TSV or JSON. A switch a command does not use is an error, not a silent no-op.
- **Safe actions.** Destructive verbs refuse to run without `--yes` (exit 3), support `--dry-run`, check PIDs against process creation time, and never try to elevate themselves.
- **Joins that no single built-in tool performs.** Process path, service, parent process, integrity level, reverse DNS, GeoIP country, byte counters, kernel connection age, bookmarks and notes in one row.
- **Answers "should I trust this process".** A Parent column for who launched it, Integrity for the level Windows gives it (`High` means it could have written to `HKLM`), and an Authenticode Signature column that separates *unsigned* (normal for most software) from *BAD SIG* (a chain that does not verify). `--signatures` is opt-in because a certificate chain is not a per-refresh cost.
- **Built for busy machines.** A virtual list view stays responsive with tens of thousands of rows. Row identity is *endpoint + PID*, so dozens of identical sockets (every browser binds its own mDNS socket) do not produce false change events.

## Quick start

### GUI

Run `wintcp-gui.exe` for the native window. It is the GUI itself, not a wrapper; it does not locate or start `wintcp.exe`. Running `wintcp.exe` with no arguments prints CLI help and never opens a window. The window refreshes automatically; press **F5** to refresh on demand. Right-click a row for **Details**, **Copy**, **End process**, **Close connection** and **Export**. Run it elevated (right-click, *Run as administrator*) if you want UDP byte counters or to close connections.

See the [GUI guide](docs/gui.md) for columns, filtering, the change log, performance graphs and settings.

### Local Web UI

Run `wintcp.exe webui serve` for the foreground dashboard, or use `webui-service.bat start` to launch it in the background. The manager defaults to **DEBUG** logging; use `webui-service.bat status` and `webui-service.bat stop` to manage it. The dashboard filters and sorts connections, exports the full filtered snapshot to CSV, and can show optional privacy-preserving browser alerts. Logs are written to `%LOCALAPPDATA%\WinTCP\WebUi\webui.log`; configuration and the audit log remain in the same folder. Six of the 40 prepared monitor templates currently have evaluators; monitors run only while the dashboard tab is open, and unsupported templates stay disabled. See the [Web UI guide](docs/webui.md) for controls, feature coverage, telemetry limits, and the confirmed firewall action.

### CLI

```bat
:: What is the machine exposing to the network?
wintcp.exe list --filter "state:listen exclude:127." --sort lport --columns pid,process,lport,local

:: Which processes are using the network right now?
wintcp.exe list --group --traffic --sort nettotal --desc --limit 4 --columns pid,process,nettotal,rx,tx

:: What opened while I was away? (30 one-second snapshots)
wintcp.exe list --watch 1 --changes --event appear --count 30 --filter "proto:tcp state:estab"

:: Preview ending the owner of a port; nothing is changed
wintcp.exe kill --select "ipv4: local:port:49665" --dry-run

:: Silent predicate for scripts and Task Scheduler: exit 0 if anything matched
wintcp.exe list --filter "port:443" --quiet && echo someone-is-on-https

:: Open the optional local browser dashboard
wintcp.exe webui serve
```

`wintcp.exe help` prints the overview and `wintcp.exe help <command>` prints full help with examples. The [cookbook](docs/cookbook.md) walks through 36 worked recipes with real output; the two that measure the tool rather than the machine (the benchmark and the self-check, formerly recipes 31 and 32) live in the test binary.

## Requirements and permissions

| | |
|---|---|
| **Operating system** | Windows 10 or 11 recommended. Core connection listing uses APIs present since Windows 7. Everything built on `SIO_TCP_INFO` (no-admin traffic totals, connection age, per-socket rate, RTT/cwnd/retransmits) requires Windows 10 version 1703 or later; on older systems the traffic columns report that they need admin. Example output in these docs was captured on Windows 11. |
| **Dependencies** | None. No Visual C++ redistributable and no installer. |
| **Settings** | Native GUI/CLI settings use `HKCU\Software\WinTCP`; Web UI config and audit records use `%LOCALAPPDATA%\WinTCP\WebUi`. |
| **GeoIP** | Optional. Supply your own MaxMind-format `.mmdb` with `--db` (see below). |

### What needs administrator rights

Everything else runs as a standard user.

| Feature | Why |
|---|---|
| `close` | `SetTcpEntry` is a privileged call (and exists for IPv4 only). |
| `block` / `unblock` | They write Windows Firewall rules. |
| `capture` | It starts a packet capture. |
| ETW traffic counters | The NT Kernel Logger needs elevation. Without it, WinTCP falls back to a per-socket scan: TCP byte totals still work, but they are lifetime-of-socket rather than session totals, and UDP has no counters. |

Run unelevated, a privileged command prints a clear message and exits non-zero without partial effects. WinTCP never prompts for or attempts elevation on its own.

## GeoIP database

WinTCP ships no GeoIP database and never downloads one. That is deliberate twice over: MaxMind's licence does not permit redistributing its files, so there is nothing to bundle, and a network-inspection tool that quietly fetches several megabytes from a third party on every machine it runs on is a tool that phones home. You supply a `.mmdb` file you already have; every lookup runs against that local file, and nothing about your connections leaves the machine.

Without one, the `Country` column is empty and nothing else changes: no command fails, no filter silently widens, and a `country:` clause simply finds nothing.

### Getting a GeoLite2 database

`GeoLite2-Country.mmdb` is free; obtaining one just requires an account, which is why this section is instructions rather than a download link.

1. Create a free account at <https://www.maxmind.com/en/geolite2/signup>. The e-mail address you supply becomes the account's username.
2. Sign in and open **Account → Download Databases** (<https://www.maxmind.com/en/accounts/current/geoip/downloads>). The **Download Links** column offers **Get Permalink(s)** per edition: take `GeoLite2-Country`, authenticate the link with your account ID and license key, and unzip the result.
3. Keep the path — that is what `--db` takes.

The file is refreshed on a schedule, so treat it as something you re-fetch rather than something you install once. MaxMind's own [`geoipupdate`](https://github.com/maxmind/geoipupdate/releases) does that for you and ships a Windows zip: it reads a `GeoIP.conf` holding your `AccountID`, your `LicenseKey` and the `EditionIDs` you asked for (here `GeoLite2-Country`) and writes the downloaded database files into `DatabaseDirectory`. A pre-filled config is available from <https://www.maxmind.com/en/accounts/current/license-key/GeoIP.conf>, and on Windows `geoipupdate` looks in `%ProgramData%\MaxMind\GeoIPUpdate\GeoIP.conf` by default. Point `--db` at whichever directory you configured. Downloads are rate-limited: over an account's limit answers HTTP `429`, never a partial file.

### Attaching it

| Entry point | What you do |
|---|---|
| CLI | Pass `--db FILE` to `list`, `geoip info` or `geoip lookup`. It covers that run's printed rows only, so the next run needs it again. |
| GUI | **View → GeoIP database (.mmdb)...** opens a picker filtered to `*.mmdb`, and the column fills immediately rather than at the next refresh. The [GUI guide](docs/gui.md#geoip-in-the-window) covers what happens to that choice across a restart. |

### Autonomous systems (ASN)

The `Country` column also carries the **autonomous system** - the network an address belongs to - rendered alongside the country code as `US · AS15169 Google LLC`. That is a *second, different* MaxMind file: `GeoLite2-ASN.mmdb` has a different record shape from `GeoLite2-Country.mmdb`, so one `--db` cannot supply both.

| Entry point | What you do |
|---|---|
| CLI | Pass `--asn-db FILE` alongside (or instead of) `--db FILE`. The two are completely independent. |
| GUI | **View → ASN database (.mmdb)...** is a separate picker for the separate file. |

Either, both or neither works: the two are loaded independently and neither is required for the other. An address that no database covers leaves the country code alone rather than inventing one, and non-routable addresses never get an ASN at all.

`asn:` then filters on it, in both directions. A bare number is a threshold on the AS number, so `asn:15169` and the range `asn:15169-20000` work; anything else is a case-insensitive substring of the whole cell, so `asn:cloudflare` finds the operator by name. A bare `asn:` means "has an autonomous system", and a row with none never matches whatever you typed.

The full rule is in [filters.md](docs/filters.md).

### What the commands report

`geoip info --db FILE` prints one line:

```text
<database_type>, <records> records, <nodes> nodes, <bytes> bytes
```

The four fields are the file's own `database_type` metadata (for MaxMind's country file, `GeoLite2-Country`), its record count, its search-tree node count and its size on disk. It is the first thing to check when the column is empty, because an empty cell is otherwise ambiguous between "no database attached" and "attached, but no entry for this address".

`geoip lookup --db FILE <ip>` answers a single address with its two-letter code, or `-` when it has none.

**Pass a GeoLite2-ASN file and it answers with the autonomous system instead** - `AS13335 Cloudflare, Inc.` - because the verb answers whichever kind of database it was handed rather than only ever looking for a country record. An earlier build printed `-` for every address against an ASN file and gave no hint that the file had loaded perfectly well.

Exit codes are `0` for an answer, `2` for the command being used wrongly (`--db` missing, no address, or an argument that is not an IP), and `1` for a file that was there but would not load — truncated, not an MMDB at all, or declaring a record size this reader refuses. The message says which.

### Addresses that are never a country

Loopback, the RFC 1918 private ranges, CGNAT (`100.64/10`), link-local, the benchmarking and documentation blocks, multicast and the reserved/broadcast range are all rejected **before** the database is consulted. For IPv6 the same applies to `::1`, unique-local `fc00::/7`, link-local `fe80::/10`, `2001:db8::/32`, multicast and the discard-only range. Such a row reads `—` even with a database loaded, and even where a registry happens to hold a row for the range.

That is the difference worth keeping straight: **"not a country"** is a fact about the address, while **"country unknown"** means no database is attached.

### What an `.mmdb` file is

A MaxMind DB is one binary file laid out as `[search tree][16-byte separator][data section][marker][metadata]`, built to be memory-mapped rather than loaded into a database engine. The tree's branches spell out IP prefixes; the data section holds the records those branches point at; a marker then a metadata block close the file, describing what it is — node count, record size, `database_type`, build time. Looking an address up is a walk down the tree bit by bit followed by one offset read, which is why `--db` costs a memory map and a binary search per printed row and nothing else.

The tree stores two pointers per node at one of three widths the format allows: **24, 28 or 32 bits**. 28 is not a whole number of bytes — a node is 7 of them — and it is what essentially every real MaxMind database uses. All three load. Anything else is refused with the value the file declared, including the common `record_size = 4`, which is 4 *bytes* (that is 32 bits) written in the wrong unit; the refusal says so instead of reporting an impossible search tree.

### Also about GeoIP

- [CLI reference → `geoip`](docs/cli.md#geoip) — the two sub-commands and when `info` is the right first question.
- [Cookbook . recipe 12](docs/cookbook.md#12-country-watchdog-gated-on-the-answer) — a country filter gated as an automation predicate.
- [Filter language → `country:`](docs/filters.md#field-matches) — which switches each enrichment clause needs.

## Command-line overview

```text
Usage: wintcp.exe <command> [switches]
       wintcp.exe help <command>     full help + examples for one command
       wintcp.exe <command> --help   same as above
```

| Group | Commands | Purpose |
|---|---|---|
| Monitor | `list` (alias `conn`), `ps`, `top`, `stat` (alias `sys`), `details` | Snapshots of connections, processes and system rates. Single snapshot unless `--watch` is given. |
| Act | `kill`, `close`, `block`, `unblock`, `capture` | Change state. Require `--yes`; support `--dry-run`. |
| Audit | `blocks` | Count firewall rules WinTCP created. Read-only; no confirmation needed. |
| Library | `bookmark`, `preset`, `export`, `geoip` | Annotations, saved views, file export, GeoIP lookups. |
| Other | `version`, `help` | `version` reports what is available on this system and, if a feature is not, why. |

**Exit codes**

| Code | Meaning |
|---|---|
| `0` | Success. |
| `1` | Failure or empty result: a `--select` matched nothing, `list --quiet` matched nothing, target not found, or the operation failed. |
| `2` | Bad arguments, including a switch the command does not accept. |
| `3` | Refused: a mutating command was run without `--yes`. |

Full switch reference, output formats and the JSON conventions: the [CLI reference](docs/cli.md).

## The filter language

The GUI filter box, `list --filter`, `export --filter`, and the `--select` selectors of the action verbs share one grammar. Space means AND.

| You type | It means |
|---|---|
| `chrome` | Substring match over every field. |
| `port:443`, `pid:1000-2000`, `state:listen`, `process:svchost`, `proto:udp` | Field-restricted match; `pid:` and the port fields accept `a-b` ranges. |
| `local:port:80`, `remote:203.` | Restrict a port or address to one side of the connection. |
| `ipv6: state:listen` | Protocol or address-family prefix (`tcp:`, `udp:`, `ipv4:`, `ipv6:`). |
| `exclude:127.` | Negate the next term. |
| `note:"vendor api"` | Quoted value keeps its space and stays one term. |
| `cpu:12`, `mem:100-500`, `tx:1KB`, `rtt:100`, `duration:1h` | **Numeric thresholds** on live readings, not text matches. |

Thresholds have two properties worth knowing up front: a bare value on the byte-based fields (`mem`, `disk`, `rx`, `tx`, `net`) means **megabytes** (write `tx:1KB` for kilobytes), and a row whose reading could not be measured matches no threshold at all, so `mem:0` never selects a process that simply could not be read. The complete grammar is in the [filter language](docs/filters.md).

## Safety model

- **Confirmation is explicit.** `kill`, `close`, `block`, `unblock` and `capture` exit `3` without `--yes`. There is deliberately no `--force`: `--yes` means "I meant it", not "skip the checks".
- **Preview first.** `--dry-run` prints the plan, changes nothing, and exits `0`.
- **Selectors must be unambiguous.** `--select` resolves to exactly one live row or the command exits `1` naming the match count. It will not guess.
- **PID reuse is handled.** Before ending a process, its PID is re-validated against the process creation time, so a recycled PID is refused rather than killing an unrelated program. PID 0 and PID 4 are always refused.
- **Bad targets and refusals are distinct.** A malformed command is exit `2`; a well-formed but unconfirmed one is exit `3`. A script can tell them apart.
- **No self-elevation, no partial effects.** Privileged verbs fail cleanly when unelevated.
- **Small footprint.** The only registry location written is `HKCU\Software\WinTCP`. Firewall rules created by `block` carry a WinTCP tag so `blocks` can count them and `unblock` can remove exactly those.

## How it compares with the built-in tools

Every recipe in the cookbook answers a question that cannot be answered with one built-in command (`netstat`, `tasklist`, `taskkill`, `Get-NetTCPConnection`, `Get-Process`, `netsh`, `pktmon`) or with an obvious two- or three-step pipeline.

| Question | Built-in route | WinTCP |
|---|---|---|
| Which process owns port 445, and where is its executable? | `netstat -ano` gives a PID only; `netstat -b` needs admin and gives a service name. | `list --filter "state:listen lport:445" --columns process,path,pid,local,state` |
| End whatever holds a port, safely | `netstat -ano \| findstr :PORT \| taskkill /PID …` is racy: a PID can be recycled between steps. | `kill --select … --yes` resolves and re-validates in one step |
| Close one connection, keep the process | `SetTcpEntry` code or a third-party tool. | `close --select … --yes` (admin, IPv4) |
| Per-process bandwidth, from a script, no admin | Resource Monitor is GUI-only; ETW needs admin. | `list --group --traffic --sort nettotal --desc` |
| What connections appeared in the last 30 seconds? | Poll and diff by hand. | `list --watch 1 --changes --event appear --count 30` |
| RTT, congestion window and retransmits per connection | Not shown by `netstat` or `Get-NetTCPConnection`. | `list --traffic --sort rtt --desc --columns process,remote,rport,rtt,minrtt,cwnd,retrans` |
| Capture one process's connection | `pktmon` filters by address and port, not by process. | `capture --select … --secs 8 --yes` |
| Read one TCP stream's bytes | Nothing in the built-in tools reassembles a stream. | `capture --select . --secs 8 --text --yes` |
| Read a connection's TLS handshake | `netstat` shows nothing about TLS; `pktmon` shows bytes, not meaning. | `capture --select . --secs 8 --yes`, and read the `tls:` lines |
| Keep a capture to open in Wireshark | Same, plus a manual conversion step. | `capture --select . --secs 8 --out c:\tmp\s.pcapng --yes` |

## Documentation

| Document | Contents |
|---|---|
| [GUI guide](docs/gui.md) | Window layout, columns, row highlighting, Details dialog, export, change log, performance graphs, tray, theming and DPI. |
| [Web UI guide](docs/webui.md) | Local service operation, 40-template readiness, configuration, audit logs, monitor limits, and the confirmed firewall workflow. |
| [CLI reference](docs/cli.md) | Commands, switches, exit codes, output formats, JSON conventions, switch dependencies, column reference. |
| [Filter language](docs/filters.md) | The full grammar, units, and the rules that keep filters from returning wrong answers silently. |
| [Traffic counters](docs/traffic.md) | ETW versus the per-socket fallback, what each can and cannot measure, status-bar states and limits. |
| [Cookbook](docs/cookbook.md) | 36 worked recipes with real output and an explanation of every load-bearing switch. |
| [Architecture](docs/architecture.md) | Design principles, concurrency model, row identity, source layout. |

## Building from source

Requires Visual Studio 2022 or later with the C++ workload (MSVC and the Windows 10/11 SDK). No admin rights, package manager or third-party dependencies are needed.

```bat
cmake -B build -A x64 && cmake --build build --config Release
```

A Visual Studio solution (`wintcp.sln`) and project (`wintcp\wintcp.vcxproj`) are also provided. All build paths compile with warnings as errors.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Traffic cells show `—` for some processes | The process is UDP-only (the fallback reads TCP only), is protected, or one of its sockets did not answer the scan. Run elevated for ETW totals. `—` means *unknown*; it is never a hidden zero. |
| Status bar says `TCP only — UDP needs admin` | Expected: the unprivileged fallback is active. Run elevated to include UDP. |
| `Traffic off — needs admin` | No source can run. This is the case on systems without `SIO_TCP_INFO` (before Windows 10 1703). |
| `host:` filter or `host` column is empty in the CLI | Reverse DNS only runs with `--dns`. Bound it with `--limit`; it is slow. |
| `country:` filter or column is empty | Pass `--db FILE`. Non-routable addresses never get a country. |
| `asn:` filter matches nothing, or the country cell never shows an ASN | Pass `--asn-db FILE` - a GeoLite2-ASN file, which is a *different* product from the country one. A row with no ASN never matches, whatever the value. |
| `tx:`, `rx:`, `duration:`, `rtt:` filters match nothing | Add `--traffic`. Rows that could not be measured match no threshold. |
| `duration` reads `0s` everywhere | Without `--traffic` there is no age source. |
| `bandwidth` or `procspeed` show `—` on the first tick | A rate is the difference of two samples. Use `--watch N --count 2` or more. |
| `kill --select … matches 2 rows` | A dual-stack listener is one socket reported once per address family. Add `ipv4:` or `ipv6:` to the selector. |
| `close` refuses a row | The Windows API behind it has no IPv6 form, and it needs admin. |
| Exit code 2 and "not a switch of this command" | Intentional. Run `wintcp.exe help <command>` for the switches that command honours. |
| `export` refuses `--limit`, or refuses a column with `--group` | A file must not silently hold a partial view or a header that promises values the rows do not carry. See the [CLI reference](docs/cli.md#export). |
| A feature seems missing on an unusual Windows install | Run `wintcp.exe version`; it lists any delay-loaded library that was unavailable and what that disables. |

## Known limitations

- The unprivileged fallback reads **TCP only**. UDP sockets expose no byte counters without ETW.
- The fallback misses sockets that open and close entirely between two refreshes. Long-lived connections carry their full history, including time before WinTCP started.
- ETW totals begin when the session starts; fallback totals are lifetime-of-socket. ETW totals are best-effort under extreme load.
- A socket that does not answer `SIO_TCP_INFO` is skipped for the pass and not retried. Its columns stay `—`, and the GUI reports how many sockets were affected. See [Traffic counters](docs/traffic.md#stalled-sockets).
- Change feeds are polling-based: the `--watch` interval is the sensitivity, and a socket that opens and closes inside one interval is never seen.
- `close` supports IPv4 only. The Windows `SetTcpEntry` API has no IPv6 form, so neither the GUI nor the CLI can tear down an IPv6 connection. The GUI greys *Close connection* on IPv6 rows (label: "Close connection (IPv6 - use Block instead...)"); `block` still works family-agnostically via firewall rules and is the supported way to stop an IPv6 conversation.
- Per-connection rates exist only where a single socket's own counters are available. A per-process total is never divided across its connections to fake one.

## Contributing

Bug reports and pull requests are welcome. Before submitting a change, build with warnings as errors and run the unit tests (`wintcp-dev.exe unit`). If you add or change a documented command, update `the documented-command list` as well.

## License

Original sources: a from-scratch native Win32 application with no third-party dependencies.

Released under the **Apache License, Version 2.0**. The full text is in [LICENSE](LICENSE); it permits use, modification and redistribution, and includes an explicit patent grant.

## Acknowledgements

WinTCP follows the interface ideas of Sysinternals TCPView (and its `tcpvcon` command-line companion) and NirSoft CurrPorts. GeoIP lookups read the MaxMind DB (`.mmdb`) format.

## Web UI v2

The Web UI has been upgraded to a multi-page control room with:

- Collapsible grouped sidebar (Monitor, Respond, System)
- Top bar with breadcrumb, command palette (Ctrl+K), theme and density toggles
- Pages: Overview, Performance, Processes, Network, Map, Automations, System, Settings
- Light and dark themes with shadcn design tokens
- Real-time charts (uPlot + ECharts)
- Virtualised tables handling 10,000+ rows
- Metrics collector with PDH (CPU, memory, disk, network, GPU)

See [docs/webui.md](docs/webui.md) for the full guide and
[docs/webui-design.md](docs/webui-design.md) for the design system.
