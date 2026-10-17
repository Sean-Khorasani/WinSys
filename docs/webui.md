# Local Web UI and automation guide

The Web UI is an optional, local-only dashboard served by `wintcp.exe`. The CLI remains the authoritative command engine; this page describes the browser front end, its current monitor coverage, and the safety limits that apply.

## Start and stop

### Foreground

Run from the directory containing the WinTCP binary and sibling `webui` asset folder:

```bat
wintcp.exe webui serve
```

WinTCP binds an ephemeral port on **127.0.0.1 only**, prints the exact local URL, and asks Windows to open the default browser. If the browser does not open, copy the printed URL. The foreground process stops on **Ctrl+C**.

### Background batch manager

Keep `webui-service.bat` and its `webui-service.ps1` helper together in the repository root. Build `wintcp.exe`, then use:

```bat
webui-service.bat start
webui-service.bat status
webui-service.bat stop
```

`start` launches the built `build\wintcp.exe` hidden, waits for the loopback URL, and does not open a browser. It defaults to **DEBUG**; an optional level can be selected with `start INFO`, `start WARN`, or `start ERROR`. The manager stores the PID, executable path, and process start time under `%LOCALAPPDATA%\WinTCP\WebUi`, verifies that identity before reporting or stopping it, and signals a PID-scoped Windows event for graceful shutdown. It does not install a Windows service, scheduled task, firewall rule, or startup entry. The dashboard's monitors evaluate snapshots only while the browser page is open.

The `webui` folder is a runtime dependency of this optional feature. The build stages it beside `wintcp.exe`. Copy the executable and that folder together if moving a build. The native CLI and GUI do not require the browser assets.

The background manager writes timestamped UTC diagnostics to `%LOCALAPPDATA%\WinTCP\WebUi\webui.log`. **DEBUG** is the default and includes HTTP method, route, and status; request bodies, session tokens, and authorization headers are not logged. The log rotates at 2 MiB to `.1` and `.2`.

## What is implemented

The dashboard has three views:

- **Overview:** current connection rows, process/PID counts, established TCP count, sampler status, and per-socket counter coverage. Filter and sort the full snapshot, then export all matching rows to CSV. A failed refresh keeps the last good rows visible but labels them stale.
- **Automations:** a searchable catalog of 40 local CLI playbooks, separate browser-side monitor rules, thresholds and recent events, plus a script workbench for authoring, running, debugging, copying, importing, exporting and removing local scripts.
- **Configuration:** a configurable 2/5/10/30-second page refresh, opt-in browser desktop alerts, local storage explanation, and the persisted audit trail.

### Connection filtering, sorting, and export

The connection search matches process, PID, protocol, local/remote address and port, and state. Sort by process, PID, protocol, endpoint, state, or per-socket RX/TX byte count; missing counters stay at the bottom rather than being interpreted as zero. **Export CSV** writes every row matching the current filter, even when the on-screen table is capped at 250 rows. The file includes the snapshot UTC timestamp and exact byte counters when the API supplies them. Missing counters are blank. CSV quoting and formula-prefix neutralization make values safer to open in spreadsheet software. The export is a point-in-time snapshot, not a packet capture or a continuous log.

### Browser desktop alerts and freshness

Desktop alerts are off by default. In Configuration, choose **Enable browser notifications** to request permission from the browser; no permission prompt is triggered on page load. The separate **Show desktop alerts** preference can be switched off at any time. Browser toasts contain a generic message only, not process names, IP addresses, or ports; the dashboard and audit view retain the detailed event. Delivery is capped at three notifications per minute, with suppressed events counted in the next allowed summary. Alerts are best-effort and monitors still run only while the dashboard page is open. Unsupported browsers, insecure contexts, and denied permissions are reported in the settings panel rather than silently treated as enabled.

The service pill announces service-state changes to assistive technology without taking focus; the frequently refreshed timestamp remains visible without repeatedly interrupting screen-reader users. After a failed refresh, the dashboard retains the last successful snapshot for inspection, changes the service state to **Stale snapshot**, and shows the last-good timestamp with the failure. A stale row set is not presented as live data.

Rules are **disabled when first added**. Active monitors run in the browser tab while it remains open. The current executable monitor types are:

| Template | Current behavior | Default |
|---|---|---|
| T01 — Remote peer exceeds 10 GB in a rolling hour | Sum observed per-socket TCP RX+TX byte deltas by remote IP over a rolling 3,600-second window. Uses decimal GB (10,000,000,000 bytes). | Notify; a user may separately select **Offer confirmed block**. |
| T06 — New remote peer appears | Notify when an established remote IP first appears after the monitor is enabled. The current snapshot seeds the baseline. | Notify |
| T07 — New listening socket appears | Notify when a new TCP listener identity is observed after enablement. | Notify |
| T08 — Wildcard-bound listener detected | Count current TCP listeners bound to `0.0.0.0`, `::` (including scoped or bracketed forms), or `*`. Loopback-only binds do not match. The alert fires once while the count meets the configured limit and rearms after the count falls below it. | Notify; default limit 1 |
| T11 — Process opens too many listeners | Group current TCP listeners by PID and compare distinct local endpoint/port count with the threshold. | Notify; default threshold 10 |
| T12 — Process fans out to many remote peers | Group established connections by PID and compare distinct remote IP count with the threshold. | Notify; default threshold 50 |
| T29 — Round-trip latency exceeds threshold | Notify when a live RTT measurement exceeds the threshold. Rows without a live RTT are skipped. | Notify; default threshold 250 ms |

The catalog marks the remaining **33 templates** **PREPARED / capability pending** and does not let them be activated. They are product-ready scenarios, not claims that telemetry or evaluators for all 40 have shipped. The 40 entries and their data requirements are defined in [`wintcp/webui/templates.json`](../wintcp/webui/templates.json). This distinction is deliberate: missing data is not treated as zero, unsigned is not treated as malicious, and a process-wide counter is not attributed to an individual peer.

### Automation script workbench

Every one of the 40 built-in templates now contains editable **WinTCP Script** source that invokes documented `wintcp.exe` commands. Opening a built-in fills the editor; changing and saving it creates a user-managed copy. Users can create custom scripts, edit saved copies, copy/paste source, import/export `.wtscript` or `.txt` files, search the libraries, and remove their own copies. Removing a script never removes a monitor rule. A template's continuous monitor readiness is separate: 7 templates have browser-side evaluators; the other 33 are on-demand CLI playbooks, not claims of a background detector.

Scripts use a deliberately small line-oriented language. `let name = <verb> [arguments]` runs a CLI command and stores its result; `run <verb> [arguments]` stores its result as `last`; `set name = value` assigns text; `print` writes an interpolated line; and `if / else / end` supports numeric `exitCode` comparisons and `stdout`/`stderr contains "text"` tests. `${name}`, `${name.stdout}`, `${name.stderr}`, `${name.exitCode}`, and `${name.durationMs}` can be used in later non-sensitive arguments or printed text. Quoted CLI arguments preserve spaces. A typical script is:

```text
# WinTCP Script v1
let rows = list --format json --filter "state:estab" --limit 25
if rows.exitCode == 0
  print "Captured ${rows.stdout}"
else
  print "CLI error: ${rows.stderr}"
end
```

Grammar, in full — every construct the parser accepts:

```text
line        := comment | blank | if-line | 'else' | 'end' | statement
comment     := '#' <rest of line>          (a # inside quotes is literal text)
if-line     := 'if' condition
condition   := NAME '.exitCode' OP NUMBER
             | NAME '.stdout'  'contains' "TEXT"
             | NAME '.stderr'  'contains' "TEXT"
statement   := 'let' NAME '=' command      (result stored under NAME)
             | 'run' command               (result stored as 'last')
             | 'set' NAME '=' value        (string assignment)
             | 'print' value
             | command                     (result discarded)
command     := [('wintcp.exe' | 'wintcp')] VERB [ARG ...]
value       := "double-quoted" | 'single-quoted' | plain text   (interpolated)
interpolation := '${' NAME ['.' ('exitCode'|'stdout'|'stderr'|'durationMs')] '}'
OP          := '==' | '!=' | '>' | '<' | '>=' | '<='
```

`if` blocks nest with `else` / `end`; indentation is cosmetic, not significant. A
quoted argument (`"state:estab"`) keeps its spaces; `\` escapes a quote or a
backslash inside one.

The parser accepts at most 8 KiB of UTF-8, 200 lines, 100 statements, and 8 nested `if` blocks. The entire script is parsed before its first command. The runtime has **no shell, PowerShell, JavaScript evaluation, pipeline/redirection, loop, external process verb, cloud request, or telemetry**. Each call is passed as a separate argument vector to the sibling `wintcp.exe`; the server caps each command at 64 arguments / 2,048 bytes per argument, output at 64 KiB per stream, and execution at 30 seconds. Scripted `--watch` commands must include `--count` and fit within 12 seconds; captures are capped at 15 seconds. The UI caps combined displayed output at 256,000 characters.

Run results show the executed command, duration, exit code, stdout/stderr, a step trace, and current variable values. Nonzero exit codes remain available to `if` branches; they do not silently become success. A sensitive command with variable-substituted arguments is rejected so its exact target is visible before confirmation. Before a script containing sensitive actions runs, the UI lists the exact command vectors for one explicit confirmation. Each sensitive invocation then requires a separate 30-second, single-use server permit bound to the exact verb and argument list. The server writes a sensitive-action attempt before starting the child and records its exit code/timeout afterward; an unavailable write-ahead audit prevents that action from starting. Read-only scripts do not need a confirmation.

Saved scripts are stored with monitor configuration in `%LOCALAPPDATA%\WinTCP\WebUi\config.json`: at most 40 copies, 8 KiB each, 46,000 bytes combined script text, and a 60,000-byte browser-side total configuration limit (the server's JSON request bound is 64 KiB). Earlier declarative `wintcp-automation` JSON drafts are preserved as inert comments plus a migration note; they are **not executed**. Large old drafts may be truncated to keep the migrated source within its size bound. Version-1 monitor rules are migrated separately and remain separate from scripts.

### Traffic coverage and threshold semantics

T01 requires the non-admin per-socket TCP sampler to report every current TCP row with readable counters and no reported timeout, unreadable socket, or scan failure. On a degraded snapshot it **clears the current rolling window and counter baseline**, then waits for fresh complete snapshots; it does not fill gaps with zero or resume a possibly understated total. Its first complete sample establishes a baseline, so only observed counter deltas after that point are counted. The value is an observation-window estimate, not wire-level accounting. UDP is not included.

The API carries the 64-bit byte values both as ordinary JSON numbers for inspection and as decimal strings for exact browser arithmetic. This avoids JavaScript's 53-bit integer precision limit for long-lived sockets.

## Human-confirmed firewall response

The traffic monitor never changes the firewall by itself. If T01 is set to **Offer confirmed block**, crossing the threshold creates an event with a **Preview block** button. The server:

1. Accepts only a literal IPv4/IPv6 address and the fixed TCP scope.
2. Calls the existing typed WinTCP firewall-rule planner in dry-run mode and returns the plan.
3. Creates a random, one-use preview token that expires after 30 seconds.
4. Requires the browser's explicit confirmation after showing the plan.
5. Revalidates the request, records a write-ahead audit event, and calls the shared `CmdRule` implementation.

The traffic total is grouped by remote IP, not port, so the preview is for **all outbound TCP remote ports at that address**. It can interrupt network access and normally requires an elevated process; WinTCP does not elevate itself. If the action is refused or the user cancels, no firewall change is made. The control is available only on a T01 threshold event, not on unrelated alerts.

## Local API and storage

The loopback server serves same-origin static assets and these routes:

| Method and path | Purpose |
|---|---|
| `GET /api/health` | Local service readiness. |
| `GET /api/connections` | A live snapshot from the shared `CmdListInto` / `ConnectionStore` path, plus sampler coverage metadata. No shell command text is invoked. |
| `GET /api/templates` | The shipped versioned catalog. |
| `GET /api/config` | Current local configuration. First run, a missing file, or an unreadable/corrupt file recovers to the shipped config.default.json defaults and logs a warning (never an HTTP 500). |
| `POST /api/config` | Persist a bounded JSON object from the same-origin UI. |
| `POST /api/cli/authorize` | Validate a sensitive command vector and issue an exact-vector, 30-second, one-use permit after explicit UI confirmation. |
| `POST /api/cli/run` | Start the sibling `wintcp.exe` without a shell; return bounded output, exit status, duration, and timeout/truncation flags. |
| `GET /api/audit` | Return up to the latest 1000 records (`kAuditRetention`); optional `q` filters by case-insensitive substring; `format=ndjson` streams matched/redacted records for download; session tokens are masked (`<redacted>`) before return. |
| `POST /api/audit` | Append one bounded event record. |
| `POST /api/block/preview` | Produce a dry-run plan and one-use confirmation token. |
| `POST /api/block/commit` | Consume an unexpired preview token and attempt the typed firewall action. |

Configuration and logs are stored per user under `%LOCALAPPDATA%\WinTCP\WebUi\`:

- `config.json` — page refresh preference, active monitor rules, and up to 40 managed WinTCP Script source files; atomic replacement; server maximum 64 KiB. A config that is missing or no longer a valid JSON object is recovered to the shipped defaults and logged (corruption recovery).
- `audit.ndjson` — timestamped configuration, alert, and firewall events; rotates at 2 MiB to `.1` and `.2`.
- `webui.log` — server and manager diagnostics; DEBUG by default; rotates at 2 MiB to `.1` and `.2`.
- `webui-service.pid` — the manager's PID, executable path, and process start time; removed after clean shutdown.

The audit view and API return the latest 1000 records (`kAuditRetention`), optionally filtered by a case-insensitive `q` substring matched against each record via the Dashboard search box (server-side). Session tokens are not stored in the configuration, audit file, or diagnostic log, and are masked as `<redacted>` server-side before any audit record is returned. Audit event writes are bounded, and a firewall action is not attempted if its write-ahead record cannot be created; the outcome is appended after the action when possible.

### Sensitive commands and script bounds

A script request runs a **sibling `wintcp.exe`** with separate arguments (never a shell). Two
classes of command are treated as **sensitive** and each requires a one-use, exact-vector,
30-second permit issued by `/api/cli/authorize` after explicit confirmation:

- any of the act verbs `kill`, `close`, `block`, `unblock`, `capture` when **not** `--dry-run`;
- any command carrying `--yes` / `-y` / `--force`;
- `export`, or any command carrying `--out`;
- `bookmark` / `preset` with a mutating subverb (`add`, `remove`, `delete`, `note`, `colour`,
  `save`, `import`);
- `alert` carrying a state-changing switch (`--enable`, `--disable`, `--on-*` / `--off-*`,
  `--bps-warn`, `--bps-critical`, `--connections`, `--rule-*`).

Everything else runs without a permit. The server also enforces hard bounds regardless of
permit state, so a script can neither hang the service nor starve it:

| Bound | Value |
|---|---|
| CLI arguments per request | ≤ 64 |
| Bytes per argument | ≤ 2048 |
| Total command characters | ≤ 8192 |
| Captured stdout+stderr | ≤ 64 KiB (truncation flagged) |
| CLI wall-clock | ≤ 30 s, then the child is terminated |
| `--watch` scripts | `--count` required, `--count` ≤ 20, and `count × interval` ≤ 12 s |
| `capture` duration in a script | ≤ 15 s |
| Request body / header / asset sizes | 64 KiB / 16 KiB / 1 MiB |
| JSON nesting depth accepted | 32 |
| Audit trail entries served | most recent 1000 valid entries (raw log file capped at 2 MiB) |
| `webui` verb from a script | refused (a script cannot start another service) |

## Security boundaries

- The listener binds to IPv4 loopback only. It rejects non-loopback clients, unexpected `Host`, and unexpected `Origin` values.
- Each process creates a cryptographically random 256-bit session token. State-changing API calls require both the exact same-origin `Origin` and the `X-WinTCP-Token` header. No CORS permission is granted.
- Firewall preview/commit uses a separate one-time nonce; a commit cannot be replayed or substituted for another address/port scope.
- CLI requests never pass through `cmd.exe` or a shell. The server accepts bounded form fields, validates the sibling executable and argument vector, enforces runtime/output/watch limits, and rejects attempts to start another Web UI service.
- A sensitive CLI permit is bound server-side to the exact verb and arguments and consumed once. The browser's confirmation is not accepted as a general-purpose token; the server separately checks the mutation token, origin, permit expiry, command identity, and audit write.
- Header/body and asset sizes are bounded; unsupported transfer encodings and content types are rejected; request read/write timeouts are set; connections close after one response.
- Responses include `nosniff`, frame denial, a restrictive Content Security Policy, no-store caching, and no referrer policy. UI assets make no external requests.
- The server is single-threaded and serializes requests. The snapshot call can take longer on machines with slow/unreadable sockets; the client surfaces errors rather than claiming a healthy sample.

This is a local management interface, not a LAN service. Do not expose its port with a proxy or change the binding without a separate authentication, transport, and authorization design.

## Requirements and acceptance criteria

| Requirement | Current acceptance evidence |
|---|---|
| Keep CLI and GUI independent | `wintcp.exe` is console-only and no-argument invocation prints help; `wintcp-gui.exe` contains the GUI and does not locate or start its sibling. |
| Preserve the shared model | Both native front ends use the same shared command and connection-model sources; their entry points and PE subsystems are separate. |
| Keep one shared model | `/api/connections` uses `CmdListInto` and `ConnectionStore` directly; the snapshot path uses no subprocess, `netstat` scraping, or duplicate command logic. Script requests separately run the sibling CLI. |
| Keep local configuration and logs | Configuration, audit and diagnostic logs, and the manager PID record remain under the current user's LocalAppData. |
| Prepare 40 automation concepts | 40 unique template IDs retain their monitor capability requirements and each includes a local CLI playbook. Only 7 have continuous browser-side monitor evaluators; the other 33 are not represented as background detectors. |
| Manage automation content | All 40 scripts can be opened, edited into a managed copy, validated, copied/pasted, imported/exported as source, searched, run, debugged, and removed. Scripts and monitor rules are separate. |
| Run and debug local scripts | A bounded parser executes commands through the sibling CLI with if/else, variable assignment/interpolation, step trace, variable inspection, and bounded stdout/stderr; no shell or cloud service is involved. |
| Make enforcement explicit | T01 is notify-only by default; address-wide TCP blocking requires a shown dry-run plan, browser confirmation, an expiring one-time token, and audit writes. |

## Known first-release limitations and next steps

- Only **7 of 40** templates have a continuous monitor evaluator. All 40 have an on-demand CLI playbook, but that does not provide the missing telemetry or turn the other 33 scenarios into continuous monitors.
- Rule evaluation is tab-bound, not a persistent background monitor. Closing the page stops evaluation. The foreground server exits with Ctrl+C; use the batch manager's `stop` command in background mode.
- Monitor evaluation and optional browser desktop notifications require the dashboard page to remain open. There is no independent background evaluator, native Windows notification service, email, or external webhook.
- The script language intentionally has no loops, timers, or scheduled/background execution. Its conditional grammar is limited to CLI exit-code comparisons and stdout/stderr substring checks; richer event correlation, cancellation, and a persistent job queue remain future work.
- The current Web UI is not yet at native-GUI feature parity. Remaining work includes full process-tree views, full column-profile and change-log controls, GeoIP/ASN/DNS/ETW capability controls, historical graphs/time ranges, richer process detail/file-location workflows, and any native typed action without a documented browser replacement. Current implemented browser equivalents include saved views, bookmarks/notes, sortable/visible columns, grouping/freeze, connection details, selected-row copy/export, firewall inventory/confirmation, audit, and local CLI playbooks.
- Address-wide firewall response applies to outbound TCP only. It does not block UDP, close a live connection, or terminate a process.
- The batch manager backgrounds the HTTP server but does not install a native Windows service or startup entry. The CLI script adapter uses the sibling `wintcp.exe`; copying the Web UI executable to another folder without that CLI sibling disables script execution, while the separate `wintcp-gui.exe` remains independent.

See [`gui-webui-design.md`](gui-webui-design.md) for the product requirement analysis and launch architecture, and [CLI reference](cli.md) for command syntax.
