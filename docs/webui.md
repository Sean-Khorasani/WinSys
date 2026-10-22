# Web UI guide

The optional Web UI is a local dashboard served by `wintcp.exe`. It uses the same connection and process data as the native applications and keeps its assets on the machine. The server listens on `127.0.0.1`; it is not intended to be exposed to a network.

## Start and stop

Run the foreground server from the directory containing `wintcp.exe` and its sibling `webui` folder:

```bat
wintcp.exe webui serve
```

WinTCP prints a loopback URL and opens the default browser. Press **Ctrl+C** in the terminal to stop it. To suppress the browser launch, set `WINTCP_WEBUI_OPEN_BROWSER=0` before running the command.

For background operation, keep `webui-service.bat`, `webui-service.ps1`, `wintcp.exe`, and the `webui` folder together, then run:

```bat
webui-service.bat start
webui-service.bat status
webui-service.bat stop
```

The manager starts the process without opening a browser. It defaults to port `45455`; `start` also accepts a log level and port, for example `webui-service.bat start INFO 45456`. Pass port `0` to request an ephemeral port. The manager is a background-process helper, not a Windows service or startup task. Logs and manager state are stored under `%LOCALAPPDATA%\WinTCP\WebUi`.

The Web UI needs the `webui` assets beside `wintcp.exe`. The native CLI and GUI work without that folder.

To store dashboard configuration, audit events and logs in another location,
set `WINTCP_WEBUI_DATA_DIR` to an absolute writable directory before starting the
server. Leave it unset to use `%LOCALAPPDATA%\WinTCP\WebUi`.

## Pages

| Page | What it shows |
|---|---|
| **Overview** | Current CPU, memory, disk, network, connection, and process summaries with recent trends. |
| **Performance** | Per-core CPU readings and CPU, memory, disk, and network history where the system provides it. Includes an evidence-export button for troubleshooting. |
| **Processes** | Process table and parent/child tree, with a treemap sized by working set or CPU share. |
| **Network** | Live connections, listening sockets, retained closed history, blocked-peer, and country-flow views. |
| **Map** | Interactive country map with a globe/2D projection switch and connection markers. |
| **Automations** | CLI playbooks, local scripts, and recent events. |
| **Firewall Rules** | A local inventory of rules returned by Windows Firewall COM, supplemented by readable WinTCP-owned rules. |
| **System** | Operating-system, processor, memory, and capability information. |
| **Settings** | Theme, display preferences, refresh interval, GeoIP paths, and audit history. |

Use the sidebar to navigate. **Ctrl+K** opens the command palette. **Pause** holds the current snapshot while inspecting it; **Resume** restarts polling. The refresh button requests one immediate sample even while paused, without resuming automatic updates. The status shows the age of a held snapshot and identifies unavailable data sources. The browser also pauses background work while its tab is hidden.

## Inspect and copy connections

Select a connection or process row to open its inspector. On wide screens it
docks beside the table; on narrow screens it opens as an in-bounds modal. Use
the width control to resize the docked inspector; its width is remembered
separately for Network and Processes in this browser profile. Inspectors group
identity, endpoint, activity, and related-rule information, and provide a copy
button beside values that can be copied precisely. Action buttons lead to the
existing reviewed workflows rather than applying destructive changes directly.

**Hold values** keeps the captured details visible while samples continue.
The inspector reports newer values or a vanished item without silently
switching to a different connection or process. **Resume live** follows only
the same stable connection identity or process instance; if that identity is
unavailable, live following is disabled. Closing an inspector with **Escape**
or its close button restores focus to the row that opened it. Leaving the page
closes its inspector.

Right-click a row in **Network**, press **Shift+F10** on a focused row, or use its
**Connection actions** button. The menu can copy a remote IP without its port,
the resolved hostname, an endpoint including its port, either port, the PID,
the executable path, a connection summary, or the row's visible columns as
tab-separated values (TSV), in their current order and excluding the Actions
control. The selection bar uses the same visible columns. IPv6 endpoints use brackets;
copying an IP preserves the address itself, including a scope ID when present.
Copied rows retain the displayed column order and header names. UDP endpoints
without a remote peer show `*` for that port, and retained rows are marked
`Closed (retained history)` in the copied state column.
Unavailable values are disabled with an explanation. Use the arrow keys to
move through the menu and **Escape** to dismiss it.

In the Connections and Closed history tables, **Ctrl/Command-click** toggles a row,
**Shift-click** selects a visible range, and the **Selection** group keeps
**Select all shown** beside **Clear selection**. **Ctrl+A** selects all shown only
when the table has keyboard focus;
otherwise it performs the browser's normal text selection.
When rows are selected, actions appear in separate **Copy**, **Export**, and
**Evidence** groups. They can copy deduplicated remote IPs, resolved hostnames,
endpoints, or all selected rows as TSV, and download current selected rows as TSV
or JSON using the visible column order. Text fields containing tabs, quotes, or
line breaks are escaped for spreadsheet import; unresolved hostnames and unknown
values remain blank. Sorting and refresh keep selection attached to stable
connection identities. Rows outside the filter are counted separately from rows
that are no longer current; copy actions use last-seen values, while export omits
stale rows.
Bulk close and firewall changes are not offered; use a row's reviewed action menu.

The Network filter accepts space-separated terms combined with AND. Bare words
search the supported visible text fields: process name, executable path, service,
local/remote address, state, hostname, protocol, country, and address family.
Use `pid:`, `port:`, `lport:`, or `rport:` with a number or range, for example
`process:"Program Files" pid:100-200 remote:2001:db8::1 remote:port:443`.
Text fields include `process:`, `path:`, `service:`, `host:`, `local:`,
`remote:`, `state:`, `proto:`, `country:`, and `family:`; for example,
`proto:udp state:listen`, `proto:ipv6`, or `family:ipv6`. `local:port:` and `remote:port:`
scope a port range to one endpoint. Prefix a term with `exclude:` to omit
matches. Unsupported fields, malformed ranges, and unclosed quotes are reported
below the filter instead of being treated as ordinary text. This is a supported
browser subset of the [CLI/GUI filter language](filters.md); advanced fields such
as signatures, metrics, ASN, and bookmarks are not supported in this filter.

Sortable headers start ascending and toggle direction. Process names use
case-insensitive natural order, numeric fields compare as numbers, and endpoint
addresses sort by IP family, address bytes, then IPv6 scope ID. TCP states use a
fixed connection-state order. Unavailable values stay at the bottom in either
direction.

Use **Columns** above the Processes, Connections, or Firewall Rules table to hide
optional fields, move columns earlier or later, or adjust their relative width. **Essentials**
provides a compact preset; **All columns** and **Default** restore broader or
original layouts. Process/name identity and row actions remain visible. Layouts
are saved with the local dashboard configuration and restored when the page is
reopened.

On the Network page, open **Manage views** and use **Name this view** and
**Save view** to keep up to 30 named presets. A preset stores the current text and structured filters, sort,
Network tab, and that tab's table layout; loading it reapplies those settings to
the live snapshot. Saving another view with the same name updates it, and
**Delete view** removes the selected preset. Presets do not save sampled rows,
scroll position, or row selection.

**Recent views** keeps up to ten distinct Network states in this browser profile:
the query, structured filters, sort, tab, and current table layout. This history
is stored in browser-local storage rather than the WinTCP server configuration.
Use **Clear recent** to remove it; named presets are unaffected.

Open **Compare endpoints…** above the connection table to save the current
filtered endpoint set as a browser-local baseline. **Compare with baseline** then
lists endpoint identities added since that capture and identities no longer in the
current filtered view. This is a point-in-time identity comparison, not complete
connection history or a reachability test. **Clear baseline** removes only this
browser-local comparison data; it does not affect named views or live endpoints.

**Block remote peer** is a reviewed, outbound TCP firewall rule for the literal
remote IP and port; it is not application-scoped and does not close the current
connection. UDP rows cannot use this TCP-only action. **Close and block this
connection** requests separate, fresh previews for both operations, creates the
firewall rule first, then attempts the captured connection close. The review
reports each result independently: a firewall failure does not suppress the
close attempt, and a close failure does not undo a created rule. On successful
rule creation, **Open firewall rule** selects the exact deterministic rule name
returned by the server in the inventory. If the rule is not currently visible,
the inventory explains its best-effort limitation instead of substituting a
different matching rule. This is not an atomic transaction; inspect the result
before deciding what to do next.

**Close this connection** opens a review dialog for the captured row. The server
requires an exact connection ID, endpoint tuple, and known process lifetime;
it refreshes the connection table again before acting. Only an established IPv4
TCP connection in an elevated WinTCP process can be closed. UDP, IPv6, listeners,
retained history, unknown process lifetimes, stale rows, and non-elevated sessions
remain unavailable with a reason. Closing one endpoint does not stop its
application from reconnecting. Before confirmation, review the process instance,
local and remote endpoints, snapshot age, and explicit elevation requirement.
Immediately before Windows teardown, WinTCP rechecks the live IPv4 tuple, state,
owner PID, and captured process lifetime. Windows' teardown API accepts a tuple
but not a PID, leaving a narrow, unavoidable race if that exact tuple is reused
between the final check and the API call.

**Connections** shows live endpoints. **Closed history** shows the bounded set
of closed endpoints retained by the server (with a retention note and a reset-to-live button), separately from live counts.
Historical rows cannot apply a live peer-block action. **Listening** includes
TCP listeners and UDP bindings, their numeric local ports, and their binding
scope: all interfaces, loopback, private/link-local, or a specific address.
The **Port owner** input above the Listening sockets table finds which process,
interface, and rules apply to a given listening port. It links directly to the
process details, automation draft, and inbound firewall investigation for that
port. A bound socket is distinct from a tested reachable service; firewall policy
and routing determine reachability.
IPv4-mapped IPv6 addresses follow the mapped IPv4 address scope. These labels
describe the local bind only; a wildcard or specific bind does not prove that a
firewall permits access or that the endpoint is externally reachable.

Choose **Units**, **Density**, and **Refresh interval** in Settings to change the
current view. Process sizes use readable units while their tooltips retain the
exact values. Desktop notifications require browser permission; denied or later
revoked permission turns the option off and saves the disabled state.
Saved preference changes are synchronized to other open Settings tabs. Incoming
updates do not replace fields currently being edited or saved locally.

## Map and network flows

Country enrichment requires a MaxMind-format `.mmdb` database. WinTCP does not ship one or download one. Configure a country database in **Settings**; the map and Flows view use the configured database without a restart. An ASN database is separate and is not required for country lookup.

The Map page shades countries with remote connections and places a marker for each geolocated connection. Hover a marker to see its process, PID, remote address and port, DNS name when available, protocol, state, and country. Use the button in the page header to switch between the globe and a 2D projection. The map boundaries are bundled locally; the page does not request map tiles from an external service. If the map fails to load, use **Retry map** to reload it. The map resizes with the browser window.

Locations are **country-level estimates**, not device or person locations. Private, loopback, link-local, reserved, and unrecognized addresses are not assigned a country. The map and Flows view show connection counts, not bandwidth. Without a configured database, the dashboard explains why geographic results are unavailable.

The Flows tab groups remote peers by country. The Connections and Listening tabs retain their network-table views. **Firewall Rules** reads the rules returned by Windows Firewall COM and supplements those results with readable WinTCP-owned rules. The inventory shows when Windows generated the current snapshot; if a refresh fails, the last successful result remains visible with a stale-data warning. Windows may omit rules from COM enumeration; the list is therefore not guaranteed exhaustive, does not include an effective-policy verdict, and cannot prove reachability. Non-WinTCP rules are read-only in this view. WinTCP-owned rules can be enabled, disabled, or removed after a review; WinTCP re-reads the complete rule before applying the change and verifies it afterward. These changes require an elevated process. The Web UI does not collect per-socket byte counters; use the CLI or desktop GUI when those counters are needed.

Select or keyboard-activate a firewall rule row to inspect its full configured scope, ownership and status. Unknown fields remain labeled **Unknown**; the details view does not infer effective policy. Before enabling, disabling, or removing a WinTCP-managed rule, the review shows the server-read current direction, action, protocol, profiles, addresses, ports, application and service scope; unavailable fields remain **Unknown** rather than being copied from a possibly stale table row.

Use **Find related firewall rules** in a live connection's action menu to narrow the inventory to outbound rules whose known direction, protocol, addresses, or ports do not definitely conflict with that connection. In **Listening**, choose **Find inbound firewall rules for this listening port** to compare inbound rule direction, protocol, local bind address, and local port. The listening socket cannot identify incoming remote peers, so remote address and port scopes remain broad or unknown. When Windows reports the active firewall profiles, rules that apply to none are excluded and partial profile overlap is identified; if profile data is unavailable, it remains unknown. The row explains each compared field as exact, broad, partial, no-match, or unknown; application and service checks remain unknown when the system does not provide enough information. Disabled, allow, and block rules remain visible as candidates when their scopes fit. These are scope comparisons only—not proof that a rule is effective, that traffic is blocked or allowed, or that the endpoint is reachable. Use **Show all rules** to clear the candidate view. Retained history cannot start these drilldowns.

Use **Create rule** on the Firewall Rules page to review a custom inbound or outbound block/allow rule. Specify TCP, UDP, or Any; remote and local address scopes; local and remote port lists/ranges; optional full executable path and service short name; and one or more Windows Firewall profiles. Use `*` explicitly for an unrestricted field. The preview shows the generated rule identity and complete effective scope. Port restrictions require TCP or UDP. An allow rule does not override a matching block rule. Confirming creation requires administrator rights; WinTCP re-reads the rule and reports whether its configured fields match the preview. This editor creates new rules; use row actions to enable, disable, or remove WinTCP-managed rules.

## Processes and automation

The Processes page lists the process snapshot, not only processes that own a connection. Use **Table**, **Tree**, or **Treemap** to change the view; the treemap can be sized by working set or CPU share. Select a treemap tile to open that process's details. **Group by executable** combines instances only when their full executable paths are known to match; pathless processes stay separate. Group totals sum readable values only and identify partial subtotals. Select a grouped tile to choose an exact process instance before opening its details. The lower-ranked remainder tile also opens a list of its exact processes; individual tiles too small to activate are still available in Tree or Table. The treemap draws positive measured values only, reports unavailable measurements separately from known zero values, and groups lower-ranked processes. The Tree view keeps matching descendants under labeled ancestor context; use the arrow keys to move, expand, and collapse, **Enter** for details, and right-click or **Shift+F10** for process actions. Parent links require verified creation times in chronological order; when a PID has been reused or either lifetime is unavailable, the process remains a root and the relationship is labeled instead of implied. Tree expansion and focus follow process-instance identity across samples. The table includes the full process set supported by the local API, and its filter, sort, view, and scroll position stay in place as samples update. A dash indicates a value Windows could not provide, not a measured zero. Large memory and I/O counters retain exact values even when they exceed JavaScript's safe integer range; hover a formatted byte value to see its exact raw byte count. On narrow screens, tables scroll horizontally rather than hiding columns.

**Block this executable** in a Process action menu reviews an outbound TCP rule scoped to the verified full image path. It affects every current and future instance of that executable, all remote addresses and ports, and does not close existing connections. A readable path and process lifetime are required; the action is unavailable when either is unknown. Creating the rule requires running WinTCP with administrator rights.

**Allow this executable** uses the same verified path and all-instance scope. It is an explicit Windows Firewall allow rule, not a bypass: a matching block rule may still take precedence. Review the displayed plan before creating it.

The Network connection menu also offers **Block this executable to this peer** when the selected live TCP connection has a known process lifetime and readable image path. The review scopes the rule to that executable, remote IP and remote port; the API revalidates the complete connection tuple and owning process lifetime before offering a one-use create action. This affects every instance of the executable for that peer and leaves existing connections open. When Windows also reports a service short name for that connection, **Block this service to this peer** adds both the executable and service scopes, which can distinguish one service hosted by `svchost.exe`. Scoped IPv6 literals that include a zone identifier are currently refused rather than risking loss of the interface scope.

The Automations page provides scenario-oriented CLI playbooks, a workbench for local WinTCP scripts, and the audit trail. The playbooks are on-demand command examples; their scenario descriptions are not active detectors, and this page does not create or evaluate monitor rules. Scripts execute the adjacent `wintcp.exe` with bounded arguments and output. Sensitive actions require a separate confirmation and can still require administrator rights. For background connection-change logging, use the CLI `monitor start` command described in the [CLI guide](cli.md). The Web UI does not provide a persistent scheduler, cloud service, or remote notification service.

Firewall actions are explicit. The UI shows a preview before a supported rule is applied, records the action in the local audit trail, and does not elevate the process. Review the target and scope before confirming. Connection close is a separate action: it does not create a firewall rule.

## Local data and privacy

The Web UI uses local static assets and makes no third-party asset or analytics requests. The server accepts loopback traffic only and uses a per-process token for state-changing requests. Do not place it behind a proxy, forward its port, or treat it as a LAN-accessible service.

Per-user configuration, audit records, and diagnostic logs are stored in `%LOCALAPPDATA%\WinTCP\WebUi`:

- `config.json` stores display preferences, GeoIP paths, and saved scripts.
- `audit.ndjson` records relevant configuration and response actions.
- `webui.log` contains server and manager diagnostics.

Reverse-DNS lookups use the Windows resolver when enabled. GeoIP lookups use the configured local database; WinTCP does not send addresses to a hosted geolocation service.

## Local API

The same-origin API is intended for the Web UI and local integrations. Read-only routes include `/api/health`, `/api/connections`, `/api/processes`, `/api/metrics/now`, `/api/metrics/history`, `/api/geo/summary`, `/api/firewall`, `/api/templates`, and `/api/audit`. Configuration and response routes require the session token and same-origin request checks. The server binds only to loopback; API access is not a substitute for a remote authentication layer.

`GET /api/config` returns an `ETag` revision. Send that value in `If-Match` when
posting an updated configuration. A stale revision returns HTTP 412 without
changing the file; read the latest configuration and merge the intended changes
before retrying. The dashboard does this automatically, with bounded retries and
a visible unsaved-change error if conflicts continue. Older integrations may
still post without `If-Match`, but those unconditional writes cannot protect
against concurrent edits.

Each server start creates a new session token and configuration revision. If an
open tab attempts a change after the server restarts, the dashboard reports that
pending changes were not saved and offers **Reload dashboard** to reconnect with
the new session.

`POST /api/connections/action/preview` accepts the captured row fields and
returns current close availability, a reason, snapshot age, and, when eligible, a
30-second one-use preview token. `POST /api/connections/action/execute` accepts
that token, refreshes the endpoint table, and refuses if the exact IPv4 TCP tuple
or process lifetime changed. The server consumes the token before execution and
records attempt and outcome in the audit trail. Windows cannot make the final
tuple check and kernel teardown atomic, so a narrow race remains between those
operations.

`POST /api/firewall/rule/preview` accepts a rule name and `enable`, `disable`, or
`remove` operation. It only prepares actions for readable WinTCP-owned rules,
requires elevation, and returns a short-lived one-use token. The matching
`POST /api/firewall/rule/execute` accepts only that token, re-reads and compares
the complete captured rule state, applies the requested change, and verifies
the result. Rules not owned by WinTCP are read-only in this UI. No rule action
is atomic with an external Windows Firewall edit, so changes made after the
server's final comparison remain a platform race.

For the CLI command set and exit codes, see the [CLI reference](cli.md). For the visual system and interface conventions, see the [Web UI design guide](webui-design.md).
