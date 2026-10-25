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

Remote hostnames are resolved asynchronously by the local Windows resolver.
Network rows show **Pending** while a reverse lookup is in progress, the PTR
hostname when one is returned, or **Not resolved** when the lookup completes
without a name. Lookups stay on the backend; the browser does not send endpoint
addresses to an external DNS-over-HTTPS service. As with other reverse-DNS
lookups, results depend on the machine's configured DNS/network access.

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
exact values. Desktop notifications require browser permission and cover both
new connection sightings and newly recorded recipe inbox entries while the Web
UI is open. Denied or later revoked permission turns the option off and saves
the disabled state. Browser delivery is best-effort: the local engine inbox is
the durable record and remains available when the browser is closed or
notifications are unavailable.
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

The Automations page includes **Monitors**, **Engine**, **Restrictions**, **Event history**, scenario-oriented CLI playbooks, a workbench for local WinTCP scripts, and the audit trail. Monitors are persistent exact-executable rules managed by the optional per-user engine; sampled TCP sightings and TCP listeners remain passive, while the optional ETW collector can provide outbound TCP-established and UDP-activity events. Snapshot sightings can miss short connections and never establish direction or connection attempts. ETW process-start image-name strings can annotate PID/QPC-matched short-lived processes, but may be only basenames; they are not shown as verified executable paths and have no verified creation time, so they cannot authorize actions. Ambiguous or missing identity remains unknown. A supported outbound monitor can be explicitly armed either as a preemptive block or as a bounded event-triggered action. Event-triggered actions require the elevated collector, an enabled recipe, a live ETW event source, and a separate explicit confirmation; the first observed flow may already be established, and the temporary rule blocks subsequent matching traffic. Passive notification cooldown suppresses inbox alerts only; it does not suppress a separately approved action for a complete eligible lifecycle event. Grants are memory-only, revision-bound, expire within eight hours, and enforce action/duration budgets. They are not restored after engine or broker restart. The playbooks remain on-demand command examples, not active detectors. Scripts execute the adjacent `wintcp.exe` with bounded arguments and output. Sensitive actions require a separate confirmation and can still require administrator rights. For packet-level connection-change logging, use the CLI `monitor start` command described in the [CLI guide](cli.md). This page does not provide a general-purpose task scheduler, cloud service, or remote notification service.

Firewall actions are explicit. The UI shows a preview before a supported rule is applied, records the action in the local audit trail, and does not elevate the process. Review the target and scope before confirming. Connection close is a separate action: it does not create a firewall rule.

For outbound TCP recipe notifications, a snapshot sighting and an ETW-established event with the same complete tuple and verified process lifetime are correlated for up to two maximum snapshot intervals (120 seconds). The paired observations produce at most one recipe notification, while both source records remain visible in Event history. Correlation does not change Active eligibility: only a complete eligible ETW lifecycle event can enter the separately approved action path.

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

The Automations **Engine** tab reads the optional per-user snapshot engine. It
shows its actual sample state and a small recent-events page. Start or stop it
from the Engine or Monitors tab, or use `wintcp.exe engine start|stop`. The Web
UI starts it as the current user without requesting elevation.
Stopping waits until the engine has drained its workers and released its
single-instance lock before reporting success, so a Start immediately after a
successful Stop does not race the previous engine's shutdown.
`GET /api/engine/history` pages durable snapshot evidence; its cursor survives
an engine restart while the referenced segment is retained and expires
explicitly after rotation. `GET /api/engine/notifications` preserves inbox IDs
and acknowledgement state across restart. This persistence does not restore
Active recipe authorization.

The Monitors list shows whether each rule is disabled, starting, running, or
degraded, its current cooldown state, and the latest trigger recorded in this
engine session. Suppression counts cover matching observations skipped by that
rule's cooldown; the inbox remains the durable trigger history across restarts.
Recipes may run always or in a weekly local-time window using a Windows
time-zone ID. The weekday selection names the day on which a window starts;
overnight windows continue into the next day and the end time is exclusive.
UTC event time is converted with Windows dynamic time-zone rules, so both
occurrences of a repeated fall-back hour are evaluated consistently and a
spring-forward local time that never occurs cannot trigger. Unknown time-zone
IDs are rejected on save; if a saved zone becomes unavailable, that recipe is
degraded and does not fire. Scheduled evaluation ignores live events more than
10 seconds old, preventing stale collector backlog from replaying after sleep;
the side-effect-free Test action evaluates retained evidence at its original
event time without that live freshness cutoff. The runtime reports the next
window transition in UTC and whether the window opens or closes. When an
enabled recipe leaves its window, WinTCP queues a recipe-owner release through
the optional collector, which also invalidates that recipe's in-memory Active
grant. A failed release is shown with its error and retried with a short
backoff; it is never silently reported as released. Returning to an active
window resumes Passive evaluation, but does not restore an Active grant.
Passive matching requires a nonzero PID, a resolved full executable path,
and the trigger-specific endpoint evidence. When the process creation time is
unknown, cooldowns are tied to that evidence event rather than treating a
reused PID as the same process instance; cross-source deduplication requires a
verified process instance. Such evidence can therefore produce separate
notifications when identity cannot be joined safely.
`deliveryStatus: "inbox"` means the notice was appended to WinTCP's local
durable inbox; it does not claim that a browser or operating-system toast was
shown. Older retained rows that used to say `pending` are normalized to `inbox`
in the read view; the append-only on-disk history is not rewritten.
Acknowledgment is a separate persisted user action. When desktop notifications
are enabled and permission is granted, the open Web UI polls the durable inbox
and offers new recipe notices through the browser Notification API. A shared
Web Lock (with a short local-storage lease fallback) coordinates open tabs;
existing inbox rows are silently baselined on first use or after history
rotation, and bursts are capped at three toasts per poll. This adapter is
best-effort only and never changes inbox persistence or acknowledgment state.
Lifecycle capability becomes available when event tracking is running, before
any matching connection has occurred, so an active recipe can be armed in
advance.
**Arm notify + block** explicitly approves an outbound-activity recipe's exact
executable, optional peer/port, approval lifetime, per-action lease duration,
and action budget. The elevated broker holds the approved scope; the engine
keeps a nonpersistent revision/expiry marker for trigger validation and UI
status. Both are bound to the saved recipe revision and are not restored after
restart. Only an actionable, normalized outbound TCP
established or UDP activity event for that same executable can consume it; the
broker rechecks the executable's file identity and verified WFP filters before
reporting success. The notice is recorded in the inbox with the resulting lease
ID and a direct link to its triggering retained event. This is post-observation
mitigation, not prevention of the first attempt.
Inbox links resolve Passive event IDs and Active trigger IDs in the shared,
durable event history. The event history is bounded and rotated; when a linked
record has expired, the page reports that it is no longer retained instead of
showing unrelated evidence.
The current UI exposes a one-action budget per arm; the broker also enforces
the grant lifetime and cumulative-duration limits. Disarm, recipe edit/disable/
delete, heartbeat loss, broker exit, and restart invalidate the grant and
release owned temporary filters. After the action or restart, review and arm
again if desired.
Stopping event tracking also cancels recipe grants and releases their active
recipe-owned leases, without affecting manual temporary leases.
The Monitors page reports trigger-queue losses and failed active actions for
the current engine session instead of implying that every observed trigger
became a verified block.

Automations **Restrictions** manages temporary outbound blocks separately from
permanent Firewall Rules. Start the engine, then click **Start collector (UAC)**
or explicitly launch `wintcp.exe collector run` from an elevated terminal for
that same Windows user; opening the dashboard alone never requests elevation.
The start operation completes only after the elevated helper confirms its
same-user engine heartbeat. A ready helper may still report WFP unavailable;
in that state lifecycle tracing can be used, but restriction actions stay
disabled with the reported capability reason.
Preview an exact
executable and optional literal IPv4 or IPv6 peer/port/protocol, review the user SID and
duration, and apply within 30 seconds. IPv6 zone-scoped literals are not accepted.
An enabled outbound-activity monitor can
be explicitly armed; its card shows the broker-reported **ARMED** state and
lease expiry. Successful recipe-owned application creates a durable inbox
notification linked to the restriction lease ID; it says the block was
verified at apply time, while the Restrictions panel remains authoritative for
current state. The Monitors card offers **Arm preemptive
block** for supported outbound-activity recipes: the user chooses peer scope
and a 1–480 minute lease, reviews the exact executable/scope/duration, and
confirms separately. This is an explicit preemptive lease, not an automatic
reaction to a snapshot observation. The engine also invalidates a recipe-owned
approval/lease before accepting edits, disable, or deletion, regardless of
whether the change came from Web UI or CLI. **Disarm** and recipe disable/edit/delete
release only leases and pending approvals owned by that recipe; manual leases
are unaffected. The engine attempts owner release whenever the same-user broker
is reachable, even if its current WFP capability is degraded; if it is
unreachable, broker heartbeat-loss and lease expiry remain the cleanup path. A
broker restart drops its in-memory approvals and dynamic
filters and grants, so recipe-owned blocks must be explicitly re-armed. The panel lists active leases, filter
counts, expiry countdowns, individual release, and release-all. When a prior
recipe-owned apply is retained in the inbox but no matching live lease is
reported, the monitor shows **Needs re-arm**. If the collector inventory is
unavailable, it shows **Status unknown** instead and disables another arm
attempt until current state can be checked. Collector exit
removes its dynamic filters; existing connections may continue. Passive
notifications remain distinct from active actions: an action is attempted only
for the explicit, supported outbound event types above, never for snapshots,
listeners, process-only evidence, late/incomplete chronology, or unknown process
identity.
Collector controls and restriction mutations return `202` with an operation
ID; the panel polls the shared engine operation journal for the final result.
Each submission carries a request ID so a retry cannot apply the same plan
twice. UAC and WFP calls run on a separate engine worker, allowing monitoring
and recipe configuration to continue while a collector operation is pending.
The bounded journal reserves capacity for stop and release controls, and runs
those ahead of queued previews or reactive actions. If a lane is saturated, a
new request gets an explicit `operation_queue_full` error with HTTP 503; it is
not silently dropped or misreported as a malformed request. Reusing a request
ID with different contents returns HTTP 409.
The Restrictions panel also pages through retained outcomes using
`GET /api/restrictions/history?limit=30&cursor=...`. Reads require the session
token. The collector keeps at most 1,024 changes; the engine copies them to
bounded audit segments and checkpoints its cursor. Expiry, manual release,
failure cleanup, and heartbeat loss have separate reasons. A lost broker or
evicted change journal produces a coverage gap; an unavailable broker is not
reported as a verified clean shutdown. Creation is limited to 32 leases per
minute and 128 concurrent leases.
Queued collector commands retain request and result audit records without
storing preview confirmation tokens. Operation results include a separate
audit status: an audit failure does not hide whether an action completed.
Release and stop remain available when audit storage fails. A normal collector
stop releases filters, disables new restrictions, and waits briefly for the
engine's persisted final cursor before exiting.

Automations **Event history** provides explicit engine, collector/UAC, and
event-tracking controls. Its token-protected `/api/engine/lifecycle` endpoint
pages through retained decoded ETW evidence. The engine writes two rotating
8 MiB raw-evidence segments and checkpoints its source cursor. In parallel, it
publishes normalized TCP establish/close, UDP send/receive, and process
start/exit events into the shared `/api/engine/events` journal and Passive
recipe evaluator. Engine status separates current write availability from
cumulative storage loss: a later successful non-empty write clears a transient
write error, but never erases the count of records previously lost. This does
not make every event an outbound connection:
recipes notify only for verified outbound TCP establishment or UDP send;
explicit failures and denied attempts remain unavailable. The raw view
preserves QPC time, payload PID, source/destination fields, provider/version
and loss gaps. Verified live-handle lifetime intervals retain creation time and
executable path after process exit. Events outside a proven interval remain
unattributed. QPC-to-UTC uses piecewise mapping generations. A detected 50 ms
or larger discontinuity starts a new generation and temporarily withholds UTC
projection and time-based attribution. Two subsequent consistent, reliable
clock samples restore mapping; the uncertain interval remains explicitly
unknown, and recovered observations carry the new generation and a recovery
marker. Collector status exposes mapping generation and recovery count. The
engine records a `source_clock_mapping_unstable` coverage gap before the first
affected observation in a trace epoch; raw QPC timestamps remain available
even when UTC projection is unavailable. The elevated dev-only check
`powershell -ExecutionPolicy Bypass -File tools/webui-e2e/lifecycle-exit-check.ps1 -Url http://127.0.0.1:PORT/`
also starts a uniquely named unrelated real-time ETW session, confirms its
owner GUID remains unchanged across WinTCP event-trace start/stop and collector
shutdown, then stops only that test-owned session. It uses twelve disposable
short-lived local clients and preserves explicit loss/identity uncertainty;
the collector requires elevation and the test refuses to alter an existing
recipe or collector. A bounded 250 ms reorder window correlates TCP
flow generations and labels late, mid-session, and incomplete chronology. Source
records remain intact; derived records reference their evidence IDs. UDP stays
activity evidence. Publication cursors remain monotonic even when source
sequences reorder. Source-based endpoint roles are explicitly marked. Active
actions require an actionable process identity, known outbound peer, supported
event kind, and complete chronology; snapshot observations and uncertain
attribution cannot authorize them. The engine commits the collector cursor only after raw evidence,
normalized event records, resulting notification rows, and the cooldown
checkpoint are durable. Retried source pages are de-duplicated by event ID in
both the raw lifecycle store and shared event journal; a failed notification or
cooldown write rolls the evaluator back so the page can be retried without
silently consuming its alert.
On a clean **Stop event tracking**, the collector consumes final ETW buffers,
drains queued decoding, and flushes pending normalized flows before reporting
completion; queue and ETW loss remain explicit counters rather than silently
discarded shutdown data.
The Event history view also reads `collectorEventLoss` from `/api/engine` and
shows queue drops, schema rejects, ETW event/buffer losses, and collector
history/flow evictions. These are cumulative counters for the current ETW trace
session, refreshed on demand or after collector controls; they are unavailable
as live values when the elevated helper is disconnected. The last sampled
counters remain labeled as stale for the last-known session when available.
Counter increases and same-session resets also create deterministic coverage-gap
rows in retained lifecycle and shared event history. The engine checkpoints
those cumulative totals after the evidence append, preventing a restart from
counting the same observed increase twice. These rows share the bounded history
retention policy, and the counters reset when a new trace session starts.
`/api/engine`, `/api/engine/capabilities`, and `/api/engine/events` require the
page's session token even for GET. If the process is absent they return an
explicit unavailable response. Its live event feed combines sampled endpoints
with normalized collector events; snapshot appearance is not evidence of an
attempted connection.
The separate token-protected `/api/engine/history` reads retained NDJSON
segments across engine restarts. Pages are limited to 500 records and a bounded
response size; cursors identify a file generation and byte offset, and return
HTTP 410 if rotation evicts that generation. The Engine tab offers sequential
pages under **Persisted observations**. Corrupt/incomplete records are reported
as errors rather than silently included as valid events. An unfinished line
at the active file tail is withheld and flagged as `partialTail: true` until
its writer completes it.

The experimental incident-window API is separate from durable history:
`POST /api/engine/incidents` accepts `arm`, `trigger`, `disarm`, explicit
`save`, or `discard` actions; `GET /api/engine/incidents` reports state, and adding
`?offset=N&limit=N` reads a bounded page from the current incident. Arm begins
a 120-second rolling pre-trigger window; a manual trigger captures 30 seconds
afterward and related triggers extend that window up to 120 seconds. While the
recorder is armed, a fired enabled Passive recipe also starts/extends an
incident with its recipe name and trigger reason; the ordinary inbox
notification remains independent of recorder availability. It records observed
snapshot and normalized lifecycle events with their original evidence
JSON and a separate engine capture timestamp. The recorder reports the
requested pre-trigger window and the measured span from its earliest retained
pre-trigger record to the trigger, alongside a separate incomplete-coverage
flag; this span is not a claim of continuous event visibility. While armed, the sampler also
records a complete snapshot-only state checkpoint at least every five seconds;
each checkpoint is capped at 128 KiB and explicitly reports included/total
endpoints when truncated. It does not claim ETW, adapter, route, or other
sources that are not present in that snapshot. Capture remains in memory until
the user explicitly saves a finalized incident. Save writes a generated,
per-user directory under `%LOCALAPPDATA%\WinTCP\Engine\Incidents` containing
`manifest.json`, `events.ndjson`, `checkpoints.ndjson`, and `index.json`; files
are flushed in a temporary directory and exposed by same-volume rename, and
the manifest includes SHA-256 hashes for event, checkpoint, and index files.
Checkpoint rows are stored separately and returned in the bounded archive
pages; the manifest records their count and whether each captured snapshot was
complete. The manifest also records the WinTCP build version, observed source
coverage and loss counts, coverage-gap reasons, and per-timebase monotonic/UTC
anchor pairs. These are observations from the captured records, not claims that
an unobserved source was active or that coverage was continuous. The manifest
sets `replayReady` only when checkpoint data exists.
Offline replay seeks to the nearest prior checkpoint and applies later snapshot
appearance/disappearance deltas in monotonic capture order. A coverage gap or
truncated checkpoint makes the displayed state partial; a later complete
checkpoint restores a known baseline. The UI provides scrub, play/pause, speed,
transport/search filters, and recorded trigger reasons. As the replay position
moves, a separate historical-evidence list shows the non-checkpoint archive
events at or before that position (latest 100, with an explicit truncation
count); this is a time-filtered view, not reconstructed state. Replay still
reconstructs only snapshot endpoint state. Import accepts
the versioned JSON export envelope and validates schema, counts, timestamps,
checkpoint shape, nesting, object keys, and the 64 MiB/100,000-record bounds
before rendering it as local read-only evidence. Imported JSON is always
untrusted and unauthenticated, is never uploaded or written to the archive
store, and cannot invoke actions; users must review its provenance. The Saved
incident library can export a verified archive as JSON:
**Private export** is the default and
omits executable paths/names and free-form trigger reasons while consistently
pseudonymizing process, flow, event, timebase, and endpoint identifiers;
timestamps and event kinds remain visible. **Full metadata export** retains
paths, names, addresses, and identifiers and requires an explicit confirmation.
Export reads all bounded pages from the integrity-checked archive and enforces
a 64 MiB client-side safety cap. It does not modify the saved archive. Imported
JSON is evidence only, not an authenticated native archive, and cannot be
re-exported or used to alter archive retention/pinning.
Saved archives are retained up to 20 incidents and 1 GiB by default. When a
new save needs room, the oldest valid unpinned archive(s) are removed first;
pinned archives count toward both limits. If corrupt inventory prevents a safe
retention decision, or every candidate is pinned, the save fails visibly and
existing archives are preserved. The library reports each archive's byte size
and pin state, and offers explicit pin/unpin controls. Saved archives survive
engine restart; the live capture and
its in-session view do not. `disarm` stops early and marks the post-window
incomplete; `discard` clears only the in-memory incident and does not erase a
saved archive. The token-protected `GET /api/engine/incidents/archives?limit=N`
lists finalized archives; `GET /api/engine/incidents/archives/{id}?offset=N&limit=N`
validates file hashes and JSON structure before returning a bounded event page.
`POST /api/engine/incidents/archives/{id}/pin` and `/unpin` require a unique
request ID and the same session-token/origin checks as other mutations.
Automations > Event history exposes a Saved incident library labeled
**Recorded / Read-only**. It distinguishes snapshot-state checkpoints from
event deltas and provides offline scrub/playback with transport/search filters.
It reports partial state honestly and offers no live actions or external
lookups. These controls never enable ETW or apply firewall actions by themselves. The
endpoints require the session token; POST also uses the normal same-origin
mutation checks.
The focused disposable-loopback integration check is
`node tools/webui-e2e/incident-recorder-check.mjs --url http://127.0.0.1:PORT/`.
It requires an unarmed recorder with no retained incident, arms and
triggers the recorder, opens a local loopback TCP connection, verifies a
snapshot observation is readable, explicitly saves and verifies archive file
hashes plus checkpoint shape/completeness metadata (without assuming the host's
full endpoint set fits the checkpoint cap), then removes only the generated
test archive and discards its fixture. It waits across one five-second capture
interval and verifies that the periodic checkpoint follows the arm-time base.
Use optional `--soak-seconds 6..120` for a longer run; related manual triggers
extend the post-trigger window within the recorder's configured maximum.
It does not enable ETW or require administrator privileges.
The headless browser replay acceptance test is
`node tools/webui-e2e/incident-replay-ui-check.mjs --url http://127.0.0.1:PORT/`
(or `npm run incident-replay` from `tools/webui-e2e`). It creates and removes
its own loopback-only archive fixture, exercises load/scrub/playback/search,
checks historical evidence follows the selected replay time, and verifies that
replay makes only same-origin reads and exposes no actions. The bounded pure
reducer check `node tools/webui-e2e/incident-replay-check.mjs` also covers
timeline filtering, gap inclusion, and the event-list limit.
The schedule parser/runtime acceptance check is
`node tools/webui-e2e/recipe-schedule-check.mjs --url http://127.0.0.1:PORT/`
(or `npm --prefix tools/webui-e2e run recipe-schedule -- --url http://127.0.0.1:PORT/`).
It refuses to proceed unless the recipe store is empty, verifies unknown-zone
rejection, a valid UTC schedule round trip, and runtime transition/lease-state
fields, then removes its fixture. Native unit tests also cover next-transition
calculation across the spring-forward gap and fall-back repeated hour.
The elevated active-recipe integration is
`node tools/webui-e2e/active-recipe-check.mjs --url http://127.0.0.1:PORT/`
(or `npm run active-recipe -- --url http://127.0.0.1:PORT/`). It uses only a
copied disposable PowerShell image and a loopback listener, and refuses to run
when recipes, a collector, or restriction inventory are already present. It
also verifies a real recipe-owned lease is removed when its short UTC window
closes, before the lease TTL, and that the same test flow works afterward.
The browser recipe-notification adapter has a deterministic headless check at
`node tools/webui-e2e/recipe-notification-delivery-check.mjs --url http://127.0.0.1:PORT/`
(or `npm run recipe-notification-delivery -- --url http://127.0.0.1:PORT/`
from `tools/webui-e2e`). It covers
silent initial inbox baselining, once-only delivery, denied permission, and
cross-tab coordination without changing the engine inbox.
`node tools/webui-e2e/incident-import-check.mjs` exercises strict import
validation; the browser replay test also covers imported-file UI behavior.
`node tools/webui-e2e/incident-recipe-trigger-check.mjs --url http://127.0.0.1:PORT/`
uses a disposable same-host non-loopback TCP peer to verify a Passive recipe
triggers an armed recorder, retains the evidence and inbox notice, and restores
the initially empty recipe store.
Monitor state checkpoints retain remaining cooldowns and suppressed counts in
the engine's local storage. Restart restores those deadlines without restoring
privileged authorization. Offline time reduces a cooldown only when monotonic
and UTC elapsed time agree; clock uncertainty conservatively retains the
remaining cooldown. Fired inbox records carry private recovery metadata so a
restart can reconstruct a fired cooldown if the inbox append completed but the
separate checkpoint replacement did not; this metadata is not returned by the
notification API. Invalid or unwritable checkpoints are reported through the
engine notification error field. This narrows the crash window but does not
claim transactional exactly-once delivery when the underlying append/flush
result is ambiguous or an event was lost before an inbox record was committed.

The tab also displays engine snapshot interval and live-ring limits. Saving
uses a unique request ID and the displayed SHA-256 configuration revision;
stale edits are refused with HTTP 409. `POST /api/engine/config` returns 202
and an operation ID, which can be polled through
`GET /api/engine/operations/{id}`. A successful save persists atomically but
applies after an explicit engine restart. The config and operation GETs require
the session token; config POST uses the normal mutation-origin checks. No
settings change grants elevation or enables a privileged collector.
