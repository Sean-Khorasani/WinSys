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

## Pages

| Page | What it shows |
|---|---|
| **Overview** | Current CPU, memory, disk, network, connection, and process summaries with recent trends. |
| **Performance** | Per-core CPU readings and CPU, memory, disk, and network history where the system provides it. |
| **Processes** | Process table and parent/child tree, with a treemap sized by working set or CPU share. |
| **Network** | Connection, listening, blocked-peer, and country-flow views. |
| **Map** | Interactive country map with a globe/2D projection switch and connection markers. |
| **Automations** | Monitor templates, local scripts, and recent events. |
| **Blocked Peers** | WinTCP-managed firewall rules and their status. |
| **System** | Operating-system, processor, memory, and capability information. |
| **Settings** | Theme, display preferences, refresh interval, GeoIP paths, and audit history. |

Use the sidebar to navigate. **Ctrl+K** opens the command palette; when live, the refresh button requests an immediate update. Use **Pause** in the top bar to hold the current snapshot while inspecting it; **Resume** restarts polling. The browser also pauses background work while its tab is hidden.

## Map and network flows

Country enrichment requires a MaxMind-format `.mmdb` database. WinTCP does not ship one or download one. Configure a country database in **Settings**; the map and Flows view use the configured database without a restart. An ASN database is separate and is not required for country lookup.

The Map page shades countries with remote connections and places a marker for each geolocated connection. Hover a marker to see its process, PID, remote address and port, DNS name when available, protocol, state, and country. Use the button in the page header to switch between the globe and a 2D projection. The map boundaries are bundled locally; the page does not request map tiles from an external service.

Locations are **country-level estimates**, not device or person locations. Private, loopback, link-local, reserved, and unrecognized addresses are not assigned a country. The map and Flows view show connection counts, not bandwidth. Without a configured database, the dashboard explains why geographic results are unavailable.

The Flows tab groups remote peers by country. The Connections and Listening tabs retain their network-table views, while Blocked shows the firewall inventory. The Web UI does not collect per-socket byte counters; use the CLI or desktop GUI when those counters are needed.

## Processes and automation

The Processes page lists the process snapshot, not only processes that own a connection. Use **Table**, **Tree**, or **Treemap** to change the view; the treemap can be sized by working set or CPU share. The table includes the full process set supported by the local API, and its filter, sort, view, and scroll position stay in place as samples update. A dash indicates a value Windows could not provide, not a measured zero. On narrow screens, tables scroll horizontally rather than hiding columns.

The Automations page includes monitor templates and a workbench for local WinTCP scripts. Monitor evaluation and browser notifications run only while the dashboard page is open. Closing the page stops those evaluations; it does not stop the background Web UI server. Scripts execute the adjacent `wintcp.exe` with bounded arguments and output. Sensitive actions require a separate confirmation and can still require administrator rights. The Web UI does not provide a persistent scheduler, cloud service, or remote notification service.

Firewall actions are explicit. The UI shows a preview before a supported rule is applied, records the action in the local audit trail, and does not elevate the process. Review the target and scope before confirming.

## Local data and privacy

The Web UI uses local static assets and makes no third-party asset or analytics requests. The server accepts loopback traffic only and uses a per-process token for state-changing requests. Do not place it behind a proxy, forward its port, or treat it as a LAN-accessible service.

Per-user configuration, audit records, and diagnostic logs are stored in `%LOCALAPPDATA%\WinTCP\WebUi`:

- `config.json` stores display preferences, GeoIP paths, monitor settings, and saved scripts.
- `audit.ndjson` records relevant configuration and response actions.
- `webui.log` contains server and manager diagnostics.

Reverse-DNS lookups use the Windows resolver when enabled. GeoIP lookups use the configured local database; WinTCP does not send addresses to a hosted geolocation service.

## Local API

The same-origin API is intended for the Web UI and local integrations. Read-only routes include `/api/health`, `/api/connections`, `/api/processes`, `/api/metrics/now`, `/api/metrics/history`, `/api/geo/summary`, `/api/templates`, and `/api/audit`. Configuration and response routes require the session token and same-origin request checks. The server binds only to loopback; API access is not a substitute for a remote authentication layer.

For the CLI command set and exit codes, see the [CLI reference](cli.md). For the visual system and interface conventions, see the [Web UI design guide](webui-design.md).
