# GUI guide

← [Back to the README](../README.md)

This page covers the desktop application. For the command-line mode see the [CLI reference](cli.md).

## Contents

- [Main window](#main-window)
- [Launching without a console flash](#launching-without-a-console-flash)
- [Refreshing and row highlighting](#refreshing-and-row-highlighting)
- [Columns](#columns)
- [Filtering and sorting](#filtering-and-sorting)
- [Actions](#actions)
- [Details window](#details-window)
- [Bookmarks](#bookmarks)
- [Grouping and freezing](#grouping-and-freezing)
- [Keyboard shortcuts](#keyboard-shortcuts)
- [Export](#export)
- [Change log](#change-log)
- [Performance graphs](#performance-graphs)
- [Traffic counters in the GUI](#traffic-counters-in-the-gui)
- [GeoIP in the window](#geoip-in-the-window)
- [Blocked peers](#blocked-peers)
- [Alerts](#alerts)
- [Windows integration](#windows-integration)
- [Settings and reset](#settings-and-reset)
- [Process tree](#process-tree)

## Launching without a console flash

Use **`wintcp-gui.exe`** when starting the desktop window from Explorer or a shortcut. It is the complete Windows-subsystem GUI application, not a launcher; it does not locate, start, or require `wintcp.exe`. Keep `wintcp.exe` for CLI commands and scripts. Invoking the CLI with no arguments prints its help overview and never opens a window. Both products use the same WinTCP model and shared command implementation, but have separate entry points and executable images.

The native GUI runs independently when copied by itself to a compatible Windows x64 system. Its optional external databases (for example GeoIP) remain user-supplied. To run the separate local browser dashboard, use `wintcp.exe webui serve`; that optional feature needs the `webui` static-assets directory beside the CLI executable. See the [Web UI guide](webui.md).

## Main window

The window lists every TCP and UDP endpoint, IPv4 and IPv6, with its owning process. Enumeration uses `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)` and `GetExtendedUdpTable(UDP_TABLE_OWNER_PID)`. UDP rows follow `netstat` conventions: local port only, remote shown as `*:*`, state shown as `—`.

Some conventions you will see in the list:

- PID 0 shows `—` and PID 4 shows `System`.
- IPv6 link-local addresses show their **scope ID** (`fe80::…%12`).
- Process name, path and service are resolved through a persistent cache that is validated by PID *and* creation time, using one Toolhelp snapshot per refresh.

All heavy work (enumeration, process resolution, reverse DNS) runs on worker threads and is posted to the UI thread when ready. The list itself is a **virtual ListView** (`LVS_OWNERDATA`), so it stays responsive with tens of thousands of rows and preserves selection, focus and scroll position across refreshes.

Every row also carries an **accessible name and description** for screen readers: the name is `chrome.exe, TCPv4, ESTABLISHED` and the description is `PID 1234, 8 connections`, and a grouped row names the aggregate (`svchost.exe, TCP+UDP`, `PID 4321, 14 connections`). Roles, states, navigation and hit-testing remain what the list control itself reports — only the two text properties are added — so assistive technology hears the same truth the pixels show.

## Refreshing and row highlighting

The list refreshes automatically; **F5** refreshes immediately. The live per-process columns are sampled on the refresh worker on every cycle, whether manual or automatic. CPU % is meaningful from the very first refresh because the worker primes its baseline with a short double sample.

Rows keep a stable identity across refreshes, so changes are visible rather than the list simply flickering:

| Highlight | Meaning |
|---|---|
| Green | New row. |
| Yellow | The TCP state changed (for example `ESTABLISHED` → `TIME_WAIT`). |
| Red | The row vanished **this** refresh. It flashes red for one cycle. |
| Grey "ghost" | A retained closed socket. After the red flash it lingers as a grey ghost so the table keeps a short history of what closed; up to 500 sockets are kept, the oldest dropped first, with their final byte counters frozen at the moment of death. |

The identity of a row is **endpoint + PID**. State is not part of the identity, so a state change updates the same row instead of replacing it. Duplicates pair up in order rather than collapsing, which matters in practice: every browser binds its own socket to mDNS port 5353, so a busy desktop has dozens of rows that share one key. See [Architecture](architecture.md#row-identity-and-diffing) for why this matters.

In high-contrast mode every highlight color is derived from `COLOR_HIGHLIGHT` and `COLOR_WINDOW` rather than a fixed palette.

## Columns

Open **View → Columns** to show or hide columns. A check mark appears on every visible column and stays in sync when the menu is opened, when the header context menu is used, and at startup. Column titles are shared by the GUI, CSV export and CLI output.

| Column | Contents |
|---|---|
| Process | Executable name; `System` for PID 4, `—` for PID 0. |
| CPU % | Per-process CPU usage. |
| Traffic | Combined per-process bytes received / sent. Source: ETW when elevated, otherwise the per-socket fallback. See [Traffic counters](traffic.md). |
| Proto | `TCPv4`, `TCPv6`, `UDPv4`, `UDPv6`. |
| Local, LPort | Local address and port. |
| Remote, RPort | Remote address and port (`*:*` for UDP). |
| State | TCP state; `—` for UDP. |
| PID | Owning process ID. |
| Service | Windows service name, when the process hosts one. |
| Hostname | Reverse-DNS name of the remote address (resolved on a background worker). |
| Path | Full path of the executable. |
| Received, Sent, Net total | The split of the Traffic column. |
| Memory | Working set. |
| Disk I/O | Bytes read plus written. |
| Parent process | The owning process's parent, as `<pid> <name>` (header *Parent*). `—` when the Toolhelp snapshot did not cover it — which is not the same as "no parent". |
| Integrity | The process's mandatory integrity level as a word: `Medium`, `High`, `System`, `Protected`, `Low`, `Untrusted`, with `+AC` appended for an AppContainer process. |
| Signature | The Authenticode verdict: `Signed`, `unsigned`, or `BAD SIG`. In the GUI this reads `—` unless verification has been asked for, because the trust provider is far too slow to run on every refresh. |

**Default layout** leads with identity: Process, CPU %, Traffic, Proto, Local, LPort, Remote, RPort, State, PID, Service, Host, Path. Memory, Disk I/O and the split Received / Sent / Net total columns are opt-in.

Five further diagnostic columns are available from **View → Columns** and hidden by default because they are valuable while chasing one slow connection and noise otherwise: `RTT`, `Min RTT`, `Cwnd`, `Retrans` and `Process rate`. Their meaning is explained in [Traffic counters](traffic.md#what-the-per-socket-scan-provides).

**Parent process** and **Integrity** are hidden by default for a different reason than those five: they are *trust* columns, and a question about who launched a process or how much Windows trusts it is asked about a handful of rows, not about the three hundred on screen. They need no switch — both are read on the handle and the snapshot the resolver already has. `Signature` needs `--signatures` on the command line, because `WinVerifyTrust` builds a certificate chain per image; see the `list` verb in the [CLI reference](cli.md).

`unsigned` is **not** a warning. Most of what runs is unsigned and that is normal; `BAD SIG` is the state that means something. `—` means WinTCP did not look, which is a third answer again and is never rendered as `unsigned`.

Readings that cannot be taken (for example a protected process without elevation) show `—` and sort to the end in **both** directions, rather than sorting to the top as a zero would.

The visible set, order, widths and sort persist between runs. The persisted column mask is versioned (`ColVersion`), so an existing profile gains newly default-visible columns exactly once and is not reset again afterwards. The ceiling is 32 columns and that is a deliberate freeze, not a limit that ran into - see architecture.md; the 32nd column leaves no room for another, so a feature that needs one reuses an existing column or raises it deliberately.

## Filtering and sorting

Above the list are a **Protocol** combo (All, TCPv4, TCPv6, UDP and so on), a **TCP-state** combo, and a **filter box** with a 250 ms debounce. Both combos carry visible captions (`Protocol:`, `State:`) like the `Filter:` box, and every control-bar control has a tooltip naming what it does. The filter box accepts the field expressions described in the [filter language](filters.md): substring matches, field-restricted matches, ranges, numeric thresholds on live stats, side restrictions, quoting, `exclude:` and implicit AND.

The window enforces a minimum size (about 760x420 at 100%) so the right-anchored combos never run off a narrow window, and the search box stretches between the `Filter:` caption and the `Protocol:` caption to use whatever width is left.

Click a column header to sort, and click again to reverse. Sorting by State uses the natural TCP-state order rather than alphabetical order. Sort column, direction, column widths and visibility, and the filter text all persist.

Menu commands exist for *Select all*, *Focus filter* and *Clear filter*, and an accelerator table is provided. **Filter → Focus custom filter** (no ellipsis, no dialog) does what it says: it puts the caret in the filter box.

A refresh that has been requested but not yet answered reads `Refreshing...` in the status bar, so a slow enumeration or a DNS stall looks busy rather than idle. When the table itself is empty for a fixable reason, the reason is also drawn **in the list** where the rows would have been (with the action that clears it), not only in the status bar — and **View → Table diagnostics...** offers the same fix on demand.

Presets saved with `wintcp.exe preset save` appear in the **File** menu, so a view built on the command line is available in the window. **Load preset...** and **Delete preset...** show the numbered preset list inside the prompt itself, so the number you type refers to something on screen.

### Process-tree view mode

**View → Process tree** swaps the connection list for a **tree of every process on the machine**, the way Task Manager's Processes tab shows them: one node per process, labelled `name (PID n, k connections)` where `k` is how many connections that process owns (0 for most), under its parent when the parent is also running and as a root otherwise. The command is a checked **mode** (its tick on the menu, and `[Tree]` in the caption), not a window of its own — the tree occupies exactly the rectangle the list uses, and switching back restores the selection and scroll position you had. The filter box does not narrow the tree: a tree built from a filtered view is a broken tree, because the parents are missing.

Why all processes and not the connected ones: the tree is read as a hierarchy, and a hierarchy built from the connection table is missing most of itself. chrome.exe runs 32 renderers and almost none of them holds a socket at any instant, so a connection-only tree showed a browser as one node and nothing else — that was the reported defect. The process list comes from one Toolhelp snapshot and the connection counts from the table, merged in one place.

Every row command works on the tree unchanged. The node you are on is mapped to that process's first row, so **Copy**, **Export**, **Block**, **Close**, **End process** and **Open file location** act on the process you can see. **Details** (double-click, or `Enter`) opens the process dossier even when the process owns **no** connection — which is most of the tree, since a renderer between requests has no socket: the window describes the process itself rather than doing nothing. The status bar shows `N processes, M connections` where the selection count would be. Roots are expanded one level on open, and the first node is selected, so the arrow keys work the moment the mode is switched on.

## Actions

Right-click a row (or double-click to open Details):

| Command | Behavior |
|---|---|
| **Details** | Opens the [Details window](#details-window). Double-clicking a row does the same. |
| **Copy selected / Copy all** | Copies rows to the clipboard. |
| **End process** | Ends the owning process after verifying that the PID still refers to the same process (PID-reuse check). Bound to `Ctrl`+`Del` — a stray keypress must not end a process. The scriptable path is `wintcp.exe kill <pid> --yes`. |
| **Close connection** | Deletes the TCP entry with `SetTcpEntry(DELETE_TCB)`. IPv4 only, and requires administrator rights. Bound to `Del`. |
| **Open file location** | Opens Explorer on the row's executable, pre-selected — the same `explorer.exe /select,` call the Details window's button makes, so the two cannot disagree. |
| **Block this connection** | Adds a firewall block rule. IPv4 only, and requires administrator rights. |

Each of the three destructive confirms (**End process**, **Close connection**, **Block this connection**) ends with a **Scriptable:** line naming the CLI verb for the same row — `wintcp.exe kill --pid N --yes`, `wintcp.exe close --select "pid:N remote:A" --yes`, `wintcp.exe block --select "pid:N remote:A" --yes` — verified on the real machine to resolve to exactly the row the window had. A successful block reports on the status bar rather than a modal, so the list keeps updating; a partial failure still takes a modal because it must not be missed.
| **Export selection.** | Writes the selected rows to a file. See [Export](#export). |
| **Refresh** | Same as F5. |

Two commands were **removed on 2026-10-05** after being reported not to work. Neither was repaired in place, and the reasoning is worth stating because both look like features one could still want:

- ***Process properties*** is gone from both the Process menu and the context menu. `properties` is a shell **verb**, run through a shell item rather than by handing `ShellExecuteW` a bare path - which is exactly the case where it fails. The old handler reported one indistinguishable message box for that, for a missing path, and for PID 4's placeholder `System` path.
- ***Follow TCP stream*** is gone from both menus. The capability is not lost: it is the [`capture`](cli.md#capture) verb on the command line, where the blocking it requires is the point rather than the defect. `capture --text` prints the reassembled stream to stdout the way `tcpflow -A` does, and `capture --out FILE` keeps the capture as pcapng for Wireshark or `tshark`.

## Details window

A sectioned, modeless window with the process identity, command line, creation time and service; live CPU, memory, disk and network statistics; the full list of connections owned by the same PID; and the selected connection.

- The header line reads `process.exe (PID n)`.
- It opens centered over the main window and scales with DPI.
- While open it **refreshes silently on every auto-refresh**. If the tracked process exits, a note appears once.
- **Copy** and **Open file location** buttons are provided, in a row below the body.
- **Every connection owned by that PID is listed** - all of them, not a preview. It used to stop at 25 rows and report *… and N more*, which hid the one section that answers "what is this process actually connected to"; the cap is gone rather than made expandable, because an expander would put the answer behind a click on a window whose whole model is "read, and collapse sections". A browser process with 70-odd sockets lists all of them.
- Note that a multi-process browser puts each process in its **own PID**, so `PID 50092` never mixes in another `chrome.exe`'s sockets, and rows belonging to other PIDs are never listed at all. The list is scoped to the selected row's process, not to everything in the snapshot.

### Threads

A **Threads** section lists the process's own threads, ranked by CPU time with the busiest first:

- Each row is one thread: `TID`, total CPU time since it started, how long ago it started, and its base priority.
- **Ranked by CPU**, because that ordering is the answer to "what is this process doing". A ranked list says which thread is working; an unordered one says only how many there are.
- All of them are listed. A 460-thread process shows 460 rows.
- Threads whose times cannot be read show `-`, not `0`, and sort **last**. That is a real condition for protected processes, and printing `0.00 s` for them would be a fabricated measurement rather than an admission of ignorance.
- The note says how long ago the sample was taken, and that the CPU figure is lifetime-since-thread-start rather than since the window opened - otherwise "cpu 3985 s" beside a window opened five minutes ago reads as a rate.
- The section appears within one refresh of opening, not instantly: the enumeration costs about 48 ms because `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)` walks every thread on the machine, and that runs on a worker so it never freezes the window. `wintcp.exe details` has no such problem - it is a one-shot command and waits for the answer.

**There is deliberately no per-connection thread column, because none exists.** Windows has no notion of a socket's owning thread: `MIB_TCPROW_OWNER_PID` - the row behind the `GetExtendedTcpTable` call this whole app is built on - carries no thread id, and an AFD endpoint is owned by the *process*. That is why TCPView, Process Explorer and Wireshark all stop at the PID too. The only thread association available comes from ETW event headers, and it is the thread that *performed an I/O*, not an owner: on a socket shared between threads it changes from packet to packet, and it is only observable while a trace session runs. A column headed *Thread* holding that would be a label the data does not support.

For the same reason the section omits each thread's current state. `GetThreadInfo`/`THREADINFO` is a legacy kernel32 export that the Windows SDK no longer declares for user mode, and its state and wait-reason values are not published - so "Waiting"/"Running" would mean inventing a mapping. Better absent than wrong.


### Layout

Fields are laid out as a **two-column table**, one row per field:

- The label sits in a fixed-width left column, so every value in the window starts at the same horizontal position regardless of how long its label is. The two are joined by a **dotted leader**, which is what makes a row read as a pair rather than as a caption with a value that happens to share a line.
- A **hairline rule** separates the label column from the value column.
- Values are drawn in a fixed-pitch face only where alignment matters (byte counts, timestamps, addresses); everything else uses the UI font, including the labels.
- Every section header carries an **accent bar** down its left edge, so the sections read as separated at a glance without hovering anything. Hovering a header highlights it, which is the cue that it can be collapsed.
- Sections are collapsible by clicking their header. A `[-]`/`[+]` chevron marks every collapsible header, and hovering one brightens its band. The state is per-window and is never persisted.
- The tabs share **one strip**: every slot is measured and painted in the same bold face on a single row, so no tab sits lower or further right than the last (the "cascaded" layout stacked one row per tab). Click, hover and paint all use the strip's own geometry, and section clicks and hover agree with what is painted rather than sitting a header-height below it.
- Long values are elided rather than wrapped; a visibly shortened value beats a silent cut. Copy the value to the clipboard to get all of it.
- The body scrolls on a **native scrollbar** (arrows, paging, thumb-drag, Home/End all work), and the keyboard scrolls too: `Up`/`Down` step a line, `PageUp`/`PageDown` a page, `Home`/`End` jump. Tabs switch with `Ctrl`+`Tab` / `Ctrl`+`Shift`+`Tab` (or the `Left`/`Right` arrows when the window itself has focus); section headers and tabs show a hand cursor. The window's accessible name is the plain-text model, so screen readers announce the same text **Copy** puts on the clipboard.

Two layout faults were fixed on 2026-10-05, both of which surface as "the window doesn't split correctly":

- Each field used to be **two** stacked rows - the label, then the value indented beneath it - so a section cost 34 px of captions and read as text rather than as a table. It is now one row per field.
- The body painted down to the **full client height** rather than to the bottom of the content region, so the last visible fields were drawn behind *Copy* / *Open file location* / *Close*. The click and hover handlers had the same missing bound, so a click in the button row could toggle a section hidden behind it.

The same report is available from the command line with `wintcp.exe details`; see the [cookbook](cookbook.md#14-full-dossier-for-one-connection).

## Bookmarks

A **bookmark** is a note and a colour attached to one remote address and port, so a peer you have decided something about can be found again later. Bookmarks live under `HKCU\Software\WinTCP\Bookmarks`, one subkey per endpoint - per user, never machine-wide.

| Where | What |
|---|---|
| **File -> Bookmarks...** | Opens the manager: every bookmark, editable, with its tag and note. |
| Select a row, then **Process -> Bookmark this connection** | Adds a bookmark for the selected row's remote address and port. |
| Select a row, then **Process -> Edit bookmark note...** | Attaches or changes that row's note. |
| **View -> Columns -> Bookmarks** | Adds the *Bookmarks* column: the tag, colour-coded. Hidden by default. |
| **View -> Columns -> Note** | Adds the *Note* column carrying the text. Hidden by default. |

Both **Process** entries act on the current selection rather than on the row under the cursor, so a bookmark is placed where you last clicked.

Five tags: **Red**, **Amber**, **Blue**, **Green**, and **None** for a bookmark that is deliberately unremarkable. The tag is the first thing the column shows, and the note is the second, so a glance answers "do I already know about this peer?" before you read anything.

This is the feature the `pinned` and `note` columns belong to, and it has a command-line face as well - see [`bookmark`](cli.md#bookmark). The notes are also searchable: `note:` is a filter field, so `--filter "note:corporate dns"` selects every bookmarked peer whose note mentions it.

## Grouping and freezing

Two **View** switches change what a row *means* rather than what it shows:

| Switch | Shortcut | Effect |
|---|---|---|
| **Group rows by process** | `F7` | Collapses the table to one row per **process** instead of one per socket. A browser with 70 sockets becomes one row. |
| **Freeze view** | `F6` | Stops the row list being repainted, so a selection and a scroll position stay put while the refresh continues behind it. Use it when reading a column and the list would otherwise move under the cursor. |

Grouping answers "who", not "which socket" - the difference between recipe 5 in the [cookbook](cookbook.md) (one row per process) and recipe 14 (everything known about one connection). Nine columns cannot survive that change honestly: **Local address**, **Local port**, **Remote address**, **Remote port**, **Duration**, **Hostname**, **TLS**, **Country** and **Note** each describe one connection, or in the case of a note one remote endpoint. Under `--group` the CLI refuses those nine in `csv`, `json` and `full`, because a file's header would promise a value its rows do not carry - and it names the offending columns so the mismatch is visible rather than silently repaired. The default `table` format is deliberately exempt: a grouped row already says what it is, because its **State** cell reads `4 connections`, its **Proto** cell reads `TCP+UDP`, and its **Process** cell falls back to the PID when the name is unknown. In a table a blank column next to those is self-explanatory; in a CSV it is a lie.

A grouped or frozen view says so in three places, not just the status bar: the **caption** gains `[Grouped]` / `[Frozen]` (and `[Filtered]` when a filter is active), the **Process column header** reads `Process (N groups)` with the live group count, and **copied rows** carry `#`-comment header lines naming the mode — so a pasted table cannot be mistaken for a live flat one.

## Keyboard shortcuts

**Help -> Keyboard shortcuts** (`F1`) opens the in-app sheet. The same set, in the order the sheet groups it - by what the keys do, not alphabetically:

| Keys | Action |
|---|---|
| `F1` | Keyboard shortcuts (this sheet) |
| `F5` | Refresh now |
| `F6` | Freeze / unfreeze the view |
| `F7` | Group rows by process on / off |
| `Ctrl+C` | Copy selected connections |
| `Ctrl+A` | Select all rows |
| `Ctrl+F` | Focus the filter box |
| `Ctrl+S` | Save view as preset |
| `Ctrl+E` | Export to CSV |
| `Esc` | Clear the filter |
| `Del` | Close the selected connection |
| `Ctrl`+`Del` | End the selected process (graceful close first; the scriptable path is `wintcp.exe kill <pid> --yes`) |
| `A`-`Z` | Type to jump to a row by process name |
| `Backspace` | Back out of a type-to-jump prefix |
| `Alt` | Underline a letter to walk the menus (hold `Ctrl` as well) |
| `Ctrl`+click | Extend the selection |
| `Shift`+click | Select a range |
| Double-click | Open the details window for the row |
| `Shift`+`F10` | Open the context menu for the selected row |
| Drag a header | Reorder a column; the order is remembered |
| `Tab` | Move between the filter controls and the list |

Type-to-jump matches a prefix of the process name and moves the selection with each keystroke, so a stray letter typed over the list is harmless rather than destructive. Two details make it usable: pressing the **same character again cycles** to the next match, so a prefix shared by a dozen rows (`svchost.exe`) still moves; and a repeated character is never appended, so pressing `s` twice means "the next row starting with s" rather than a prefix of `ss` that matches nothing. A pause of about a second (the Explorer's interval) breaks the sequence, so the first keystroke after thinking always starts a fresh search. Matching is prefix-only by design: typing `svch` lands on rows *beginning* `svch`, never on the first row that merely contains it somewhere.

`Ctrl+S` saves the current filter, sort and column selection as a preset that **File -> Load preset...** restores; it is listed by the menu, bound in the accelerator table, and present in the F1 sheet like every other shortcut.

## Export

Export to **CSV**, **TSV** or **JSON**, either the whole table or just the selection.

- Files are UTF-8. CSV and TSV carry a BOM so Excel on a Western locale reads non-ASCII paths and process names correctly; JSON never carries one, because many parsers reject it.
- CSV uses RFC 4180 quoting.
- The extension picks the format when one is present.
- The last-used folder is remembered.

For scripted exports and column control use `wintcp.exe export`; see [CLI reference](cli.md#export).

## Change log

**File → Change log** writes an append-only CSV of `APPEAR`, `DISAPPEAR` and `STATE` events, taken from the same diff that drives the row highlighting on each refresh.

The **Change log window** (`File → Change log window...`) shows the same feed live: **Clear** asks for confirmation (with the safe button defaulted), **Copy** with no selection copies the whole buffer and says how many rows it took, `Ctrl`+`A` selects all, and `Esc` hides the window without losing the buffer. An empty window names its next action (`File → Log changes to file...` starts the feed) instead of sitting blank.

## Performance graphs

**View → Performance graphs…** opens a modeless window with four live line charts, sampled once per second with a 120-sample history stretched across the plot area:

| Panel | Source |
|---|---|
| System CPU % | System-wide CPU sampling. |
| Memory used % | System memory. |
| Disk read / write B/s | PDH `PhysicalDisk(_Total)`, using locale-independent English counter paths. Shows `n/a` for that panel when counters are disabled. |
| Network down / up B/s | 64-bit interface octet deltas from `GetIfTable2`. |

Each panel is independent and has its own "collecting…" and `n/a` states; before the first samples land, one line over the plot area says traces are on their way. The two-line panels (Disk, Network) carry a **colour legend** (`R`/`W`, `down`/`up`) at the right of the caption row, so the two line colours are explained where they are drawn. The charts are double-buffered, follow the system theme (including high contrast, where the series borrow the system's contrast-picked highlight pair) and enforce a minimum window size. The window opens centered over the main window; closing it with **X** — or `Esc` — hides it and stops the one-second sampling timer, the menu entry shows it again (and its check mark re-syncs when the menu opens), and it is destroyed with the application.

The window is display-only no longer: **&Export…** writes the full histories as CSV through the same exporter the tests pin (panel order, units and ceilings identical to the traces), and **&Copy values** puts the current-values table on the clipboard — the same table the window's accessible name announces, so keyboard and screen-reader users reach every number the traces show.

## Traffic counters in the GUI

**View → Per-PID traffic counters (ETW, admin)** starts the kernel logger explicitly. Making any traffic column visible, or starting with one persisted, tries ETW **once** silently; if that fails, the unprivileged socket fallback arms itself with no message box, because it succeeds.

The status bar's second pane reports which source is feeding the columns:

| Pane text | Meaning |
|---|---|
| `Ready` | A source is feeding the visible traffic columns. |
| `TCP only — UDP needs admin` | The unprivileged fallback is running (tooltip explains the UDP gap). |
| `Traffic off — needs admin` | No source can run on this system. |

Full details, including limits, are in [Traffic counters](traffic.md).

## GeoIP in the window

**View → GeoIP database (.mmdb)...** opens a picker titled *Open a MaxMind .mmdb database*, filtered to `*.mmdb`. Pick a file and the `Country` column fills at once rather than at the next refresh: choosing a file is a request to see results, not to wait for a tick. Cancelling the picker is not an error and changes nothing.

A file that will not load reports the parser's own reason under **GeoIP database not loaded**, because a missing file, a truncated one, a file that is not an MMDB, and a database declaring an unsupported record size are four different problems that need four different answers from you.

Reloading works on a live session: picking another file replaces the previous one, and a peer that moves out of the new database's coverage has its country **cleared** rather than keeping a stale answer — the one way a swap could look like it worked while showing the wrong country. Nothing is downloaded either way. [GeoIP database](../README.md#geoip-database) explains why not, where a free `GeoLite2-Country.mmdb` comes from, and how `geoipupdate` keeps it current.

**The choice survives a restart.** Window placement, columns, sort, filter, always-on-top, tray and the database path all persist in `HKCU\Software\WinTCP`. Pick a database once and the next launch silently reloads the stored path, so the `Country` column repopulates without a second trip through the picker. A moved or deleted file fails to load quietly — `Country` shows "—" as it would for no database at all, which is the honest outcome — and **View → GeoIP database** still reports the parser's reason under **GeoIP database not loaded** when it does fail.

The path is the only thing remembered, not the database's contents: a file replaced in place is picked up on the next refresh. From the command line `--db FILE` stays explicit per run, and `list --watch --db FILE` re-reads the file on every tick, so a refreshed database shows up without restarting anything.

## Blocked peers

**View → Blocked peers…** lists the firewall rules **Block this connection** created, and lets you delete one or all of them. It needs no elevation to open or to delete a rule.

The list is a **report view** with sortable **Rule**, **Remote** and **Status** columns — click a header to sort, click again to reverse, with the arrow kept on the ordering column. Each row is read from the rule the firewall actually holds, not from what the ledger remembered writing, so a rule you disabled, or flipped to allow, in `netsh advfirewall` or WF.msc shows up **as it really is** — `disabled` or `not a block` in the Status column — rather than being counted as protection. A block that is not blocking is the one state this window must never pass off as cover. A rule deleted out from under the ledger is simply absent from the list. An empty list says blocking a connection adds the first row, instead of sitting blank, and the action buttons disable until there is a rule to act on.

- **Delete** removes the selected rule, after a confirmation naming it.
- **Enable** / **Disable** leave the rule installed and flip its Enabled state. Disabling is not deleting: a disabled rule keeps its identity, its name and its description, so "turn this off for an hour and put it back" is one step instead of delete-then-re-derive. A rule recreated from scratch is a rule whose name may change and whose description is gone.
- **Remove all** removes every WinTCP rule — the same function the tray menu's **Remove all WinTCP blocks** runs, reached here without the trip through the tray — after a confirmation, with the safe button defaulted.
- **Close** dismisses the dialog. Dismissing it (or `Esc`) without changing anything reports "looked and left", so the main table does not refresh for nothing.

**The list is re-read from the firewall after every action**, and the selection follows the rule it was on when that rule still exists. A manager that closed after each action would take three operations per change, and a manager that kept its own copy of the list would show a state the firewall was not in. If the re-read fails, the list is left as it was rather than emptied — an empty list on a failed read would read as "you have no rules", which is the one answer this dialog must never give wrongly.

From the command line the same information is available as `wintcp.exe blocks --list`, in `table`, `csv` or `json` — see [`block`, `unblock`, `blocks`](cli.md#block-unblock-blocks). The window and the verb read the same rules, so they cannot disagree.

### The ASN database is a second file

**View → ASN database (.mmdb)...** is a separate picker, for a separate reason: GeoLite2-Country and GeoLite2-ASN are different MaxMind products with different record shapes, so one database cannot answer both. Supply either, both or neither — the window holds them independently, so picking one never disturbs the other.

Its picker is titled *Open a GeoLite2-ASN .mmdb database* and names the expected product on failure (**ASN database not loaded (expected GeoLite2-ASN)**), because the mistake a new user makes is picking the Country file they already have. That is not an error at all — the file loads, it simply carries no ASN records — so nothing would complain, and the column would just stay empty for a reason no dialog would otherwise explain. The title is where that gets said.

The ASN appears in the same `Country` cell as `US · AS15169 Google LLC`, because the column count is frozen at 32 (see the [CLI column reference](cli.md#column-reference)). The separator only appears when both halves are known, and the AS number is placed *before* the operator name, so a narrow window that ellipsises on overflow never hides which network the row belongs to. **Details** gives the two their own rows when you want them apart.

Its path persists on exactly the same terms as the country one, in its own `HKCU\Software\WinTCP` value: pick it once and it reloads silently, and a file that has moved fails quietly rather than nagging at every launch.

## Alerts

Threshold alerting is **off until you turn it on**, and that is the point: a
network viewer that pops a balloon every time a connection crosses a line is one
you switch off, and then it is useless for the one event that mattered.

Set it with `wintcp.exe alert --enable --bps-warn 1000000` on the command line,
or read the current state with `wintcp.exe alert`. The GUI window reads the same
settings, so a change made anywhere takes effect on the next refresh.

Each distinct condition fires **once** and then goes quiet until it clears, so a
connection sitting above the threshold does not re-notify every tick. When the
tray icon is off, an alert lands on the status bar instead of vanishing - an alert
that does nothing is worse than no alert.

### What can raise an alert

Two kinds of rule, both read and written by the `alert` verb (full grammar in the
[CLI reference](cli.md#alert)):

**Threshold rules** - a rate or a count. All optional; each is off until set, and
`0` disables it. Rates are **bytes per second**, the unit the engine applies.

| Switch | Fires when |
|---|---|
| `--bps-warn N` | A connection's rate reaches N bytes/sec. |
| `--bps-critical N` | The rate reaches the critical N. |
| `--connections N` | The connection count reaches N. |

**Event rules** - the four toggles, which default to `on, on, on, off`:

| Switch | Fires when |
|---|---|
| `--on-listener` / `--off-listener` | A new listening socket appears. |
| `--on-connection` / `--off-connection` | A new connection appears. |
| `--on-rst` / `--off-rst` | A reset (RST) is seen. |
| `--on-closed` / `--off-closed` | A connection closes. |

**Named rules** - `alert rule add --rule-name N` scopes a rule to one
`--rule-address` and/or `--rule-process`, and picks its triggers with
`--rule-on-new`, `--rule-on-close` and `--rule-on-threshold`. `alert rule list`
shows them, `alert rule remove --rule-name N` deletes one. A named rule is how
you watch *one peer* or *one program* without turning on a machine-wide
threshold.

## Windows integration

- **DPI.** Per-Monitor V2 DPI awareness via the manifest, 9 pt Segoe UI. Widths and fonts are recomputed on `WM_DPICHANGED`.
- **Theme.** There is no dark-mode toggle. The list, status bar and filter box are painted from the live system colors (`GetSysColor`) and repaint on `WM_SYSCOLORCHANGE` and `WM_THEMECHANGED`, so light, dark and high-contrast schemes work without a restart. One shared palette header (`Theme.h`) derives every self-painted surface: the Details bands, the charts background/grid and the dark substitutes (`0x202020`/`0xF0F0F0`) are single spellings now, not per-window copies.
- **High contrast.** Every window probes `HighContrastActive()` from the same header (`SPI_GETHIGHCONTRAST`) and bypasses its dark palette when it is set, deriving every colour from `GetSysColor` so the scheme's own values win. `MainWindow::ThemeIsDark` short-circuits to `false` under HC; Details, Charts, Change log and the process tree all repaint on `WM_SYSCOLORCHANGE` without a restart. The shared dark substitutes are never applied on top of an HC palette, and the charts' fixed series colours yield to the system's highlight pair under HC.
- **Tray.** Minimize-to-tray hides the window; the tray menu offers Open, Always on top and Exit; single-click (double-click works too) restores, and the first hide explains that once per run with a balloon. The tray tip names what the window holds — rows shown / total, plus grouped, frozen and alert states — instead of a fixed title. Alerts are evaluated on every refresh, after the view is rebuilt, so a balloon names rows you can actually look at. **First-run minimize prompt:** the first time you minimize while the tray icon is off, a dialog asks "Minimize to tray or exit?" and an unchecked "Don't ask me again" means it will ask again next time. The remembered choice and the tray-on flag persist in `HKCU\Software\WinTCP` as `TrayMinimizeChoice` and `TrayEnabled`.
- **Always on top** can be toggled from the menu or the tray.

## Settings and reset

Window placement, columns (mask, order, widths), sort, filter, always-on-top, tray and the database paths all persist in `HKCU\Software\WinTCP`. When a persisted layout goes wrong, **View → Reset columns & layout** restores every default the startup path uses — visible set, widths, order, `PID`-ascending sort and an empty filter — and persists the fix through the same single write path, so it survives a restart. No registry editing required.

The tree renders the main table's snapshot (taken when the window opens, re-taken on **Refresh**), over the same pure `ProcessTree` engine the `killtree` verb plans on — so the view and the verb cannot disagree about the shape. A very deep chain reports that some nodes were omitted instead of truncating silently. `Esc` or **Close** hides the window without losing the snapshot; **Refresh** re-reads the main table. An empty tree says the main table has no rows and points at refreshing it, instead of sitting blank.
