# Cookbook

← [Back to the README](../README.md)

Worked recipes for questions that a Windows user cannot answer with a single built-in command (`netstat`, `tasklist`, `taskkill`, `Get-NetTCPConnection`, `Get-Process`, `netsh`, `pktmon`), and not with the obvious two- or three-step pipeline either. Where Linux has a tool for the job it is named; where Windows has half a tool, the recipe says which half.

**How to read a recipe.** Each one gives the command, real output, and a short table explaining the switches that carry the answer and *why each is in that command*. Most tools of this kind fail silently when a switch is wrong, so knowing which switch is load-bearing for which question is the useful part, even if you never run the command.

**About the output.** Output was captured by running each command on one Windows 11 host. PIDs, process names, ports and byte totals are machine-specific and will differ on yours; the *shapes* are the point. Every recipe that can run as a standard user was run as one, and recipes that need administrator rights say so up front. Recipe numbers are stable identifiers and are not renumbered when recipes are regrouped.

Background pages: [filter language](filters.md), [CLI reference](cli.md), [traffic counters](traffic.md).

## Index

| # | Question | Admin |
|---|---|---|
| **Act on live connections** | | |
| [1](#1-close-one-connection-spare-the-process) | Close one connection without killing its process | yes |
| [2](#2-kill-the-owner-of-a-port-with-a-pid-reuse-guard) | End whatever owns a port, safely | no |
| [3](#3-block-a-peer-audit-the-rules-undo-them) | Block a peer, audit the rules, undo them | yes |
| [4](#4-a-refusal-contract-for-dangerous-actions) | What does "refused" look like to a script? | no |
| **Bandwidth and traffic** | | |
| [5](#5-who-is-using-the-network-right-now) | Who is using the network right now? | no |
| [6](#6-upload-versus-download) | Who is *sending* the most? | no |
| [7](#7-threshold-hunts-on-live-bytes) | Which processes have sent more than N bytes? | no |
| [8](#8-one-apps-total-and-the-per-socket-speed-column) | One app's total across ticks, and per-socket speed | no |
| [9](#9-per-process-rate-what-is-eating-the-link) | What is eating the link right now? | no |
| **Connection health** | | |
| [10](#10-oldest-connections-by-kernel-age) | Which connections are the oldest? | no |
| [11](#11-rtt-congestion-window-and-retransmits-ss--i-for-windows) | Which connections are slow or lossy? | no |
| **Enrichment** | | |
| [12](#12-country-watchdog-gated-on-the-answer) | Is anything talking to country X? | no |
| [13](#13-the-enriched-triage-row) | Host, country, process and bytes in one row | no |
| [13a](#13a-which-network-is-that-asn) | Whose network is this? (ASN) | no |
| [14](#14-full-dossier-for-one-connection) | Everything about one connection | no |
| **Watching for change** | | |
| [15](#15-churn-journal-and-the---event-filter) | A readable feed of connection changes | no |
| [16](#16-tcp-only-churn) | The same, without UDP noise | no |
| [17](#17-silent-watchdog-gates-for-task-scheduler) | Exit-code-only checks for schedulers | no |
| [18](#18-what-opened-while-i-was-away) | What opened while I was away? | no |
| [19](#19-a-machine-readable-change-feed) | The change feed as JSON | no |
| **Capture** | | |
| [20](#20-follow-one-stream-selected-from-the-live-row) | Capture exactly the conversation I can see | yes |
| [21](#21-bounded-scripted-capture) | A capture that starts, waits and exits on its own | yes |
| [22](#22-dry-run-the-capture-plan) | What would this capture catch? | no |
| **Inventory and audit** | | |
| [23](#23-port-owner-including-the-executable-path) | Port owner, with executable path | no |
| [24](#24-exposed-listeners-beyond-loopback) | What can the network reach on this box? | no |
| [25](#25-udp-owner-inventory) | UDP sockets and their owners | no |
| [26](#26-ipv6-udp-and-tcp-in-one-table) | IPv6, UDP and TCP in one table | no |
| [27](#27-process-table-with-cpu--and-connection-counts) | Processes with CPU % and connection counts | no |
| [28](#28-one-shot-system-health-as-json) | System health as JSON | no |
| [29](#29-the-filter-grammar-ranges-excludes-prefixes-quoting) | The filter grammar in action | no |
| **Library and automation** | | |
| [30](#30-pin-a-peer-with-a-tag-and-a-note-and-find-it-again) | Annotate a peer and find it again | no |
| [31](#31-save-and-reuse-a-triage-view) | Save and reuse a triage view | no |
| [32](#32-excel-ready-export-with-column-selection) | Excel-ready export | no |
| [33](#33-a-stable-json-schema-for-dashboards) | JSON for dashboards | no |
| [34](#34-quiet-exit-code-automation) | Exit-code automation | no |
| [35](#35-what-can-this-build-do-on-this-machine-and-what-is-missing) | What can this build do on this machine, and what is missing? | no |
| [36](#36-why-does-my-json-parser-wait-for-the-array-to-close) | Why does my JSON parser wait for the array to close? | no |

The benchmark and self-test (formerly recipes 31 and 32) are developer tools, not user features.

---

## Act on live connections

> Linux: `ss -K`, `tcpkill`, `conntrack -D`. Windows: nothing built in. Closing one connection needs `SetTcpEntry` code or a third-party tool (TCPView, WinSockKill, wKillcx).

### 1. Close one connection, spare the process

**Needs administrator rights.** `close` tears down a single socket instead of killing its owner. This is the case where "the process survives" *is* the requirement: the app is a remote-support agent, and the user wants that one session gone, not the whole agent.

```bat
wintcp.exe list --filter "process:AnyDesk.exe state:estab" --columns pid,process,local,remote,rport,state
wintcp.exe close --select "pid:5168 remote:107.155.105.90" --dry-run
wintcp.exe close --select "pid:5168 remote:107.155.105.90" --yes
```

```text
  PID  Process                      Local address                 Remote address   Remote port  State
 5168  AnyDesk.exe                  10.0.0.92                     107.155.105.90            443  ESTABLISHED

close 10.0.0.92:48433 -> 107.155.105.90:443 pid 5168
```

| Switch | Why it is in this command |
|---|---|
| `list --filter` | `--select` needs a selector that matches **exactly one** live row, so the first step is *finding* the row. Filtering is how you build that selector. |
| `list --columns` | You are reading this table to copy a selector out of it, so it needs `pid`, `process` and the **remote port**, the three things a selector can be built from. |
| `close --select` | Names *one connection* rather than a process. A PID alone is not enough: one process owns many connections, and a single socket is what you want gone. |
| `close --dry-run` | Prints the plan and changes nothing. Tells you whether your selector picked the connection you meant. |
| `close --yes` | Performs the teardown. Without it the command refuses with exit `3`. |

`close` requires elevation (a medium-integrity close of an ESTABLISHED connection fails) and handles IPv4 only: `SetTcpEntry` has no IPv6 form, so an IPv6 row is *refused with a message* rather than silently skipped.

### 2. Kill the owner of a port, with a PID-reuse guard

Replaces the `netstat -ano | findstr :8080 | taskkill /PID` chain with one atomic step that also handles a recycled PID.

```bat
wintcp.exe kill --select "local:port:49665" --dry-run
```

```text
kill: 'local:port:49665' matches 2 rows; refine to one.
:: exit code 1
```

The two rows are the IPv4 and IPv6 halves of one dual-stack listener (`0.0.0.0:49665` and `:::49665`). The refusal is the useful part: WinTCP will not guess. Add the family prefix to resolve it:

```bat
wintcp.exe kill --select "ipv4: local:port:49665" --dry-run
```

| Switch | Why it is in this command |
|---|---|
| `kill --select` | Resolves the filter to exactly one **live** row, then kills that row's owning process. "Which process holds this port" and "end it" are one step, so there is no window in which the port and the PID can disagree. |
| `kill --dry-run` | The port is often a shared service. Preview before you end someone's session server. |
| `--pid N` | The alternative selector when you already know the PID. `--select` is for "I have a port or socket", `--pid` for "I already looked it up". |

Before killing, the PID is re-validated against the process's **creation time**, so a PID that was recycled between your `netstat` and your `taskkill` is refused rather than killing an unrelated process. That window is real; it is why the `netstat | findstr | taskkill` recipe is unsafe on a busy machine, and it is the one thing the pipeline cannot do for itself.

### 3. Block a peer, audit the rules, undo them

**Needs administrator rights.** `netsh advfirewall` can add a rule but cannot tear down the live connection, and nothing pairs add with remove. `block` does both layers, `blocks` audits, `unblock` undoes.

```bat
wintcp.exe block  --select "remote:20.47.110.73 state:estab" --dry-run
wintcp.exe block  --select "remote:20.47.110.73 state:estab" --yes
wintcp.exe blocks
wintcp.exe unblock --address 20.47.110.73 --port 443 --yes
```

```text
block 10.0.0.92:41723 -> 20.47.110.73:443
wintcp-firewall-rules: 1
unblock 20.47.110.73:443
```

| Switch | Why it is in this command |
|---|---|
| `block --select` | The firewall rule is derived from the **remote** endpoint of the row you picked. You name the conversation you saw, and the tool works out both the local teardown and the outbound rule from it. You never hand-type an address and risk blocking the wrong thing. |
| `block --yes` | `block` is the most consequential verb in the tool: it kills a connection *and* writes a firewall rule. Explicit confirmation is the point. |
| `block --dry-run` | Shows what would be torn down and what rule would be created, without doing either. |
| `blocks` | Counts rules carrying the WinTCP tag, in any direction or family. `netsh advfirewall firewall show rule name=all` dumps thousands of rules; this answers "did I leave any of these behind" in one line. Exits `0`, needs no elevation. |
| `unblock --address`, `--port` | `unblock` cannot take `--select`: by the time you want to undo, the connection is usually gone, so there is no row to select. A rule's identity is address plus port, and those are what you still have. Together they name exactly the rules `block` created and nothing else. |

`blocks` finds its rules by reading a ledger at `%APPDATA%\WinTCP\blocked.txt`, one line per block, written when `block` succeeds so that a later session can still find rules the firewall enumerator omits. **A ledger that cannot be read with confidence is refused, not counted.** The count line still prints on stdout so a script keeps its number, and the reason prints on stderr:

```text
wintcp-firewall-rules: 0
the block ledger C:\Users\you\AppData\Roaming\WinTCP\blocked.txt is 4560000 bytes, over the 4194304-byte limit; refusing to load it. A real ledger holds one short line per blocked peer.
```

Read that as "unknown", never as "you have no blocks". Three things make the file untrustworthy: over **4 MiB** (a real ledger is one short line per peer, so that is tens of thousands of lines), a line over **4096 bytes**, or a line that is not valid UTF-8. The whole file is refused rather than the bad line skipped, because a skipped line is a rule name nobody recorded — and `Remove all WinTCP blocks` would then leave that rule installed with no way to find it again. The same refusal stops `block` and `unblock` from rewriting a ledger they could not read, which would drop every other rule's record.

### 4. A refusal contract for dangerous actions

No Windows tool has one. This is the recipe that makes the other three safe to script.

```bat
> wintcp.exe kill --pid 999999
kill PID 999999: refused: pass --yes to proceed (or --dry-run to preview).
:: exit code 3

> wintcp.exe kill --pid 999999 --dry-run
kill PID 999999
:: exit code 0
```

| Switch | Why it is in this command |
|---|---|
| `kill --pid` | Kills by PID directly. PID 0 and PID 4 are **always** refused (the idle process and `System`), and a recycled PID is refused after a creation-time check. Both guards live in the `--pid` path, so this recipe exercises them without needing a real target. |
| `kill --dry-run` | The safe half of the contract. The exit codes differ: `0` for "here is what would happen", `3` for "I will not do it without permission". A script can branch on *whether it was refused*, not just on success. |
| `kill --yes` | The only way past the refusal. There is deliberately no `--force`: `--yes` is not "skip a check", it is "I meant it". |

A bad target is a *different* exit code from a refusal, because they mean different things to a script:

```bat
> wintcp.exe kill --pid 4
kill: refusing PID 4: That row has no process that can be ended. PID 0 and the System pseudo-process do not own a real image.
:: exit code 2 — a bad ARGUMENT, not a missing permission
```

The full contract: **`0`** did it, **`1`** the target is gone or gone-shaped (no live row, nothing to act on), **`2`** the command line was wrong, **`3`** it was refused for want of `--yes`.

---

## Bandwidth and traffic

> Linux: `nethogs`. Windows: nothing on the CLI; Resource Monitor is GUI-only and ETW needs admin. WinTCP gives per-PID byte totals **without** elevation by duplicating socket handles and reading `SIO_TCP_INFO`, and per-**socket** rates with them. See [Traffic counters](traffic.md).

### 5. Who is using the network right now?

Including the PID, because process names lie.

```bat
wintcp.exe list --group --traffic --sort nettotal --desc --limit 4 --columns pid,process,nettotal,rx,tx
```

```text
  PID  Process                       Net total    Received        Sent
 5580  svchost.exe                     19.4 KB     12.5 KB      7.0 KB
 5168  AnyDesk.exe                      4.1 KB      1.8 KB      2.3 KB
 9128  svchost.exe                         —           —           —
 3372  svchost.exe                         —           —           —
```

| Switch | Why it is in this command |
|---|---|
| `list --group` | One row per **process** instead of per connection. The question is "who", not "which socket": a browser has 50 connections, and without grouping you get 50 rows of the same program and no answer. |
| `list --traffic` | Runs one bounded socket scan and joins the byte totals per PID. Without it every traffic cell is `—` and a `note:` on stderr says so. No elevation needed (see [Traffic counters](traffic.md)). |
| `list --sort nettotal` | Sorts by rx plus tx. For "who is using the network" the two directions together are the answer. Recipe 6 splits them. |
| `--desc` | Without it you get the *quietest* processes first: a plausible-looking wrong answer rather than an error. |
| `list --limit 4` | Combined with `--sort … --desc` this is "the top 4". |
| `--columns pid,…` | **The PID is not decoration.** `svchost.exe` appears twice above and those are two *different* processes, as is every `chrome.exe`, `brave.exe` or `firefox.exe` row on a normal desktop. A per-process table without a PID cannot be acted on: you cannot tell which instance to close, and the totals cannot be attributed. |

### 6. Upload versus download

The `--sort tx` variant answers "what is this box *sending*", which is the question that matters when you are chasing an exfiltration or a misbehaving updater.

```bat
wintcp.exe list --group --traffic --sort tx --desc --limit 4 --columns pid,process,tx,rx
```

```text
  PID  Process                           Sent    Received
 5580  svchost.exe                     7.0 KB     12.5 KB
 5168  AnyDesk.exe                     2.3 KB      1.8 KB
 9128  svchost.exe                          —           —
 3372  svchost.exe                          —           —
```

| Switch | Why it is in this command |
|---|---|
| `list --sort tx` | The only difference from recipe 5, and the whole point. `--sort nettotal` ranks by rx plus tx, which lets a big download outrank a big upload. |
| `--columns pid,process,tx,rx` | `tx` first because it is the sort key and the answer; `rx` second for context. A process sending 7 KB and receiving 12.5 MB is a downloader, not a sender. |

`--group` and `--traffic` are the same as in recipe 5: this is a re-sort of the same single scan, not a different tool.

### 7. Threshold hunts on live bytes

No Windows *or* Linux one-liner filters by live byte totals. A bare number is **MB**, `K`/`M`/`G` multiply, and `a-b` is a range.

```bat
wintcp.exe list --group --traffic --filter "tx:1KB" --sort tx --desc --columns pid,process,tx
```

```text
  PID  Process                            Sent
 6500  tailscaled.exe                 162.8 KB
 5580  svchost.exe                      7.0 KB
 5168  AnyDesk.exe                      2.3 KB
```

The unit suffix is what makes this usable: `tx:1KB` selects 162.8 KB, while `tx:1` would have meant 1 **MB** and matched nothing. That asymmetry (bare means MB, so a small threshold needs an explicit unit) is the one thing to remember.

| Switch | Why it is in this command |
|---|---|
| `list --filter "tx:1KB"` | Compares numbers, not text: "1 KB or more"; `tx:1MB-1GB` is a range. A reading that could not be taken matches *no* threshold, so a protected process cannot slip through `tx:0`. |
| `list --group` | A single connection's 900 KB is noise; a process's total is the unit of guilt. |
| `list --traffic` | The scan the filter reads. Without it the `tx:` field is empty, the filter can only answer "no match", and a `note:` on stderr tells you to add this switch. |
| `--columns pid,process,tx` | The filtered value is in the output so you can see *how far past* the threshold each row is, and the PID is there so you can act on it. |

A threshold nothing reaches is correctly empty, not an error:

```bat
wintcp.exe list --group --traffic --filter "tx:500GB" --columns pid,process,tx
```

```text
  PID  Process                            Sent
```

### 8. One app's total, and the per-socket Speed column

Two things at once, because they are the same scan: totals **accumulate** across a watch instead of restarting, and the per-connection `Speed` column finally has a source that observes a single socket.

```bat
wintcp.exe list --group --traffic --filter "process:svchost.exe" --sort tx --desc --limit 3 --columns pid,process,tx --watch 1 --count 2
wintcp.exe list --traffic --watch 2 --count 4 --sort bandwidth --desc --limit 3 --columns pid,process,remote,rport,bandwidth
```

```text
  PID  Process                            Sent
 5580  svchost.exe                      7.0 KB
 9128  svchost.exe                         —
 3372  svchost.exe                         —
  PID  Process                            Sent
 5580  svchost.exe                      7.0 KB
 9128  svchost.exe                         —
 3372  svchost.exe                         —
```

```text
  PID  Process             Remote address   Remote port  Speed
 5580  svchost.exe         172.172.255.216          443  13.2 KB/s / 6.4 KB/s
```

| Switch | Why it is in this command |
|---|---|
| `list --watch 1` | The only polling switch in the tool. A bare `list` is one snapshot and exit, so a *rate* cannot exist without two snapshots. |
| `list --count 2` | Makes the loop safe to run. `--watch` alone runs until Ctrl+C, which is fine interactively and a hang in a script. |
| `list --sort tx` vs `--sort bandwidth` | `tx` is cumulative bytes sent; `bandwidth` is the *per-connection* bytes per second between two samples. Different questions: "who sent the most" versus "which socket is busy now". |
| `list --traffic` | The scan, once per tick. Reused across ticks, so the second tick's numbers are deltas of the first rather than an unrelated fresh measurement. |
| `--columns …,bandwidth` | Requests the Speed column. It is only populated from the **per-socket** source: a per-PID total divided by its connection count would be an invented number, so those rows keep `—`. Asking for the column without `--traffic` gets a `note:` on stderr naming the missing switch. |

The `—` rows in the first table are not broken. Those PIDs' sockets did not answer `SIO_TCP_INFO` during the scan, so their counters keep their last known values. The usual reason is not a stall at all: most sockets on a busy machine are UDP, to which `SIO_TCP_INFO` does not apply, so they answer instantly with `WSAENOTSOCK`. A genuine stall costs only its own reading; see [Stalled sockets](traffic.md#stalled-sockets).

### 9. Per-process rate: what is eating the link?

`bandwidth` is one socket's rate. A browser with 40 tabs has 40 rows, each small; the useful answer is the sum, which is `procspeed`.

```bat
wintcp.exe list --traffic --watch 1 --count 3 --filter "state:estab" --columns process,bandwidth,procspeed --limit 8
wintcp.exe list --traffic --group --sort procspeed --desc --limit 6 --columns pid,process,procspeed
```

```text
 Process                      Rate                            Process rate
 AnyDesk.exe                  idle                            idle
 svchost.exe                  idle                            idle
 cline.exe                  idle                            idle
```

```text
Process                      Rate                            Process rate
AnyDesk.exe                  idle                            idle
Avira.Spotlight.Service.exe  —                               —
svchost.exe                  idle                            idle
wslrelay.exe                 —                               —
tailscaled.exe               —                               —
cline.exe                    idle                            idle
```

```text
  PID  Process                      Process rate
 6500  tailscaled.exe               ↓ 0 B/s  ↑ 365 B/s
 20868  brave.exe                    idle
  6436  wslrelay.exe                 idle
  5404  jhi_service.exe             idle
```

Rows showing `—` in both columns are processes whose traffic came from the ETW path or whose sockets the scan could not read. `—` means *unknown*; `idle` means *measured, and nothing moved*.

| Switch | Why it is in this command |
|---|---|
| `list --traffic` | **Required.** The socket scan supplies the per-socket counters; without it both rate columns are dashes. |
| `--filter "state:estab"` | Not cosmetic. `TIME_WAIT` and wildcard rows have no owning process and can never carry a per-socket rate; including them fills the table with permanent dashes and hides the rows that have answers. |
| `--watch 1 --count 3` | A rate is a *difference*. One snapshot cannot have one, so the first tick shows dashes by design and the second shows the answer. |
| `procspeed` | The **process's** bytes per second, summed over its sockets. Differs from `bandwidth` exactly where you care: `tailscaled` shows the same figure in both because that socket *is* the process's traffic, while a browser's per-socket figures are a fraction of its total. |
| `list --group` | One row per process. Here `procspeed` is the column that makes sense and `bandwidth` deliberately shows `—`. |
| `--sort procspeed --desc` | Ranks by what the process is doing *now*, not by its lifetime total. |

Why `procspeed` is a sum, and why ETW-sourced processes show `—`, is explained in [Traffic counters](traffic.md#per-process-rate).

---
## Connection health

> Windows has no built-in view of what the TCP stack concluded about a connection. `netstat` has no notion of latency or age, `Get-NetTCPConnection` has neither, and `pktmon` gives you packets without summarising anything. Linux: `ss -i`.

### 10. Oldest connections by kernel age

`netstat` shows no age at all, and PowerShell still cannot range-filter a `CreationTime` pipeline.

```bat
wintcp.exe list --traffic --sort duration --desc --limit 4 --columns pid,process,remote,rport,duration
wintcp.exe list --traffic --filter "duration:1h" --sort duration --desc --limit 4 --columns pid,process,remote,rport,duration
```

```text
  PID  Process                      Remote address   Remote port      Duration
 5580  svchost.exe                  172.172.255.216          443        4h 12m
```

Both commands print the same single row on this machine. The reason is explained below.

| Switch | Why it is in this command |
|---|---|
| `list --traffic` | **Required** for `duration`. The ages come from the kernel (`SIO_TCP_INFO`'s `ConnectionTimeMs`) via the same socket scan as the traffic columns, so a single-shot run already knows them. Without `--traffic` the column reads `0s` for everything, because there is no age source. |
| `list --sort duration --desc` | Oldest first. Ascending gives youngest-first, which is the useful default for "what just happened" and useless for "what has been squatting on this port". |
| `list --filter "duration:1h"` | A threshold in **seconds** with `s`/`m`/`h`/`d` suffixes, and ranges. Note the asymmetry with the byte fields: a bare `duration:3600` is 3600 **seconds**, while a bare `mem:100` is 100 **MB**. |
| `--columns …,duration` | `pid` and `remote` are there so you can act on what you find; `rport` distinguishes two long-lived connections to the same host. |

**A current limitation.** Ages come from the same scan as the traffic columns, and a socket whose `SIO_TCP_INFO` does not return cannot be measured at all. That is why the table above has one row and not four. Such a socket now costs only its own reading, not every socket behind it (see [Stalled sockets](traffic.md#stalled-sockets)), so the ranking is real but may not be complete. The GUI reports the count. Rows with no age never match `duration:`, so the filter returns fewer rows than the table shows rather than pretending the unmeasured ones are new.

### 11. RTT, congestion window and retransmits: `ss -i` for Windows

These four numbers are the kernel's own verdict on each connection, and they are what you want when a link feels slow: a high RTT with a small congestion window is a *path* problem, while a small RTT with a large one is a *bandwidth* problem. The values come out of the same `SIO_TCP_INFO` call as the byte counters, so there is no extra scan and no extra cost.

Slowest round trips first:

```bat
wintcp.exe list --traffic --sort rtt --desc --limit 4 --columns process,remote,rport,rtt,minrtt,cwnd,retrans
```

```text
Process                      Remote address   Remote port        RTT    Min RTT          Cwnd       Retrans
chrome.exe                   74.6.160.107             443         30         20       21.2 KB           0 B
brave.exe                    185.199.110.133          443         17         15       16.6 KB           0 B
cline.exe                    127.0.0.1              19536         <1          -       63.8 KB           0 B
```

Most data lost to retransmission first:

```bat
wintcp.exe list --traffic --sort retrans --desc --limit 4 --columns process,remote,rport,rtt,minrtt,cwnd,retrans
```

```text
Process                      Remote address   Remote port        RTT    Min RTT          Cwnd       Retrans
chrome.exe                   157.90.91.72             443        219        165       21.3 KB        4.5 KB
Telegram.exe                 149.154.167.92           443        235        171       21.8 KB        2.8 KB
brave.exe                    140.248.153.91           443         25          6       23.8 KB         768 B
chrome.exe                   100.26.11.145            443         83         63       33.3 KB         232 B
```

Yours will usually be thinner than this. `--traffic` reports what the kernel hands back per socket, and most rows are listening, closing or not TCP at all, so they carry an em-dash rather than a number; only a handful of connections per run answer at all. That em-dash means *not measured*, never *zero*, which is why `cwnd:` and `rtt:` as bare selectors mean "has a reading" and deliberately select nothing else.

Read it as the diagnostic it is: the two rows losing the most to retransmission (4.5 KB and 2.8 KB) also have the **highest** RTTs, 219 ms and 235 ms, while the two below them have retransmitted almost nothing and sit at 25 ms and 83 ms. Those first two are losing packets on the path, and no amount of bandwidth will fix it.

Both columns can also be used as thresholds:

```bat
wintcp.exe list --traffic --filter "rtt:100" --sort rtt --desc --limit 4 --columns process,remote,rport,rtt,minrtt,cwnd,retrans
```

```bat
wintcp.exe list --traffic --filter "retrans:1KB" --sort retrans --desc --limit 4 --columns process,remote,rport,rtt,minrtt,cwnd,retrans
```

| Switch | Why it is in this command |
|---|---|
| `list --traffic` | **Required.** Runs the socket scan that supplies all four values. |
| `list --sort rtt --desc` | Worst latency first, the useful direction: ascending would put the fastest connection on top, the answer to no question anyone asks. Unmeasured rows sort last, so dashes never crowd out the top of the list. |
| `list --filter "rtt:100"` | Threshold in **milliseconds**: "100 ms or worse". It is a number, not a substring of the printed cell, so it cannot be fooled by a process name containing the digits. |
| `list --filter "retrans:1KB"` | Threshold in **bytes**. Retransmits are cumulative and monotonic, so this means "this connection has lost at least this much", usually the single most diagnostic number here and one no Windows tool reports. |
| `--columns …,rtt,minrtt,cwnd,retrans` | The four `ss -i` fields, named so the two tools can be read side by side. In the GUI they are in *View ▸ Columns*, hidden by default. |

Three value rules matter more than they look (details in [Traffic counters](traffic.md#tcp-health-rtt-minimum-rtt-congestion-window-retransmits)): RTT columns are in **milliseconds** although the kernel reports microseconds, a sub-millisecond RTT prints `<1` rather than a physically impossible `0`, and zero retransmits prints `0 B` because "never retransmitted" is a real answer, not a missing one.

---

## Enrichment

> Linux: `lsof` links socket to process only. Nothing on either platform joins DNS, country, process, bytes and a bookmark into one row.

### 12. Country watchdog, gated on the answer

Requires a `.mmdb` database you supply (see [GeoIP database](../README.md#geoip-database)). This recipe is the shape; the `geoip` sub-commands check the database first.

```bat
wintcp.exe geoip info --db GeoLite2-Country.mmdb
wintcp.exe list --db GeoLite2-Country.mmdb --filter "country:US" --columns remote,country,process --limit 3
wintcp.exe list --db GeoLite2-Country.mmdb --filter "country:US" --quiet && echo us-traffic
```

| Switch | Why it is in this command |
|---|---|
| `geoip info --db` | The first question about any `--db` recipe is "is this file even the thing I think it is". Without it, an empty `country` column is ambiguous between "no database" and "database with no entry for this address". |
| `list --db FILE` | Loads the `.mmdb` and joins country codes for the **printed** rows. A memory map and a binary search, not a network call, but still per printed row, which is why the recipe pairs it with `--limit`. |
| `list --filter "country:US"` | Matches on the joined country code. This is why `country` is in `--columns`: a filter on a value the column is displaying. |
| `list --quiet` | Zero bytes; exit `0` if and only if a row matched. `&& echo us-traffic` turns a question into a scriptable predicate. |
| `--columns remote,country,process` | When the gate *fails* you need to see why, and a bare exit code tells you nothing. |

Two deliberate limits: addresses that are not globally routable (loopback, RFC 1918, CGNAT, link-local, multicast) never get a country, and a country nothing is connected to returns an empty table, not an error.

### 13. The enriched triage row

`netstat` for the socket, `nslookup -x` for the name, a GeoIP database for the country, Task Manager for the process: four tools, four hand-made joins, and the joins are where hand-rolled pipelines go wrong.

```bat
wintcp.exe list --dns --db GeoLite2-Country.mmdb --traffic --filter "state:estab" --limit 4 --columns remote,host,country,process,nettotal
```

```text
Remote address    Hostname                                                   Country   Process                      Net total
107.155.105.90    relay-5d111ddb.net.anydesk.com                            —        AnyDesk.exe                  4.1 KB
52.38.112.215     ec2-52-38-112-215.us-west-2.compute.amazonaws.com         US        brave.exe                   —
100.26.11.145     ec2-100-26-11-145.compute-1.amazonaws.com                 —        chrome.exe                  —
```

| Switch | Why it is in this command |
|---|---|
| `list --dns` | Blocking reverse DNS for the **printed** rows only. The expensive switch, so it is bounded by `--limit`; without that the recipe would stall on every remote on the machine. |
| `list --db FILE` | Joins the country. A memory-mapped lookup with no network, so the cost is dominated by DNS. |
| `list --traffic` | The third join. It runs **before** sorting, so `--sort nettotal` orders real totals rather than zeros. |
| `list --filter "state:estab"` | Not cosmetic. The unfiltered head of this table is `TIME_WAIT` and wildcard rows whose enrichment columns are legitimately empty, which makes the example look broken. |
| `--limit 4` | The cost control for `--dns`. A `note:` on stderr appears when a printed enrichment column cannot be filled, naming the missing switch. |
| `--columns remote,host,country,process,nettotal` | The five columns the four tools would each give you. `host` and `country` can be empty *honestly*: an address in no database, or a peer whose PTR record does not resolve, is a real answer. |

#### 13a. Which network is that? (ASN)

`country` answers *where*; the autonomous system answers *whose*. The country code comes from GeoLite2-Country and the AS number and operator from GeoLite2-ASN, so they are two files and two switches. The ASN rides in the `country` cell - `US · AS15169 Google LLC` - because the column count is frozen at 32.

```bat
REM every row that has an autonomous system at all
wintcp.exe list --db GeoLite2-Country.mmdb --asn-db GeoLite2-ASN.mmdb ^
  --filter "asn:" --columns remote,country,process --limit 10

REM one operator, by name - case-insensitive, matches the whole cell
wintcp.exe list --asn-db GeoLite2-ASN.mmdb --filter "asn:cloudflare" --limit 10

REM a numeric RANGE on the AS number, which is a threshold and not a substring
wintcp.exe list --asn-db GeoLite2-ASN.mmdb --filter "asn:15169-20000" --limit 10
```

| Switch | Why it is in this command |
|---|---|
| `--asn-db FILE` | The GeoLite2-ASN database. Separate from `--db` because the two are different products with different record shapes; supply either, both or neither. |
| `--filter "asn:..."` | A bare number is a threshold on the AS number and accepts ranges; anything else is a substring of `AS<n> <org>`, so both "which AS is this" and "who runs this" are one field. |
| `--columns ... country ...` | The ASN shares the `country` cell. `details` gives it its own `AS number` and `AS organisation` rows when you want them apart. |

Two honest limits, the same as the country recipe: an address that is not globally routable never gets an ASN, and an address no database covers leaves the cell as the country alone rather than inventing one.

### 14. Full dossier for one connection

`details` refuses anything that is not exactly one live row. It will not guess which of 60 connections you meant.

```bat
wintcp.exe details --select "pid:19080 lport:52425 proto:tcpv4" --traffic
```

```text
putty.exe
PID 19080   ·   127.0.0.1:52425  →  127.0.0.1:22

Process
Name                    putty.exe
PID                     19080
Path                    C:\Program Files\PuTTY\putty.exe
Command line            putty &000000000000061C:6214
Started                 2026-10-03 15:49:02
Service                 —
First seen              2d 3h

Threads (5)
TID 30668               cpu 18.95 s   started 2d 3h ago   pri 8
TID 35204               cpu 0.50 s   started 2d 3h ago   pri 9
TID 49116               cpu 0.02 s   started 1d 1h ago   pri 8
TID 27124               cpu 0.00 s   started 1d 1h ago   pri 8
TID 37412               cpu 0.00 s   started 1d 1h ago   pri 8
  sampled 0s ago; CPU time is total since each thread started, not since this window opened.

Live stats (this refresh)
CPU                     0.0 %
Memory (working set)    27.3 MB
Memory (private)        7.9 MB
Disk read               236.6 KB
Disk written            343 B
Disk total              237.0 KB
Network received        3.9 MB
Network sent            208.9 KB
Network total           4.1 MB

Selected connection
Protocol                TCPv4
Local                   127.0.0.1:52425
Remote                  127.0.0.1:22
State                   ESTABLISHED
Hostname                —
Duration                2d 3h

Connections (1)
  TCPv4  127.0.0.1:52425   127.0.0.1:22  (ESTABLISHED)
```

The **Threads** section is the one worth stopping at. It lists every thread the process
owns, **ranked by CPU time**, because that ordering is the answer to "what is this
process doing" - `TID 30668` has burned 19 s and the other four have barely started.
Three things in that section are deliberate and each prevents a misreading:

- **`cpu` is total since that thread started**, not since this window opened. The
  note under the list says so, because "18.95 s" beside a window you opened ten
  seconds ago otherwise reads as a rate, and would be a startling one.
- **Threads with unreadable times show `-`, not `0`, and sort last.** That is a
  real condition for protected processes; printing `0.00 s` would be a fabricated
  measurement rather than an admission of ignorance.
- **There is no per-connection thread, because Windows has none.** A socket is
  owned by the process, not a thread, which is why the section is attached to the
  process rather than to a row. See [the GUI guide](gui.md#threads) for why no
  Thread column is possible at all.

| Switch | Why it is in this command |
|---|---|
| `details --select` | Exactly one connection, or exit `1`. A dossier for "the connection you probably meant" out of 60 is worse than none, because it is confidently wrong. Ambiguity and no-match both exit `1` with the count or the reason. |
| `details --traffic` | Fills the network received/sent/total lines and the rate. The live-stat block is per process, so without it you get CPU and memory but an empty network section. |
| `details --db FILE` | Fills the country. The report already names the endpoint; `geoip lookup` is the right tool for a one-off address question. |

The `Connections (1)` block is the part no other tool gives you: the other endpoints owned by the same PID. It is how you notice that an "AnyDesk connection" is one of four, or that a process you did not recognise holds a listener.

---

## Watching for change

> Linux: `conntrack -E`. Windows: nothing built in streams events; you poll and diff by hand, and the diff is where it goes wrong.

### 15. Churn journal, and the `--event` filter

An unfiltered event feed on a normal desktop is dominated by socket closes, so the switch that selects *kinds* is the difference between a usable feed and noise.

```bat
wintcp.exe list --watch 1 --changes --event appear,state --count 4
```

```text
baseline: 286 rows (further changes below)
[2026-09-30 14:44:50] APPEAR TCPv4 10.0.0.92:6383 -> 64.59.144.91:53 (SYN_SENT) pid=28276 chrome.exe
[2026-09-30 14:44:51] APPEAR TCPv4 10.0.0.92:6383 -> 64.59.144.91:53 (TIME_WAIT) pid=0 —
[2026-09-30 14:44:52] STATE  TCPv4 10.0.0.92:41723 -> 20.47.110.73:443 (CLOSE_WAIT) pid=5172 Avira.Spotlight.Service.exe
```

| Switch | Why it is in this command |
|---|---|
| `list --changes` | Prints only APPEAR / DISAPPEAR / STATE deltas instead of full snapshots. Without it you get the same 300 rows every second and the diff is yours to compute. |
| `list --watch 1` | The delta is computed between two snapshots, so the interval **is** the sensitivity: at 1 s you catch short-lived sockets, at 10 s you miss them entirely. |
| `list --event appear,state` | Which kinds to print, from `appear,disappear,state`. `--event appear` alone answers "what opened while I was away" and drops the close stream that would otherwise bury it. Comma-separated, any order, case-insensitive; an unrecognised name exits `2`. |
| `list --count 4` | Bounds the loop. It counts **snapshots, not events**: on a busy machine four snapshots can emit hundreds of lines, so pipe through `head` if you need exactly N. |
| `list --filter` | Applied to the event's row, not the table, so every clause works (recipe 16 uses it to remove UDP). |

The `baseline:` line goes to **stderr**, so `> file` captures only events. That is a contract, not a detail: an event pipe with a human sentence in it is not a pipe.

### 16. TCP-only churn

Skip the UDP socket noise that otherwise dominates.

```bat
wintcp.exe list --watch 2 --changes --filter "proto:tcp" --count 5
```

```text
baseline: 286 rows (further changes below)
[2026-09-30 13:45:37] DISAPPEAR TCPv4 10.0.0.92:17796 -> 74.6.160.106:443 (ESTABLISHED) pid=28276 chrome.exe
[2026-09-30 13:45:37] STATE  TCPv4 127.0.0.1:49374 -> 127.0.0.1:29543 (ESTABLISHED) pid=22180 cloudflared.exe
```

| Switch | Why it is in this command |
|---|---|
| `list --filter "proto:tcp"` | The filter runs against each event's row, so it removes whole events rather than hiding lines after the fact. On the capture machine mDNS alone is about 86 rows that change constantly. |
| `list --watch 2` | A slower interval than recipe 15 on purpose: fewer events, and a different view of what "churn" means at 2 s granularity. |

`--event` is available but not needed here: the filter already does the narrowing, and adding `--event` would be a second tool for one job.

### 17. Silent watchdog gates for Task Scheduler

No output at all. The exit code is the answer, and it is the *only* answer.

```bat
wintcp.exe list --filter "port:443" --quiet && echo someone-is-on-https
wintcp.exe list --filter "port:443" --quiet || echo nothing-on-https
```

```text
someone-is-on-https
:: exit code 0
```

| Switch | Why it is in this command |
|---|---|
| `list --quiet` | Prints **nothing**; exit `0` if any row matched, else `1`. It is a zero-byte contract on *both* streams (no header, no advisory hints) so it is safe in a scheduled task whose output nobody reads. |
| `list --filter "port:443"` | The predicate. It uses the full filter grammar, so a gate can be as precise as the investigation: `pid:1234 state:estab`, `process:svchost service:Dnscache`, `note:vendor`. |
| `&&` / `\|\|` | The shell is the control flow. This is why the exit-code contract is documented rather than incidental: it is the public interface. |

**The trap.** A predicate nothing can answer looks identical to one that matched nothing. `list --filter "host:cdn"` returns *no rows*, not because nothing matched but because reverse DNS never ran, and in `--quiet` mode the hint that would say so is suppressed along with everything else. For a filter on an enrichment column, add the switch it depends on (`--dns`, `--db`, `--traffic`) or the gate silently answers the wrong question.

### 18. What opened while I was away

The longest-running form, and the one that answers "did that installer just start something".

```bat
wintcp.exe list --watch 1 --changes --event appear --count 30 --filter "proto:tcp state:estab"
```

| Switch | Why it is in this command |
|---|---|
| `list --event appear` | Only APPEAR events. Without it the closes bury the opens: the single most valuable use of the feed and the reason `--event` exists. |
| `list --filter "proto:tcp state:estab"` | Two clauses AND-ed. `state:estab` makes it readable: `SYN_SENT` and `TIME_WAIT` rows are noise in a "what started" question, and a `TIME_WAIT` row is reported with `pid=0` because the owning process is already gone. |
| `list --watch 1` | As short as is useful. A short-lived connection must be caught between two snapshots or it does not exist. |
| `list --count 30` | 30 snapshots is roughly 30 seconds: the "while I was away" window, and the bound. Larger values lengthen the run linearly. |

The output is a log of what the machine *did*, with a process name and a PID on every line, which polling `Get-NetTCPConnection` in a loop cannot give you without writing a diff engine.

### 19. A machine-readable change feed

```bat
wintcp.exe list --watch 2 --changes --event appear,state --format json --count 5 2>nul
```

```json
{"t":"2026-09-30 14:44:50","event":"appear","proto":"TCPv4","local":"10.0.0.92","lport":6383,"remote":"64.59.144.91","rport":53,"state":"SYN_SENT","pid":28276,"process":"chrome.exe"}
{"t":"2026-09-30 14:44:51","event":"appear","proto":"TCPv4","local":"10.0.0.92","lport":6383,"remote":"64.59.144.91","rport":53,"state":"TIME_WAIT","pid":0,"process":"—"}
{"t":"2026-09-30 14:44:52","event":"state","proto":"TCPv4","local":"10.0.0.92","lport":41723,"remote":"20.47.110.73","rport":443,"state":"CLOSE_WAIT","old_state":"ESTABLISHED","pid":5172,"process":"Avira.Spotlight.Service.exe"}
```

| Switch | Why it is in this command |
|---|---|
| `list --format json` | One JSON object **per line** (NDJSON), not the array of recipe 33. Deliberately: an event stream is consumed incrementally, so a line-at-a-time format can be piped into a reader that never buffers the whole thing. |
| `list --event appear,state` | The switch that makes the feed usable at scale, as in recipe 15. |
| `list --watch 2` | Also the **sensitivity**: a socket that opens and closes inside the interval is never seen. Choose it against the shortest event you care about. |
| `2>nul` | Drops the human-readable stderr baseline line so the data stream stays pure. |

`--count` bounds watch *ticks*, not emitted events, so a busy machine produces far more lines than 5. Types follow recipe 33 with one deliberate difference: `lport`, `rport` and `pid` are JSON **numbers** here (an event is a machine record and a consumer will compare them), and a `state` event adds `old_state` so the transition is visible rather than inferred from two records.

---

## Capture

> Linux: `tcpdump` plus `tshark -z follow`. Windows: `pktmon` cannot filter by process and has no reassembly or follow view at all.

### 20. Follow one stream, selected from the live row

**Needs administrator rights.** The capture filter is derived from the row you can see, so the capture is provably the right conversation.

```bat
wintcp.exe list --filter "state:estab exclude:127." --columns pid,process,local,remote,rport,state --limit 3
wintcp.exe capture --select "pid:5172 remote:20.47.110.73 remote:port:443" --secs 8 --text --dir first --yes
```

`--dry-run` stops after printing the plan, so you can see which conversation the selector picked before spending the window on it. Run once by hand, and this is the line:

```text
capture 10.0.0.92:16921 -> 20.47.110.73:443 for 8s
mode: print the reassembled stream to stdout
```

The real run prints that same plan, then a summary once the window closes:

```text
packets=<n> toServer=<n> toClient=<n> blocks=<n>
```

`toServer` and `toClient` are the reassembly result in each direction; `blocks` is the number of TCP segments parsed.

Every run also prints `tls:` lines, and that is the one place WinTCP can report a TLS session at all: Windows has no socket-level TLS ioctl, so the only source is the handshake, and the handshake is readable precisely because TLS sends it in the clear. Here is a real capture of an established HTTPS connection on one Windows 11 host:

```text
packets=1918 toServer=0 toClient=346685 blocks=4345
tls: the capture is TLS but no handshake message is among the captured bytes, so no SNI, version or cipher can be reported - the window opened after the session was established.
tls: to first endpoint ([2604:3d08:5d8a:f000:cffe:9c3c:8201:712b]:36677) captured no payload
tls: from first endpoint ([2606:4700::6810:7c60]:443) begins with TLS records but no handshake message was captured (the window opened after the handshake) | 346230 bytes of application_data after the handshake
```

Read that as a limitation of *where the window fell*, not as a verdict on the connection. `pktmon` records only what happens after the filter is armed, so on a connection that was already up the handshake was never captured and no SNI exists to report. **To get an SNI you must capture a connection that is being established** - which is why this recipe starts with a `list`, so you can catch a row while it is still young. The four possible reports, and what each one is allowed to claim, are tabulated in the [CLI reference](cli.md#reading-the-tls-handshake).

Note the `toServer=0` in that output: only the response direction carried bytes inside the window. A direction that captured nothing is named rather than omitted, because "one side of this connection has no bytes" would otherwise be indistinguishable from "we only looked one way".

Two things stop it before any of that, and both exit 1 with the reason rather than an empty table. They are worth knowing because the selector in the first line is exactly how you meet them:

- **Loopback.** `pktmon` does not capture `127.0.0.1` or `::1` at all, so a selector that resolves to a loopback connection reports *the capture produced no packets* and then names loopback as the cause. This is the trap recipe 24 warns about: `exclude:127.` drops `127.` but leaves `::1` rows in the list, and a `::1` row always fails here.

- **Idle.** No packets inside the window exits 1 with *No packets for this connection were captured*, blaming either a quiet conversation or one established before the capture began. Pick a busier row or lengthen `--secs`.

Reassembly stops at a per-direction byte cap. A stream that reaches it reports the cap, and the summary then carries a note naming the direction that stopped: *that byte count is truncated - a floor, not a total.* Read it as "at least this much", never as the size of the stream. Without the note, a count of exactly the cap looks like a measurement.

| Switch | Why it is in this command |
|---|---|
| `capture --select` | `pktmon` filters on ports and addresses, not on process, so the process-to-4-tuple step is the whole added value. It is the same step you do by eye in recipe 1. |
| `capture --secs 8` | A **fixed** window of 1 to 60 seconds (default 5), not an interactive one. The command starts, waits, stops and exits on its own, which is what makes it scriptable. |
| `capture --text` | Prints the reassembled stream to stdout, which is the point of the recipe - the counters alone tell you the capture happened, not what was said. |
| `capture --dir first` | One direction instead of both, so a request/response exchange is readable in order rather than interleaved. |
| `capture --out c:\tmp\stream.pcapng` | Keeps the capture as pcapng for Wireshark, when you want the packets rather than the reassembled bytes. |
| `capture --yes` | Confirms, because it installs a global capture filter and starts a capture. Same refusal contract as recipe 4. |
| `capture --dry-run` | Prints the plan (`capture <local> -> <remote> for Ns`) and touches nothing: one line that tells you whether the selector picked the socket you meant before you spend 8 seconds on the wrong one. |

The packet-size limit is disabled in the underlying `pktmon` run, because the default truncates each packet and a truncated stream cannot be reassembled. The filter is always removed afterwards, even on failure, so an abandoned capture cannot skew a later one.

#### Reading the bytes

Add `--text` and the summary is followed by one hex block per direction, each headed by the **endpoint that sent it**:

```text
--- to first endpoint: 10.0.0.92:16921 ---
00000000  47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a  |GET / HTTP/1.1..|
00000010  48 6f 73 74 3a 20 65 78  61 6d 70 6c 65 2e 63 6f  |Host: example.co|
00000020  6d 0d 0a 43 6f 6e 6e 65  63 74 69 6f 6e 3a 20 6b  |m..Connection: k|
00000030  65 65 70 2d 61 6c 69 76  65 0d 0a 0d 0a           |eep-alive....|
```

Three details in that output are deliberate, and each of them prevents a specific misreading:

- **The heading names an endpoint, not `client` or `server`.** `pktmon` does not reliably report which end sent the SYN, so those words would be a claim the capture cannot support. The two headings can therefore arrive in either order, and that is not a bug.
- **The offsets are that direction's own stream offsets**, so they line up with the TCP sequence base. Line `00000010` is 16 bytes into that direction, not into the capture.
- **A `NOTE:` line comes before the bytes, never after.** A gap in a reassembled stream silently corrupts every decode after it, so the note is placed where a reader who stops early still sees it.

The ASCII gutter uses `.` for every non-printable byte, the `hexdump(1)` convention, so the right-hand column is comparable at a glance across many lines.

`--out` writes the capture **byte-for-byte** as pcapng while it is still on disk, so the file you get is the file that was parsed - not a re-serialisation that could differ. It opens in Wireshark or `tshark` with no conversion step.

### 21. Bounded scripted capture

One atomic run, where `pktmon` needs a manual start, a stop and an `etl2pcap`.

```bat
wintcp.exe capture --select "pid:22180" --secs 5 --yes
```

| Switch | Why it is in this command |
|---|---|
| `capture --select "pid:22180"` | The coarse form: select by PID alone. Valid whenever the process has exactly one live TCP row; an ambiguous selector is refused rather than capturing the wrong stream. |
| `capture --secs 5` | The window. Fixed, so the whole run is `5 s + convert + parse` with no interaction: the difference between a job that finishes and a job that waits forever. |
| `capture --yes` | Required; without it, exit `3`. |

### 22. Dry-run the capture plan

No tool shows its plan. This one prints it, changes nothing, and refuses a plan that would catch more than one stream.

```bat
wintcp.exe capture --select "proto:tcp state:estab" --dry-run
```

```text
capture: 'proto:tcp state:estab' matches 47 rows; refine to one.
:: exit code 1
```

| Switch | Why it is in this command |
|---|---|
| `capture --dry-run` | Resolves the selector, prints the plan, changes nothing. The refusal **is** the output here: capturing 47 streams and calling it "the one I asked for" is how a follow-stream view ends up showing the wrong conversation. |
| `capture --select` | Deliberately over-broad, to demonstrate the guard. |

The plan and the `--yes` gate come **before** the elevation check, so a dry run never demands elevation and a refusal never does either.

---
## Inventory and audit

> One table where Windows needs two to four tools.

### 23. Port owner, including the executable path

`netstat` gives a PID only, and `tasklist` has no port link at all.

```bat
wintcp.exe list --filter "state:listen lport:445" --columns process,path,pid,local,state
```

```text
Process                      Path                                                                                                       PID  Local address                            State
System                       System                                                                                                       4  0.0.0.0                                  LISTENING
System                       System                                                                                                       4  ::                                       LISTENING
```

| Switch | Why it is in this command |
|---|---|
| `list --filter "state:listen lport:445"` | Two clauses AND-ed: state **and** local port. The port is qualified as `lport:` rather than `port:` on purpose: `port:445` would also match a row *connecting out* to a remote 445, which is a different question. |
| `--columns process,path,pid,local,state` | `path` is the column `netstat` cannot give you. `netstat -b` gives a service name and needs admin; `tasklist /v` gives no path for a `System` row. One command answers "what is listening, where does it live, and what is its PID". |

Two rows, not one: a dual-stack listener is **one socket reported once per family**, exactly as `netstat` does. That is also why a bare port selector is ambiguous for a listener (recipe 2).

### 24. Exposed listeners beyond loopback

Neither `netstat` nor `tasklist` can filter at all, and this is the security question people actually have: *what is this box listening on that the network can reach?*

```bat
wintcp.exe list --filter "state:listen exclude:127." --sort lport --columns pid,process,lport,local --limit 8
```

```text
  PID  Process                      Local port  Local address
 6436  wslrelay.exe                         22  ::1
 6436  wslrelay.exe                         80  ::1
 1940  svchost.exe                         135  0.0.0.0
 1940  svchost.exe                         135  ::
    4  System                              139  10.0.0.92
    4  System                              139  169.254.123.200
    4  System                              139  169.254.123.251
    4  System                              139  169.254.123.36
```

| Switch | Why it is in this command |
|---|---|
| `list --filter "state:listen exclude:127."` | Only LISTENING rows, minus anything containing `127.`. This is a **substring** exclusion, not "not loopback": the IPv6 loopback prints as `::1`, which `exclude:127.` does not catch, and `::1` rows are visible in the output above. The filter grammar composes, so the predicate can be as precise as the question; for a strict loopback exclusion, filter on the address and read the result. |
| `list --sort lport` | Ports are the readable order for a listener audit: you scan for gaps and known services. `--sort` also takes `state`, `pid`, `process` and every column name. |
| `--columns pid,process,lport,local` | `local` is what makes it a security question. `0.0.0.0` is reachable from the network; `127.0.0.1` and `::1` are not; `169.254.x`, `10.x` and `172.16-31.x` are reachable only from their segment. Without the column you cannot tell which rows matter. |
| `list --limit 8` | Sorting by `lport` first and then limiting is the "give me the low ports" pattern. |

The dual-stack duplication shows again: `135` on `0.0.0.0` and `::` is one socket in two families, so a port count from this table is not a count of sockets. `Get-NetTCPConnection` has the same duplication and no filter to remove it.

### 25. UDP owner inventory

`netstat -b` is slow, needs admin, and gives service names without PIDs for half the rows.

```bat
wintcp.exe list --filter "proto:udp" --columns process,pid,local,lport,proto --limit 5
```

```text
Process                        PID  Local address                 Local port  Proto
System                           4  10.0.0.92                            137  UDPv4
System                           4  10.0.0.92                            138  UDPv4
System                           4  169.254.123.200                       137  UDPv4
System                           4  169.254.123.200                       138  UDPv4
System                           4  169.254.123.251                       137  UDPv4
```

| Switch | Why it is in this command |
|---|---|
| `list --filter "proto:udp"` | UDP rows only. UDP has no state: the table prints `—`, and the remote as `*:*`, as `netstat` does. That is why `state` is not in `--columns`: a column of dashes is worse than no column. |
| `--columns process,pid,local,lport,proto` | `proto` prints `UDPv4` / `UDPv6` rather than a generic `UDP`, which is what makes a UDP inventory readable: otherwise a dual-stack listener looks like two services. |
| `list --limit 5` | UDP tables are long (mDNS alone is about 86 rows on the capture machine). |

`netstat -ab` is the built-in that comes closest, and it is the reason this recipe exists: it is too slow to use in a loop, it needs elevation for the `-b` part, and it prints the service name rather than the owning process and PID, which is what you need to act.

### 26. IPv6, UDP and TCP in one table

`Get-NetTCPConnection` is TCP-only, and `netstat` splits its output by family and protocol into sections you read separately.

```bat
wintcp.exe list --filter "proto:ipv6" --columns proto,process,local,lport,state --limit 5
```

```text
Proto  Process     Local address   Local port   State
TCPv6  System      ::               445          LISTENING
TCPv6  System      ::               5357         LISTENING
TCPv6  wininit.exe ::               49665        LISTENING
TCPv6  services.exe ::               49683        LISTENING
TCPv6  lsass.exe   ::               49664        LISTENING
```

| Switch | Why it is in this command |
|---|---|
| `list --filter "proto:ipv6"` | An address-family prefix, usable on its own. `tcp:`, `udp:`, `ipv4:` and `ipv6:` compose with everything else, so `ipv6: state:listen` means "IPv6 listeners". |
| `--columns proto,process,local,lport,state` | `proto` carries the family (`TCPv6`), so one table answers both "which protocol" and "which family" without a second query. |

Link-local IPv6 addresses print with their **scope ID** (`fe80::1%12`), because the scope is part of the address for routing purposes and dropping it makes the row unroutable on paper. IPv4-mapped IPv6 (`::ffff:1.2.3.4`) is normalised to `1.2.3.4` so the same host does not appear twice.

### 27. Process table with CPU % and connection counts

`tasklist` has neither, and Task Manager is GUI-only.

```bat
wintcp.exe ps --sort cpu --limit 4
wintcp.exe ps --filter "proto:udp" --sort conns --limit 3
```

```text
  PID  Process                      Conns   CPU%   Memory      Disk
5172  Avira.Spotlight.Service.exe      2   0.3   24.3 MB   30.6 MB
22180  cloudflared.exe                 10   0.3   45.1 MB   52.8 MB
1940  svchost.exe                      2   0.0   21.0 MB  168.0 KB
```

| Switch | Why it is in this command |
|---|---|
| `ps` | One row per process: PID, name, connection count, CPU %, working set, disk I/O. `tasklist` gives name, PID and memory; the connection count and per-process CPU % are the two columns it lacks. |
| `ps --sort cpu` | `ps` sorts by its own six keys (`cpu`, `mem`, `disk`, `conns`, `pid`, `process`), not the column names of `list`. `ps` has no `--group` because it is already grouped. |
| `ps --filter "proto:udp"` | The filter selects **connections**, then `ps` aggregates the processes that own them. So this answers "which processes have UDP sockets", not "which processes match the text udp". |

CPU % is meaningful from the very first refresh because the sampler primes its baseline with a short double sample. A reading that cannot be taken (a protected process without elevation) shows `—` and sorts last in **both** directions, rather than first as a zero would.

### 28. One-shot system health as JSON

No built-in emits JSON, and `Get-Counter` needs a multi-counter script plus its own formatting.

```bat
wintcp.exe stat
wintcp.exe stat --format json
```

```text
CPU 7.6%  MEM 26.38 GB/63.72 GB (41.4%)  DISK 0 B/s+356.7 KB/s  NET 17.6 KB/s+9.0 KB/s
{"cpu":7.6,"cpuKnown":true,"memUsed":28333527040,"memTotal":68422742016,"memPct":41.4,"memKnown":true,"diskReadBps":0,"diskWriteBps":364468,"diskKnown":true,"netRecvBps":18016,"netSendBps":9241,"netKnown":true}
```

| Switch | Why it is in this command |
|---|---|
| `stat` | Samples system CPU, memory, disk and network rates **once**, then exits. Rates need two reads, so each run sleeps about one second internally. It prints one aligned line: `dir` behaviour, not `top` behaviour. |
| `stat --format json` | One object with stable lowercase keys: a machine-readable health line a dashboard or scheduled job can consume without a PowerShell wrapper. |
| `stat --watch 2 --count 5` | Available (poll, bounded), but not the point: the value of `stat` is that it is one shot. |

Every reading carries a `*Known` flag, so a value that could not be taken is distinguishable from a real zero: `"diskKnown":false` with `diskReadBps:0` is a different statement from a disk that genuinely read nothing. That is the difference between a health check you can alert on and one that pages you at 3 a.m. for a disabled counter.

### 29. The filter grammar: ranges, excludes, prefixes, quoting

```bat
wintcp.exe list --filter "lport:49600-49700 exclude:127." --sort lport --columns pid,process,lport,local --limit 8
wintcp.exe list --filter "local:port:49665" --columns pid,process,local,lport,state
wintcp.exe list --filter "note:""corporate dns""" --columns remote,rport,pinned --limit 3
```

```text
  PID  Process                      Local port  Local address
 1616  lsass.exe                         49664  0.0.0.0
 1616  lsass.exe                         49664  ::
 1508  wininit.exe                       49665  0.0.0.0
 1508  wininit.exe                       49665  ::
 2172  svchost.exe                       49666  0.0.0.0
 2172  svchost.exe                       49666  ::
 2808  svchost.exe                       49667  0.0.0.0
 2808  svchost.exe                       49667  ::
```

```text
  PID  Process                      Local address                 Local port  State
 1508  wininit.exe                  0.0.0.0                            49665  LISTENING
```

```text
Remote address   Remote port  bookmarks
64.59.150.137             53  blue
```

The complete grammar is in the [filter language reference](filters.md). The commands above exercise four of its forms:

| Form | Why it is in these commands |
|---|---|
| `lport:49600-49700` | A numeric **range** on the local port only, combined with a numeric `--sort lport` on the same column: the "find the gaps" pattern. |
| `exclude:127.` | Negation, as in recipe 24. |
| `local:port:49665` | The port, restricted to the **local** side, so it cannot match a connection *to* a remote 49665. |
| `note:"corporate dns"` | A quoted value: one term, not two AND-ed ones. On the command line the embedded quotes are doubled (`"note:""corporate dns"""`). |

Two details are worth internalising, because both are places a filter silently returns the wrong answer:

- **A threshold is a threshold, not a substring.** `mem:100` is "100 MB or more", and an unknown reading matches **no** threshold at all, so `mem:0` never selects a process that simply could not be measured. That is the opposite of how a text match behaves.
- **Direction and field are separate concepts.** `local:` / `remote:` select which *endpoint*; `lport:` / `rport:` / `local:port:` select which *column*. Collapsing them would turn `local:port:80` into a text match for the literal `port:80`, which can never match anything.

---

## Library and automation

> No built-in analog: nothing on Windows stores a filter you reuse, or pins a peer with a note and then lets you *find* it again.

### 30. Pin a peer with a tag and a note, and find it again

A bookmark's identity is **remote address + remote port**, because that pair survives a reconnect. The port is part of the match, not decoration: a mark on `1.2.3.4:9999` does not light up a live `1.2.3.4:443` row.

```bat
wintcp.exe bookmark add   --address 64.59.150.137 --port 53 --tag 3 --note "corporate dns resolver"
wintcp.exe bookmark note   --address 64.59.150.137 --port 53 --note "confirmed with netops"
wintcp.exe bookmark colour --address 64.59.150.137 --port 53 --tag 1
wintcp.exe bookmark list --format json
wintcp.exe list --filter "note:netops" --columns remote,rport,pinned --limit 3
wintcp.exe bookmark remove --address 64.59.150.137 --port 53
```

```text
bookmark added: 64.59.150.137:53
bookmark note updated.
bookmark colour updated.
[
  {"address":"64.59.150.137","port":53,"tag":"Red","note":"confirmed with netops"}
]
Remote address   Remote port  bookmarks
64.59.150.137             53  red
bookmark removed.
```

| Command | Why it is in this recipe |
|---|---|
| `bookmark add --address --port` | The pair is what "this conversation" means. Addresses normalise (`::ffff:1.2.3.4` becomes `1.2.3.4`) and placeholders like `0.0.0.0` are refused, because you cannot bookmark "somewhere". |
| `bookmark add --tag 0..4` | `0` none, `1` red, `2` amber, `3` blue, `4` green. Per endpoint, so every row to that peer shows the same color. The `pinned` column prints the color name, which also sorts first in both directions. |
| `bookmark add --note` | Free text on the endpoint, stored per user in `HKCU`, so it survives restarts. |
| `bookmark note`, `bookmark colour` | Separate verbs so neither can be lost by using the other. `add` on an existing endpoint does **not** clobber a note you wrote: losing a note to a re-add is not a recoverable mistake. |
| `bookmark list --format json` | The store, machine-readable, for pasting into a ticket. |
| `list --filter "note:…"` | The step that makes a note worth writing. The note is joined onto the row, so `note:` is a real filter field. **Quote a multi-word note** (`note:"vendor api"`) or the space is read as AND. |
| `bookmark remove` | Deletes the bookmark; the color and note go with it, because the join clears both on every refresh. |

### 31. Save and reuse a triage view

```bat
wintcp.exe preset save  --name web --filter "port:443" --sort pid
wintcp.exe preset list
wintcp.exe preset show  --name web
wintcp.exe preset apply --name web --limit 10 --columns pid,process,remote,rport
wintcp.exe preset save  --name web --filter "port:80"          :: exit 3, refuses to overwrite
wintcp.exe preset save  --name web --filter "port:80" --force
wintcp.exe preset delete --name web
```

```text
preset created: web
Preset
web
{"filter":"port:443","sortColumn":6,"sortAsc":true,"grouped":false,"colVisible":4493311,"sources":0}
  PID  Process                      Remote address   Remote port
    0  —                            172.253.117.19            443
 5168  AnyDesk.exe                  107.155.105.90            443
 5172  Avira.Spotlight.Service.exe  20.47.110.73               443
preset 'web' exists: refused: pass --force to proceed (or --dry-run to preview).
```

| Command | Why it is in this recipe |
|---|---|
| `preset save --name` | Names are the point. A filter you retype is a filter you will get subtly wrong next time. Stored in `HKCU`. |
| `preset save --force` | Overwriting an existing name is **exit `3`** without it. Refusing to clobber a saved view by accident is worth one switch, and the refusal names the fix. |
| `preset show` | The stored view as JSON. The state also carries the column mask and sort direction, which is why `colVisible` prints as a number: it is a bitmask. |
| `preset apply --limit --columns` | The payoff. Output switches are layered **over** the preset rather than ignored: `--limit 10 --columns pid,process,remote,rport` is the web view, ten rows, four columns. The same presets appear in the GUI **File** menu. |

An applied view that matches nothing prints only its header and exits `0`, exactly as a non-quiet `list` does. `preset apply` does not accept `--quiet` - that is exit `2` - so unlike `list` it offers no match-or-not exit code to branch on; branch on whether a data row was printed.

### 32. Excel-ready export with column selection

`netstat` output cannot be columned at all, and `ConvertTo-Csv` gives you neither a BOM nor column control.

```bat
wintcp.exe export --out conns.csv --filter "tcp: state:listen"
wintcp.exe export --out procs.tsv --format tsv --columns proto,pid,process,state
wintcp.exe export --out by-proc.csv --group --traffic --sort nettotal --desc
wintcp.exe export --out snap.csv --quiet
```

```text
exported 49 rows to conns.csv
exported 283 rows to procs.tsv
exported 48 rows to by-proc.csv
:: the --quiet run prints nothing at all
```

| Switch | Why it is in this recipe |
|---|---|
| `export --out FILE` | Mandatory. Without `--format`, the **extension** picks the format (`.csv`, `.tsv`, `.json`); an unknown extension is refused with instructions rather than guessed at. An **existing** file at that path is refused too (exit `2`) — see the note below. |
| `export --force` | Authorises replacing an existing `--out` file. The recipe's own filenames are new, so the command above does not need it; a script that re-exports to the same path every day does. |
| `export --filter` | Same grammar as `list --filter`. Exports are views, not dumps: the filter keeps a spreadsheet from being 300 rows of `TIME_WAIT`. |
| `export --columns a,b,c` | The exact column list, in the order you want. `default`, `minimal` and `full` are shorthands. Applies to CSV, TSV and JSON alike. |
| `export --group --traffic --sort` | A per-process file: "one row per process, heaviest first", a shape `list` can print but a spreadsheet cannot derive. |
| `export --format tsv` | Tabs, for when a value may contain a comma and the consumer is not Excel. |
| `export --quiet` | Still writes the file but prints no confirmation line. The exit code still says whether rows were written. |

With `--group` and no `--columns`, the file gets a default set that a group can honestly answer. The third command above wrote a `by-proc.csv` headed:

```text
  PID,Process,Proto,State,Traffic (rx/tx),Net total,CPU %,Memory (WS),Disk I/O
  9128,svchost.exe,UDP,30 connections,-,-,0.0 %,10.8 MB,0 B
  3372,svchost.exe,UDP,9 connections,-,-,0.0 %,10.8 MB,5.7 KB
  
```

Compare the flat `conns.csv` header (`Proto,Local address,Local port,Remote address,Remote port,…`): four of the ten flat columns have no meaning for a group. Naming a per-connection column together with `--group` is refused with exit `2`, and no file is written (see [Grouped views](cli.md#grouped-views)).

Run any of those four commands a second time and it exits `2` instead:

```text
export: 'conns.csv' already exists. --out replaces the whole file and this
command cannot ask before doing that. Add --force to replace it, or write
somewhere else.
```

That is deliberate. `--out` truncates, so an export aimed at a file you already had would destroy it with no warning and an exit code that says nothing went wrong — measured here: a 6-byte file became an 844-byte export, exit `0`. The GUI asks first, through the save dialog's own overwrite prompt; a script has no way to ask, so `--force` is how it says yes. `capture --out` follows the same rule and checks it before the capture window opens, so `--dry-run` is enough to find out.

Two further details: **CSV and TSV carry a UTF-8 BOM and JSON never does** (verified byte-wise by `the CLI test suite`), and **`--limit` is refused, not ignored**, because a file that quietly holds 5 of 300 rows while the tool reports success is a lie about the machine. Narrow with `--filter`, or pipe `list --limit` output instead.

### 33. A stable JSON schema for dashboards

Stable lowercase keys, so a consumer is written once.

```bat
wintcp.exe list --format json --columns proto,local,lport,remote,rport,state,pid,process --limit 2
wintcp.exe list --format json --columns full --limit 1 2>nul
```

```text
[
  {"proto":"TCPv4","local":"10.0.0.92","lport":"9337","remote":"64.59.150.137","rport":"53","state":"TIME_WAIT","pid":"0","process":"—"}
]
```

```text
[
  {"proto":"TCPv4","local":"10.0.0.92","lport":"12924","remote":"104.18.24.129","rport":"443","state":"TIME_WAIT","pid":"0","process":"—","service":"","path":"","host":"","tls":"—","country":"","traffic":"—","bandwidth":"—","duration":"0s"}
]
```

| Switch | Why it is in this recipe |
|---|---|
| `list --format json` | A real **array** of objects, valid JSON with no trailing commas, so `jq` and a dashboard can both consume it. A parser that chokes on a trailing comma is the usual reason people fall back to scraping a table. |
| `list --columns a,b,c` | Decides which keys appear and in which order. Asking for `pid,process` gives exactly those two keys, so the consumer's field list is under your control. |
| `2>nul` | Drops stderr. **Advisory** messages (`column: "host" without --dns…`) go to stderr and never into the JSON: stdout is data, stderr is advice. |

Types are chosen for the consumer, not for the table's convenience. `proto`, `state` and `process` are display strings; `lport` and `rport` are **strings**, so a consumer never has to care that port 0 means "no port" for UDP; and an unreadable stat is the em dash `—` rather than `0` or `null`, because "we could not measure this" and "this is zero" are different answers. The change feed in recipe 19 uses numeric `lport`/`rport`/`pid`, so a consumer of both knows the difference is deliberate.

### 34. Quiet exit-code automation

Zero output, and the exit code is the answer. This is recipe 17 seen as a composition: the same contract wired into a scheduler or a CI step.

```bat
wintcp.exe list --filter "state:listen exclude:127." --quiet || echo no-exposed-listeners
wintcp.exe list --group --traffic --filter "tx:1GB" --quiet && echo someone-is-uploading-a-lot
wintcp.exe ps --sort mem --limit 1 --quiet || echo no-processes
```

| Switch | Why it is in this recipe |
|---|---|
| `list --quiet` | Nothing printed; exit `0` if and only if a row matched. A **zero-byte** contract on both streams (no header, no hints, no progress), so it is safe where output would corrupt a pipeline. |
| `list --filter` | Any grammar term, including thresholds. `--traffic` alongside it is required for `tx:`, `rx:` and `net:` to mean anything, and a `note:` on stderr says so when a switch is missing (except under `--quiet`, where the silence is the contract). |
| `list --group` | Per-process, so a threshold hits the process total. `--filter "tx:1GB"` over connections and over processes are different questions; grouping is how you ask the second. |
| `ps --quiet` | The same contract on the process table. `ps --quiet` alone is an "is the process table readable" gate. |
| `\|\|` / `&&` | The branch. The shell is the control flow. |

### 35. What can this build do on this machine, and what is missing?

A feature that is missing and a feature that is broken look identical from the outside: the column is empty either way. `version` reports the state of **this run** instead of a feature list, so the reason is read rather than guessed at, and it is the first thing to run on an unfamiliar Windows install.

`version` takes no switches at all, so the table below breaks down what it prints instead.

```bat
wintcp.exe version
```

```text
WinTCP 1.0.0

A live view of every TCP and UDP endpoint on this machine (IPv4 + IPv6), with the process that owns it, read through the IP Helper API (GetExtendedTcpTable / GetExtendedUdpTable).
Plain Win32 API and the common controls. No MFC, ATL or Qt.

This run
Administrator     yes — traffic counters and connection closing are available
Traffic source    none (no collector is running)
GeoIP database    not loaded (Country column shows —)
Saved presets     available
Optional features all available
Connections       304
Handles           154
GDI objects       0
USER objects      1
```

| Line | What it reports |
|---|---|
| `Administrator` | The **security token**, not "was this process relaunched". Whoever opened an already-elevated console sees `yes` here *and* on the two capabilities that line names. |
| `Traffic source` | The collector this run has. An elevated run reads `none (no collector is running)`, because `version` opens no session and does not name one it did not start. The other two values are `ETW kernel logger (full, including UDP)` and `socket fallback (TCP only)`, the latter being what an unelevated run would use. |
| `GeoIP database` | Whether a `.mmdb` was loaded **by this run**, with the symptom printed beside the state (`Country column shows —`) rather than a bare `no`. |
| `Saved presets` | The preset store is in-process, so it reads `available` whenever the binary runs. |
| `Optional features` | Counted from the capabilities probed in this process. `all available` means the count was zero; on a machine that is missing one, each absence prints its own detail line above the summary, naming what is absent and what would provide it. |
| `Connections` | One real enumeration taken for this call, so it is a measured number rather than a placeholder. The `Columns shown` line is absent for the same reason: a CLI run has no persisted view mask to count, so the line is omitted instead of faked. |
| `Handles`, `GDI objects`, `USER objects` | This process's own resource budgets, read from the OS (`GetProcessHandleCount`, `GetGuiResources`) rather than tracked by this program. The numbers exist so "it gets slower after a day" can be answered with evidence: run `version` twice, hours apart, and compare. Both drawing budgets have a default ceiling of 10,000 per process, so a count climbing toward that is a leak worth reporting, and `USER` is reported separately from `GDI` because they are separate ceilings. **`GDI objects 0` is the correct answer for a console run** — no window means no GDI objects — and the line is omitted only when the handle count itself could not be read. |

`version` always exits `0` - it is a report, not a test, so a wrapper can call it before deciding whether anything is wrong. The `Optional features` line is the one that separates *the binary cannot do this* from *this machine cannot*, which is the distinction a blank column never makes on its own.

To catch a slow leak, sample rather than guess:

```bat
wintcp.exe version > "handles-1.txt"
timeout /t 3600 /nobreak >nul
wintcp.exe version > "handles-2.txt"
findstr /c:"Handles" "handles-1.txt" "handles-2.txt"
```

Two numbers an hour apart are evidence. A feeling is not — and a rising count is also not automatically a bug, since the numbers include whatever the traffic, GeoIP and process-detail work is currently holding.

### 36. Why does my JSON parser wait for the array to close?

`--format json` emits a single array, so nothing can be read until the closing `]` - and on a `--watch` run that closing bracket does not arrive until the process exits. `jsonl` is NDJSON: one complete object per line, no wrapper, so a line-oriented consumer gets whole records as they are produced.

```bat
wintcp.exe list --format json  --columns proto,local,lport,remote,rport,state,pid,process --limit 2
wintcp.exe list --format jsonl --columns proto,local,lport,remote,rport,state,pid,process --limit 2
```

```text
[
  {"proto":"TCPv4","local":"10.0.0.92","lport":"6495","remote":"18.64.67.41","rport":"443","state":"TIME_WAIT","pid":"0","process":"—"},
  {"proto":"TCPv4","local":"10.0.0.92","lport":"24753","remote":"64.59.144.91","rport":"53","state":"TIME_WAIT","pid":"0","process":"—"}
]
```

```text
{"proto":"TCPv4","local":"10.0.0.92","lport":"1515","remote":"64.59.144.91","rport":"53","state":"TIME_WAIT","pid":"0","process":"—"}
{"proto":"TCPv4","local":"10.0.0.92","lport":"6495","remote":"18.64.67.41","rport":"443","state":"TIME_WAIT","pid":"0","process":"—"}
```

| Switch | Why it is in this recipe |
|---|---|
| `list --format jsonl` | NDJSON: every line is a complete object, so `while read` or any line-buffered reader never has to match brackets or buffer across reads. `json` holds the identical objects inside one array a parser cannot finish until the process ends. |
| `list --format json` | Kept in the same recipe as the contrast - same rows, same keys, different framing. Choosing between them is a framing decision, not a data decision. |
| `--columns a,b,c` | Fixes which keys appear and in which order. Because both formats render the same column set, switching `json` to `jsonl` does not move the consumer's field list. |
| `--limit 2` | Bounds the sample. In a real script `--watch` supplies the stream instead and `--limit` stays off. |

`jsonl` is `json` with a different renderer, not a fourth format: same keys, same types, and the same em dash `—` for a stat nobody could measure rather than `0` or `null`. One consequence is worth knowing - **with `--changes` both formats are already NDJSON**, because a change feed is a stream by nature and there is no array to close; the difference only shows up on the snapshot forms above. See [the change feed as JSON]#19-a-machine-readable-change-feed) for that feed in either format.
