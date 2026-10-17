# Traffic counters

← [Back to the README](../README.md)

The **Traffic**, **Received**, **Sent** and **Net total** columns show cumulative per-PID byte totals. WinTCP has two sources for them and uses the best one that can run:

| | ETW kernel logger | Per-socket fallback |
|---|---|---|
| **Needs admin** | Yes | No |
| **Protocols** | TCP and UDP | TCP only |
| **Mechanism** | NT Kernel Logger session with `EVENT_TRACE_FLAG_NETWORK_TCPIP`, summing `TcpIp`/`UdpIp` send and receive events per PID | Scans the system handle table, duplicates socket handles and reads `SIO_TCP_INFO` (`BytesIn` / `BytesOut`). Requires Windows 10 version 1703 or later, the first release with `SIO_TCP_INFO`. |
| **Totals are** | Session totals: counting starts when the session starts | Lifetime-of-socket totals, including time before WinTCP started |
| **Also provides** | Authoritative totals | Connection age, per-connection rate, RTT / min RTT / congestion window / retransmits |

## Contents

- [ETW kernel logger](#etw-kernel-logger)
- [Per-socket fallback](#per-socket-fallback)
- [Which source is used](#which-source-is-used)
- [What the per-socket scan provides](#what-the-per-socket-scan-provides)
- [Stalled sockets](#stalled-sockets)
- [Limits](#limits)

## ETW kernel logger

Selected from **View → Per-PID traffic counters (ETW, admin)**, or tried once automatically when a traffic column becomes visible. It starts the NT Kernel Logger with `EVENT_TRACE_FLAG_NETWORK_TCPIP` and sums send and receive bytes per PID from the classic `TcpIp` and `UdpIp` events (payload PID at offset 0, size at offset 4), re-applied to every refresh.

- The session flushes at least once per second (`FlushTimer = 1`), so a refresh right after some traffic already sees it.
- The buffer pool is widened (32 to 128 buffers of 64 KB) to keep up with bursts. Like every real-time ETW consumer, totals are **best-effort** under extreme load.
- Stopping the counters (`ControlTrace(STOP)` and the menu toggle) clears the totals. Exiting does the same.

## Per-socket fallback

When the ETW session cannot start (`ERROR_ACCESS_DENIED`), WinTCP switches silently to the fallback. Each refresh it scans the system handle table, duplicates the target processes' socket handles, and reads `SIO_TCP_INFO`, a per-socket kernel counter that needs no privilege.

- Totals **accumulate across refreshes**. Closed sockets, and handle values that get reused, are retired into the PID total so numbers never go backwards.
- Because it reads each socket's lifetime counters, long-lived connections carry their full history, even from before WinTCP started.
- A PID that has TCP sockets shows its TCP totals on all of its rows, matching the per-PID model of the ETW path.
- Status pane 2 shows `TCP only — UDP needs admin`, with a tooltip explaining the UDP gap.

## Which source is used

- A traffic column becoming visible (or starting with one persisted) tries ETW **once**, silently. On failure the socket fallback arms itself automatically, with no message box, because it succeeds. The explicit menu toggle keeps its message box, since it controls the ETW session; the note there says TCP totals are already flowing without admin.
- While the ETW session runs it is **authoritative** and the fallback stands down for totals. Stopping the counters clears the totals, and the fallback stays off too: the menu check mark always mirrors the ETW session.
- Even on the ETW path the socket scan is still consulted for per-connection **rates**. Totals come from ETW; a per-socket figure can only come from a socket.
- Status pane 2 shows `Ready` when either source feeds the visible columns, `TCP only — UDP needs admin` while the fallback runs, and `Traffic off — needs admin` only when **no** source can run (for example on systems without `SIO_TCP_INFO`, where the fallback probes once at startup and degrades to exactly that).

On the command line, `--traffic` runs **one bounded socket scan** per snapshot and joins the byte totals per PID.

## What the per-socket scan provides

The same scan that produces byte totals also yields figures a per-PID total cannot. They cost no extra handle-table pass: the fields were already in the `SIO_TCP_INFO` result.

### Connection age

`TCP_INFO_v0.ConnectionTimeMs` is the kernel's own age of the socket. A single-shot `list --traffic` therefore knows how old each connection really is, instead of reporting `0s` for everything because it has no "first seen" of its own. Without `--traffic` the `duration` column reads `0s`. The `duration:` filter takes seconds with `s`/`m`/`h`/`d` suffixes.

### Per-connection rate

The `bandwidth` column (header *Speed*) and the `speed:` filter report bytes per second between two samples of **one socket**. This is the only source permitted to mark a row as carrying its own counters. A per-PID total spread across a process's connection rows cannot honestly be attributed to a single socket, and dividing it by the connection count would produce a number that looks plausible and is invented. Rows whose bytes came from a per-PID source keep the same `—` as any other unreadable reading.

A rate is a difference, so it needs two samples: use `--watch N --count 2` or more. The first tick shows `—` by design.

### TCP health: RTT, minimum RTT, congestion window, retransmits

These are the kernel's own conclusions about each connection, analogous to `ss -i` on Linux:

| Column | Meaning |
|---|---|
| `rtt` | Current estimated round-trip time, in milliseconds. |
| `minrtt` | Smallest sampled round-trip time, in milliseconds. |
| `cwnd` | Congestion window, in bytes. |
| `retrans` | Cumulative bytes retransmitted. |

How to read them: a high RTT with a small congestion window points at the *path*, while a small RTT with a large one points at *bandwidth*. `retrans` is cumulative and monotonic, so a threshold such as `retrans:1KB` means "this connection has lost at least this much to retransmission".

Value details that are easy to get wrong:

- The kernel reports `RttUs` and `MinRttUs` in **microseconds**; the only millisecond field in `TCP_INFO_v0` is `ConnectionTimeMs`. The columns convert once at the read boundary. A raw read would show a 24 ms round trip as `24000`, which looks like a number and so is hard to notice.
- A sub-millisecond RTT prints as `<1`, never `0`, because a loopback or same-switch round trip is tens of microseconds and `0` would claim a physically impossible reading.
- Zero retransmits is a real answer. It prints `0 B`, not `—`.
- Each field is gated on its own known flag, because the kernel populates them independently. A socket with TCP timestamps off still reports a real congestion window, and blanking the row would discard three good readings to hide one missing one.

In the GUI these four columns and `Process rate` are available from **View → Columns** and hidden by default.

### Per-process rate

`procspeed` (header *Process rate*) is a process's bytes per second **summed over its sockets**, comparable to `nethogs` on Linux. It differs from `bandwidth` on exactly the rows that matter: a browser's per-socket figures are a fraction of its total, whereas a process with one busy socket shows the same figure in both. With `--group` the row *is* a process, so `procspeed` is the meaningful column and `bandwidth` deliberately shows `—`.

The sum is a correctness claim rather than a style choice:

- Dividing a per-PID byte total by the connection count invents a number, because one process's sockets carry wildly different shares of its traffic.
- Summing per-socket counters is the only honest answer, and it is only correct because each socket is counted exactly once, which is what the row identity (PID plus endpoint) guarantees.
- A process whose traffic came from the ETW source reports `—` rather than a number. ETW is per-PID and cannot be split across sockets, so adding such a row to the sum of the same process's sockets would count its bytes twice. Unknown is the honest answer; a doubled total is not.

`idle` means *measured, and nothing moved*. `—` means *unknown*. They are different answers.

## Stalled sockets

A socket whose `SIO_TCP_INFO` call does not return stalls that socket's read, and nothing else. This matters: on one test machine, of 391 sockets walked, 387 answered or failed instantly, one call took 28.3 seconds, and the next was still running after 90 seconds. Any design that reads sockets serially would have left the traffic columns largely empty.

The scan therefore works in two phases:

1. **Walk.** The handle-table walk decides *what* to read. It cannot block.
2. **Read.** The reads run on a pool of 16 worker threads, so a stalled socket costs one worker instead of the whole pass, and every other socket is still measured.

Supporting rules:

- A socket that stalls once is remembered and **not retried**. The cost is bounded to one abandoned thread per *distinct* bad socket, not one per refresh.
- Reads are folded in **per socket**, not at the end of the pass, so a pass that gives up still keeps everything it did read.
- A pass stops waiting once its workers stop making progress (250 ms of silence, with 4 s as a hard ceiling) rather than waiting out a fixed budget for a thread that will never return.

On a machine with such a socket the traffic, age and rate columns are **partial**: `—` for sockets that could not be read. The GUI status bar reports the count in its tooltip so it is visible rather than silent. A row with no age never matches `duration:`, so the filter can return fewer rows than the table shows instead of pretending the unmeasured ones are new.

Most `-` cells are not stalls at all. The majority of sockets on a busy machine are UDP, to which `SIO_TCP_INFO` does not apply, and they answer instantly with `WSAENOTSOCK`. Measured on one Windows 11 host by walking every socket-shaped handle the system reported: of **199,464** handles total, **13,955** belonged to sockets, and of those **12,235** failed the ioctl instantly and **1,720** belonged to a process that could not be opened at all. **None** of them answered with a byte count. A scan that appears to be failing is usually a scan that is correctly finding that most of the machine is not TCP.

Because the scan is only as complete as the pool allows, a one-shot `list --traffic` can differ between two runs on the same machine: when every worker is consumed by a socket that never answers, the pass stops on its no-progress budget and merges only what it read, so fewer rows carry a figure. `--watch` is steadier because the remembered-stalled set means the second tick does not pay for the same sockets again.

## Limits

- The fallback reads **TCP only**. UDP-only rows and protected processes keep showing `—` until you run elevated.
- Sockets that open **and** close entirely between two refreshes are missed by the fallback; their bytes were never observed. Long-lived connections carry their full history.
- ETW totals start at session start; fallback totals are lifetime-of-socket. The two are not interchangeable, so a number should be read together with the status-bar state that produced it.
- ETW totals are best-effort under extreme load.
- Per-connection rate, age and TCP health figures exist only for sockets the scan could read.
