# Traffic counters

WinTCP can report byte totals, rates, connection age, and selected TCP health values. Availability depends on the collection source, Windows version, permissions, and whether an individual socket responds to the requested query. An em dash means unavailable; it is not a zero.

## Collection sources

| Source | Permission | Coverage | Counter period |
|---|---|---|---|
| **ETW kernel logger** | Administrator rights | TCP and UDP traffic observed after the ETW session starts. | Begins when the session starts. |
| **Per-socket TCP information** | Standard user, when supported | TCP sockets that provide `SIO_TCP_INFO`; UDP is not covered. | Lifetime of each socket, including activity before WinTCP started. |

WinTCP uses the available source and reports its status in the GUI. ETW and per-socket totals have different start times, so do not compare them as if they measured the same interval. Run elevated when UDP totals or ETW coverage are needed.

## Per-socket measurements

When Windows provides the data, WinTCP can report:

- received and sent bytes for a connection;
- per-connection rates between samples;
- connection age;
- round-trip time, minimum RTT, congestion window, and retransmissions for TCP.

A rate requires two valid readings. The first sample establishes a baseline; until the next usable sample, the rate is unavailable. Per-process rates sum the measurable rates of that process's sockets. WinTCP does not divide a process total among sockets when individual counters are missing.

## Reading missing values

Some sockets do not support the TCP information query, and protected processes may not be readable. WinTCP skips unavailable socket measurements rather than substituting zero. If a query stalls, bounded parallel collection allows other sockets to be sampled; the affected socket may remain unavailable for that pass.

In the GUI, the status bar identifies the active source and reports incomplete coverage. The CLI can show the source and capability details with `wintcp.exe version`; add `--traffic` to commands that support traffic columns or filters. See the [CLI reference](cli.md) and [GUI guide](gui.md).

## Limits

- The unprivileged fallback covers TCP only. It does not provide UDP byte counters.
- Per-socket totals are lifetime-of-socket; ETW totals start with the ETW session.
- A socket that opens and closes between observations may not be measured by the fallback.
- Rates, age, and TCP health values are unavailable when Windows cannot provide the underlying reading.
- The Web UI does not collect per-socket counters; use the CLI or desktop GUI for those values.
