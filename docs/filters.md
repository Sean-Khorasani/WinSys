# Filter language

← [Back to the README](../README.md)

One grammar is used everywhere WinTCP selects rows:

| Where | Example |
|---|---|
| GUI filter box | `chrome port:443` |
| `list --filter`, `export --filter` | `wintcp.exe list --filter "state:listen exclude:127."` |
| `ps --filter` | Filters the **connection rows first**, then aggregates the processes that own them. `ps --filter "proto:udp"` answers "which processes have UDP sockets", not "which processes match the text udp". |
| `--select` on `kill`, `close`, `block`, `capture`, `details` | `wintcp.exe close --select "pid:5168 remote:203.0.113.90"` |

A `--select` selector must resolve to **exactly one live row**; see [Selectors](#selectors).

## Contents

- [Syntax](#syntax)
- [Field matches](#field-matches)
- [Trust: integrity and signature](#trust-integrity-and-signature)
- [Sides: local and remote](#sides-local-and-remote)
- [Protocol and family prefixes](#protocol-and-family-prefixes)
- [Numeric thresholds](#numeric-thresholds)
- [Quoting and negation](#quoting-and-negation)
- [Rules that prevent silent wrong answers](#rules-that-prevent-silent-wrong-answers)
- [Selectors](#selectors)
- [Examples](#examples)

## Syntax

- Terms are separated by spaces, and **a space means AND**.
- A bare term is a substring match over every field: `chrome`.
- `field:value` restricts the match to one field.
- Wrap a value in double quotes to keep its space and treat it as **one** term: `note:"vendor api"`.
- `exclude:` negates the term that follows.

## Field matches

| Field | Matches | Notes |
|---|---|---|
| `port:` | Local **or** remote port | Accepts ranges: `port:1000-60000`. |
| `lport:`, `rport:` | Local port, remote port | Accept ranges: `lport:49600-49700`. |
| `pid:` | Process ID | Accepts ranges: `pid:1000-2000`. |
| `state:` | TCP state | `state:listen`, `state:estab`. |
| `process:` | Process name | `process:svchost`. |
| `service:` | Windows service name | `service:dnscache`. |
| `path:` | Executable path | `path:c:\bin`, `path:"program files"`. |
| `host:` | Reverse-DNS name | CLI: needs `--dns`. |
| `proto:` | Protocol or family | `proto:udp`, `proto:tcp`, `proto:ipv6`. |
| `country:` | GeoIP country code | `country:de`. CLI: requires `--db`; see [GeoIP database](../README.md#geoip-database). |
| `asn:` | Autonomous system | **Both kinds of value.** A bare number is a threshold on the AS number, so `asn:15169` and `asn:15169-20000` work and accept ranges. Anything else is a case-insensitive substring of the cell `AS15169 Google LLC`, so `asn:google` finds the operator by name. A bare `asn:` means "has an autonomous system"; a row with no ASN never matches, whatever the value. CLI: needs `--asn-db`, which is a GeoLite2-ASN file and is separate from `--db`. |
| `tls:` | TLS summary | **Matches nothing** - the column is never populated, so no row can ever match. See [the column reference](cli.md#column-reference). |
| `note:` | A bookmark's note | `note:vendor`. A bare `note:` means "has a note". |
| `ppid:` | Parent process ID | `ppid:1588`. Accepts ranges: `ppid:1000-2000`. An exact number, not a substring. |
| `parent:` | Parent's image name | `parent:services`. |

Alerting is not a filter. `wintcp.exe alert` sets thresholds and reads them back; a filter narrows
the table, an alert reacts to it. The two share no switches.

### Trust: integrity and signature

Three questions about a process come up together — *who started it*, *how much
is it trusted by Windows*, and *is its binary signed* — so they are filtered
together. All three are read per **process** and joined onto each of its rows.

| Form | Meaning |
|---|---|
| `integrity:high` | Mandatory integrity level: `untrusted`, `low`, `medium`, `high`, `system`, `protected`. A prefix works (`integrity:med`). |
| `integrity:ac` | AppContainer processes, at any level. The cell prints `+AC` beside the level, and the filter searches that same cell. |
| `integrity:` | Rows whose level could be read at all. |
| `signed:` | **Verified, and the verdict was good.** This is the useful query, and it is narrower than it looks — see below. |
| `signature:unsigned` | The image carries no Authenticode signature. |
| `signature:bad sig` | The image is signed but its chain does not verify. |

Three things about these two that are easy to get wrong:

- **`signed:` does not mean "a verdict exists".** Bare, it means the verdict is
  *Signed*. A row whose image was never verified matches nothing, because
  reporting an unasked question as though it had been asked is exactly the
  failure this document exists to prevent.
- **`unsigned` is not a finding.** Most of what runs — script hosts, portable
  binaries, anything built without a certificate — is unsigned, and that is
  normal. Folding it into "invalid" would paint most of a machine red and teach
  the reader to ignore the colour, which is the only thing the highlight is for.
  `bad sig` is the state that means something.
- **The CLI needs `--signatures`.** Signature verification is opt-in because
  `WinVerifyTrust` builds a certificate chain; see the `list` verb in
  the [CLI reference](cli.md). Integrity and parent are read on every pass and need no
  switch.

A row whose process could not be opened at all — a protected or elevated service
this shell cannot query — has **no** integrity level and **no** signature, and
therefore matches neither field. It shows `—`, never a guess. On a typical
elevated session that is a substantial minority of all rows.

**Revocation is not checked.** Verification runs offline (`WTD_REVOKE_NONE`), so
a certificate that has been revoked but not yet expired can still read `Signed`.
That is a deliberate trade — a background check that may reach a CRL or OCSP
endpoint can outlive the refresh that asked for it — not a silent gap.

## Sides: local and remote

`local:` and `remote:` restrict a value to one endpoint of the connection.

| Form | Meaning |
|---|---|
| `local:10.` | The local **address** contains `10.`. |
| `local:private` / `local:global` | Whether the local endpoint is on a **non-routable** range; `remote:private` is the same question about the peer. `local:private` is what the GUI's **Mine** quick filter writes. Negates as `exclude:local:private`. |
| `remote:203` | The remote address contains `203`. |
| `local:port:80` | The **port**, restricted to the local side. It cannot match a connection *to* a remote port 80. |
| `remote:port:443` | The port, restricted to the remote side. |
| `local:port:1000-60000` | One side, numeric range. |

Direction and field are separate ideas. `local:` / `remote:` choose which *endpoint*; `lport:` / `rport:` / `local:port:` choose which *column*. For a listener audit use `lport:445`, not `port:445`: the latter also matches a row connecting *out* to a remote port 445, which is a different question.

## Protocol and family prefixes

`tcp:`, `udp:`, `ipv4:` and `ipv6:` can be used alone or combined with other terms: `ipv6:` means "IPv6, anything" and `ipv6: state:listen` means "IPv6 listeners". The cookbook also uses the `proto:` field with the same words (`proto:udp`, `proto:ipv6`).

## Numeric thresholds

Live readings are compared as **numbers**, not as text. `cpu:12` means "12 % or more", and `mem:100` means "100 MB or more". A range is written `a-b`.

| Field | Unit | Examples |
|---|---|---|
| `cpu:` | percent | `cpu:12` |
| `mem:` | MB (working set) | `mem:100`, `mem:100-500` |
| `disk:` | MB (bytes read + written) | `disk:1.5` |
| `rx:`, `tx:`, `net:` | MB (bytes received, sent, total) | `rx:2.0`, `tx:1KB`, `tx:1MB-1GB`, `net:2.5` |
| `duration:` | seconds, with `s` `m` `h` `d` suffixes | `duration:1h`, `duration:3600` |
| `speed:` | bytes per second (two samples) | `speed:1KB` |
| `rtt:`, `minrtt:` | milliseconds | `rtt:100` ("100 ms or worse") |
| `cwnd:`, `retrans:` | bytes | `cwnd:65536`, `retrans:1KB` |

On the byte-based stat fields (`mem`, `disk`, `rx`, `tx`, `net`, and `speed`, where everything is per second) a **bare number means megabytes**, and the suffixes `K`, `M`, `G` (also written `KB`, `MB`, `GB`) multiply. To ask for 2 KB write `rx:2KB`; `rx:2` means 2 MB.

**`cwnd:` and `retrans:` are byte counts.** A plain **integer** is a byte count (`retrans:1024`, `cwnd:65536`) and a value carrying a unit is scaled to bytes (`retrans:1KB`). Write the unit: a bare *decimal* with no unit is read as megabytes, exactly as on the other byte fields, so `retrans:1.5` means 1.5 MB and not 1.5 bytes. The cookbook always writes an explicit unit here; do the same.

The units are not uniform across fields: a bare `duration:3600` is 3600 **seconds**, a bare `mem:100` is 100 **MB**, a bare `rtt:100` is 100 **ms**, and a bare `retrans:100` is 100 **bytes**.

## Quoting and negation

- `note:"vendor api"` and `path:"program files"` each remain a single term.
- `exclude:chrome` removes rows matching `chrome`. It applies to the next term only, so `exclude:127.` removes rows containing `127.`.
- Inside a quoted `--filter` argument on the command line, an embedded quote is doubled. The documented form is:

  ```bat
  wintcp.exe list --filter "note:""corporate dns""" --columns remote,rport,pinned --limit 3
  ```

  The GUI filter box takes `note:"corporate dns"` directly.

`exclude:` is a **substring** exclusion, not a semantic one. `exclude:127.` removes IPv4 loopback rows but does not remove `::1`, which prints without `127.` in it. When the question is strict ("not loopback"), filter on the address column and read the result.

## Rules that prevent silent wrong answers

Each of these exists because the opposite behavior returns a plausible but wrong list.

1. **A threshold is not a substring.** `mem:100` is "100 MB or more", and it cannot be fooled by a process name that contains the digits.
2. **Unknown matches nothing.** A row whose reading could not be taken (a protected process without elevation, a socket that did not answer the scan) matches **no** threshold. `mem:0` never selects a process that merely could not be measured, and `tx:0` cannot smuggle in unreadable rows. A row without a connection age never matches `duration:` at all, so the filtered list can be shorter than the table.
3. **A threshold nothing reaches is empty, not an error.** `tx:500GB` simply returns no rows.
4. **Enrichment filters need the switch that fills them** (CLI only; the GUI fills them itself):

   | Filter | Needs |
   |---|---|
   | `host:` | `--dns` |
   | `country:` | `--db FILE` |
   | `asn:` | `--asn-db FILE` |
   | `rx:` `tx:` `net:` `duration:` `speed:` `rtt:` `minrtt:` `cwnd:` `retrans:` | `--traffic` |

   Without the switch the column stays unmeasured and the filter can only answer "no match". Every filter in the table except `duration:` names the missing switch in a `note:` on stderr; `duration:` stays silent on purpose, because a one-shot already prints the `0s` the filter is failing on, so the column itself shows why nothing matched. Advice is advisory: never fatal, never on stdout, and never under `--quiet`, where silence is the contract. But a `--quiet` gate on an enrichment *filter* without its switch would turn "unanswerable" into "no match", which no exit code can distinguish from a real one — so the CLI **refuses it** (exit `2`, naming the switch) instead of answering wrongly. Columns are exempt: `--quiet`'s answer is about the filter, and a requested column cannot change it. Either way, add the switch.
5. **Per-connection rates are never invented.** `speed:` only matches rows whose bytes came from that socket's own counters. A per-process total is never divided across a process's connections.

## Selectors

The action verbs (`kill`, `close`, `block`, `capture`) and `details` use the same grammar through `--select`, with one extra constraint: the selector must resolve to **exactly one live row**. Zero matches or more than one match exits `1` with the count or the reason. WinTCP will not guess which of 60 connections you meant.

A dual-stack listener is a single socket reported once per address family, so a port selector alone matches two rows:

```bat
wintcp.exe kill --select "local:port:49665" --dry-run
```

```text
kill: 'local:port:49665' matches 2 rows; refine to one.
:: exit code 1
```

Add the family prefix to resolve it:

```bat
wintcp.exe kill --select "ipv4: local:port:49665" --dry-run
```

## Examples

| Filter | Selects |
|---|---|
| `chrome port:443` | Rows mentioning `chrome` whose either port is 443. |
| `state:listen exclude:127.` | Listeners, minus anything with `127.` in it. |
| `lport:49600-49700 exclude:127.` | Local ports in a range, minus IPv4 loopback. |
| `pid:1000-2000 state:estab` | Established connections owned by PIDs in a range. |
| `proto:udp` | UDP rows only. |
| `ipv6: state:listen` | IPv6 listeners. |
| `local:port:49665` | Rows whose **local** port is 49665 (a connection *to* a remote 49665 does not match). |
| `note:"corporate dns"` | Rows bookmarked with that note. |
| `cpu:12` | Rows owned by processes using 12 % CPU or more. |
| `tx:1KB` | Processes that have sent at least 1 KB (CLI: add `--traffic`; add `--group` to rank processes). |
| `duration:1h` | Connections at least an hour old (CLI: add `--traffic`). |
| `rtt:100` | Connections with an RTT of at least 100 ms (CLI: add `--traffic`). |

Worked, real-output examples of each form are in the [cookbook](cookbook.md#29-the-filter-grammar-ranges-excludes-prefixes-quoting).
