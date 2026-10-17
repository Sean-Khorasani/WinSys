// Columns.h
// SPDX-License-Identifier: Apache-2.0
// The logical column set, shared by the model (ConnectionStore), the
// settings (Settings) and the UI. It lives in its own header so Settings
// does not have to include the whole model just to learn COL_COUNT - the
// store's filter/sort/view machinery is irrelevant to registry code.

#pragma once

#include <cstddef>
#include <cstdint>

namespace wintcp {

// Logical columns (order = default display order).
enum ColumnId {
    COL_PROTO = 0,
    COL_LOCAL,
    COL_LPORT,
    COL_REMOTE,
    COL_RPORT,
    COL_STATE,
    COL_PID,
    COL_PROCESS,
    COL_SERVICE,
    COL_HOST,
    COL_PATH,
    COL_TRAFFIC,
    COL_RX,         // per-PID network received (needs elevation)
    COL_TX,         // per-PID network sent
    COL_NETTOTAL,   // per-PID network received + sent
    COL_CPU,        // per-process CPU % (shown by default)
    COL_MEM,        // per-process working set
    COL_DISK,       // per-process disk I/O bytes read+written
    // Appended after the original set so existing ColumnId values - and the
    // persisted column mask - keep their meaning across an upgrade. New
    // columns therefore arrive hidden and the ColVersion migration in
    // Settings grants them, exactly as it did for COL_CPU.
    COL_DURATION,   // how long this endpoint has existed
    COL_BANDWIDTH,  // per-connection bytes/second
    // NOT DISPLAYED - reserved, and not offered anywhere in the UI.
    //
    // A column has to earn its place by being able to show something. This one
    // cannot: TLS session parameters are not readable from a socket at all.
    // `SIO_TLS_INFO` is not declared in this SDK (verified against the Windows
    // SDK headers), `TCP_INFO_v0` carries no TLS field, and the only per-connection
    // sources both need elevation AND a source the user cannot be expected to run
    // continuously (the ETW Schannel provider, or a packet capture of the
    // handshake). Measured on a real host, elevated, with every data source
    // enabled: the cell answers "unknown" on 302 of 302 rows - 100%, with no
    // row anywhere it could ever differ. A column that is always unknown is not
    // information; it is a blank column that teaches the user to ignore blanks.
    //
    // The enum value and its mask bit are deliberately KEPT. Renumbering would
    // shift every column after it, which silently moves the bits in a persisted
    // column mask and changes what a restored layout shows. Excluding it from
    // kDisplayOrder is what actually removes it: that list is the single place
    // the header, the Columns menu and the presets all read from, so one entry
    // removes it from all three at once without touching a bit anywhere.
    //
    // If a socket-level TLS source ever appears, the way back is one entry in
    // kDisplayOrder plus a line in kDefaultVisibleCols - no data migration, no
    // mask change, nothing else to undo.
    COL_TLS,        // reserved: not populated, so not displayed
    COL_COUNTRY,    // GeoIP country of the remote address
    COL_PINNED,     // user bookmark + colour tag
    // The bookmark NOTE, as its own column.
    //
    // Why a column and not only a filter. `note:` is already searchable and the
    // CLI can print the note, but the GUI had no way to SEE one: the note lived
    // in the row and reached the screen only as a tooltip on the Bookmarks
    // column, which meant a note written on the command line was invisible to
    // the person using the app. A filter you cannot see the result of is half a
    // feature - "show me everything I annotated" answers the question, but
    // "which of these did I annotate, and why" needs the text on screen.
    //
    // Appended, like every column after the original set, so existing persisted
    // column masks keep their meaning.
    COL_NOTE,
    // The TCP_INFO columns - "ss -i for Windows". Appended for the same
    // reason as the set above: a new id cannot renumber an existing one, so
    // the persisted column mask keeps its meaning and ColVersion in
    // Settings.cpp grants the new ones.
    //
    // THE UNIT IS THE WHOLE TASK. TCP_INFO_v0 reports RTT and minimum RTT in
    // MICROseconds (RttUs, MinRttUs) - ConnectionTimeMs is the only Ms field in
    // the structure. `ss -i` prints milliseconds, and these columns are named
    // for `ss -i`, so the value is converted on the way in (SocketTcpInfo) and
    // every consumer sees milliseconds. Reading the raw microseconds would
    // report a 12 ms round trip as 12000, and the error is invisible in a
    // table because the number still looks like a number.
    COL_RTT,        // smoothed round-trip time, ms
    COL_MINRTT,     // minimum RTT ever seen on this connection, ms
    COL_CWND,       // congestion window, bytes
    COL_RETRANS,    // cumulative bytes retransmitted
    COL_GROUPRATE,  // per-PROCESS bytes/second (a group answer only)
    // Appended for the same reason as every column above: a
    // new id cannot renumber an existing one, so a persisted column mask keeps
    // its meaning and the ColVersion migration in Settings.cpp grants them.
    //
    // HIDDEN BY DEFAULT, all three. They answer "should I trust this process",
    // which is a question asked about a handful of rows, not about the three
    // hundred on screen - and two of the three (Integrity, Signature) read as
    // em-dashes until the caller asks for the underlying work. A column that is
    // empty on first launch looks broken, which is the same reasoning the ss -i
    // columns use.
    COL_PPID,       // "<ppid> <parent image name>", e.g. "1234 explorer.exe"
    COL_INTEGRITY,  // mandatory integrity level, "+AC" for AppContainer
    COL_SIGNATURE,  // Authenticode verdict
    COL_COUNT
};

// How one column is drawn in an aligned table (the CLI's default `format
// table`; the GUI's kColumns carries the same split as LVCFMT, so both
// surfaces read the same).
//
//   right - numeric columns align right so digits stack under the header;
//           everything else is text and aligns left. Mirrors the GUI's
//           LVCFMT_RIGHT set exactly (ports, PID, the stat columns).
//   cap   - a width BUDGET, in display columns, for cells whose final value
//           is not knowable when the column header is printed: they are
//           filled by a late enrichment join (dns/traffic) or by the clock
    // (duration). The aligned header prints before those run,
//           so the column takes this fixed width instead of its content's,
//           and a cell that overflows it truncates with an ellipsis. 0 =
//           the width is measured from the content (snug).
//
//           A budget is the EXCEPTION, not the rule, and only exists where
//           a late value can exceed the header's own width: the Country
//           column is the counter-example - GeoIP writes an ISO 3166-1
//           alpha-2 code (always 2 columns), which the 7-column "Country"
//           header already covers before any join runs, so it measures
//           snug and can never fall out of step with a streamed header.
//           Every column the snapshot itself fills (Process, Path, CPU,
//           Memory, Disk, ...) measures snug too: its cells are present
//           before the header is printed.
struct ColumnStyle {
    bool right;
    int cap;
};

constexpr ColumnStyle GetColumnStyle(int col) {
    switch (col) {
        case COL_LPORT:
        case COL_RPORT:
        case COL_PID:
        case COL_CPU:
        case COL_MEM:
        case COL_DISK:
            return {true, 0};
        case COL_RX:
        case COL_TX:
        case COL_NETTOTAL:
            // 10 = "1023.99 TB", wide enough for any counter below
            // 100 PiB; past that a per-PID total truncates rather than
            // moving the column.
            return {true, 10};
        case COL_DURATION:
            return {true, 12};   // clock-filled: "36524d 23h" = 273 years
        case COL_HOST:
            // Reverse-DNS names are the widest late-joined value there is,
            // and 40 is not enough for the common ones: Akamai's
            // "*.deploy.static.akamaitechnologies.com" is 47 columns, an
            // EC2 regional FQDN 52. 56 fits both; a longer PTR (there are
            // a few) shows "..." instead of shifting the table.
            return {false, 56};
        case COL_COUNTRY:
            // No budget: an ISO alpha-2 code is 2 columns against a
            // 7-column header, so the pre-join and post-join widths agree
            // on the header alone (see the note on `cap` above).
            return {false, 0};
        case COL_TRAFFIC:
            return {false, 23};  // "<rx> / <tx>", 10 + 3 + 10
        case COL_BANDWIDTH:
        case COL_GROUPRATE:
            return {false, 30};  // "↓ 1023.99 TB/s  ↑ 1023.99 TB/s"
        case COL_NOTE:
            // Notes are free text written by the user, so they have no natural
            // width - but they DO need a budget for a different reason than the
            // late-joined columns: a note is filled by the bookmark join, which
            // runs after the header is printed, so an unbounded column would
            // measure its pre-join width (one dash) and then overflow every row.
            // 60 columns is roughly a full sentence, and anything longer elides
            // with the ellipsis plus the tooltip, which shows it in full.
            return {false, 60};
        case COL_RTT:
        case COL_MINRTT:
            // Right-aligned, because these are numbers and the digits should
            // stack under the header. Budget 9: "99999.999" - a 100-second
            // RTT is already pathological, and a wider one would push every
            // normal row's column across the table for a value that means the
            // connection is broken.
            return {true, 9};
        case COL_CWND:
        case COL_RETRANS:
            // Both are byte counts. 12 covers "1023.99 GB" and the cwnd's own
            // "64.0 MB"; beyond that the cell truncates rather than moving the
            // column, which is what a rate column must never do.
            return {true, 12};
        case COL_INTEGRITY:
            // Left, because these are words. 12 is exactly the longest cell the
            // column can produce - "Protected+AC" - so the budget can never
            // disagree with the content, which is the property the Country
            // column's zero budget relies on.
            return {false, 12};
        case COL_PPID:
        case COL_SIGNATURE:
            // Both are filled by the per-PID resolver during the refresh, i.e.
            // BEFORE the header is printed, so both measure snug like Process
            // and Path do. A cap here would only make the column wider than its
            // content on a machine whose process names are short.
            return {false, 0};
        default:
            return {false, 0};
    }
}

// Default visible-column mask. Everything the user can act on out of the box
// is shown: identity, the live per-process stats, the combined Traffic
// column, a connection's age and its bookmark state. The split per-PID
// Received / Sent / Net-total columns are redundant next to Traffic, and
// Memory / Disk I/O / Speed / TLS / Country are opt-in enrichment. Must stay
// in step with the ColVersion migration in Settings.cpp.
//
// These three need UINT32, which is a windows.h typedef, and this header is
// included at global scope by Settings.h and ConnectionStore.h *before*
// either of them pulls windows.h in. They therefore live in ColumnsWin.h
// along with windows.h itself; the numbers are unchanged, only their
// location. Include ColumnsWin.h (or a header that already includes it) to
// use them.

// ---- Named column sets ----------------------------------------------------
// A column set is a display-order list of ColumnId values, NUL-terminated so
// it can be written as one initialiser instead of a count that has to be kept
// in step. They live here (not in Cli.cpp) because they are pure
// presentation policy: the CLI's --format names resolve through them, and a
// future exporter can reuse the same lists. They are additions only - no
// ColumnId value and no COL_COUNT below this point is touched, so the
// persisted column mask keeps its meaning.
struct ColumnSet {
    const int* columns;
    size_t count;
};

// How a list of ColumnId ends.
//
// NOT a bare 0 sentinel. COL_PROTO is 0, so a 0-terminated list stops after
// its FIRST element - and every set below would have come out as one column,
// with a `static_assert` catching it at compile time. That is precisely the
// bug the first version of this had. -1 is not a valid ColumnId, so it is
// unambiguous.
constexpr int kEndOfColumnList = -1;

constexpr size_t CountColumns(const int* c) {
    size_t n = 0;
    while (c[n] != kEndOfColumnList) ++n;
    return n;
}

constexpr ColumnSet MakeColumnSet(const int* c) {
    return ColumnSet{c, CountColumns(c)};
}

// The historical CLI set: the GUI's set minus Hostname (the CLI
// never resolves) and minus every column needing a traffic source, so the
// default output stays byte-for-byte what it always was.
constexpr int kColsCliDefault[] = {
    COL_PROTO, COL_LOCAL, COL_LPORT, COL_REMOTE, COL_RPORT,
    COL_STATE, COL_PID, COL_PROCESS, COL_SERVICE, COL_PATH,
    kEndOfColumnList
};
constexpr ColumnSet kColumnSetDefault = MakeColumnSet(kColsCliDefault);

// Endpoint identity only - for "is anything up, and what is talking to what"
// scripting, where the process/service columns are noise.
constexpr int kColsCliMinimal[] = {
    COL_PROTO, COL_LOCAL, COL_REMOTE, COL_STATE, kEndOfColumnList
};
constexpr ColumnSet kColumnSetMinimal = MakeColumnSet(kColsCliMinimal);

// Every column that can be shown. Several (Traffic, Speed, TLS, Country,
// Duration) only have a value when the corresponding enrichment source ran;
// with no source they render as the em-dash, which is the honest answer for
// a CLI that never starts ETW. Hostname is excluded for the same reason as
// in the default set: the CLI does no reverse DNS. The per-PID stat columns
// are omitted because a per-PID figure on a per-connection row would imply a
// split the samplers do not actually produce.
constexpr int kColsCliFull[] = {
    COL_PROTO, COL_LOCAL, COL_LPORT, COL_REMOTE, COL_RPORT,
    COL_STATE, COL_PID, COL_PROCESS, COL_SERVICE, COL_PATH,
    COL_HOST, COL_TLS, COL_COUNTRY, COL_TRAFFIC, COL_BANDWIDTH,
    COL_DURATION, kEndOfColumnList
};
constexpr ColumnSet kColumnSetFull = MakeColumnSet(kColsCliFull);

// Guard the contract the delimited writer's static_assert also depends on:
// these three sets are quoted in the CLI help and the README, so a silent
// edit to one of them is a documentation lie.
static_assert(kColumnSetDefault.count == 10,
              "the default CLI set is frozen at ten columns");

// Every buffer that formats a column cell through
// ConnectionStore::GetColumnText must be at least this many wchar_t.
// Reviewed 2026-10-01: ProcessInfo resolves image paths into
// wchar_t[MAX_PATH * 2] (520 chars), i.e. 8 past this buffer. That is a
// deliberate display-width decision, not a bug — GetColumnText marks any
// elision with a visible ellipsis rather than cutting mid-path, so a 520-char
// path shows as 511 chars plus "…". Sizing every cell for the longest possible
// path would widen every column of every table for one pathological value.
constexpr size_t kMaxColumnText = 512;

}  // namespace wintcp
