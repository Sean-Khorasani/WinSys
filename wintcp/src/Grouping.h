// Grouping.h
// SPDX-License-Identifier: Apache-2.0
// Group connection rows by process for display.
//
// WHY A SEPARATE MODULE. Grouping is pure logic over a row list - which
// process owns this set of rows, how many connections, how much traffic in
// total, what the aggregate state is - with no window in it. Keeping it here
// means it can be tested directly, which matters because the failure modes
// are silent: a group header that shows the wrong count, or an aggregate that
// reads "0 B" for a busy process, looks like a rendering bug and nobody can
// tell whether the arithmetic or the drawing is at fault.
//
// WHAT A GROUP IS. A group is ONE process (by PID) and every connection row
// that belongs to it. The rows themselves are untouched - grouping changes
// the *shape of the list*, never the data. A row keeps its stable id, its
// state, its addresses. This is what makes grouping safe to toggle: turning
// it off restores exactly the flat list, because nothing was consumed or
// merged to produce the groups.
//
// WHY BY PID AND NOT BY PROCESS NAME. Two processes can share a name
// (svchost.exe, and any user-launched copy). Grouping by name would merge
// unrelated processes and report traffic and connection counts for a
// "process" that does not exist. The name is a label on the group; the PID is
// its identity.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

namespace wintcp {

// a + b, clamped at UINT64_MAX rather than wrapping. Declared before
// ProcessGroup because TotalTraffic() below calls it.
std::uint64_t SaturatingAdd(std::uint64_t a, std::uint64_t b);

// A minimal view of one connection, so this module does not need the whole
// Connection type. Passing a projection rather than the real struct keeps the
// grouping test honest - the tests below build these directly, and a bug in
// the real data path cannot hide a bug in the grouping arithmetic.
struct GroupRow {
    std::uint32_t pid = 0;
    const std::wstring* processName = nullptr;  // may be null; not owned
    bool tcp = true;
    std::uint64_t trafficRx = 0;
    std::uint64_t trafficTx = 0;
    std::uint64_t connectionCount = 1;   // per-row: 1, unless already merged
    bool removed = false;                 // a ghost row (vanished last cycle)

    // This row's PROCESS rate, identical on every row of a PID. Carried on
    // the projection so the group can show the process figure without this
    // module knowing anything about Connection - the same discipline as
    // trafficRx above, which is also a per-PID value flattened onto per-row
    // fields.
    double groupRxBps = 0.0;
    double groupTxBps = 0.0;
    bool groupBpsKnown = false;
};

// One process's worth of connections, plus the aggregates the group header
// shows.
struct ProcessGroup {
    std::uint32_t pid = 0;
    std::wstring name;              // "svchost.exe", or "PID 1234" if unknown
    bool nameKnown = false;         // false -> the name is a placeholder

    // Indexes into the source row array, in display order. Empty for a group
    // that exists only as a total (a process with no visible rows cannot
    // happen, but the invariant is asserted rather than assumed).
    std::vector<size_t> members;

    // Aggregates over 'members'.
    size_t rowCount = 0;            // number of connection rows
    size_t ghostCount = 0;          // of those, how many are vanished rows
    bool hasTcp = false;
    bool hasUdp = false;

    // Per-PID traffic, taken as the MAXIMUM over the member rows - NOT the
    // sum. SetTraffic writes the same cumulative rx/tx to every row carrying a
    // PID, so summing a process's ten connection rows would report ten times
    // its real traffic: a plausible, wrong number nobody questions. See the
    // comment at the aggregation site in Grouping.cpp.
    std::uint64_t trafficRx = 0;
    std::uint64_t trafficTx = 0;

    // rx + tx, saturating. A wrapped counter must not wrap the displayed
    // total into a small, plausible-looking, wrong number.
    std::uint64_t TotalTraffic() const { return SaturatingAdd(trafficRx, trafficTx); }

    // the PROCESS's bytes/second. Taken as the MAXIMUM over the members,
    // for the same reason trafficRx above is - every row of one PID carries the
    // identical figure (ComputeGroupRates writes it to all of them), so max and
    // sum would agree in value and sum would be wrong by the member count. Using
    // max keeps the aggregation rule uniform and removes any chance of a future
    // change summing this field by accident.
    double groupRxBps = 0.0;
    double groupTxBps = 0.0;
    bool groupBpsKnown = false;
};

// Build one group per distinct PID, in first-appearance order of that PID in
// 'rows'.
//
// First-appearance order rather than sorted-by-name is deliberate: it keeps a
// group directly above the row that produced it, so toggling grouping on and
// off does not make rows appear to move. Sorting by name would be prettier in
// isolation and more disorienting in use.
std::vector<ProcessGroup> GroupByProcess(const std::vector<GroupRow>& rows);

// Render one cell of a GROUP row. Returns false for columns that should fall
// through to the underlying connection instead, so a group still shows real
// addresses, state and id rather than blanks.
//
// Only the columns that have a meaningful per-process answer are handled:
//   PROCESS - the process name (or the PID placeholder)
//   PROTO   - "TCP" / "TCP+UDP" / "UDP" across the group
//   STATE   - the count of connections, since a group can be in many states
//   PID     - the group's PID (same as the member's, but explicit)
//   TRAFFIC/RX/TX/NETTOTAL - the aggregate byte totals
//   BANDWIDTH - "—", deliberately: per-socket rates are not summable
bool GroupColumnText(const ProcessGroup& g, int columnId, wchar_t* out,
                     size_t outLen);

// True when a column describes ONE CONNECTION and therefore has no honest
// value for a group of several.
//
// WHY THIS EXISTS, and why it is separate from GroupColumnText. Falling
// through to the representative connection is the RIGHT behaviour for an
// interactive table and for the GUI: the row is visibly a group (its State
// cell reads "4 connections"), so showing one member's remote address is
// informative rather than misleading, and blanking it would be strictly less
// useful. GroupColumnText returning false is that mechanism, and it is
// unchanged.
//
// It is the WRONG behaviour for `export`, because a delimited file's header
// row is a SCHEMA CLAIM: `Remote address` promises that every value under it is
// a remote address, and a reader has no way to know that one of four members
// was picked. Measured before this existed: `export --group --columns
// pid,process,remote` wrote a header saying "Remote address" over the single
// value "0.0.0.0" for a process with four connections. A spreadsheet loads
// that, the wrongness propagates, and nothing in the file says so.
//
// So the table/GUI keep the representative value, and `export` refuses the
// combination BY NAME (see CmdExport) rather than writing a file whose header
// over-claims. A named refusal is louder than a plausible wrong file, and this
    // codebase's whole posture - see MissingEnrichmentAdvice and the switch
// allow-lists - is that a silent wrong answer is the failure to design out.
//
// Note which columns are NOT here: cpu, mem and disk fall through to the
// representative but are perfectly correct for a group, because they are
// per-PROCESS values joined onto every row carrying the PID. A group row would
// print the same number either way; only genuinely per-connection columns are
// unsafe to fall through with.
bool ColumnIsPerConnectionOnly(int columnId);

}  // namespace wintcp
