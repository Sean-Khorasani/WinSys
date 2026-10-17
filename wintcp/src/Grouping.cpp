// Grouping.cpp
// SPDX-License-Identifier: Apache-2.0
// See Grouping.h.

#include "Grouping.h"

#include <cwchar>
#include <unordered_map>

#include "Columns.h"
#include "Utils.h"

namespace wintcp {

std::uint64_t SaturatingAdd(std::uint64_t a, std::uint64_t b) {
    if (a > UINT64_MAX - b) return UINT64_MAX;
    return a + b;
}

std::vector<ProcessGroup> GroupByProcess(const std::vector<GroupRow>& rows) {
    std::vector<ProcessGroup> groups;
    // PID -> index into 'groups'. A plain map, not a hash map with a
    // worst-case-adversarial key: PIDs are small dense integers in practice,
    // and std::map keeps the output in first-appearance order for free, which
    // is what the ordering rule below wants anyway.
    std::unordered_map<std::uint32_t, size_t> byPid;
    groups.reserve(rows.size() / 4 + 1);
    byPid.reserve(rows.size() / 4 + 1);

    for (size_t i = 0; i < rows.size(); ++i) {
        const GroupRow& r = rows[i];
        auto it = byPid.find(r.pid);
        if (it == byPid.end()) {
            ProcessGroup g;
            g.pid = r.pid;
            g.nameKnown = (r.processName != nullptr && !r.processName->empty());
            // A placeholder rather than an empty cell: a row with no resolved
            // process must still say WHICH process the group is, or the user
            // sees a header they cannot act on.
            g.name = g.nameKnown ? *r.processName
                                 : (L"PID " + std::to_wstring(r.pid));
            byPid.emplace(r.pid, groups.size());
            groups.push_back(std::move(g));
            it = byPid.find(r.pid);
        }
        ProcessGroup& g = groups[it->second];

        g.members.push_back(i);
        // static_cast: the ternary promotes to uint64_t (the common type of
        // `1` and connectionCount), and rowCount is size_t. Same width on x64
        // but nominally distinct, so /W4 C4244 + /WX rejects the implicit
        // narrowing. The values are row counts, bounded by the store, so the
        // cast cannot actually lose anything.
        g.rowCount += static_cast<size_t>(r.connectionCount == 0 ? 1 : r.connectionCount);
        if (r.removed) ++g.ghostCount;
        if (r.tcp) g.hasTcp = true;
        else        g.hasUdp = true;

        // MAXIMUM, NOT SUM. This is the single most important line in the
        // file. The traffic counters are PER-PID: SetTraffic writes the same
        // cumulative rx/tx to every row carrying that PID. Summing them
        // across a process's ten connection rows would report ten times the
        // real traffic - a number that looks entirely plausible and is the
        // kind of thing that ships and goes unnoticed. Every row for a PID
        // carries the identical value, so the maximum is that value; max also
        // tolerates rows that had not yet been joined (0) when another had.
        if (r.trafficRx > g.trafficRx) g.trafficRx = r.trafficRx;
        if (r.trafficTx > g.trafficTx) g.trafficTx = r.trafficTx;

        // and the same MAXIMUM-not-sum rule for the same reason: every row
        // of a PID carries the identical process rate (ComputeGroupRates writes
        // it to all of them), so the maximum is that value. Summing would report
        // a process's rate multiplied by its connection count - which for a
        // browser with 40 tabs is 40x the truth, and looks like a plausible
        // number rather than an obvious error.
        //
        // Only rows that actually HAVE a rate may set it. A process whose
        // traffic came from the per-PID ETW source has no group rate, and its
        // rows must leave the group's "known" flag clear rather than one of
        // them being believed.
        if (r.groupBpsKnown) {
            // MAXIMUM, for the same reason trafficRx above is a maximum and
            // not a sum: the rows are not samples, they are copies of one
            // measurement. This is written as an explicit maximum (rather than
            // a plain assignment) so that a future edit which starts treating
            // these as independent readings cannot quietly reintroduce a sum -
            // the check below is what makes the intent testable.
            if (!g.groupBpsKnown || r.groupRxBps + r.groupTxBps >
                                       g.groupRxBps + g.groupTxBps) {
                g.groupRxBps = r.groupRxBps;
                g.groupTxBps = r.groupTxBps;
            }
            g.groupBpsKnown = true;
        }
    }
    return groups;
}

// Render one cell of a group row. See Grouping.h for the column list.
//
// Only columns with a real per-process answer are handled. Everything else
// returns false so the caller falls through to the underlying connection: a
// group row that blanked the remote address or the state would be strictly
// less informative than the flat list, and the point of grouping is to
// compress, not to hide.
bool GroupColumnText(const ProcessGroup& g, int columnId, wchar_t* out,
                     size_t outLen) {
    if (out == nullptr || outLen == 0) return false;
    const auto set = [out, outLen](const std::wstring& s) {
        ::wcsncpy_s(out, outLen, s.c_str(), _TRUNCATE);
        return true;
    };
    // "—" is the app-wide "no data" marker (GetColumnText uses it too), so a
    // group with no traffic reads the same as a connection with no traffic.
    const auto none = [&set]() { return set(L"—"); };

    switch (columnId) {
        case COL_PROCESS:
            // the grouped header carries its member count so the row
            // reads "chrome.exe (14)" at a glance, matching the freeze banner's
            // "chrome.exe (14)" shape. ghosts count toward it - they are the
            // process's vanished connections, still part of the group until
            // GC'd. COL_STATE still reports the count in words; this is the
            // one-shot numeric badge the eye catches first.
            if (g.rowCount > 0)
                return set(g.name + L" (" + std::to_wstring(g.rowCount) + L")");
            return set(g.name);
        case COL_PID:
            return set(std::to_wstring(g.pid));
        case COL_PROTO:
            if (g.hasTcp && g.hasUdp) return set(L"TCP+UDP");
            return set(g.hasUdp ? L"UDP" : L"TCP");
        case COL_STATE:
            // A group spans many states, so the state column carries the one
            // thing that IS uniform across it: how many connections.
            return set(std::to_wstring(g.rowCount) +
                       (g.rowCount == 1 ? L" connection" : L" connections"));
        case COL_RX:
            return (g.trafficRx != 0) ? set(FormatBytes(g.trafficRx)) : none();
        case COL_TX:
            return (g.trafficTx != 0) ? set(FormatBytes(g.trafficTx)) : none();
        case COL_TRAFFIC:
        case COL_NETTOTAL: {
            const std::uint64_t total = g.TotalTraffic();
            return (total != 0) ? set(FormatBytes(total)) : none();
        }
        case COL_BANDWIDTH:
            // Per-socket rates are not summable into a process rate, and a
            // group has no single value to report. Showing the underlying
            // connection's rate would be actively misleading, so show none.
            return none();
        default:
            return false;   // caller renders the underlying connection
    }
}

bool ColumnIsPerConnectionOnly(int columnId) {
    switch (columnId) {
        // One socket's endpoint. A process with four connections has four of
        // these and no single answer, so printing one member's is a choice the
        // file's header cannot disclose.
        case COL_LOCAL:
        case COL_LPORT:
        case COL_REMOTE:
        case COL_RPORT:
        // One connection's state and lifetime. Duration in particular is the
        // age of ONE socket; "the group's duration" is not a thing, and
        // borrowing one member's makes an old process look young.
        case COL_DURATION:
        // Enrichment attached to one peer: a hostname, a country and a TLS
        // session all belong to a single conversation. A group spans several.
        case COL_HOST:
        case COL_TLS:
        case COL_COUNTRY:
        // a note is written against ONE remote endpoint (that is what a
            // bookmark is keyed on), so a group of several connections has no
            // single note. Same shape as the host column beside it, and it must
            // be in this set for the same reason: a grouped CSV whose Note
            // header promises the group's note while the cells carry one
            // arbitrary member's is the bug all over again.
            case COL_NOTE:
            return true;
        default:
            return false;
    }
}

}  // namespace wintcp
