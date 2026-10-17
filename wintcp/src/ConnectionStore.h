// ConnectionStore.h
// SPDX-License-Identifier: Apache-2.0
// The model: owns all connection rows, computes refresh-to-refresh diffs
// (stable row ids + appear/disappear/state-change events), applies the
// active filter (plain text or field expression) and sorting
// (precomputed keys, natural TCP-state ordering), and supplies
// text for the virtual ListView.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>

#include <cstdint>
#include <cstring>        // std::memcmp in ConnectionKey::operator==
#include <map>
#include <string>
#include <string_view>     // std::hash<std::string_view> for ConnectionKey
#include <unordered_map>
#include <vector>

#include "Columns.h"   // ColumnId, COL_COUNT, kMaxColumnText
#include "ColumnsWin.h"  // kDefaultVisibleCols (needs windows.h for UINT32)
#include "Connection.h"
#include "Grouping.h"  // ProcessGroup, GroupRow

namespace wintcp {

// The logical column set (ColumnId / COL_COUNT / kDefaultVisibleCols) lives
// in Columns.h so Settings can size its column state without pulling in the
// model; the re-export above keeps every existing consumer working.
static_assert(COL_COUNT <= 32, "visible-column bitmask is 32 bits wide");

// Change events produced by ReplaceSnapshot (consumed by the change log).
enum RowChangeKind { kChangeAppear = 0, kChangeDisappear = 1, kChangeState = 2 };
struct RowChange {
    int kind = kChangeAppear;
    Connection row;
    DWORD oldState = 0;
};

// One entry of the bookmark store, as handed to ConnectionStore::JoinBookmarks.
//
// It carries the PORT and the NOTE, not just the address. The port is the
// bookmark's real identity - `bookmark add` stores address + remote port
// precisely because that pair survives a reconnect - so a join that matched on
// the address alone flagged the wrong conversation: a bookmark on
// 107.155.105.90:9999 made the live :443 row print "red" (measured). The note
// is carried so it can be filtered on; before this, a note was writable and
// listable but unreachable from the connection table, which made it half a
// feature.
struct BookmarkMark {
    std::wstring address;
    UINT port = 0;
    unsigned tag = 0;
    std::wstring note;
};

// ---- Filter expressions ----------------------------------------
// Grammar (space-separated tokens, AND semantics):
//   token    := ["exclude:"] clause
//   clause   := [direction ":"] [proto ":"] [field ":"] value
//   direction:= "local:" | "remote:"   -> which ENDPOINT a field refers to
//   proto    := "tcp:" | "udp:" | "ipv4:" | "ipv6:"
//   field    := local|remote|lport|rport|port|pid|process|path|
//               state|proto|host|service|cpu|mem|disk|rx|tx|net|
//               duration|speed|tls|country|asn
//   value    := text | number | lo "-" hi   (numeric for port/pid fields)
// `asn:` is deliberately BOTH: a bare number is a threshold on the AS number
// (`asn:15169` and the range `asn:15169-20000` work), and anything else is a
// substring of "AS<n> <org>", so `asn:cloudflare` finds the operator by name. One
// field, two kinds of value, because "which network is this?" is asked both ways
// and a user should not have to remember which spelling answers which.
// The live-stat fields (cpu/mem/disk/rx/tx/net) take a numeric THRESHOLD, not
// text: a bare number is MB (cpu: %), `K`/`M`/`G` suffixes multiply, a
// range is "lo-hi", and a bare value is a lower bound. So `mem:100` is "100
// MB or more", `tx:1GB` is "a gigabyte sent or more". A non-numeric value
// degrades to a text match, as it always did.
// Examples: chrome  port:443  exclude:remote:tcp:443  pid:1000-2000
//           state:estab  proto:udp  process:svchost  mem:100-500
//           local:port:80            -> LOCAL port equals 80
//           remote:tcp:443           -> remote port 443 on TCP
//           local:10.                -> local address contains "10."
//
// 'direction' and 'field' are separate concepts: "local:"/"remote:" select
// which endpoint, "lport:"/"rport:"/"local:" as a *field* name select which
// column. Treating one as the other is why local:port:80 used to parse into
// {field=Local, text="port:80"}, which can never match anything.
enum class FilterField {
    Any, Local, Remote, LPort, RPort, Port, Pid,
    Process, Path, State, Proto, Host, Service,
    Cpu, Mem, Disk, Rx, Tx, Net,
    Duration, Speed, Tls, Country, Asn, Note,
    // Rtt/MinRtt/Cwnd/Retrans are thresholds in MILLISECONDS / bytes,
    // matching what the columns show - the microseconds the kernel reports are
    // converted at the sampler boundary (see SocketTcpInfo), so a filter and a
    // displayed cell can never disagree about the unit.
    Rtt, MinRtt, Cwnd, Retrans,
    // Per-PROCESS facts joined onto every row of that process,
    // so they filter exactly like the Process column they sit beside rather
    // than needing a separate process view of their own.
    Ppid, Parent, Integrity, Signature
};

struct FilterClause {
    bool exclude = false;
    FilterField field = FilterField::Any;
    int direction = 0;            // -1 = local endpoint, +1 = remote
    UINT proto = 0;                 // IPPROTO_TCP / IPPROTO_UDP / 0 = any
    int family = 0;                 // 4 / 6 / 0 = any
    std::wstring text;              // lowercase substring ("" = match all)
    bool numeric = false;           // value parsed as a number/range
    long long lo = 0;
    long long hi = 0;               // inclusive; for a stat threshold a bare
                                    // value leaves hi at LLONG_MAX (no upper
                                    // bound), while ports/pid stay exact
};

// One recognised filter-keyword spelling and the field it selects.
//
// This is part of the module's TESTABLE SURFACE, not an implementation detail.
// It exists because the accepted vocabulary used to be a 25-branch if/else
// chain that nothing could enumerate, which is how the corrupted spelling
// `dis.` survived as a working filter keyword (see kFilterKeywords in the .cpp
// for the full account). With the vocabulary enumerable, the selftest can hold
// every spelling to a policy - lower-case, `[a-z0-9-]` only, no duplicates, no
// debris - instead of nothing being able to assert anything at all.
struct FilterKeyword {
    FilterField field;
    const wchar_t* spelling;
};

// The parser's keyword table, in declaration order. The returned pointer is to
// storage with static lifetime; do not free it. Call FilterKeywordCount() for
// the length rather than assuming one.
const FilterKeyword* FilterKeywordTable();
size_t FilterKeywordCount();

// Parse a filter box string into clauses. Never fails; unparsable values
// degrade to plain text matching. Exposed for --selftest.
bool ParseFilter(const std::wstring& text, std::vector<FilterClause>& out);
bool MatchClause(const Connection& c, const FilterClause& cl);
bool MatchFilter(const Connection& c, const std::vector<FilterClause>& prog);

// ---- pure display helpers for the newer columns ---------------------------
// All exposed for --selftest: each one encodes a formatting or arithmetic
// decision that is easy to get wrong and impossible to eyeball in the list.

std::wstring FormatDuration(ULONGLONG seconds);   // "1d 4h" / "2h 17m" / "8m 03s"

// An RTT in milliseconds, formatted the way `ss -i` prints it.
//
// A dedicated helper rather than reusing FormatBytes or FormatDuration,
// because both are wrong here in a way that is easy to miss: FormatBytes would
// turn 12 ms into "12 B", and FormatDuration into "0m 00s" for anything under a
// second - which is most LAN RTTs. Sub-millisecond readings print as "<1" rather
// than "0", because "0 ms" is a claim that the round trip took no time at all
// and the measurement merely rounded to zero.
std::wstring FormatRttMs(unsigned ms);

// "↓ 1.2 MB/s  ↑ 340 B/s", or "idle" when both directions are under half a
// byte per second, or "—" when the rate is unknown.
//
// The reason for existing as its own function: the per-connection Speed cell
// and the per-PROCESS Speed cell are the same SHAPE and must render
// identically, and two copies of a three-branch format string will drift. A
// shared helper is the only way the two columns stay comparable at a glance -
// which is the entire point of putting them side by side.
std::wstring FormatBpsCell(double rxBps, double txBps, bool known);
// The default belongs on the declaration, not the definition - a default
// argument on the .cpp alone is invisible to every caller, so a one-argument
// call fails to compile.
ULONGLONG DurationSeconds(const Connection& c, ULONGLONG nowTick = 0);
std::wstring TlsProtocolName(USHORT wireVersion);
std::wstring TlsCipherName(USHORT cipherSuite);
std::wstring TlsSummary(const TlsInfo& t);
std::wstring TagLabel(unsigned tag);

// Bytes/second between two samples of one row. Returns false - leaving the
// caller's 'known' flag cleared - when the interval is zero (a paused
// snapshot, or two samples inside the same millisecond) or when a counter
// went backwards (a socket was recycled, so the delta would be a huge
// negative turned into a nonsense rate).
bool ComputeBps(ULONGLONG prevBytes, ULONGLONG nowBytes,
                ULONGLONG elapsedMs, double* bytesPerSecond);

// Proto-filter combo bitmask (kProtoMaskAll = "All (IPv4 + IPv6)").
enum {
    kProtoMaskV4  = 1,
    kProtoMaskV6  = 2,
    kProtoMaskTCP = 4,
    kProtoMaskUDP = 8,
    kProtoMaskAll = kProtoMaskV4 | kProtoMaskV6 | kProtoMaskTCP | kProtoMaskUDP
};
const DWORD kAllStates = 0xFFFFFFFFu;

// Default visible-column mask (kDefaultVisibleCols) lives in Columns.h.

struct ViewQuery {
    unsigned protoMask = kProtoMaskAll;
    DWORD stateFilter = kAllStates;                 // 0 = "— (none)", else MIB_TCP_STATE_*
    const std::vector<FilterClause>* program = nullptr;  // nullptr = no text filter
};

// Counters that UpdateStatusBar shows. Recomputed once per snapshot
// instead of by rescanning every row on each debounced keystroke.
struct RowStats {
    size_t total = 0;
    size_t ipv4 = 0;
    size_t ipv6 = 0;
    size_t udp = 0;
    // Per-state tallies for the status bar's "ESTABLISHED 12, LISTENING 8"
    // summary. Indexes MIB_TCP_STATE_* (0..12); state 0 is UDP, which also
    // has its own 'udp' counter above. A small fixed array rather than a map
    // because the state space is closed and this must stay O(rows) with no
    // allocation on the UI thread.
    size_t byState[13] = {};
    size_t pinned = 0;      // rows carrying a bookmark or colour tag
    size_t secure = 0;      // rows with an established TLS session

    size_t StateCount(DWORD state) const {
        return (state < 13) ? byState[state] : 0;
    }
};

// Row identity, PACKED. This is byte for byte the sequence that KeyOf used
// to build in a std::string - family flag, protocol flag, address, local
// port, address, remote port, pid - held in the object instead of on the
// heap. Looking up one row therefore allocates nothing: ReplaceSnapshot used
// to build TWO std::strings per row per refresh, one to index the previous
// snapshot and one to look the fresh row up in it, so 1000 rows at 1 Hz
// cost ~2000 heap operations per second to key data whose widest form is 46
// bytes and whose width never changes for a given address family.
//
// `len` is part of the key rather than a NUL terminator: IPv4 keys are 17
// bytes and IPv6 keys 46, so the length itself distinguishes the two
// layouts (two v4 rows differing only in unused v6 bytes must still be the
// SAME row, which is why those bytes are simply never written).
struct ConnectionKey {
    // 1 + 1 (flags) + 16 + 4 + 16 (IPv6 addrs + port) + 4 + 4 (port + pid).
    static constexpr size_t kMaxBytes = 46;

    size_t len = 0;
    unsigned char bytes[kMaxBytes] = {};

    // Identical to the std::string comparison it replaced: same bytes, same
    // length. (Equal length is implied by equal bytes for a fixed layout, but
    // it costs one compare and makes a truncated key impossible.)
    bool operator==(const ConnectionKey& o) const {
        return len == o.len && std::memcmp(bytes, o.bytes, len) == 0;
    }
};

// Hashes exactly the bytes the std::string used to hold, through the same
// std::hash the string got, so bucket distribution is unchanged. The
// string_view is non-owning - hashing a key still allocates nothing.
struct ConnectionKeyHash {
    size_t operator()(const ConnectionKey& k) const {
        return std::hash<std::string_view>()(
            std::string_view(reinterpret_cast<const char*>(k.bytes), k.len));
    }
};

// ReplaceSnapshot's previous-row lookup: identity key -> the queue of previous
// row indexes carrying that key.
//
// It is a map of VECTORS, not of one index, and that is the whole point. A
// single-index map collapses every duplicate key onto one row, so N identical
// sockets (mDNS on 5353 is the real-world case - 62 measured on this host)
// report N-1 false DISAPPEAR ghosts on every refresh and re-appear as new rows
// on the next one. The queue hands out one previous row per fresh row, which
// pairs them 1:1 and reports the truth: nothing changed.
using PrevKeyIndex =
    std::unordered_map<ConnectionKey, std::vector<size_t>, ConnectionKeyHash>;

class ConnectionStore {
public:
    // Diff 'fresh' against the current rows: assign stable ids, flag
    // new/changed rows, keep one-cycle ghosts for vanished rows, emit
    // change events, and recompute all precomputed keys.
    void ReplaceSnapshot(std::vector<Connection> fresh);

    // Filter + sort -> viewIndex_.
    void SetView(const ViewQuery& q);

    void SetSort(int column, bool ascending);
    int SortColumn() const { return sortColumn_; }
    bool SortAscending() const { return sortAsc_; }

    const std::vector<Connection>& Rows() const { return rows_; }
    const std::vector<size_t>& View() const { return viewIndex_; }
    const Connection* ViewRow(size_t viewIdx) const;   // nullptr if OOR
    size_t ViewToRow(size_t viewIdx) const;            // SIZE_MAX if OOR
    long long RowToView(size_t rowIdx) const;          // -1 if filtered out
    size_t CountForPid(DWORD pid) const;
    const RowStats& Stats() const { return stats_; }

    // cap on how long a vanished socket is kept as a retained (grey)
    // ghost, so the table does not grow without bound on a busy host.
    static constexpr size_t kMaxRetainedGhosts = 500;
    // The snapshot tick most recently installed by ReplaceSnapshot. The view
    // uses it to flash a just-vanished socket red for one refresh and keep older
    // ones as grey ghosts.
    ULONGLONG SnapshotTick() const { return lastSnapshotTick_; }

    // group the view by process. Rebuilds the view so each entry is one
    // process rather than one connection; the underlying rows are untouched,
    // so SetGrouped(false) restores the flat view exactly.
    //
    // Kept in the store rather than in MainWindow because the list is virtual
    // and asks ViewRow()/ViewToRow() to translate indices in three places
    // (paint, selection capture, status). A group-aware view means all three
    // agree by construction instead of each needing a special case.
    void SetGrouped(bool on) { grouped_ = on; RebuildView(); }
    bool Grouped() const { return grouped_; }
    // The group displayed at a view index, or nullptr when the view is flat or
    // the index is out of range. Valid until the next view rebuild.
    const ProcessGroup* ViewGroup(size_t viewIdx) const;

    // ---- headless row targeting (stage 2.1) ------------------------------
    //
    // WHY THIS EXISTS. Every row-targeted action - Follow stream, Block, Kill,
    // Close, Details, Bookmark, Export selection, Open location - used to
    // resolve its target through MainWindow::FirstSelectedRow(), which is an
    // LVM_GETNEXTITEM against a real list control. That made "what row does
    // this command act on?" unanswerable without a window, which is precisely
    // why those commands could only be tested by creating the real window and
    // posting real WM_COMMAND messages - 40 seconds per run, and flaky.
    //
    // These three functions answer the same question from data alone, so a
    // command can be driven from a test with no HWND anywhere in sight. The
    // GUI's FirstSelectedRow() becomes a thin wrapper: it finds the selected
    // VIEW index from the control and then asks the store for the row.
    //
    // NOTE ON GHOSTS. Matching runs over rows_ and includes last cycle's
    // vanished rows, because a command that acted on "what is on screen" must
    // not silently act on a different set just because a refresh landed
    // between listing and acting. Callers that care about live rows only can
    // filter on kRowRemoved themselves; SelectByFilter's own contract says only
    // "matches the filter".

    // Row indices into Rows() whose row matches 'text' (the same grammar as
    // the GUI filter box: pid:1000-2000, state:estab, process:svchost, and so
    // on). An empty 'text' matches nothing, deliberately: "select everything"
    // must be asked for explicitly, so a command with a typo'd filter cannot
    // quietly act on the whole machine.
    std::vector<size_t> SelectByFilter(const std::wstring& text) const;

    // The same, restricted to the current view (what the user can see). A
    // command offered in the GUI acts on what is on screen, so its default is
    // this rather than SelectByFilter.
    std::vector<size_t> SelectByFilterInView(const std::wstring& text) const;

    // The single row a command should act on, given a selection of view
    // indices (the GUI's answer from the list control). Returns nullptr when
    // the selection is empty or does not resolve to a live row.
    const Connection* RowForViewIndex(int viewIdx) const;

    // Async updates applied between refreshes.
    bool SetHostname(const std::wstring& addr, const std::wstring& host);
    // Join a GeoIP country code onto every row sharing this remote address
    // Like SetHostname it updates the lower-case key so the text
    // filter can search a value the column is displaying.
    bool SetCountry(const std::wstring& addr, const std::wstring& country);
    // Join an autonomous system onto every row sharing this remote address.
    // number == 0 with an empty org means "no ASN", and CLEARS a previous answer
    // - unlike SetCountry, which skips an empty code on the CLI path.
    bool SetAsn(const std::wstring& addr, uint32_t number,
                const std::wstring& org);

    // mark rows whose remote endpoint is bookmarked and apply its colour
    // tag and note. The match is on address AND remote port, because that pair
    // is the bookmark's identity ("what survives a reconnect") - matching on
    // the address alone flagged the wrong conversation (measured: a bookmark on
    // 107.155.105.90:9999 painted the live :443 row "red"). Rows whose
    // endpoint is absent are CLEARED, so removing a bookmark actually removes
    // the pin and the note instead of leaving them stuck on the row.
    void JoinBookmarks(const std::vector<BookmarkMark>& known);
    void SetTraffic(DWORD pid, ULONGLONG rx, ULONGLONG tx);
    void ClearTraffic();

    // Attach kernel-reported connection ages (TCP_INFO_v0::ConnectionTimeMs)
    // to the rows they belong to, matching on the 4-tuple. The kernel's age is
    // authoritative, so it BACKDATES firstSeenTick: a row WinTCP saw for the
    // first time thirty seconds ago really is 30s old, and a single-shot CLI
    // run - which has no "first seen" of its own at all - gets a real age from
    // this. Never moves firstSeenTick forward, so a stale or absent sample can
    // only leave the existing (watch-derived) value alone. Returns the number
    // of rows updated.
    int ApplyKernelAges(const std::vector<SocketAge>& ages);

    // Attach PER-SOCKET cumulative byte counters (same scan) to the rows they
    // belong to, and mark those rows `perRowBytes`.
    //
    // This is the only join permitted to set `perRowBytes`, because it is the
    // only source that observes a single socket. That flag is what lets
    // ReplaceSnapshot compute a real bytes/second for the Speed column; the
    // per-PID path must not set it, or a process total would be divided across
    // its connections and reported as if it were a per-connection rate.
    // Each row is claimed at most once per call, so two rows sharing a 4-tuple
    // (the mDNS case) get the same true counters rather than an invented split.
    int ApplySocketBytes(const std::vector<SocketBytes>& bytes);

    // join per-socket TCP_INFO congestion state (RTT, min RTT, congestion
    // window, retransmitted bytes, TCP-timestamp support) onto the rows.
    //
    // Same 4-tuple matching and same first-row-wins rule as ApplySocketBytes,
    // for the same reason: these are per-SOCKET facts and duplicate 4-tuples
    // exist. The two are separate calls rather than one merged join
    // because they come from separate samplers' outputs and a caller may want
    // bytes without asking for congestion state.
    //
    // Per-field, so a socket with TCP timestamps off still shows its real
    // congestion window rather than a blank row.
    int ApplySocketTcpInfo(const std::vector<SocketTcpInfo>& infos);

    // Turn this tick's byte counters into a per-connection bytes/second, for
    // the Speed column and the `speed:` filter.
    //
    // Call order matters and is not optional: ReplaceSnapshot (which carries
    // the previous sample forward) -> SetTraffic/ApplySocketBytes (which write
    // this tick's counters) -> ComputeRates (which differences them). The rate
    // lives here rather than inside ReplaceSnapshot precisely because the
    // counters do not exist yet at diff time; computing it inline compared a
    // previous reading against a fresh row's zeros, and guarded on a flag
    // nothing had set, so the column never printed a value.
    //
    // Rows whose counters came from a per-PID source are skipped by design -
    // see Connection::perRowBytes. Returns how many rows now have a known rate.
    //
    // Also runs ComputeGroupRates(), which fills the per-PROCESS rate from
    // the same per-socket counters. It is a separate pass rather than inline
    // because a process's rate needs the SUM over all of its rows, and no single
    // row can know that while the loop is still walking them.
    int ComputeRates();

    // Join per-process live stats into every row with this PID.
    // Always overwrites: pass cpuPct < 0 / memKnown=false / ioKnown=false
    // for values the sampler could not read (the row then shows "—").
    void SetProcStats(DWORD pid, double cpuPct, bool memKnown,
                      ULONGLONG memWs, ULONGLONG memPrivate, bool ioKnown,
                      ULONGLONG diskRead, ULONGLONG diskWrite);

    std::vector<RowChange> TakeChangeEvents();

    // Row finalization: labels + lowercase keys (idempotent).
    static void FinalizeRow(Connection& c);

    // Fill 'buf' with the display text of one column of one connection.
    static void GetColumnText(const Connection& c, int column,
                              wchar_t* buf, size_t bufChars);

    // Column header text (shared by the GUI, CSV export, and CLI).
    static const wchar_t* ColumnTitle(int column);

    // Total traffic (rx+tx) used as the COL_TRAFFIC sort key.
    static ULONGLONG TrafficKey(const Connection& c);

    static int CompareRows(const Connection& a, const Connection& b,
                           int column, bool ascending);

private:
    // the per-process rate, summing each PID's socket-counted rows.
    // Called by ComputeRates() after the per-connection pass; separate because
    // it needs a whole process's worth of rows before any one row's rate is
    // knowable. See the definition for why the sum is the only honest answer.
    void ComputeGroupRates();

    // Row -> lookup tables, rebuilt in one pass at the end of
    // ReplaceSnapshot. Without them every per-PID update (traffic, stats)
    // scanned all rows, which is O(pids x rows) per refresh on the UI
    // thread - ~35M iterations for 700 PIDs and 50k rows.
    void RebuildIndexes();
    // bound the retained-ghost history; evict the oldest beyond
    // kMaxRetainedGhosts. Operates on the merged vector in place.
    void TrimRetainedGhosts(std::vector<Connection>& rows);

    std::vector<Connection> rows_;          // includes last cycle's ghosts
    std::vector<size_t> viewIndex_;
    std::vector<RowChange> changes_;
    std::unordered_map<DWORD, std::vector<size_t>> pidRows_;
    std::unordered_map<std::wstring, std::vector<size_t>> addrRows_;
    // grouping. flatIndex_ is the filtered+sorted row list;
    // viewIndex_ is what the list actually displays, which is the same thing
    // ungrouped and one-entry-per-process grouped.
    std::vector<size_t> flatIndex_;
    std::vector<ProcessGroup> groups_;
    bool grouped_ = false;
    void RebuildView();
    RowStats stats_;
    int sortColumn_ = COL_PID;
    bool sortAsc_ = true;
    std::uint64_t nextId_ = 1;
    ULONGLONG lastSnapshotTick_ = 0;     // for SnapshotTick()
};

}  // namespace wintcp
