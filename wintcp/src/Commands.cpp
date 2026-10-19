// Commands.cpp
// SPDX-License-Identifier: Apache-2.0
// See Commands.h. All headless; no HWND, no dialogs, no clipboard.

#include "Commands.h"
#include "Alerts.h"     // AlertRule, AlertRuleStore
#include "Notify.h"     // BuildStatePayload, PostWebhook, UtcIso8601
#include "Settings.h"

#include <algorithm>
#include <atomic>
#include <cwchar>
#include <map>
#include <set>
#include <sstream>
#include <tcpmib.h>
#include <unordered_set>

#include "BlockConn.h"
#include "Bookmarks.h"
#include "BookmarkFile.h"  // the export/import codec
#include "BuildInfo.h"
#include "ColumnsWin.h"
#include "DnsResolver.h"
#include "Elevate.h"
#include "GeoIp.h"
#include "Opt.h"
#include "PresetFile.h"  // the preset export/import codec
#include "Presets.h"
#include "ProcessInfo.h"
#include "SocketTraffic.h"
#include "StreamCapture.h"
#include "TcpTable.h"
#include "TlsDecode.h"
#include "Utils.h"

namespace wintcp {
// Forward: defined with the public serializers below; used by the
// anonymous-namespace list builders above it.
const char* JsonKeyFor(int column);
namespace {

// Grace period KillPid gives a process to exit after WM_CLOSE before falling
// back to TerminateProcess. 3 s is enough for a GUI app to run its normal
// shutdown and short enough that a scripted kill does not stall; the help text
// next to `kill` states this number, so change both together (see A4).
constexpr DWORD kKillGraceMs = 3000;   // B4: dev constant, no --wait flag:
// every switch is API surface, and no workflow needs a custom grace.

// Gap between the two samples `stat` differences into rates. 1 s matches the
// help text and makes the arithmetic trivially readable (delta == per-second);
// a shorter gap would quantise small rates, a longer one would make every
// `stat` call feel hung. B4 may surface this as --sample-ms; until then it is
// one constant, not two call sites.
constexpr DWORD kStatSampleGapMs = 1000;   // B4: dev constant, no --sample-ms:
// delta == per-second keeps the arithmetic readable; shorter quantises.

// Milliseconds per second, and bytes in an address field of a BlockRequest.
// Both appear in this file as well as in MainWindow.cpp / ConnectionStore.cpp
// and TcpReasm.cpp / TcpTable.cpp / StreamCapture.cpp / BlockConn.cpp, so the
// names are identical on purpose - a grep should find every site that assumes
// either width. 1000 here divides a millisecond age or grace into seconds,
// which is the "factor-of-1000" failure the file-level comment on kMsPerSecond
// in MainWindow.cpp describes.
constexpr DWORD kMsPerSecond = 1000;
constexpr size_t kIpv6AddrBytes = 16;

// Escape a wide string for a JSON string literal.
//
// The conversion to UTF-8 stays here - WideToUtf8 is the owner of the
// surrogate rules - and the escaping itself is wintcp::JsonEscapeOpt
// (Opt.cpp), which scans 16 bytes at a time with SSE2 for the six
// characters that need a backslash and copies the spans between them with
// memcpy. Control characters below 0x20 still emit the identical \\u00XX
// sequence, and UTF-8 continuation bytes pass through untouched.
//
// A/B bench, same source: 1.0-1.9x depending on how much of the string is
// escape-free; the differential tests pin it against the original switch
// over control chars, quotes, backslashes, CR/LF/TAB and multi-byte UTF-8.
std::string JsonEscapeA(const std::wstring& s) {
    return JsonEscapeOpt(s);
}

std::string TsvCell(const std::wstring& w) {
    std::string s = WideToUtf8(w);
    for (char& ch : s) {
        if (ch == '\t' || ch == '\r' || ch == '\n') ch = ' ';
    }
    return s;
}

const int kDefaultCols[] = {COL_PROTO, COL_LOCAL, COL_LPORT, COL_REMOTE,
                            COL_RPORT, COL_STATE, COL_PID, COL_PROCESS,
                            COL_SERVICE, COL_PATH};

// Element count of kDefaultCols. The export column set is built as a pointer
// pair, so the length is a second spelling of the array's own size; a literal
// here that drifts from the initialiser silently drops or gains a column, and
// the only symptom is an export with the wrong number of fields.
constexpr size_t kDefaultColCount = sizeof(kDefaultCols) / sizeof(kDefaultCols[0]);

// ---- text-buffer bounds ---------------------------------------------------
// Each swprintf_s / snprintf / sprintf_s site below bounds its own buffer, and
// every one of them truncates rather than overruns - so these are the widest
// value each format can hold plus its fixed wording, with slack, rather than a
// shared maximum. They are named because the numbers sat bare at a dozen sites
// and a wrong one reads as a plausible truncated number rather than as a
// failure.

// A short number on its own: "%.1f", "TID %u", "%.1f%%".
constexpr size_t kNumTextChars = 32;

// One details value, e.g. "cpu 12.34 s   started 3m 2s ago".
constexpr size_t kThreadDetailChars = 96;

// The two-direction rate cell: "down 1.2 MB/s   up 3.4 MB/s".
constexpr size_t kRateTextChars = 64;

// An error line, which carries a system message of unbounded length.
constexpr size_t kErrLineChars = 128;

// One numeric field on the `stat` line ("%.1f%%").
constexpr size_t kStatFieldChars = 128;

// An IPv6 literal in its narrow form: INET6_ADDRSTRLEN plus slack.
constexpr size_t kIpv6TextChars = 64;

// A GeoIP description line: version string plus two counts and a byte total.
constexpr size_t kGeoIpDescChars = 256;

// A capture summary line: four counters with labels.
constexpr size_t kCaptureLineChars = 256;

// The whole `stat --json` object on one line.
constexpr size_t kStatJsonChars = 512;

// THE refusal wording, exit 3. Every "we will not do that without being told
// twice" answer goes through here, so a script can match one shape.
//
//   <verb>: refused: pass <FLAG> to proceed (or --dry-run to preview).
//
// <FLAG> differs because the remedy differs: --yes for the mutating verbs,
// --force for overwriting an existing named object. They share the exit code
// because they share the meaning - "your intent was not confirmed" - so
// treating them as one kind of message is honest; splitting them into two
// sentences was not.
//
// Deliberately NOT unified with these, because they mean something else:
//   * "kill: refusing PID 4: ..." (exit 2) is a BAD ARGUMENT, not a missing
//     confirmation. --yes does not make PID 4 killable, so telling the user to
//     pass --yes would be a false promise - the exact failure mode.
//   * "export --limit is not accepted" (exit 2) is the same: the switch does
//     not belong to the verb, and no flag makes it belong.
CommandResult Refused(const std::string& what, const char* flag = "--yes") {
    CommandResult r;
    r.exitCode = kExitRefused;
    r.err = what + ": refused: pass " + flag +
            " to proceed (or --dry-run to preview).\r\n";
    return r;
}

void ApplyListView(ConnectionStore& store, const ListOptions& opt,
                   std::vector<FilterClause>* prog = nullptr) {
    std::vector<FilterClause> local;
    std::vector<FilterClause>* p = prog != nullptr ? prog : &local;
    ViewState v;
    v.filter = opt.filter;
    v.protoMask = opt.protoMask;
    v.stateFilter = opt.stateFilter;
    v.sortColumn = opt.sortColumn;
    v.sortAsc = opt.sortAsc;
    v.grouped = opt.grouped;
    v.ApplyTo(&store, p);
}

std::string DelimitedHeader(const std::vector<int>& cols, char delim,
                            bool rfcCsv) {
    std::string out;
    for (size_t i = 0; i < cols.size(); ++i) {
        if (i != 0) out += delim;
        const std::string title =
            WideToUtf8(ConnectionStore::ColumnTitle(cols[i]));
        out += rfcCsv ? CsvEscapeUtf8(title) : TsvCell(ConnectionStore::ColumnTitle(cols[i]));
    }
    return out;
}


// The default column set for a GROUPED machine-readable output.
//
// WHY IT EXISTS. The normal default set is ten columns and four of them are
// per-connection (local, lport, remote, rport), so keeping that set for a
// grouped CSV would write four arbitrary member addresses under four headers
// that promise otherwise. Every column here is one a group can actually
// answer: identity (pid, process), what kind of traffic (proto), the thing a
// group DOES have a single answer for (state -> the connection count), the
// aggregates (traffic, nettotal), and the per-process stats.
//
// Defined ABOVE ListColumns because that function calls it; the two are one
// idea (the shape-aware default) and splitting them across a declaration just
// makes the reader stitch it back together.
std::vector<int> GroupedDefaultColumns() {
    return {COL_PID, COL_PROCESS, COL_PROTO, COL_STATE,
            COL_TRAFFIC, COL_NETTOTAL, COL_CPU, COL_MEM, COL_DISK};
}

// The column set an output should render: what the user asked for, or the
// default for the output shape.
//
// a GROUPED stream defaults to the group-answerable set rather than the
// flat one. The flat default is ten columns and four of them are
// per-connection, so a grouped CSV would otherwise carry four arbitrary
// member addresses under four headers that promise otherwise - and a header
// row in a data file is a SCHEMA CLAIM, not a label. A human reading the table
// can see the row is a group (its State cell reads "4 connections"); a
// consumer reading a CSV cannot, so the table keeps the representative value
// and the machine shapes do not.
//
// The explicit-`--columns` half of the rule is enforced separately, by
// refusal rather than substitution - see ValidateStreamColumns.
std::vector<int> ListColumns(const ListOptions& opt) {
    if (!opt.columns.empty()) return opt.columns;
    if (opt.grouped && opt.format != "table") return GroupedDefaultColumns();
    return DefaultExportColumns();
}

// refuse a grouped MACHINE-READABLE output that explicitly asks for a
// per-connection column, by name, and say which columns do work.
//
// Why a refusal and not a substitution: silently swapping the user's chosen
// column for a different one would mean `export --columns pid,remote` produced
// a file with no remote column and no error. Why not on `table`: there the row
// is visibly a group (State reads "4 connections"), so one member's address is
// informative rather than misleading, and blanking it would be strictly less
// useful - which is why this lives here and not in GroupColumnText.
//
// Returns an empty string when the request is fine.
std::string ValidateStreamColumns(const ListOptions& opt) {
    if (!opt.grouped || opt.format == "table") return std::string();
    if (opt.columns.empty()) return std::string();   // the default is safe
    std::string bad;
    for (int c : opt.columns) {
        if (!ColumnIsPerConnectionOnly(c)) continue;
        if (!bad.empty()) bad += ", ";
        // ColumnTitle, not the JSON key: this is the exact string the refused
        // file's header row would have carried, so naming it lets the reader
        // see the mismatch they were about to get.
        bad += WideToUtf8(ConnectionStore::ColumnTitle(c));
    }
    if (bad.empty()) return std::string();
    return bad;
}

// ---- aligned "table" rendering ---------------------------------------
// `format table` is the default human shape, and raw tab stops do not make
// one: header and data cells start at different 8-column stops, so columns
// never line up vertically. The table now pads every cell to its column's
// computed width - text left, numbers right, the split the GUI's column
// list already uses - measured in DISPLAY columns so CJK names, the em-dash
// and the down/up arrows count the way a terminal draws them. csv/tsv keep
// their exact raw delimiters: they are machine shapes. The same job is done
// by `column -t`, docker ps, kubectl and Go's text/tabwriter.

// Decode the code point at 'i' (UTF-8 from WideToUtf8; a stray byte counts
// as itself) and return how many bytes it spans.
//
// The whole UTF-8 width walk - CpWidth, NextCp, DisplayWidth and
// TruncateToWidth - now lives in Opt.cpp. The four are one set and only make
// sense together: DisplayWidthOpt scans ASCII 16 bytes at a time and decodes
// codepoint by codepoint across the non-ASCII gaps, TruncateToWidthOpt fuses
// the measure pass with the cut pass (the original paid DisplayWidth a second
// time before walking again), and the measured gain came from both. Splitting
// them back apart would put the slow path straight back.
//
// A/B bench, same source: DisplayWidth 2.2x on a 47-char process cell to 27x
// on a 256-char path cell, TruncateToWidth 2.2-2.9x, and the mixed CJK/emoji
// cells 2.2-2.6x. CpWidthOpt is the original range chain unchanged - a 12 KB
// lookup table was built from the chain with a constexpr table and MEASURED
// at 0.62x/0.78x, so it was rejected and the chain kept. The differential
// sweeps in wintcp/tests/asm pin all four: 169,692 code points for CpWidth,
// and every width from 0 to total+1 for TruncateToWidth.

size_t DisplayWidth(const std::string& s) {
    return DisplayWidthOpt(s);
}

// Truncate to at most 'width' display columns, marking the cut with U+2026
// so a shortened cell reads as shortened instead of as the whole value.
std::string TruncateToWidth(const std::string& s, size_t width) {
    return TruncateToWidthOpt(s, width);
}

// The width cap in force for a column under 'opt' (0 = measure from the
// content). A cell a JOIN fills - or the clock ticks - takes its width from
// the cap whenever that source will run: the streamed header is printed
// BEFORE the join, the rows are padded AFTER it, and only a
// source-determined width makes the two passes compute the same table
// character for character.
//
// Country is deliberately absent: an ISO alpha-2 code is 2 columns wide
// against a 7-column header, so its width is the header's in both passes
// without a budget (Columns.h explains when a budget is needed at all).
int ActiveCap(int col, const ListOptions& opt) {
    switch (col) {
        case COL_GROUPRATE:
            return GetColumnStyle(COL_GROUPRATE).cap;  // late-joined
        case COL_NOTE:
            // filled by the bookmark join, which happens after the header
            // is printed - so the width must be the source's, not the
            // content's. Same rule as COL_HOST.
            return GetColumnStyle(COL_NOTE).cap;
        case COL_DURATION:
            return GetColumnStyle(COL_DURATION).cap;  // clock-filled: always
        case COL_HOST:
            return opt.dns ? GetColumnStyle(COL_HOST).cap : 0;
        case COL_RX:
        case COL_TX:
        case COL_NETTOTAL:
        case COL_TRAFFIC:
        case COL_BANDWIDTH:
            return opt.traffic ? GetColumnStyle(col).cap : 0;
        case COL_RTT:
        case COL_MINRTT:
        case COL_CWND:
        case COL_RETRANS:
            // late-joined exactly like the byte counters - the kernel fills
            // these during the socket scan, so with no scan every cell is "—" and
            // the two width passes still have to agree on the same table. Same
            // rule as BANDWIDTH: the header is streamed before the join, so the
            // column takes the source's budget rather than its content's.
            return opt.traffic ? GetColumnStyle(col).cap : 0;
        default:
            return 0;
    }
}

std::vector<bool> RightFlags(const std::vector<int>& cols) {
    std::vector<bool> out;
    out.reserve(cols.size());
    for (int c : cols) out.push_back(GetColumnStyle(c).right);
    return out;
}

std::vector<std::string> HeaderCells(const std::vector<int>& cols) {
    std::vector<std::string> out;
    out.reserve(cols.size());
    for (int c : cols) {
        out.push_back(WideToUtf8(ConnectionStore::ColumnTitle(c)));
    }
    return out;
}

// Column widths for the aligned table: the widest of the header title, the
// active cap and every cell the table can print.
//
// Measured over the store's FLAT rows (never the view) so the result is a
// pure function of (rows, opt): the streamed header scans before the
// enrichment joins, the renderer scans after them, and the two must agree.
// Ghost rows and rows the filter hides only make the scan a superset of
// what the view shows - a column can come out a little wider than needed,
// never too narrow.
std::vector<size_t> ScanTableWidths(const ConnectionStore& store,
                                    const ListOptions& opt) {
    const std::vector<int> cols = ListColumns(opt);
    std::vector<size_t> w(cols.size(), 0);
    for (size_t i = 0; i < cols.size(); ++i) {
        w[i] = DisplayWidth(WideToUtf8(ConnectionStore::ColumnTitle(cols[i])));
        const int cap = ActiveCap(cols[i], opt);
        if (cap > 0 && static_cast<size_t>(cap) > w[i]) w[i] = static_cast<size_t>(cap);
    }
    wchar_t buf[kMaxColumnText] = {0};
    const std::vector<Connection>& rows = store.Rows();
    for (size_t r = 0; r < rows.size(); ++r) {
        for (size_t i = 0; i < cols.size(); ++i) {
            if (ActiveCap(cols[i], opt) > 0) continue;
            ConnectionStore::GetColumnText(rows[r], cols[i], buf, kMaxColumnText);
            const size_t cw = DisplayWidth(TsvCell(buf));
            if (cw > w[i]) w[i] = cw;
        }
    }
    if (opt.grouped) {
        // Cells the flat scan never sees: "N connections" under State,
        // "TCP+UDP" under Proto, a "PID n" placeholder name. Projected here
        // exactly the way ConnectionStore::RebuildView projects them, from
        // the same flat rows - so a group's cells are counted before (the
        // streamed header) and after (the rows) the joins with the same
        // result. Group columns that fall through to the representative
        // connection are flat cells and were counted above already.
        std::vector<GroupRow> proj;
        proj.reserve(rows.size());
        for (const Connection& c : rows) {
            GroupRow g;
            g.pid = c.identity.pid;
            g.processName = c.display.processName.empty() ? nullptr : &c.display.processName;
            g.tcp = (c.identity.protocol != IPPROTO_UDP);
            g.trafficRx = c.traffic.trafficRx;
            g.trafficTx = c.traffic.trafficTx;
            g.connectionCount = 1;
            g.removed = (c.flags & kRowRemoved) != 0;
            proj.push_back(g);
        }
        const std::vector<ProcessGroup> groups = GroupByProcess(proj);
        for (const ProcessGroup& g : groups) {
            for (size_t i = 0; i < cols.size(); ++i) {
                if (ActiveCap(cols[i], opt) > 0) continue;
                wchar_t gb[kMaxColumnText] = {0};
                if (!GroupColumnText(g, cols[i], gb, kMaxColumnText)) continue;
                const size_t cw = DisplayWidth(TsvCell(gb));
                if (cw > w[i]) w[i] = cw;
            }
        }
    }
    return w;
}

// Widths for a table whose cells are all present before printing (ps,
// bookmarks): header vs content only, no late-join caps in play.
std::vector<size_t> ContentWidths(
    const std::vector<std::string>& header,
    const std::vector<std::vector<std::string>>& rows) {
    std::vector<size_t> w(header.size(), 0);
    for (size_t i = 0; i < header.size(); ++i) w[i] = DisplayWidth(header[i]);
    for (const std::vector<std::string>& cells : rows) {
        for (size_t i = 0; i < cells.size() && i < w.size(); ++i) {
            const size_t cw = DisplayWidth(cells[i]);
            if (cw > w[i]) w[i] = cw;
        }
    }
    return w;
}

// One padded table. The last column is never right-padded, so no line ends
// in whitespace (trailing spaces are invisible noise in a terminal and byte
// noise in a redirect).
std::string RenderAlignedLines(
    const std::vector<std::string>& header,
    const std::vector<std::vector<std::string>>& rows,
    const std::vector<bool>& right, const std::vector<size_t>& widths,
    bool includeHeader) {
    auto line = [&](const std::vector<std::string>& cells) {
        std::string out;
        for (size_t i = 0; i < cells.size() && i < widths.size(); ++i) {
            const size_t w = widths[i];
            const std::string cell = TruncateToWidth(cells[i], w);
            const size_t pad = w - DisplayWidth(cell);
            if (right[i]) {
                out.append(pad, ' ');
                out += cell;
            } else {
                out += cell;
                if (i + 1 < cells.size()) out.append(pad, ' ');
            }
            if (i + 1 < cells.size()) out += "  ";
        }
        // The last column is never right-padded, and an empty trailing cell
        // (no Path, no Service) must not leave the separator in place either:
        // no line ever ends in whitespace. Stripping here cannot lose
        // alignment - everything stripped is beyond the final non-empty cell.
        while (!out.empty() && out.back() == ' ') out.pop_back();
        out += "\r\n";
        return out;
    };
    std::string out;
    if (includeHeader) out += line(header);
    for (const std::vector<std::string>& cells : rows) out += line(cells);
    return out;
}

// The header exactly as RenderList would print it - the streamed copy for
// Same functions, same widths as the row pass below.
std::string ListHeaderLine(const ConnectionStore& store,
                           const ListOptions& opt) {
    const std::vector<int> cols = ListColumns(opt);
    if (opt.format == "table") {
        return RenderAlignedLines(HeaderCells(cols), {}, RightFlags(cols),
                                  ScanTableWidths(store, opt), true);
    }
    const bool csv = (opt.format == "csv");
    return DelimitedHeader(cols, csv ? ',' : '\t', csv) + "\r\n";
}

std::string DelimitedList(const ConnectionStore& store, const ListOptions& opt,
                           bool skipHeader = false) {
    const bool table = (opt.format == "table");
    const bool csv = (opt.format == "csv");
    const char delim = csv ? ',' : '\t';
    const std::vector<int> cols = ListColumns(opt);
    if (!store.Grouped()) {
        std::vector<Connection> rows;
        rows.reserve(store.View().size());
        for (size_t v = 0; v < store.View().size(); ++v) {
            if (opt.limit != 0 && rows.size() >= opt.limit) break;
            const Connection* c = store.ViewRow(v);
            if (c != nullptr) rows.push_back(*c);
        }
        if (table) {
            std::vector<std::vector<std::string>> cells;
            cells.reserve(rows.size());
            wchar_t buf[kMaxColumnText] = {0};
            for (const Connection& c : rows) {
                std::vector<std::string> row;
                row.reserve(cols.size());
                for (int col : cols) {
                    ConnectionStore::GetColumnText(c, col, buf, kMaxColumnText);
                    row.push_back(TsvCell(buf));
                }
                cells.push_back(std::move(row));
            }
            return RenderAlignedLines(HeaderCells(cols), cells, RightFlags(cols),
                                      ScanTableWidths(store, opt), !skipHeader);
        }
        return RenderDelimitedRows(rows, cols, delim, csv, !skipHeader);
    }
    // Grouped: one row per process group. A column the group has no answer
    // for falls through to the representative connection - the GUI has
    // always rendered it that way, and the CLI used to print the cell
    // BLANK (a table whose columns are half empty is exactly the messy
    // output it exists to fix).
    std::vector<std::vector<std::string>> cells;
    size_t shown = 0;
    for (size_t v = 0; v < store.View().size(); ++v) {
        if (opt.limit != 0 && shown >= opt.limit) break;
        const ProcessGroup* g = store.ViewGroup(v);
        if (g == nullptr) continue;
        const Connection* rep = store.ViewRow(v);
        std::vector<std::string> row;
        row.reserve(cols.size());
        for (int col : cols) {
            wchar_t gb[kMaxColumnText] = {0};
            if (!GroupColumnText(*g, col, gb, kMaxColumnText)) {
                if (rep == nullptr) {
                    row.push_back(std::string());
                    continue;
                }
                ConnectionStore::GetColumnText(*rep, col, gb, kMaxColumnText);
            }
            row.push_back(TsvCell(gb));
        }
        cells.push_back(std::move(row));
        ++shown;
    }
    if (table) {
        return RenderAlignedLines(HeaderCells(cols), cells, RightFlags(cols),
                                  ScanTableWidths(store, opt), !skipHeader);
    }
    std::string out;
    if (!skipHeader) {
        out = DelimitedHeader(cols, delim, csv);
        out += "\r\n";
    }
    for (const std::vector<std::string>& row : cells) {
        for (size_t i = 0; i < row.size(); ++i) {
            if (i != 0) out += delim;
            out += csv ? CsvEscapeUtf8(row[i]) : row[i];
        }
        out += "\r\n";
    }
    return out;
}

std::string JsonList(const ConnectionStore& store, const ListOptions& opt) {
    const std::vector<int> cols = ListColumns(opt);
    if (!store.Grouped()) {
        std::vector<Connection> rows;
        rows.reserve(store.View().size());
        for (size_t v = 0; v < store.View().size(); ++v) {
            if (opt.limit != 0 && rows.size() >= opt.limit) break;
            const Connection* c = store.ViewRow(v);
            if (c != nullptr) rows.push_back(*c);
        }
        return RenderJsonRows(rows, cols, /*extraHostname=*/false,
                              opt.jsonLines, opt.webMetadata);
    }
    // Grouped: same two shapes, so the same three edits as above - no
    // brackets, "\n" between records, one "\n" after the last.
    std::string out = opt.jsonLines ? "" : "[";
    bool first = true;
    size_t shown = 0;
    for (size_t v = 0; v < store.View().size(); ++v) {
        if (opt.limit != 0 && shown >= opt.limit) break;
        const ProcessGroup* g = store.ViewGroup(v);
        if (g == nullptr) continue;
        const Connection* rep = store.ViewRow(v);
        if (!first) out += (opt.jsonLines ? "\n" : ",");
        out += (opt.jsonLines ? "{" : "\n  {");
        bool needComma = false;
        for (size_t i = 0; i < cols.size(); ++i) {
            const char* key = JsonKeyFor(cols[i]);
            if (key == nullptr) continue;
            wchar_t gb[kMaxColumnText] = {0};
            // Same fall-through as the table/CSV branch (and the GUI): a
            // group column with no aggregate answer shows the representative
            // connection's cell, not an empty string.
            if (!GroupColumnText(*g, cols[i], gb, kMaxColumnText)) {
                if (rep == nullptr) continue;
                ConnectionStore::GetColumnText(*rep, cols[i], gb,
                                               kMaxColumnText);
            }
            if (needComma) out += ",";
            needComma = true;
            out += "\"";
            out += key;
            out += "\":\"";
            out += JsonEscapeA(gb);
            out += "\"";
        }
        out += "}";
        first = false;
        ++shown;
    }
    if (opt.jsonLines) {
        if (!out.empty()) out += "\n";
    } else {
        out += "\n]";
    }
    return out;
}


}  // namespace

// ---- shared serializers (public: Commands.h) --------------------------
std::string RenderDelimitedRows(const std::vector<Connection>& rows,
                                const std::vector<int>& cols, char delim,
                                bool rfcCsv, bool includeHeader) {
    std::string out;
    if (includeHeader) {
        out = DelimitedHeader(cols, delim, rfcCsv);
        out += "\r\n";
    }
    wchar_t buf[kMaxColumnText] = {0};
    for (const Connection& c : rows) {
        for (size_t i = 0; i < cols.size(); ++i) {
            if (i != 0) out += delim;
            ConnectionStore::GetColumnText(c, cols[i], buf, kMaxColumnText);
            const std::string cell = WideToUtf8(buf);
            if (rfcCsv) {
                out += CsvEscapeUtf8(cell);
            } else {
                std::string t = cell;
                for (char& ch : t) {
                    if (ch == '\t' || ch == '\r' || ch == '\n') ch = ' ';
                }
                out += t;
            }
        }
        out += "\r\n";
    }
    return out;
}

const char* JsonKeyFor(int column) {
    // Frozen lowercase keys: the same names the legacy --json emitter and
    // the GUI file export have always written, so every JSON artifact from
    // this binary is interchangeable.
    switch (column) {
        case COL_PROTO: return "proto";
        case COL_LOCAL: return "local";
        case COL_LPORT: return "lport";
        case COL_REMOTE: return "remote";
        case COL_RPORT: return "rport";
        case COL_STATE: return "state";
        case COL_PID: return "pid";
        case COL_PROCESS: return "process";
        case COL_SERVICE: return "service";
        case COL_HOST: return "host";
        case COL_PATH: return "path";
        case COL_TRAFFIC: return "traffic";
        case COL_RX: return "rx";
        case COL_TX: return "tx";
        case COL_NETTOTAL: return "nettotal";
        case COL_CPU: return "cpu";
        case COL_MEM: return "mem";
        case COL_DISK: return "disk";
        case COL_DURATION: return "duration";
        case COL_BANDWIDTH: return "bandwidth";
        // the `ss -i` names, so someone comparing the two is looking for
        // the same strings. JSON keys are lower case by convention (every other
        // key here is), which is why they differ from the CELL HEADERS - those
        // are "RTT" / "Min RTT" / "Cwnd" / "Retrans", and the two conventions
        // are deliberately allowed to differ.
        case COL_RTT: return "rtt";
        case COL_MINRTT: return "minrtt";
        case COL_CWND: return "cwnd";
        case COL_RETRANS: return "retrans";
        // Named "procspeed" rather than "groupspeed" on purpose: the value
        // is a PROCESS total, and it is populated on flat rows too, so a key
        // that said "group" would mislead anyone reading a non-grouped JSON
        // document.
        case COL_GROUPRATE: return "procspeed";
        case COL_NOTE: return "note";
        case COL_TLS: return "tls";
        case COL_COUNTRY: return "country";
        case COL_PINNED: return "pinned";
        // JSON keys match the --columns spellings, not the CELL
        // HEADERS, for the same reason the ss -i keys do: the header says
        // "Parent" and "Integrity", and the machine-readable name is the flat
        // one a jq author would type.
        case COL_PPID: return "ppid";
        case COL_INTEGRITY: return "integrity";
        case COL_SIGNATURE: return "signature";
        default: return nullptr;
    }
}

// ---- help reference: columns / filters -----------------------------
// `help columns` and `help filters` print the vocabulary from the SAME tables
// the parser uses (JsonKeyFor above, ColumnTitle, ColumnIsPerConnectionOnly,
// kColumnSet*), so the reference can never drift from the spellings the rest of
// the binary accepts. Generated rather than hand-written: a column that the
// parser knows but this list forgot would be an undocumentable column, and a
// spelling the parser rejects but this list shows would be a documentation lie.

static const char* ColumnSource(int col) {
    switch (col) {
        case COL_HOST:      return "dns (--dns)";
        case COL_COUNTRY:   return "geoip (--db)";
        case COL_TLS:       return "etw";
        case COL_NOTE:
        case COL_PINNED:    return "bookmarks";
        case COL_RX:
        case COL_TX:
        case COL_NETTOTAL:
        case COL_TRAFFIC:
        case COL_BANDWIDTH:
        case COL_RTT:
        case COL_MINRTT:
        case COL_CWND:
        case COL_RETRANS:
        case COL_GROUPRATE: return "traffic";
        default:            return "snapshot";
    }
}

static const char* FilterFieldLabel(FilterField f) {
    switch (f) {
        case FilterField::Any:       return "any";
        case FilterField::Local:     return "local";
        case FilterField::Remote:    return "remote";
        case FilterField::LPort:     return "lport";
        case FilterField::RPort:     return "rport";
        case FilterField::Port:      return "port";
        case FilterField::Pid:       return "pid";
        case FilterField::Process:   return "process";
        case FilterField::Path:      return "path";
        case FilterField::State:     return "state";
        case FilterField::Proto:     return "proto";
        case FilterField::Host:      return "host";
        case FilterField::Service:   return "service";
        case FilterField::Cpu:       return "cpu";
        case FilterField::Mem:       return "mem";
        case FilterField::Disk:      return "disk";
        case FilterField::Rx:        return "rx";
        case FilterField::Tx:        return "tx";
        case FilterField::Net:       return "net";
        case FilterField::Duration:  return "duration";
        case FilterField::Speed:     return "speed";
        case FilterField::Tls:       return "tls";
        case FilterField::Country:   return "country";
        case FilterField::Asn:       return "asn";
        case FilterField::Note:      return "note";
        case FilterField::Rtt:       return "rtt";
        case FilterField::MinRtt:    return "minrtt";
        case FilterField::Cwnd:      return "cwnd";
        case FilterField::Retrans:   return "retrans";
        case FilterField::Ppid:      return "ppid";
        case FilterField::Parent:    return "parent";
        case FilterField::Integrity: return "integrity";
        case FilterField::Signature: return "signature";
    }
    return "?";
}

std::string HelpColumnsText() {
    std::string out =
        "columns - every column, its CLI name, its header, the source that "
        "fills it, and whether it is group-safe. A group is one process, so a "
        "per-connection column has no honest group answer and is refused by "
        "`--group`.\r\n"
        "\r\n"
        "name | header | source | group-safe\r\n";
    for (int col = 0; col < COL_COUNT; ++col) {
        out += JsonKeyFor(col);
        out += " | ";
        out += WideToUtf8(ConnectionStore::ColumnTitle(col));
        out += " | ";
        out += ColumnSource(col);
        out += " | ";
        out += ColumnIsPerConnectionOnly(col) ? "per-connection" : "group-safe";
        out += "\r\n";
    }
    out += "\r\n";
    out += "Named column sets (--columns SET): default, minimal, full.\r\n";
    auto dumpSet = [&](const char* setName, const int* cols) {
        out += "  ";
        out += setName;
        out += ": ";
        const size_t n = CountColumns(cols);
        for (size_t i = 0; i < n; ++i) {
            if (i) out += ", ";
            out += JsonKeyFor(cols[i]);
        }
        out += "\r\n";
    };
    dumpSet("default", kColsCliDefault);
    dumpSet("minimal", kColsCliMinimal);
    dumpSet("full",    kColsCliFull);
    return out;
}

std::string HelpFiltersText() {
    std::string out =
        "filters - accepted `--select` / `--filter` keywords (case-insensitive "
        "substrings unless noted). Family prefixes (tcp/udp/ipv4/ipv6) and "
        "direction (local:/remote:) compose with any keyword.\r\n"
        "\r\n"
        "keyword | field | kind\r\n";
    const FilterKeyword* table = FilterKeywordTable();
    const size_t n = FilterKeywordCount();
    for (size_t i = 0; i < n; ++i) {
        out += WideToUtf8(table[i].spelling);
        out += " | ";
        out += FilterFieldLabel(table[i].field);
        out += " | keyword\r\n";
    }
    out += "\r\n";
    out += "Numeric keywords (pid/lport/rport/port/state/cpu/mem/disk/rx/tx/net/"
           "duration/speed/rtt/minrtt/cwnd/retrans/ppid) accept ranges: a-b.\r\n";
    out += "State keywords: estab, time-wait, listen, close-wait, and others.\r\n";
    out += "Proto keywords: tcp, udp.\r\n";
    return out;
}

// 'lines' selects NDJSON over the JSON array - see ListOptions::jsonLines.
// One renderer for both, because everything else about the two shapes (the
// keys, the escaping, the limit, the group fall-through) is identical, and
// two renderers would drift on exactly the part nobody looks at. The only
// differences are the brackets, the separator and the indent: in lines mode
// a record is separated by "\n" and the last one is terminated by "\n", so
// appending the next --watch tick's output CONTINUES the stream instead of
// starting a second array inside the first.
std::string RenderJsonRows(const std::vector<Connection>& rows,
                           const std::vector<int>& cols, bool extraHostname,
                           bool lines, bool webMetadata) {
    std::string out = lines ? "" : "[";
    bool first = true;
    wchar_t buf[kMaxColumnText] = {0};
    for (const Connection& c : rows) {
        if (!first) out += (lines ? "\n" : ",");
        out += (lines ? "{" : "\n  {");
        bool needComma = false;
        for (size_t i = 0; i < cols.size(); ++i) {
            const char* key = JsonKeyFor(cols[i]);
            if (key == nullptr) continue;
            if (needComma) out += ",";
            needComma = true;
            out += "\"";
            out += key;
            out += "\":\"";
            ConnectionStore::GetColumnText(c, cols[i], buf, kMaxColumnText);
            out += JsonEscapeA(buf);
            out += "\"";
        }
        if (extraHostname) {
            if (needComma) out += ",";
            out += "\"hostname\":\"" + JsonEscapeA(c.display.hostname) + "\"";
        }
        if (webMetadata) {
            if (needComma) out += ",";
            out += "\"hostname\":\"" + JsonEscapeA(c.display.hostname) + "\"";
            out += ",\"id\":" + std::to_string(c.id);
            out += ",\"idExact\":\"" + std::to_string(c.id) + "\"";
            out += ",\"processInstanceId\":";
            out += c.procMeta.processCreateKnown
                ? ("\"" + std::to_string(c.identity.pid) + ":" +
                    std::to_string(c.procMeta.processCreate.dwHighDateTime) + ":" +
                    std::to_string(c.procMeta.processCreate.dwLowDateTime) + "\"")
                : "null";
            out += ",\"removed\":";
            out += (c.flags & kRowRemoved) != 0 ? "true" : "false";
            out += ",\"socketRxBytes\":";
            out += c.rate.perRowBytes ? std::to_string(c.traffic.trafficRx) : "null";
            out += ",\"socketRxBytesExact\":";
            out += c.rate.perRowBytes ? ("\"" + std::to_string(c.traffic.trafficRx) + "\"")
                                 : "null";
            out += ",\"socketTxBytes\":";
            out += c.rate.perRowBytes ? std::to_string(c.traffic.trafficTx) : "null";
            out += ",\"socketTxBytesExact\":";
            out += c.rate.perRowBytes ? ("\"" + std::to_string(c.traffic.trafficTx) + "\"")
                                 : "null";
            out += ",\"socketCountersAvailable\":";
            out += c.rate.perRowBytes ? "true" : "false";
            out += ",\"rttMs\":";
            out += c.tcpInfo.rttLive ? std::to_string(c.tcpInfo.rttMs) : "null";
            out += ",\"retransBytes\":";
            out += c.tcpInfo.retransKnown ? std::to_string(c.tcpInfo.retransBytes) : "null";
            // Numeric duration in seconds, for template evaluators that need to
            // threshold on connection age. The COL_DURATION cell above is a
            // human-readable string; this is the same value as a number.
            out += ",\"durationSeconds\":";
            out += (c.lifetime.firstSeenTick != 0)
                       ? std::to_string(DurationSeconds(c)) : "null";
            // Numeric signature state and integrity level for template evaluators.
            // SignatureLabel values: 0=unchecked, 1=signed, 2=invalid, 3=unsigned, 4=error.
            out += ",\"signatureState\":";
            out += (c.security.signature < static_cast<unsigned>(kSigCount))
                       ? std::to_string(c.security.signature) : "0";
            out += ",\"integrityLevel\":";
            out += (c.security.integrity < static_cast<unsigned>(kIntegrityCount))
                       ? std::to_string(c.security.integrity) : "0";
        }
        out += "}";
        first = false;
    }
    if (lines) {
        // Terminate the last record - NDJSON defines each line as a complete
        // value, and the trailing newline is what lets the next one follow.
        // An EMPTY result stays empty: a run that matched no rows writes
        // nothing at all rather than one blank line a reader would try to
        // parse as an object.
        if (!out.empty()) out += "\n";
    } else {
        out += "\n]";
    }
    return out;
}

std::vector<int> DefaultExportColumns() {
    return std::vector<int>(kDefaultCols,
                            kDefaultCols + static_cast<ptrdiff_t>(kDefaultColCount));
}

bool BuildStoreSnapshot(SnapshotSource& source, ConnectionStore& store,
                        bool procStats, bool resolveDns, bool geoIp,
                        const wchar_t* geoIpPath, std::wstring* error) {
    SnapshotOptions so;
    so.resolveProcesses = true;
    so.procStats = procStats;
    so.resolveDns = resolveDns;
    so.geoIp = geoIp;
    so.geoIpPath = geoIpPath;
    Snapshot snap;
    if (!source.Build(so, &snap)) {
        if (error != nullptr) *error = snap.error;
        return false;
    }
    for (const auto& kv : snap.procStats) {
        // Join live stats into the snapshot rows before the diff, so the
        // store's first view already carries CPU/mem/disk.
        (void)kv;
    }
    store.ReplaceSnapshot(std::move(snap.rows));
    // Join services + procStats that Snapshot produced alongside rows.
    for (const auto& kv : snap.services) {
        (void)kv;  // already joined inside SnapshotSource::Build
    }
    for (const auto& kv : snap.procStats) {
        store.SetProcStats(kv.first, kv.second.cpuPct, kv.second.memKnown,
                           kv.second.memWs, kv.second.memPrivate,
                           kv.second.ioKnown, kv.second.ioRead,
                           kv.second.ioWrite);
    }
    // Join bookmarks on every snapshot (one cheap HKCU read): the pinned
    // column and tag then work in the CLI exactly as in the GUI, which
    // joins them per refresh in RefreshBookmarkMarks.
    //
    // Address AND port AND note are all carried: the port is the bookmark's
    // identity (matching on the address alone painted the wrong conversation -
    // see ConnectionStore::JoinBookmarks) and the note is what makes
    // `note:<text>` a working filter instead of a literal string search.
    {
        size_t unreadable = 0;
        const std::vector<Bookmark> all = Bookmarks::List(&unreadable);
        (void)unreadable;  // corrupt entries are skipped, same as the GUI
        std::vector<BookmarkMark> known;
        known.reserve(all.size());
        for (const Bookmark& b : all) {
            BookmarkMark m;
            m.address = b.address;
            m.port = b.port;
            m.tag = b.tag;
            m.note = b.note;
            known.push_back(std::move(m));
        }
        store.JoinBookmarks(known);
    }
    return true;
}

// Process-lifetime socket sampler for --traffic. Deliberately leaked (one
// object per process, never freed): a scan thread wedged in SIO_TCP_INFO
// holds a pointer to it and cannot be cancelled - the same documented
// trade-off as the GUI's sampler. Reused across polls so the learned
// socket-type filter persists and later scans stay fast.
//
// The slot is atomic and the object is built through a function-local static,
// so two threads racing to arm the sampler construct exactly ONE instance
// (C++11's thread-safe static initialization) instead of leaking a second and
// racing on the pointer. The slot only publishes it for ActiveTrafficSampler().
std::atomic<SocketTrafficSampler*>& TrafficSamplerSlot() {
    static std::atomic<SocketTrafficSampler*> s{nullptr};
    return s;
}

SocketTrafficSampler* ActiveTrafficSampler() {
    return TrafficSamplerSlot().load(std::memory_order_acquire);
}
SocketTrafficSampler& TrafficSampler() {
    static SocketTrafficSampler* const s = new SocketTrafficSampler();
    TrafficSamplerSlot().store(s, std::memory_order_release);
    return *s;
}

namespace {
// Cooperative cancellation flag - see the public accessors just below. File
// local: only this TU's joins read it, and only the front end writes it.
std::atomic<bool> g_cancelRequested{false};
}  // namespace

// ---- cooperative cancellation (public: Commands.h) --------------------------
// Relaxed ordering is enough: the flag is a one-way latch, and every consumer
// re-reads its own state after observing it.
void RequestCancellation() { g_cancelRequested.store(true, std::memory_order_relaxed); }
bool CancellationRequested() { return g_cancelRequested.load(std::memory_order_relaxed); }
void ResetCancellation() { g_cancelRequested.store(false, std::memory_order_relaxed); }

void JoinDnsAddrs(ConnectionStore& store,
                  const std::vector<std::wstring>& addrs,
                  unsigned timeoutMs /* =0 = resolver default */,
                  unsigned* stuckOut /* =nullptr */) {
    std::set<std::wstring> seen;
    unsigned stuck = 0;
    for (const std::wstring& a : addrs) {
        // Ctrl+C lands here: a reverse lookup is blocking and can take seconds,
        // so without this the join outlives the interrupt. What was already
        // resolved stays resolved.
        if (CancellationRequested()) break;
        if (a.empty() || !seen.insert(a).second) continue;
        const std::wstring host = DnsResolver::Lookup(a, timeoutMs);
        if (!host.empty()) store.SetHostname(a, host);
        // A stalled lookup is still "" (Lookup is synchronous), so count it:
        // callers that passed a timeout treat an empty result as "pending or
        // failed". The CLI emits one stderr line per run via stuckOut.
        if (timeoutMs != 0 && host.empty()) ++stuck;
    }
    if (stuckOut) *stuckOut = stuck;
}

// A remote endpoint plus its family for GeoIP lookup (values, not row
// pointers: joins mutate the store).
struct GeoTarget {
    std::wstring address;
    bool ipv6 = false;
};

bool JoinGeoAddrs(ConnectionStore& store, GeoIpDatabase& db,
                  const std::vector<GeoTarget>& targets) {
    for (const GeoTarget& t : targets) {
        std::wstring code;
        if (t.ipv6) {
            IN6_ADDR a6 = {};
            if (::InetPtonW(AF_INET6, t.address.c_str(), &a6) != 1) continue;
            code = db.LookupV6(a6.s6_addr);
        } else {
            IN_ADDR a4 = {};
            if (::InetPtonW(AF_INET, t.address.c_str(), &a4) != 1) continue;
            code = db.LookupV4(ntohl(a4.S_un.S_addr));
        }
        if (!code.empty()) store.SetCountry(t.address, code);
    }
    return true;
}

// The ASN join, shaped exactly like JoinGeoAddrs so the two read as a pair.
//
// Two differences from the country join, both deliberate:
//
// - The answer is written even when it is EMPTY. JoinGeoAddrs skips an empty code,
//   which is right there (a stale country must not be cleared by a database that
//   simply lacks this range) but wrong here in one specific case: a row whose ASN
//   was resolved by an earlier pass and is not covered by the file now loaded
//   should stop claiming an AS number. A stale AS number is a wrong answer;
//   a blank cell is not.
// - The parse failure is still a silent skip. An address the row printed but the
//   parser rejects is not the join's problem to report, and JoinGeoAddrs sets the
//   precedent.
bool JoinAsnAddrs(ConnectionStore& store, GeoIpDatabase& db,
                  const std::vector<GeoTarget>& targets) {
    for (const GeoTarget& t : targets) {
        AsnInfo info;
        if (t.ipv6) {
            IN6_ADDR a6 = {};
            if (::InetPtonW(AF_INET6, t.address.c_str(), &a6) != 1) continue;
            info = db.LookupAsnV6(a6.s6_addr);
        } else {
            IN_ADDR a4 = {};
            if (::InetPtonW(AF_INET, t.address.c_str(), &a4) != 1) continue;
            info = db.LookupAsnV4(ntohl(a4.S_un.S_addr));
        }
        store.SetAsn(t.address, info.number, info.org);
    }
    return true;
}

// One sentence for the traffic columns of this run, for both front ends.
//
// and this is the whole point of it: a blank traffic cell has three
// different causes that look identical on screen - the connection really moved
// nothing, the row could not be measured, or THE SCAN FAILED - and nothing in
// the output said which. Naming the third is the only one a reader can act on.
//
// Deliberately NOT phrased as an error. The run did print its rows and its
// exit code still means what it always meant, so prefixing this with "error"
// would overstate it; and it is deliberately not folded into the existing
// unenrichable-window note, which claims the opposite - that the ROWS are
// unmeasurable - and would be actively misleading here.
//
// ENDS IN "\r\n", which is not decoration. The list path appends this to the
// shared advisory string and every other producer of that string ends in a
// newline; the first version of this function did not, so it both broke the
// rule the CommandResult comment states and would have printed without a
// trailing line break. The rule caught its own first violation.
std::string TrafficScanFailedNote(unsigned passes) {
    return "note: " + std::to_string(passes) +
           " traffic scan" + (passes == 1 ? "" : "s") +
           " failed to read the process handle table, so every traffic "
           "column is unmeasured for this run (not zero). Re-run; if it "
           "persists the handle table is being denied.\r\n";
}

// The STALE half, which is a different problem with a different remedy - see
// TrafficScanGaps. Kept as its own sentence rather than folded into the
// failure note: one means "these numbers are old", the other means "these
// numbers are not there at all", and a sentence that said both at once would
// leave the reader unable to tell which they are looking at.
std::string TrafficScanDroppedNote(unsigned passes) {
    return "note: " + std::to_string(passes) +
           " traffic scan" + (passes == 1 ? "" : "s") +
           " abandoned because a socket's byte counters would not return, so "
           "the traffic columns show the LAST values read rather than current "
           "ones. Closing the owning connection clears it.\r\n";
}

// What this call could not measure. It was widened from a single failure
// count to both gap kinds, because a caller that learns about one and not the
// other still cannot answer the reader's question:
//
//   failures - a pass could not read the process handle table at all, so
//              NOTHING was merged and every traffic cell is UNMEASURED.
//   dropped  - a pass was abandoned because a worker stopped making progress,
//              so the PREVIOUS totals were kept and they are STALE.
//
// Both are deltas across this call, not the sampler's lifetime totals, because
// a one-shot `list --traffic` must report what went wrong with ITS scan.
//
// The early return on an empty PID set reports zeros, not a failure: there was
// nothing to scan, so nothing failed. Counting it would fire the diagnostic on
// every `--select` that matched no process at all.
struct TrafficScanGaps {
    unsigned failures = 0;
    unsigned dropped = 0;
};

TrafficScanGaps JoinTrafficPids(ConnectionStore& store,
                                const std::vector<DWORD>& pids) {
    if (pids.empty()) return TrafficScanGaps();
    const unsigned failBefore = TrafficSampler().ScanFailureCount();
    const unsigned dropBefore = TrafficSampler().TimeoutCount();
    const std::map<DWORD, PidTraffic> totals = TrafficSampler().Sample(pids);
    for (const auto& kv : totals)
        store.SetTraffic(kv.first, kv.second.rx, kv.second.tx);
    // Same scan, second reading: the kernel's own connection age. A single-shot
    // `list --traffic` then reports how old each connection REALLY is, instead
    // of 0s for everything (there is no first-seen to fall back on). Costs no
    // extra handle-table pass - the ages come from the sockets just read.
    const std::vector<SocketAge> ages = TrafficSampler().Ages(pids);
    store.ApplyKernelAges(ages);
    // ...and the same sockets' own byte counters, which is the only source
    // allowed to mark a row perRowBytes. Without this the Speed column and
    // `speed:` could never fire: nothing in the tree set the flag, so the
    // column read an em-dash on every tick of every watch while `help list`
    // advertised it. Applied AFTER SetTraffic on purpose - a per-socket total
    // must win over the per-PID total for the rows it covers, because it is
    // the more specific fact about the same cell.
    const std::vector<SocketBytes> bytes = TrafficSampler().Bytes(pids);
    store.ApplySocketBytes(bytes);
    // `ss -i` for Windows, from the SAME TCP_INFO_v0 reading as the bytes
    // and ages above - no extra handle duplication, no extra ioctl, no extra
    // pass over the handle table. RTT, minimum RTT, congestion window and
    // retransmitted bytes are per-socket facts, so this joins on the 4-tuple
    // exactly as ApplySocketBytes does and leaves a duplicate 4-tuple's second
    // row blank rather than inventing a share.
    const std::vector<SocketTcpInfo> tcpInfo = TrafficSampler().TcpInfo(pids);
    store.ApplySocketTcpInfo(tcpInfo);
    // Only now are all the readings in place (the previous sample was carried
    // forward by ReplaceSnapshot, this tick's counters were just written), so
    // both the per-connection and the per-process rate can be computed. See
    // ConnectionStore::ComputeRates for why this cannot happen earlier.
    (void)store.ComputeRates();
    TrafficScanGaps gaps;
    gaps.failures = TrafficSampler().ScanFailureCount() - failBefore;
    gaps.dropped = TrafficSampler().TimeoutCount() - dropBefore;
    return gaps;
}

// What the renderers will print for these options (remote addresses, GeoIP
// targets and PIDs as VALUES, never row pointers: the joins below mutate
// the store, which must not invalidate anything being iterated).
struct PrintSelection {
    std::vector<std::wstring> remotes;   // in view order, dedup not needed
    std::vector<GeoTarget> geoTargets;   // distinct remotes with family
    std::vector<DWORD> pids;             // distinct PIDs
};

// A clause on a JOINED column (tx/rx/net need --traffic, country needs
// --db, host needs --dns) cannot be evaluated before its join: the column is
// still empty, the clause rejects every row, and the join then has nothing
// left to fill - a filter that can only ever answer "no match". When the
// filter contains such a clause the candidate set is therefore the rows
// matching the OTHER clauses; the join fills those, and RenderList applies
// the full filter afterwards against the filled values.
//
// DURATION belongs here for the same reason. With --traffic the kernel's own
// connection age is one of the joined values: ApplyKernelAges backdates
// firstSeenTick, and the Duration column reads it. Before that join the only
// age a row has is the store's first-seen clock, which for a one-shot `list`
// is "right now" - so every row reads 0s. Pre-filtering on `duration:1h`
// therefore rejected the whole table, sel.pids came out EMPTY, no PID was
// ever sampled, and the filter could only ever answer "no rows" while the
// same rows were about to print "6d 8h". Measured: every row reached
// MatchClause with firstSeen == nowTick, i.e. secs == 0.
// the four TCP_INFO fields join in exactly like the byte counters - they
// are filled by the socket scan - so a clause on any of them must be treated
// as enrichment-dependent or it is evaluated against an empty column.
//
// Measured consequence of getting this wrong, which is why it is called out
// rather than left implicit: `--filter "cwnd:"` printed 0 rows while the same
// command WITHOUT the filter showed a dozen rows with real congestion windows.
// The pre-join pass filtered on the empty column, so `sel.pids` came out EMPTY,
// so no PID was ever sampled, so the filter could only ever answer "no match" -
// and the columns it was asking about were about to be filled on rows that had
// already been discarded.
//
// SPEED was the last field added here, and it looked exempt for a reason that
// turns out not to be one: it needs two snapshots, so it is empty on the first
// and "would not have matched anyway". That only describes tick 1. The view is
// filtered BEFORE the join, the filtered view is what yields sel.pids, and
// JoinTrafficPids returns at once on an empty PID set - so the scan that would
// have filled the column on tick 2 never runs, and every tick after it is
// filtered against the same empty column. The column stays empty BECAUSE the
// filter is present, which reads to the user as "no row matches".
// Measured: `list --traffic --watch 1 --count 2 --filter "speed:0"` printed no
// data rows on either tick, while the same command WITHOUT the filter printed
// `idle` on the second tick.
bool DependsOnEnrichment(FilterField f) {
    return f == FilterField::Rx || f == FilterField::Tx ||
           f == FilterField::Net || f == FilterField::Country ||
           f == FilterField::Asn ||
           f == FilterField::Asn ||
           f == FilterField::Host || f == FilterField::Duration ||
           f == FilterField::Rtt || f == FilterField::MinRtt ||
           f == FilterField::Cwnd || f == FilterField::Retrans ||
           f == FilterField::Speed ||
           // only. Ppid, Parent and Integrity are deliberately ABSENT:
           // they are filled by the process resolver during the snapshot
           // itself, which runs before any filter is applied, so a clause on
           // one of them sees a populated column and must not be deferred.
           // Marking them enrichment-dependent would be actively harmful - the
           // pre-join path would filter on the still-empty column, produce an
           // empty view, and skip the resolver, so the filter could only ever
           // answer "no match" for the same reason `cwnd:` did.
           f == FilterField::Signature;
}

// True when any clause of 'filter' needs an enrichment join first. Negated
// clauses count: they compare the same joined value.
bool HasEnrichmentClause(const std::wstring& filter) {
    if (filter.empty()) return false;
    std::vector<FilterClause> all;
    ParseFilter(filter, all);
    for (const FilterClause& cl : all)
        if (DependsOnEnrichment(cl.field)) return true;
    return false;
}

// 'filter' with every enrichment-dependent clause removed. Empty means "no
// restriction beyond the other switches", which is the widest candidate set
// the pre-pass can legitimately use.
std::vector<FilterClause> PreJoinClauses(const std::wstring& filter) {
    std::vector<FilterClause> out;
    if (filter.empty()) return out;
    std::vector<FilterClause> all;
    ParseFilter(filter, all);
    for (const FilterClause& cl : all)
        if (!DependsOnEnrichment(cl.field)) out.push_back(cl);
    return out;
}

// The switch each enrichment-dependent clause needs to mean anything. When
// that switch is off the joined column stays empty forever and the clause can
// only ever answer "no match" - measured: `list --filter host:easeus` printed
// a header, rc 0, and NOTHING on stderr, so the caller had no way to learn
// that the filter was being asked a question its own switches left
// unanswerable. This names the switch instead. Advisory only: never fatal,
// never on stdout, never under --quiet (quiet = zero bytes).
//
// DURATION is deliberately absent: in --watch the persistent store's own
// clock ages rows with no --traffic involved, so "add --traffic" would be a
// lie there; in a one-shot the Duration column already shows the 0s the
// filter is failing on, so the empty match is visible in the row itself.
// split into parts so the two contracts cannot drift. The FILTER
// half is quiet-agnostic - the CLI's quiet refusal (exit 2) needs to see
// exactly what the advisory path suppresses - and excludes columns,
// because `--quiet`'s exit code answers "does the FILTER match" and a
// requested column cannot change that answer. MissingEnrichmentAdvice
// below keeps its original promise: advisory only, silent under quiet.
std::string FilterEnrichmentAdvice(const ListOptions& opt) {
    std::string out;
    if (!opt.filter.empty()) {
        std::vector<FilterClause> all;
        ParseFilter(opt.filter, all);
        bool needDns = false, needGeo = false, needAsn = false, needTraffic = false;
        for (const FilterClause& cl : all) {
            if (!DependsOnEnrichment(cl.field)) continue;
            if (cl.field == FilterField::Host) {
                if (!opt.dns) needDns = true;
            } else if (cl.field == FilterField::Country) {
                if (opt.geoIpPath.empty()) needGeo = true;
            } else if (cl.field == FilterField::Asn) {
                if (opt.asnIpPath.empty()) needAsn = true;
            } else if (cl.field != FilterField::Duration) {
                if (!opt.traffic) needTraffic = true;
            }
        }
        if (needDns)
            out += "filter: \"host:\" matches reverse-DNS names; add --dns "
                   "(blocking; resolves every candidate remote).\r\n";
        if (needGeo)
            out += "filter: \"country:\" matches GeoIP codes; add --db "
                   "<path to a .mmdb database>.\r\n";
        if (needAsn)
            out += "filter: \"asn:\" matches autonomous systems; add --asn-db "
                   "<path to a GeoLite2-ASN .mmdb>.\r\n";
        if (needTraffic) {
            // Name the fields the user actually typed where possible. A bare
            // "add --traffic" for `rtt:100` would be true but unhelpful - the
            // reader has to work out which of seven traffic-dependent fields
            // their query is about.
            std::string named;
            auto addName = [&named](const char* n) {
                if (!named.empty()) named += ", ";
                named += n;
            };
            bool anyRtt = false, anyByte = false, anySpeed = false, anySig = false;
            for (const FilterClause& cl : all) {
                if (!DependsOnEnrichment(cl.field)) continue;
                switch (cl.field) {
                    case FilterField::Rtt:    addName("\"rtt:\""); anyRtt = true; break;
                    case FilterField::MinRtt: addName("\"minrtt:\""); anyRtt = true; break;
                    case FilterField::Cwnd:   addName("\"cwnd:\""); anyByte = true; break;
                    case FilterField::Retrans:addName("\"retrans:\""); anyByte = true; break;
                    case FilterField::Rx:     addName("\"rx:\""); anyByte = true; break;
                    case FilterField::Tx:     addName("\"tx:\""); anyByte = true; break;
                    case FilterField::Net:    addName("\"net:\""); anyByte = true; break;
                    // Speed is not a "traffic total" and must not be described
                    // as one: it is a RATE, and a rate takes two samples, so
                    // naming --traffic alone would send the reader into a
                    // second silent-empty run. Both facts go in the note.
                    case FilterField::Speed:  addName("\"speed:\""); anySpeed = true; break;
                    // Its own note, and NOT the traffic wording: the
                    // signature verdict is read during the snapshot rather than
                    // by the socket scan, so telling the reader to add
                    // --traffic would send them down a switch that cannot
                    // possibly change the answer.
                    case FilterField::Signature:
                        addName("\"signature:\"");
                        anySig = true;
                        break;
                    default: break;
                }
            }
            // Signature is checked FIRST, and separately from the rest: the
            // advice is a sentence about one switch, and a filter mixing
            // `signature:` with `rx:` is two questions that need two answers.
            if (anySig) {
                out += "filter: " + named +
                       " match Authenticode verdicts, which are not read unless "
                       "you ask for them; add --signatures.\r\n";
            } else if (anyRtt) {
                out += "filter: " + named +
                       " match TCP congestion state read from the kernel's "
                       "SIO_TCP_INFO; add --traffic.\r\n";
            } else if (anySpeed) {
                out += "filter: " + named +
                       " is a rate between two samples of the same socket; add "
                       "--traffic and re-run with --watch 1 --count 2.\r\n";
            } else if (!named.empty()) {
                out += "filter: " + named +
                       " match traffic totals; add --traffic.\r\n";
            }
        }
    }
    return out;
}

std::string ColumnEnrichmentAdvice(const ListOptions& opt) {
    std::string out;
    // The columns half: a printed enrichment column whose switch is off
    // is the same silent-empty failure this advice exists to prevent for
    // filters - every row comes out blank and nothing says why. Measured:
    // `list --columns rx` printed a full column of em-dashes with no
    // explanation.
    // Same contract as the filter half: stderr only, never fatal, nothing
    // under --quiet (handled by the guard above).
    //
    // Speed/TLS are deliberately absent: Bandwidth only ever fills in a
    // --watch poll (it is a delta between samples), so "add --traffic" would
    // not be enough of an answer, and no list switch decodes TLS at all.
    bool colHost = false, colGeo = false, colSig = false;
    std::string colTraffic;
    auto addColName = [](std::string& s, const char* n) {
        if (!s.empty()) s += ", ";
        s += n;
    };
    for (int c : ListColumns(opt)) {
        if (c == COL_HOST) colHost = true;
        else if (c == COL_COUNTRY) colGeo = true;
        else if (c == COL_RX) addColName(colTraffic, "\"rx\"");
        else if (c == COL_TX) addColName(colTraffic, "\"tx\"");
        else if (c == COL_NETTOTAL) addColName(colTraffic, "\"nettotal\"");
        else if (c == COL_TRAFFIC) addColName(colTraffic, "\"traffic\"");
        // all four are filled by the same socket scan as the byte counters,
        // so "add --traffic" is exactly as true for them as for "rx".
        else if (c == COL_RTT)     addColName(colTraffic, "\"rtt\"");
        else if (c == COL_MINRTT)  addColName(colTraffic, "\"minrtt\"");
        else if (c == COL_CWND)    addColName(colTraffic, "\"cwnd\"");
        else if (c == COL_RETRANS) addColName(colTraffic, "\"retrans\"");
        // and NOT folded into colTraffic: this column is empty because the
        // trust provider was never asked, which is a different problem from the
        // socket scan not having run, and the fix is a different switch.
        else if (c == COL_SIGNATURE) colSig = true;
    }
    if (colHost && !opt.dns)
        out += "column: \"host\" without --dns: reverse DNS never ran, so the "
               "cell stays empty; add --dns (blocking; resolves every "
               "candidate remote).\r\n";
    // The country cell half-comes from --db and half from --asn-db, so
    // "the cell stays empty" is FALSE whenever either is loaded: an ASN database
    // fills the same cell with "AS15169 Google LLC" and no country code. The
    // message used to claim the cell stayed empty in that case, which is both
    // wrong and the opposite of helpful - the user is looking at a populated cell
    // while being told it is blank. Say precisely which HALF is missing.
    if (colGeo && opt.geoIpPath.empty() && opt.asnIpPath.empty()) {
        out += "column: \"country\" without --db: GeoIP never ran, so the cell "
               "stays empty; add --db <path to a .mmdb database>.\r\n";
    } else if (colGeo && opt.geoIpPath.empty()) {
        out += "column: \"country\" without --db: the ASN half is filled from "
               "--asn-db, but no country code is, so the cell shows only "
               "\"AS<n> <org>\"; add --db for the code.\r\n";
    }
    if (colSig && !opt.signatures)
        out += "column: \"signature\" without --signatures: WinVerifyTrust was "
               "never called, so the cell is \"—\" rather than a verdict; add "
               "--signatures (slow; paid once per distinct binary).\r\n";
    if (!colTraffic.empty() && !opt.traffic)
        out += "column: " + colTraffic +
               " without --traffic: the socket scan never ran, so every value "
               "is \"—\"; add --traffic.\r\n";
    return out;
}

std::string EnrichmentAdvice(const ListOptions& opt) {
    return FilterEnrichmentAdvice(opt) + ColumnEnrichmentAdvice(opt);
}

std::string MissingEnrichmentAdvice(const ListOptions& opt) {
    if (opt.quiet) return {};
    return EnrichmentAdvice(opt);
}

PrintSelection SelectedForPrint(ConnectionStore& store,
                                const ListOptions& opt) {
    PrintSelection sel;
    // unordered: these are membership-only sets on the hot selection path, so a
    // hash lookup beats the red-black tree's compares (and needs no ordering).
    std::unordered_set<std::wstring> seenAddr;
    std::unordered_set<DWORD> seenPid;

    if (HasEnrichmentClause(opt.filter)) {
        // Pre-join path. The view would be filtered by the very columns the
        // join has not filled yet, so candidates come from the flat rows with
        // those clauses removed. Traffic is one bounded scan over the PID
        // set and GeoIP is a memory-mapped lookup, so covering every
        // candidate is cheap; DNS is blocking, so it honours --limit unless a
        // host: clause makes resolving mandatory.
        const std::vector<FilterClause> pre = PreJoinClauses(opt.filter);
        bool needsHost = false;
        {
            std::vector<FilterClause> all;
            ParseFilter(opt.filter, all);
            for (const FilterClause& cl : all)
                if (cl.field == FilterField::Host) needsHost = true;
        }
        for (const Connection& c : store.Rows()) {
            if (c.flags & kRowRemoved) continue;
            if (!pre.empty() && !MatchFilter(c, pre)) continue;
            if (seenPid.insert(c.identity.pid).second) sel.pids.push_back(c.identity.pid);
            if (c.display.remoteAddress.empty()) continue;
            if (seenAddr.insert(c.display.remoteAddress).second) {
                GeoTarget t;
                t.address = c.display.remoteAddress;
                t.ipv6 = (c.identity.family == AF_INET6);
                sel.geoTargets.push_back(t);
            }
            if (needsHost || opt.limit == 0 || sel.remotes.size() < opt.limit)
                sel.remotes.push_back(c.display.remoteAddress);
        }
        return sel;
    }

    std::vector<FilterClause> prog;
    ViewState v;
    v.filter = opt.filter;
    v.protoMask = opt.protoMask;
    v.stateFilter = opt.stateFilter;
    v.sortColumn = opt.sortColumn;
    v.sortAsc = opt.sortAsc;
    v.grouped = opt.grouped;
    v.ApplyTo(&store, &prog);
    if (store.Grouped()) {
        // Grouped output aggregates. Per-address enrichment (DNS/GeoIP) stays
        // skipped - a group header cannot resolve as one address - but TRAFFIC
        // is per-PID, and a group row IS one PID: skipping it blanked the very
        // columns `--sort nettotal` exists for (every group printed "—").
        // Collect the visible groups' PIDs here; the join lands on the flat
        // member rows, and RenderList's ApplyListView rebuilds the groups
        // (GroupByProcess takes max-over-members) with the totals attached.
        for (size_t i = 0; i < store.View().size(); ++i) {
            const Connection* c = store.ViewRow(i);
            if (c == nullptr) continue;
            if (seenPid.insert(c->identity.pid).second) sel.pids.push_back(c->identity.pid);
        }
        return sel;
    }
    // Traffic is one bounded scan for the whole PID set, so PIDs come from
    // every view row: sampling only the printed rows would make
    // `--sort nettotal` order unsampled (zero) rows. DNS/GeoIP are
    // per-address and expensive, so they honor --limit.
    for (size_t i = 0; i < store.View().size(); ++i) {
        const Connection* c = store.ViewRow(i);
        if (c == nullptr) continue;
        if (seenPid.insert(c->identity.pid).second) sel.pids.push_back(c->identity.pid);
    }
    for (size_t i = 0; i < store.View().size(); ++i) {
        if (opt.limit != 0 && sel.remotes.size() >= opt.limit) break;
        const Connection* c = store.ViewRow(i);
        if (c == nullptr) continue;
        sel.remotes.push_back(c->display.remoteAddress);
        if (seenAddr.insert(c->display.remoteAddress).second && !c->display.remoteAddress.empty()) {
            GeoTarget t;
            t.address = c->display.remoteAddress;
            t.ipv6 = (c->identity.family == AF_INET6);
            sel.geoTargets.push_back(t);
        }
    }
    return sel;
}

// Address enrichment needs a concrete remote IP. Process ownership and TCP
// state do not affect whether reverse DNS or GeoIP can resolve that address.
bool RowCanEnrich(const Connection& c) {
    if (c.display.remoteAddress.empty() || c.display.remoteAddress == L"*") return false;
    if (c.display.remoteAddress == L"0.0.0.0" || c.display.remoteAddress == L"::") return false;
    return true;
}

// `--limit N` truncates BEFORE the enrichment join, so when the head of
// the default (PID-ascending) table is TIME_WAIT / listener / wildcard rows
// the printed window is entirely unenrichable and every enrichment column
// reads `—` - which looks like the feature is broken when it is only that
// nothing in the window can be enriched.
//
// The default sort is NOT reordered to hide this: that is a CLI/GUI parity
// surface (the GUI list has the same head), and silently changing which rows
// `--limit` means is worse than saying so. Instead the caller gets one hint
// on STDERR - never on stdout, which must stay a clean table/CSV/JSON feed
// (the lesson).
//
// Scoped to what the hint can honestly claim: a per-ADDRESS join
// (DNS/GeoIP) over rows whose host/country columns are actually printed.
// Measured before that scoping: `list --group --traffic --sort tx --desc
// --limit 3 --columns process,tx,rx` printed rows carrying 43.80 GB of real
// traffic and then claimed "none of the 3 rows ... can be enriched", with
// advice that would not have helped anyway. Three cases it no longer
// pretends about: per-PID traffic (blank exactly when no totals were
// sampled - "state:estab" does not fix that, and no host/country is in
// play); grouped views (a group header cannot resolve as one address, so
// its blanks are design, not a bad --limit window - the advice would be a
// lie); and runs that print no host/country column at all (nothing visible
// is broken, so there is nothing to explain).
//
// Returns true when the hint was produced.
bool UnenrichableHeadWarning(const ConnectionStore& store,
                             const ListOptions& opt, std::string* err) {
    if (err == nullptr || opt.limit == 0 || opt.quiet) return false;
    if (!opt.dns && opt.geoIpPath.empty()) return false;  // no per-address join
    if (store.Grouped()) return false;                    // never resolvable
    bool showsRemote = false;
    for (int c : ListColumns(opt)) {
        if (c == COL_HOST || c == COL_COUNTRY) showsRemote = true;
    }
    if (!showsRemote) return false;  // no enrichment column printed
    if (opt.filter.find(L"state:") != std::wstring::npos) return false;
    size_t shown = 0, enrichable = 0;
    for (size_t i = 0; i < store.View().size(); ++i) {
        if (shown >= opt.limit) break;
        const Connection* c = store.ViewRow(i);
        if (c == nullptr) continue;
        ++shown;
        if (RowCanEnrich(*c)) ++enrichable;
    }
    if (shown == 0 || enrichable != 0) return false;
    // "note:", not the verb prefix: the run succeeded and printed; this is an
    // observation about the window, not a failure (an error-styled prefix made
    // it read like an internal fault).
    *err = "note: none of the " + std::to_string(shown) +
           " rows in --limit can be enriched (TIME_WAIT/listener/wildcard); "
           "add a filter such as \"state:estab\" to see host/country.\r\n";
    return true;
}

// View-scoped enrichment for list/export: DNS + GeoIP + traffic over the
// printed rows only. Returns false + err when the GeoIP database fails;
// DNS/traffic failures are silent per-address (em-dash), never fatal.
// 'advice', when non-null, receives an OPTIONAL hint (the unenrichable
// window) that is never fatal: the run still succeeds and still prints.
bool EnrichViewForList(ConnectionStore& store, const ListOptions& opt,
                       std::wstring* err, std::string* advice) {
    // Missing-switch advice first: it must fire even when NO join runs below
    // (that early return is exactly the case it exists for).
    if (advice != nullptr) *advice = MissingEnrichmentAdvice(opt);
    if (!opt.dns && !opt.traffic && opt.geoIpPath.empty() &&
        opt.asnIpPath.empty()) {
        return true;
    }
    const PrintSelection sel = SelectedForPrint(store, opt);
    if (opt.dns) {
        unsigned stuck = 0;
        // when --dns-timeout is set, stale/empty answers from lookups
        // that exceeded the budget are reported as pending via the stall
        // count rather than silently rendered as `—`. Lookup itself is
        // synchronous (getnameinfo is uncancellable), so a genuinely wedged
        // resolver still blocks the CLI - but the advisory tells the user how
        // many names were affected, and the GUI worker (Run) gets the real
        // per-tick budget.
        JoinDnsAddrs(store, sel.remotes, opt.dnsTimeoutMs, &stuck);
        if (opt.dnsTimeoutMs != 0 && stuck > 0 && err != nullptr) {
            const std::string note =
                "note: " + std::to_string(stuck) + " reverse-DNS "
                "lookup(s) exceeded --dns-timeout "
                + std::to_string(opt.dnsTimeoutMs)
                + " ms and show as pending; re-run with a larger value or "
                "against a reachable resolver.\r\n";
            *err += Utf8ToWide(note.c_str());
        }
    }
    if (!opt.geoIpPath.empty()) {
        GeoIpDatabase db;
        std::wstring loadErr;
        if (!db.Load(opt.geoIpPath.c_str(), &loadErr)) {
            if (err != nullptr) *err = loadErr;
            return false;
        }
        JoinGeoAddrs(store, db, sel.geoTargets);
    }
    // A separate block, not a second Load inside the one above: the two
    // databases are different files, and a user may legitimately supply either or
    // both. The error prefix says ASN so a bad path is attributable - the same
    // message twice with different files behind it is not an error message.
    if (!opt.asnIpPath.empty()) {
        GeoIpDatabase asnDb;
        std::wstring loadErr;
        if (!asnDb.Load(opt.asnIpPath.c_str(), &loadErr)) {
            if (err != nullptr) *err = L"ASN database: " + loadErr;
            return false;
        }
        JoinAsnAddrs(store, asnDb, sel.geoTargets);
    }
    if (opt.traffic) {
        // A failed pass is named explicitly, and BEFORE the unenrichable-window
        // note below - that note claims the rows are unmeasurable, which is
        // exactly the wrong diagnosis when the cause was the scan. The
        // unenrichable note also declines to fire for traffic columns at all
        // (see its own comment: per-PID blanks used to be indistinguishable
        // from no-totals, which is precisely the gap this closes).
        const TrafficScanGaps gaps = JoinTrafficPids(store, sel.pids);
        // Both gap kinds, in the order that matters: UNMEASURED before STALE,
        // because "we measured nothing" is the answer that must not be trusted
        // and a reader who sees only the second would conclude the first did
        // not happen.
        // GATED ON QUIET, and that gate was MISSING here until it was found.
        // MissingEnrichmentAdvice() returns {} under --quiet, but it only
        // covers the advice it produces ITSELF - anything appended to the
        // same string afterwards went straight out. The dropped-pass note hit
        // that immediately: the CLI test's "quiet zero bytes" check failed, because
        // --quiet promises no output at all and the exit code is the whole
        // answer. The scan-failure note above had the SAME latent bug,
        // invisible only because a failed scan is unreachable from a test.
        //
        // So the rule is enforced where a note is ADDED, not only where the
        // advice string is CREATED. UnenrichableHeadWarning already gates on
        // opt.quiet for the same reason.
        if (advice != nullptr && !opt.quiet) {
            if (gaps.failures != 0) *advice += TrafficScanFailedNote(gaps.failures);
            if (gaps.dropped != 0) *advice += TrafficScanDroppedNote(gaps.dropped);
        }
    }
    if (HasEnrichmentClause(opt.filter)) {
        // A filter with an enrichment clause has had NO view applied yet:
        // SelectedForPrint's pre-join branch works off the flat rows (the
        // columns the clause matches on were empty), and export applies its
        // view BEFORE the joins run. Measured: `export --dns --filter
        // "host:com"` wrote a silent 0-row file while the same filter on
        // `list` printed 55 rows, and the head hint saw view=0 on every
        // pre-join filter. The joins have filled those columns now, so apply
        // the filter for real: this is the view it inspects below, and the
        // rows export writes to its file. RenderList re-applies the same
        // filter afterwards and yields the same view, so list output is
        // unchanged by this.
        ApplyListView(store, opt);
    }
    // Advisory only: reported on stderr, never fatal, never on stdout.
    // Appended, not assigned: the missing-switch advice above may already be
    // present and both are worth seeing.
    std::string hint;
    if (UnenrichableHeadWarning(store, opt, &hint) && advice != nullptr) {
        *advice += hint;
    }
    return true;
}

CommandResult RenderList(ConnectionStore& store, const ListOptions& opt,
                         bool skipHeader) {
    CommandResult r;
    // enforced HERE so it covers every machine-readable shape at once -
    // `export` and `list --format csv|tsv|json` - rather than per call site.
    //
    // A grouped stream cannot honestly carry a per-connection column: there is
    // no group-level answer for a remote address, a hostname, a duration or a
    // country, so the cell falls through to one arbitrary member while the
    // header still promises the column. Measured before this: a 4-connection
    // process exported the single value "0.0.0.0" under a header reading
    // "Remote address", and a spreadsheet loads that without complaint.
    //
    // The `table` format is deliberately exempt. There the row is visibly a
    // group - its State cell reads "4 connections" - so a representative
    // address is informative, and blanking it would be strictly less useful.
    // That is the same reason the GUI keeps it, and it is why this rule lives
    // in the stream path rather than in GroupColumnText.
    {
        const std::string bad = ValidateStreamColumns(opt);
        if (!bad.empty()) {
            r.exitCode = kExitArgs;
            r.err = "--group cannot report " + bad +
                    ": a group is one process, and that column describes one "
                    "connection, so a " +
                    (opt.format == "json" ? "JSON key" : "file header") +
                    " would promise a value the rows do not carry.\r\n"
                    "Drop the column, or drop --group. Columns that DO have a "
                    "group answer: pid, process, proto, state, traffic, rx, "
                    "tx, nettotal, cpu, mem, disk, service, path, pinned.\r\n"
                    "(The aligned `table` output is exempt: its State column "
                    "already shows the connection count, so a representative "
                    "value there is readable rather than misleading.)\r\n";
            return r;
        }
    }
    ApplyListView(store, opt);
    if (opt.quiet) {
        // No output at all; the exit code is the whole answer.
        r.exitCode = store.View().empty() ? kExitFail : kExitOk;
        return r;
    }
    if (opt.format == "json") {
        r.out = JsonList(store, opt);
    } else {
        r.out = DelimitedList(store, opt, skipHeader);
    }
    return r;
}

// One snapshot pass of `list` into a CALLER-owned store.
//
// CmdList (below) owns a throwaway store, which is right for a single shot.
// The watch loop cannot: it re-enters this function every tick, and a fresh
// store means a fresh firstSeenTick, so Duration read 0s on every poll - a
// connection looked older with every refresh. Keeping the store (and the
// SnapshotSource, which caches PID->name/service) across ticks is what makes
// the per-row lifetime state accumulate. Deliberately the ONLY implementation
// of the list pass, so the two entry points cannot drift apart.
CommandResult CmdListInto(SnapshotSource& source, ConnectionStore& store,
                          const ListOptions& opt) {
    CommandResult r;
    std::wstring err;
    // Before the pass, because the resolver reads the flag while it
    // resolves - and on EVERY pass, not just the first: `list --watch` re-enters
    // this function per tick against the same source, so setting it once at
    // startup would be fine, but the GUI shares a source with `details` and
    // resetting it here keeps each pass independent of how the last one ran.
    source.SetVerifySignatures(opt.signatures);
    if (!BuildStoreSnapshot(source, store, /*procStats=*/true,
                            /*resolveDns=*/false, /*geoIp=*/false, nullptr,
                            &err)) {
        r.exitCode = kExitFail;
        r.err = "Enumeration failed: " + WideToUtf8(err) + "\r\n";
        return r;
    }
    // the fixed frame first. The columns are known the moment the
    // snapshot exists, and the enrichment joins below can take seconds
    // (--dns resolves, --traffic scans) - so the header goes to stdout NOW,
    // while the rows follow in r.out when they are ready. json has no
    // header line to lead with; --quiet prints nothing at all. RenderList's
    // skipHeader keeps the combined byte stream identical to an unstreamed
    // run: same header, same widths, same rows.
    const bool streamHeader =
        opt.streamHeader && !opt.quiet && opt.format != "json";
    if (streamHeader) StreamOut(ListHeaderLine(store, opt));
    std::string advice;
    if (!EnrichViewForList(store, opt, &err, &advice)) {
        r.exitCode = kExitFail;
        r.err = "GeoIP: " + WideToUtf8(err) + "\r\n";
        return r;
    }
    // hint. Appended AFTER RenderList fills r.out, and the caller prints r.err
    // on stderr, so the table/CSV/JSON on stdout stays byte-identical to a run
    // without the hint - a consumer parsing stdout cannot tell the difference.
    r = RenderList(store, opt, /*skipHeader=*/streamHeader);
    if (!advice.empty()) {
        if (!r.err.empty()) r.err += advice;
        else r.err = advice;
    }
    return r;
}

CommandResult CmdList(SnapshotSource& source, const ListOptions& opt) {
    ConnectionStore store;   // single shot: this store dies with the command
    return CmdListInto(source, store, opt);
}

// One-decimal CPU text shared by the ps table and JSON paths, so a
// machine-readable consumer sees the same number a human does: a raw
// std::to_wstring(double) prints 12.300000 where the table prints 12.3.
std::wstring CpuOneDecimal(double cpu) {
    wchar_t buf[kNumTextChars] = {0};
    ::swprintf_s(buf, L"%.1f", cpu);
    return buf;
}

CommandResult RenderPs(ConnectionStore& store, const PsOptions& opt) {
    CommandResult r;
    // Filter rows first, then aggregate the survivors by PID.
    std::vector<FilterClause> prog;
    if (!opt.filter.empty()) ParseFilter(opt.filter, prog);
    struct Agg {
        std::wstring name;
        size_t conns = 0;
        double cpu = -1.0;
        ULONGLONG mem = 0;
        bool memKnown = false;
        ULONGLONG disk = 0;
        bool diskKnown = false;
    };
    std::map<DWORD, Agg> byPid;
    for (const Connection& c : store.Rows()) {
        if (c.flags & kRowRemoved) continue;
        if (!prog.empty() && !MatchFilter(c, prog))
            continue;
        Agg& a = byPid[c.identity.pid];
        if (a.name.empty()) a.name = c.display.processName;
        ++a.conns;
        if (c.procStats.cpuPct >= 0.0) a.cpu = c.procStats.cpuPct;
        if (c.procStats.memKnown) {
            a.memKnown = true;
            if (a.mem == 0) a.mem = c.procStats.memWorkingSet;
        }
        if (c.procStats.ioKnown) {
            a.diskKnown = true;
            if (a.disk == 0) a.disk = c.procStats.diskReadBytes + c.procStats.diskWriteBytes;
        }
    }
    struct Row {
        DWORD pid;
        Agg a;
    };
    std::vector<Row> rows;
    for (const auto& kv : byPid) rows.push_back(Row{kv.first, kv.second});
    if (opt.quiet) {
        r.exitCode = rows.empty() ? kExitFail : kExitOk;
        return r;
    }
    const std::string key = opt.sortBy;
    std::sort(rows.begin(), rows.end(), [&](const Row& x, const Row& y) {
        if (key == "mem") {
            if (x.a.memKnown != y.a.memKnown)
                return x.a.memKnown > y.a.memKnown;
            if (x.a.mem != y.a.mem) return x.a.mem > y.a.mem;
            return x.pid < y.pid;
        }
        if (key == "disk") {
            if (x.a.diskKnown != y.a.diskKnown)
                return x.a.diskKnown > y.a.diskKnown;
            if (x.a.disk != y.a.disk) return x.a.disk > y.a.disk;
            return x.pid < y.pid;
        }
        if (key == "conns") {
            if (x.a.conns != y.a.conns) return x.a.conns > y.a.conns;
            return x.pid < y.pid;
        }
        if (key == "pid") return x.pid < y.pid;
        if (key == "process") {
            if (x.a.name != y.a.name) return x.a.name < y.a.name;
            return x.pid < y.pid;
        }
        // "cpu" (default): known first, hottest first, pid tiebreak.
        if ((x.a.cpu >= 0.0) != (y.a.cpu >= 0.0))
            return x.a.cpu >= 0.0;
        if (x.a.cpu != y.a.cpu) return x.a.cpu > y.a.cpu;
        return x.pid < y.pid;
    });
    const bool csv = (opt.format == "csv");
    const char delim = csv ? ',' : '\t';
    if (opt.format == "json") {
        std::string out = "[";
        bool first = true;
        size_t shown = 0;
        for (const Row& row : rows) {
            if (opt.limit != 0 && shown >= opt.limit) break;
            if (!first) out += ",";
            out += "\n  {\"pid\":" + std::to_string(row.pid) + ",\"process\":\"" +
                   JsonEscapeA(row.a.name) + "\",\"connections\":" +
                   std::to_string(row.a.conns) + ",\"cpu\":\"" +
                   JsonEscapeA(row.a.cpu >= 0.0
                                   ? CpuOneDecimal(row.a.cpu)
                                   : std::wstring(L"")) +
                   "\",\"memory\":\"" +
                   JsonEscapeA(row.a.memKnown ? FormatBytes(row.a.mem)
                                              : std::wstring(L"")) +
                   "\",\"disk\":\"" +
                   JsonEscapeA(row.a.diskKnown ? FormatBytes(row.a.disk)
                                               : std::wstring(L"")) +
                   "\"}";
            first = false;
            ++shown;
        }
        out += "\n]";
        r.out = out;
        return r;
    }
    // Collect the printed cells once; the aligned table and the
    // delimited shapes then render from the same strings.
    std::vector<std::vector<std::string>> cells;
    for (const Row& row : rows) {
        if (opt.limit != 0 && cells.size() >= opt.limit) break;
        wchar_t cpu[kNumTextChars] = {0};
        if (row.a.cpu >= 0.0)
            ::swprintf_s(cpu, L"%.1f", row.a.cpu);
        else
            ::swprintf_s(cpu, L"—");
        const std::wstring mem =
            row.a.memKnown ? FormatBytes(row.a.mem) : std::wstring(L"—");
        const std::wstring disk =
            row.a.diskKnown ? FormatBytes(row.a.disk) : std::wstring(L"—");
        cells.push_back({std::to_string(row.pid), TsvCell(row.a.name),
                         std::to_string(row.a.conns), TsvCell(cpu),
                         TsvCell(mem), TsvCell(disk)});
    }
    if (opt.format == "table") {
        // Numbers right, names left - the same split the GUI's list shows.
        const std::vector<std::string> header = {"PID", "Process", "Conns",
                                                 "CPU%", "Memory", "Disk"};
        const std::vector<bool> right = {true, false, true, true, true, true};
        r.out = RenderAlignedLines(header, cells, right,
                                   ContentWidths(header, cells), true);
        return r;
    }
    std::string out = std::string("PID") + delim + "Process" + delim +
                      "Conns" + delim + "CPU%" + delim + "Memory" + delim +
                      "Disk\r\n";
    for (const std::vector<std::string>& f : cells) {
        for (size_t i = 0; i < f.size(); ++i) {
            if (i != 0) out += delim;
            // CSV must quote a field containing a comma (a process name
            // can have one); the old path wrote it raw and produced
            // columns that did not line up for any parser.
            out += csv ? CsvEscapeUtf8(f[i]) : f[i];
        }
        out += "\r\n";
    }
    r.out = out;
    return r;
}

CommandResult CmdPs(SnapshotSource& source, const PsOptions& opt) {
    CommandResult r;
    ConnectionStore store;
    std::wstring err;
    if (!BuildStoreSnapshot(source, store, /*procStats=*/true,
                            /*resolveDns=*/false, /*geoIp=*/false, nullptr,
                            &err)) {
        r.exitCode = kExitFail;
        r.err = "Enumeration failed: " + WideToUtf8(err) + "\r\n";
        return r;
    }
    return RenderPs(store, opt);
}

// POST the current snapshot (or a test event) to a webhook URL. `test` sends a
// minimal event so an endpoint can be verified; otherwise a JSON summary of
// the live snapshot is sent. Delivery is bounded and a failure is reported as
// a non-zero exit, never a crash.
CommandResult CmdWebhook(const std::wstring& url, bool test) {
    if (url.empty()) {
        CommandResult r;
        r.exitCode = kExitArgs;
        r.err = "webhook: a URL is required.\r\n";
        return r;
    }
    std::string payload;
    if (test) {
        payload = "{\"test\":true,\"source\":\"wintcp\",\"time\":\"" +
                  UtcIso8601() + "\"}";
    } else {
        SnapshotSource source;
        ConnectionStore store;
        ListOptions opt;
        opt.format = "json";
        // Deliberately NO traffic: the summary is connection/state counts, which
        // ReplaceSnapshot already computes. Asking for traffic triggers the
        // per-socket SIO_TCP_INFO scan, whose detached probe threads can wedge in
        // an uncancelable kernel call - and a webhook must not hang on that.
        const CommandResult list = CmdListInto(source, store, opt);
        if (list.exitCode != kExitOk) {
            CommandResult r;
            r.exitCode = kExitFail;
            r.err = "webhook: snapshot unavailable.\r\n";
            return r;
        }
        const RowStats& st = store.Stats();
        payload = BuildStatePayload(UtcIso8601(), st.total, st.total - st.udp,
                                    st.udp,
                                    st.StateCount(MIB_TCP_STATE_ESTAB));
    }
    const bool ok = PostWebhook(url, payload);
    CommandResult r;
    r.exitCode = ok ? kExitOk : kExitFail;
    if (ok) {
        r.out = "webhook: delivered " + std::to_string(payload.size()) +
                " bytes to " + WideToUtf8(url) + "\r\n";
    } else {
        r.err =
            "webhook: delivery failed (unreachable host, non-2xx, or bad URL).\r\n";
    }
    return r;
}

DetailModel BuildDetailModel(const Connection& c,
                             const ConnectionStore& store,
                             bool threadsMayBlock) {
    DetailModel m;
    m.title = c.display.processName.empty() ? c.keys.protoLabel : c.display.processName;
    m.subtitle = L"PID " + std::to_wstring(c.identity.pid) + L"   ·   " +
                 c.display.localEndpoint + L"  →  " + c.display.remoteEndpoint;
    const std::wstring created =
        FormatFileTimeLocal(c.procMeta.processCreate, c.procMeta.processCreateKnown);
    const std::wstring cmdline =
        (c.identity.pid != 0) ? QueryProcessCommandLine(c.identity.pid) : std::wstring();
    const auto add = [](DetailSection& sec, const wchar_t* label,
                        const std::wstring& value, bool mono = false) {
        DetailField f;
        f.label = label;
        f.value = value.empty() ? L"—" : value;
        f.monospace = mono;
        sec.fields.push_back(std::move(f));
    };
    DetailSection proc;
    proc.title = L"Process";
    proc.tab = kTabProcess;
    add(proc, L"Name", c.display.processName);
    add(proc, L"PID", std::to_wstring(c.identity.pid));
    add(proc, L"Path", c.display.processPath);
    add(proc, L"Command line", cmdline, /*mono=*/true);
    add(proc, L"Started", created, /*mono=*/true);
    add(proc, L"Service", c.display.serviceName);
    if (c.lifetime.firstSeenTick != 0) {
        add(proc, L"First seen", FormatDuration(DurationSeconds(c)));
    }
    m.sections.push_back(std::move(proc));

    // ---- Threads ------------------------------------------
    //
    // What a process is doing, thread by thread. This is NOT a per-connection
    // thread, because no such thing is obtainable: MIB_TCPROW_OWNER_PID carries
    // no thread id and an AFD endpoint is owned by the process. See ProcessInfo.h.
    //
    // Rendered as ordinary fields rather than a special list: the label column
    // is 184 px, which suits "TID 8124", and reusing the two-column table means
    // the section scrolls, elides and copies for free.
    //
    // Ranked by CPU time, busiest first, because that ordering is the whole
    // answer to "what is this process doing" - a ranked list says which thread is
    // working, an unordered one says only how many there are. Ties break on
    // thread id so the list does not jitter between refreshes, and threads whose
    // times could not be read sort LAST rather than being treated as zero: a
    // protected process's threads have not done no work, they are unknown.
    {
        bool threadsKnown = false;
        unsigned threadsAgeMs = 0;
        std::vector<ThreadInfo> threads =
            ProcessThreads(c.identity.pid, threadsMayBlock, &threadsKnown,
                            &threadsAgeMs);
        if (c.identity.pid != 0 && (threadsKnown || !threads.empty())) {
            std::stable_sort(threads.begin(), threads.end(),
                             [](const ThreadInfo& a, const ThreadInfo& b) {
                                 if (a.timesKnown != b.timesKnown)
                                     return a.timesKnown;   // known before unknown
                                 if (a.cpu100ns != b.cpu100ns)
                                     return a.cpu100ns > b.cpu100ns;
                                 return a.tid < b.tid;
                             });

            DetailSection thr;
            thr.title = L"Threads (" + std::to_wstring(threads.size()) + L")";

            // "Now" in the same epoch as create100ns, for the age arithmetic.
            FILETIME nowFt = {};
            ::GetSystemTimeAsFileTime(&nowFt);
            const ULONGLONG now100ns =
                (static_cast<ULONGLONG>(nowFt.dwHighDateTime) << 32) |
                nowFt.dwLowDateTime;

            wchar_t label[kNumTextChars] = {0};
            for (const ThreadInfo& t : threads) {
                ::swprintf_s(label, L"TID %u", t.tid);
                std::wstring value;
                if (t.timesKnown) {
                    wchar_t buf[kThreadDetailChars] = {0};
                    // CPU as a duration, not bytes: this is the number a reader
                    // compares against the others, and "1.2 s" says that where
                    // "12000000" would only say that we counted.
                    const double cpuSec = static_cast<double>(t.cpu100ns) / 1e7;
                    ::swprintf_s(buf, L"cpu %.2f s", cpuSec);
                    value = buf;
                    if (t.create100ns != 0 && now100ns > t.create100ns) {
                        const double ageSec =
                            static_cast<double>(now100ns - t.create100ns) / 1e7;
                        value += L"   started " + FormatDuration(
                                                       static_cast<unsigned>(
                                                           ageSec));
                        value += L" ago";
                    }
                } else {
                    // Not zero. A protected process's threads have no readable
                    // times, and printing 0.00 s would be a fabricated
                    // measurement rather than an admission of ignorance.
                    value = L"cpu -   started -";
                }
                value += L"   pri " + std::to_wstring(t.basePriority);
                add(thr, label, value, /*mono=*/false);
            }

            // The note carries the two things the numbers cannot: how fresh they
            // are, and that the CPU figure is lifetime-since-thread-start rather
            // than since this window opened - which is otherwise a very easy
            // misreading.
            std::wstring note;
            if (threadsAgeMs != UINT_MAX) {
                note = L"sampled " + FormatDuration(threadsAgeMs / kMsPerSecond) +
                       L" ago; CPU time is total since each thread started, "
                       L"not since this window opened.";
            } else {
                note = L"reading threads...";
            }
            if (!threads.empty()) {
                bool anyUnknown = false;
                for (const ThreadInfo& t : threads) {
                    if (!t.timesKnown) { anyUnknown = true; break; }
                }
                if (anyUnknown) {
                    note += L"  Some threads belong to a process whose times "
                            L"cannot be read; those show - rather than 0.";
                }
            }
            thr.note = note;
            thr.tab = kTabProcess;
            m.sections.push_back(std::move(thr));
        } else if (c.identity.pid == 0) {
            // An ownerless row (TIME_WAIT) has no process and therefore no
            // threads. Saying so beats an empty section with no explanation.
            DetailSection thr;
            thr.title = L"Threads";
            thr.note = L"this row has no owning process.";
            thr.tab = kTabProcess;
            m.sections.push_back(std::move(thr));
        }
        // c.identity.pid != 0, nothing published yet, empty: the first sample is still in
        // flight (see ProcessThreads). Rendered as NO section rather than an
        // empty one - an empty "Threads" heading would assert "zero threads",
        // and every process has at least one. The next refresh fills it in.
    }

    DetailSection live;
    live.title = L"Live stats (this refresh)";
    live.tab = kTabProcess;
    if (c.procStats.cpuPct >= 0.0) {
        wchar_t cpu[kNumTextChars] = {0};
        ::swprintf_s(cpu, L"%.1f %%", c.procStats.cpuPct);
        add(live, L"CPU", cpu);
    } else {
        add(live, L"CPU", std::wstring());
    }
    if (c.procStats.memKnown) {
        add(live, L"Memory (working set)", FormatBytes(c.procStats.memWorkingSet));
        add(live, L"Memory (private)", FormatBytes(c.procStats.memPrivate));
    } else {
        add(live, L"Memory", std::wstring());
    }
    if (c.procStats.ioKnown) {
        const ULONGLONG total = c.procStats.diskReadBytes + c.procStats.diskWriteBytes;
        add(live, L"Disk read", FormatBytes(c.procStats.diskReadBytes));
        add(live, L"Disk written", FormatBytes(c.procStats.diskWriteBytes));
        add(live, L"Disk total",
            (total == 0) ? std::wstring() : FormatBytes(total));
    } else {
        add(live, L"Disk I/O", std::wstring());
    }
    if (c.traffic.trafficRx != 0 || c.traffic.trafficTx != 0) {
        const ULONGLONG total = c.traffic.trafficRx + c.traffic.trafficTx;
        add(live, L"Network received", FormatBytes(c.traffic.trafficRx));
        add(live, L"Network sent", FormatBytes(c.traffic.trafficTx));
        add(live, L"Network total", FormatBytes(total));
        if (c.rate.bpsKnown) {
            wchar_t rate[kRateTextChars] = {0};
            ::swprintf_s(rate, L"↓ %s/s   ↑ %s/s",
                         FormatBytes(static_cast<ULONGLONG>(c.rate.rxBps + 0.5)).c_str(),
                         FormatBytes(static_cast<ULONGLONG>(c.rate.txBps + 0.5)).c_str());
            add(live, L"Network rate", rate);
        }
    } else {
        add(live, L"Network", std::wstring());
        live.note =
            L"Enable View > Per-PID traffic counters (ETW, admin) for "
            L"per-process byte totals, or the non-admin per-socket fallback "
            L"fills TCP rows automatically.";
    }
    m.sections.push_back(std::move(live));

    if (c.enrichment.tls.known) {
        DetailSection tls;
        tls.title = L"TLS";
        tls.tab = kTabSecurity;
        if (c.enrichment.tls.secure) {
            add(tls, L"Protocol", TlsProtocolName(c.enrichment.tls.protocol));
            add(tls, L"Cipher suite",
                c.enrichment.tls.cipherSuite ? TlsCipherName(c.enrichment.tls.cipherSuite)
                                  : std::wstring());
            add(tls, L"SNI", c.enrichment.tls.haveSni ? c.enrichment.tls.sni : std::wstring());
            add(tls, L"Certificate subject", c.enrichment.tls.certSubject);
            add(tls, L"Certificate issuer", c.enrichment.tls.certIssuer);
            add(tls, L"Valid", c.enrichment.tls.certValidity);
        } else {
            add(tls, L"State", L"not encrypted");
        }
        m.sections.push_back(std::move(tls));
    }

    // a Security section for process-level trust metadata that the row
    // already carries (fetched with the process name) but the Details window
    // never surfaced. Integrity level is the single thing that answers "could
    // this process have written to HKLM"; signature state disambiguates
    // "unsigned" (honest, many binaries) from "BAD SIG" (tampered) from
    // "sig?" (could not be checked); app-container marks a sandboxed process;
    // the parent link is what makes the process tree navigable. All four are
    // only meaningful when actually known, so each renders an em-dash when
    // the resolver never filled it - never a fabricated default.
    if (c.identity.pid != 0) {
        DetailSection sec;
        sec.title = L"Security";
        sec.tab = kTabSecurity;
        add(sec, L"Integrity level",
            std::wstring(IntegrityLabel(static_cast<IntegrityLevel>(c.security.integrity))));
        add(sec, L"App container", c.security.appContainer ? L"yes" : L"—");
        add(sec, L"Signature",
            std::wstring(SignatureLabel(static_cast<SignatureState>(c.security.signature))));
        std::wstring parent;
        if (c.security.ppidKnown && c.security.parentName.empty())
            parent = std::to_wstring(c.security.ppid);
        else if (c.security.ppidKnown)
            parent = c.security.parentName + L" (PID " + std::to_wstring(c.security.ppid) + L")";
        add(sec, L"Parent", parent);
        m.sections.push_back(std::move(sec));
    }

    DetailSection conn;
    conn.title = L"Selected connection";
    conn.tab = kTabConnection;
    add(conn, L"Local", c.display.localEndpoint);
    add(conn, L"Remote", c.display.remoteEndpoint);
    add(conn, L"State", c.keys.stateLabel);
    add(conn, L"Hostname", c.display.hostname);
    if (!c.enrichment.country.empty()) add(conn, L"Country", c.enrichment.country);
    // Its own rows rather than being folded into Country: the two answers
    // come from different database files, and "which country" and "which network"
    // are two questions. An org with no number still gets a row, because the name
    // is the part a reader recognises.
    if (!c.enrichment.asnOrg.empty()) add(conn, L"AS organisation", c.enrichment.asnOrg);
    if (c.enrichment.asnNumber != 0)
        add(conn, L"AS number", L"AS" + std::to_wstring(c.enrichment.asnNumber));
    if (c.lifetime.firstSeenTick != 0)
        add(conn, L"Duration", FormatDuration(DurationSeconds(c)));
    m.sections.push_back(std::move(conn));

    // EVERY sibling connection is listed. There was a 25-line cap here
    // ("25 sibling lines fit the dossier on one screen", with connectionTotal
    // still reporting the true count), and the justification had stopped being
    // true: the window scrolls.
    //
    // A user who opened Details on a browser with 46 sockets got 25 rows and
    // an unexpandable "... and 21 more". That answers none of the questions
    // they opened the window to ask, and the section it truncated is the only
    // one that shows what the process is actually connected to.
    //
    // The cap is removed rather than made expandable. An expander would have
    // been a second control on a window whose whole design is "read, and
    // collapse sections", and it would still have hidden the answer behind a
    // click. The selected row is in that list too, so scrolling to it was the
    // only other way to find it.
    //
    // connectionTotal therefore always equals connectionLines.size() for a
    // model built here. Both fields and the "... and N more" rendering stay:
    // DetailModel is a shared struct that the CLI `details` verb also reads,
    // and deleting the contract is a wider break than this fix is worth. The
    // renderer keeps its guard, which now simply never fires.
    for (const Connection& row : store.Rows()) {
        if (row.identity.pid != c.identity.pid || (row.flags & kRowRemoved)) continue;
        ++m.connectionTotal;
        std::wstring line = row.keys.protoLabel + L"  " + row.display.localEndpoint +
                            L"   " + row.display.remoteEndpoint + L"  (" +
                            row.keys.stateLabel + L")";
        if (!row.display.hostname.empty()) {
            // a pending lookup renders as "pending" (not the raw
            // kPendingHost sentinel) so the details view is legible.
            if (row.display.hostname == DnsResolver::kPendingHost)
                line += L"  @ pending";
            else
                line += L"  @ " + row.display.hostname;
        }
        m.connectionLines.push_back(std::move(line));
    }

    // the Notes section carries the user's annotations on the row -
    // the colour tag and the free-text note, both applied through the
    // bookmarking verbs. A plain ("") note and an untagged row render their
    // em-dashes, which is the honest answer for "nothing was ever set" and
    // also avoids the "is this a blank field or just unknown?" ambiguity
    // that the Process section already taught us to fear.
    DetailSection notes;
    notes.title = L"Notes";
    notes.tab = kTabNotes;
    add(notes, L"Colour tag",
        std::wstring(BookmarkTagLabel(c.annotations.tag)));
    add(notes, L"Pinned", c.annotations.pinned ? L"yes" : L"—");
    add(notes, L"Note", c.annotations.note);
    m.sections.push_back(std::move(notes));

    return m;
}

// Resolve a --select filter to exactly one live row index. The shared
// "find it, refuse to guess" core behind details/close/block/capture and
// kill-by-select, so every verb reports ambiguity the same way.
bool SelectSingleLiveIndex(const ConnectionStore& store,
                           const std::wstring& select, const char* verb,
                           size_t* out, std::string* err) {
    const std::vector<size_t> hits = store.SelectByFilter(select);
    std::vector<size_t> live;
    for (size_t i : hits) {
        if (i < store.Rows().size() &&
            !(store.Rows()[i].flags & kRowRemoved))
            live.push_back(i);
    }
    if (live.empty()) {
        if (err != nullptr)
            *err = std::string(verb) + ": no live row matches '" +
                   WideToUtf8(select) + "'.\r\n";
        return false;
    }
    if (live.size() > 1) {
        if (err != nullptr)
            *err = std::string(verb) + ": '" + WideToUtf8(select) +
                   "' matches " + std::to_string(live.size()) +
                   " rows; refine to one.\r\n";
        return false;
    }
    if (out != nullptr) *out = live[0];
    return true;
}

CommandResult CmdDetails(SnapshotSource& source, const std::wstring& select,
                         const EnrichOptions& eo) {
    CommandResult r;
    if (select.empty()) {
        r.exitCode = kExitArgs;
        r.err = "details: --select <filter> is required (e.g. --select pid:1234).\r\n";
        return r;
    }
    ConnectionStore store;
    std::wstring err;
    // same reason and same position as in CmdListInto: the flag reaches
    // the resolver, not the row join, so it must be set before the pass.
    source.SetVerifySignatures(eo.signatures);
    if (!BuildStoreSnapshot(source, store, eo.procStats, /*resolveDns=*/false,
                            /*geoIp=*/false, nullptr, &err)) {
        r.exitCode = kExitFail;
        r.err = "Enumeration failed: " + WideToUtf8(err) + "\r\n";
        return r;
    }
    size_t idx = 0;
    std::string serr;
    if (!SelectSingleLiveIndex(store, select, "details", &idx, &serr)) {
        r.exitCode = kExitFail;
        r.err = serr;
        return r;
    }
    // Enrich exactly the chosen row (values, then join: joins mutate).
    const Connection chosen = store.Rows()[idx];
    if (eo.dns && !chosen.display.remoteAddress.empty()) {
        const std::wstring host = DnsResolver::Lookup(chosen.display.remoteAddress,
                                                       eo.dnsTimeoutMs);
        if (!host.empty()) store.SetHostname(chosen.display.remoteAddress, host);
    }
    if (!eo.geoIpPath.empty()) {
        GeoIpDatabase db;
        std::wstring loadErr;
        if (!db.Load(eo.geoIpPath.c_str(), &loadErr)) {
            r.exitCode = kExitFail;
            r.err = "GeoIP: " + WideToUtf8(loadErr) + "\r\n";
            return r;
        }
        GeoTarget t;
        t.address = chosen.display.remoteAddress;
        t.ipv6 = (chosen.identity.family == AF_INET6);
        JoinGeoAddrs(store, db, std::vector<GeoTarget>(1, t));
    }
    if (!eo.asnIpPath.empty()) {
        GeoIpDatabase asnDb;
        std::wstring loadErr;
        if (!asnDb.Load(eo.asnIpPath.c_str(), &loadErr)) {
            r.exitCode = kExitFail;
            r.err = "ASN database: " + WideToUtf8(loadErr) + "\r\n";
            return r;
        }
        GeoTarget at;
        at.address = chosen.display.remoteAddress;
        at.ipv6 = (chosen.identity.family == AF_INET6);
        JoinAsnAddrs(store, asnDb, std::vector<GeoTarget>(1, at));
    }
    if (eo.traffic) {
        // Reported here for the same reason as in the list path: a failed pass
        // leaves every traffic field in the detail block at its unmeasured
        // value, and the reader would otherwise see a connection that simply
        // moved no bytes.
        const TrafficScanGaps gaps =
            JoinTrafficPids(store, std::vector<DWORD>(1, chosen.identity.pid));
        // Assigned, not appended: r.err is empty at this point, and each note
        // already carries its own terminator. Same two gap kinds, same order
        // (UNMEASURED before STALE) as the list path.
        if (gaps.failures != 0) r.err += TrafficScanFailedNote(gaps.failures);
        if (gaps.dropped != 0) r.err += TrafficScanDroppedNote(gaps.dropped);
    }
    // A one-shot command pays the ~48 ms thread snapshot inline, because the
    // alternative is to exit before the background worker ever answers - which
    // is what the first version did, and it printed no Threads section at all.
    const DetailModel m =
        BuildDetailModel(store.Rows()[idx], store, /*threadsMayBlock=*/true);
    r.out = WideToUtf8(m.ToPlainText()) + "\r\n";
    return r;
}

ViewState CurrentPresetViewFor(const std::wstring& filter, UINT32 colVisible,
                               int sortColumn, bool sortAsc,
                               unsigned sources) {
    ViewState v;
    v.filter = filter;
    v.colVisible = colVisible;
    v.sortColumn = sortColumn;
    v.sortAsc = sortAsc;
    v.sources = sources;
    return v;
}

void ApplyPresetViewToStore(const ViewState& v, ConnectionStore& store,
                            std::vector<FilterClause>* out) {
    v.ApplyTo(&store, out);
}

// One rule, applied by both front ends, with the self-kill case in it.
//
// WHY THIS LIVES HERE AND NOT IN THE GUI. The GUI is supposed to render what
// this layer computes, never decide for itself (the invariant). A rule that
// only the GUI enforced would leave the CLI able to do the same thing: `kill
// --select` resolves a selector to a row, and nothing stopped that row from
// being one of wintcp.exe's own connections - `kill --select "pid:<self>"` is
// just a command line. Placing the refusal here closes both.
//
// WHY THE SELF-CHECK IS NOT PARANOIA. This was first seen as "wintcp.exe closed
// when I killed something else", which turned out to be a use-after-free handing
// KillPid() a garbage PID. But the self-kill is reachable on its own, with no
// memory bug at all: wintcp.exe is a network tool, so it has its own sockets and
// therefore its own rows. Right-click one, choose End process, and the tool
// closes. There is no crash and no error - the program ends exactly as the user
// asked it to, having simply ended the wrong thing.
PidVerdict PidKillVerdict(DWORD rowPid, DWORD selfPid, bool exists) {
    if (!exists || rowPid == 0) return PidVerdict::Pseudo;
    if (rowPid == selfPid) return PidVerdict::IsSelf;
    // PID 4 is the System pseudo-process. It has no image to end, and OpenProcess
    // on it is a different story on different builds, so refuse rather than ask.
    if (rowPid == 4) return PidVerdict::Pseudo;
    return PidVerdict::Ok;
}

const wchar_t* PidKillRefusal(PidVerdict v) {
    switch (v) {
        case PidVerdict::IsSelf:
            return L"WinTCP cannot end its own process. Close the window "
                   L"instead - that is the same thing without the data loss.";
        case PidVerdict::Pseudo:
            return L"That row has no process that can be ended. PID 0 and the "
                   L"System pseudo-process do not own a real image.";
        case PidVerdict::NotPermitted:
            return L"This process cannot be ended with the rights this session "
                   L"holds. Run WinTCP elevated to end it.";
        case PidVerdict::Ok:
        default:
            return L"";
    }
}

CommandResult KillPid(DWORD pid, const FILETIME& create, bool createKnown,
                      const std::wstring& label, const MutateOptions& mo) {
    // Checked before anything else, including --dry-run: a plan that says
    // "kill PID 5168 (wintcp.exe)" is a bad thing to print even if nothing is
    // done, because the next thing a user does is paste it somewhere.
    const DWORD selfPid = ::GetCurrentProcessId();
    const PidVerdict verdict = PidKillVerdict(pid, selfPid, pid != 0);
    if (verdict != PidVerdict::Ok) {
        CommandResult r;
        r.exitCode = kExitArgs;
        r.err = "kill: refusing PID " + std::to_string(pid) + ": " +
                WideToUtf8(PidKillRefusal(verdict)) + "\r\n";
        return r;
    }
    std::string plan = "kill PID " + std::to_string(pid);
    if (!label.empty()) plan += " (" + WideToUtf8(label) + ")";
    // the plan names the mode. A --dry-run that hid the difference
    // between "ask" and "terminate" would be the swallowed-switch problem
    // in plan form.
    if (mo.forceNow) plan += " [terminate immediately]";
    else if (mo.closeOnly) plan += " [WM_CLOSE only, never forced]";
    plan += "\r\n";
    if (mo.dryRun) {
        CommandResult r;
        r.out = plan;
        return r;
    }
    if (!mo.yes) return Refused("kill PID " + std::to_string(pid));
    if (!createKnown) {
        CommandResult r;
        r.exitCode = kExitFail;
        r.err = "kill: process lifetime was not captured; refresh and try again.\r\n";
        return r;
    }
    HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
                             PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
    if (h == nullptr) {
        CommandResult r;
        r.exitCode = kExitFail;
        wchar_t buf[kErrLineChars] = {0};
        ::swprintf_s(buf, L"kill: OpenProcess(%lu) failed: %ls.\r\n", pid,
                     FormatSystemError(::GetLastError()).c_str());
        r.err = WideToUtf8(buf);
        return r;
    }
    std::wstring verificationError;
    if (!ProcessResolver::VerifyProcessHandle(h, create, verificationError)) {
        ::CloseHandle(h);
        CommandResult r;
        r.exitCode = kExitFail;
        r.err = "kill: PID " + std::to_string(pid) + " refused because " +
                WideToUtf8(verificationError) + ".\r\n";
        return r;
    }
    bool ok = false;
    if (mo.forceNow) {
        // --force: terminate at once - no WM_CLOSE, no wait.
        ok = ::TerminateProcess(h, 1) != FALSE;
    } else {
        (void)PostCloseToProcessWindows(pid);
        const DWORD wait = ::WaitForSingleObject(h, kKillGraceMs);
        if (wait == WAIT_OBJECT_0) {
            ok = true;
        } else if (!mo.closeOnly) {
            ok = ::TerminateProcess(h, 1) != FALSE;
        } else {
            // --close: never escalate. Report the survival honestly;
            // exiting 0 after a refused force would be the silent-answer
            // failure this tool does not ship.
            ::CloseHandle(h);
            CommandResult rr;
            rr.exitCode = kExitFail;
            rr.err = "kill: PID " + std::to_string(pid) +
                     " is still running after " +
                     std::to_string(kKillGraceMs / kMsPerSecond) +
                     " s of WM_CLOSE; --close never forces. Retry with "
                     "--force to terminate it.\r\n";
            return rr;
        }
    }
    ::CloseHandle(h);
    CommandResult r;
    if (!ok) {
        r.exitCode = kExitFail;
        r.err = "kill: PID " + std::to_string(pid) + " did not exit.\r\n";
        return r;
    }
    r.out = plan;
    return r;
}

// kill a process and everything it started. The SHAPE of the plan is
// ProcessTree's (pure, tested); this is only the wiring that works it, so the
// CLI and the GUI apply one rule rather than two that can drift.
//
// The order is deepest-first (PlanKillTree is post-order) and the PID-reuse
// guard is re-applied per target BY THIS CALLER, because a plan is a snapshot:
// by the time the second process dies the third may have exited and its PID
// been reused, and killing a recycled PID kills an innocent process.
CommandResult CmdKillTree(SnapshotSource& source, DWORD rootPid,
                          const MutateOptions& mo) {
    // Resolve the create times for the PID-reuse check.
    SnapshotOptions so;
    so.resolveProcesses = true;
    Snapshot snap;
    if (!source.Build(so, &snap)) {
        CommandResult r;
        r.exitCode = kExitFail;
        r.err = "Enumeration failed: " + WideToUtf8(snap.error) + "\r\n";
        return r;
    }

    // The plan is built from ROWS, not the view: a tree built from a filtered
    // view is a broken tree, because the parents are missing.
    std::vector<TreeNodeInfo> rows;
    rows.reserve(snap.rows.size());
    for (const Connection& c : snap.rows) {
        if (c.identity.pid == 0) continue;   // not resolvable, so not a tree node
        TreeNodeInfo n;
        n.pid = c.identity.pid;
        n.ppid = c.security.ppid;
        n.ppidKnown = c.security.ppidKnown;
        n.processCreate = c.procMeta.processCreate;
        rows.push_back(n);
    }
    const KillTreePlan plan =
        PlanKillTree(rows, rootPid, ::GetCurrentProcessId());
    if (plan.targets.empty()) {
        CommandResult r;
        r.exitCode = kExitArgs;
        r.err = "killtree: no such process (" + std::to_string(rootPid) +
                "), so there is no tree to kill.\r\n";
        return r;
    }

    CommandResult r;
    std::string text = "killtree: PID " + std::to_string(rootPid) +
                       " and " + std::to_string(plan.targets.size()) +
                       " process(es) beneath it\r\n";
    if (plan.partial) {
        // A partial plan must be said out loud: acting on it silently would
        // leave processes the user asked for still running.
        text += "  WARNING: the walk hit its depth ceiling, so some "
                "descendants are NOT in this plan.\r\n";
    }
    for (size_t i : plan.targets) {
        const TreeNodeInfo& n = rows[i];
        text += "  PID " + std::to_string(n.pid);
        if (plan.rootPid != n.pid && n.ppidKnown) {
            text += " (parent " + std::to_string(n.ppid) + ")";
        }
        if (n.pid == ::GetCurrentProcessId()) text += " [this process - last]";
        text += "\r\n";
    }
    r.out = text;
    if (mo.dryRun) return r;
    if (!mo.yes) return Refused("killtree PID " + std::to_string(rootPid));

    // Work the plan, deepest-first. Each step is a fresh verification because
    // the machine moved between steps; a step that fails is REPORTED and the
    // plan CONTINUES, because a tree with one stubborn child should still lose
    // the rest of it. That is different from kill's all-or-nothing contract
    // and is deliberate: "kill the tree" means kill as much of it as can be
    // killed, and the report is what says which parts survived.
    size_t ended = 0;
    std::vector<std::wstring> failures;
    for (size_t i : plan.targets) {
        const TreeNodeInfo& n = rows[i];
        if (n.pid == ::GetCurrentProcessId()) {
            // Ending ourselves would abandon the rest of the plan mid-way and
            // report a success the machine did not deliver.
            failures.push_back(L"refusing to end this process");
            continue;
        }
        const PidVerdict verdict = PidKillVerdict(n.pid, ::GetCurrentProcessId(),
                                                  true);
        if (verdict != PidVerdict::Ok) {
            failures.push_back(std::wstring(L"refused: ") +
                               PidKillRefusal(verdict));
            continue;
        }
        std::wstring verr;
        if (n.processCreate.dwLowDateTime != 0 ||
            n.processCreate.dwHighDateTime != 0) {
            if (!ProcessResolver::VerifyProcess(n.pid, n.processCreate, true,
                                                verr)) {
                failures.push_back(L"PID reused: " + verr);
                continue;
            }
        }
        std::wstring label;
        for (const Connection& c : snap.rows) {
            if (c.identity.pid == n.pid && !c.display.processName.empty()) {
                label = c.display.processName;
                break;
            }
        }
        const CommandResult one = KillPid(n.pid, n.processCreate, true, label,
                                          mo);
        if (one.exitCode == kExitOk) {
            ++ended;
        } else {
            failures.push_back(std::wstring(one.err.begin(), one.err.end()));
        }
    }
    r.out += "ended " + std::to_string(ended) + " of " +
             std::to_string(plan.targets.size()) + "\r\n";
    if (!failures.empty()) {
        r.exitCode = kExitFail;
        r.err = "killtree: " + std::to_string(failures.size()) +
                " process(es) could not be ended:\r\n";
        for (const std::wstring& f : failures) {
            r.err += "  " + WideToUtf8(f) + "\r\n";
        }
    }
    return r;
}

CommandResult CmdKill(SnapshotSource& source, DWORD pid,
                       const MutateOptions& mo) {
    // This used to carry its own copy of the pseudo-PID rule
    // (`if (pid == 0 || pid == 4)`) alongside the one in KillPid, and the two
    // explained why. Two guards for one rule in one file is exactly the drift
    // the review exists to catch, and it was only visible because a golden
    // check asserted on the MESSAGE rather than the exit code.
    //
    // Removed rather than kept in step: the rule lives in PidKillVerdict() and
    // the wording in PidKillRefusal(), and the only thing a caller should have
    // to decide is whether it has a PID to act on. `kill --pid 4` now reaches
    // KillPid's guard and prints the same explanation the GUI shows.
    // --dry-run still refuses here rather than at KillPid, because this
    // function is reached before the snapshot and the refusal should not
    // depend on how long enumeration takes.
    // Resolve the create time for PID-reuse verification.
    SnapshotOptions so;
    so.resolveProcesses = true;
    Snapshot snap;
    if (!source.Build(so, &snap)) {
        CommandResult r;
        r.exitCode = kExitFail;
        r.err = "Enumeration failed: " + WideToUtf8(snap.error) + "\r\n";
        return r;
    }
    const Connection* rep = nullptr;
    for (const Connection& c : snap.rows) {
        if (c.identity.pid == pid) {
            rep = &c;
            break;
        }
    }
    FILETIME processCreate = {};
    bool processCreateKnown = false;
    for (const ProcessRecord& process : EnumerateProcesses(true)) {
        if (process.pid == pid) {
            processCreate = process.processCreate;
            processCreateKnown = process.processCreateKnown;
            break;
        }
    }
    return KillPid(pid,
                   processCreate,
                   processCreateKnown,
                   rep != nullptr ? rep->display.processName : std::wstring(), mo);
}

std::string ConnectionCloseCapabilityReason(const Connection& c,
                                            bool elevated) {
    if ((c.flags & kRowRemoved) != 0)
        return "This endpoint is retained history and is no longer live.";
    if (c.identity.protocol != IPPROTO_TCP)
        return "Windows teardown supports TCP connections only.";
    if (c.identity.family != AF_INET)
        return "Windows exposes no public IPv6 connection teardown.";
    if (c.identity.state != MIB_TCP_STATE_ESTAB)
        return "Only established TCP connections can be closed.";
    if (c.identity.pid == 0 || !c.procMeta.processCreateKnown)
        return "The owning process lifetime is unknown, so this target cannot be verified.";
    if (c.identity.pid == 4)
        return "The System process cannot be safely verified as a user-process target.";
    if (!elevated)
        return "Closing a TCP connection requires an elevated WinTCP process.";
    return {};
}

CommandResult CloseRow(const Connection& c, const MutateOptions& mo) {
    if ((c.flags & kRowRemoved) != 0) {
        CommandResult result;
        result.exitCode = kExitFail;
        result.err = "close: this connection is retained history and is no longer live.\r\n";
        return result;
    }
    if (c.identity.protocol != IPPROTO_TCP || c.identity.family != AF_INET ||
        c.identity.state != MIB_TCP_STATE_ESTAB) {
        CommandResult r;
        r.exitCode = kExitFail;
        r.err = "close: only established IPv4 TCP connections can be closed "
                "(Windows exposes no public IPv6 teardown).\r\n";
        return r;
    }
    if (c.identity.pid == 0 || !c.procMeta.processCreateKnown) {
        CommandResult r;
        r.exitCode = kExitFail;
        r.err = "close: the owning process lifetime is unknown, so this target "
                "cannot be verified. Refresh and try again.\r\n";
        return r;
    }
    if (c.identity.pid == 4) {
        CommandResult r;
        r.exitCode = kExitFail;
        r.err = "close: the System process cannot be safely verified as a "
                "user-process target.\r\n";
        return r;
    }
    // SetTcpEntry refuses without elevation, so say so up front instead of
    // reporting the raw API failure afterwards. (Verified live: a medium-
    // integrity close of our own ESTABLISHED connection fails.)
    if (!IsElevated()) {
        CommandResult r;
        r.exitCode = kExitFail;
        r.err = "close: needs elevation (run as administrator); the row is "
                "untouched.\r\n";
        return r;
    }
    const std::string plan = "close " + WideToUtf8(c.display.localEndpoint) + " -> " +
                             WideToUtf8(c.display.remoteEndpoint) + " pid " +
                             std::to_string(c.identity.pid) + "\r\n";
    if (mo.dryRun) {
        CommandResult r;
        r.out = plan;
        return r;
    }
    if (!mo.yes) return Refused("close connection");
    std::wstring processError;
    if (!ProcessResolver::VerifyProcess(c.identity.pid, c.procMeta.processCreate,
                                        c.procMeta.processCreateKnown,
                                        processError)) {
        CommandResult r;
        r.exitCode = kExitFail;
        r.err = "close: target process verification failed: " +
                WideToUtf8(processError) + "\r\n";
        return r;
    }
    std::wstring cerr;
    if (!CloseTcpConnection(c, cerr)) {
        CommandResult r;
        r.exitCode = kExitFail;
        r.err = "close failed: " + WideToUtf8(cerr) + "\r\n";
        return r;
    }
    CommandResult r;
    r.out = plan;
    return r;
}

CommandResult CmdClose(SnapshotSource& source, const std::wstring& select,
                       const MutateOptions& mo) {
    if (select.empty()) {
        CommandResult r;
        r.exitCode = kExitArgs;
        r.err = "close: --select <filter> is required.\r\n";
        return r;
    }
    ConnectionStore store;
    std::wstring err;
    if (!BuildStoreSnapshot(source, store, /*procStats=*/false,
                            /*resolveDns=*/false, /*geoIp=*/false, nullptr,
                            &err)) {
        CommandResult r;
        r.exitCode = kExitFail;
        r.err = "Enumeration failed: " + WideToUtf8(err) + "\r\n";
        return r;
    }
    const std::vector<size_t> hits = store.SelectByFilter(select);
    std::vector<size_t> live;
    for (size_t i : hits) {
        if (i < store.Rows().size() &&
            !(store.Rows()[i].flags & kRowRemoved))
            live.push_back(i);
    }
    if (live.empty()) {
        CommandResult r;
        r.exitCode = kExitFail;
        r.err = "close: no live row matches '" + WideToUtf8(select) + "'.\r\n";
        return r;
    }
    if (live.size() > 1) {
        CommandResult r;
        r.exitCode = kExitFail;
        r.err = "close: '" + WideToUtf8(select) + "' matches " +
                std::to_string(live.size()) + " rows; refine to one.\r\n";
        return r;
    }
    const Connection& c = store.Rows()[live[0]];
    return CloseRow(c, mo);
}

CommandResult CmdKillSelect(SnapshotSource& source, const std::wstring& select,
                            const MutateOptions& mo) {
    if (select.empty()) {
        CommandResult r;
        r.exitCode = kExitArgs;
        r.err = "kill: --pid N or --select <filter> is required.\r\n";
        return r;
    }
    ConnectionStore store;
    std::wstring err;
    if (!BuildStoreSnapshot(source, store, /*procStats=*/false,
                            /*resolveDns=*/false, /*geoIp=*/false, nullptr,
                            &err)) {
        CommandResult r;
        r.exitCode = kExitFail;
        r.err = "Enumeration failed: " + WideToUtf8(err) + "\r\n";
        return r;
    }
    size_t idx = 0;
    std::string serr;
    if (!SelectSingleLiveIndex(store, select, "kill", &idx, &serr)) {
        CommandResult r;
        r.exitCode = kExitFail;
        r.err = serr;
        return r;
    }
    const Connection& c = store.Rows()[idx];
    return KillPid(c.identity.pid, c.procMeta.processCreate, c.procMeta.processCreateKnown,
                   c.display.processName, mo);
}

bool ConnectionToBlockRequest(const Connection& c, BlockRequest* out,
                              std::wstring* whyNot) {
    if (out == nullptr) return false;
    if ((c.flags & kRowRemoved) != 0) {
        if (whyNot != nullptr)
            *whyNot = L"This connection is retained history and is no longer live.";
        return false;
    }
    if (c.identity.protocol != IPPROTO_TCP || c.identity.state == MIB_TCP_STATE_LISTEN ||
        c.identity.state == 0) {
        if (whyNot != nullptr)
            *whyNot = L"Only an established TCP connection can be blocked.";
        return false;
    }
    BlockRequest req;
    req.ipv6 = (c.identity.family == AF_INET6);
    req.localPort = static_cast<uint16_t>(c.identity.localPort);
    req.remotePort = static_cast<uint16_t>(c.identity.remotePort);
    req.label = c.display.localEndpoint + L" -> " + c.display.remoteEndpoint;
    if (req.ipv6) {
        ::memcpy(req.remoteAddr, c.identity.remote6.s6_addr, kIpv6AddrBytes);
    } else {
        ::memcpy(req.remoteAddr, &c.identity.remote4, 4);
    }
    *out = req;
    return true;
}

CommandResult BlockNow(const BlockRequest& req, const MutateOptions& mo) {
    const std::string plan = "block " + WideToUtf8(req.label) + "\r\n";
    if (mo.dryRun) {
        CommandResult r;
        r.out = plan;
        return r;
    }
    if (!mo.yes) return Refused("block connection");
    // Both layers (teardown + firewall rules) refuse without elevation.
    if (!IsElevated()) {
        CommandResult r;
        r.exitCode = kExitFail;
        r.err = "block: needs elevation (run as administrator); nothing was "
                "changed.\r\n";
        return r;
    }
    std::wstring berr;
    const BlockOutcome o = BlockConnection(req, &berr);
    CommandResult r;
    r.out = WideToUtf8(BlockOutcomeToString(o)) + ": " + plan;
    if (o == BlockOutcome::kFailed || o == BlockOutcome::kKilledOnly) {
        r.exitCode = kExitFail;
        r.err = WideToUtf8(berr) + "\r\n";
    }
    return r;
}

CommandResult CmdBlock(SnapshotSource& source, const std::wstring& select,
                       const MutateOptions& mo) {
    if (select.empty()) {
        CommandResult r;
        r.exitCode = kExitArgs;
        r.err = "block: --select <filter> is required.\r\n";
        return r;
    }
    ConnectionStore store;
    std::wstring err;
    if (!BuildStoreSnapshot(source, store, /*procStats=*/false,
                            /*resolveDns=*/false, /*geoIp=*/false, nullptr,
                            &err)) {
        CommandResult r;
        r.exitCode = kExitFail;
        r.err = "Enumeration failed: " + WideToUtf8(err) + "\r\n";
        return r;
    }
    size_t idx = 0;
    std::string serr;
    if (!SelectSingleLiveIndex(store, select, "block", &idx, &serr)) {
        CommandResult r;
        r.exitCode = kExitFail;
        r.err = serr;
        return r;
    }
    BlockRequest req;
    std::wstring why;
    if (!ConnectionToBlockRequest(store.Rows()[idx], &req, &why)) {
        CommandResult r;
        r.exitCode = kExitFail;
        r.err = "block: " + WideToUtf8(why) + "\r\n";
        return r;
    }
    return BlockNow(req, mo);
}

CommandResult CmdUnblock(const std::wstring& address, UINT port,
                         const MutateOptions& mo) {
    if (address.empty() || port == 0 || port > 65535) {
        CommandResult r;
        r.exitCode = kExitArgs;
        r.err = "unblock: --address <ip> and --port <1..65535> are required.\r\n";
        return r;
    }
    const std::wstring norm = NormalizeAddress(address);
    if (norm.empty()) {
        CommandResult r;
        r.exitCode = kExitArgs;
        r.err = "unblock: '" + WideToUtf8(address) +
                "' is not a usable address.\r\n";
        return r;
    }
    const bool v6 = (norm.find(L':') != std::wstring::npos);
    BlockRequest req;
    req.ipv6 = v6;
    req.remotePort = static_cast<uint16_t>(port);
    if (v6) {
        IN6_ADDR a6 = {};
        if (::InetPtonW(AF_INET6, norm.c_str(), &a6) != 1) {
            CommandResult r;
            r.exitCode = kExitArgs;
            r.err = "unblock: cannot parse IPv6 address.\r\n";
            return r;
        }
        ::memcpy(req.remoteAddr, a6.s6_addr, kIpv6AddrBytes);
    } else {
        IN_ADDR a4 = {};
        if (::InetPtonW(AF_INET, norm.c_str(), &a4) != 1) {
            CommandResult r;
            r.exitCode = kExitArgs;
            r.err = "unblock: cannot parse IPv4 address.\r\n";
            return r;
        }
        ::memcpy(req.remoteAddr, &a4, 4);
    }
    const std::string plan =
        "unblock " + WideToUtf8(norm) + ":" + std::to_string(port) + "\r\n";
    if (mo.dryRun) {
        CommandResult r;
        r.out = plan;
        return r;
    }
    if (!mo.yes) return Refused("unblock");
    std::wstring uerr;
    CommandResult r;
    if (!UnblockConnection(req, &uerr)) {
        r.exitCode = kExitFail;
        r.err = "unblock failed: " + WideToUtf8(uerr) + "\r\n";
        return r;
    }
    r.out = plan;
    return r;
}

CommandResult CmdRule(const RuleRequest& req, bool dryRun, bool yes) {
    // ---- a stated policy rule --------------------------------------
    // Maps the CLI's words onto the engine's constants in ONE place. Every
    // refusal below happens before the engine is called, so a rule the
    // firewall would refuse is rejected here with a message about the rule
    // rather than an HRESULT.
    FwRule r;
    r.inbound = req.inbound;
    r.allow = req.allow;
    if (req.proto == L"tcp") {
        r.protocol = 6;
    } else if (req.proto == L"udp") {
        r.protocol = 17;
    } else if (req.proto == L"any") {
        r.protocol = 0;
    } else {
        CommandResult bad;
        bad.exitCode = kExitArgs;
        bad.err = "block --rule: --proto must be tcp, udp or any (got '" +
                  WideToUtf8(req.proto) + "').\r\n";
        return bad;
    }

    // An address is required, and it is the one field with no sensible
    // default: "any" is a real choice a user may make deliberately, so it has
    // to be stated rather than assumed when only ports or a process were
    // given.
    if (req.address.empty()) {
        CommandResult bad;
        bad.exitCode = kExitArgs;
        bad.err =
            "block --rule needs --address (\"*\" for any, or an address, "
            "list, or CIDR range).\r\n";
        return bad;
    }
    r.remoteAddress = req.address;
    r.localAddress = req.localAddress.empty() ? L"*" : req.localAddress;
    r.localPorts = req.localPorts.empty() ? L"*" : req.localPorts;
    r.remotePorts = req.remotePorts.empty() ? L"*" : req.remotePorts;
    r.profiles = req.profiles;
    r.processPath = req.process;
    r.service = req.service;
    r.label = req.label;

    // The full plan is printed for a dry run, INCLUDING the name the rule will
    // be given - the name is the handle for removing it later, so seeing it
    // before the rule exists is the point of the dry run.
    {
        std::wstring why;
        if (!ValidateFwRule(r, &why)) {
            CommandResult bad;
            bad.exitCode = kExitArgs;
            bad.err = "block --rule refused: " + WideToUtf8(why) + "\r\n";
            return bad;
        }
    }
    const std::wstring name = BuildFwRuleName(r);
    std::string plan;
    plan += "rule ";
    plan += WideToUtf8(name);
    plan += "\r\n";
    plan += req.allow ? "  allow  " : "  block ";
    plan += req.inbound ? "inbound from " : "outbound to ";
    plan += WideToUtf8(req.address);
    plan += "  proto=";
    plan += WideToUtf8(req.proto);
    if (r.localAddress != L"*")
        plan += "  local-address=" + WideToUtf8(r.localAddress);
    if (!req.localPorts.empty() || !req.remotePorts.empty()) {
        plan += "  local-ports=" + WideToUtf8(r.localPorts);
        plan += "  remote-ports=" + WideToUtf8(r.remotePorts);
    }
    if (!req.process.empty()) {
        plan += "  process=" + WideToUtf8(req.process);
    }
    if (!req.service.empty()) {
        plan += "  service=" + WideToUtf8(req.service);
    }
    if (req.profiles != 0x7fffffffL)
        plan += "  profiles=" + std::to_string(req.profiles);
    plan += "\r\n";
    {
        CommandResult pre;
        pre.out = plan;
        if (dryRun) {
            return pre;
        }
        if (!yes) {
            return Refused("block");
        }
        // The refusal contract is 3 for "no --yes"; that is checked after the
        // plan is built so `--dry-run` without `--yes` still shows it.
        //
        // A CONFIRMED command falls through to the AddFwRule block below. It
        // used to end this block with `pre.exitCode = kExitRefused; return
        // pre;`, which refused the one case that had been confirmed and left
        // everything below unreachable - Debug's /W4 /WX C4702 said so while
        // Release optimization hid it, and no gate could see it: the CLI test never
        // passes --yes to a mutating verb and examples.txt only exercises
        // --dry-run and the exit-2 validations. The observable damage was
        // `block --rule ... --yes` always exiting 3 with "pass --yes to
        // proceed" - after --yes had been passed - and the Web UI's confirmed
        // firewall action (WebUi.cpp CmdRule(..., false, true)) logging
        // "refused-or-failed" without a rule ever existing.
    }
    {
        std::wstring error;
        std::wstring created;
        const FwRuleOutcome outcome = AddFwRule(r, &created, &error);
        CommandResult out;
        if (outcome == FwRuleOutcome::kFailed) {
            out.exitCode = kExitFail;
            out.err = "block --rule failed: " + WideToUtf8(error) + "\r\n";
            return out;
        }
        out.out = plan;
        if (outcome == FwRuleOutcome::kAlreadyPresent) {
            // Not an error and not a duplicate: the rule the user asked for is
            // already in place, which is the state they wanted.
            out.out += "  already present; nothing added.\r\n";
        }
        return out;
    }
}

CommandResult CmdBlocks(bool listRules, const std::string& format) {
    CommandResult r;
    // R3: a count that could not be made must not be reported as zero. Before
    // this, an unreadable ledger - over the 4 MiB cap, or holding a line that
    // is not valid UTF-8 - produced "wintcp-firewall-rules: 0" with nothing on
    // stderr, which is indistinguishable from "you have no blocks".
    std::wstring error;
    if (!listRules) {
        const int n = CountWinTcpRules(&error);
        if (!error.empty()) {
            r.err = WideToUtf8(error) + "\r\n";
        }
        r.out = "wintcp-firewall-rules: " + std::to_string(n) + "\r\n";
        return r;
    }

    // ---- the listing half -------------------------------------------
    // Reads the rules the firewall reports, so the count above is left alone:
    // this path never calls CountWinTcpRules and never writes the ledger.
    std::vector<BlockedRule> rules;
    if (!ListBlockedRules(&rules, &error)) {
        r.exitCode = kExitFail;
        r.err = "blocks --list failed: " + WideToUtf8(error) + "\r\n";
        return r;
    }
    if (!error.empty()) {
        r.err = WideToUtf8(error) + "\r\n";
    }

    if (format == "json") {
        std::string out = "[";
        for (size_t i = 0; i < rules.size(); ++i) {
            const BlockedRule& b = rules[i];
            if (i != 0) out += ",";
            out += "{\"name\":\"" + JsonEscapeA(b.name) + "\",\"enabled\":" +
                   (b.enabled ? "true" : "false") + ",\"blocking\":" +
                   (b.isBlocking ? "true" : "false") + ",\"remote\":\"" +
                   JsonEscapeA(b.remoteAddrs) + "\",\"localPort\":\"" +
                   JsonEscapeA(b.localPorts) + "\",\"remotePort\":\"" +
                   JsonEscapeA(b.remotePorts) + "\"}";
        }
        out += "]\r\n";
        r.out = out;
        return r;
    }

    const bool csv = (format == "csv");
    std::string out;
    if (!csv) {
        out += "Rule name                                     En  Block  Remote        LPort RPort\r\n";
    } else {
        out += "name,enabled,blocking,remote,localPort,remotePort\r\n";
    }
    for (const BlockedRule& b : rules) {
        const std::string name = WideToUtf8(b.name);
        if (csv) {
            out += CsvEscapeUtf8(name) + "," +
                   std::string(b.enabled ? "1" : "0") + "," +
                   std::string(b.isBlocking ? "1" : "0") + "," +
                   CsvEscapeUtf8(WideToUtf8(b.remoteAddrs)) + "," +
                   CsvEscapeUtf8(WideToUtf8(b.localPorts)) + "," +
                   CsvEscapeUtf8(WideToUtf8(b.remotePorts)) + "\r\n";
            continue;
        }
        const std::string en = b.enabled ? "yes" : "NO";
        // A tagged rule the user disabled or flipped to allow is still shown,
        // and is flagged: a block that is not blocking is the one state this
        // surface must never pass off as protection.
        const std::string blk = b.isBlocking ? "yes" : "NOT";
        out += TruncateToWidth(name, 44) + "  " + TruncateToWidth(en, 4) + "  " +
               TruncateToWidth(blk, 6) + "  " +
               TruncateToWidth(WideToUtf8(b.remoteAddrs), 14) + "  " +
               TruncateToWidth(WideToUtf8(b.localPorts), 6) + "  " +
               TruncateToWidth(WideToUtf8(b.remotePorts), 6) + "\r\n";
    }
    if (rules.empty()) {
        out += csv ? std::string()
                   : std::string("(no WinTCP firewall rules)\r\n");
    }
    r.out = out;
    return r;
}

// ---- alert -------------------------------------------------
// The engine has been pure and tested since it was written; what it lacked was a
// persistence layer and a surface to set the thresholds. Both are here.
//
// Everything is expressed in the SAME domain the threshold is applied in - the
// engine reads bytes/sec, so the switch takes bytes/sec. A KB/MB suffix would be
// friendlier to type and one more place for a unit to be misread, and the numbers
// are small enough that "1000000" is not a burden.
// ---- alert -------------------------------------------------
// The engine has been pure and tested since it was written; what it lacked was a
// persistence layer and a surface to set the thresholds. Both are here.
//
// Rates are in the SAME domain the engine applies them in - bytes/sec - because a
// KB/MB suffix would be friendlier to type and one more place for a unit to be
// misread, and the numbers are small enough that "1000000" is not a burden.
//
// AlertFlags is tri-state so a caller can change one switch without restating the
// whole configuration; the engine's own defaults are what "unset" leaves alone.
// A threshold stored as a double but typed as a whole number of bytes/sec.
// std::to_string on a double gives "2000000.000000", which is correct and
// unreadable; printing the two halves separately would print "2e+06" for the same
// value on a different compiler. Round, and only show a fraction when there is one.
std::string NumberNoTrailingZeros(double v) {
    const long long whole = static_cast<long long>(v < 0 ? v - 0.5 : v + 0.5);
    if (static_cast<double>(whole) == v) return std::to_string(whole);
    char buf[kRateTextChars] = {0};
    ::snprintf(buf, sizeof(buf), "%.3f", v);
    std::string s(buf);
    while (!s.empty() && s.back() == '0') s.pop_back();
    if (!s.empty() && s.back() == '.') s.pop_back();
    return s;
}

CommandResult CmdAlert(AlertFlags f) {
    CommandResult r;
    Settings s;
    // portable defaults FIRST, so the registry always wins. A file that
    // exists but cannot be read is reported rather than swallowed - it is a
    // user-visible fault, and silently ignoring it would mean the portable copy
    // quietly does nothing.
    wchar_t exePath[MAX_PATH] = {0};
    const DWORD pn = ::GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::wstring portableErr;
    if (pn != 0 && pn < MAX_PATH) {
        s.ApplyPortableDefaults(exePath, &portableErr);
    }
    if (!portableErr.empty()) {
        r.err = "note: " + WideToUtf8(portableErr) + "\r\n";
    }
    if (!s.Load()) {
        // A Settings store that will not read is not fatal here: the engine works
        // from the struct's defaults, which are the muted ones. Say so rather than
        // failing, because a user asking to SEE the configuration should get an
        // answer rather than a refusal.
        r.err = "note: settings could not be read; showing and writing defaults.\r\n";
    }

    // MUTED BY DEFAULT is a design rule, not an unfinished state, and it is
    // asserted here as well as in the engine: a network viewer that raises a
    // balloon on every refresh is one the user switches off, and then it is useless
    // for the one event that mattered.
    bool changed = false;
    if (f.enableSet)         { s.alerts.enabled = f.enable; changed = true; }
    if (f.bpsWarn >= 0)      { s.alerts.bpsWarn = static_cast<double>(f.bpsWarn); changed = true; }
    if (f.bpsCritical >= 0)  { s.alerts.bpsCritical = static_cast<double>(f.bpsCritical); changed = true; }
    if (f.connWarn >= 0)     { s.alerts.connectionWarn = static_cast<size_t>(f.connWarn); changed = true; }
    if (f.onListenerSet)     { s.alerts.alertOnNewListener = f.onListener; changed = true; }
    if (f.onConnectionSet)   { s.alerts.alertOnNewConnection = f.onConnection; changed = true; }
    if (f.onRstSet)          { s.alerts.alertOnRst = f.onRst; changed = true; }
    if (f.onClosedSet)       { s.alerts.alertOnClosed = f.onClosed; changed = true; }

    if (changed && !s.Save()) {
        r.exitCode = kExitFail;
        r.err += "alert: could not write settings to the registry.\r\n";
        return r;
    }

    if (f.format == "json") {
        std::string out = "{";
        out += "\n  \"enabled\": " + std::string(s.alerts.enabled ? "true" : "false") + ",";
        out += "\n  \"bpsWarn\": " + NumberNoTrailingZeros(s.alerts.bpsWarn) + ",";
        out += "\n  \"bpsCritical\": " + NumberNoTrailingZeros(s.alerts.bpsCritical) + ",";
        out += "\n  \"connectionWarn\": " + std::to_string(s.alerts.connectionWarn) + ",";
        out += "\n  \"onNewListener\": " +
               std::string(s.alerts.alertOnNewListener ? "true" : "false") + ",";
        out += "\n  \"onNewConnection\": " +
               std::string(s.alerts.alertOnNewConnection ? "true" : "false") + ",";
        out += "\n  \"onRst\": " + std::string(s.alerts.alertOnRst ? "true" : "false") + ",";
        out += "\n  \"onClosed\": " +
               std::string(s.alerts.alertOnClosed ? "true" : "false");
        out += "\n}\n";
        r.out = out;
        return r;
    }

    std::wstring o;
    o += L"alerting      : " +
         std::wstring(s.alerts.enabled ? L"enabled" : L"muted") + L"\r\n";
    o += L"rate warning  : " +


         (s.alerts.bpsWarn > 0
              ? Utf8ToWide(NumberNoTrailingZeros(s.alerts.bpsWarn).c_str()) + L" bytes/sec"
              : L"off") + L"\r\n";
    o += L"rate critical : " +
         (s.alerts.bpsCritical > 0
              ? Utf8ToWide(NumberNoTrailingZeros(s.alerts.bpsCritical).c_str()) + L" bytes/sec"
              : L"off") + L"\r\n";

    o += L"new listener  : " +
         std::wstring(s.alerts.alertOnNewListener ? L"yes" : L"no") + L"\r\n";
    o += L"new connection: " +
         std::wstring(s.alerts.alertOnNewConnection ? L"yes" : L"no") + L"\r\n";
    o += L"reset seen    : " +
         std::wstring(s.alerts.alertOnRst ? L"yes" : L"no") + L"\r\n";
    o += L"closed seen   : " +
         std::wstring(s.alerts.alertOnClosed ? L"yes" : L"no") + L"\r\n";
    if (!s.alerts.enabled) {
        o += L"note: alerting is muted by default. Set --enable to turn it on.\r\n";
    }
    r.out = WideToUtf8(o);
    return r;
}


// ---- alert rule sub-commands -----------------------------------------
// The engine and the store landed first; this is the surface that fills them.
//
// `add` is deliberately idempotent by name: the same rule name twice is one rule,
// which is what the registry already does and what a user retyping a command
// expects. It is NOT upsert-by-content - editing a rule means adding it again with
// the same name, which is the smallest number of concepts.
CommandResult CmdAlertRule(const std::wstring& action, AlertRuleFlags f) {
    CommandResult r;

    if (action == L"list") {
        const std::vector<AlertRule> rules = AlertRuleStore::Load();
        if (f.format == "json") {
            if (rules.empty()) { r.out = "[]\n"; return r; }
            std::string out = "[";
            bool first = true;
            for (const AlertRule& rule : rules) {
                if (!first) out += ",";
                first = false;
                out += "\n  {\"name\":\"" + WideToUtf8(rule.name) + "\",";
                out += "\"address\":\"" + WideToUtf8(rule.address) + "\",";
                out += "\"process\":\"" + WideToUtf8(rule.process) + "\",";
                out += "\"onNew\":" + std::string(rule.onNew ? "true" : "false") + ",";
                out += "\"onClose\":" + std::string(rule.onClose ? "true" : "false") + "}";
            }
            out += "\n]\n";
            r.out = out;
            return r;
        }
        if (rules.empty()) {
            r.out = "no alert rules. add one with: alert rule add --rule-name NAME [--rule-address A.B.C.D] [--rule-process IMAGE]\r\n";
            return r;
        }
        // Fixed widths, truncated rather than wrapped. The previous version
        // padded by eye, which produced a table whose columns only lined up when
        // every field happened to be the same length.
        std::wstring o;
        const auto cell = [](const std::wstring& v, size_t w) {
            if (v.size() > w - 1) return v.substr(0, w - 1);
            return v + std::wstring(w - v.size(), L' ');
        };
        o += cell(L"name", 22) + cell(L"address", 18) + cell(L"process", 18) +
             L"new  close" + L"\r\n";
        for (const AlertRule& rule : rules) {
            o += cell(rule.name, 22);
            o += cell(rule.address.empty() ? L"(any)" : rule.address, 18);
            o += cell(rule.process.empty() ? L"(any)" : rule.process, 18);
            o += rule.onNew ? L"yes" : L"no";
            o += L"  ";
            o += rule.onClose ? L"yes" : L"no";
            o += L"\r\n";
        }
        r.out = WideToUtf8(o);
        return r;
        return r;
    }

    if (action == L"remove") {
        if (f.name.empty()) {
            r.exitCode = kExitArgs;
            r.err = "alert rule remove: --rule-name NAME is required.\r\n";
            return r;
        }
        if (!AlertRuleStore::Remove(f.name)) {
            // "removed" and "never was there" are different answers, and a caller
            // that cannot tell them cannot tell whether it needs to retry.
            r.exitCode = kExitFail;
            r.err = "alert rule remove: there is no rule named '" +
                    WideToUtf8(f.name) + "'.\r\n";
            return r;
        }
        r.out = "removed rule '" + WideToUtf8(f.name) + "'\r\n";
        return r;
    }

    if (action == L"add") {
        if (f.name.empty()) {
            r.exitCode = kExitArgs;
            r.err = "alert rule add: --rule-name NAME is required.\r\n";
            return r;
        }
        if (f.address.empty() && f.process.empty()) {
            // A rule matching everything is legal but a mistake nine times out of
            // ten, so it is refused rather than created silently.
            r.exitCode = kExitArgs;
            r.err = "alert rule add: give --address or --process, otherwise the "
                    "rule matches every connection.\r\n";
            return r;
        }
        AlertRule rule;
        rule.name = f.name;
        rule.address = f.address;
        rule.process = f.process;
        rule.onNew = f.onNewSet ? f.onNew : true;    // default: on
        rule.onClose = f.onCloseSet ? f.onClose : false;
        rule.onThreshold = f.onThreshold;
        if (!AlertRuleStore::Save(rule)) {
            r.exitCode = kExitFail;
            r.err = "alert rule add: could not write the rule to the registry.\r\n";
            return r;
        }
        if (f.format == "json") {
            r.out = "{\"added\":\"" + WideToUtf8(rule.name) + "\"}\n";
        } else {
            r.out = "added rule '" + WideToUtf8(rule.name) + "'\r\n";
        }
        return r;
    }

    r.exitCode = kExitArgs;
    r.err = "alert rule: usage is add | list | remove\r\n";
    return r;
}
// A database's own record_count metadata, phrased honestly.
//
// Real files very often OMIT this field - every DBIP edition does - so 0 means
// "the file does not say", NOT "the file holds no records". Printing a bare "0
// records" told a user looking at an 8 MB, fully-populated database that it was
// empty, and sent them off to check for a corrupted download. The JSON form is
// null for the same reason: an absent fact is not the number zero.
std::string RecordsText(uint64_t n) {
    return n == 0 ? "record count not stated" : std::to_string(n) + " records";
}
std::string RecordsJson(uint64_t n) {
    return n == 0 ? "null" : std::to_string(n);
}


CommandResult CmdDoctor(bool verbose, const std::wstring& geoDbPath,
                         const std::wstring& asnDbPath, const std::string& format) {
    CommandResult r;
    // doctor reuses the SAME BuildSummary assembly the `version` verb uses
    // (handles/GDI/USER, traffic fallback) so the two verbs can never disagree
    // about process state. See BuildSummary/AboutText for why each field is
    // probed rather than hard-coded - notably the handle count, where 0 is a
    // real answer and must not be hidden.
    BuildSummary s;
    s.elevated = IsElevated();
    s.presetsAvailable = true;
    s.totalColumnCount = COL_COUNT;
    s.visibleColumnCount = 0;
    s.columnCountKnown = false;
    {
        SocketTrafficSampler probe;
        s.trafficFallback = !s.elevated && probe.Supported();
        if (const SocketTrafficSampler* live = ActiveTrafficSampler()) {
            s.trafficScanRan = true;
            s.trafficTimeouts = live->TimeoutCount();
            s.trafficScanFailures = live->ScanFailureCount();
        }
    }
    {
        DWORD handles = 0;
        s.resourceCountsKnown =
            ::GetProcessHandleCount(::GetCurrentProcess(), &handles) != FALSE;
        s.handleCount = handles;
        s.gdiCount = ::GetGuiResources(::GetCurrentProcess(), GR_GDIOBJECTS);
        s.userCount = ::GetGuiResources(::GetCurrentProcess(), GR_USEROBJECTS);
    }

    // GeoIP: an optional one-off --db probe. A fresh Load() here (not the
    // process-wide store), so a bad path is reported by doctor instead of
    // surfacing later as an empty Country column.
    bool geoOk = false;
    std::wstring geoPath, geoVersion, geoError;
    uint64_t geoRecords = 0;
    size_t geoSize = 0;
    if (geoDbPath.empty()) {
        geoError = L"no --db given";
    } else {
        GeoIpDatabase db;
        if (db.Load(geoDbPath, &geoError)) {
            geoOk = true;
            geoPath = db.SourcePath();
            geoVersion = db.DatabaseVersion();
            geoRecords = db.RecordCount();
            geoSize = db.FileSize();
        }
    }

    // The same probe for the ASN file, which is a DIFFERENT database and was
    // previously undiagnosable: --asn-db was not in this verb's switch list, so a
    // user whose asn: filter matched nothing had no way to ask doctor whether the
    // file it was given was even an ASN database. Reported as its own block, with
    // its own "not given"/"not loaded" state, because "which database is wrong" is
    // the question this is answering.
    bool asnOk = false;
    std::wstring asnPath, asnVersion, asnError;
    uint64_t asnRecords = 0;
    size_t asnSize = 0;
    if (asnDbPath.empty()) {
        asnError = L"no --asn-db given";
    } else {
        GeoIpDatabase adb;
        if (adb.Load(asnDbPath, &asnError)) {
            asnOk = true;
            asnPath = adb.SourcePath();
            asnVersion = adb.DatabaseVersion();
            asnRecords = adb.RecordCount();
            asnSize = adb.FileSize();
        }
    }

    // Firewall: the WinTCP rule ledger. CountWinTcpRules returns the count with
    // the reason in fwError when the ledger cannot be read with confidence.
    std::wstring fwError;
    const int fwRules = CountWinTcpRules(&fwError);

    // Capture: the same tools + elevation question EvaluateCaptureGate answers,
    // reported as capability text rather than a go/no-go.
    std::wstring capWhy;
    const bool capOk = CaptureAvailable(&capWhy);

    if (format == "json") {
        std::string out = "{";
        out += "\n  \"elevation\": " + std::string(s.elevated ? "true" : "false") + ",";
        out += "\n  \"handles\": " +
               (s.resourceCountsKnown ? std::to_string(s.handleCount) : "null") + ",";
        out += "\n  \"gdiObjects\": " + std::to_string(s.gdiCount) + ",";
        out += "\n  \"userObjects\": " + std::to_string(s.userCount) + ",";
        out += "\n  \"traffic\": {";
        out += "\n    \"fallback\": " + std::string(s.trafficFallback ? "true" : "false") + ",";
        out += "\n    \"scanned\": " + std::to_string(s.trafficScanRan ? 1 : 0) + ",";
        out += "\n    \"timeouts\": " + std::to_string(s.trafficTimeouts) + ",";
        out += "\n    \"failures\": " + std::to_string(s.trafficScanFailures);
        out += "\n  },";
        out += "\n  \"geoIp\": {";
        out += "\n    \"loaded\": " + std::string(geoOk ? "true" : "false") + ",";
        out += "\n    \"path\": \"" + JsonEscapeA(geoPath) + "\",";
        out += "\n    \"version\": \"" + JsonEscapeA(geoVersion) + "\",";
        out += "\n    \"records\": " + RecordsJson(geoRecords) + ",";
        out += "\n    \"size\": " + std::to_string(geoSize);
        if (!geoError.empty())
            out += ",\n    \"error\": \"" + JsonEscapeA(geoError) + "\"";
        out += "\n  },";
        // Same shape as "geoIp", so a consumer parsing doctor's JSON does
        // not need a special case for the second database.
        out += "\n  \"asnIp\": {";
        out += "\n    \"loaded\": " + std::string(asnOk ? "true" : "false") + ",";
        out += "\n    \"path\": \"" + JsonEscapeA(asnPath) + "\",";
        out += "\n    \"version\": \"" + JsonEscapeA(asnVersion) + "\",";
        out += "\n    \"records\": " + RecordsJson(asnRecords) + ",";
        out += "\n    \"size\": " + std::to_string(asnSize);
        if (!asnError.empty())
            out += ",\n    \"error\": \"" + JsonEscapeA(asnError) + "\"";
        out += "\n  },";
        out += "\n  \"firewall\": {";
        out += "\n    \"rules\": " + std::to_string(fwRules);
        if (!fwError.empty())
            out += ",\n    \"error\": \"" + JsonEscapeA(fwError) + "\"";
        out += "\n  },";
        out += "\n  \"capture\": {";
        out += "\n    \"available\": " + std::string(capOk ? "true" : "false") + ",";
        out += "\n    \"why\": \"" + JsonEscapeA(capWhy) + "\"";
        out += "\n  }";
        out += "\n}\n";
        r.out = out;
        return r;
    }

    // Text: the About box (version + capabilities) then a diagnostic section.
    r.out = WideToUtf8(AboutText(s, verbose));
    if (!r.out.empty() && r.out.back() != '\n') r.out += "\r\n";
    r.out += "\r\n--- Environment diagnostics\r\n";
    if (geoOk) {
        r.out += "geoip: " + WideToUtf8(geoPath) + " (version " +
                 WideToUtf8(geoVersion) + ", " + RecordsText(geoRecords) +
                 ", " + std::to_string(geoSize) + " bytes)\r\n";
    } else {
        r.out += "geoip: not loaded (" + WideToUtf8(geoError) + ")\r\n";
    }
    // Its own block, with its own not-given / not-loaded state. Which of the
    // two databases is wrong is the question a user arrives with, and until now
    // there was no way to ask it - --asn-db was not even accepted here.
    if (asnOk) {
        r.out += "asn:   " + WideToUtf8(asnPath) + " (version " +
                 WideToUtf8(asnVersion) + ", " + RecordsText(asnRecords) +
                 ", " + std::to_string(asnSize) + " bytes)\r\n";
    } else {
        r.out += "asn:   not loaded (" + WideToUtf8(asnError) + ")\r\n";
    }
    if (fwError.empty()) {
        r.out += "firewall: " + std::to_string(fwRules) + " WinTCP rules\r\n";
    } else {
        r.out += "firewall: " + std::to_string(fwRules) +
                 " WinTCP rules (ledger unreadable: " +
                 WideToUtf8(fwError) + ")\r\n";
    }
    r.out += "capture: " + std::string(capOk ? "available" :
             ("unavailable (" + WideToUtf8(capWhy) + ")")) + "\r\n";
    return r;
}

CommandResult CmdBookmarkList(const std::string& format) {
    CommandResult r;
    size_t unreadable = 0;
    const std::vector<Bookmark> all = Bookmarks::List(&unreadable);
    if (format == "json") {
        std::string out = "[";
        bool first = true;
        for (const Bookmark& b : all) {
            if (!first) out += ",";
            out += "\n  {\"address\":\"" + JsonEscapeA(b.address) +
                   "\",\"port\":" + std::to_string(b.port) + ",\"tag\":\"" +
                   JsonEscapeA(BookmarkTagLabel(b.tag)) + "\",\"note\":\"" +
                   JsonEscapeA(b.note) + "\"}";
            first = false;
        }
        out += "\n]";
        r.out = out;
        return r;
    }
    if (format == "table") {
        // Aligned like every other human table: addresses, tags and
        // notes left, the port number right.
        const std::vector<std::string> header = {"Address", "Port", "Tag",
                                                 "Note"};
        const std::vector<bool> right = {false, true, false, false};
        std::vector<std::vector<std::string>> cells;
        cells.reserve(all.size());
        for (const Bookmark& b : all) {
            cells.push_back({TsvCell(b.address), std::to_string(b.port),
                             TsvCell(BookmarkTagLabel(b.tag)),
                             TsvCell(b.note)});
        }
        r.out = RenderAlignedLines(header, cells, right,
                                   ContentWidths(header, cells), true);
    } else {
        const char delim = (format == "csv") ? ',' : '\t';
        std::string out = std::string("Address") + delim + "Port" + delim +
                          "Tag" + delim + "Note\r\n";
        for (const Bookmark& b : all) {
            std::string line = TsvCell(b.address) + delim +
                               std::to_string(b.port) + delim +
                               TsvCell(BookmarkTagLabel(b.tag)) + delim +
                               TsvCell(b.note) + "\r\n";
            if (format == "csv") {
                line = CsvEscapeUtf8(WideToUtf8(b.address)) + delim +
                       std::to_string(b.port) + delim +
                       CsvEscapeUtf8(WideToUtf8(BookmarkTagLabel(b.tag))) +
                       delim + CsvEscapeUtf8(WideToUtf8(b.note)) + "\r\n";
            }
            out += line;
        }
        r.out = out;
    }
    if (unreadable != 0) {
        r.err = "warning: " + std::to_string(unreadable) +
                " unreadable bookmark entries skipped.\r\n";
    }
    return r;
}

// ---- bookmark export / import ---------------------------------------

CommandResult CmdBookmarkExport(const std::wstring& outPath,
                                bool forceOverwrite) {
    CommandResult r;
    if (outPath.empty()) {
        r.exitCode = kExitArgs;
        r.err = "bookmark export: --out <file> is required.\r\n";
        return r;
    }
    std::wstring existsErr;
    if (RefuseExistingOutput(L"bookmark export", outPath, forceOverwrite,
                             &existsErr)) {
        r.exitCode = kExitArgs;
        r.err = WideToUtf8(existsErr);
        return r;
    }
    size_t unreadable = 0;
    const std::vector<Bookmark> all = Bookmarks::List(&unreadable);
    // No BOM: this is a JSON document, and a BOM in front of it breaks every
    // parser that follows the spec - including this tool's own reader.
    std::string json;
    SerialiseBookmarks(all, &json);
    const std::wstring werr = WriteUtf8FileWithBom(outPath, json, false);
    if (!werr.empty()) {
        r.exitCode = kExitFail;
        r.err = "bookmark export failed: " + WideToUtf8(werr) + "\r\n";
        return r;
    }
    r.out = "exported " + std::to_string(all.size()) + " bookmarks to " +
            WideToUtf8(outPath) + "\r\n";
    if (unreadable != 0) {
        r.err = "warning: " + std::to_string(unreadable) +
                " unreadable bookmark entries skipped.\r\n";
    }
    return r;
}

CommandResult CmdBookmarkImport(const std::wstring& inPath, bool yes) {
    CommandResult r;
    if (inPath.empty()) {
        r.exitCode = kExitArgs;
        r.err = "bookmark import: --in <file> is required.\r\n";
        return r;
    }

    // Read and parse BEFORE touching the registry. A file that will not parse
    // must leave the bookmarks that were already there alone - importing half
    // a file is the failure the codec exists to prevent, and a partial import
    // followed by a fatal one is the same failure with extra steps.
    std::string text;
    std::wstring readErr = ReadUtf8File(inPath, &text);
    if (!readErr.empty()) {
        r.exitCode = kExitFail;
        r.err = "bookmark import failed: could not read " +
                WideToUtf8(inPath) + ": " + WideToUtf8(readErr) + "\r\n";
        return r;
    }
    std::vector<Bookmark> items;
    std::wstring parseErr;
    if (!ParseBookmarks(text, &items, &parseErr)) {
        r.exitCode = kExitArgs;
        r.err = "bookmark import refused " + WideToUtf8(inPath) + ": " +
                WideToUtf8(parseErr) + "\r\n";
        return r;
    }

    // The plan is printed before anything is written, so a dry run shows
    // exactly what would be imported and the count is checkable by eye.
    std::string plan = "import " + std::to_string(items.size()) +
                       " bookmarks from " + WideToUtf8(inPath) + "\r\n";
    if (items.empty()) {
        plan += "  (the file holds no bookmarks; nothing to do)\r\n";
    } else {
        for (size_t i = 0; i < items.size() && i < 5; ++i) {
            plan += "  " +
                    WideToUtf8(JoinEndpoint(items[i].address, items[i].port,
                                            items[i].address.find(L':') !=
                                                std::wstring::npos)) +
                    "\r\n";
        }
        if (items.size() > 5) {
            plan += "  ... and " + std::to_string(items.size() - 5) + " more\r\n";
        }
    }
    // The refusal contract is the one every act verb follows: 3 for "no --yes",
    // after the plan is built so `--dry-run` without `--yes` still shows it.
    if (!yes) {
        return Refused("bookmark import");
    }

    size_t added = 0;
    size_t already = 0;
    std::wstring firstErr;
    for (const Bookmark& b : items) {
        // Add refreshes the timestamp of an existing bookmark and nothing
        // else, so re-importing a file cannot discard a note the user typed -
        // the contract Bookmarks::Add already documents.
        if (Bookmarks::IsBookmarked(b.address, b.port)) {
            ++already;
            continue;
        }
        if (!Bookmarks::Add(b.address, b.port, b.tag, b.note)) {
            if (firstErr.empty()) {
                firstErr = L"could not import " + b.address;
            }
            continue;
        }
        ++added;
    }
    r.out = plan;
    r.out += "imported " + std::to_string(added) +
             (already != 0 ? " (already present: " + std::to_string(already) +
                                 ")"
                           : "") +
             "\r\n";
    if (!firstErr.empty()) {
        r.exitCode = kExitFail;
        r.err = "bookmark import partly failed: " + WideToUtf8(firstErr) +
                "\r\n";
    }
    return r;
}

// ---- preset export / import ------------------------------------------

CommandResult CmdPresetExport(const std::wstring& outPath,
                              bool forceOverwrite) {
    CommandResult r;
    if (outPath.empty()) {
        r.exitCode = kExitArgs;
        r.err = "preset export: --out <file> is required.\r\n";
        return r;
    }
    std::wstring existsErr;
    if (RefuseExistingOutput(L"preset export", outPath, forceOverwrite,
                             &existsErr)) {
        r.exitCode = kExitArgs;
        r.err = WideToUtf8(existsErr);
        return r;
    }
    // Presets::Load is strict - a preset that fails to read is skipped rather
    // than written half - so a file this exports is a file of readable views.
    std::vector<PresetRecord> items;
    size_t unreadable = 0;
    for (const std::wstring& name : Presets::List()) {
        PresetRecord rec;
        rec.name = name;
        if (Presets::Load(name, &rec.view)) {
            items.push_back(std::move(rec));
        } else {
            ++unreadable;
        }
    }
    std::string json;
    SerialisePresets(items, &json);
    const std::wstring werr = WriteUtf8FileWithBom(outPath, json, false);
    if (!werr.empty()) {
        r.exitCode = kExitFail;
        r.err = "preset export failed: " + WideToUtf8(werr) + "\r\n";
        return r;
    }
    r.out = "exported " + std::to_string(items.size()) + " presets to " +
            WideToUtf8(outPath) + "\r\n";
    if (unreadable != 0) {
        r.err = "warning: " + std::to_string(unreadable) +
                " unreadable presets skipped.\r\n";
    }
    return r;
}

CommandResult CmdPresetImport(const std::wstring& inPath, bool yes) {
    CommandResult r;
    if (inPath.empty()) {
        r.exitCode = kExitArgs;
        r.err = "preset import: --in <file> is required.\r\n";
        return r;
    }

    // Parse and plan BEFORE writing anything, exactly like the bookmark
    // import: a file that will not parse leaves the presets that were there
    // alone, and loading half a view is a view the user never saved.
    std::string text;
    std::wstring readErr = ReadUtf8File(inPath, &text);
    if (!readErr.empty()) {
        r.exitCode = kExitFail;
        r.err = "preset import failed: could not read " + WideToUtf8(inPath) +
                ": " + WideToUtf8(readErr) + "\r\n";
        return r;
    }
    std::vector<PresetRecord> items;
    std::wstring parseErr;
    if (!ParsePresets(text, &items, &parseErr)) {
        r.exitCode = kExitArgs;
        r.err = "preset import refused " + WideToUtf8(inPath) + ": " +
                WideToUtf8(parseErr) + "\r\n";
        return r;
    }

    std::string plan = "import " + std::to_string(items.size()) +
                       " presets from " + WideToUtf8(inPath) + "\r\n";
    if (items.empty()) {
        plan += "  (the file holds no presets; nothing to do)\r\n";
    } else {
        for (size_t i = 0; i < items.size() && i < 5; ++i) {
            plan += "  " + WideToUtf8(items[i].name) + "\r\n";
        }
        if (items.size() > 5) {
            plan += "  ... and " + std::to_string(items.size() - 5) + " more\r\n";
        }
    }
    // The act-verb contract: 3 for no --yes, after the plan is built so
    // `--dry-run` without `--yes` still shows what would happen.
    if (!yes) {
        return Refused("preset import");
    }

    // WITHOUT --force an existing name is refused rather than silently
    // replaced. Presets::Save's default argument already never writes over an
    // existing preset, and reusing that contract is what makes an import safe:
    // the user confirms and repeats with --force, exactly as the GUI does.
    size_t written = 0;
    size_t skipped = 0;
    std::wstring firstSkipped;
    for (const PresetRecord& rec : items) {
        if (Presets::Exists(rec.name)) {
            ++skipped;
            if (firstSkipped.empty()) firstSkipped = rec.name;
            continue;
        }
        if (Presets::Save(rec.name, rec.view) != PresetSave::kCreated) {
            if (firstSkipped.empty()) firstSkipped = rec.name;
            continue;
        }
        ++written;
    }
    r.out = plan;
    r.out += "imported " + std::to_string(written) +
             (skipped != 0 ? " (already present, skipped: " +
                                 std::to_string(skipped) + ")"
                           : "") +
             "\r\n";
    if (skipped != 0) {
        r.err = "presets already present were NOT replaced; pass --force to "
                "overwrite them. First skipped: " +
                WideToUtf8(firstSkipped) + "\r\n";
    }
    return r;
}

// The CLI parser enforces kMinTag..kMaxTag (Commands.h); the canonical tag
// set lives in Bookmarks.h. These must be the same range — a tag the parser
// accepts but the store rejects (or vice versa) is a refusal that depends on
// which layer you ask. Pinned at compile time, not by convention.
static_assert(kMinTag == kBookmarkTagNone && kMaxTag == kBookmarkTagGreen,
              "CLI tag range drifted from the bookmark tag set");
CommandResult CmdBookmarkAdd(const std::wstring& address, UINT port,
                             unsigned tag, const std::wstring& note) {
    CommandResult r;
    if (!IsValidBookmarkTag(tag)) {
        r.exitCode = kExitArgs;
        r.err = "bookmark add: --tag must be 0..4.\r\n";
        return r;
    }
    if (note.size() > Bookmarks::kMaxNoteChars) {
        r.exitCode = kExitArgs;
        r.err = "bookmark add: note too long.\r\n";
        return r;
    }
    if (!Bookmarks::Add(address, port, tag, note)) {
        r.exitCode = kExitFail;
        r.err = "bookmark add: failed (bad address, port, or registry).\r\n";
        return r;
    }
    r.out = "bookmark added: " + WideToUtf8(MakeBookmarkKey(
                                NormalizeAddress(address), port)) +
            "\r\n";
    return r;
}

CommandResult CmdBookmarkRemove(const std::wstring& address, UINT port) {
    CommandResult r;
    if (!Bookmarks::Remove(address, port)) {
        r.exitCode = kExitFail;
        r.err = "bookmark remove: failed.\r\n";
        return r;
    }
    r.out = "bookmark removed.\r\n";
    return r;
}

CommandResult CmdBookmarkNote(const std::wstring& address, UINT port,
                              const std::wstring& note) {
    CommandResult r;
    if (!Bookmarks::SetNote(address, port, note)) {
        r.exitCode = kExitFail;
        r.err = "bookmark note: failed (no such bookmark?).\r\n";
        return r;
    }
    r.out = "bookmark note updated.\r\n";
    return r;
}

CommandResult CmdBookmarkColour(const std::wstring& address, UINT port,
                                unsigned tag) {
    CommandResult r;
    if (!IsValidBookmarkTag(tag)) {
        r.exitCode = kExitArgs;
        r.err = "bookmark colour: --tag must be 0..4.\r\n";
        return r;
    }
    if (!Bookmarks::SetColour(address, port, tag)) {
        r.exitCode = kExitFail;
        r.err = "bookmark colour: failed (no such bookmark?).\r\n";
        return r;
    }
    r.out = "bookmark colour updated.\r\n";
    return r;
}

CommandResult CmdPresetList(const std::string& format) {
    CommandResult r;
    const std::vector<std::wstring> names = Presets::List();
    if (format == "json") {
        std::string out = "[";
        bool first = true;
        for (const std::wstring& n : names) {
            if (!first) out += ",";
            out += "\n  \"" + JsonEscapeA(n) + "\"";
            first = false;
        }
        out += "\n]";
        r.out = out;
        return r;
    }
    const char delim = (format == "csv") ? ',' : '\t';
    std::string out = std::string("Preset") + "\r\n";
    (void)delim;
    for (const std::wstring& n : names) {
        const std::string cell = WideToUtf8(n);
        out += (format == "csv" ? CsvEscapeUtf8(cell) : cell) + "\r\n";
    }
    r.out = out;
    return r;
}

CommandResult CmdPresetSave(const std::wstring& name, const ViewState& view,
                            bool overwrite) {
    CommandResult r;
    const PresetSave s = Presets::Save(name, view, overwrite);
    switch (s) {
        case PresetSave::kCreated:
            r.out = "preset created: " + WideToUtf8(name) + "\r\n";
            break;
        case PresetSave::kOverwrote:
            r.out = "preset overwritten: " + WideToUtf8(name) + "\r\n";
            break;
        case PresetSave::kExists:
            // The one non---yes route through Refused: same exit code and
            // same meaning, different remedy, so the wording says --force.
            // Returned, not assigned + broken out of, because Refused() builds
            // the whole CommandResult including the exit code.
            return Refused("preset '" + WideToUtf8(name) + "' exists",
                           "--force");
        case PresetSave::kInvalidName:
            r.exitCode = kExitArgs;
            r.err = "preset: invalid name.\r\n";
            break;
        case PresetSave::kFailed:
        default:
            r.exitCode = kExitFail;
            r.err = "preset save failed (registry).\r\n";
            break;
    }
    return r;
}

CommandResult CmdPresetShow(const std::wstring& name) {
    CommandResult r;
    PresetView v;
    if (!Presets::Load(name, &v)) {
        r.exitCode = kExitFail;
        r.err = "preset '" + WideToUtf8(name) + "' not found or corrupt.\r\n";
        return r;
    }
    r.out = ViewStateToJson(v) + "\r\n";
    return r;
}

CommandResult CmdPresetDelete(const std::wstring& name) {
    CommandResult r;
    if (!Presets::Delete(name)) {
        r.exitCode = kExitFail;
        r.err = "preset delete failed.\r\n";
        return r;
    }
    r.out = "preset deleted: " + WideToUtf8(name) + "\r\n";
    return r;
}

CommandResult CmdPresetApply(SnapshotSource& source, const std::wstring& name,
                             ListOptions* appliedView,
                             const ListOptions* overrides) {
    CommandResult r;
    PresetView v;
    if (!Presets::Load(name, &v)) {
        r.exitCode = kExitFail;
        r.err = "preset '" + WideToUtf8(name) + "' not found or corrupt.\r\n";
        return r;
    }
    ListOptions opt;
    opt.filter = v.filter;
    opt.sortColumn = v.sortColumn;
    opt.sortAsc = v.sortAsc;
    opt.grouped = v.grouped;
    // layer the user's OWN switches over the saved view. Before this the
    // command-line switches were parsed and then thrown away, so
    // `preset apply --name web --limit 2` printed the entire 27-row table in
    // the preset's default column set and exited 0 - a script asking for two
    // rows and a narrow table got both of neither.
    //
    // Only fields the caller ACTUALLY set are taken, which is why this takes a
    // ListOptions plus the set of switches the user typed: limit 0 and an empty
    // column list are both legitimate "unset" values, so a plain struct copy
    // would clobber the preset with defaults.
    if (overrides != nullptr) {
        if (overrides->limit != 0) opt.limit = overrides->limit;
        if (!overrides->columns.empty()) opt.columns = overrides->columns;
        if (overrides->sortColumn != COL_PID)
            opt.sortColumn = overrides->sortColumn;
        opt.sortAsc = overrides->sortAsc;
        opt.format = overrides->format;
        opt.traffic = overrides->traffic;
        opt.dns = overrides->dns;
        opt.geoIpPath = overrides->geoIpPath;
        // carried alongside, for the same reason. A preset that pinned the
        // ASN database must not silently lose it on the view that applies it.
        opt.asnIpPath = overrides->asnIpPath;
    }
    if (appliedView != nullptr) *appliedView = opt;
    ConnectionStore store;
    std::wstring err;
    if (!BuildStoreSnapshot(source, store, /*procStats=*/true,
                            (v.sources & kPresetSourceHosts) != 0,
                            (v.sources & kPresetSourceGeoIp) != 0, nullptr,
                            &err)) {
        r.exitCode = kExitFail;
        r.err = "Enumeration failed: " + WideToUtf8(err) + "\r\n";
        return r;
    }
    ApplyListView(store, opt);
    r.out = DelimitedList(store, opt);
    // An empty view is a real, reportable answer for an applied view, so the
    // exit code says so - the same contract `list` already has.
    if (r.out.empty()) r.exitCode = kExitFail;
    return r;
}

std::string FormatChangeEvents(const std::vector<RowChange>& events,
                               const std::string& format,
                               const std::wstring& stamp,
                               const std::vector<FilterClause>* prog,
                               unsigned eventMask) {
    const std::string t = WideToUtf8(stamp);
    const bool json = (format == "json");
    std::string out;
    for (const RowChange& e : events) {
        // the event-kind gate, BEFORE the row filter, so a user asking for
        // only APPEAR never pays for (or is confused by) the DISAPPEAR half of
        // the diff. `eventMask` defaults to all three, so every existing caller
        // that passes 0x7 behaves exactly as before.
        if (eventMask != 0 && (eventMask & (1u << e.kind)) == 0) continue;
        if (prog != nullptr && !prog->empty() && !MatchFilter(e.row, *prog))
            continue;
        const char* kind = (e.kind == kChangeDisappear) ? "DISAPPEAR"
                           : (e.kind == kChangeState)   ? "STATE"
                                                        : "APPEAR";
        const char* jkind = (e.kind == kChangeDisappear) ? "disappear"
                            : (e.kind == kChangeState)   ? "state"
                                                         : "appear";
        if (json) {
            out += "{\"t\":\"" + JsonEscapeA(stamp) + "\",\"event\":\"" +
                   jkind + "\",\"proto\":\"" +
                   JsonEscapeA(e.row.keys.protoLabel) + "\",\"local\":\"" +
                   JsonEscapeA(e.row.display.localAddress) +
                   "\",\"lport\":" + std::to_string(e.row.identity.localPort) +
                   ",\"remote\":\"" + JsonEscapeA(e.row.display.remoteAddress) +
                   "\",\"rport\":" + std::to_string(e.row.identity.remotePort) +
                   ",\"state\":\"" + JsonEscapeA(e.row.keys.stateLabel) + "\"";
            if (e.kind == kChangeState) {
                out += ",\"old_state\":\"" +
                       JsonEscapeA(TcpStateToString(e.oldState)) + "\"";
            }
            out += ",\"pid\":" + std::to_string(e.row.identity.pid) +
                   ",\"process\":\"" + JsonEscapeA(e.row.display.processName) +
                   "\"}\r\n";
            continue;
        }
        out += "[" + t + "] " + kind + " " +
               WideToUtf8(e.row.keys.protoLabel) + " " +
               WideToUtf8(e.row.display.localEndpoint) + " -> " +
               WideToUtf8(e.row.display.remoteEndpoint) + " (" +
               WideToUtf8(e.row.keys.stateLabel) + ")";
        if (e.kind == kChangeState) {
            out += " was " + WideToUtf8(TcpStateToString(e.oldState));
        }
        out += " pid=" + std::to_string(e.row.identity.pid) + " " +
               WideToUtf8(e.row.display.processName) + "\r\n";
    }
    return out;
}

// R4. Refuse to write over an existing file unless the caller authorised it.
//
// WHY A REFUSAL AND NOT A DOCUMENTATION NOTE. The write is CREATE_ALWAYS, so
// the previous behaviour destroyed whatever was at that path with no output and
// nothing in the exit code to say so. Measured before this change: a 6-byte file
// containing "AAAA" was replaced by an 844-byte export, exit 0, one line of
// output naming the destination and nothing about what it replaced. A script
// that exports on a schedule would do that to a real report and report success.
//
// WHY HERE AND NOT AT THE WRITE. Same ordering `capture` already uses - refuse
// before the work, not after - so a refused request costs no snapshot and
// touches no state.
//
// A DIRECTORY at that path counts as existing. Overwriting a directory with a
// file fails anyway, but reporting it here says why, instead of surfacing a
// CreateFile error about access.
bool RefuseExistingOutput(const wchar_t* verb, const std::wstring& path,
                          bool forceOverwrite, std::wstring* err) {
    if (forceOverwrite || path.empty()) return false;
    const DWORD attr = ::GetFileAttributesW(path.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) return false;   // does not exist: fine
    *err = std::wstring(verb) + L": '" + path +
           L"' already exists. --out replaces the whole file and this command "
           L"cannot ask before doing that. Add --force to replace it, or write "
           L"somewhere else.\r\n";
    return true;
}

CommandResult CmdExport(SnapshotSource& source, const ListOptions& opt,
                        const std::wstring& outPath,
                        bool forceOverwrite) {
    if (outPath.empty()) {
        CommandResult r;
        r.exitCode = kExitArgs;
        r.err = "export: --out <file> is required.\r\n";
        return r;
    }
    {
        std::wstring existsErr;
        if (RefuseExistingOutput(L"export", outPath, forceOverwrite, &existsErr)) {
            CommandResult r;
            r.exitCode = kExitArgs;
            r.err = WideToUtf8(existsErr);
            return r;
        }
    }
    // the same rule RenderList applies, needed here because export writes
    // the file itself and does not go through RenderList. Checked BEFORE the
    // snapshot so a refused request costs nothing and touches no state.
    {
        const std::string bad = ValidateStreamColumns(opt);
        if (!bad.empty()) {
            CommandResult r;
            r.exitCode = kExitArgs;
            r.err = "export: --group cannot report " + bad +
                    ": a group is one process, and that column describes one "
                    "connection, so the file's header would promise a value "
                    "the rows do not carry.\r\n"
                    "Drop the column, or drop --group. Columns that DO have a "
                    "group answer: pid, process, proto, state, traffic, rx, "
                    "tx, nettotal, cpu, mem, disk, service, path, pinned.\r\n";
            return r;
        }
    }
    ConnectionStore store;
    std::wstring err;
    if (!BuildStoreSnapshot(source, store, /*procStats=*/true,
                            /*resolveDns=*/false, /*geoIp=*/false, nullptr,
                            &err)) {
        CommandResult r;
        r.exitCode = kExitFail;
        r.err = "Enumeration failed: " + WideToUtf8(err) + "\r\n";
        return r;
    }
    ApplyListView(store, opt);
    // Export means everything the view selects: --limit is a display
    // truncation for list/ps, and must not silently truncate a file while
    // the report claims the full count. The CLI therefore REFUSES --limit on
    // export (exit 2, naming the switch) rather than accepting and ignoring
    // it - a swallowed switch is worse than a rejected one, because a
    // script cannot tell from the exit code that it got the whole file.
    ListOptions full = opt;
    full.limit = 0;
    full.quiet = false;
    // Enrichment flags (--dns/--db/--traffic) apply to exports too: the
    // file carries what the screen would show.
    std::string advice;
    if (!EnrichViewForList(store, full, &err, &advice)) {
        CommandResult r;
        r.exitCode = kExitFail;
        r.err = "GeoIP: " + WideToUtf8(err) + "\r\n";
        return r;
    }
    const std::string content = (full.format == "json")
        ? JsonList(store, full)
        : DelimitedList(store, full);
    const bool isJson = (full.format == "json");
    const std::wstring werr =
        WriteUtf8FileWithBom(outPath, content, !isJson);
    CommandResult r;
    if (!werr.empty()) {
        r.exitCode = kExitFail;
        r.err = "export failed: " + WideToUtf8(werr) + "\r\n";
        return r;
    }
    r.out = "exported " + std::to_string(store.View().size()) + " rows to " +
            WideToUtf8(outPath) + "\r\n";
    // --quiet now means what it means everywhere else. It used to be
    // accepted by export and then printed this line anyway, so
    // `export --out f.csv --quiet > log` still wrote a line into the log - a
    // quiet switch that is not quiet is a trap for exactly the scripts that
    // use it. The file is still written; only the confirmation line is
    // suppressed, and the exit code still says whether rows were written.
    if (opt.quiet) r.out.clear();
    // Missing-switch advice: without it an export written against an
    // enrichment clause its switches cannot answer is a silent zero-row file.
    if (!advice.empty()) r.err = advice;
    return r;
}

CommandResult CmdGeoIpLookup(SnapshotSource& source,
                             const std::wstring& geoIpPath,
                             const std::wstring& ip) {
    CommandResult r;
    if (ip.empty()) {
        r.exitCode = kExitArgs;
        r.err = "geoip lookup: <ip> is required.\r\n";
        return r;
    }
    GeoIpDatabase db;
    if (!geoIpPath.empty()) {
        std::wstring err;
        if (!db.Load(geoIpPath, &err)) {
            r.exitCode = kExitFail;
            r.err = "geoip: cannot load database: " + WideToUtf8(err) + "\r\n";
            return r;
        }
    } else {
        // Use the source's loaded database when no path is given.
        (void)source;
        r.exitCode = kExitArgs;
        r.err = "geoip lookup: --db <file.mmdb> is required.\r\n";
        return r;
    }
    IN_ADDR a4 = {};
    IN6_ADDR a6 = {};
    std::wstring code;
    AsnInfo asn;
    if (::InetPtonW(AF_INET, ip.c_str(), &a4) == 1) {
        code = db.LookupV4(ntohl(a4.S_un.S_addr));
        asn = db.LookupAsnV4(ntohl(a4.S_un.S_addr));
    } else if (::InetPtonW(AF_INET6, ip.c_str(), &a6) == 1) {
        char a6s[kIpv6TextChars] = {0};
        ::InetNtopA(AF_INET6, &a6, a6s, sizeof(a6s));
        code = db.LookupV6(a6.s6_addr);
        asn = db.LookupAsnV6(a6.s6_addr);
    } else {
        r.exitCode = kExitArgs;
        r.err = "geoip lookup: '" + WideToUtf8(ip) + "' is not an IP.\r\n";
        return r;
    }
    // A GeoLite2-ASN file has no country records, so before this the verb
    // answered "-" for every address and gave the reader nothing to go on: the
    // database had loaded, the address was fine, and nothing was wrong. An answer
    // is whichever the file actually holds, so an ASN file answers with its ASN
    // and a country file answers with its code.
    std::wstring answer = code.empty() ? asn.Display() : code;
    r.out = WideToUtf8(answer.empty() ? std::wstring(L"-") : answer) + "\r\n";
    return r;
}

CommandResult CmdGeoIpInfo(SnapshotSource& /*source*/,
                           const std::wstring& geoIpPath) {
    CommandResult r;
    if (geoIpPath.empty()) {
        r.exitCode = kExitArgs;
        r.err = "geoip info: --db <file.mmdb> is required.\r\n";
        return r;
    }
    GeoIpDatabase db;
    std::wstring err;
    if (!db.Load(geoIpPath, &err)) {
        r.exitCode = kExitFail;
        r.err = "geoip: cannot load database: " + WideToUtf8(err) + "\r\n";
        return r;
    }
    // The record count is the database's own metadata, and most real files omit
    // it (every DBIP edition does), so 0 must read as "not stated" rather than as
    // an empty database. `swprintf_s` with %llu cannot say that, and the buffer is
    // sized for the shorter, honest form.
    const uint64_t recs = db.RecordCount();
    wchar_t buf[kGeoIpDescChars] = {0};
    if (recs == 0) {
        ::swprintf_s(buf, L"%ls, record count not stated, %llu nodes, %zu bytes",
                     db.DatabaseVersion().c_str(),
                     static_cast<unsigned long long>(db.NodeCount()),
                     db.FileSize());
    } else {
        ::swprintf_s(buf, L"%ls, %llu records, %llu nodes, %zu bytes",
                     db.DatabaseVersion().c_str(),
                     static_cast<unsigned long long>(recs),
                     static_cast<unsigned long long>(db.NodeCount()),
                     db.FileSize());
    }
    r.out = WideToUtf8(buf) + "\r\n";
    return r;
}

namespace {

// One direction's worth of the TLS report, already formatted.
//
// Kept as a struct rather than a bag of out-parameters because the caller has
// to distinguish four outcomes per direction - no payload, not TLS, TLS with
// no handshake message, TLS with one - and collapsing them is exactly how a
// reader ends up believing a negative they were never shown.
struct TlsDirectionReport {
    bool havePayload = false;      // bytes were captured at all
    bool looksLikeTls = false;     // begins with a TLS record header
    bool sawHandshake = false;     // a ClientHello/ServerHello/Certificate
    size_t chainedRecords = 0;      // contiguous TLS records found mid-stream
    size_t chainStart = 0;
    std::string line;              // the whole `tls: ...` line, ready to emit
    std::string caveat;            // an honesty note, or empty
};

// Format one value for the report, or "-" when it is genuinely unknown.
//
// "-" and never an empty pair of quotes and never a guess: TlsVersionName and
// TlsCipherSuiteName already return "" for a value they do not recognise, and
// printing that as `cipher=` would read as "the cipher is nothing".
std::string TlsField(const std::string& v) {
    return v.empty() ? std::string("-") : v;
}

// The length of the run of CONTIGUOUS TLS records starting at 'from', or 0.
//
// Contiguity is the whole point, and it is what makes this a measurement
// rather than a guess. A random byte can look like a record header often
// enough to matter: on one real 131,072-byte mid-stream TLS capture, 13 offsets
// passed the "type 20-23, version 0x03xx, plausible length" test. Five of them
// were coincidence. Eight were real - each one's declared length put the next
// header at an exact offset, and the longest such run was 9 records.
//
// The reason coincidence cannot fake that: for the next header to appear at
// precisely off+5+len is a further one-in-thirty-thousand, so across the ~13
// candidates in that capture the expected number of chains by luck is about
// four thousandths. Chaining is therefore decisive, and scanning for headers
// ALONE is not - which is why this function exists rather than a header count.
size_t TlsRecordChainRun(const std::string& bytes, size_t from) {
    const unsigned char* p =
        reinterpret_cast<const unsigned char*>(bytes.data());
    const size_t n = bytes.size();
    size_t off = from;
    size_t run = 0;
    while (off + 5 <= n) {
        if (p[off] < kTlsChangeCipherSpec || p[off] > kTlsApplicationData)
            break;
        if (p[off + 1] != 0x03) break;
        const size_t len =
            (static_cast<size_t>(p[off + 3]) << 8) | p[off + 4];
        if (len == 0 || off + 5 + len > n) break;
        ++run;
        off += 5 + len;
    }
    return run;
}

// The longest contiguous record run anywhere in 'bytes', and where it starts.
// Returns 0 when there is none.
size_t TlsLongestRecordChain(const std::string& bytes, size_t* startAt) {
    size_t best = 0;
    size_t bestAt = 0;
    for (size_t i = 0; i + 5 <= bytes.size(); ++i) {
        const size_t run = TlsRecordChainRun(bytes, i);
        if (run > best) {
            best = run;
            bestAt = i;
        }
        // A run this long cannot be beaten by anything further in; and the loop
        // is over the whole direction, which for a 32 MB reassembly is the one
        // cost worth caring about - hence the early exit rather than an
        // unbounded rescan.
        if (best >= 8) break;
    }
    *startAt = bestAt;
    return best;
}

TlsDirectionReport TlsDescribeOne(const ReasmResult& dir,
                                  const std::wstring& label,
                                  const char* heading) {
    TlsDirectionReport rep;
    rep.havePayload = !dir.bytes.empty();
    if (!rep.havePayload) {
        rep.line = std::string("tls: ") + heading + " (" + WideToUtf8(label) +
                   ") captured no payload\r\n";
        return rep;
    }
    // The cheap check before the real parse: a first record header is 5 bytes,
    // and a direction that does not start with one cannot carry a handshake.
    rep.looksLikeTls = LooksLikeTls(dir.bytes);
    if (!rep.looksLikeTls) {
        // THE HONEST NEGATIVE, and the reason this branch is not one line.
        //
        // "does not begin with a TLS record" is true in TWO quite different
        // situations, and a reader who is told only the first will draw the
        // wrong conclusion about the second:
        //
        //   (a) this really is a plaintext protocol;
        //   (b) this IS TLS, and the capture window opened after the records
        //       began, so the reassembly starts in the middle of one.
        //
        // (b) is the COMMON case for a connection that was already up, and it
        // was measured here: a 6-second capture of a live HTTPS transfer
        // produced 130,816 bytes that began mid-record and were correctly
        // reported as not starting with one. Reporting (b) as (a) would tell a
        // reader their HTTPS connection is not encrypted, which is worse than
        // saying nothing.
        //
        // So the two are told apart by CONTIGUITY: a real record layer declares
        // each record's length, so consecutive headers sit at exact offsets.
        // Random ciphertext produces occasional lookalikes - 14 in those 130,816
        // bytes - but not one of them chained.
        rep.chainedRecords =
            TlsLongestRecordChain(dir.bytes, &rep.chainStart);
        if (rep.chainedRecords >= 3) {
            rep.line = std::string("tls: ") + heading + " (" +
                       WideToUtf8(label) +
                       ") does not begin with a TLS record, but " +
                       std::to_string(rep.chainedRecords) +
                       " contiguous TLS records start at offset " +
                       std::to_string(rep.chainStart) +
                       ": this is TLS whose records began before the capture "
                       "window, so no handshake is recoverable from it.\r\n";
        } else {
            rep.line = std::string("tls: ") + heading + " (" +
                       WideToUtf8(label) +
                       ") does not begin with a TLS record, and no run of "
                       "contiguous TLS records appears anywhere in it\r\n";
        }
        return rep;
    }
    const TlsHandshake hs = ParseTlsHandshake(dir.bytes);
    rep.sawHandshake = hs.sawClientHello || hs.sawServerHello ||
                       hs.sawCertificate;
    std::string s = std::string("tls: ") + heading + " (" +
                    WideToUtf8(label) + ") ";
    if (hs.sawClientHello) {
        s += "ClientHello: SNI=" + TlsField(hs.sni) +
             " ALPN=" + TlsField(hs.sniProto) +
             " offered=" + TlsField(TlsVersionName(hs.clientVersion));
    }
    if (hs.sawServerHello) {
        if (hs.sawClientHello) s += " | ";
        s += "ServerHello: negotiated=" +
             TlsField(TlsVersionName(hs.serverVersion)) +
             " cipher=" + TlsField(TlsCipherSuiteName(hs.cipherSuite));
    }
    if (hs.sawCertificate) {
        s += " | certificate: subject=" + TlsField(hs.certSubject) +
             " issuer=" + TlsField(hs.certIssuer) +
             " valid=" + TlsField(hs.certValidity);
    }
    if (!rep.sawHandshake) {
        // The distinction that matters: the bytes ARE TLS, but no handshake
        // message is in them. That is the normal result when the capture window
        // opened after the connection was established, and it must not be
        // reported as "no TLS" - the session exists, we simply missed its
        // opening.
        s += "begins with TLS records but no handshake message was captured "
             "(the window opened after the handshake)";
    } else if (hs.sawAlert) {
        s += " | alert seen";
    }
    if (hs.sawApplicationData) {
        s += " | " + std::to_string(hs.encryptedBytes) +
             " bytes of application_data after the handshake";
    }
    s += "\r\n";
    rep.line = s;

    // Two ways this decode can be incomplete, and both have to be said: a hole
    // means every byte after it is misaligned, and the record layer stops at
    // the first record that overruns what we captured.
    if (dir.hasGap || dir.bytesMissing != 0) {
        rep.caveat = std::string("tls: NOTE: ") + heading + " (" +
                     WideToUtf8(label) +
                     ") has " + std::to_string(dir.bytesMissing) +
                     " byte(s) missing, so the handshake decode after the hole "
                     "at offset " + std::to_string(dir.firstSeq) +
                     " is unreliable.\r\n";
    }
    if (dir.truncated) {
        rep.caveat += std::string("tls: NOTE: ") + heading + " (" +
                      WideToUtf8(label) +
                      ") hit the reassembly cap, so a handshake that started "
                      "later was never captured.\r\n";
    }
    return rep;
}

}  // namespace

// Both directions, plus the one-line verdict that ties them together.
// Declared in Commands.h so the selftest can drive it.
std::string TlsCaptureLines(const ReasmResult& toServer,
                            const ReasmResult& toClient,
                            const std::wstring& dir1Label,
                            const std::wstring& dir2Label) {
    const TlsDirectionReport a =
        TlsDescribeOne(toServer, dir1Label, "to first endpoint");
    const TlsDirectionReport b =
        TlsDescribeOne(toClient, dir2Label, "from first endpoint");

    std::string out;
    // A capture of a connection that is not TLS at all still has to say so:
    // silence here is indistinguishable from a decoder that did not run, which
    // is the ambiguity this whole file exists to avoid.
    //
    // "Not TLS" is only claimed when NEITHER direction begins with a record AND
    // neither holds a contiguous run of them. One direction holding a chain is
    // positive evidence of TLS, and it outranks the other direction's silence:
    // this is a connection, and half of it demonstrably is encrypted.
    const bool anyTls = a.looksLikeTls || b.looksLikeTls ||
                        a.chainedRecords >= 3 || b.chainedRecords >= 3;
    if (!anyTls && a.havePayload && b.havePayload) {
        out += "tls: neither direction begins with a TLS record, and neither "
               "holds a run of them, so this is not a TLS session in the "
               "captured window.\r\n";
    } else if (anyTls && !a.sawHandshake && !b.sawHandshake) {
        out += "tls: the capture is TLS but no handshake message is among the "
               "captured bytes, so no SNI, version or cipher can be reported - "
               "the window opened after the session was established.\r\n";
    }
    out += a.caveat;
    out += b.caveat;
    // BOTH lines always, including for a direction that captured nothing. The
    // guard that used to be here (`if (havePayload)`) silently dropped exactly
    // the line that accounts for an empty direction - which is the case a reader
    // most needs to see, because "one side of this connection has no bytes" is
    // otherwise indistinguishable from "we only looked one way".
    out += a.line;
    out += b.line;
    return out;
}

CommandResult CmdCapture(SnapshotSource& source, const std::wstring& select,
                         const MutateOptions& mo, unsigned secs,
                         const CaptureOptions& co) {
    if (select.empty()) {
        CommandResult r;
        r.exitCode = kExitArgs;
        r.err = "capture: --select <filter> is required.\r\n";
        return r;
    }
    // --filter is an extra pktmon address pin, so it must be a bare IP.
    // Cheap format check BEFORE the snapshot, so a typo is rc 2 on any box and
    // not rc 1 "no live row" hiding behind a dead selector.
    if (!co.filter.empty()) {
        IN_ADDR a4 = {};
        IN6_ADDR a6 = {};
        if (::InetPtonW(AF_INET, co.filter.c_str(), &a4) != 1 &&
            ::InetPtonW(AF_INET6, co.filter.c_str(), &a6) != 1) {
            CommandResult r;
            r.exitCode = kExitArgs;
            r.err = "capture: --filter '" + WideToUtf8(co.filter) +
                    "' is not an IPv4 or IPv6 address.\r\n";
            return r;
        }
    }
    ConnectionStore store;
    std::wstring err;
    if (!BuildStoreSnapshot(source, store, /*procStats=*/false,
                            /*resolveDns=*/false, /*geoIp=*/false, nullptr,
                            &err)) {
        CommandResult r;
        r.exitCode = kExitFail;
        r.err = "Enumeration failed: " + WideToUtf8(err) + "\r\n";
        return r;
    }
    size_t idx = 0;
    std::string selErr;
    if (!SelectSingleLiveIndex(store, select, "capture", &idx, &selErr)) {
        CommandResult r;
        r.exitCode = kExitFail;
        r.err = selErr;
        return r;
    }
    const Connection& c = store.Rows()[idx];
    // The direction selector is validated BEFORE any capture work, so a typo
    // costs a parse error rather than fifteen seconds of pktmon. Refused
    // explicitly rather than quietly defaulted to "both": a reader who asked for
    // one direction and got two would have no way to notice the mistake.
    CaptureDir dir = CaptureDir::kBoth;
    if (!ParseCaptureDir(co.dir, &dir)) {
        CommandResult r;
        r.exitCode = kExitArgs;
        r.err = "capture: --dir " + WideToUtf8(co.dir) +
                " is not a direction. Use both, first (a) or second (b).\r\n";
        return r;
    }
    // --bin writes raw bytes and has nowhere to go but --out, and concatenating
    // hex framing onto binary output would be a silent corruption. Checked here
    // (after dir resolution, before any target work) so the parser and the verb
    // agree on what a valid --bin invocation looks like.
    if (co.bin) {
        if (co.text) {
            CommandResult r;
            r.exitCode = kExitArgs;
            r.err = "capture: --bin and --text are mutually exclusive.\r\n";
            return r;
        }
        if (co.outPath.empty()) {
            CommandResult r;
            r.exitCode = kExitArgs;
            r.err = "capture: --bin writes binary bytes, so it needs --out FILE.\r\n";
            return r;
        }
    }
    // One builder for both front ends (see StreamCapture.h): binary fields,
    // never the display strings that carry the port.
    const CaptureTarget t = MakeCaptureTarget(c);
    // R4, and it belongs BEFORE --dry-run for the same reason the --yes gate
    // does: a dry run that hides the fact the destination is occupied is not a
    // dry run of this command. The pcapng write is CREATE_ALWAYS, so without
    // this an existing capture file is destroyed with no warning.
    if (!co.outPath.empty()) {
        std::wstring existsErr;
        if (RefuseExistingOutput(L"capture", co.outPath, co.forceOverwrite,
                                 &existsErr)) {
            CommandResult r;
            r.exitCode = kExitArgs;
            r.err = WideToUtf8(existsErr);
            return r;
        }
    }
    // The plan (and the --yes gate) come before the elevation gate: a
    // dry run must never demand elevation, and refusing must not either.
    // Order: resolve -> dry-run -> confirm -> availability -> start.
    std::string plan = "capture " + WideToUtf8(c.display.localEndpoint) +
                       " -> " + WideToUtf8(c.display.remoteEndpoint) +
                       " for " + std::to_string(secs) + "s\r\n";
    // Say what the run WILL do, in the plan, before it does it. Without this a
    // --text run's own framing lines arrive looking like payload, and a reader
    // piping it somewhere would capture them too.
    if (co.text) plan += "mode: print the reassembled stream to stdout\r\n";
    if (co.bin) plan += "mode: write the raw reassembled stream to " +
                        WideToUtf8(co.outPath) + " (binary, not hex)\r\n";
    if (!co.outPath.empty())
        plan += "saving the capture to " + WideToUtf8(co.outPath) + "\r\n";
    if (co.eventFlags != kCaptureFlagsDefault)
        plan += "pktmon flags: capture events SYN/FIN/RST mask "
                + std::to_string(co.eventFlags) + "\r\n";
    if (!co.filter.empty())
        plan += "pktmon address filter: -i " + WideToUtf8(co.filter) +
                " (extra address pin)\r\n";
    if (mo.dryRun) {
        CommandResult r;
        r.out = plan;
        return r;
    }
    if (!mo.yes) return Refused("capture (starts pktmon, needs elevation)");
    std::wstring why2;
    if (!CaptureAvailable(&why2)) {
        CommandResult r;
        r.exitCode = kExitFail;
        if (why2.empty())
            why2 = L"this run is not elevated (an elevated run would work)";
        r.err = "capture unavailable: " + WideToUtf8(why2) + ".\r\n";
        return r;
    }
    std::wstring serr;
    if (!StartCapture(t, co.eventFlags, co.filter, &serr)) {
        CommandResult r;
        r.exitCode = kExitFail;
        r.err = "capture start failed: " + WideToUtf8(serr) + "\r\n";
        return r;
    }
    // Belt and braces with the parser (which enforces the same range): a
    // future in-process caller must get the same clamp the CLI promises.
    if (secs < kCaptureSecsMin) secs = kCaptureSecsMin;
    if (secs > kCaptureSecsMax) secs = kCaptureSecsMax;
    ::Sleep(secs * 1000u);   // bounded capture window
    // --out: hand the destination to StopCapture, which writes the capture
    // while the converted file is still on disk. Passing the path (not the
    // bytes) is deliberate - see StopCapture's header for the memory reason.
    const CaptureResult cr =
        StopCapture(t, co.outPath.empty() ? nullptr : &co.outPath);
    ClearCaptureFilter();
    CommandResult r;
    if (!cr.ok) {
        r.exitCode = kExitFail;
        r.err = "capture failed: " + WideToUtf8(cr.error) + "\r\n";
        return r;
    }
    char buf[kCaptureLineChars] = {0};
    ::sprintf_s(buf, "packets=%llu toServer=%llu toClient=%llu blocks=%llu\r\n",
                static_cast<unsigned long long>(cr.packetsParsed),
                static_cast<unsigned long long>(cr.toServer.bytes.size()),
                static_cast<unsigned long long>(cr.toClient.bytes.size()),
                static_cast<unsigned long long>(cr.blocksSeen));
    r.out = plan + buf;
    // A direction that hit the in-memory reassembly cap reports the CAP, not a
    // measurement, and that figure is indistinguishable from a real one on the
    // line above. ReasmResult::truncated exists for exactly this and the hex
    // view already honours it; printing the number without saying so would let
    // a reader treat 33554432 as "this stream carried 32 MB" when the truth is
    // "at least 32 MB, and we stopped looking". So name the direction that
    // stopped, without the limit itself - the cap is an implementation detail
    // that may move, and a stale number here would be a second thing to keep
    // true.
    if (cr.toServer.truncated || cr.toClient.truncated) {
        std::string capped;
        if (cr.toServer.truncated && cr.toClient.truncated)
            capped = "toServer and toClient";
        else if (cr.toServer.truncated)
            capped = "toServer";
        else
            capped = "toClient";
        r.out += "note: " + capped +
                 " reached the reassembly cap, so that byte count is truncated "
                 "- a floor, not a total.\r\n";
    }
    // The TLS handshake, decoded out of the bytes we just reassembled.
    //
    // This is the ONLY place in the product that can report a TLS session, and
    // it can only do it for a connection the user chose to capture. That limit
    // is not an omission: Windows has no socket-level TLS ioctl - there is no
    // SIO_TLS_INFO anywhere in the SDK, and TCP_INFO_v0, which is what a
    // separate process CAN read off a duplicated socket, carries no TLS field
    // (see Connection.h for the whole argument). The handshake is visible here
    // precisely because TLS sends it in the clear before the session exists.
    //
    // Both directions are reported, because they carry different facts and
    // reporting one alone is how a reader concludes "no SNI" when the capture
    // simply never saw the direction that carries it. Directions are named by
    // ENDPOINT for the reason given at the --text block below.
    r.out += TlsCaptureLines(cr.toServer, cr.toClient, cr.dir1Label, cr.dir2Label);
    // --text. This is the CLI replacement for the GUI's Follow TCP stream.
    //
    // Each direction is introduced by the ENDPOINT that sent it, not by
    // "client"/"server": pktmon does not reliably report which end sent the SYN,
    // so those words would be an assertion the capture cannot support (see
    // ReasmResult's naming note). dir1Label/dir2Label come from the same
    // canonicalisation ReassembleStream used, so the label cannot disagree with
    // which half of the bytes this is.
    if (co.text) {
        const auto emit = [&r](const wchar_t* heading, const std::wstring& label,
                               const ReasmResult& dir) {
            r.out += "\r\n--- ";
            r.out += WideToUtf8(heading);
            r.out += ": ";
            r.out += label.empty() ? std::string("(unknown endpoint)")
                                   : WideToUtf8(label);
            r.out += " ---\r\n";
            // The honesty notes come BEFORE the bytes, not after, so a reader
            // who stops reading at the first block has still been told the
            // stream is incomplete.
            if (dir.bytes.empty()) {
                r.out += "(no payload captured in this direction)\r\n";
                return;
            }
            if (dir.hasGap || dir.bytesMissing != 0) {
                r.out += "NOTE: " + std::to_string(dir.bytesMissing) +
                         " byte(s) were never observed; the stream has a hole "
                         "at offset " + std::to_string(dir.firstSeq) +
                         " and every decode after it is unreliable.\r\n";
            }
            if (dir.truncated) {
                r.out +=
                    "NOTE: this direction hit the reassembly cap, so what "
                    "follows is a prefix, not the whole stream.\r\n";
            }
            r.out += FormatStreamHex(dir.bytes);
        };
        if (dir == CaptureDir::kBoth || dir == CaptureDir::kFirst)
            emit(L"to first endpoint", cr.dir1Label, cr.toServer);
        if (dir == CaptureDir::kBoth || dir == CaptureDir::kSecond)
            emit(L"from first endpoint", cr.dir2Label, cr.toClient);
    }
    if (co.bin) {
        // Raw stream bytes, no hex/pcapng framing. kBoth concatenates dir1 then
        // dir2 with no separator; kFirst -> toServer; kSecond -> toClient.
        std::string blob;
        if (dir == CaptureDir::kBoth || dir == CaptureDir::kFirst)
            blob.append(cr.toServer.bytes);
        if (dir == CaptureDir::kBoth || dir == CaptureDir::kSecond)
            blob.append(cr.toClient.bytes);
        HANDLE h = CreateFileW(co.outPath.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            CommandResult r2;
            r2.exitCode = kExitFail;
            r2.err = "capture: cannot open " + WideToUtf8(co.outPath) +
                     " for writing (" + WideToUtf8(FormatSystemError(::GetLastError())) + ").\r\n";
            return r2;
        }
        DWORD written = 0;
        BOOL ok = WriteFile(h, blob.data(), static_cast<DWORD>(blob.size()), &written, nullptr);
        CloseHandle(h);
        if (!ok || written != blob.size()) {
            CommandResult r2;
            r2.exitCode = kExitFail;
            r2.err = "capture: wrote " + std::to_string(written) + " of " +
                     std::to_string(blob.size()) + " bytes to " +
                     WideToUtf8(co.outPath) + ".\r\n";
            return r2;
        }
        r.out += "wrote " + std::to_string(blob.size()) + " raw bytes to " +
                 WideToUtf8(co.outPath) + "\r\n";
    }
    return r;
}

CommandResult CmdStat(SystemStatsSampler& sampler, const std::string& format) {
    // Prime then sample: CPU/network rates need two reads.
    (void)sampler.Sample();
    ::Sleep(kStatSampleGapMs);
    const SystemStats s = sampler.Sample();
    CommandResult r;
    if (format == "json") {
        r.out = SystemStatsToJson(s) + "\r\n";
        return r;
    }
    r.out = FormatSystemStatsLine(s) + "\r\n";
    return r;
}

int ColumnIdForName(const std::wstring& name) {
    const std::wstring n = ToLowerW(name);
    if (n == L"proto") return COL_PROTO;
    if (n == L"local") return COL_LOCAL;
    if (n == L"lport") return COL_LPORT;
    if (n == L"remote") return COL_REMOTE;
    if (n == L"rport") return COL_RPORT;
    if (n == L"state") return COL_STATE;
    if (n == L"pid") return COL_PID;
    if (n == L"process") return COL_PROCESS;
    if (n == L"service") return COL_SERVICE;
    if (n == L"host") return COL_HOST;
    if (n == L"path") return COL_PATH;
    if (n == L"traffic") return COL_TRAFFIC;
    if (n == L"rx") return COL_RX;
    if (n == L"tx") return COL_TX;
    if (n == L"nettotal" || n == L"net") return COL_NETTOTAL;
    if (n == L"cpu") return COL_CPU;
    if (n == L"mem" || n == L"memory") return COL_MEM;
    if (n == L"disk") return COL_DISK;
    if (n == L"duration") return COL_DURATION;
    if (n == L"bandwidth" || n == L"speed") return COL_BANDWIDTH;
    // "procspeed" is the canonical name; "groupspeed" is accepted because
    // that is what it reads as in a --group view, and refusing a name someone
    // can reasonably guess is the kind of friction it exists to remove.
    if (n == L"procspeed" || n == L"groupspeed") return COL_GROUPRATE;
    if (n == L"note" || n == L"notes") return COL_NOTE;
    // the `ss -i` names. "rtt"/"latency" both accepted - "rtt" is jargon
    // and "latency" is the plainer word a person may reach for first.
    if (n == L"rtt" || n == L"latency") return COL_RTT;
    if (n == L"minrtt" || n == L"min-rtt") return COL_MINRTT;
    if (n == L"cwnd" || n == L"window") return COL_CWND;
    if (n == L"retrans" || n == L"retransmits") return COL_RETRANS;
    if (n == L"tls") return COL_TLS;
    if (n == L"country") return COL_COUNTRY;
    if (n == L"pinned" || n == L"bookmark") return COL_PINNED;
    // Several spellings each, on the same principle as
    // procspeed/rtt above: refusing a name someone can reasonably guess is the
    // friction it exists to remove. "parent" is accepted for the column whose
    // header is "Parent", and "signed" for the one whose header is "Signature",
    // because those are the words the two things are actually called.
    if (n == L"ppid" || n == L"parent" || n == L"parentpid") return COL_PPID;
    if (n == L"integrity" || n == L"il" || n == L"integritylevel")
        return COL_INTEGRITY;
    if (n == L"signature" || n == L"signed" || n == L"sig") return COL_SIGNATURE;
    return -1;
}

bool ResolveColumnSpec(const std::wstring& spec, std::vector<int>& out) {
    const std::wstring n = ToLowerW(spec);
    auto setTo = [&](const ColumnSet& s) {
        out.assign(s.columns, s.columns + s.count);
        return true;
    };
    if (n == L"default") return setTo(kColumnSetDefault);
    if (n == L"minimal") return setTo(kColumnSetMinimal);
    if (n == L"full" || n == L"wide") return setTo(kColumnSetFull);
    std::vector<int> cols;
    size_t i = 0;
    while (i < spec.size()) {
        size_t j = spec.find(L',', i);
        if (j == std::wstring::npos) j = spec.size();
        std::wstring part = spec.substr(i, j - i);
        size_t a = 0;
        while (a < part.size() && part[a] == L' ') ++a;
        size_t b = part.size();
        while (b > a && part[b - 1] == L' ') --b;
        const int id = ColumnIdForName(part.substr(a, b > a ? b - a : 0));
        if (id >= 0) cols.push_back(id);
        i = j + 1;
    }
    if (cols.empty()) return false;
    out = cols;
    return true;
}

std::string ViewStateToJson(const ViewState& v) {    std::string out = "{\"filter\":\"" + JsonEscapeA(v.filter) +
                      "\",\"sortColumn\":" + std::to_string(v.sortColumn) +
                      ",\"sortAsc\":" + (v.sortAsc ? "true" : "false") +
                      ",\"grouped\":" + (v.grouped ? "true" : "false") +
                      ",\"colVisible\":" + std::to_string(v.colVisible) +
                      ",\"sources\":" + std::to_string(v.sources) + "}";
    return out;
}

bool ViewStateFromPreset(const PresetView& v, ViewState* out) {
    if (out == nullptr) return false;
    *out = v;
    return true;
}

std::string FormatSystemStatsLine(const SystemStats& s) {
    std::string line = "CPU ";
    char buf[kStatFieldChars] = {0};
    if (s.cpuKnown)
        ::sprintf_s(buf, "%.1f%%", s.cpuPct);
    else
        ::sprintf_s(buf, "--");
    line += buf;
    line += "  MEM ";
    if (s.memKnown) {
        char mb[kStatFieldChars] = {0};
        ::sprintf_s(mb, "%.1f%%", s.memPct);
        line += WideToUtf8(FormatBytes(s.memUsed)) + "/" +
                WideToUtf8(FormatBytes(s.memTotal)) + " (" + mb + ")";
    } else {
        line += "--";
    }
    line += "  DISK ";
    if (s.diskKnown) {
        line += WideToUtf8(FormatBytes(static_cast<ULONGLONG>(s.diskReadBps))) +
                "/s+" +
                WideToUtf8(FormatBytes(static_cast<ULONGLONG>(s.diskWriteBps))) +
                "/s";
    } else {
        line += "n/a";
    }
    line += "  NET ";
    if (s.netKnown) {
        line += WideToUtf8(FormatBytes(static_cast<ULONGLONG>(s.netRecvBps))) +
                "/s+" +
                WideToUtf8(FormatBytes(static_cast<ULONGLONG>(s.netSendBps))) +
                "/s";
    } else {
        line += "collecting";
    }
    return line;
}

std::string SystemStatsToJson(const SystemStats& s) {
    char buf[kStatJsonChars] = {0};
    ::sprintf_s(buf,
                "{\"cpu\":%.1f,\"cpuKnown\":%s,\"memUsed\":%llu,\"memTotal\":"
                "%llu,\"memPct\":%.1f,\"memKnown\":%s,\"diskReadBps\":%.0f,"
                "\"diskWriteBps\":%.0f,\"diskKnown\":%s,\"netRecvBps\":%.0f,"
                "\"netSendBps\":%.0f,\"netKnown\":%s}",
                s.cpuPct, s.cpuKnown ? "true" : "false",
                static_cast<unsigned long long>(s.memUsed),
                static_cast<unsigned long long>(s.memTotal), s.memPct,
                s.memKnown ? "true" : "false", s.diskReadBps, s.diskWriteBps,
                s.diskKnown ? "true" : "false", s.netRecvBps, s.netSendBps,
                s.netKnown ? "true" : "false");
    return buf;
}

bool CliScanThreadMayBeLive() {
    // Ask only if a scan was ever started. Constructing the sampler here to
    // answer the question would probe SIO_TCP_INFO support and read the system
    // handle table during teardown, on every verb including `version`.
    SocketTrafficSampler* s = TrafficSamplerSlot().load(std::memory_order_acquire);
    if (s == nullptr) return false;
    // A scan that is merely still finishing is given its budget to do so; only
    // one the kernel is holding past that leaves something running.
    return !s->ShutdownScanForExit();
}

}  // namespace wintcp
