// ConnectionStore.cpp
// SPDX-License-Identifier: Apache-2.0
// Model implementation: diffing, filtering (expressions), sorting, text.

#include "ConnectionStore.h"

#include <tcpmib.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <cwctype>
#include <unordered_map>

#include "TcpTable.h"
#include "Utils.h"
#include "DnsResolver.h"
#include "GeoIp.h"   // IsPrivateAddrV4/V6   // kPendingHost sentinel for COL_HOST cell rendering
#include "Opt.h"
// the column cells below need the integrity and signature
// LABELS, and those are defined next to the enums they describe rather than in
// a presentation header - so the labels and the states cannot drift apart.
#include "ProcessInfo.h"

namespace wintcp {
namespace {

// Time units and the cell capacities derived from them. kMsPerSecondU is the
// unsigned twin of kMsPerSecond: the RTT formatter divides unsigned values, and
// mixing an unsigned dividend with a signed divisor is a narrowing that /W4
// would reject - so both exist and the pair is named rather than one being
// retyped at each site.
constexpr unsigned kMsPerSecondU = 1000;
constexpr unsigned kMsPerMinute = 60000;
// The RTT cell shows one decimal below a minute, so the divisor is a tenth of a
// second. Named because it is a TRUNCATION divisor (see FormatRttMs): rounding
// here would let the cell report more time than was measured.
constexpr unsigned kRttDecimalDivisor = kMsPerSecondU / 10;
// A formatted RTT: "1234", "12.3", or "1234" - at most 4 digits plus a decimal
// and a sign, so this is generous. Sized here rather than at the call site so
// the three formatters cannot disagree about the widest case.
constexpr size_t kRttCellChars = 32;

// A filter threshold over a percentage is stored as tenths of a percent, so the
// comparison is an integer one: `cpu:12.5` has to match a row reading 12.5
// exactly, and comparing the two as doubles would make the answer depend on how
// each side had been parsed. Both sites scale by this, so the two cannot
// disagree about the precision a threshold is expressed to.
constexpr double kPercentTenthsScale = 10.0;

// Duration suffix multipliers, in seconds - the unit a `duration:` value is
// stored in, so a bare number and an `s` suffix are the same multiplier. Same
// reason the millisecond ladder above is named: these appear in a filter
// grammar the user types, so a wrong one silently matches the wrong time
// window rather than failing.
constexpr long long kSecPerMinute = 60;
constexpr long long kSecPerHour = 3600;
constexpr long long kSecPerDay = 86400;

// Width of ConnectionStore::Stats::byState, i.e. one histogram slot per
// MIB_TCP_STATE_* value. This bounds `r.identity.state` DIRECTLY, not a StateRank()
// result - those are a different numbering (StateRank maps "none" and any
// unrecognised state onto 12 and 13, so the highest rank is this width, not
// one below it). The array is `byState[13]` in ConnectionStore.h and the
// accessor below it uses the same fixed 13; the four must agree.
constexpr DWORD kByStateEntries = 13;

// Bytes in an address field of a ConnectionKey's packed form. Same name as the
// copies in TcpReasm.cpp, TcpTable.cpp, StreamCapture.cpp and BlockConn.cpp on
// purpose, so a grep finds every place an address width is assumed - the key
// layout static_assert below and the two pushes that fill it must agree.
constexpr size_t kIpv6AddrBytes = 16;

// Cell capacities for the column text formatters. Each one is the widest value
// its format can hold plus fixed wording, with slack, and every swprintf_s in
// this file truncates rather than overruns.
constexpr size_t kPidTextChars = 16;
constexpr size_t kCipherTextChars = 16;
// A port rendered as a decimal string. At most five digits, so this is slack,
// and the two bookmark-join sites below must agree on it or the join key
// changes shape between the two halves of the same lookup.
constexpr size_t kPortTextChars = 16;
constexpr size_t kTmpTextChars = 24;
constexpr size_t kCellTextChars = 64;

// ---- small helpers ---------------------------------------------------------

// 'haystack' must already be lowercase; 'needle' too (FilterClause::text).
bool Has(const std::wstring& haystack, const std::wstring& needle) {
    return needle.empty() || haystack.find(needle) != std::wstring::npos;
}

// Rebuild the aggregated lowercase key from the per-field keys. Shared by
// FinalizeRow and SetHostname so the two can never drift apart.
//
// The body is wintcp::BuildLowerAllOpt (Opt.cpp), which totals the ten field
// sizes, reserves once and appends - the original's +-chain built nine
// intermediate wstrings per row, and a row is finalized on every refresh.
// The fields are passed as POINTERS so the call does not copy them first.
//
// A/B bench, same source: 4.95x on a 10-field row (269 ns -> 54 ns).
// The shorter-than-10 and longer-than-10 counts are pinned by the bench
// tests, which also check the all-empty case yields the nine separators.
void RebuildLowerAll(Connection& c) {
    const std::wstring* const fields[] = {
        &c.keys.lowerLocal,  &c.keys.lowerRemote, &c.keys.lowerState, &c.keys.pidText,
        &c.keys.lowerProcess, &c.keys.lowerPath,   &c.keys.lowerService, &c.keys.lowerHost,
        &c.keys.lowerProto,  &c.keys.lowerParent,
    };
    c.keys.lowerAll = BuildLowerAllOpt(fields, 10);
}

bool StartsWithCi(const std::wstring& s, const wchar_t* prefix, std::wstring& rest) {
    const size_t n = ::wcslen(prefix);
    // Allow exact matches too: "ipv6:" / "tcp:" with an empty value are
    // valid family/proto-only tokens (caught by --selftest).
    if (s.size() < n) return false;
    if (::_wcsnicmp(s.c_str(), prefix, n) != 0) return false;
    rest = s.substr(n);
    return true;
}

// --- the filter vocabulary ---------------------------------------------------
//
// This table IS the parser, not a parallel copy of it. The previous form was a
// 25-branch if/else chain, and that shape had two consequences, both of which
// bit us:
//
//   1. Nothing could enumerate the accepted spellings, so no test could assert
//      anything about them. That is how `dis.` survived: debris from the 2026
//      identifier-corruption incident in temp/audit_report.md, where a regex
//      pass turned `Disk` into `Dis.` and the repair made that broken spelling
//      WORK instead of deleting it. `list --filter "dis.:1"` returned rows,
//      every gate passed, and no gate COULD fail - nothing asserted that
//      `dis.` should not match.
//   2. Any repair meant editing a 25-way conditional, which is precisely how
//      the debris got re-accepted in the first place.
//
// So: one table, exposed via FilterKeywordTable(), which makes the vocabulary
// inspectable data the selftest can hold to a policy. A second hand-written
// list of the same spellings would have been worse than the if-chain, because it
// could drift - and drift is the failure mode this whole change exists to
// remove.
//
// FilterKeyword itself is declared in ConnectionStore.h, NOT here. Declaring it
// in both places makes it an ambiguous symbol inside this file (C2872), and the
// header copy is the one the selftest sees, so the table must use that type or
// the two would silently be different types.
//
// The hyphen in `min-rtt` is deliberate - `ss -i` spells it that way - which is
// why the selftest policy permits `-` and forbids `.` specifically rather than
// demanding plain alphanumeric.
constexpr FilterKeyword kFilterKeywords[] = {
    {FilterField::Local,    L"local"},
    {FilterField::Remote,   L"remote"},
    {FilterField::LPort,    L"lport"},
    {FilterField::RPort,    L"rport"},
    {FilterField::Port,     L"port"},
    {FilterField::Pid,      L"pid"},
    {FilterField::Process,  L"process"},
    {FilterField::Path,     L"path"},
    {FilterField::State,    L"state"},
    {FilterField::Proto,    L"proto"},
    {FilterField::Host,     L"host"},
    {FilterField::Service,  L"service"},
    {FilterField::Cpu,      L"cpu"},
    {FilterField::Mem,      L"mem"},
    {FilterField::Mem,      L"memory"},
    // `disk` and `io`, and nothing else. `dis.` was accepted here until this
    // table existed; it was corruption debris a botched repair had turned into
    // a working keyword.
    {FilterField::Disk,     L"disk"},
    {FilterField::Disk,     L"io"},
    {FilterField::Rx,       L"rx"},
    {FilterField::Rx,       L"received"},
    {FilterField::Tx,       L"tx"},
    {FilterField::Tx,       L"sent"},
    {FilterField::Net,      L"net"},
    {FilterField::Net,      L"total"},
    {FilterField::Duration, L"duration"},
    {FilterField::Duration, L"age"},
    {FilterField::Speed,    L"speed"},
    {FilterField::Speed,    L"bps"},
    {FilterField::Speed,    L"bandwidth"},
    {FilterField::Tls,      L"tls"},
    {FilterField::Tls,      L"ssl"},
    {FilterField::Country,  L"country"},
    {FilterField::Country,  L"geo"},
    // `asn` is the whole name; the alias is there because "as" and "autonomous"
    // are what people type, and a filter that silently matches nothing is worse
    // than one that accepts a second spelling. No "asn:" - the vocabulary policy
    // rejects a colon, and every other field drops it too.
    {FilterField::Asn,      L"asn"},
    {FilterField::Asn,      L"autonomous-system"},
    // the bookmark note is joined onto the row, so it is a real,
    // searchable field. `note:` previously did not exist as a field name at
    // all, so `note:corp` degraded to a substring search for the literal text
    // "note:corp" and could never match anything.
    {FilterField::Note,     L"note"},
    // `ss -i` field names. `rtt` and `minrtt` are MILLISECONDS, which is
    // what the columns show and what `ss -i` prints - the kernel's RttUs is
    // converted at the sampler boundary, so a filter threshold and the cell
    // beside it are always the same unit.
    //
    // `latency` is accepted as an alias because "rtt" is jargon and a person
    // looking for a slow connection may well reach for the plainer word first.
    {FilterField::Rtt,      L"rtt"},
    {FilterField::Rtt,      L"latency"},
    {FilterField::MinRtt,   L"minrtt"},
    {FilterField::MinRtt,   L"min-rtt"},
    {FilterField::Cwnd,     L"cwnd"},
    {FilterField::Cwnd,     L"window"},
    {FilterField::Retrans,  L"retrans"},
    {FilterField::Retrans,  L"retransmits"},
    // `ppid` is also the column's underlying number, so
    // `ppid:1234` is an exact threshold rather than a substring; `parent` is the
    // image name beside it. `signed` is an alias of `signature` because the
    // question people actually ask is "is it signed", not "what is its
    // signature state" - the same reason `latency` aliases `rtt`.
    {FilterField::Ppid,      L"ppid"},
    {FilterField::Parent,    L"parent"},
    {FilterField::Integrity, L"integrity"},
    {FilterField::Signature, L"signature"},
    {FilterField::Signature, L"signed"},
};

constexpr size_t kFilterKeywordCount =
    sizeof(kFilterKeywords) / sizeof(kFilterKeywords[0]);

bool FieldFromName(const std::wstring& raw, FilterField& out) {
    const std::wstring n = ToLowerW(raw);
    for (size_t i = 0; i < kFilterKeywordCount; ++i) {
        if (n == kFilterKeywords[i].spelling) {
            out = kFilterKeywords[i].field;
            return true;
        }
    }
    return false;
}

// "443" or "1000-2000" -> inclusive range. Returns false if not numeric.
bool ParseNumberRange(const std::wstring& v, long long& lo, long long& hi) {
    const size_t dash = v.find(L'-');
    const std::wstring a = (dash == std::wstring::npos) ? v : v.substr(0, dash);
    const std::wstring b = (dash == std::wstring::npos) ? v : v.substr(dash + 1);
    if (a.empty() || b.empty()) return false;
    for (wchar_t ch : a) if (!::iswdigit(ch)) return false;
    for (wchar_t ch : b) if (!::iswdigit(ch)) return false;
    errno = 0;
    lo = ::wcstoll(a.c_str(), nullptr, 10);
    hi = ::wcstoll(b.c_str(), nullptr, 10);
    if (errno != 0 || lo < 0 || hi < 0 || lo > hi) return false;
    return true;
}

// The live-stat filter fields (cpu / mem / disk / rx / tx / net / speed).
bool IsStatField(FilterField f) {
    return f == FilterField::Cpu || f == FilterField::Mem ||
           f == FilterField::Disk || f == FilterField::Rx ||
           f == FilterField::Tx || f == FilterField::Net ||
           f == FilterField::Speed;
}

// One threshold in a stat field's own unit, not a substring of the printed
// cell. `cpu:12` means "12 % or more", `mem:100` "100 MB or more" - the units
// the documented examples already used - and a bare number is MB (cpu: %).
// An optional K/M/G suffix (a trailing `b` allowed, so 512KB and 512K agree)
// multiplies. False when there is no number: the caller then keeps the old
// text-clause behaviour instead of silently matching nothing.
bool ParseStatValue(const std::wstring& v, bool cpuUnit, long long* out) {
    size_t b = 0, e = v.size();
    while (b < e && ::iswspace(v[b])) ++b;
    while (e > b && ::iswspace(v[e - 1])) --e;
    if (b >= e) return false;

    size_t numEnd = e;
    wchar_t unit = 0;
    const wchar_t last = v[e - 1];
    if (last == L'b' || last == L'B') {
        // "512KB" / "1.5GB": the unit is TWO characters, so both go. "512B"
        // on its own is a plain byte count.
        if (e - b < 2) return false;
        const wchar_t u = v[e - 2];
        if (u == L'k' || u == L'K' || u == L'm' || u == L'M' ||
            u == L'g' || u == L'G') {
            numEnd = e - 2;
            unit = (u == L'k' || u == L'K') ? L'k'
                 : ((u == L'g' || u == L'G') ? L'g' : L'm');
        } else {
            numEnd = e - 1;
            unit = L'b';
        }
    } else if (last == L'k' || last == L'K' || last == L'm' || last == L'M' ||
               last == L'g' || last == L'G') {
        numEnd = e - 1;
        unit = (last == L'k' || last == L'K') ? L'k'
             : ((last == L'g' || last == L'G') ? L'g' : L'm');
    }

    bool digits = false;
    for (size_t i = b; i < numEnd; ++i)
        if (::iswdigit(v[i])) digits = true;
    if (!digits) return false;
    const std::wstring num = v.substr(b, numEnd - b);
    errno = 0;
    wchar_t* end = nullptr;
    const double d = ::wcstod(num.c_str(), &end);
    if (errno != 0 || d < 0.0 || end == nullptr || *end != L'\0') return false;

    if (cpuUnit) {
        *out = static_cast<long long>(d * kPercentTenthsScale + 0.5);   // tenths
        return true;
    }
    long long mult = 1024LL * 1024LL;                     // default: MB
    if (unit == L'b') mult = 1;
    else if (unit == L'k') mult = 1024LL;
    else if (unit == L'g') mult = 1024LL * 1024LL * 1024LL;
    const double bytes = d * static_cast<double>(mult);
    if (bytes > 9.0e18) return false;
    *out = static_cast<long long>(bytes + 0.5);
    return true;
}

// "100" | "100MB" | "1.5-2" | "1MB-2GB". A bare value is a LOWER BOUND ONLY
// (hi = LLONG_MAX). Ports and PIDs deliberately keep the exact-match meaning
// ParseNumberRange has always had, which is why the two do not share a parser.
bool ParseStatRange(const std::wstring& v, bool cpuUnit, long long* lo, long long* hi) {
    const size_t dash = v.find(L'-', 1);
    if (dash == std::wstring::npos) {
        if (!ParseStatValue(v, cpuUnit, lo)) return false;
        *hi = static_cast<long long>(0x7FFFFFFFFFFFFFFFULL);
        return true;
    }
    return ParseStatValue(v.substr(0, dash), cpuUnit, lo) &&
           ParseStatValue(v.substr(dash + 1), cpuUnit, hi) && *lo <= *hi;
}

// A connection AGE, in seconds. Unlike the byte fields - where a bare number is
// MB - a bare number here is SECONDS, and s/m/h/d are honoured so `duration:1h`
// reads the way a person writes it. `duration:` used to be a substring match on
// the PRINTED cell ("6d 6h"), which is why `duration:1h` matched nothing at all:
// the typed text and the displayed text rarely share a shape.
bool ParseDurationValue(const std::wstring& v, long long* out) {
    size_t b = 0, e = v.size();
    while (b < e && ::iswspace(v[b])) ++b;
    while (e > b && ::iswspace(v[e - 1])) --e;
    if (b >= e) return false;

    size_t numEnd = e;
    long long mult = 1;                          // bare = seconds
    const wchar_t last = v[e - 1];
    if (last == L's' || last == L'S')      { numEnd = e - 1; mult = 1; }
    else if (last == L'm' || last == L'M') { numEnd = e - 1; mult = kSecPerMinute; }
    else if (last == L'h' || last == L'H') { numEnd = e - 1; mult = kSecPerHour; }
    else if (last == L'd' || last == L'D') { numEnd = e - 1; mult = kSecPerDay; }

    bool digits = false;
    for (size_t i = b; i < numEnd; ++i)
        if (::iswdigit(v[i])) digits = true;
    if (!digits) return false;                   // "abc" stays a text clause
    const std::wstring num = v.substr(b, numEnd - b);
    errno = 0;
    wchar_t* end = nullptr;
    const double d = ::wcstod(num.c_str(), &end);
    if (errno != 0 || d < 0.0 || end == nullptr || *end != L'\0') return false;
    const double seconds = d * static_cast<double>(mult);
    if (seconds > 9.0e18) return false;
    *out = static_cast<long long>(seconds + 0.5);
    return true;
}

// A bare value is a LOWER BOUND ONLY (hi = LLONG_MAX), li.e the stat fields.
bool ParseDurationRange(const std::wstring& v, long long* lo, long long* hi) {
    const size_t dash = v.find(L'-', 1);
    if (dash == std::wstring::npos) {
        if (!ParseDurationValue(v, lo)) return false;
        *hi = static_cast<long long>(0x7FFFFFFFFFFFFFFFULL);
        return true;
    }
    return ParseDurationValue(v.substr(0, dash), lo) &&
           ParseDurationValue(v.substr(dash + 1), hi) && *lo <= *hi;
}

// Stable identity key of an endpoint: protocol + family + addresses + ports
// + OWNING PID.
//
// WHY THE PID IS PART OF IT. The 4-tuple alone is NOT unique on a real
// machine, and that is not a corner case - it is the normal shape of an mDNS
// endpoint. Measured on this host: `list --filter "lport:5353" --format csv`
// returns 86 rows over only 10 distinct (pid, proto, local) identities, with 62
// rows sharing the identical key UDPv4|0.0.0.0:5353|*|* and 24 sharing
// UDPv6|::|5353|*|*. Every browser process binds its own Socket to port 5353.
//
// When ReplaceSnapshot's previous-row map was keyed without the PID, those 62
// rows collapsed onto ONE map entry (the last write wins), so on every single
// refresh 61 of the 62 previous rows matched nothing and were reported as
// DISAPPEAR ghosts, and the 62 fresh rows were reported as new. Measured
// effect: `list --changes --watch 1 --count 3` emitted 173 DISAPPEAR and 0
// APPEAR events, repeating the same false lines every tick, and the GUI
// re-flashed 62 rows red then 62 green forever. An event feed that can only
// ever say DISAPPEAR is worse than no feed.
//
// Adding the PID and known process creation time prevents a reused PID from
// inheriting a prior process's socket identity. `ReplaceSnapshot` additionally
// matches duplicate keys in order (see PrevKeyIndex), so indistinguishable rows
// keep a stable 1:1 pairing across refreshes instead of collapsing.
//
// The state is deliberately still NOT part of the key: a connection moving
// ESTABLISHED -> TIME_WAIT must stay the SAME row (that is what produces the
// STATE change event), and a closed socket also changes owner PID to 0, which
// is why the PID is matched by pairing rather than by equality on the previous
// snapshot's value alone.
ConnectionKey KeyOf(const Connection& c) {
    static_assert(2 + 16 + 4 + 16 + 4 + 4 + 1 + sizeof(FILETIME) <=
                      ConnectionKey::kMaxBytes,
                  "the widest key (IPv6) must fit ConnectionKey::bytes");

    ConnectionKey k;
    const auto push = [&k](const void* src, size_t n) {
        std::memcpy(k.bytes + k.len, src, n);
        k.len += n;
    };

    // Byte for byte the layout the std::string version wrote, in the same
    // order and the same widths, so every pairing decision ReplaceSnapshot
    // makes is unchanged - only the allocation is gone.
    k.bytes[k.len++] = static_cast<unsigned char>(
        c.identity.family == AF_INET6 ? '6' : '4');
    k.bytes[k.len++] = static_cast<unsigned char>(
        c.identity.protocol == IPPROTO_UDP ? 'U' : 'T');
    if (c.identity.family == AF_INET6) {
        push(&c.identity.local6, kIpv6AddrBytes);
        push(&c.identity.localPort, sizeof(UINT));
        push(&c.identity.remote6, kIpv6AddrBytes);
    } else {
        // Only local4/remote4 are read for IPv4: the v6 fields of an IPv4 row
        // are untouched by the enumerator and may hold stale bytes from a
        // reused Connection, so including them would split one row into two.
        push(&c.identity.local4, 4);
        push(&c.identity.localPort, sizeof(UINT));
        push(&c.identity.remote4, 4);
    }
    push(&c.identity.remotePort, sizeof(UINT));
    push(&c.identity.pid, sizeof(DWORD));
    k.bytes[k.len++] = c.procMeta.processCreateKnown ? 1 : 0;
    if (c.procMeta.processCreateKnown)
        push(&c.procMeta.processCreate, sizeof(FILETIME));
    return k;
}

// Natural TCP state ordering: active first, passive last.
int StateRank(DWORD s) {
    switch (s) {
        case MIB_TCP_STATE_ESTAB:      return 0;
        case MIB_TCP_STATE_SYN_SENT:   return 1;
        case MIB_TCP_STATE_SYN_RCVD:   return 2;
        case MIB_TCP_STATE_FIN_WAIT1:  return 3;
        case MIB_TCP_STATE_FIN_WAIT2:  return 4;
        case MIB_TCP_STATE_TIME_WAIT:  return 5;
        case MIB_TCP_STATE_CLOSE_WAIT: return 6;
        case MIB_TCP_STATE_CLOSING:    return 7;
        case MIB_TCP_STATE_LAST_ACK:   return 8;
        case MIB_TCP_STATE_LISTEN:     return 9;
        case MIB_TCP_STATE_CLOSED:     return 10;
        case MIB_TCP_STATE_DELETE_TCB: return 11;
        case 0:                        return 12;   // none (UDP)
        default:                       return 13;
    }
}

int CmpStr(const std::wstring& a, const std::wstring& b) {
    return a.compare(b);
}

bool IsUnknownProcessName(const std::wstring& name) {
    return name.empty() || name == L"—";
}

int CmpInt(long long a, long long b) {
    return (a < b) ? -1 : ((a > b) ? 1 : 0);
}

int CompareAddress(const ConnectionIdentity& a, const ConnectionIdentity& b,
                   bool local) {
    const int familyCmp = CmpInt(a.family, b.family);
    if (familyCmp != 0) return familyCmp;
    if (a.family == AF_INET) {
        const IN_ADDR& left = local ? a.local4 : a.remote4;
        const IN_ADDR& right = local ? b.local4 : b.remote4;
        const int bytesCmp = std::memcmp(&left, &right, sizeof(IN_ADDR));
        return (bytesCmp < 0) ? -1 : ((bytesCmp > 0) ? 1 : 0);
    }
    if (a.family == AF_INET6) {
        const IN6_ADDR& left = local ? a.local6 : a.remote6;
        const IN6_ADDR& right = local ? b.local6 : b.remote6;
        const int bytesCmp = std::memcmp(&left, &right, sizeof(IN6_ADDR));
        if (bytesCmp != 0) return (bytesCmp < 0) ? -1 : 1;
        const DWORD leftScope = local ? a.localScope : a.remoteScope;
        const DWORD rightScope = local ? b.localScope : b.remoteScope;
        return CmpInt(leftScope, rightScope);
    }
    return 0;
}

int CmpU64(ULONGLONG a, ULONGLONG b) {
    return (a < b) ? -1 : ((a > b) ? 1 : 0);
}

int CmpDbl(double a, double b) {
    return (a < b) ? -1 : ((a > b) ? 1 : 0);
}

// Saturating add for byte totals (a pathological ETW/IO counter pair must
// never wrap the displayed or sorted total back to ~0).
ULONGLONG SatAdd(ULONGLONG a, ULONGLONG b) {
    const ULONGLONG r = a + b;
    return (r < a) ? static_cast<ULONGLONG>(~0ULL) : r;
}

// Display-style lowercase text of a live-stat field, for text filtering
//. Unknown/zero values yield "" so `cpu:12` only matches rows
// that actually have a reading.
std::wstring StatFieldText(const Connection& c, FilterField f) {
    wchar_t buf[kCellTextChars] = {0};
    switch (f) {
        case FilterField::Cpu:
            if (c.procStats.cpuPct < 0.0) return std::wstring();
            ::swprintf_s(buf, L"%.1f %%", c.procStats.cpuPct);
            return ToLowerW(buf);
        case FilterField::Mem:
            return c.procStats.memKnown ? ToLowerW(FormatBytes(c.procStats.memWorkingSet))
                              : std::wstring();
        case FilterField::Disk:
            return c.procStats.ioKnown
                       ? ToLowerW(FormatBytes(
                             SatAdd(c.procStats.diskReadBytes, c.procStats.diskWriteBytes)))
                       : std::wstring();
        case FilterField::Rx:
            return (c.traffic.trafficRx != 0) ? ToLowerW(FormatBytes(c.traffic.trafficRx))
                                      : std::wstring();
        case FilterField::Tx:
            return (c.traffic.trafficTx != 0) ? ToLowerW(FormatBytes(c.traffic.trafficTx))
                                      : std::wstring();
        case FilterField::Net:
            return (SatAdd(c.traffic.trafficRx, c.traffic.trafficTx) != 0)
                       ? ToLowerW(FormatBytes(
                             SatAdd(c.traffic.trafficRx, c.traffic.trafficTx)))
                       : std::wstring();
        default:
            return std::wstring();
    }
}

}  // namespace

// The two exported handles on the keyword table. They sit here, outside the
// anonymous namespace, and return the SAME array FieldFromName reads - so the
// table cannot be extended in one place and forgotten in the other, which is
// the drift risk a hand-maintained mirror list would have introduced.
const FilterKeyword* FilterKeywordTable() { return kFilterKeywords; }

size_t FilterKeywordCount() { return kFilterKeywordCount; }

// ---- exported display helpers ----------------------------------------------
// These are declared in ConnectionStore.h (and exercised by --selftest), so
// they live in namespace wintcp rather than the file-local anonymous
// namespace - otherwise the header declaration and the definition would be
// two different functions and every call site would be ambiguous.

// "1d 4h", "2h 17m", "8m 03s" - a connection's age at a glance. Deltas are
// floored rather than rounded so the display never shows "59s" for 59.7s
// worth of connection and never wraps to "0s" too early.
//
// The four shapes move to wintcp::FormatDurationOpt (Opt.cpp), which renders
// through the same digit table FormatPort uses instead of four separate
// swprintf_s calls with a format string to parse each. A/B bench: 7.75x.
std::wstring FormatDuration(ULONGLONG seconds) {
    wchar_t buf[kRttCellChars] = {0};
    FormatDurationOpt(buf, kRttCellChars, seconds);
    return std::wstring(buf);
}

// Shared by COL_BANDWIDTH (per connection) and COL_GROUPRATE (per process).
// The reason for the extraction is in the header: two rate columns that must
// render identically, in one place so they cannot drift.
std::wstring FormatBpsCell(double rxBps, double txBps, bool known) {
    if (!known) return L"—";
    // Under half a byte per second in both directions is "nothing is moving",
    // and printing "↓ 0 B/s ↑ 0 B/s" for it is noise: the reader's eye goes to
    // a rate and finds a rounding artefact.
    if (rxBps < 0.5 && txBps < 0.5) return L"idle";
    wchar_t buf[kCellTextChars] = {0};
    ::swprintf_s(buf, L"↓ %s/s  ↑ %s/s",
                 FormatBytes(static_cast<ULONGLONG>(rxBps + 0.5)).c_str(),
                 FormatBytes(static_cast<ULONGLONG>(txBps + 0.5)).c_str());
    return buf;
}

// Milliseconds, the way `ss -i` prints an RTT.
//
// Three rules, each of which is a decision rather than a formatting habit:
//
//  * SUB-MILLISECOND PRINTS "<1", NOT "0". A loopback or same-switch RTT is
//    tens of microseconds, and the sampler rounds it to 0 ms. Printing "0" would
//    claim the round trip too. no time at all - a physically impossible reading
//    that a user would reasonably report as a bug. "<1" is what `ss` shows and
//    it is true.
//  * WHOLE MILLISECONDS PRINT WITHOUT A DECIMAL. "12" not "12.000": most
//    RTTs are not fractional, and trailing zeros make the column wide enough to
//    push every other column across the table.
//  * FRACTIONAL VALUES KEEP ONE DECIMAL, THEN TRIM IT. 12.5 is a real reading
//    worth seeing exactly; 12.50 is noise.
std::wstring FormatRttMs(unsigned ms) {
    wchar_t buf[kRttCellChars] = {0};
    if (ms == 0) return L"<1";
    if (ms < kMsPerSecondU) {
        ::swprintf_s(buf, L"%u", ms);
        return buf;
    }
    if (ms < kMsPerMinute) {
        // One decimal place: (ms % 1000) / 100. So 1250 ms prints "1.2" and
        // 1499 ms prints "1.4" - a truncation, not a round-to-nearest. Both are
        // defensible, but a column that shows "1.4" beside a min RTT of "1.5"
        // would be self-evidently wrong, and truncation can never report a value
        // greater than the one measured.
        //
        // A trailing ".0" is then trimmed, so exactly 1000 ms reads "1" rather
        // than "1.0": the decimal exists to show SUB-second detail, and a whole
        // number of seconds has none.
        ::swprintf_s(buf, L"%u.%u", ms / kMsPerSecondU,
                             (ms % kMsPerSecondU) / kRttDecimalDivisor);
        std::wstring s(buf);
        const size_t dot = s.rfind(L'.');
        // Only trim when the '.0' is the whole fractional part. "10.0" -> "10",
        // and a value li.e "1.05" never reaches here (only one decimal is ever
        // produced), so there is no ris. of eating a significant digit.
        if (dot != std::wstring::npos && s.size() == dot + 2 &&
            s[dot + 1] == L'0') {
            s.erase(dot);
        }
        return s;
    }
    ::swprintf_s(buf, L"%llu",
                 static_cast<unsigned long long>(ms / kMsPerSecondU));
    return buf;
}

// Age of a connection in seconds, or 0 when it is unknown. 'nowTick' is
// GetTickCount64; both it and Connection::firstSeenTick are monotonic so
// the subtraction cannot go backwards the way a wall clock would across a
// DST or NTP change. Passing 0 (the default) means "now", so display code
// does not have to thread the current tick through every call site.
ULONGLONG DurationSeconds(const Connection& c, ULONGLONG nowTick) {
    if (nowTick == 0) nowTick = ::GetTickCount64();
    if (c.lifetime.firstSeenTick == 0 || nowTick < c.lifetime.firstSeenTick) return 0;
    return (nowTick - c.lifetime.firstSeenTick) / 1000ULL;
}

// One cell of the TLS column. The most useful fact is the negotiated
// protocol; the SNI and certificate are appended when a capture-based or
// ETW source supplied them, because those are what identify the peer.
std::wstring TlsSummary(const TlsInfo& t) {
    if (!t.known || !t.secure) return L"—";
    std::wstring out = TlsProtocolName(t.protocol);
    if (t.haveSni && !t.sni.empty()) {
        out += L"  " + t.sni;
    } else if (t.cipherSuite != 0) {
        out += L"  " + TlsCipherName(t.cipherSuite);
    }
    return out;
}

// "TLS 1.3" / "TLS 1.2" / "SSL 3.0"; the wire bytes are major<<8 | minor.
std::wstring TlsProtocolName(USHORT v) {
    switch (v) {
        case 0x0300: return L"SSL 3.0";
        case 0x0301: return L"TLS 1.0";
        case 0x0302: return L"TLS 1.1";
        case 0x0303: return L"TLS 1.2";
        case 0x0304: return L"TLS 1.3";
        default:     return L"TLS";
    }
}

// Only the handful an analyst actually sees in a connection viewer; an
// unmapped id is reported numerically rather than guessed, so the column
// never asserts a cipher it does not know.
std::wstring TlsCipherName(USHORT id) {
    switch (id) {
        case 0x1301: return L"TLS_AES_128_GCM_SHA256";
        case 0x1302: return L"TLS_AES_256_GCM_SHA384";
        case 0x1303: return L"TLS_CHACHA20_POLY1305_SHA256";
        case 0xC02B: return L"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
        case 0xC02F: return L"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        case 0xC030: return L"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
        case 0xC034: return L"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
        case 0x009C: return L"TLS_RSA_WITH_AES_128_GCM_SHA256";
        case 0x009D: return L"TLS_RSA_WITH_AES_256_GCM_SHA384";
        case 0xCCA8: return L"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
        default: {
            wchar_t buf[kCipherTextChars] = {0};
            ::swprintf_s(buf, L"0x%04X", id);
            return buf;
        }
    }
}

std::wstring TagLabel(unsigned tag) {
    switch (tag) {
        case kTagRed:   return L"red";
        case kTagAmber: return L"amber";
        case kTagBlue:  return L"blue";
        case kTagGreen: return L"green";
        default:        return L"—";
    }
}

bool ComputeBps(ULONGLONG prevBytes, ULONGLONG nowBytes,
                ULONGLONG elapsedMs, double* bytesPerSecond) {
    // No elapsed time means no rate. This is not a theoretical case: a
    // paused snapshot followed by an immediate manual F5 samples twice
    // inside the same millisecond.
    if (elapsedMs == 0) return false;
    // A counter that went backwards means the Socket was recycled (or the
    // owning PID exited and the row was rebuilt). The unsigned difference
    // would be astronomically large, so report "no reading" for this
    // interval instead of a nonsense spi.e; the next sample is normal.
    if (nowBytes < prevBytes) return false;
    if (bytesPerSecond != nullptr) {
        *bytesPerSecond =
            static_cast<double>(nowBytes - prevBytes) * 1000.0 /
            static_cast<double>(elapsedMs);
    }
    return true;
}

// ---- filter parsing / matching -----------------------------------

bool ParseFilter(const std::wstring& text, std::vector<FilterClause>& out,
                 std::wstring* error) {
    out.clear();
    if (error != nullptr) error->clear();
    const size_t len = text.size();
    size_t i = 0;
    while (i < len) {
        while (i < len && ::iswspace(text[i])) ++i;
        const size_t start = i;
        // A token may be a QUOTED string, and the quotes are part of the token
        // only so the shell and this scanner agree on where it ends.
        //
        // WHY. Space is AND in this grammar, so a value containing a space -
        // a bookmark note ("vendor api"), a path fragment with a space in the
        // directory name, a host suffix - was unreachable: `note:vendor api`
        // parsed as `note:vendor` AND a bare `api`, which is a different
        // question and almost never the one meant. Quoting is the standard
        // answer and costs one branch on the token scanner. The quotes are
        // stripped from the value, so `note:"vendor api"` and
        // `path:"program files"` mean what they look like.
        std::wstring t;
        if (i < len && (text[i] == L'"' || text[i] == L'\'')) {
            const wchar_t quote = text[i];
            ++i;
            while (i < len && text[i] != quote) t.push_back(text[i++]);
            if (i == len) {
                out.clear();
                FilterClause literal;
                literal.text = ToLowerW(text);
                out.push_back(std::move(literal));
                if (error != nullptr) *error = L"Unclosed quote";
                return false;
            }
            ++i;
        } else {
            // A quoted PART of a token: `note:"vendor api"` keeps its field
            // prefix and quotes only the value. Handling only the "token starts
            // with a quote" case made every `field:"..."` split at the space,
            // which is precisely the form a user writes for a note or a path
            // with a space in it - the case quoting was added for.
            while (i < len && !::iswspace(text[i])) {
                if (text[i] == L'"' || text[i] == L'\'') {
                    const wchar_t quote = text[i++];
                    while (i < len && text[i] != quote) t.push_back(text[i++]);
                    if (i == len) {
                        out.clear();
                        FilterClause literal;
                        literal.text = ToLowerW(text);
                        out.push_back(std::move(literal));
                        if (error != nullptr) *error = L"Unclosed quote";
                        return false;
                    }
                    ++i;
                    continue;
                }
                t.push_back(text[i++]);
            }
        }
        if (start == i) continue;

        FilterClause cl;
        std::wstring rest;
        if (StartsWithCi(t, L"exclude:", rest)) { cl.exclude = true; t = rest; }
        // Direction is stripped first and consumed on its own: it selects
        // the endpoint, it is not itself a field. Stripping it as a field
        // (the old code) made local:port:80 collapse into
        // {field=Local, text="port:80"}, which never matches.
        if (StartsWithCi(t, L"local:", rest))       { cl.direction = -1; t = rest; }
        else if (StartsWithCi(t, L"remote:", rest)) { cl.direction = +1; t = rest; }
        if (StartsWithCi(t, L"tcp:", rest))          { cl.proto = IPPROTO_TCP; t = rest; }
        else if (StartsWithCi(t, L"udp:", rest))     { cl.proto = IPPROTO_UDP; t = rest; }
        else if (StartsWithCi(t, L"ipv4:", rest))    { cl.family = 4; t = rest; }
        else if (StartsWithCi(t, L"ipv6:", rest))    { cl.family = 6; t = rest; }

        if (cl.field == FilterField::Any) {
            const size_t colon = t.find(L':');
            if (colon != std::wstring::npos && colon > 0) {
                FilterField f;
                if (FieldFromName(t.substr(0, colon), f)) {
                    cl.field = f;
                    t = t.substr(colon + 1);
                }
            }
        }

        const std::wstring value = t;
        const bool numericWanted =
            (cl.field == FilterField::Pid || cl.field == FilterField::Port ||
             cl.field == FilterField::LPort || cl.field == FilterField::RPort) ||
            (cl.proto != 0 && cl.field == FilterField::Any);
        long long lo = 0, hi = 0;
        if (!value.empty() && numericWanted && ParseNumberRange(value, lo, hi)) {
            cl.numeric = true;
            cl.lo = lo;
            cl.hi = hi;
        } else if (!value.empty() && IsStatField(cl.field) &&
                   ParseStatRange(value, cl.field == FilterField::Cpu, &lo, &hi)) {
            // Live stats compare as numbers: `mem:100` is "100 MB or more"
            // (bare = MB, K/M/G suffix allowed, `mem:100-500` a range) and
            // `cpu:12` is "12 % or more". A non-numeric value falls through to
            // the text clause below, exactly as an unknown port value does.
            cl.numeric = true;
            cl.lo = lo;
            cl.hi = hi;
        } else if (cl.field == FilterField::Asn && !value.empty() &&
                   ParseNumberRange(value, lo, hi)) {
            // A bare number is the AS NUMBER as a threshold, so `asn:15169`
            // and the range `asn:15169-20000` behave like every other numeric
            // field. Anything else falls through to the text clause below and
            // matches the "AS<n> <org>" cell as a substring, which is what makes
            // `asn:cloudflare` find the operator by name.
            //
            // ParseNumberRange and not ParseStatRange: an ASN has no K/M/G
            // suffixes, and accepting `asn:15169K` as a byte count would be a
            // joke.
            cl.numeric = true;
            cl.lo = lo;
            cl.hi = hi;
        } else if (cl.field == FilterField::Duration && !value.empty() &&
                   ParseDurationRange(value, &lo, &hi)) {
            // `duration:` is a threshold in SECONDS, not a substring of the
            // printed cell: `duration:1h` means "at least an hour old" and
            // `duration:1h-2d` is a range. A non-numeric value falls through to
            // the text clause below, exactly as `mem:abc` does.
            cl.numeric = true;
            cl.lo = lo;
            cl.hi = hi;
        } else if ((cl.field == FilterField::Rtt ||
                    cl.field == FilterField::MinRtt ||
                    cl.field == FilterField::Cwnd ||
                    cl.field == FilterField::Retrans) && !value.empty() &&
                   (ParseNumberRange(value, lo, hi) ||
                    ((cl.field == FilterField::Cwnd ||
                      cl.field == FilterField::Retrans) &&
                     ParseStatRange(value, false, &lo, &hi)))) {
            // A threshold in the units the column shows - ms for the RTTs,
            // bytes for cwnd and retransmits. `rtt:100` is "100 ms or worse".
            // The two time fields are deliberately NOT routed through
            // ParseStatRange: that would make `rtt:1M` mean 1 megabyte of
            // latency, which is a joke waiting to happen.
            //
            // The parse is part of the branch CONDITION on purpose. It used to
            // be an `if` inside the body, so a value the number parser rejected
            // - `retrans:1KB`, whose suffix is not a digit - left BOTH
            // cl.numeric false and cl.text unset. That empty text then reached
            // HasLowerSubstring, which returns true for an empty needle, so a
            // threshold silently degraded into "matches every row that has a
            // reading" - exactly the outcome `help list` promises never
            // happens. An unparsable value now falls through to the text clause
            // at the end of this chain, the way the stat and duration branches
            // already did.
            //
            // The two byte fields also accept the documented KB/MB/GB/B
            // suffixes, via ParseStatRange. A plain integer still takes the
            // first path, so `retrans:1024` and `cwnd:65536` keep the byte
            // meaning `help list` gives them.
            //
            // A BARE value is "at least this much", with NO upper bound - the
            // same rule `duration:1h` and `mem:100` follow. lo == hi would mean
            // `rtt:20` matches only a connection whose RTT is exactly 20 ms,
            // which is not a threshold at all and is the sort of thing that
            // ships because "it parsed" was taken for "it works". Measured:
            // `rtt:20` returned 0 rows against a row reading 24.
            cl.numeric = true;
            cl.lo = lo;
            cl.hi = (value.find(L'-') == std::wstring::npos)
                        ? LLONG_MAX
                        : hi;
        } else if (cl.field == FilterField::Proto && !value.empty()) {
            const std::wstring v = ToLowerW(value);
            if      (v == L"tcp")  cl.proto = IPPROTO_TCP;
            else if (v == L"udp")  cl.proto = IPPROTO_UDP;
            else if (v == L"4" || v == L"ipv4") cl.family = 4;
            else if (v == L"6" || v == L"ipv6") cl.family = 6;
            else cl.text = v;    // fall back to substring on the proto label
        } else if (value.empty() && cl.proto == 0 && cl.family == 0 &&
                   cl.field == FilterField::Any) {
            continue;            // bare "exclude:" etc. - no-op token
        } else {
            // A NAMED field with an empty value is a real clause, not a no-op:
            // `note:` means "has a note", `path:` means "has a path". It used
            // to be dropped with the bare-prefix tokens above, so the useful
            // "show me everything I annotated" query silently became a no-op
            // and matched every row instead. The empty text then falls
            // through to Has(), which matches everything for most fields -
            // which is right for `path:` and `service:` and wrong only for
            // note, handled explicitly in MatchClause.
            cl.text = ToLowerW(value);
            if (cl.field == FilterField::State) {
                // State labels use underscores (TIME_WAIT); users type
                // hyphens (time-wait) just as often. Normalize once here so
                // both spellings match and the hot match path stays a plain
                // substring test.
                for (wchar_t& ch : cl.text) {
                    if (ch == L'-') ch = L'_';
                }
            }
        }
        out.push_back(std::move(cl));
    }
    return true;
}

// Is this endpoint on a non-routable range? One helper for both families,
// so a v6 row is not answered by the v4 predicate - which would call every
// IPv4-mapped address public.
bool AddrIsPrivate(const IN_ADDR& v4, const IN6_ADDR& v6, bool isV6) {
    return isV6 ? IsPrivateAddrV6(reinterpret_cast<const unsigned char*>(&v6))
                : IsPrivateAddrV4(ntohl(v4.S_un.S_addr));
}
bool MatchClause(const Connection& c, const FilterClause& cl) {
    if (cl.proto != 0 && c.identity.protocol != cl.proto) return false;
    if (cl.family != 0) {
        const int f = (c.identity.family == AF_INET6) ? 6 : 4;
        if (f != cl.family) return false;
    }

    // 'field' names the column; 'direction' narrows Port/LPort/RPort to one
    // side of the endpoint. A bare direction with no field keeps the
    // documented meaning "this side's address" ("remote:203").
    FilterField f = cl.field;

    if (cl.numeric) {
        const auto inRange = [&cl](long long v) { return v >= cl.lo && v <= cl.hi; };
        // A direction narrows Port to that side: "local:port:443" must not
        // match a row whose REMOTE port is 443.
        switch (f) {
            case FilterField::Pid:   return inRange(static_cast<long long>(c.identity.pid));
            case FilterField::LPort: return inRange(static_cast<long long>(c.identity.localPort));
            case FilterField::RPort: return inRange(static_cast<long long>(c.identity.remotePort));
            case FilterField::Port:
                if (cl.direction < 0)
                    return inRange(static_cast<long long>(c.identity.localPort));
                if (cl.direction > 0)
                    return inRange(static_cast<long long>(c.identity.remotePort));
                return inRange(static_cast<long long>(c.identity.localPort)) ||
                       inRange(static_cast<long long>(c.identity.remotePort));
            // "tcp:80" with no side: either port may match. A direction
            // narrows it. The live-stat fields (cpu/mem/dis./rx/tx/net) are
            // NOT handled here - they have a unit-aware comparison further
            // down, so fall through to it rather than reject the row. Any
            // OTHER numeric field is not defined: return false rather than
            // falling back to ports, which made "pid:1-2" match any connection
            // using a port in 1..2.
            // A row with no ASN is UNKNOWN, and unknown never matches a
            // threshold. Without this case the clause would fall through to the
            // text path below with an empty needle, and Has() returns true for
            // an empty needle - so `asn:1-4294967295` would select the entire
            // table, every row in it, including the ones with no ASN at all. That
            // reads like "everything has an ASN" and answers the opposite of the
            // question.
            case FilterField::Asn:
                if (c.enrichment.asnNumber == 0) return false;
                return inRange(static_cast<long long>(c.enrichment.asnNumber));
            case FilterField::Any:
                if (cl.direction < 0)
                    return inRange(static_cast<long long>(c.identity.localPort));
                if (cl.direction > 0)
                    return inRange(static_cast<long long>(c.identity.remotePort));
                return inRange(static_cast<long long>(c.identity.localPort)) ||
                       inRange(static_cast<long long>(c.identity.remotePort));
            default: break;   // -> the live-stat block. below
        }
    }

    // Text match against one lowercased key.
    wchar_t tmp[kTmpTextChars] = {0};
    const std::wstring* hay = nullptr;
    switch (f) {
        // `local:private` / `remote:private` and their `global` inverses.
        //
        // They live in the Any case because `local:` and `remote:` are consumed as
        // DIRECTION prefixes before the field is resolved (see the StartsWithCi pair
        // above), so `local:private` arrives here as field=Any with
        // direction=-1 - not as field=Local. Putting the check in the Local case
        // instead compiles, passes every type check, and silently never fires.
        //
        // The predicate is the same one GeoIP uses to refuse a country, declared in
        // GeoIp.h so there is one table of ranges rather than two that could drift.
        case FilterField::Any:
            if ((cl.text == L"private" || cl.text == L"global") &&
                cl.direction != 0) {
                const bool v6 = c.identity.family == AF_INET6;
                const bool priv =
                    cl.direction < 0
                        ? AddrIsPrivate(c.identity.local4, c.identity.local6, v6)
                        : AddrIsPrivate(c.identity.remote4, c.identity.remote6, v6);
                // Folded into the exclude flag rather than returning early, so
                // `!local:private` works from the same code.
                return (priv == (cl.text == L"private")) != cl.exclude;
            }
            if (cl.direction != 0)
                hay = (cl.direction < 0) ? &c.keys.lowerLocal : &c.keys.lowerRemote;
            else
                hay = &c.keys.lowerAll;
            break;
        case FilterField::Local:
            if (cl.text == L"private" || cl.text == L"global") {
                const bool priv = AddrIsPrivate(c.identity.local4, c.identity.local6,
                                                c.identity.family == AF_INET6);
                return (priv == (cl.text == L"private")) != cl.exclude;
            }
            hay = &c.keys.lowerLocal;
            break;
        case FilterField::Remote:
            if (cl.text == L"private" || cl.text == L"global") {
                const bool priv = AddrIsPrivate(c.identity.remote4, c.identity.remote6,
                                                c.identity.family == AF_INET6);
                return (priv == (cl.text == L"private")) != cl.exclude;
            }
            hay = &c.keys.lowerRemote;
            break;
        case FilterField::Process: hay = &c.keys.lowerProcess; break;
        case FilterField::Path:    hay = &c.keys.lowerPath;   break;
        case FilterField::Service: hay = &c.keys.lowerService; break;
        case FilterField::Host:    hay = &c.keys.lowerHost;   break;
        case FilterField::State:   hay = &c.keys.lowerState;  break;
        case FilterField::Proto:   hay = &c.keys.lowerProto;  break;
        case FilterField::Pid:     hay = &c.keys.pidText;     break;
        // `parent` searches the parent's IMAGE NAME. It is in the hay
        // switch rather than a case of its own because, like Process, it is a
        // precomputed lowercase string and needs no formatting.
        case FilterField::Parent:  hay = &c.keys.lowerParent; break;
        // `ppid` is a NUMBER, so it formats on demand exactly like the
        // ports do - including the same reuse of `tmp`, since that buffer is
        // already what this switch formats digits into.
        case FilterField::Ppid:
            if (!c.security.ppidKnown) return false;
            ::swprintf_s(tmp, L"%lu", static_cast<unsigned long>(c.security.ppid));
            return HasLowerSubstring(tmp, cl.text);
        // Ports are formatted digits: they have no case, so match the
        // buffer directly instead of paying for a ToLowerW copy of every
        // row, per clause, on every keystro.e.
        case FilterField::LPort:
            ::swprintf_s(tmp, L"%u", c.identity.localPort);
            return HasLowerSubstring(tmp, cl.text);
        case FilterField::RPort:
            ::swprintf_s(tmp, L"%u", c.identity.remotePort);
            return HasLowerSubstring(tmp, cl.text);
        case FilterField::Port:
            if (cl.text.empty()) return true;
            if (cl.direction < 0) {
                ::swprintf_s(tmp, L"%u", c.identity.localPort);
                return HasLowerSubstring(tmp, cl.text);
            }
            if (cl.direction > 0) {
                ::swprintf_s(tmp, L"%u", c.identity.remotePort);
                return HasLowerSubstring(tmp, cl.text);
            }
            ::swprintf_s(tmp, L"%u", c.identity.localPort);
            if (HasLowerSubstring(tmp, cl.text)) return true;
            ::swprintf_s(tmp, L"%u", c.identity.remotePort);
            return HasLowerSubstring(tmp, cl.text);
        case FilterField::Cpu:
        case FilterField::Mem:
        case FilterField::Disk:
        case FilterField::Rx:
        case FilterField::Tx:
        case FilterField::Net: {
            // Live per-process stats. A numeric clause is a threshold in the
            // field's real unit (cpu: tenths of a %, everything else bytes),
            // not a substring of the printed cell: the old text match only
            // ever satisfied `mem:100` by accident, when "100" happened to be
            // printed inside some other value. An unknown reading matches
            // nothing at all - a protected process must not slip through
            // `mem:0` just because it could not be read.
            if (cl.numeric) {
                switch (f) {
                    case FilterField::Cpu: {
                        if (c.procStats.cpuPct < 0.0) return false;
                        const long long v =
                            static_cast<long long>(c.procStats.cpuPct * kPercentTenthsScale + 0.5);
                        return v >= cl.lo && v <= cl.hi;
                    }
                    case FilterField::Mem:
                        if (!c.procStats.memKnown) return false;
                        return c.procStats.memWorkingSet >= static_cast<ULONGLONG>(cl.lo) &&
                               c.procStats.memWorkingSet <= static_cast<ULONGLONG>(cl.hi);
                    case FilterField::Disk: {
                        if (!c.procStats.ioKnown) return false;
                        const ULONGLONG t = SatAdd(c.procStats.diskReadBytes, c.procStats.diskWriteBytes);
                        return t >= static_cast<ULONGLONG>(cl.lo) &&
                               t <= static_cast<ULONGLONG>(cl.hi);
                    }
                    case FilterField::Rx:
                        return c.traffic.trafficRx >= static_cast<ULONGLONG>(cl.lo) &&
                               c.traffic.trafficRx <= static_cast<ULONGLONG>(cl.hi);
                    case FilterField::Tx:
                        return c.traffic.trafficTx >= static_cast<ULONGLONG>(cl.lo) &&
                               c.traffic.trafficTx <= static_cast<ULONGLONG>(cl.hi);
                    case FilterField::Net: {
                        const ULONGLONG t = SatAdd(c.traffic.trafficRx, c.traffic.trafficTx);
                        return t >= static_cast<ULONGLONG>(cl.lo) &&
                               t <= static_cast<ULONGLONG>(cl.hi);
                    }
                    default:
                        return false;
                }
            }
            // Not numeric (e.g. "mem:abc"): keep the substring behaviour so
            // the box filter never silently changes shape.
            return Has(StatFieldText(c, f), cl.text);
        }
        case FilterField::Duration: {
            // Unknown age matches nothing rather than everything, so
            // "duration:" cannot silently select the rows that lac. a value.
            if (c.lifetime.firstSeenTick == 0) return false;
            if (cl.numeric) {
                const long long secs = static_cast<long long>(
                    DurationSeconds(c));
                return secs >= cl.lo && secs <= cl.hi;
            }
            return HasLowerSubstring(FormatDuration(DurationSeconds(c)),
                                     cl.text);
        }
        case FilterField::Speed: {
            if (!c.rate.bpsKnown) return false;
            const long long bps =
                static_cast<long long>((c.rate.rxBps + c.rate.txBps) + 0.5);
            if (cl.numeric) return bps >= cl.lo && bps <= cl.hi;
            return HasLowerSubstring(FormatBytes(static_cast<ULONGLONG>(bps)),
                                     cl.text);
        }
        case FilterField::Rtt:
        case FilterField::MinRtt:
        case FilterField::Cwnd:
        case FilterField::Retrans: {
            // An UNKNOWN value matches nothing, never everything - the same
            // rule as `duration:` above, and for the same reason: a row the
            // kernel could not measure must not be selected by a query about a
            // measurement. `rtt:` alone therefore means "has an RTT reading",
            // which is a genuinely useful question ("which of these can I even
            // measure?"), rather than a no-op that matches all 300 rows.
            const bool known =
                (cl.field == FilterField::Rtt)     ? c.tcpInfo.rttLive
                : (cl.field == FilterField::MinRtt) ? c.tcpInfo.rttEver
                : (cl.field == FilterField::Cwnd)   ? c.tcpInfo.cwndKnown
                :                                  c.tcpInfo.retransKnown;
            if (!known) return false;
            const long long v =
                (cl.field == FilterField::Rtt)     ? static_cast<long long>(c.tcpInfo.rttMs)
                : (cl.field == FilterField::MinRtt) ? static_cast<long long>(c.tcpInfo.minRttMs)
                : (cl.field == FilterField::Cwnd)   ? static_cast<long long>(c.tcpInfo.cwnd)
                :                                  static_cast<long long>(c.tcpInfo.retransBytes);
            if (cl.numeric) return v >= cl.lo && v <= cl.hi;
            // Text form: match the cell the column would actually print, so a
            // filter and a display can never disagree. "12.5" matches "12.500",
            // and "50" matches a byte count formatted as "50 B".
            const std::wstring cell =
                (cl.field == FilterField::Rtt || cl.field == FilterField::MinRtt)
                    ? FormatRttMs(static_cast<unsigned>(v))
                    : FormatBytes(static_cast<ULONGLONG>(v));
            return HasLowerSubstring(cell, cl.text);
        }
        case FilterField::Tls:
            return Has(ToLowerW(TlsSummary(c.enrichment.tls)), cl.text);
        case FilterField::Country:
            // A bare `country:` means "this row HAS a country" - the useful "show
            // me everything with a known country" query - and is therefore false for
            // a row with none.
            //
            // This is the empty-needle bug, and it was live: Has() returns TRUE for
            // an empty needle, so before this guard a bare `country:` matched every
            // row in the table, including the ones with no country at all. Pinned by
            // geo.enrichment.country-unenriched-matches-bare-BUG in the selftest, which failed
            // until the guard was added. `asn:` never had it.
            if (cl.text.empty()) return !c.enrichment.country.empty();
            return Has(ToLowerW(c.enrichment.country), cl.text);
        case FilterField::Asn: {
            // A bare `asn:` means "this row HAS an autonomous system", and is
            // therefore false for a row with none - an unenriched row, or one
            // whose address the ASN database does not cover.
            //
            // This is handled explicitly rather than left to Has(), which returns
            // TRUE for an empty needle: an empty `cl.text` would then match every
            // row in the table, including the ones with no ASN at all. That is
            // the opposite of the question being asked - the same empty-needle
            // trap `country:` above was pinned by
            // geo.enrichment.country-unenriched-matches-bare-BUG, and `asn:` keeps its own
            // guard so it can never inherit the behaviour.
            const bool has = c.enrichment.asnNumber != 0 || !c.enrichment.asnOrg.empty();
            if (cl.text.empty()) return has;
            if (!has) return false;   // unknown never matches a needle
            return Has(ToLowerW(c.AsnDisplay()), cl.text);
        }
        case FilterField::Note:
            // The joined bookmark note. A bare `note:` means "this row HAS a
            // note" - the useful "show me everything I annotated" query -
            // and is therefore false for an unbookmarked row, whose note is
            // empty. `note:x` matches the rows whose note contains x, which is
            // the whole point of writing one.
            if (cl.text.empty()) return !c.annotations.lowerNote.empty();
            return Has(c.annotations.lowerNote, cl.text);
        // The level is a WORD, so it is matched as the text the column
        // prints - `integrity:high`, `integrity:system` - and never as the RID,
        // because "12288" is not an answer to any question a reader asks. The
        // bare form means "has a readable level", which is how `note:` and
        // `country:` behave: the useful query is "show me everything running as
        // System".
        case FilterField::Integrity: {
            if (c.security.integrity == 0 ||
                c.security.integrity >= static_cast<unsigned>(kIntegrityCount))
                return false;
            if (cl.text.empty()) return true;
            // ToLowerW, not a bare HasLowerSubstring: the parameter is named
            // `haystackLower` and does NOT fold case itself. The labels are
            // capitalised ("High", "Protected"), so matching the raw label
            // against a lower-case needle never found anything - `integrity:high`
            // returned 0 rows on a machine with eleven High processes, which is
            // precisely the "silently matches nothing" failure help list
            // forbids.
            //
            // The needle is matched against the CELL, marker included, so a
            // filter and the column cannot disagree: `integrity:ac` finds the
            // AppContainer rows because "+AC" is literally what the column
            // prints beside the level.
            std::wstring cell =
                ToLowerW(IntegrityLabel(static_cast<IntegrityLevel>(c.security.integrity)));
            if (cell.empty()) return false;
            if (c.security.appContainer) cell += L"+ac";
            return cell.find(cl.text) != std::wstring::npos;
        }
        // Same shape: match the printed verdict, and let the bare form ask
        // the question worth asking - `signed:` alone means "WinTCP actually
        // verified this image", which is NOT the same as "the verdict was good".
        // A row whose image was never checked matches neither, because
        // reporting it would mean passing off an unasked question as an answer.
        case FilterField::Signature: {
            if (c.security.signature == 0 ||
                c.security.signature >= static_cast<unsigned>(kSigCount))
                return false;
            if (cl.text.empty())
                return c.security.signature == static_cast<unsigned>(kSigValid);
            // ToLowerW for the same reason as the integrity case above: the
            // haystack parameter does not fold case, and "BAD SIG" is the label
            // that needs folding most.
            const std::wstring label =
                ToLowerW(SignatureLabel(static_cast<SignatureState>(c.security.signature)));
            return label.find(cl.text) != std::wstring::npos;
        }
        default: return false;
    }
    return hay != nullptr && Has(*hay, cl.text);
}

bool MatchFilter(const Connection& c, const std::vector<FilterClause>& prog) {
    for (const FilterClause& cl : prog) {
        bool m = MatchClause(c, cl);
        if (cl.exclude) m = !m;
        if (!m) return false;
    }
    return true;
}

// ---- store -----------------------------------------------------------------

void ConnectionStore::FinalizeRow(Connection& c) {
    c.keys.protoLabel = (c.identity.protocol == IPPROTO_UDP) ? L"UDP" : L"TCP";
    c.keys.protoLabel += (c.identity.family == AF_INET6) ? L"v6" : L"v4";
    c.keys.stateLabel = (c.identity.protocol == IPPROTO_UDP) ? L"—" : TcpStateToString(c.identity.state);

    wchar_t pidb[kPidTextChars] = {0};
    ::swprintf_s(pidb, L"%lu", static_cast<unsigned long>(c.identity.pid));
    c.keys.pidText = pidb;

    c.keys.lowerLocal   = ToLowerW(c.display.localAddress);
    c.keys.lowerRemote  = ToLowerW(c.display.remoteAddress);
    c.keys.lowerProcess = ToLowerW(c.display.processName);
    c.keys.lowerPath    = ToLowerW(c.display.processPath);
    c.keys.lowerService = ToLowerW(c.display.serviceName);
    c.keys.lowerHost    = ToLowerW(c.display.hostname);
    c.keys.lowerState   = ToLowerW(c.keys.stateLabel);
    c.keys.lowerProto   = ToLowerW(c.keys.protoLabel);
    // Precomputed here for the same reason every other lower* field is:
    // MatchClause runs per row per clause, and ToLowerW allocates a fresh
    // string every time - doing it once per refresh instead of once per
    // keystroke is the whole reason this row of fields exists.
    c.keys.lowerParent  = ToLowerW(c.security.parentName);

    RebuildLowerAll(c);
}

void ConnectionStore::ReplaceSnapshot(std::vector<Connection> fresh) {
    changes_.clear();
    const ULONGLONG nowTick = ::GetTickCount64();
    lastSnapshotTick_ = nowTick;

    // Map previous (non-ghost) rows by identity key, keeping a QUEUE per key
    // rather than one entry.
    //
    // WHY NOT ONE ENTRY. A plain map assignment (`prevMap[KeyOf(row)] = i`) keeps
    // only the LAST row for a repeated key, so N rows sharing an identity match
    // one previous row between them and the other N-1 are reported as
    // DISAPPEAR ghosts - then reappear as new rows on the next refresh, forever.
    // That is not hypothetical: mDNS endpoints (UDP 5353) are shared by every
    // browser on the box, and 62 identical rows were measured here. It turned
    // `--changes` into a stream of 173 false DISAPPEAR / 0 APPEAR per run and
    // made the GUI flash rows red-then-green without end.
    //
    // With a queue, the N-th fresh row of a key pairs with the N-th previous
    // row of that key. Rows of one key are interchangeable to the user (same
    // endpoint, same owner, same state - that is why they share a key), so
    // first-come pairing is a stable 1:1 and nothing is reported as churn.
    // Built BACKWARDS - highest previous index first - so that a queue
    // consumed with pop_back() hands out ascending indexes, which is exactly
    // the first-come order front()/erase(begin()) used to produce.
    //
    // WHY THE DIRECTION MATTERS. Taking the front off a vector shifts every
    // element behind it, so one key of N previous rows cost O(N^2) across the
    // refresh while it should cost O(N); the mDNS case this queue exists for
    // is 62 rows of one key. Reversing the build buys the O(1) pop with no
    // second pass, no head index and no change to which row pairs with which -
    // the pairing is still first-come, only the container's idea of "first"
    // is now its back. Rows of a key are interchangeable to the pairing logic
    // anyway (same endpoint, same owner, same state - that is why they share
    // a key), but keeping the exact previous order means no change event,
    // age or bookmark can move to a different row than it did before.
    PrevKeyIndex prevMap;
    prevMap.reserve(rows_.size() * 2 + 1);
    for (size_t i = rows_.size(); i-- > 0;) {
        if (rows_[i].flags & kRowRemoved) continue;
        prevMap[KeyOf(rows_[i])].push_back(i);
    }
    std::vector<char> matched(rows_.size(), 0);

    std::vector<Connection> merged;
    merged.reserve(fresh.size() + rows_.size());

    for (Connection& f : fresh) {
        FinalizeRow(f);
        const ConnectionKey key = KeyOf(f);
        const auto it = prevMap.find(key);
        if (it != prevMap.end() && !it->second.empty()) {
            // Consume this key's queue: the queue was built backwards (see
            // above), so back() is the LOWEST previous index still waiting -
            // first-come order - and popping it means a later fresh row with
            // the same key gets the NEXT previous row, exactly as before.
            // pop_back() is O(1); erase(begin()) was O(N).
            const size_t pi = it->second.back();
            it->second.pop_back();
            const Connection& p = rows_[pi];
            matched[pi] = 1;
            f.id = p.id;
            f.display.hostname = p.display.hostname;         // carry reverse-DNS results
            // State that outlives a single refresh: when the endpoint first
            // appeared, and the user's own annotations. Both are keyed on
            // the endpoint identity, so a row that vanishes and comes back.
            // with the same 4-tuple keeps its age and bookmark.
            f.lifetime.firstSeenTick = p.lifetime.firstSeenTick;
            f.annotations.pinned = p.annotations.pinned;
            f.annotations.tag = p.annotations.tag;
            f.flags = 0;
            if (p.identity.state != f.identity.state) {
                f.flags |= kRowChanged;
                RowChange ch;
                ch.kind = kChangeState;
                ch.row = f;
                ch.oldState = p.identity.state;
                changes_.push_back(std::move(ch));
            }
            // Carry the PREVIOUS sample forward, and let ComputeRates() do the
            // arithmetic once the traffic join has written this tick's
            // counters.
            //
            // WHY NOT HERE. The bps used to be computed inline, which looks
            // right and is not: at this point the fresh row still has
            // perRowBytes == false and trafficRx == 0, because the byte counters
            // are joined onto the row AFTER the snapshot is installed. So the
            // test was always false and the Speed column was a permanent
            // em-dash even after the per-Socket join started supplying real
            // per-row counters. Splitting it means the comparison is between
            // two REAL readings of the same Socket, taken at two real times.
            f.rate.perRowBytes = p.rate.perRowBytes;
            f.rate.lastSampleTick = p.rate.lastSampleTick;
            f.rate.lastRxBytes = p.rate.lastRxBytes;
            f.rate.lastTxBytes = p.rate.lastTxBytes;
            // the two rate accumulators are carried separately, and the
            // PREVIOUS tick's sample point is what both need - the previous
            // per-Socket counters (above, for the row's own rate) and the
            // previous GROUP total (for the process rate). Sharing one
            // lastSampleTick between them is safe precisely because they are
            // sampled by the same scan at the same instant; carrying a second
            // tick would only create a way for them to disagree about when
            // "a second ago" was.
            f.groupRate.lastGroupRxBytes = p.groupRate.lastGroupRxBytes;
            f.groupRate.lastGroupTxBytes = p.groupRate.lastGroupTxBytes;
            f.groupRate.lastGroupTick = p.groupRate.lastGroupTick;
            // congestion state is per-Socket and absolute (not a delta), so
            // there is no previous sample to carry - the fresh join simply
            // overwrites it each tick. The CUMULATIVE parts are protected from
            // going backwards inside ApplySocketTcpInfo, which is where the
            // "a smaller reading means a recycled Socket" rule belongs.
            f.tcpInfo.rttLive = false;   // no RTT sample yet this tick -> blank until join
            f.tcpInfo.cwndKnown = false;
            f.tcpInfo.retransKnown = false;
            f.tcpInfo.timestampsKnown = false;
        } else {
            f.id = nextId_++;
            f.lifetime.firstSeenTick = nowTick;   // age starts now, not at launch
            f.flags |= kRowNew;
            RowChange ch;
            ch.kind = kChangeAppear;
            ch.row = f;
            changes_.push_back(std::move(ch));
        }
        merged.push_back(std::move(f));
    }

    // Vanished sockets are retained instead of dropped after one cycle.
    // A socket that vanishes THIS refresh emits exactly one DISAPPEAR event and
    // becomes a grey ghost; on later refreshes it is carried forward silently (no
    // event), so a stable snapshot neither re-fires DISAPPEAR nor recreates the
    // row. The retained set is bounded by TrimRetainedGhosts below.
    for (size_t i = 0; i < rows_.size(); ++i) {
        if (matched[i]) continue;
        Connection& prev = rows_[i];
        if (prev.flags & kRowRemoved) {
            // Already a retained ghost: carry it forward unchanged.
            merged.push_back(std::move(prev));
            continue;
        }
        // Freshly vanished -> one DISAPPEAR, then a ghost carrying the last
        // sample's counters as its final metrics. The row is MOVED out of rows_
        // (it is dead after this loop, which reassigns rows_ below); only the
        // change event needs a copy, because it outlives this pass.
        Connection ghost = std::move(prev);
        ghost.flags &= ~kRowNew;
        ghost.flags &= ~kRowChanged;
        ghost.flags |= kRowRemoved;
        ghost.lifetime.deathTick = nowTick;
        ghost.lifetime.finalRx = ghost.traffic.trafficRx;
        ghost.lifetime.finalTx = ghost.traffic.trafficTx;
        RowChange ch;
        ch.kind = kChangeDisappear;
        ch.row = ghost;
        changes_.push_back(std::move(ch));
        merged.push_back(std::move(ghost));
    }

    TrimRetainedGhosts(merged);

    rows_ = std::move(merged);
    RebuildIndexes();
}

// Keep at most kMaxRetainedGhosts grey ghosts, evicting the oldest. The
// order is by deathTick (earliest-vanished leaves first); id breaks ties for
// sockets that vanished in the same snapshot, so the eviction is stable.
void ConnectionStore::TrimRetainedGhosts(std::vector<Connection>& rows) {
    size_t ghostCount = 0;
    for (const Connection& r : rows)
        if (r.flags & kRowRemoved) ++ghostCount;
    if (ghostCount <= kMaxRetainedGhosts) return;

    struct GhostPos { ULONGLONG deathTick; std::uint64_t id; size_t idx; };
    std::vector<GhostPos> gp;
    gp.reserve(ghostCount);
    for (size_t i = 0; i < rows.size(); ++i)
        if (rows[i].flags & kRowRemoved)
            gp.push_back({ rows[i].lifetime.deathTick, rows[i].id, i });
    std::sort(gp.begin(), gp.end(),
              [](const GhostPos& a, const GhostPos& b) {
                  if (a.deathTick != b.deathTick) return a.deathTick < b.deathTick;
                  return a.id < b.id;
              });
    const size_t drop = ghostCount - kMaxRetainedGhosts;
    std::vector<bool> kill(rows.size(), false);
    for (size_t k = 0; k < drop; ++k) kill[gp[k].idx] = true;
    std::vector<Connection> kept;
    kept.reserve(rows.size() - drop);
    for (size_t i = 0; i < rows.size(); ++i)
        if (!kill[i]) kept.push_back(std::move(rows[i]));
    rows = std::move(kept);
}

// Turn this tick's byte counters into a per-connection RATE, now that the
// traffic join has written them.
//
// MUST be called AFTER SetTraffic/ApplySocketBytes and after ReplaceSnapshot:
// the rate is a difference between two readings of the SAME Socket, so both
// the previous sample (carried forward by ReplaceSnapshot) and the current one
// (written by the join) have to be in place first. Calling it inside
// ReplaceSnapshot instead - which is where it used to live - compares a
// previous reading against a fresh row's zeros, and the `perRowBytes` test it
// guarded on was never true, so the Speed column was a permanent em-dash.
//
// The per-PID ETW path leaves perRowBytes false on purpose: a process total
// spread over its connection rows cannot honestly be attributed to one Socket,
// so those rows keep showing the same em-dash as any other unreadable reading
// rather than an invented split.
//
// Returns the number of rows that now have a known rate.
int ConnectionStore::ComputeRates() {
    const ULONGLONG nowTick = ::GetTickCount64();
    int known = 0;
    for (Connection& r : rows_) {
        if (!r.rate.perRowBytes) {
            r.rate.bpsKnown = false;
            continue;
        }
        // First tick for this row: there is no previous reading yet, so there
        // is no rate. Record the baseline so the NEXT tick can produce one.
        if (r.rate.lastSampleTick == 0) {
            r.rate.lastSampleTick = nowTick;
            r.rate.lastRxBytes = r.traffic.trafficRx;
            r.rate.lastTxBytes = r.traffic.trafficTx;
            r.rate.bpsKnown = false;
            continue;
        }
        const ULONGLONG elapsed = nowTick - r.rate.lastSampleTick;
        double rx = 0.0, tx = 0.0;
        const bool okRx = ComputeBps(r.rate.lastRxBytes, r.traffic.trafficRx, elapsed, &rx);
        const bool okTx = ComputeBps(r.rate.lastTxBytes, r.traffic.trafficTx, elapsed, &tx);
        if (okRx && okTx) {
            r.rate.rxBps = rx;
            r.rate.txBps = tx;
            r.rate.bpsKnown = true;
            ++known;
        } else {
            r.rate.bpsKnown = false;
        }
        r.rate.lastSampleTick = nowTick;
        r.rate.lastRxBytes = r.traffic.trafficRx;
        r.rate.lastTxBytes = r.traffic.trafficTx;
    }
    ComputeGroupRates();
    return known;
}

// The per-PROCESS rate, summed over the process's Sockets.
//
// WHY A SEPARATE PASS AND NOT A DIVISION. The obvious way to get "how fast is
// this process moving bytes" from a per-PID total is to divide it by the
// connection count. That is inventing a number: the Sockets of one process carry
// wildly different shares of its traffic (one 500 MB download and forty
// keepalives), so the quotient is not any Socket's rate and not the process's
// either - it is the average of a distribution, which is exactly the figure
// `perRowBytes` was introduced to forbid. The same honesty rule applies here,
// and the sum is the only honest answer available from per-Socket readings.
//
// WHY THE SUM IS TRUSTWORTHY. Summing is only correct
// if each Socket is counted exactly once. The row key once omitted the
// PID, so 86 mDNS rows collapsed onto 10 identities and a per-key queue was
// needed to pair duplicates 1:1 - without that work a process holding several
// Sockets on the same endpoint would either double-count its own bytes or lose
// some, and this column would be wrong by an unknown factor. That is why the
// duplicate-identity fix is load-bearing here and not merely tidy.
//
// ONLY ROWS WITH PER-SOCKET BYTES COUNT. A row fed by the ETW source has
// perRowBytes false and represents a process total, not a Socket. Including it
// would add the whole process figure to a sum that is already counting its
// Sockets - and so count the same bytes twice. Such rows are excluded, and a
// process whose traffic came only from ETW reports no group rate rather than a
// doubled one.
//
// A PROCESS WITH NO SOCKET-COUNTERED ROWS reports "unknown", never zero: zero is
// a claim about a process we did measure, and a dash is the honest answer for
// one we could not.
void ConnectionStore::ComputeGroupRates() {
    const ULONGLONG nowTick = ::GetTickCount64();

    // One pass: sum each PID's Socket counters, remembering whether any of
    // its rows was Socket-counted at all.
    //
    // wintcp::SumPidTrafficOpt (Opt.cpp) replaces the std::map accumulation
    // with a sort plus one linear pass over the runs. std::map allocated a
    // node per DISTINCT PID and paid a tree descent per row; the bench
    // measured 3.63x (500 rows / 50 processes) and 4.24x (5k rows / 700
    // processes). The semantics are the ones this loop depends on and the
    // comment above states them: saturating adds, and a PID whose rows were
    // all ETW-fed gets hasSum == false rather than a zero sum, because
    // "unknown" and "measured zero" are different answers.
    //
    // Only rows carrying per-Socket bytes take part, so the flat array is
    // built in a first sweep and the results are read back by PID.
    std::vector<PidTrafficRow> pidRows;
    {
        size_t counted = 0;
        for (const Connection& r : rows_) {
            if (r.rate.perRowBytes) ++counted;
        }
        pidRows.resize(counted);
        size_t at = 0;
        for (const Connection& r : rows_) {
            if (!r.rate.perRowBytes) continue;
            PidTrafficRow& t = pidRows[at++];
            t.pid = r.identity.pid;
            t.counted = true;
            t.rx = r.traffic.trafficRx;
            t.tx = r.traffic.trafficTx;
        }
    }
    SumPidTrafficOpt(pidRows.data(), pidRows.size());

    // Sums keyed by PID. The lookup is only read below, never iterated, so
    // this map carries no ordering contract and a flat index would do just
    // as well - it is sized by the DISTINCT pids, which is far smaller than
    // the row count on a busy box.
    std::map<DWORD, PidTraffic> sum;
    std::map<DWORD, bool> anyCounted;
    for (const PidTrafficRow& t : pidRows) {
        if (!t.hasSum) continue;
        PidTraffic& s = sum[t.pid];
        s.rx = t.sumRx;
        s.tx = t.sumTx;
        anyCounted[t.pid] = true;
    }

    // Second pass: difference, then write the result and the new baseline onto
    // EVERY row of that PID. Writing to all of them (rather than to one chosen
    // row) is what keeps the invariant true: the next tick reads the same
    // baseline from any row it happens to visit.
    for (Connection& r : rows_) {
        const auto it = sum.find(r.identity.pid);
        const bool counted = it != sum.end() && anyCounted[r.identity.pid];
        if (!counted) {
            r.groupRate.groupBpsKnown = false;
            r.groupRate.lastGroupTick = nowTick;
            continue;
        }
        const PidTraffic& t = it->second;
        // First tick for this process: no previous total, so no rate yet. The
        // baseline is recorded so the NEXT tick can produce one.
        if (r.groupRate.lastGroupTick == 0) {
            r.groupRate.lastGroupTick = nowTick;
            r.groupRate.lastGroupRxBytes = t.rx;
            r.groupRate.lastGroupTxBytes = t.tx;
            r.groupRate.groupBpsKnown = false;
            continue;
        }
        const ULONGLONG elapsed = nowTick - r.groupRate.lastGroupTick;
        double rx = 0.0, tx = 0.0;
        const bool okRx =
            ComputeBps(r.groupRate.lastGroupRxBytes, t.rx, elapsed, &rx);
        const bool okTx =
            ComputeBps(r.groupRate.lastGroupTxBytes, t.tx, elapsed, &tx);
        if (okRx && okTx) {
            r.groupRate.groupRxBps = rx;
            r.groupRate.groupTxBps = tx;
            r.groupRate.groupBpsKnown = true;
        } else {
            r.groupRate.groupBpsKnown = false;
        }
        r.groupRate.lastGroupTick = nowTick;
        r.groupRate.lastGroupRxBytes = t.rx;
        r.groupRate.lastGroupTxBytes = t.tx;
    }
}

void ConnectionStore::RebuildIndexes() {
    pidRows_.clear();
    addrRows_.clear();
    stats_ = RowStats{};
    stats_.total = rows_.size();

    pidRows_.reserve(rows_.size() / 2 + 1);
    addrRows_.reserve(rows_.size() / 2 + 1);
    for (size_t i = 0; i < rows_.size(); ++i) {
        const Connection& r = rows_[i];
        pidRows_[r.identity.pid].push_back(i);
        if (!r.display.remoteAddress.empty()) addrRows_[r.display.remoteAddress].push_back(i);
        if (r.identity.family == AF_INET6) ++stats_.ipv6; else ++stats_.ipv4;
        if (r.identity.protocol == IPPROTO_UDP) ++stats_.udp;
        if (r.identity.state < kByStateEntries) ++stats_.byState[r.identity.state];
        if (r.annotations.pinned || r.annotations.tag != kTagNone) ++stats_.pinned;
        if (r.enrichment.tls.known && r.enrichment.tls.secure) ++stats_.secure;
    }
}

void ConnectionStore::SetView(const ViewQuery& q) {
    flatIndex_.clear();
    flatIndex_.reserve(rows_.size());
    for (size_t i = 0; i < rows_.size(); ++i) {
        const Connection& r = rows_[i];
        const unsigned famBit  = (r.identity.family == AF_INET6) ? kProtoMaskV6 : kProtoMaskV4;
        const unsigned protoBit = (r.identity.protocol == IPPROTO_UDP) ? kProtoMaskUDP : kProtoMaskTCP;
        if ((q.protoMask & famBit) == 0 || (q.protoMask & protoBit) == 0) continue;
        if (q.stateFilter != kAllStates && r.identity.state != q.stateFilter) continue;
        if (q.program != nullptr && !q.program->empty() && !MatchFilter(r, *q.program))
            continue;
        flatIndex_.push_back(i);
    }
    std::sort(flatIndex_.begin(), flatIndex_.end(),
              [this](size_t a, size_t b) {
                  return CompareRows(rows_[a], rows_[b], sortColumn_, sortAsc_) < 0;
              });
    RebuildView();
}

// Collapses the filtered+sorted flat list into one entry per process
// when grouping is on. The flat list is kept, so turning grouping off
// restores the previous view exactly rather than re-deriving it - the rows
// were never consumed to build the groups.
void ConnectionStore::RebuildView() {
    if (!grouped_) {
        viewIndex_ = flatIndex_;
        groups_.clear();
        return;
    }

    // Project the flat rows into the grouping module's minimal view. Names
    // point into rows_, which outlive the call.
    std::vector<GroupRow> proj;
    proj.reserve(flatIndex_.size());
    for (size_t rowIdx : flatIndex_) {
        const Connection& c = rows_[rowIdx];
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
    groups_ = GroupByProcess(proj);

    // One view entry per group, pointing at that group's FIRST member row.
    // The list paints the row via ViewRow() and the aggregate via ViewGroup(),
    // so a group row and its totals always describe the same process.
    viewIndex_.clear();
    viewIndex_.reserve(groups_.size());
    for (const ProcessGroup& g : groups_) {
        if (g.members.empty()) continue;
        viewIndex_.push_back(flatIndex_[g.members.front()]);
    }
}

const ProcessGroup* ConnectionStore::ViewGroup(size_t viewIdx) const {
    if (!grouped_ || viewIdx >= groups_.size()) return nullptr;
    return &groups_[viewIdx];
}

void ConnectionStore::SetSort(int column, bool ascending) {
    if (column < 0 || column >= COL_COUNT) return;
    sortColumn_ = column;
    sortAsc_ = ascending;
}

const Connection* ConnectionStore::ViewRow(size_t viewIdx) const {
    if (viewIdx >= viewIndex_.size()) return nullptr;
    const size_t row = viewIndex_[viewIdx];
    return (row < rows_.size()) ? &rows_[row] : nullptr;
}

size_t ConnectionStore::ViewToRow(size_t viewIdx) const {
    return (viewIdx < viewIndex_.size()) ? viewIndex_[viewIdx] : SIZE_MAX;
}

long long ConnectionStore::RowToView(size_t rowIdx) const {
    for (size_t i = 0; i < viewIndex_.size(); ++i)
        if (viewIndex_[i] == rowIdx) return static_cast<long long>(i);
    return -1;
}

size_t ConnectionStore::CountForPid(DWORD pid) const {
    const auto it = pidRows_.find(pid);
    if (it == pidRows_.end()) return 0;
    size_t n = 0;
    for (size_t i : it->second)
        if (!(rows_[i].flags & kRowRemoved)) ++n;
    return n;
}

// Join the bookmark store onto the rows: mar. every row whose remote
// endpoint is bookmarked, and set its colour tag and note.
//
// Called after the snapshot and after any add/remove, not per-row. It reads
// the registry-backed store once and then walks the rows, which is the right
// way round: a registry read per row would be thousands of them on a busy
// machine.
//
// 'known' is the set of endpoints present in the bookmark store, so a row
// whose endpoint is NOT bookmarked is explicitly CLEARED rather than left
// alone. S.ipping the clear would leave a stale pin on a row after the user
// removed the bookmark, which is worse than never showing the column.
//
// THE PORT IS PART OF THE MATCH, and that is a fix, not a refinement.
// `bookmark add` stores its identity as address + remote port ("what survives a
// reconnect"), so that is what the join must use. Matching on the address
// alone painted the wrong conversation: with a bookmark on
// 107.155.105.90:9999, the live 107.155.105.90:443 row printed "red" in the
// bookmarks column. A user who marked one peer "suspicious" therefore saw every
// unrelated session to that host flagged, and could not trust the column at all.
//
// Rows whose remote is a placeholder (`*`, `0.0.0.0`) carry remotePort 0, and
// a bookmark on port 0 is rejected at the CLI, so they can never match - which
// is correct: you cannot bookmark "somewhere".
void ConnectionStore::JoinBookmarks(const std::vector<BookmarkMark>& known) {
    // Key: address, a NUL, then the port in decimal. The separator cannot occur
    // inside an address, so no two distinct (address, port) pairs can collide
    // - an address li.e "1.2.3.4:5" is not a legal address, so there is no
    // "1.2.3.4:5" + ":12" vs "1.2.3.4" + ":5:12" ambiguity to guard against.
    std::unordered_map<std::wstring, const BookmarkMark*> byEndpoint;
    byEndpoint.reserve(known.size() * 2 + 1);
    for (const BookmarkMark& b : known) {
        if (b.address.empty()) continue;
        wchar_t port[kPortTextChars] = {0};
        ::swprintf_s(port, L"%u", b.port);
        byEndpoint.emplace(b.address + L"\x01" + port, &b);
    }

    for (Connection& r : rows_) {
        const BookmarkMark* hit = nullptr;
        if (!r.display.remoteAddress.empty() && r.identity.remotePort != 0) {
            wchar_t port[kPortTextChars] = {0};
            ::swprintf_s(port, L"%u", r.identity.remotePort);
            const auto it = byEndpoint.find(r.display.remoteAddress + L"\x01" + port);
            if (it != byEndpoint.end()) hit = it->second;
        }
        const bool marked = (hit != nullptr);
        r.annotations.pinned = marked;
        // The tag is per-ENDPOINT, so every row to the same peer shows the
        // same colour. That is what "this conversation is red" means.
        // Stored as unsigned on the row, and kTagNone is the anonymous enum's
        // 0, so an unbookmarked row needs no separate "unknown" state.
        r.annotations.tag = marked ? hit->tag : static_cast<unsigned>(kTagNone);
        // the note used to live only in the registry, where the table
        // could not see it and no filter could reach it. Carrying it on the
        // row is what makes `note:` and the note-bearing columns work.
        r.annotations.note = marked ? hit->note : std::wstring();
        if (!r.annotations.note.empty()) {
            r.annotations.lowerNote = ToLowerW(r.annotations.note);
            RebuildLowerAll(r);
        } else if (!r.annotations.lowerNote.empty()) {
            r.annotations.lowerNote.clear();
            RebuildLowerAll(r);
        }
    }
    if (stats_.total != 0) {
        size_t n = 0;
        for (const Connection& r : rows_)
            if (r.annotations.pinned) ++n;
        stats_.pinned = n;
    }
}

bool ConnectionStore::SetCountry(const std::wstring& addr,
                                 const std::wstring& country) {
    if (addr.empty()) return false;
    const auto it = addrRows_.find(addr);
    if (it == addrRows_.end()) return false;
    bool changed = false;
    for (size_t i : it->second) {
        Connection& r = rows_[i];
        if (r.enrichment.country == country) continue;
        r.enrichment.country = country;
        // The lower-case copy is what the filter searches. S.ipping it would
        // make `country:de` fail while the column visibly reads "DE" - a
        // filter that ignores a value shown on screen.
        RebuildLowerAll(r);
        changed = true;
    }
    return changed;
}

// Joins by remote address exactly as SetCountry does - one ASN belongs to
// one network, and a process with twenty connections to it gets the same answer
// on all twenty rows.
//
// Both halves are written even when only one is known, and the CLEARING case
// matters as much as the setting one: an address whose answer disappears (the
// database was reloaded with different contents) must stop claiming an ASN, so
// an all-empty answer clears rather than being skipped. A row that kept a stale
// AS number after the file changed under it would be worse than a blank cell.
bool ConnectionStore::SetAsn(const std::wstring& addr, uint32_t number,
                             const std::wstring& org) {
    if (addr.empty()) return false;
    const auto it = addrRows_.find(addr);
    if (it == addrRows_.end()) return false;
    bool changed = false;
    for (size_t i : it->second) {
        Connection& r = rows_[i];
        if (r.enrichment.asnNumber == number && r.enrichment.asnOrg == org) continue;
        r.enrichment.asnNumber = number;
        r.enrichment.asnOrg = org;
        changed = true;
    }
    return changed;
}

bool ConnectionStore::SetHostname(const std::wstring& addr,
                                  const std::wstring& host) {
    if (addr.empty()) return false;
    const auto it = addrRows_.find(addr);
    if (it == addrRows_.end()) return false;
    bool changed = false;
    for (size_t i : it->second) {
        Connection& r = rows_[i];
        if (r.display.hostname == host) continue;
        r.display.hostname = host;
        r.keys.lowerHost = ToLowerW(host);
        RebuildLowerAll(r);
        changed = true;
    }
    return changed;
}

void ConnectionStore::SetTraffic(DWORD pid, ULONGLONG rx, ULONGLONG tx) {
    const auto it = pidRows_.find(pid);
    if (it == pidRows_.end()) return;
    for (size_t i : it->second) {
        rows_[i].traffic.trafficRx = rx;
        rows_[i].traffic.trafficTx = tx;
    }
}

void ConnectionStore::ClearTraffic() {
    for (Connection& r : rows_) {
        r.traffic.trafficRx = 0;
        r.traffic.trafficTx = 0;
        // A per-Socket total and a per-PID total are different facts about the
        // same cell. Clearing one without the other would leave the row
        // claiming a source it no longer has, which is what keeps `perRowBytes`
        // honest: the flag is re-derived by whichever join runs next.
        r.rate.perRowBytes = false;
        r.rate.bpsKnown = false;
        r.rate.rxBps = 0.0;
        r.rate.txBps = 0.0;
    }
}

// Per-SOCKET counters, from the same scan the per-PID totals come from.
//
// This is the join that sets `perRowBytes`, and it is the ONLY one allowed to:
// a per-PID total spread over a process's connection rows cannot honestly be
// attributed to a single Socket, and dividing it by the connection count would
// invent a plausible-looking rate. Before this existed nothing set the flag at
// all (a repo-wide grep found only the declaration and its single read), so
// `Connection::bpsKnown` was never true, the Speed column was a permanent
// em-dash and `speed:`/`bandwidth:` filters could match nothing - while `help
// list` and the README both advertised the column.
//
// Matching is on the full 4-tuple plus the protocol, and rows are only claimed
// once per sample: two rows that genuinely share a 4-tuple (the mDNS case) get
// the same cumulative counters, and the second row is left alone rather than
// being given an invented share.
int ConnectionStore::ApplySocketBytes(const std::vector<SocketBytes>& bytes) {
    if (bytes.empty()) return 0;
    int updated = 0;
    std::vector<char> claimed(rows_.size(), 0);
    for (const SocketBytes& b : bytes) {
        if (!b.known) continue;
        for (size_t i = 0; i < rows_.size(); ++i) {
            if (claimed[i]) continue;
            Connection& r = rows_[i];
            if (r.identity.localPort != b.localPort || r.identity.remotePort != b.remotePort)
                continue;
            if (r.display.localAddress != b.localAddress ||
                r.display.remoteAddress != b.remoteAddress)
                continue;
            if (r.identity.protocol != IPPROTO_TCP) continue;   // SIO_TCP_INFO is TCP
            r.traffic.trafficRx = b.rx;
            r.traffic.trafficTx = b.tx;
            r.rate.perRowBytes = true;   // this row's counters ARE one Socket's
            claimed[i] = 1;
            ++updated;
            break;
        }
    }
    return updated;
}

// Join TCP_INFO congestion state onto the rows.
//
// SAME MATCHING AS ApplySocketBytes, and for the same reason: these are
// per-sOCKET facts, so two rows that genuinely share a 4-tuple must not
// both claim the same reading. The first row to match wins
// and the Socket is then marked claimed, so the second row is left blanket rather
// than given a duplicate - which is the honest answer, since we genuinely
// cannot tell which of the two Sockets the reading came from.
//
// Per-field assignment rather than all-or-nothing, because the kernel populates
// these independently: a Socket with TCP timestamps off still has a perfectly
// real congestion window. A blanketet copy guarded on one `known` would blanket the
// three fields that did come back..
int ConnectionStore::ApplySocketTcpInfo(
    const std::vector<SocketTcpInfo>& infos) {
    if (infos.empty()) return 0;
    int updated = 0;
    std::vector<char> claimed(rows_.size(), 0);
    for (const SocketTcpInfo& t : infos) {
        for (size_t i = 0; i < rows_.size(); ++i) {
            if (claimed[i]) continue;
            Connection& r = rows_[i];
            if (r.identity.localPort != t.localPort || r.identity.remotePort != t.remotePort)
                continue;
            if (r.display.localAddress != t.localAddress ||
                r.display.remoteAddress != t.remoteAddress)
                continue;
            if (r.identity.protocol != IPPROTO_TCP) continue;   // TCP_INFO_v0 is TCP only
            // Cumulative/best-ever values only move in one direction, so a
            // smaller reading is a recycled Socket rather than new information.
            // Letting it overwrite would reset the connection's history every
            // time a handle was reused.
            if (t.retransKnown &&
                (!r.tcpInfo.retransKnown || t.retransBytes >= r.tcpInfo.retransBytes)) {
                r.tcpInfo.retransBytes = t.retransBytes;
                r.tcpInfo.retransKnown = true;
            }
            if (t.rttLive) {
                if (!r.tcpInfo.rttEver || t.minRttMs < r.tcpInfo.minRttMs)
                    r.tcpInfo.minRttMs = t.minRttMs;
                r.tcpInfo.rttMs = t.rttMs;
                r.tcpInfo.rttLive = true;   // sample live on THIS tick
                r.tcpInfo.rttEver = true;   // latches: a real RTT was observed once
            }
            if (t.cwndKnown) {
                r.tcpInfo.cwnd = t.cwnd;
                r.tcpInfo.cwndKnown = true;
            }
            if (t.timestampsKnown) {
                r.tcpInfo.tcpTimestamps = t.timestamps;
                r.tcpInfo.timestampsKnown = true;
            }
            claimed[i] = 1;
            ++updated;
            break;
        }
    }
    return updated;
}

// Kernel ages arrive keyed by the 4-tuple in the printable form the rows
// already carry, so this is a lookup by identity, not by PID: a process with
// twenty connections reports twenty ages, each belonging to one row.
int ConnectionStore::ApplyKernelAges(const std::vector<SocketAge>& ages) {
    if (ages.empty()) return 0;
    const ULONGLONG nowTick = ::GetTickCount64();
    int updated = 0;
    for (const SocketAge& a : ages) {
        if (!a.known || a.ageMs == 0) continue;
        // A kernel age cannot exceed the time since boot, and a sample taken
        // from another machine's clock can be nonsense. Clamping keeps a bad
        // reading from printing "400d" for a Socket opened a moment ago; the
        // row's own first-seen value is left alone if the age is unusable.
        if (a.ageMs > nowTick) continue;
        const ULONGLONG kernelSeen = nowTick - a.ageMs;
        // Narrow to the rows that already share this remote address via the
        // per-address index, so the walk is O(ages x rows-per-address) instead
        // of O(ages x rows). An empty remote address has no index entry (the
        // index skips it), so that rare case keeps the full scan.
        const std::vector<size_t>* bucket = nullptr;
        std::vector<size_t> allRows;
        if (!a.remoteAddress.empty()) {
            const auto it = addrRows_.find(a.remoteAddress);
            if (it == addrRows_.end()) continue;
            bucket = &it->second;
        } else {
            allRows.reserve(rows_.size());
            for (size_t i = 0; i < rows_.size(); ++i) allRows.push_back(i);
            bucket = &allRows;
        }
        for (size_t idx : *bucket) {
            Connection& r = rows_[idx];
            if (r.identity.localPort != a.localPort || r.identity.remotePort != a.remotePort)
                continue;
            if (r.display.localAddress != a.localAddress) continue;
            if (r.identity.protocol != IPPROTO_TCP) continue;   // TCP_INFO_v0 is TCP only
            // Backdate only: the kernel's age is authoritative, but a shorter
            // reading must not make a connection look younger than we have
            // already proven it to be.
            if (r.lifetime.firstSeenTick == 0 || kernelSeen < r.lifetime.firstSeenTick)
                r.lifetime.firstSeenTick = kernelSeen;
            ++updated;
            break;   // the 4-tuple identifies exactly one row
        }
    }
    return updated;
}

void ConnectionStore::SetProcStats(DWORD pid, double cpuPct, bool memKnown,
                                   ULONGLONG memWs, ULONGLONG memPrivate,
                                   bool ioKnown, ULONGLONG diskRead,
                                   ULONGLONG diskWrite) {
    const auto it = pidRows_.find(pid);
    if (it == pidRows_.end()) return;
    for (size_t i : it->second) {
        Connection& r = rows_[i];
        r.procStats.cpuPct = cpuPct;
        r.procStats.memKnown = memKnown;
        r.procStats.memWorkingSet = memKnown ? memWs : 0;
        r.procStats.memPrivate = memKnown ? memPrivate : 0;
        r.procStats.ioKnown = ioKnown;
        r.procStats.diskReadBytes = ioKnown ? diskRead : 0;
        r.procStats.diskWriteBytes = ioKnown ? diskWrite : 0;
    }
}

std::vector<RowChange> ConnectionStore::TakeChangeEvents() {
    std::vector<RowChange> out;
    out.swap(changes_);
    return out;
}

ULONGLONG ConnectionStore::TrafficKey(const Connection& c) {
    return c.traffic.trafficRx + c.traffic.trafficTx;
}

const wchar_t* ConnectionStore::ColumnTitle(int column) {
    switch (column) {
        case COL_PROTO:   return L"Proto";
        case COL_LOCAL:   return L"Local address";
        case COL_LPORT:   return L"Local port";
        case COL_REMOTE:  return L"Remote address";
        case COL_RPORT:   return L"Remote port";
        case COL_STATE:   return L"State";
        case COL_PID:     return L"PID";
        case COL_PROCESS: return L"Process";
        case COL_SERVICE: return L"Service";
        case COL_HOST:    return L"Hostname";
        case COL_PATH:    return L"Path";
        case COL_TRAFFIC: return L"Traffic (rx/tx)";
        case COL_RX:      return L"Received";
        case COL_TX:      return L"Sent";
        case COL_NETTOTAL: return L"Net total";
        case COL_CPU:     return L"CPU %";
        case COL_MEM:     return L"Memory (WS)";
        case COL_DISK:    return L"Disk I/O";
        case COL_DURATION: return L"Duration";
        case COL_BANDWIDTH: return L"Speed";
        // The headers are the `ss -i` field names in lower case, because
        // that is what someone comparing the two will be looking for. `RTT` is
        // rendered as "RTT" and not "Rtt" purely because it is an initialism;
        // the CLI COLUMN NAMES (what you type) are lower case separately, so
        // the two conventions never have to agree.
        case COL_RTT:      return L"RTT";
        case COL_MINRTT:   return L"Min RTT";
        case COL_CWND:     return L"Cwnd";
        case COL_RETRANS:  return L"Retrans";
        case COL_GROUPRATE: return L"Process rate";
        case COL_NOTE: return L"Note";
        case COL_TLS:     return L"TLS";
        case COL_COUNTRY: return L"Country";
        case COL_PINNED:  return L"bookmarks";
        case COL_PPID:    return L"Parent";
        case COL_INTEGRITY: return L"Integrity";
        case COL_SIGNATURE: return L"Signature";
        default:          return L"?";
    }
}

void ConnectionStore::GetColumnText(const Connection& c, int column,
                                    wchar_t* buf, size_t bufChars) {
    if (buf == nullptr || bufChars == 0) return;
    buf[0] = L'\0';
    // Copy, marking any elision with an ellipsis. wcsncpy_s(_TRUNCATE)
    // silently produced a cut-off path, which is worse than a visibly
    // shortened one: a long path truncated mid-component reads as a real
    // but wrong location.
    const auto set = [&](const std::wstring& s) {
        const size_t maxChars = bufChars - 1;   // leave room for the NUL
        if (s.size() <= maxChars) {
            ::wcsncpy_s(buf, bufChars, s.c_str(), _TRUNCATE);
            return;
        }
        if (maxChars == 0) return;              // no room for an ellipsis
        const size_t keep = (maxChars >= 2) ? (maxChars - 1) : 0;
        for (size_t i = 0; i < keep; ++i) buf[i] = s[i];
        buf[keep] = L'…';                       // horizontal ellipsis
        buf[keep + 1] = L'\0';
    };
    switch (column) {
        case COL_PROTO:   set(c.keys.protoLabel); break;
        case COL_LOCAL:   set(c.display.localAddress); break;
        case COL_LPORT:   ::swprintf_s(buf, bufChars, L"%u", c.identity.localPort); break;
        case COL_REMOTE:  set(c.display.remoteAddress); break;
        case COL_RPORT:
            if (c.identity.protocol == IPPROTO_UDP && c.identity.remotePort == 0)
                set(L"*");
            else
                ::swprintf_s(buf, bufChars, L"%u", c.identity.remotePort);
            break;
        case COL_STATE:   set(c.keys.stateLabel); break;
        case COL_PID:     ::swprintf_s(buf, bufChars, L"%lu",
                                       static_cast<unsigned long>(c.identity.pid)); break;
        case COL_PROCESS: set(c.display.processName.empty() ? L"—" : c.display.processName); break;
        case COL_SERVICE: set(c.display.serviceName); break;
        case COL_HOST:
            // an empty hostname = no PTR record (render em-dash);
            // the pending sentinel = a lookup still in flight (render
            // "pending" so a stale name is distinguishable from a missing
            // one rather than looking like an empty cell).
            if (c.display.hostname.empty()) set(L"—");
            else if (c.display.hostname == DnsResolver::kPendingHost) set(L"pending");
            else set(c.display.hostname);
            break;
        case COL_PATH:
            // PID 4 (System) has no image to point at; render a description
            // instead of the internal "System" sentinel so the row is not a
            // blank mystery.
            set(c.display.processPath == L"System"
                ? std::wstring(L"Windows kernel process (no image)")
                : c.display.processPath);
            break;
        case COL_TRAFFIC:
            if (c.traffic.trafficRx == 0 && c.traffic.trafficTx == 0) {
                set(L"—");
            } else {
                ::swprintf_s(buf, bufChars, L"%s / %s",
                             FormatBytes(c.traffic.trafficRx).c_str(),
                             FormatBytes(c.traffic.trafficTx).c_str());
            }
            break;
        case COL_RX:
            set((c.traffic.trafficRx == 0) ? L"—" : FormatBytes(c.traffic.trafficRx));
            break;
        case COL_TX:
            set((c.traffic.trafficTx == 0) ? L"—" : FormatBytes(c.traffic.trafficTx));
            break;
        case COL_NETTOTAL: {
            const ULONGLONG total = SatAdd(c.traffic.trafficRx, c.traffic.trafficTx);
            set((total == 0) ? L"—" : FormatBytes(total));
            break;
        }
        case COL_CPU:
            if (c.procStats.cpuPct < 0.0) {
                set(L"—");
            } else {
                ::swprintf_s(buf, bufChars, L"%.1f %%", c.procStats.cpuPct);
            }
            break;
        case COL_MEM:
            set(c.procStats.memKnown ? FormatBytes(c.procStats.memWorkingSet) : L"—");
            break;
        case COL_DISK:
            set(c.procStats.ioKnown ? FormatBytes(
                                SatAdd(c.procStats.diskReadBytes, c.procStats.diskWriteBytes))
                          : L"—");
            break;
        case COL_DURATION: set(FormatDuration(DurationSeconds(c))); break;
        case COL_BANDWIDTH:
            // Both directions are shown because the split is the useful part;
            // a single number would hide which way the bytes went.
            set(FormatBpsCell(c.rate.rxBps, c.rate.txBps, c.rate.bpsKnown));
            break;
        case COL_GROUPRATE:
            // Same SHAPE as COL_BANDWIDTH and the same helper, different
            // source: this is the PROCESS's rate, summed over its Sockets. It is
            // populated on flat rows too - where it is the truth and makes the
            // column useful ungrouped - and on a grouped row the group renderer
            // supplies it (see GroupColumnText).
            set(FormatBpsCell(c.groupRate.groupRxBps, c.groupRate.groupTxBps, c.groupRate.groupBpsKnown));
            break;
        // Each of these is gated on ITS OWN known flag, never on a shared
        // one: the kernel populates them independently, so a Socket with TCP
        // timestamps off still has a real congestion window. Gating all four on
        // a single flag would show four dashes for a row that has three good
        // readings - the same "one missing value blankets the row" failure the
        // ApplySocketTcpInfo join would otherwise have introduced.
        case COL_RTT:
            set(c.tcpInfo.rttLive ? FormatRttMs(c.tcpInfo.rttMs) : L"—");
            break;
        case COL_MINRTT:
            // Only meaningful alongside a live RTT: without one the "best ever
            // seen" has no measurement to be the best of. But Min RTT is a
            // running minimum, so it latches on `rttEver` rather than the
            // per-tick `rttLive`: a connection that idles after traffic still
            // shows its best observed value, while a socket that never produced
            // one correctly blanks to a dash. A zero minRtt beside a real rttMs
            // means the kernel reported an RTT but no running minimum, so there
            // is genuinely nothing to print.
            set((c.tcpInfo.rttEver && c.tcpInfo.minRttMs != 0) ? FormatRttMs(c.tcpInfo.minRttMs)
                                              : L"—");
            break;
        case COL_CWND:
            set(c.tcpInfo.cwndKnown ? FormatBytes(c.tcpInfo.cwnd) : L"—");
            break;
        case COL_RETRANS:
            // ZERO IS A REAL ANSWER here, not "unknown": zero retransmitted
            // bytes is the best possible result and is exactly what you want to
            // see. Printing a dash would hide the healthy case.
            set(c.tcpInfo.retransKnown ? FormatBytes(c.tcpInfo.retransBytes) : L"—");
            break;
        case COL_TLS:      set(TlsSummary(c.enrichment.tls)); break;
        case COL_COUNTRY: {
            // The ASN rides in the Country column rather than taking a
            // 33rd one: the table is frozen at 32 columns, and the decision
            // recorded for a feature in this position was to reuse the slot.
            //
            // The two are separated by a middle dot and only when BOTH are known,
            // so a row with a country alone reads exactly as it did before, and a
            // row with only an ASN still says something useful. `set` ellipsises
            // on overflow, so a narrow window truncates the organisation name -
            // the full value is in `details`, and the AS NUMBER is deliberately
            // placed before the name so a truncation never hides which network
            // this is.
            {
                const std::wstring asn = c.AsnDisplay();
                if (c.enrichment.country.empty())      set(asn);
                else if (asn.empty())      set(c.enrichment.country);
                else                       set(c.enrichment.country + L" \xB7 " + asn);
            }
            break;
        }
        case COL_PINNED:
            // The tag letter only means something next to its colour, which
            // the row itself carries; a pin alone is the default 'P'.
            if (c.annotations.pinned && c.annotations.tag == kTagNone) set(L"pinned");
            else if (c.annotations.tag != kTagNone) set(TagLabel(c.annotations.tag));
            else set(L"—");
            break;
        case COL_NOTE:
            // The user's own text. An UNBOOKMARKED row shows the dash even if a
            // note somehow survived on it, because the bookmark join clears both
            // together and a note without a bookmark is not a state that can
            // exist - showing one would imply it could.
            set(c.annotations.note.empty() ? L"—" : c.annotations.note);
            break;
        // "<ppid> <parent image name>". The name is omitted when the
        // snapshot did not contain the parent, which is NOT the same as having
        // no parent - so the number still prints on its own, because collapsing
        // the cell to a dash would tell a reader "this process has no parent",
        // which is the one answer the snapshot cannot actually give.
        case COL_PPID:
            if (!c.security.ppidKnown) {
                set(L"—");
            } else if (c.security.parentName.empty()) {
                ::swprintf_s(buf, bufChars, L"%lu",
                             static_cast<unsigned long>(c.security.ppid));
            } else {
                ::swprintf_s(buf, bufChars, L"%lu %s",
                             static_cast<unsigned long>(c.security.ppid),
                             c.security.parentName.c_str());
            }
            break;
        // The level, plus "+AC" when the process is AppContainer. Shown
        // WITH the level rather than instead of it: a sandboxed process still
        // has an integrity level, and replacing it with the marker would lose
        // the answer to "how much is it trusted".
        case COL_INTEGRITY: {
            if (c.security.integrity >= static_cast<unsigned>(kIntegrityCount)) {
                set(L"—");
                break;
            }
            std::wstring s =
                IntegrityLabel(static_cast<IntegrityLevel>(c.security.integrity));
            if (c.security.appContainer && s != L"—") s += L"+AC";
            set(s);
            break;
        }
        // Unchecked renders as the dash like every other unreadable
        // reading. That is the honest default: WinTCP has not looked at this
        // image, which is different from having looked and found nothing.
        case COL_SIGNATURE:
            if (c.security.signature >= static_cast<unsigned>(kSigCount)) {
                set(L"—");
            } else {
                set(SignatureLabel(static_cast<SignatureState>(c.security.signature)));
            }
            break;
        default: break;
    }
}

int ConnectionStore::CompareRows(const Connection& a, const Connection& b,
                                 int column, bool ascending) {
    int cmp = 0;
    // stat columns whose reading is unknown ("—")
    // sort to the END of the list in both directions instead of clumping
    // with the zero values.
    bool unknownLast = false;
    switch (column) {
        case COL_PROTO:
            cmp = CmpInt(static_cast<long long>(a.identity.protocol),
                         static_cast<long long>(b.identity.protocol));
            if (cmp == 0) cmp = CmpInt(a.identity.family, b.identity.family);
            break;
        case COL_LOCAL:   cmp = CompareAddress(a.identity, b.identity, true); break;
        case COL_LPORT:   cmp = CmpInt(a.identity.localPort, b.identity.localPort); break;
        case COL_REMOTE:  cmp = CompareAddress(a.identity, b.identity, false); break;
        case COL_RPORT:   cmp = CmpInt(a.identity.remotePort, b.identity.remotePort); break;
        case COL_STATE: {
            const int rankA = StateRank(a.identity.state);
            const int rankB = StateRank(b.identity.state);
            const bool knownA = a.identity.protocol == IPPROTO_TCP && rankA < 12;
            const bool knownB = b.identity.protocol == IPPROTO_TCP && rankB < 12;
            if (knownA != knownB) {
                unknownLast = true;
                cmp = knownA ? -1 : 1;
            } else if (knownA) {
                cmp = CmpInt(rankA, rankB);
            }
            break;
        }
        case COL_PID:     cmp = CmpInt(a.identity.pid, b.identity.pid); break;
        case COL_PROCESS:
            if (IsUnknownProcessName(a.display.processName) !=
                IsUnknownProcessName(b.display.processName)) {
                unknownLast = true;
                cmp = IsUnknownProcessName(a.display.processName) ? 1 : -1;
            } else if (!IsUnknownProcessName(a.display.processName)) {
                cmp = ::_wcsicmp(a.display.processName.c_str(),
                                b.display.processName.c_str());
            }
            break;
        case COL_SERVICE: cmp = CmpStr(a.keys.lowerService, b.keys.lowerService); break;
        case COL_HOST:    cmp = CmpStr(a.keys.lowerHost, b.keys.lowerHost); break;
        case COL_PATH:    cmp = CmpStr(a.keys.lowerPath, b.keys.lowerPath); break;
        case COL_TRAFFIC: cmp = CmpU64(TrafficKey(a), TrafficKey(b)); break;
        case COL_RX:      cmp = CmpU64(a.traffic.trafficRx, b.traffic.trafficRx); break;
        case COL_TX:      cmp = CmpU64(a.traffic.trafficTx, b.traffic.trafficTx); break;
        case COL_NETTOTAL:
            cmp = CmpU64(TrafficKey(a), TrafficKey(b));
            break;
        case COL_CPU: {
            const bool ka = a.procStats.cpuPct >= 0.0;
            const bool kb = b.procStats.cpuPct >= 0.0;
            if (ka != kb) { unknownLast = true; cmp = ka ? -1 : 1; }
            else cmp = ka ? CmpDbl(a.procStats.cpuPct, b.procStats.cpuPct) : 0;
            break;
        }
        case COL_MEM: {
            if (a.procStats.memKnown != b.procStats.memKnown) {
                unknownLast = true;
                cmp = a.procStats.memKnown ? -1 : 1;
            } else {
                cmp = CmpU64(a.procStats.memKnown ? a.procStats.memWorkingSet : 0,
                             b.procStats.memKnown ? b.procStats.memWorkingSet : 0);
            }
            break;
        }
        case COL_DISK: {
            if (a.procStats.ioKnown != b.procStats.ioKnown) {
                unknownLast = true;
                cmp = a.procStats.ioKnown ? -1 : 1;
            } else {
                cmp = CmpU64(
                    a.procStats.ioKnown ? SatAdd(a.procStats.diskReadBytes, a.procStats.diskWriteBytes) : 0,
                    b.procStats.ioKnown ? SatAdd(b.procStats.diskReadBytes, b.procStats.diskWriteBytes) : 0);
            }
            break;
        }
        case COL_DURATION:
            // Younger connections first is the useful default (the ones
            // worth investigating), and the ascending flip gives the
            // opposite. An unknown age (0) sorts as oldest, i.e. last when
            // ascending - it is the least actionable value.
            cmp = CmpU64(DurationSeconds(a), DurationSeconds(b));
            break;
        case COL_BANDWIDTH: {
            if (a.rate.bpsKnown != b.rate.bpsKnown) {
                unknownLast = true;
                cmp = a.rate.bpsKnown ? -1 : 1;
            } else {
                cmp = CmpDbl(a.rate.bpsKnown ? (a.rate.rxBps + a.rate.txBps) : 0.0,
                             b.rate.bpsKnown ? (b.rate.rxBps + b.rate.txBps) : 0.0);
            }
            break;
        }
        case COL_GROUPRATE: {
            if (a.groupRate.groupBpsKnown != b.groupRate.groupBpsKnown) {
                unknownLast = true;
                cmp = a.groupRate.groupBpsKnown ? -1 : 1;
            } else {
                cmp = CmpDbl(a.groupRate.groupBpsKnown ? (a.groupRate.groupRxBps + a.groupRate.groupTxBps) : 0.0,
                             b.groupRate.groupBpsKnown ? (b.groupRate.groupRxBps + b.groupRate.groupTxBps) : 0.0);
            }
            break;
        }
        // unknown LAST, for every one of these, li.e every other measured
        // column - so `--sort rtt --asc` puts the genuinely fastest connection
        // at the top instead of the em-dashes. Within the known rows the value
        // is what sorts, which for RTT means ascending is "fastest first" and
        // descending surfaces the slow ones, which is the query someone
        // diagnosing a lag actually wants.
        case COL_RTT: {
            if (a.tcpInfo.rttLive != b.tcpInfo.rttLive) {
                unknownLast = true;
                cmp = a.tcpInfo.rttLive ? -1 : 1;
            } else {
                cmp = CmpInt(a.tcpInfo.rttLive ? static_cast<long long>(a.tcpInfo.rttMs) : 0,
                             b.tcpInfo.rttLive ? static_cast<long long>(b.tcpInfo.rttMs) : 0);
            }
            break;
        }
        case COL_MINRTT: {
            if (a.tcpInfo.rttEver != b.tcpInfo.rttEver) {
                unknownLast = true;
                cmp = a.tcpInfo.rttEver ? -1 : 1;
            } else {
                cmp = CmpInt(a.tcpInfo.rttEver ? static_cast<long long>(a.tcpInfo.minRttMs) : 0,
                             b.tcpInfo.rttEver ? static_cast<long long>(b.tcpInfo.minRttMs) : 0);
            }
            break;
        }
        case COL_CWND: {
            if (a.tcpInfo.cwndKnown != b.tcpInfo.cwndKnown) {
                unknownLast = true;
                cmp = a.tcpInfo.cwndKnown ? -1 : 1;
            } else {
                cmp = CmpU64(a.tcpInfo.cwndKnown ? a.tcpInfo.cwnd : 0, b.tcpInfo.cwndKnown ? b.tcpInfo.cwnd : 0);
            }
            break;
        }
        case COL_RETRANS: {
            if (a.tcpInfo.retransKnown != b.tcpInfo.retransKnown) {
                unknownLast = true;
                cmp = a.tcpInfo.retransKnown ? -1 : 1;
            } else {
                cmp = CmpU64(a.tcpInfo.retransKnown ? a.tcpInfo.retransBytes : 0,
                             b.tcpInfo.retransKnown ? b.tcpInfo.retransBytes : 0);
            }
            break;
        }
        case COL_TLS: {
            // Non-TLS and unknown rows group at the end, the way the other
            // "no reading" columns do, so the secure ones lead.
            const bool sa = a.enrichment.tls.known && a.enrichment.tls.secure;
            const bool sb = b.enrichment.tls.known && b.enrichment.tls.secure;
            if (sa != sb) { unknownLast = true; cmp = sa ? -1 : 1; }
            else if (sa) {
                cmp = CmpInt(a.enrichment.tls.protocol, b.enrichment.tls.protocol);
                if (cmp == 0) cmp = CmpInt(a.enrichment.tls.cipherSuite, b.enrichment.tls.cipherSuite);
            }
            break;
        }
                case COL_COUNTRY: {
            // Compare what the column PRINTS, so the sort order matches the
            // screen: country first, then the ASN as a tiebreak. Without the
            // tiebreak, rows sharing a country - which is most of a table once the
            // database is loaded - sort arbitrarily against their own ASN.
            //
            // unknownLast: a row with neither answer sorts to the END in both
            // directions, as docs/cli.md promises for unknown values. Without it an
            // empty cell - which sorts below every real value - rose to the TOP
            // under --desc, which is the one direction a reader uses to find "the
            // rows I have not looked at yet".
            // Each side's ASN text is computed ONCE: the four guards and the
            // tiebreak all need it, and this comparator runs O(n log n) times per
            // sort, so calling AsnDisplay() up to six times per pair built the
            // same string over and over. It is a pure function of the row, so
            // hoisting it changes nothing but the number of allocations.
            const std::wstring aAsn = a.AsnDisplay();
            const std::wstring bAsn = b.AsnDisplay();
            if (a.enrichment.country.empty() && aAsn.empty() &&
                !(b.enrichment.country.empty() && bAsn.empty())) {
                unknownLast = true;
                cmp = 1;
                break;
            }
            if (b.enrichment.country.empty() && bAsn.empty() &&
                !(a.enrichment.country.empty() && aAsn.empty())) {
                unknownLast = true;
                cmp = -1;
                break;
            }
            cmp = CmpStr(a.enrichment.country, b.enrichment.country);
            if (cmp == 0) cmp = CmpStr(aAsn, bAsn);
            break;
        }
        case COL_PINNED: {
            // Pinned first regardless of direction, then by tag, so a
            // bookmarked row never sinks below unbookmarked noise.
            // NOTE: the unknownLast flag is required here, identical to
            // COL_NOTE's precedent below - it keeps the ascending-vs-descending
            // multiplier off the pinned comparison. Without it, sorting
            // descending by the pinned column pushed pinned rows to the
            // bottom, the exact opposite of "pinned first".
            if (a.annotations.pinned != b.annotations.pinned) { unknownLast = true; cmp = a.annotations.pinned ? -1 : 1; }
            else if (a.annotations.tag != b.annotations.tag) cmp = CmpInt(a.annotations.tag, b.annotations.tag);
            break;
        }
        case COL_NOTE: {
            // Annotated rows first, for the same reason bookmarks leads: a
            // note is the reader's own annotation and the rows carrying one are
            // the ones being looked for. Within those, alphabetical, so
            // "everything I wrote about vendor X" sorts together.
            const bool na = !a.annotations.note.empty();
            const bool nb = !b.annotations.note.empty();
            if (na != nb) { unknownLast = true; cmp = na ? -1 : 1; }
            else if (na) cmp = CmpStr(a.annotations.lowerNote, b.annotations.lowerNote);
            break;
        }
        // Sorts by the NUMBER, not by the cell text. The cell is
        // "<ppid> <name>", so a string sort would order "1000 svchost.exe"
        // before "900 wininit.exe" by the leading digit run only by accident -
        // and would order "12 a.exe" after "12.exe" for reasons that have
        // nothing to do with the hierarchy. Rows the snapshot did not cover sort
        // last, like every other "no reading" column.
        case COL_PPID: {
            if (a.security.ppidKnown != b.security.ppidKnown) {
                unknownLast = true;
                cmp = a.security.ppidKnown ? -1 : 1;
            } else if (a.security.ppidKnown) {
                cmp = CmpInt(a.security.ppid, b.security.ppid);
                if (cmp == 0) cmp = CmpStr(a.keys.lowerParent, b.keys.lowerParent);
            }
            break;
        }
        // Orders by the enum, which is already in trust order
        // (Untrusted < Low < Medium < High < System < Protected), so sorting
        // ascending on the column puts the least trusted first - the direction
        // a reader wants when auditing. Unknown is last.
        case COL_INTEGRITY: {
            const bool ka = a.security.integrity != 0 &&
                            a.security.integrity < static_cast<unsigned>(kIntegrityCount);
            const bool kb = b.security.integrity != 0 &&
                            b.security.integrity < static_cast<unsigned>(kIntegrityCount);
            if (ka != kb) { unknownLast = true; cmp = ka ? -1 : 1; }
            else if (ka) cmp = CmpInt(a.security.integrity, b.security.integrity);
            break;
        }
        // Orders by the enum (Unchecked < Valid < Invalid < Unsigned <
        // Error), then puts the AppContainer-ish detail aside - there is none
        // here, the state is the whole answer. A reviewer sorting descending
        // gets the BAD SIG rows first, which is the point of the highlight.
        case COL_SIGNATURE: {
            const bool ka = a.security.signature != 0 &&
                            a.security.signature < static_cast<unsigned>(kSigCount);
            const bool kb = b.security.signature != 0 &&
                            b.security.signature < static_cast<unsigned>(kSigCount);
            if (ka != kb) { unknownLast = true; cmp = ka ? -1 : 1; }
            else if (ka) cmp = CmpInt(a.security.signature, b.security.signature);
            break;
        }
        default:          cmp = 0; break;
    }
    // Direction-independent: "—" always ends up last (cmp is non-zero here,
    // so the flip below must not run).
    if (unknownLast) return cmp;
    if (cmp == 0) {
        // Deterministic tie-breaker so refreshes never visibly shuffle rows.
        cmp = CmpInt(a.identity.family, b.identity.family);
        if (cmp == 0) cmp = CmpInt(static_cast<long long>(a.identity.protocol),
                                   static_cast<long long>(b.identity.protocol));
        if (cmp == 0) cmp = CmpStr(a.keys.lowerLocal, b.keys.lowerLocal);
        if (cmp == 0) cmp = CmpInt(a.identity.localPort, b.identity.localPort);
        if (cmp == 0) cmp = CmpStr(a.keys.lowerRemote, b.keys.lowerRemote);
        if (cmp == 0) cmp = CmpInt(a.identity.remotePort, b.identity.remotePort);
        if (cmp == 0) cmp = CmpInt(a.identity.pid, b.identity.pid);
        if (cmp == 0) cmp = CmpU64(a.id, b.id);
    }
    return ascending ? cmp : -cmp;
}

// ---- headless row targeting (stage 2.1) -----------------------------------
// Answer "which rows does this command act on?" from data alone, with the
// same filter grammar as the GUI filter box. Empty text matches nothing, so
// a typo'd filter cannot quietly act on the whole machine.
std::vector<size_t> ConnectionStore::SelectByFilter(
        const std::wstring& text) const {
    std::vector<size_t> out;
    if (text.empty()) return out;
    std::vector<FilterClause> prog;
    if (!ParseFilter(text, prog)) return out;
    for (size_t i = 0; i < rows_.size(); ++i) {
        if (MatchFilter(rows_[i], prog)) out.push_back(i);
    }
    return out;
}

std::vector<size_t> ConnectionStore::SelectByFilterInView(
        const std::wstring& text) const {
    std::vector<size_t> out;
    if (text.empty()) return out;
    std::vector<FilterClause> prog;
    if (!ParseFilter(text, prog)) return out;
    for (size_t v = 0; v < viewIndex_.size(); ++v) {
        const size_t row = viewIndex_[v];
        if (row < rows_.size() && MatchFilter(rows_[row], prog))
            out.push_back(row);
    }
    return out;
}

const Connection* ConnectionStore::RowForViewIndex(int viewIdx) const {
    if (viewIdx < 0) return nullptr;
    const Connection* c = ViewRow(static_cast<size_t>(viewIdx));
    if (c == nullptr || (c->flags & kRowRemoved)) return nullptr;
    return c;
}

}  // namespace wintcp
