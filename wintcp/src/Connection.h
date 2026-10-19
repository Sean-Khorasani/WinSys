// Connection.h
// SPDX-License-Identifier: Apache-2.0
// Core data model: one network endpoint row (TCP or UDP, IPv4 or IPv6).
// Produced by TcpTable enumeration, enriched by ProcessResolver / service
// map / reverse-DNS, diffed and filtered by ConnectionStore.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstdint>
#include <string>

namespace wintcp {

// Transient per-refresh display flags (cleared when a row is re-appeared).
enum RowFlags : unsigned {
    kRowNew     = 1u << 0,  // first seen this refresh   -> green
    kRowChanged = 1u << 1,  // TCP state changed         -> yellow
    kRowRemoved = 1u << 2,  // ghost of a vanished row   -> red
};

// User colour tag applied to a row. 0 = untagged.
enum RowTag : unsigned {
    kTagNone  = 0,
    kTagRed   = 1,
    kTagAmber = 2,
    kTagBlue  = 3,
    kTagGreen = 4,
    kTagCount = 5,
};

// What is known about a connection's TLS session.
//
// Windows does not expose a foreign process's plaintext to a separate
// process, so a TLS row is described by its *handshake*, which is itself
// unencrypted.
//
// !! NOTHING POPULATES THIS STRUCT TODAY. Every field below keeps its
// default, so `tls` reads as an em-dash on every row, the `tls:`/`ssl:`
// filters never match, and the Details window never shows its TLS section.
// The renderer, the filter and the sort all exist and are tested; only a
// producer is missing.
//
// WHY THERE IS NO CHEAP SOURCE. An earlier version of this comment claimed
// the first source was "SIO_TLS_INFO on a duplicated socket handle - no
// elevation, gives the negotiated protocol and cipher suite". There is no
// such ioctl: SIO_TLS_INFO is not declared anywhere in the Windows SDK, and
// TCP_INFO_v0 - which the non-admin traffic scan already reads, and which is
// the only socket-level info ioctl available to another process - carries
// State, Mss, ConnectionTimeMs, TimestampsEnabled, RttUs, MinRttUs,
// BytesInFlight, Cwnd, SndWnd, RcvWnd, RcvBuf, BytesOut, BytesIn,
// BytesReordered, BytesRetrans, FastRetrans, DupAcksIn, TimeoutEpisodes and
// SynRetrans. Not one TLS field. So the cheap source this struct was designed
// around does not exist, which is the likeliest reason nothing was ever
// written here.
//
// THE TWO SOURCES THAT DO EXIST, and neither is cheap:
//
//   1. The ETW Schannel provider (Microsoft-Windows-Schannel), which reports
//      negotiated parameters per connection. Needs elevation, like the traffic
//      counters. Not implemented.
//   2. A packet capture of the handshake, parsed by TlsDecode.cpp. Needs
//      elevation, and only covers connections the user chooses to capture -
//      which is why it can never fill a column over every row. The parser
//      EXISTS, is tested (see the TlsDecode section of Bench.cpp) and HAS a
//      caller: `capture` reports the handshake it reassembled as `tls:` lines.
//      What has no caller is the COLUMN, which would need one of the two
//      sources above over every row.
//
// 'known' false means TLS was looked for and not established, or no source
// was able to look; the column then shows the same em-dash the other
// unreadable columns use, never a guess.
struct TlsInfo {
    bool known = false;            // any source produced a result
    bool secure = false;           // a TLS session is negotiated
    USHORT protocol = 0;           // TLS major<<8 | minor (0x0304 = TLS 1.3)
    USHORT cipherSuite = 0;        // IANA cipher suite id, 0 = unknown
    bool haveSni = false;
    std::wstring sni;              // from ClientHello extension 0x0000
    bool haveCert = false;
    std::wstring certSubject;      // e.g. "CN=*.example.com"
    std::wstring certIssuer;       // e.g. "CN=Example CA"
    std::wstring certValidity;     // "2026-01-14 .. 2026-10-12"
};

// --- Connection's cohesive parts -------------------------------------------
// The row was one 85-field struct; the cold, single-purpose groups are now
// named sub-structs, so a reader can see what belongs together and a live row
// carries each group as one block. Field NAMES inside each are unchanged, so
// this is a regrouping, not a rewrite.

// Process metadata, used only for PID-reuse verification.
struct ConnectionProcMeta {
    FILETIME processCreate = {};
    bool processCreateKnown = false;
};

// Row lifetime and ghost retention. firstSeenTick is the row's birth; the ghost
// fields are written once when the socket leaves the table and read only by the
// store's diff/trim path. They travel together because both answer "when", and
// both are cold on the render path.
struct ConnectionLifetime {
    ULONGLONG firstSeenTick = 0;   // 0 == unknown
    ULONGLONG deathTick = 0;       // 0 == still live
    ULONGLONG finalRx = 0;
    ULONGLONG finalTx = 0;
};

// The process-wide rate for a `--group` row. This socket's own rate lives in
// the per-connection fields below; the two are NOT interchangeable (a process
// with 20 sockets has 20 per-socket rates and one process rate).
struct ConnectionGroupRate {
    double groupRxBps = 0.0;
    double groupTxBps = 0.0;
    bool groupBpsKnown = false;
    ULONGLONG lastGroupRxBytes = 0;
    ULONGLONG lastGroupTxBytes = 0;
    ULONGLONG lastGroupTick = 0;
};

// Cumulative per-connection byte totals as reported by whichever source fed
// the row (ETW is per-PID and copies the same figure onto each of the
// process's rows; the per-socket scan is that socket's own).
struct ConnectionTraffic {
    ULONGLONG trafficRx = 0;
    ULONGLONG trafficTx = 0;
};

// This ONE socket's rate, in bytes/second, between two samples. Only the
// per-socket source can attribute bytes to a single row; the ETW source is
// per-PID, so those rows keep bpsKnown false and the column shows the same
// em-dash as any other unreadable reading rather than an invented split.
struct ConnectionRate {
    double rxBps = 0.0;
    double txBps = 0.0;
    bool bpsKnown = false;
    // True only when this row's counters came from a source that observes the
    // single socket rather than the whole process. Set by the per-socket
    // sampler; the per-PID ETW join leaves it false, which is what keeps the
    // Speed column honest instead of dividing a process total by accident.
    bool perRowBytes = false;
    ULONGLONG lastSampleTick = 0;    // GetTickCount64 at the previous sample
    ULONGLONG lastRxBytes = 0;       // per-row counters at that sample
    ULONGLONG lastTxBytes = 0;
};

// Per-process live stats, sampled on the worker every refresh and joined by
// PID like the traffic counters.
struct ConnectionProcStats {
    double cpuPct = -1.0;              // process CPU %, < 0 = unknown
    ULONGLONG memWorkingSet = 0;       // bytes; valid iff memKnown
    ULONGLONG memPrivate = 0;          // bytes (PrivateUsage); iff memKnown
    bool memKnown = false;
    ULONGLONG diskReadBytes = 0;       // cumulative transfer bytes; iff ioKnown
    ULONGLONG diskWriteBytes = 0;
    bool ioKnown = false;
};

// Lower-cased and pre-formatted strings, computed once per refresh by
// FinalizeRow so the filter and the renderer never lower-case a row twice.
struct ConnectionKeys {
    std::wstring protoLabel;          // "TCPv4" / "UDPv6"
    std::wstring stateLabel;          // "ESTABLISHED" / "—" (UDP)
    std::wstring lowerLocal;
    std::wstring lowerRemote;
    std::wstring lowerProcess;
    std::wstring lowerParent;         // lower-cased parent image name
    std::wstring lowerPath;
    std::wstring lowerService;
    std::wstring lowerHost;
    std::wstring lowerState;
    std::wstring lowerProto;
    std::wstring lowerAll;            // everything searchable, space-joined
    std::wstring pidText;
};

// TCP-layer measurements, read from TcpInfo (WinTCPTableExtended) on the
// refresh worker and joined by PID. One row's reading is its own socket; a
// --group row is that socket's reading, not the process's aggregate.
struct ConnectionTcpInfo {
    unsigned rttMs = 0;
    unsigned minRttMs = 0;
    ULONGLONG cwnd = 0;
    ULONGLONG retransBytes = 0;
    bool rttLive = false;
    bool rttEver = false;
    bool cwndKnown = false;
    bool retransKnown = false;
    bool tcpTimestamps = false;
    bool timestampsKnown = false;
};

// Enrichment data: TLS certificate details (present only for a TLS reader) and
// GeoIP/ASN lookup results. These are the slowest fields on the row and the
// most often empty, so they are grouped together.
struct ConnectionEnrichment {
    TlsInfo tls;                  // cert subject/issuer/validity, if TLS reader ran
    std::wstring country;        // GeoIP country code, e.g. "US"
    UINT asnNumber = 0;          // 0 == unknown (no hit or lookup unavailable)
    std::wstring asnOrg;         // "AS15169 Google LLC"
};

// Per-connection security metadata from the process resolver: integrity level,
// package (AppContainer) identity, and Authenticode signature status.
struct ConnectionSecurity {
    DWORD ppid = 0;              // parent PID (process resolver only)
    bool ppidKnown = false;
    std::wstring parentName;     // parent image name
    unsigned integrity = 0;      // IntegrityLevel, 0 = unknown
    bool appContainer = false;   // running inside an AppContainer (UWP)
    unsigned signature = 0;      // SignatureState, 0 = not checked
};

// The endpoint identity: what makes a row the same row across refreshes. Also
// the shape SetTcpEntry needs for a reset/close, which is why family/protocol/
// live here rather than in a display-only block.
struct ConnectionIdentity {
    int family = AF_INET;             // AF_INET or AF_INET6
    UINT protocol = IPPROTO_TCP;      // IPPROTO_TCP or IPPROTO_UDP
    IN_ADDR  local4 = {};
    IN_ADDR  remote4 = {};
    IN6_ADDR local6 = {};
    IN6_ADDR remote6 = {};
    DWORD localScope = 0;             // IPv6 scope id
    DWORD remoteScope = 0;
    UINT localPort = 0;               // host byte order
    UINT remotePort = 0;
    DWORD state = 0;                  // MIB_TCP_STATE_*; 0 = none (UDP)
    DWORD pid = 0;
};

// Everything the row prints that is not a number. Built once per refresh by
// FinalizeRow from the identity plus resolved process/DNS data.
struct ConnectionDisplay {
    std::wstring localAddress;        // printable, scope applied ("fe80::1%12")
    std::wstring remoteAddress;
    std::wstring localEndpoint;       // "addr:port" / "[v6]:port"
    std::wstring remoteEndpoint;
    std::wstring processName;
    std::wstring processPath;
    std::wstring serviceName;         // e.g. "Dnscache" (svchost-hosted)
    std::wstring hostname;            // reverse-DNS of remote address
};

// User annotations: the bookmark's colour tag and free-text note. These are
// per-row state that survives refreshes and restarts, so they travel with the
// row rather than in a side table.
struct ConnectionAnnotations {
    bool pinned = false;             // survives refreshes and restarts
    unsigned tag = kTagNone;         // RowTag
    // The bookmark's free-text note, joined onto the row so it can be DISPLAYED
    // and FILTERED. It used to live only in HKCU, which made it writable and
    // listable but unusable: `note:vendor` matched nothing and the pinned
    // column showed only a colour. Cleared on every join when the endpoint is
    // not bookmarked, so removing a bookmark cannot leave a stale note behind.
    std::wstring note;
    std::wstring lowerNote;          // what the filter searches
};

struct Connection {
    // --- identity (binary endpoint; see ConnectionIdentity) ----------------
    ConnectionIdentity identity;

    // --- display strings (see ConnectionDisplay) ---------------------------
    ConnectionDisplay display;

    // --- process metadata (for PID-reuse verification) --------------------
    ConnectionProcMeta procMeta;

    // --- security metadata (see ConnectionSecurity) -------------------------
    // Resolved once per distinct PID and copied onto each of that process's
    // rows, the same relationship PID and the process name already have. That
    // is why they are columns rather than a separate process view: the unit
    // that matters ("who owns this socket") is the row.
    ConnectionSecurity security;

    // --- traffic counters (see ConnectionTraffic) -------------------------
    ConnectionTraffic traffic;

    // --- per-connection rate (bandwidth column; see ConnectionRate) -------
    ConnectionRate rate;

    // --- per-connection rate, summed over the socket's PROCESS ------------
    // See ConnectionGroupRate. A `--group` row stands for a whole process, so
    // it needs the process's total; a process with 20 connections has 20
    // sockets, and a group showing one of them is wrong by a factor of 20.
    // Summed per-socket rather than derived from the per-PID total on purpose:
    // dividing a per-PID byte total by the connection count invents a number,
    // which is the exact failure `perRowBytes` exists to prevent - and it is
    // worse here, because a group has a denominator that varies per refresh.
    // groupBpsKnown is SEPARATE from bpsKnown on purpose: per-connection Speed
    // and grouped Speed have genuinely different availability.
    ConnectionGroupRate groupRate;

    // --- TCP congestion state (see ConnectionTcpInfo) ----------------------
    // Per-connection, like the rate above, and only ever set from the
    // per-socket source: a process-level view of an RTT is not a thing.
    // Per-field, because the kernel populates some of these and not others:
    // RTT is meaningless without TCP timestamps, so a socket can report a real
    // cwnd and no RTT at all. One blanket flag would hide the half that works.
    ConnectionTcpInfo tcpInfo;

    // --- lifetime and ghost retention (see ConnectionLifetime) ------------
    ConnectionLifetime lifetime;

    // --- user annotations (see ConnectionAnnotations) ----------------------
    ConnectionAnnotations annotations;

    // --- enrichment (see ConnectionEnrichment) -----------------------------
    // Filled lazily; empty until a source runs. ASN is two fields rather than
    // one formatted string because the halves are filtered differently:
    // `asn:15169` is a number comparison and `asn:google` a substring one.
    // Deliberately plain rather than an AsnInfo - that type belongs to GeoIp.h,
    // and Connection.h must not have to pull in a database reader to describe
    // a row.
    ConnectionEnrichment enrichment;

    // "AS15169 Google LLC", or whichever half is present, or empty. Built here
    // rather than stored so the two halves cannot disagree with it.
    std::wstring AsnDisplay() const {
        if (enrichment.asnNumber == 0 && enrichment.asnOrg.empty()) return std::wstring();
        std::wstring s;
        if (enrichment.asnNumber != 0) { s = L"AS"; s += std::to_wstring(enrichment.asnNumber); }
        if (!enrichment.asnOrg.empty()) {
            if (!s.empty()) s += L' ';
            s += enrichment.asnOrg;
        }
        return s;
    }

    // --- per-process live stats (see ConnectionProcStats) -----------------
    ConnectionProcStats procStats;

    // --- precomputed keys (see ConnectionKeys) ----------------------------
    ConnectionKeys keys;

    // --- lifecycle --------------------------------------------------------
    std::uint64_t id = 0;             // stable across refreshes (store-assigned)
    unsigned flags = 0;               // RowFlags
};

inline bool SameProcessLifetime(const Connection& left,
                                const Connection& right) {
    return left.identity.pid != 0 &&
           left.identity.pid == right.identity.pid &&
           left.procMeta.processCreateKnown &&
           right.procMeta.processCreateKnown &&
           left.procMeta.processCreate.dwHighDateTime ==
               right.procMeta.processCreate.dwHighDateTime &&
           left.procMeta.processCreate.dwLowDateTime ==
               right.procMeta.processCreate.dwLowDateTime;
}

// Cumulative per-PID byte totals - the unit exchanged between the traffic
// sources (ETW kernel logger, per-socket SIO_TCP_INFO scan)
// and ConnectionStore::SetTraffic(). Shared here so the refresh worker's
// RefreshResult can carry either source's snapshot without pulling in the
// ETW headers.
struct PidTraffic {
    ULONGLONG rx = 0;                 // bytes received
    ULONGLONG tx = 0;                 // bytes sent
};

// One socket's kernel-reported age, read from TCP_INFO_v0::ConnectionTimeMs
// by the per-socket SIO_TCP_INFO scan (SocketTraffic).
//
// This is the honest age of the CONNECTION - the kernel's own counter, valid
// the first time WinTCP ever sees the row. Without it the only age available
// is "how long this process has been watching", which is 0s for every
// single-shot CLI run and 0s on the first poll of any watch. Addresses are
// the printable form the store already keys on (IPv6 scope included, as the
// store prints it), so the join needs no address/family juggling.
struct SocketAge {
    std::wstring localAddress;
    UINT localPort = 0;
    std::wstring remoteAddress;
    UINT remotePort = 0;
    ULONGLONG ageMs = 0;              // 0 = the kernel reported nothing
    bool known = false;
};

// One socket's CUMULATIVE byte counters, read from the same SIO_TCP_INFO scan
// that produces PidTraffic and SocketAge.
//
// This is what makes the per-connection Speed (bandwidth) column real. The
// per-PID totals cannot be split across a process's rows honestly - dividing a
// process total by its connection count invents a number - so Connection has a
// `perRowBytes` flag, and only a source that observes the SINGLE socket may set
// it. Before this struct existed nothing ever set that flag (a repo-wide grep
// found only the declaration and the single read), so the column was a
// permanent em-dash in both front ends: `--traffic --watch --sort bandwidth`
// printed "-" on every tick while `help list` advertised the column.
//
// Cumulative, not a delta: the store keeps the previous reading per row and
// divides by the elapsed time, so a socket that opens and closes between two
// refreshes costs nothing and a long-lived one carries its full history.
struct SocketBytes {
    std::wstring localAddress;
    UINT localPort = 0;
    std::wstring remoteAddress;
    UINT remotePort = 0;
    ULONGLONG rx = 0;
    ULONGLONG tx = 0;
    bool known = false;
};

// One socket's TCP congestion state, from the SAME TCP_INFO_v0 reading that
// produces SocketBytes and SocketAge - no extra handle duplication, no extra
// ioctl, no extra scan.
//
// This is `ss -i` for Windows: the four numbers that tell you whether a
// connection is healthy, degraded, or broken, and that no amount of
// netstat-family tooling can show you on Windows.
//
// UNITS, AND WHY THEY ARE NORMALISED HERE. TCP_INFO_v0 carries RTT and minimum
// RTT in MICROseconds - the field names are RttUs and MinRttUs, and
// ConnectionTimeMs is the only Ms field in the structure. These four are stored
// in MILLISECONDS, converted at this boundary, because the columns are named
// for `ss -i` and `ss -i` prints milliseconds. A consumer that reached for the
// SDK values directly would report a 12 ms round trip as 12000, and the mistake
// is invisible in a table: it still looks like a plausible number. Cwnd and
// BytesRetrans are byte counts in both, so they pass through.
//
// `known` is per-field, not per-struct, because the kernel genuinely does
// populate some of these and not others: RTT is only meaningful when TCP
// timestamps or a retransmit timer are in play, so a socket with
// TimestampsEnabled false can report RttUs 0 while its cwnd is perfectly real.
// One blanket `known` would collapse that into "no data" and lose the parts
// that do have data.
struct SocketTcpInfo {
    std::wstring localAddress;
    UINT localPort = 0;
    std::wstring remoteAddress;
    UINT remotePort = 0;

    unsigned rttMs = 0;         // smoothed; 0 = not reported
    unsigned minRttMs = 0;      // best ever seen on this connection
    ULONGLONG cwnd = 0;         // congestion window, bytes
    ULONGLONG retransBytes = 0; // cumulative bytes retransmitted

    bool rttLive = false;  // an RTT sample is present in this join input
    bool cwndKnown = false;
    bool retransKnown = false;
    // Whether the peer negotiated TCP timestamps. It is what makes an RTT
    // reading meaningful at all, so it is carried rather than inferred from a
    // zero - and a row can show "off" honestly instead of a bare dash.
    bool timestamps = false;
    bool timestampsKnown = false;
};

}  // namespace wintcp
