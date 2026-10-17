// Monitors.h
// SPDX-License-Identifier: Apache-2.0
//
// The data model and the interval-diff engine for `wintcp monitor` - a
// background instance that watches a filtered connection view over time and
// appends NDJSON events to a log file. The OS work (files, a detached child
// process, a named stop event, the snapshot/enrichment passes) lives in ONE
// CLI caller (RunMonitor in CliCommands.cpp); everything here is a pure
// function over plain structs, so it unit-tests headlessly exactly the way
// Alerts / GeoIP / TlsDecode do. Keep this header free of Windows types: the
// tests and the caller both include it, and the point of the split is that a
// question worth asking ("what did this interval see?") is answerable with no
// socket, no file and no window.
#pragma once

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace wintcp {

// The cadence an interval runs at. Reuses the CLI's --interval range
// (kWatchMinSec..kWatchMaxSec, 1..3600) which is parsed and range-checked once
// in CliCommands.cpp; there is no second range here to keep the two in step.
// The self-termination bound is monitor-specific and is the only range owned
// by this module, so it is the only one defined here.
extern const unsigned kMonitorDurationMaxSec;   // seconds; 0 = until stopped
extern const unsigned kMonitorMaxDefinitions;   // persisted monitors at once

// What one monitor watches. Kept separate from MonitorDef so a saved
// definition's identity (id, log path) can be re-pointed without dragging its
// subject along, and so a caller can build a filter without an id.
struct MonitorFilter {
    std::wstring filterText;   // WinTCP filter grammar; "" = all. The CALLER
                               // parses and applies this via ParseFilter /
                               // MatchFilter; it is stored here only so a
                               // saved monitor round-trips whole.
    std::uint32_t pid = 0;     // 0 = any process
    std::wstring process;      // "" = any; case-insensitive substring of the
                               // process name
    std::uint16_t localPort = 0;   // 0 = any local port
    std::uint16_t remotePort = 0;  // 0 = any remote port
    bool traffic = false;      // record rx/tx byte deltas per interval

    bool MatchesProcess(const std::wstring& name, std::uint32_t rowPid) const {
        if (pid != 0 && rowPid != pid) return false;
        if (!process.empty() && ToLowerAscii(name).find(ToLowerAscii(process)) ==
                                    std::wstring::npos)
            return false;
        return true;
    }
    bool MatchesPorts(std::uint16_t localP, std::uint16_t remoteP) const {
        if (localPort != 0 && localP != localPort) return false;
        if (remotePort != 0 && remoteP != remotePort) return false;
        return true;
    }
    // True when this filter would match a row on pid/process/ports alone.
    // filterText is NOT consulted - that is the caller's grammar, not a field
    // this struct can parse - so IsEmpty here means "no cheap pre-filter".
    bool IsEmpty() const {
        return pid == 0 && process.empty() && localPort == 0 && remotePort == 0;
    }

private:
    static std::wstring ToLowerAscii(const std::wstring& s);
};

// A monitor as it is saved, started and listed.
struct MonitorDef {
    std::wstring id;              // stable slug; also names the files on disk
    MonitorFilter what;
    unsigned intervalSeconds = 2; // cadence; caller clamps to the --interval range
    unsigned durationSeconds = 0; // 0 = run until stopped; else self-terminate
    bool traffic = false;         // mirrors what.traffic; convenience for callers
    bool jsonl = true;            // NDJSON is the only shape today; kept so the
                                  // file format has a name that can grow
    // Resolved by the CALLER (it is an OS path under %LOCALAPPDATA%). Empty
    // means "caller assigns %LOCALAPPDATA%\WinTCP\Monitors\<id>.log". Stored on
    // the definition so a restarted monitor logs to the same file.
    std::wstring logPath;

    bool Validate(std::wstring* err) const;
};

// One matched connection, flattened from a ConnectionStore row by the caller.
// The engine never sees Connection.h: this struct is the seam the tests build
// by hand, and the difference between two of these is what a monitor reports.
struct MonitorSample {
    std::uint32_t pid = 0;
    std::wstring process;
    std::wstring proto;           // "TCPv4" / "UDPv6"
    std::wstring state;           // "ESTABLISHED" / an em-dash for UDP
    std::wstring localEndpoint;   // "addr:port"
    std::wstring remoteEndpoint;  // "addr:port"
    std::uint16_t localPort = 0;
    std::uint16_t remotePort = 0;
    std::uint64_t trafficRx = 0;
    std::uint64_t trafficTx = 0;
    bool hasBytes = false;        // a per-socket source actually read counters
    double rttMs = 0;             // latest RTT in ms (0 when unknown); populated by the
                                  // CLI caller when it builds MonitorSample rows; see T29
    bool hasRtt = false;          // true when rttMs was observed for this snapshot
};

// Stable identity for a monitored socket, so a connection that stays up across
// many intervals is not reported as a fresh "appear" each time. The four-tuple
// and PID: two processes can share a remote address, and PID reuse across a
// reboot is harmless because these keys never outlive the process.
std::string MonitorKey(const MonitorSample& s);

// The events for ONE interval, as finished NDJSON object strings WITHOUT their
// trailing '\n' (the caller writes them line by line). `first` marks the
// baseline pass, which by design emits nothing - exactly like `list --changes`
// establishes its baseline quietly - so the first line in a log is a real
// change, never a dump of every current socket.
//
// kinds, the same vocabulary as row changes:
//   appear      a socket the previous interval did not have
//   disappear   a socket the previous interval had and this one does not
//   state       same socket, different TCP state
//   traffic     only when def.what.traffic: one per matched socket whose
//               rx+tx delta is positive this interval
//
// nowUtc is a caller-formatted timestamp string pasted straight into "t".
// Samples the caller already dropped by --filter are gone; this function then
// enforces the cheap pid/process/port pre-filter from def.what on both sides.
std::vector<std::string> RenderMonitorEvents(const MonitorDef& def,
                                             const std::vector<MonitorSample>& prev,
                                             const std::vector<MonitorSample>& cur,
                                             const std::wstring& nowUtc, bool first);

// ---- T08: wildcard-bound TCP listener exposure (webui.md:58) -----------------
// Pure over MonitorSample: the tests build rows by hand exactly like the engine
// above, with no socket, OS call, or file. Matches the browser evaluator in
// webui/app.js (isWildcardBindAddress + the TCP/LISTENING filter): counts TCP
// LISTEN sockets whose local bind is 0.0.0.0, ::, or *, including scoped /
// bracketed IPv6 forms "[addr]:port". Loopback-only and per-peer binds are
// excluded, and a missing/unknown bind is never treated as a wildcard match.
inline wchar_t CharToLowerAsciiW(wchar_t c) {
    return (c >= L'A' && c <= L'Z') ? static_cast<wchar_t>(c - L'A' + L'a') : c;
}

// True when `endpoint` ("addr:port" or "[addr]:port") binds a wildcard host.
inline std::wstring EndpointHost(const std::wstring& endpoint) {
    std::wstring host;
    if (!endpoint.empty() && endpoint[0] == L'[') {
        const size_t close = endpoint.find(L']');
        host = (close == std::wstring::npos) ? endpoint
                                             : endpoint.substr(1, close - 1);
    } else {
        const size_t colon = endpoint.rfind(L':');
        host = (colon == std::wstring::npos) ? endpoint
                                              : endpoint.substr(0, colon);
    }
    const size_t zone = host.find(L'%');
    if (zone != std::wstring::npos)
        host = host.substr(0, zone);
    return host;
}

inline bool IsWildcardBindLocal(const std::wstring& endpoint) {
    const std::wstring host = EndpointHost(endpoint);
    return host == L"0.0.0.0" || host == L"::" || host == L"*";
}

// TCP LISTEN (proto prefix "TCP" + state "LISTENING"), matched case-insensitively
// so the engine tolerates any future mixed-case snapshot source, exactly as the
// browser upper-cases row fields before comparing.
inline bool IsTcpListening(const MonitorSample& s) {
    if (s.proto.size() < 3) return false;
    if (CharToLowerAsciiW(s.proto[0]) != L't' ||
        CharToLowerAsciiW(s.proto[1]) != L'c' ||
        CharToLowerAsciiW(s.proto[2]) != L'p')
        return false;
    const std::wstring want = L"listening";
    if (s.state.size() != want.size()) return false;
    for (size_t i = 0; i < want.size(); ++i)
        if (CharToLowerAsciiW(s.state[i]) != want[i]) return false;
    return true;
}

// Count of TCP LISTEN sockets bound to a wildcard local address.
inline size_t CountWildcardListeners(const std::vector<MonitorSample>& rows) {
    size_t n = 0;
    for (const MonitorSample& s : rows)
        if (IsTcpListening(s) && IsWildcardBindLocal(s.localEndpoint)) ++n;
    return n;
}

// Stateful re-arm (webui.md:58): fires once when the count meets `limit`,
// deduplicates while it stays at/above, and re-arms only once it drops below.
// The fired flag is engine state the caller persists across intervals; this
// class owns the in-memory toggle exercised by the unit test.
class T08Monitor {
    bool fired_ = false;
public:
    bool Evaluate(const std::vector<MonitorSample>& rows, unsigned limit) {
        const size_t n = CountWildcardListeners(rows);
        if (n >= limit) {
            if (!fired_) { fired_ = true; return true; }
            return false;          // still exposed - dedup, do not re-alert
        }
        fired_ = false;            // below limit - re-arm
        return false;
    }
};

// ---- T11: process opens too many listeners (webui.md:59) -------------------
// Point-in-time: groups TCP LISTEN rows by PID and counts the distinct local
// endpoints each process holds; alerts (once per PID) when that count exceeds
// the configured limit. Pure over MonitorSample (no socket/OS/file), reusing
// IsTcpListening from T08. Deduplication follows webui/app.js: an over-limit
// PID is reported once until the engine's persisted state is cleared.
inline std::map<std::wstring, size_t> CountListenersByProcess(
        const std::vector<MonitorSample>& rows) {
    std::map<std::wstring, std::set<std::wstring>> distinct;
    for (const MonitorSample& s : rows)
        if (IsTcpListening(s))
            distinct[std::to_wstring(s.pid)].insert(s.localEndpoint);
    std::map<std::wstring, size_t> counts;
    for (const auto& kv : distinct) counts[kv.first] = kv.second.size();
    return counts;
}

class T11Monitor {
    std::set<std::wstring> fired_;   // PID keys already reported (fire-once)
public:
    struct Result {
        std::map<std::wstring, size_t> fired;  // pid -> listener count this pass
    };
    Result Evaluate(const std::vector<MonitorSample>& rows, unsigned limit) {
        Result r;
        const std::map<std::wstring, size_t> counts = CountListenersByProcess(rows);
        for (const auto& kv : counts)
            if (kv.second > limit && !fired_.count(kv.first)) {
                fired_.insert(kv.first);
                r.fired[kv.first] = kv.second;
            }
        return r;
    }
};

// ---- T12: process fans out to too many remote peers (webui.md:60) -------------
// Point-in-time: groups established TCP rows by PID and counts the distinct
// remote addresses each process has, alerting (once per PID) past the threshold.
// Pure over MonitorSample; reuses EndpointHost (remote addr) the way T08 reuses
// the local-host helper. Matches webui/app.js 'process-fanout' branch.
inline bool IsEstablishedWithRemote(const MonitorSample& s) {
    // TCP ESTABLISHED with a remote endpoint present (app.js T12:
    // state 'ESTABLISHED' && row.remote truthy). No wildcard exclusion: T12
    // counts distinct remote addresses per process, like the browser.
    if (s.proto.size() < 3) return false;
    if (CharToLowerAsciiW(s.proto[0]) != L't' ||
        CharToLowerAsciiW(s.proto[1]) != L'c' ||
        CharToLowerAsciiW(s.proto[2]) != L'p')
        return false;
    const std::wstring want = L"established";
    if (s.state.size() != want.size()) return false;
    for (size_t i = 0; i < want.size(); ++i)
        if (CharToLowerAsciiW(s.state[i]) != want[i]) return false;
    return !s.remoteEndpoint.empty() && !EndpointHost(s.remoteEndpoint).empty();
}

inline std::map<std::wstring, size_t> CountRemotePeersByProcess(
        const std::vector<MonitorSample>& rows) {
    std::map<std::wstring, std::set<std::wstring>> distinct;
    for (const MonitorSample& s : rows)
        if (IsEstablishedWithRemote(s))
            distinct[std::to_wstring(s.pid)].insert(EndpointHost(s.remoteEndpoint));
    std::map<std::wstring, size_t> counts;
    for (const auto& kv : distinct) counts[kv.first] = kv.second.size();
    return counts;
}

class T12Monitor {
    std::set<std::wstring> fired_;   // PID keys already reported (fire-once)
public:
    struct Result {
        std::map<std::wstring, size_t> fired;  // pid -> remote-peer count this pass
    };
    Result Evaluate(const std::vector<MonitorSample>& rows, unsigned limit) {
        Result r;
        const std::map<std::wstring, size_t> counts = CountRemotePeersByProcess(rows);
        for (const auto& kv : counts)
            if (kv.second > limit && !fired_.count(kv.first)) {
                fired_.insert(kv.first);
                r.fired[kv.first] = kv.second;
            }
        return r;
    }
};

// ---- T07: a new TCP listener appeared (webui.md:58) -----------------------
// Stateful (mirrors browser app.js 'new-listener'): the first sample seeds the
// seen set without alerting - a baseline, exactly like `list --changes` - then
// each subsequent non-wildcard listener not yet seen is reported. Reuses the
// T08 helpers (IsTcpListening + IsWildcardBindLocal): the same pair that counts
// wildcard binds is here inverted in sense - a bind that is NOT a wildcard is
// the very thing this monitor tracks. Pure over MonitorSample (no socket/OS).
class T07Monitor {
    bool initialized_ = false;     // true once the baseline sample has run
    std::set<std::wstring> seen_;  // local endpoints already observed
public:
    struct Result {
        std::vector<std::wstring> newListeners;  // localEndpoint of each new listener
    };
    Result Evaluate(const std::vector<MonitorSample>& rows) {
        Result r;
        for (const MonitorSample& s : rows) {
            if (!IsTcpListening(s) || IsWildcardBindLocal(s.localEndpoint)) continue;
            if (!seen_.insert(s.localEndpoint).second) continue;
            if (initialized_) r.newListeners.push_back(s.localEndpoint);
        }
        initialized_ = true;
        return r;
    }
};

// ---- T06: a new remote peer appeared (webui.md / app.js 'new-peer') ---------
// Stateful (mirrors T07 and browser app.js 'new-peer'/'new-listener'): the first
// sample seeds the seen set without alerting (a baseline, like `list --changes`),
// then each subsequent ESTABLISHED peer whose remote address was not seen before
// is reported. Reuses IsEstablishedWithRemote + EndpointHost (T12) and
// IsWildcardBindLocal (T08): app.js line 1055 excludes 0.0.0.0 / :: / * remotes,
// so a wildcard remote is never a "peer" for this monitor.
class T06Monitor {
    bool initialized_ = false;          // true once the baseline sample has run
    std::set<std::wstring> seen_;       // remote addresses already observed
public:
    struct Result {
        std::vector<std::wstring> newPeers;  // remote host of each new peer
    };
    Result Evaluate(const std::vector<MonitorSample>& rows) {
        Result r;
        for (const MonitorSample& s : rows) {
            if (!IsEstablishedWithRemote(s) || IsWildcardBindLocal(s.remoteEndpoint)) continue;
            const std::wstring remote = EndpointHost(s.remoteEndpoint);
            if (!seen_.insert(remote).second) continue;
            if (initialized_) r.newPeers.push_back(remote);
        }
        initialized_ = true;
        return r;
    }
};

// ---- T29: a flow's RTT exceeds the limit (webui.md / app.js 'rtt-threshold') ---
// Point-in-time: every row whose observed RTT is strictly above `limit` is
// reported, deduplicated per socket (MonitorKey) within the monitor. Mirrors
// app.js 1094-1104 (row.rttMs != null && row.rttMs > limit, fire-once per
// rule|rowKey; here the monitor is a single rule so the key is just MonitorKey).
// The hasRtt/rttMs fields are populated by the CLI caller (see CliCommands.cpp);
// they default off so the unit tests drive them by hand with no socket/OS call.
inline std::vector<const MonitorSample*> HighRttRows(
        const std::vector<MonitorSample>& rows, double limit) {
    std::vector<const MonitorSample*> out;
    for (const MonitorSample& s : rows)
        if (s.hasRtt && s.rttMs > limit) out.push_back(&s);
    return out;
}

class T29Monitor {
    std::set<std::string> fired_;   // MonitorKey of sockets already reported
public:
    struct Result {
        std::vector<const MonitorSample*> fired;  // sockets over threshold this pass
    };
    Result Evaluate(const std::vector<MonitorSample>& rows, double limit) {
        Result r;
        for (const MonitorSample* s : HighRttRows(rows, limit))
            if (fired_.insert(MonitorKey(*s)).second) r.fired.push_back(s);
        return r;
    }
};

}  // namespace wintcp
