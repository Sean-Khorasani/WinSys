// Monitors.cpp
// SPDX-License-Identifier: Apache-2.0
// The pure half of `wintcp monitor`: no OS, no file, no socket. See Monitors.h
// for why this is split out of the CLI caller.

#include "Monitors.h"

#include <cstdio>
#include <unordered_map>

namespace wintcp {

const unsigned kMonitorDurationMaxSec = 86400;   // 24 h; 0 = until stopped
const unsigned kMonitorMaxDefinitions = 12;      // persisted monitors at once

// ASCII-only lowercase for the process-name substring test. Endpoint strings
// are ASCII; only a process name could carry non-ASCII, and even then a '?'
// collision would merely fail to de-duplicate two exotic names - it never
// mis-reports traffic. Acceptable for a match key, and it keeps this module
// free of any Windows/charset dependency.
std::wstring MonitorFilter::ToLowerAscii(const std::wstring& s) {
    std::wstring out;
    out.reserve(s.size());
    for (wchar_t c : s)
        out.push_back((c >= L'A' && c <= L'Z')
                          ? static_cast<wchar_t>(c - L'A' + L'a')
                          : c);
    return out;
}

bool MonitorDef::Validate(std::wstring* err) const {
    if (id.empty()) { if (err) *err = L"monitor id is empty"; return false; }
    if (id.size() > 64) { if (err) *err = L"monitor id is too long (max 64)"; return false; }
    // The id names files on disk (%LOCALAPPDATA%\WinTCP\Monitors\<id>.*), so it
    // may not contain a path separator, a drive colon, a wildcard, a quoting
    // character, or whitespace/control - anything that would escape the folder
    // or split a line.
    for (wchar_t c : id) {
        const bool bad = (c < 0x20) || c == L' ' || c == L'\\' || c == L'/' ||
                         c == L':' || c == L'*' || c == L'?' || c == L'"' ||
                         c == L'<' || c == L'>' || c == L'|';
        if (bad) {
            if (err)
                *err = L"monitor id may contain only letters, digits, '.', '_' and '-'";
            return false;
        }
    }
    if (intervalSeconds == 0) {
        if (err) *err = L"monitor interval must be at least 1 second";
        return false;
    }
    if (durationSeconds > kMonitorDurationMaxSec) {
        if (err) *err = L"monitor --duration is too large (max 86400 seconds)";
        return false;
    }
    if (!logPath.empty() && logPath.size() < 3) {
        if (err) *err = L"monitor log path is not a usable path";
        return false;
    }
    return true;
}

namespace {

// Narrow a wide string to bytes, substituting '?' above 0x7F. Only ever used on
// values that are ASCII in practice (addresses, ports, state words) and on a
// key/escape interior that only needs to be internally consistent; a full
// UTF-8 fold would drag a charset dependency into this otherwise-pure module.
std::string NarrowAscii(const std::wstring& s) {
    std::string out;
    out.reserve(s.size());
    for (wchar_t c : s)
        out.push_back((c >= 0x20 && c < 0x7F) ? static_cast<char>(c) : '?');
    return out;
}

void AppendJsonString(std::string& out, const char* key, const std::string& value) {
    if (key != nullptr) { out += '"'; out += key; out += "\":"; }
    out += '"';
    for (unsigned char ch : value) {
        switch (ch) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (ch < 0x20) {
                    char b[8];
                    std::snprintf(b, sizeof(b), "\\u%04x", static_cast<unsigned>(ch));
                    out += b;
                } else {
                    out += static_cast<char>(ch);
                }
        }
    }
    out += '"';
}

void AppendJsonNumber(std::string& out, const char* key, unsigned long long value) {
    if (key != nullptr) { out += '"'; out += key; out += "\":"; }
    char b[32];
    std::snprintf(b, sizeof(b), "%llu", value);
    out += b;
}

// One finished NDJSON object for an interval's event. `extra` (already a
// JSON fragment like ,"rx":4096,"tx":2048) is spliced in before the brace so a
// traffic event can carry deltas without a second builder.
std::string BuildEvent(const std::wstring& nowUtc, const char* kind,
                       const MonitorSample& s, const MonitorSample* from,
                       const char* extra) {
    std::string out = "{";
    AppendJsonString(out, "t", NarrowAscii(nowUtc));
    out += ',';
    AppendJsonString(out, "kind", kind);
    out += ',';
    AppendJsonNumber(out, "pid", s.pid);
    out += ',';
    AppendJsonString(out, "process", NarrowAscii(s.process));
    out += ',';
    AppendJsonString(out, "proto", NarrowAscii(s.proto));
    out += ',';
    AppendJsonString(out, "local", NarrowAscii(s.localEndpoint));
    out += ',';
    AppendJsonString(out, "remote", NarrowAscii(s.remoteEndpoint));
    out += ',';
    AppendJsonNumber(out, "lport", s.localPort);
    out += ',';
    AppendJsonNumber(out, "rport", s.remotePort);
    out += ',';
    AppendJsonString(out, "state", NarrowAscii(s.state));
    if (from != nullptr) {
        out += ',';
        AppendJsonString(out, "was", NarrowAscii(from->state));
    }
    if (extra != nullptr) out += extra;
    out += '}';
    return out;
}

}  // namespace

std::string MonitorKey(const MonitorSample& s) {
    std::string key;
    key += NarrowAscii(s.proto);
    key += '\x1f';
    key += NarrowAscii(s.localEndpoint);
    key += '\x1f';
    key += NarrowAscii(s.remoteEndpoint);
    key += '\x1f';
    key += std::to_string(s.pid);
    return key;
}

std::vector<std::string> RenderMonitorEvents(const MonitorDef& def,
                                             const std::vector<MonitorSample>& prev,
                                             const std::vector<MonitorSample>& cur,
                                             const std::wstring& nowUtc, bool first) {
    std::vector<std::string> events;
    if (first) return events;   // baseline: quiet, exactly like list --changes

    const MonitorFilter& f = def.what;
    auto eligible = [&f](const MonitorSample& s) {
        return f.MatchesProcess(s.process, s.pid) &&
               f.MatchesPorts(s.localPort, s.remotePort);
    };

    std::unordered_map<std::string, const MonitorSample*> curMap, prevMap;
    for (const MonitorSample& s : cur)  if (eligible(s)) curMap.emplace(MonitorKey(s), &s);
    for (const MonitorSample& s : prev) if (eligible(s)) prevMap.emplace(MonitorKey(s), &s);

    // disappear first: a session ending is the more interesting half of a pair.
    for (const auto& kv : prevMap) {
        if (curMap.find(kv.first) == curMap.end())
            events.push_back(BuildEvent(nowUtc, "disappear", *kv.second, nullptr, nullptr));
    }
    for (const auto& kv : curMap) {
        const MonitorSample& s = *kv.second;
        const auto pit = prevMap.find(kv.first);
        if (pit == prevMap.end())
            events.push_back(BuildEvent(nowUtc, "appear", s, nullptr, nullptr));
        else if (pit->second->state != s.state)
            events.push_back(BuildEvent(nowUtc, "state", s, pit->second, nullptr));
    }
    if (f.traffic) {
        for (const auto& kv : curMap) {
            const MonitorSample& s = *kv.second;
            const auto pit = prevMap.find(kv.first);
            if (pit == prevMap.end() || !s.hasBytes || !pit->second->hasBytes) continue;
            const unsigned long long drx =
                (s.trafficRx > pit->second->trafficRx) ? s.trafficRx - pit->second->trafficRx : 0ull;
            const unsigned long long dtx =
                (s.trafficTx > pit->second->trafficTx) ? s.trafficTx - pit->second->trafficTx : 0ull;
            if (drx == 0 && dtx == 0) continue;
            std::string extra = ",\"rx\":";
            char b[48];
            std::snprintf(b, sizeof(b), "%llu,\"tx\":%llu", drx, dtx);
            extra += b;
            events.push_back(BuildEvent(nowUtc, "traffic", s, nullptr, extra.c_str()));
        }
    }
    return events;
}

}  // namespace wintcp
