// WebUi.cpp
// SPDX-License-Identifier: Apache-2.0
// Local-only HTTP adapter for the shared WinTCP command/model layer.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <wincrypt.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <climits>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <locale>
#include <map>
#include <memory>
#include <functional>
#include <mutex>
#include <deque>
#include <thread>
#include <sstream>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "BlockConn.h"
#include "Commands.h"
#include "ConnectionStore.h"
#include "DnsResolver.h"
#include "Elevate.h"
#include "Settings.h"
#include "SocketTraffic.h"
#include "Utils.h"
#include "WebMetrics.h"
#include "WebProcesses.h"
#include "WebStatic.h"
#include "WebUi.h"

namespace wintcp {
namespace {

constexpr size_t kMaxHeaderBytes = 16384;
constexpr size_t kMaxBodyBytes = 65536;
constexpr size_t kMaxAssetBytes = 1024 * 1024;
constexpr size_t kMaxUploadBytes = 16 * 1024 * 1024;
constexpr int kExpectedConfigVersion = 3;
constexpr size_t kMaxAuditBytes = 2 * 1024 * 1024;
constexpr size_t kAuditRetention = 1000;
constexpr size_t kMaxPendingBlocks = 64;
constexpr size_t kMaxPendingConnectionActions = 64;
constexpr size_t kMaxPendingCliActions = 64;
constexpr size_t kMaxCliArgs = 64;
constexpr size_t kMaxCliArgBytes = 2048;
constexpr size_t kMaxCliOutputBytes = 64 * 1024;
constexpr DWORD kMaxCliExecutionMs = 30000;

struct HttpRequest {
    std::string method;
    std::string target;
    std::map<std::string, std::string> headers;
    std::string body;
};

struct HttpResponse {
    int status = 200;
    std::string contentType = "application/json; charset=utf-8";
    std::string body;
    std::string etag;
};

struct PendingBlock {
    RuleRequest rule;
    std::string scope;
    std::string ruleName;
    ULONGLONG expires = 0;
};

struct PendingCliAction {
    std::wstring verb;
    std::vector<std::wstring> args;
    ULONGLONG expires = 0;
};

struct PendingConnectionAction {
    Connection captured;
    ULONGLONG snapshotAgeMs = 0;
    ULONGLONG expires = 0;
};

struct PendingFirewallRuleAction {
    BlockedRule captured;
    RuleRequest createRequest;
    std::string operation;
    std::string ruleName;
    bool create = false;
    ULONGLONG expires = 0;
};

enum class WebUiLogLevel : unsigned char { Debug, Info, Warn, Error };

struct ServerContext {
    std::wstring executableDirectory;
    std::wstring dataDirectory;
    std::wstring geoIpDbDir;
    std::wstring configPath;
    std::mutex configMutex;
    std::mutex configApplyMutex;
    std::string configBytes;
    std::string configEtag;
    std::wstring auditPath;
    std::wstring logPath;
    WebUiLogLevel logLevel = WebUiLogLevel::Debug;
    std::string token;
    USHORT port = 0;
    SnapshotSource source;
    ConnectionStore store;
    DnsResolver dnsResolver;
    bool dnsAvailable = false;
    std::unordered_set<std::wstring> dnsCompleted;
    std::deque<std::wstring> dnsCompletionOrder;
    MetricsCollector metricsCollector;
    // GeoIP database path, cached from config so the connection refresher can
    // re-apply GeoIP enrichment without re-reading the config file every tick.
    std::wstring geoIpDbPath;
    // Process table. Sampled and OWNED by the refresher thread; requests only
    // read the published snapshot through ProcessSnapshot's own mutex.
    ProcessSnapshot processes;
    // Bumped by every endpoint that reads the store. The refresher uses it to
    // decide whether anyone is still looking.
    std::atomic<ULONGLONG> lastStoreAccess{0};
    // Set by the refresher thread. Read endpoints use it to say how old the
    // rows they are reporting are, so a stale summary is labelled rather than
    // passed off as live.
    std::atomic<ULONGLONG> connectionSnapshotTick{0};
    std::atomic<bool> connectionRefreshFailed{false};
    std::map<std::string, PendingBlock> pendingBlocks;
    std::mutex blockActionMutex;
    std::map<std::string, PendingCliAction> pendingCliActions;
    std::mutex connectionActionMutex;
    std::map<std::string, PendingConnectionAction> pendingConnectionActions;
    std::mutex firewallActionMutex;
    std::map<std::string, PendingFirewallRuleAction> pendingFirewallActions;
};

std::atomic<bool> g_stop{false};

// Lives for the life of RunWebUiServer so the Ctrl+C handler and the stop
// watcher share exactly one "stop now" signal. See the exit path there. Atomic:
// the handler runs on a different thread from the one that publishes it, so the
// read/write must be well-defined, not merely atomic-in-practice on x86.
static std::atomic<HANDLE> g_stopEvent{nullptr};

// Serialises ConnectionStore refreshes across per-connection serve threads (see
// WebUiAcceptLoop): with one thread per client, two /api/connections requests
// could otherwise race on the shared store. The SSE stream itself takes no lock
// - it only ever writes to its own socket.
std::mutex g_storeMutex;

constexpr size_t kMaxWebDnsCompletions = 4096;

std::wstring WebDnsKey(const std::wstring& address) {
    const size_t scope = address.find(L'%');
    return scope == std::wstring::npos ? address : address.substr(0, scope);
}

// Called only while g_storeMutex is held. Mark the row pending before offering
// it, so the very first JSON response exposes an honest in-progress state.
void OfferWebDnsForRows(ServerContext& context) {
    if (!context.dnsAvailable) return;
    std::unordered_set<std::wstring> offered;
    for (size_t i = 0; i < context.store.View().size(); ++i) {
        const Connection* row = context.store.ViewRow(i);
        if (row == nullptr || (row->flags & kRowRemoved) != 0 ||
            row->display.remoteAddress.empty() || row->display.remoteAddress == L"*") continue;
        const std::wstring& addr = row->display.remoteAddress;
        const std::wstring& host = row->display.hostname;
        const std::wstring key = WebDnsKey(addr);
        if (!host.empty() || context.dnsCompleted.find(key) != context.dnsCompleted.end() ||
            !offered.insert(addr).second) continue;
        context.store.SetHostname(addr, DnsResolver::kPendingHost);
        context.dnsResolver.Offer(addr);
    }
}

// Refresh the connection store on a background thread, so that the read-only
// endpoints answer from data that is already there.
//
// WHY THIS EXISTS: /api/connections refreshes the store inline as part of
// building its own response. The summary endpoints (/api/processes,
// /api/network/summary, /api/geo/summary) only read it. With nothing else
// populating it they returned empty objects on a cold server, and on a warm one
// they depended on the browser having polled /api/connections first - an
// ordering coupling that is both invisible in the code and wrong: the process
// list should not depend on which endpoint the browser happened to ask for.
//
// C-8 forbids running an IP Helper scan inside a request, and running one in
// three more handlers to paper over this would make that worse, not better. So
// the refresh moved off the request path entirely.
//
// It runs on the same g_storeMutex the inline /api/connections refresh takes, so
// the two serialise rather than race: the store is never observed mid-refresh.
// It also stops itself when nothing has asked for connections recently, so a
// server nobody is looking at costs nothing.
constexpr DWORD kConnRefreshIdleMs = 30000;   // below this, stay at 1 Hz
constexpr DWORD kConnRefreshStepMs = 2000;    // above this, idle cadence

DWORD WINAPI ConnectionRefresherThread(LPVOID param) {
    auto* context = static_cast<ServerContext*>(param);
    if (context == nullptr) return 0;
    // The one owner of this sampler. Nothing else touches it, so its internal
    // CPU-time baselines cannot be raced.
    WebProcessSampler processSampler;
    while (!g_stop.load()) {
        // "Someone is looking" is the same signal the metrics sampler uses: a
        // read endpoint touched the store recently.
        const ULONGLONG now = ::GetTickCount64();
        const ULONGLONG accessTick = context->lastStoreAccess.load();
        const ULONGLONG sinceAccess = now >= accessTick ? now - accessTick : 0;
        const DWORD stepMs = (sinceAccess < kConnRefreshIdleMs) ? 1000
                                                               : kConnRefreshStepMs;
        ULONGLONG deadline = now + stepMs;
        while (!g_stop.load() && ::GetTickCount64() < deadline) ::Sleep(50);
        if (g_stop.load()) break;

        ListOptions options;
        options.format = "json";
        // The refresher never enables the per-socket traffic scan: its probe
        // threads can wedge in an uncancelable kernel call holding the
        // process-wide Winsock lock, and a background thread doing that forever
        // is strictly worse than /api/connections doing it once per request.
        options.webMetadata = true;
        // Match the /api/connections column set so the store already carries the
        // enrichment template evaluators need. GeoIP and signature verification
        // are enabled here when configured - the refresher applies them once
        // per pass, caching signatures per image path.
        options.columns = {
            COL_PROTO, COL_LOCAL, COL_LPORT, COL_REMOTE, COL_RPORT, COL_STATE,
            COL_PID, COL_PROCESS, COL_SERVICE, COL_PATH,
            COL_DURATION, COL_SIGNATURE, COL_PPID, COL_INTEGRITY, COL_COUNTRY,
        };
        if (context->source.GeoIpLoaded()) {
            options.geoIpPath = context->geoIpDbPath;
        }
        options.signatures = true;
        bool ok = false;
        {
            std::lock_guard<std::mutex> lock(g_storeMutex);
            const CommandResult result = CmdListInto(context->source, context->store,
                                                     options);
            ok = (result.exitCode == kExitOk);
            if (ok) {
                OfferWebDnsForRows(*context);
                context->connectionSnapshotTick.store(::GetTickCount64());
                context->connectionRefreshFailed.store(false);
            } else {
                context->connectionRefreshFailed.store(true);
            }
        }
        if (!ok) ::Sleep(1000);   // do not spin on a failing source

        // Process table. Sampled on this thread, outside the store lock, because
        // it walks a different kernel structure entirely (Toolhelp, not IP
        // Helper) and the two have no reason to block each other.
        //
        // SKIPPED WHEN NOBODY IS LOOKING. Walking 350+ processes means opening
        // each one for CPU times, and doing that forever for a server nobody has
        // looked at is a pure tax: measured idle cost was 11% of one core before
        // this guard, against the 1% budget in docs/webui.md. The connection
        // refresh above still runs, because a connection is what the summaries
        // are about; the process table is only worth enumerating when a request
        // will actually read it.
        const ULONGLONG lastAccessTick = context->lastStoreAccess.load();
        const ULONGLONG sampleTick = ::GetTickCount64();
        if (sampleTick - lastAccessTick >= kConnRefreshIdleMs) {
            continue;
        }

        std::map<DWORD, int> connectionsByPid;
        std::map<DWORD, int> listenersByPid;
        {
            std::lock_guard<std::mutex> lock(g_storeMutex);
            for (size_t i = 0; i < context->store.View().size(); ++i) {
                const Connection* row = context->store.ViewRow(i);
                if (row == nullptr || (row->flags & kRowRemoved) != 0) continue;
                if (row->identity.pid == 0) continue;
                connectionsByPid[row->identity.pid]++;
                if (row->identity.protocol == IPPROTO_TCP &&
                    row->keys.stateLabel == L"LISTENING") {
                    listenersByPid[row->identity.pid]++;
                }
            }
        }
        const WebProcessSnapshot processes =
            processSampler.Sample(connectionsByPid, listenersByPid,
                                  context->connectionSnapshotTick.load() > 0);
        context->processes.Publish(processes);
    }
    return 0;
}

BOOL WINAPI WebUiControlHandler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT ||
        type == CTRL_CLOSE_EVENT || type == CTRL_LOGOFF_EVENT ||
        type == CTRL_SHUTDOWN_EVENT) {
        g_stop.store(true);
        if (HANDLE ev = g_stopEvent.load(); ev != nullptr) ::SetEvent(ev);  // wake the watcher
        return TRUE;
    }
    return FALSE;
}

std::string LowerAscii(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

std::string TrimAscii(const std::string& s) {
    size_t first = 0;
    while (first < s.size() && (s[first] == ' ' || s[first] == '\t')) ++first;
    size_t last = s.size();
    while (last > first && (s[last - 1] == ' ' || s[last - 1] == '\t' ||
                            s[last - 1] == '\r')) --last;
    return s.substr(first, last - first);
}

// The three emitters below are declared in WebUi.h so the unit tests can assert
// their output. Everything after this point is still file-local.

}  // namespace

std::string JsonQuote(const std::string& s) {
    static const char hex[] = "0123456789abcdef";
    std::string out = "\"";
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    out += "\\u00";
                    out += hex[c >> 4];
                    out += hex[c & 0x0f];
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    out += '"';
    return out;
}

std::string UtcTimestamp() {
    SYSTEMTIME t = {};
    ::GetSystemTime(&t);
    char out[40] = {};
    (void)::sprintf_s(out, sizeof(out), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
                      t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute,
                      t.wSecond, t.wMilliseconds);
    return out;
}

std::wstring ReadEnvironmentVariable(const wchar_t* name) {
    std::vector<wchar_t> value(32768, L'\0');
    const DWORD size = ::GetEnvironmentVariableW(name, value.data(),
                                                  static_cast<DWORD>(value.size()));
    if (size == 0 || size >= value.size()) return {};
    return std::wstring(value.data(), size);
}

WebUiLogLevel ParseWebUiLogLevel(std::wstring value) {
    for (wchar_t& c : value) {
        if (c >= L'a' && c <= L'z') c = static_cast<wchar_t>(c - L'a' + L'A');
    }
    if (value == L"INFO") return WebUiLogLevel::Info;
    if (value == L"WARN" || value == L"WARNING") return WebUiLogLevel::Warn;
    if (value == L"ERROR") return WebUiLogLevel::Error;
    return WebUiLogLevel::Debug;
}

const char* WebUiLogLevelName(WebUiLogLevel level) {
    switch (level) {
        case WebUiLogLevel::Info: return "INFO";
        case WebUiLogLevel::Warn: return "WARN";
        case WebUiLogLevel::Error: return "ERROR";
        default: return "DEBUG";
    }
}

bool InitializeWebUiLogging(ServerContext* context) {
    if (context == nullptr) return false;
    context->logLevel = ParseWebUiLogLevel(
        ReadEnvironmentVariable(L"WINTCP_WEBUI_LOG_LEVEL"));
    context->logPath = ReadEnvironmentVariable(L"WINTCP_WEBUI_LOG_FILE");
    if (context->logPath.empty())
        context->logPath = context->dataDirectory + L"\\webui.log";
    std::error_code ec;
    const std::filesystem::path path(context->logPath);
    if (!path.parent_path().empty())
        std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) return false;
    HANDLE file = ::CreateFileW(context->logPath.c_str(), FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    ::CloseHandle(file);
    return true;
}

void RotateWebUiLog(const std::wstring& path) {
    HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return;
    LARGE_INTEGER size = {};
    const bool shouldRotate = ::GetFileSizeEx(file, &size) != FALSE &&
                              size.QuadPart > 2LL * 1024 * 1024;
    ::CloseHandle(file);
    if (!shouldRotate) return;
    const std::wstring first = path + L".1";
    const std::wstring second = path + L".2";
    (void)::DeleteFileW(second.c_str());
    (void)::MoveFileExW(first.c_str(), second.c_str(), MOVEFILE_REPLACE_EXISTING);
    (void)::MoveFileExW(path.c_str(), first.c_str(), MOVEFILE_REPLACE_EXISTING);
}

void WriteWebUiLog(const ServerContext& context, WebUiLogLevel level,
                   std::string message) {
    if (static_cast<unsigned char>(level) <
        static_cast<unsigned char>(context.logLevel)) return;
    if (message.size() > 2048) message.resize(2048);
    RotateWebUiLog(context.logPath);
    const std::string line = UtcTimestamp() + " [" + WebUiLogLevelName(level) +
        "] pid=" + std::to_string(::GetCurrentProcessId()) + " " + message + "\r\n";
    HANDLE file = ::CreateFileW(context.logPath.c_str(), FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    (void)::WriteFile(file, line.data(), static_cast<DWORD>(line.size()),
                      &written, nullptr);
    ::CloseHandle(file);
}

bool ShouldOpenWebUiBrowser() {
    std::wstring value = ReadEnvironmentVariable(L"WINTCP_WEBUI_OPEN_BROWSER");
    for (wchar_t& c : value) {
        if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c - L'A' + L'a');
    }
    return value.empty() || (value != L"0" && value != L"false" &&
                             value != L"no" && value != L"off");
}

bool Utf8ToWide(const std::string& text, std::wstring* out) {
    if (out == nullptr || text.size() > static_cast<size_t>(INT_MAX)) return false;
    if (text.empty()) { out->clear(); return true; }
    const int count = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                             text.data(), static_cast<int>(text.size()),
                                             nullptr, 0);
    if (count <= 0) return false;
    out->resize(static_cast<size_t>(count));
    return ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                                 static_cast<int>(text.size()), out->data(), count) == count;
}

class JsonValidator {
public:
    explicit JsonValidator(const std::string& text) : text_(text) {}

    bool IsObject() {
        SkipSpace();
        if (AtEnd() || text_[pos_] != '{' || !Value(0)) return false;
        SkipSpace();
        return AtEnd();
    }

private:
    bool AtEnd() const { return pos_ >= text_.size(); }
    void SkipSpace() {
        while (!AtEnd() && (text_[pos_] == ' ' || text_[pos_] == '\t' ||
                            text_[pos_] == '\r' || text_[pos_] == '\n')) ++pos_;
    }
    bool Take(char c) {
        SkipSpace();
        if (AtEnd() || text_[pos_] != c) return false;
        ++pos_;
        return true;
    }
    bool String() {
        if (!Take('"')) return false;
        while (!AtEnd()) {
            const unsigned char c = static_cast<unsigned char>(text_[pos_++]);
            if (c == '"') return true;
            if (static_cast<unsigned char>(c) < 0x20) return false;
            if (c != '\\') continue;
            if (AtEnd()) return false;
            const char e = text_[pos_++];
            if (e == '"' || e == '\\' || e == '/' || e == 'b' || e == 'f' ||
                e == 'n' || e == 'r' || e == 't') continue;
            if (e != 'u' || pos_ + 4 > text_.size()) return false;
            for (int i = 0; i < 4; ++i) {
                const unsigned char h = static_cast<unsigned char>(text_[pos_++]);
                if (!std::isxdigit(h)) return false;
            }
        }
        return false;
    }
    bool Number() {
        const size_t start = pos_;
        if (!AtEnd() && text_[pos_] == '-') ++pos_;
        if (AtEnd()) return false;
        if (text_[pos_] == '0') ++pos_;
        else {
            if (text_[pos_] < '1' || text_[pos_] > '9') return false;
            while (!AtEnd() && text_[pos_] >= '0' && text_[pos_] <= '9') ++pos_;
        }
        if (!AtEnd() && text_[pos_] == '.') {
            ++pos_;
            const size_t fraction = pos_;
            while (!AtEnd() && text_[pos_] >= '0' && text_[pos_] <= '9') ++pos_;
            if (fraction == pos_) return false;
        }
        if (!AtEnd() && (text_[pos_] == 'e' || text_[pos_] == 'E')) {
            ++pos_;
            if (!AtEnd() && (text_[pos_] == '+' || text_[pos_] == '-')) ++pos_;
            const size_t exponent = pos_;
            while (!AtEnd() && text_[pos_] >= '0' && text_[pos_] <= '9') ++pos_;
            if (exponent == pos_) return false;
        }
        return pos_ > start;
    }
    bool Literal(const char* literal) {
        const size_t length = std::char_traits<char>::length(literal);
        if (pos_ + length > text_.size() || text_.compare(pos_, length, literal) != 0)
            return false;
        pos_ += length;
        return true;
    }
    bool Value(unsigned depth) {
        if (depth > 32) return false;
        SkipSpace();
        if (AtEnd()) return false;
        const char c = text_[pos_];
        if (c == '"') return String();
        if (c == '{') {
            ++pos_;
            SkipSpace();
            if (Take('}')) return true;
            for (;;) {
                if (!String() || !Take(':') || !Value(depth + 1)) return false;
                SkipSpace();
                if (Take('}')) return true;
                if (!Take(',')) return false;
            }
        }
        if (c == '[') {
            ++pos_;
            SkipSpace();
            if (Take(']')) return true;
            for (;;) {
                if (!Value(depth + 1)) return false;
                SkipSpace();
                if (Take(']')) return true;
                if (!Take(',')) return false;
            }
        }
        if (c == 't') return Literal("true");
        if (c == 'f') return Literal("false");
        if (c == 'n') return Literal("null");
        return Number();
    }

    const std::string& text_;
    size_t pos_ = 0;
};

bool IsValidJsonObject(const std::string& text) {
    std::wstring wide;
    if (!Utf8ToWide(text, &wide)) return false;
    return JsonValidator(text).IsObject();
}

// Scan a JSON object for a top-level string field named `key`. Returns true on
// success and writes the unescaped value to `out`. A minimal extractor: the
// config is small (kMaxBodyBytes) and validated before this is called, so a
// bounded linear scan is sufficient and allocation-free.
bool ExtractJsonString(const std::string& text, const std::string& key,
                       std::string* out) {
    if (out == nullptr) return false;
    const std::string needle = "\"" + key + "\"";
    size_t pos = 0;
    for (;;) {
        pos = text.find(needle, pos);
        if (pos == std::string::npos) return false;
        size_t p = pos + needle.size();
        // Skip whitespace between key and ':'.
        while (p < text.size() && (text[p] == ' ' || text[p] == '\t')) ++p;
        if (p >= text.size() || text[p] != ':') { ++pos; continue; }
        ++p;
        while (p < text.size() && (text[p] == ' ' || text[p] == '\t')) ++p;
        if (p >= text.size() || text[p] != '"') { ++pos; continue; }
        ++p;
        out->clear();
        while (p < text.size()) {
            const char c = text[p++];
            if (c == '"') return true;
            if (static_cast<unsigned char>(c) < 0x20) return false;
            if (c == '\\') {
                if (p >= text.size()) return false;
                const char e = text[p++];
                switch (e) {
                    case '"':  out->push_back('"');  break;
                    case '\\': out->push_back('\\'); break;
                    case '/':  out->push_back('/');  break;
                    case 'b':  out->push_back('\b'); break;
                    case 'f':  out->push_back('\f'); break;
                    case 'n':  out->push_back('\n'); break;
                    case 'r':  out->push_back('\r'); break;
                    case 't':  out->push_back('\t'); break;
                    default: return false;
                }
            } else {
                out->push_back(c);
            }
        }
        return false;
    }
}

// Strict decimal integer parse. Digits only, no sign, no whitespace, no
// trailing junk, and no overflow. Never throws, never allocates.
// std::stoull/std::stoul are the wrong tool for untrusted query strings: they
// throw std::invalid_argument / std::out_of_range, and an escaping exception
// from a request handler terminates the process.
bool ParseUint64Strict(const std::string& text, uint64_t* out) {
    if (out == nullptr || text.empty() || text.size() > 20) return false;
    uint64_t value = 0;
    for (char c : text) {
        if (c < '0' || c > '9') return false;
        const uint64_t digit = static_cast<uint64_t>(c - '0');
        if (value > (UINT64_MAX - digit) / 10) return false;   // overflow
        value = value * 10 + digit;
    }
    *out = value;
    return true;
}

// Format a double as a JSON number: classic locale, never scientific notation,
// integral values printed as integers. std::ostringstream's default turned
// 33277400000 bytes into "3.32774e+10" - valid JSON, but it threw away the low
// digits and read as noise on the dashboard.
std::string JsonNumber(double value) {
    if (!std::isfinite(value)) return "null";     // NaN/Inf are not JSON
    std::ostringstream v;
    v.imbue(std::locale::classic());
    if (value == std::floor(value) && std::fabs(value) < 9.0e15) {
        v << static_cast<long long>(value);
        return v.str();
    }
    v << std::fixed << std::setprecision(3) << value;
    std::string text = v.str();
    const size_t dot = text.find('.');
    if (dot != std::string::npos) {
        size_t last = text.size();
        while (last > dot + 1 && text[last - 1] == '0') --last;
        if (last == dot + 1) --last;              // drop the bare "."
        text.resize(last);
    }
    return text.empty() ? "0" : text;
}

std::string JsonExactUint64(uint64_t value) {
    const std::string digits = std::to_string(value);
    return value <= 9007199254740991ULL ? digits : JsonQuote(digits);
}

namespace {

bool GetExecutableDirectory(std::wstring* directory) {
    if (directory == nullptr) return false;
    std::vector<wchar_t> path(32768, L'\0');
    const DWORD n = ::GetModuleFileNameW(nullptr, path.data(),
                                         static_cast<DWORD>(path.size()));
    if (n == 0 || n >= path.size() - 1) return false;
    std::wstring full(path.data(), n);
    const size_t slash = full.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return false;
    full.resize(slash + 1);
    *directory = std::move(full);
    return true;
}

bool PrepareDataPaths(ServerContext* context) {
    if (context == nullptr) return false;
    const DWORD overrideSize = ::GetEnvironmentVariableW(L"WINTCP_WEBUI_DATA_DIR", nullptr, 0);
    if (overrideSize > 0) {
        if (overrideSize > 32768) return false;
        std::vector<wchar_t> buffer(overrideSize);
        const DWORD length = ::GetEnvironmentVariableW(L"WINTCP_WEBUI_DATA_DIR",
                                                        buffer.data(), overrideSize);
        if (length == 0 || length >= overrideSize) return false;
        context->dataDirectory.assign(buffer.data(), length);
        if (!std::filesystem::path(context->dataDirectory).is_absolute()) return false;
    } else {
    PWSTR local = nullptr;
    const HRESULT hr = ::SHGetKnownFolderPath(FOLDERID_LocalAppData,
                                               KF_FLAG_CREATE, nullptr, &local);
    if (FAILED(hr) || local == nullptr) return false;
    std::wstring base(local);
    ::CoTaskMemFree(local);
    context->dataDirectory = base + L"\\WinTCP\\WebUi";
    }
    std::error_code ec;
    std::filesystem::create_directories(context->dataDirectory, ec);
    if (ec) return false;
    context->configPath = context->dataDirectory + L"\\config.json";
    context->auditPath = context->dataDirectory + L"\\audit.ndjson";
    context->geoIpDbDir = context->dataDirectory + L"\\db";
    std::error_code ec2;
    std::filesystem::create_directories(context->geoIpDbDir, ec2);
    return true;
}

bool RandomHex(size_t bytes, std::string* out) {
    if (out == nullptr || bytes == 0 || bytes > 64) return false;
    std::vector<BYTE> random(bytes);
    if (!BCRYPT_SUCCESS(::BCryptGenRandom(nullptr, random.data(),
                                          static_cast<ULONG>(random.size()),
                                          BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        return false;
    }
    static const char hex[] = "0123456789abcdef";
    out->clear();
    out->reserve(bytes * 2);
    for (BYTE b : random) {
        out->push_back(hex[b >> 4]);
        out->push_back(hex[b & 0x0f]);
    }
    return true;
}

bool ReadFileBounded(const std::wstring& path, size_t limit, std::string* out) {
    if (out == nullptr) return false;
    std::ifstream file(std::filesystem::path(path), std::ios::binary);
    if (!file) return false;
    file.seekg(0, std::ios::end);
    const std::streamoff size = file.tellg();
    if (size < 0 || static_cast<uint64_t>(size) > limit) return false;
    file.seekg(0, std::ios::beg);
    out->assign(static_cast<size_t>(size), '\0');
    if (size != 0) file.read(out->data(), static_cast<std::streamsize>(size));
    return file.good() || file.eof();
}

bool WriteFileAtomic(const std::wstring& path, const std::string& body) {
    const std::wstring temp = path + L".tmp";
    HANDLE file = ::CreateFileW(temp.c_str(), GENERIC_WRITE, 0, nullptr,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    size_t offset = 0;
    bool ok = true;
    while (offset < body.size()) {
        const DWORD chunk = static_cast<DWORD>(std::min<size_t>(body.size() - offset,
                                                                 1024 * 1024));
        DWORD written = 0;
        if (!::WriteFile(file, body.data() + offset, chunk, &written, nullptr) ||
            written != chunk) {
            ok = false;
            break;
        }
        offset += written;
    }
    if (ok) ok = ::FlushFileBuffers(file) != FALSE;
    ::CloseHandle(file);
    if (!ok) { ::DeleteFileW(temp.c_str()); return false; }
    if (!::MoveFileExW(temp.c_str(), path.c_str(),
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        ::DeleteFileW(temp.c_str());
        return false;
    }
    return true;
}

// Load the GeoIP database referenced by config.geoIpDbPath or
// config.preferences.geoIpDbPath, if any. Logs the outcome. A missing/empty
// path is not an error (GeoIP is optional). Designed to be called at service
// startup and again after the config is persisted.
void LoadGeoIpFromConfig(ServerContext& context) {
    std::string configText;
    if (!ReadFileBounded(context.configPath, kMaxBodyBytes, &configText)) {
        return;  // First run: no persisted config yet.
    }
    std::string dbPathUtf8;
    ExtractJsonString(configText, "geoIpDbPath", &dbPathUtf8);
    if (dbPathUtf8.empty()) {
        // v3 shape: look under config.preferences.geoIpDbPath.
        size_t prefStart = configText.find("\"preferences\"");
        if (prefStart != std::string::npos) {
            size_t colon = configText.find(':', prefStart + 13);
            if (colon != std::string::npos) {
                size_t brace = configText.find('{', colon);
                if (brace != std::string::npos) {
                    size_t depth = 0;
                    size_t end = brace;
                    for (size_t p = brace; p < configText.size(); ++p) {
                        if (configText[p] == '{') ++depth;
                        else if (configText[p] == '}') {
                            if (--depth == 0) { end = p; break; }
                        }
                    }
                    std::string prefsText = configText.substr(brace, end - brace + 1);
                    ExtractJsonString(prefsText, "geoIpDbPath", &dbPathUtf8);
                }
            }
        }
    }
    std::lock_guard<std::mutex> lock(g_storeMutex);
    if (dbPathUtf8.empty()) {
        context.geoIpDbPath.clear();
        context.source.UnloadGeoIp();
        return;
    }
    std::wstring dbPath;
    if (!Utf8ToWide(dbPathUtf8, &dbPath)) {
        context.geoIpDbPath.clear();
        context.source.UnloadGeoIp();
        WriteWebUiLog(context, WebUiLogLevel::Warn,
                      "geoIpDbPath in config is not valid UTF-8");
        return;
    }
    if (dbPath == context.geoIpDbPath && context.source.GeoIpLoaded()) return;
    context.geoIpDbPath = dbPath;
    std::wstring error;
    if (context.source.LoadGeoIp(dbPath.c_str(), &error)) {
        WriteWebUiLog(context, WebUiLogLevel::Info,
                      "GeoIP database loaded from " + WideToUtf8(dbPath));
    } else {
        WriteWebUiLog(context, WebUiLogLevel::Error,
                      "GeoIP database failed to load: " + WideToUtf8(error));
    }
}

bool AppendAudit(ServerContext& context, const std::string& event) {
    if (!IsValidJsonObject(event) || event.size() > 4096) return false;
    std::error_code ec;
    const std::filesystem::path path(context.auditPath);
    if (std::filesystem::exists(path, ec) && !ec &&
        std::filesystem::file_size(path, ec) >= kMaxAuditBytes) {
        const std::wstring one = context.auditPath + L".1";
        const std::wstring two = context.auditPath + L".2";
        ::DeleteFileW(two.c_str());
        if (::GetFileAttributesW(one.c_str()) != INVALID_FILE_ATTRIBUTES &&
            !::MoveFileExW(one.c_str(), two.c_str(), MOVEFILE_REPLACE_EXISTING))
            return false;
        if (!::MoveFileExW(context.auditPath.c_str(), one.c_str(),
                           MOVEFILE_REPLACE_EXISTING)) return false;
    }
    std::ofstream file(path, std::ios::binary | std::ios::app);
    if (!file) return false;
    file << "{\"time\":" << JsonQuote(UtcTimestamp())
         << ",\"event\":" << event << "}\n";
    file.flush();
    return file.good();
}

bool ContainsIgnoreCase(const std::string& hay, const std::string& needle) {
    if (needle.empty()) return true;
    auto it = std::search(hay.begin(), hay.end(), needle.begin(), needle.end(),
        [](char a, char b) {
            return std::tolower(static_cast<unsigned char>(a)) ==
                   std::tolower(static_cast<unsigned char>(b));
        });
    return it != hay.end();
}

// Defensive at serve-time: the session token is already excluded from audit at
// write-time (see the /api/audit POST guard), but mask it here too so no path
// can leak it through the Web UI, even against a future record schema.
void RedactAudit(std::string& row, const std::string& token) {
    if (token.empty()) return;
    const std::string mask = "<redacted>";
    for (size_t pos = 0; (pos = row.find(token, pos)) != std::string::npos;
         pos += mask.size()) {
        row.replace(pos, token.size(), mask);
    }
}

enum class AuditFormat { Json, Ndjson };

std::string ReadAudit(ServerContext& context, const std::string& search, AuditFormat format) {
    std::ifstream file(std::filesystem::path(context.auditPath), std::ios::binary);
    if (!file) {
        return format == AuditFormat::Ndjson ? std::string() : "[]";
    }
    std::vector<std::string> rows;
    std::string line;
    while (std::getline(file, line)) {
        if (line.size() <= 8192 && IsValidJsonObject(line)) {
            rows.push_back(line);
            if (rows.size() > kAuditRetention) rows.erase(rows.begin());
        }
    }
    std::string out;
    if (format == AuditFormat::Json) out = "[";
    size_t emitted = 0;
    for (auto& row : rows) {
        RedactAudit(row, context.token);
        if (!search.empty() && !ContainsIgnoreCase(row, search)) continue;
        if (emitted != 0) out += (format == AuditFormat::Ndjson ? "\n" : ",");
        out += row;
        ++emitted;
    }
    if (format == AuditFormat::Json) {
        out += "]";
    } else if (emitted != 0) {
        out += "\n";
    }
    return out;
}

bool ReceiveRequest(SOCKET client, HttpRequest* request, int* errorStatus) {
    if (request == nullptr || errorStatus == nullptr) return false;
    std::string data;
    data.reserve(4096);
    size_t headerEnd = std::string::npos;
    std::array<char, 4096> buffer = {};
    while (headerEnd == std::string::npos) {
        const int n = ::recv(client, buffer.data(), static_cast<int>(buffer.size()), 0);
        if (n <= 0) { *errorStatus = 400; return false; }
        data.append(buffer.data(), static_cast<size_t>(n));
        if (data.size() > kMaxHeaderBytes) { *errorStatus = 431; return false; }
        headerEnd = data.find("\r\n\r\n");
    }
    const std::string headers = data.substr(0, headerEnd);
    const size_t firstEnd = headers.find("\r\n");
    const std::string first = headers.substr(0, firstEnd);
    {
        std::istringstream line(first);
        std::string version;
        if (!(line >> request->method >> request->target >> version) ||
            (version != "HTTP/1.1" && version != "HTTP/1.0") ||
            request->target.empty() || request->target[0] != '/') {
            *errorStatus = 400;
            return false;
        }
    }
    size_t pos = firstEnd == std::string::npos ? headers.size() : firstEnd + 2;
    while (pos < headers.size()) {
        const size_t end = headers.find("\r\n", pos);
        const std::string row = headers.substr(pos, end == std::string::npos
                                                       ? std::string::npos : end - pos);
        const size_t colon = row.find(':');
        if (colon == std::string::npos || colon == 0) { *errorStatus = 400; return false; }
        const std::string key = LowerAscii(row.substr(0, colon));
        if (request->headers.find(key) != request->headers.end()) {
            *errorStatus = 400;
            return false;
        }
        request->headers[key] = TrimAscii(row.substr(colon + 1));
        if (end == std::string::npos) break;
        pos = end + 2;
    }
    if (request->headers.find("transfer-encoding") != request->headers.end()) {
        *errorStatus = 400;
        return false;
    }
    const bool isUpload = request->method == "POST" &&
                          request->target.find("/api/geoip/upload") == 0;
    const size_t maxBody = isUpload ? kMaxUploadBytes : kMaxBodyBytes;
    size_t contentLength = 0;
    const auto length = request->headers.find("content-length");
    if (length != request->headers.end()) {
        if (length->second.empty()) { *errorStatus = 400; return false; }
        for (char c : length->second) {
            if (c < '0' || c > '9') {
                *errorStatus = 400;
                return false;
            }
            const size_t digit = static_cast<size_t>(c - '0');
            if (contentLength > (maxBody - digit) / 10) {
                *errorStatus = 413;
                return false;
            }
            contentLength = contentLength * 10 + digit;
        }
    }
    if (contentLength > maxBody) { *errorStatus = 413; return false; }
    const size_t bodyStart = headerEnd + 4;
    if (data.size() > bodyStart) request->body = data.substr(bodyStart);
    while (request->body.size() < contentLength) {
        const int n = ::recv(client, buffer.data(), static_cast<int>(buffer.size()), 0);
        if (n <= 0) { *errorStatus = 400; return false; }
        request->body.append(buffer.data(), static_cast<size_t>(n));
        if (request->body.size() > contentLength) { *errorStatus = 400; return false; }
    }
    if (request->body.size() != contentLength) { *errorStatus = 400; return false; }
    return true;
}

bool SendAll(SOCKET client, const char* data, size_t size) {
    size_t offset = 0;
    while (offset < size) {
        const int n = ::send(client, data + offset,
                             static_cast<int>(std::min<size_t>(size - offset, INT_MAX)), 0);
        if (n <= 0) return false;
        offset += static_cast<size_t>(n);
    }
    return true;
}

void SendResponse(SOCKET client, const HttpResponse& response, bool headOnly) {
    const char* reason = "OK";
    switch (response.status) {
        case 204: reason = "No Content"; break;
        case 400: reason = "Bad Request"; break;
        case 401: reason = "Unauthorized"; break;
        case 403: reason = "Forbidden"; break;
        case 404: reason = "Not Found"; break;
        case 405: reason = "Method Not Allowed"; break;
        case 409: reason = "Conflict"; break;
        case 410: reason = "Gone"; break;
        case 412: reason = "Precondition Failed"; break;
        case 413: reason = "Payload Too Large"; break;
        case 415: reason = "Unsupported Media Type"; break;
        case 431: reason = "Request Header Fields Too Large"; break;
        case 500: reason = "Internal Server Error"; break;
        case 503: reason = "Service Unavailable"; break;
        default: break;
    }
    std::ostringstream headers;
    headers << "HTTP/1.1 " << response.status << " " << reason << "\r\n";
    if (!response.etag.empty()) headers << "ETag: " << response.etag << "\r\n";
    headers
            << "Content-Type: " << response.contentType << "\r\n"
            << "Content-Length: " << response.body.size() << "\r\n"
            << "Cache-Control: no-store\r\n"
            << "X-Content-Type-Options: nosniff\r\n"
            << "X-Frame-Options: DENY\r\n"
            << "Referrer-Policy: no-referrer\r\n"
            << "Content-Security-Policy: default-src 'self'; connect-src 'self'; "
               "style-src 'self'; script-src 'self'; worker-src 'self'; font-src 'self'; "
               "img-src 'self' data:; object-src 'none'; base-uri 'none'; "
               "frame-ancestors 'none'\r\n"
            << "Connection: close\r\n\r\n";
    const std::string head = headers.str();
    (void)SendAll(client, head.data(), head.size());
    if (!headOnly && !response.body.empty())
        (void)SendAll(client, response.body.data(), response.body.size());
}

bool ValidHostAndOrigin(const ServerContext& context, const HttpRequest& request) {
    const std::string expected = "127.0.0.1:" + std::to_string(context.port);
    const auto host = request.headers.find("host");
    if (host == request.headers.end() || LowerAscii(host->second) != expected) return false;
    const auto origin = request.headers.find("origin");
    if (origin != request.headers.end() &&
        LowerAscii(origin->second) != "http://" + expected) return false;
    return true;
}

bool ContentTypeIs(const HttpRequest& request, const char* expected) {
    const auto header = request.headers.find("content-type");
    if (header == request.headers.end()) return false;
    std::string contentType = LowerAscii(header->second);
    const size_t semicolon = contentType.find(';');
    if (semicolon != std::string::npos) contentType.resize(semicolon);
    return TrimAscii(contentType) == expected;
}

// Constant-time string equality. A byte-at-a-time compare that never stops at
// the first mismatch, so the session token cannot be recovered byte-by-byte by
// timing the response. The length check leaks only the length, which is a fixed
// 64-char hex string and therefore public.
bool SecureEquals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i)
        diff |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
    return diff == 0;
}

bool AuthenticateMutation(const ServerContext& context,
                          const HttpRequest& request, HttpResponse* response) {
    const auto origin = request.headers.find("origin");
    const auto token = request.headers.find("x-wintcp-token");
    if (origin == request.headers.end() || token == request.headers.end() ||
        LowerAscii(origin->second) !=
            "http://127.0.0.1:" + std::to_string(context.port) ||
        !SecureEquals(token->second, context.token)) {
        if (response != nullptr) response->status = 403;
        return false;
    }
    return true;
}

bool ReadAsset(ServerContext& context, const wchar_t* name, std::string* out) {
    const std::wstring path = context.executableDirectory + L"webui\\" + name;
    return ReadFileBounded(path, kMaxAssetBytes, out);
}

std::string ErrorJson(const std::string& text) {
    return "{\"error\":" + JsonQuote(text) + "}";
}

std::string ConnectionsJson(ServerContext& context, const std::wstring& filter) {
    // Tell the refresher this endpoint is live, then take the lock. Order
    // matters only for tidiness: both are set/atomic operations.
    context.lastStoreAccess.store(::GetTickCount64());
    ListOptions options;
    options.format = "json";
    // NO traffic. The per-socket SIO_TCP_INFO scan's detached probe threads can
    // wedge in an uncancelable kernel call that holds the PROCESS-WIDE Winsock
    // lock, which stops the whole server answering - reproduced with a browser
    // polling /api/connections. The traffic column therefore reads "—" in the
    // Web UI; the CLI and GUI still show it, because they run the scan once per
    // invocation rather than on a timer.
    options.webMetadata = true;
    // Web UI-specific columns: enrich the JSON with the diagnostic and trust
    // columns the template evaluators need (duration, signature, ppid,
    // integrity) plus country when a GeoIP database is configured. The
    // connection refresher (ConnectionRefresherThread) applies these same
    // enrichments on its own pass, so the data is already in the store when
    // /api/connections reads it. Signature verification is cached per image
    // path, so it costs once per binary, not once per row.
    options.columns = {
        COL_PROTO, COL_LOCAL, COL_LPORT, COL_REMOTE, COL_RPORT, COL_STATE,
        COL_PID, COL_PROCESS, COL_SERVICE, COL_PATH,
        COL_DURATION, COL_SIGNATURE, COL_PPID, COL_INTEGRITY, COL_COUNTRY,
    };
    if (context.source.GeoIpLoaded()) {
        options.geoIpPath = context.geoIpDbPath;
    }
    options.signatures = true;
    std::lock_guard<std::mutex> lock(g_storeMutex);
    const CommandResult result = CmdListInto(context.source, context.store, options);
    if (result.exitCode != kExitOk) {
        context.connectionRefreshFailed.store(true);
        return ErrorJson(result.err.empty() ? "snapshot unavailable" : result.err);
    }
    OfferWebDnsForRows(context);
    const CommandResult rendered = RenderList(context.store, options);
    context.connectionSnapshotTick.store(::GetTickCount64());
    context.connectionRefreshFailed.store(false);
    size_t socketRows = 0;
    size_t tcpRows = 0;
    for (size_t i = 0; i < context.store.View().size(); ++i) {
        const Connection* row = context.store.ViewRow(i);
        if (row == nullptr || (row->flags & kRowRemoved) != 0) continue;
        if (row->identity.protocol == IPPROTO_TCP) {
            ++tcpRows;
            if (row->rate.perRowBytes) ++socketRows;
        }
    }
    const SocketTrafficSampler* sampler = ActiveTrafficSampler();
    std::string filteredJson;
    if (!filter.empty()) {
        ListOptions filteredOptions = options;
        filteredOptions.filter = filter;
        const CommandResult filtered = RenderList(context.store, filteredOptions,
                                                   /*skipHeader=*/false);
        if (filtered.exitCode != kExitOk)
            return ErrorJson(filtered.err.empty() ? "filter rendering failed"
                                                  : filtered.err);
        filteredJson = filtered.out;
    }
    std::ostringstream out;
    out << "{\"generatedAt\":" << JsonQuote(UtcTimestamp())
        << ",\"traffic\":{\"tcpRows\":" << tcpRows
        << ",\"socketRows\":" << socketRows
        << ",\"sampler\":" << (sampler != nullptr ? "true" : "false")
        << ",\"timeouts\":" << (sampler != nullptr ? sampler->TimeoutCount() : 0)
        << ",\"unreadable\":" << (sampler != nullptr ? sampler->UnreadableCount() : 0)
        << ",\"scanFailures\":" << (sampler != nullptr ? sampler->ScanFailureCount() : 0)
        << "},\"connections\":" << rendered.out;
    if (!filter.empty()) out << ",\"filteredConnections\":" << filteredJson;
    out << "}";
    return out.str();
}

bool ParseForm(const std::string& body, std::map<std::string, std::string>* fields);

// Read a REG_SZ under an absolute registry path. Returns false when the key or
// value is absent, which the callers turn into null plus a reason rather than a
// blank. Opens the key only long enough to hand it to RegReadBoundedString, so
// there is ONE bounded-string-read policy in the codebase rather than a second
// one living in the Web UI adapter.
bool ReadRegistryString(const wchar_t* subKey, const wchar_t* name,
                        std::string* out) {
    if (out == nullptr || subKey == nullptr || name == nullptr) return false;
    HKEY key = nullptr;
    if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &key) != ERROR_SUCCESS) {
        return false;
    }
    std::wstring value;
    const bool ok = RegReadBoundedString(key, name, 512, &value);
    ::RegCloseKey(key);
    if (!ok) return false;
    *out = WideToUtf8(value);
    return !out->empty();
}

std::string CapabilitiesJson(ServerContext& context) {
    std::ostringstream out;
    // Report what is actually true of THIS process, not a hardcoded assumption:
    // the front end greys out what it cannot get and says why.
    const bool pdh = context.metricsCollector.IsRunning();
    const bool perCore = pdh && context.metricsCollector.PerCoreAvailable();
    const bool elevated = IsElevated();
    out << "{\"elevated\":" << (elevated ? "true" : "false")
        << ",\"elevationReason\":" <<
            (elevated ? "null" : JsonQuote("Run WinTCP as administrator for connection teardown and firewall changes"))
        << ",\"pdh\":" << (pdh ? "true" : "false")
        << ",\"pdhReason\":" << (pdh ? "null" : JsonQuote("metrics sampler did not start"))
        << ",\"perCore\":" << (perCore ? "true" : "false")
        << ",\"perCoreReason\":"
        << (perCore ? "null"
                    : JsonQuote("per-core CPU counter is unavailable"))
        << ",\"gpu\":false"
        << ",\"geoIp\":{\"configured\":" << (context.source.GeoIpLoaded() ? "true" : "false")
        << ",\"type\":" << (context.source.GeoIpLoaded() ? JsonQuote("GeoLite2-Country") : "null")
        << ",\"error\":null}"
         << ",\"etw\":true,\"trafficScan\":false,\"dns\":true,\"signatures\":true"
        << ",\"version\":" << JsonQuote("2.0.0") << "}";
    return out.str();
}

std::string SystemInfoJson(ServerContext& context) {
    (void)context;  // reserved for future use (e.g. GeoIP database info)
    std::ostringstream out;
    out << "{";

    char computerName[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD nameLen = MAX_COMPUTERNAME_LENGTH + 1;
    ::GetComputerNameA(computerName, &nameLen);
    out << "\"hostname\":" << JsonQuote(computerName) << ",";

    // Uptime from GetTickCount64
    ULONGLONG uptimeMs = ::GetTickCount64();
    ULONGLONG uptimeSec = uptimeMs / 1000;
    ULONGLONG days = uptimeSec / 86400;
    ULONGLONG hours = (uptimeSec % 86400) / 3600;
    ULONGLONG mins = (uptimeSec % 3600) / 60;
    out << "\"uptime\":\"" << days << "d " << hours << "h " << mins << "m\",";

    // OS, from the registry. Every field is independently optional: a Server
    // SKU or a locked-down image can be missing any of them, and a missing
    // field is null plus a reason, never an empty string (C-6).
    std::string osCaption, osVersion, osBuild, cpuBrand;
    const bool haveCaption = ReadRegistryString(
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ProductName", &osCaption);
    const bool haveVersion = ReadRegistryString(
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"DisplayVersion", &osVersion);
    const bool haveBuild = ReadRegistryString(
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"CurrentBuildNumber", &osBuild);
    const bool haveBrand = ReadRegistryString(
        L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
        L"ProcessorNameString", &cpuBrand);

    out << "\"os\":{\"name\":" << (haveCaption ? JsonQuote(osCaption) : "null")
        << ",\"version\":" << (haveVersion ? JsonQuote(osVersion) : "null")
        << ",\"build\":" << (haveBuild ? JsonQuote(osBuild) : "null")
        << ",\"architecture\":"
        << JsonQuote(sizeof(void*) == 8 ? "x64" : "x86")
        << ",\"nameReason\":"
        << (haveCaption ? "null" : JsonQuote("ProductName is not readable"))
        << "},";

    // CPU. dwNumberOfProcessors is the count in the current processor group;
    // GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) is the machine total on
    // >64-core hosts, which is what an operator expects to read here.
    WORD groups = ::GetActiveProcessorGroupCount();
    DWORD processors = 0;
    for (WORD g = 0; g < groups; ++g) processors += ::GetActiveProcessorCount(g);
    if (processors == 0) processors = 1;
    out << "\"cpu\":{\"brand\":" << (haveBrand ? JsonQuote(cpuBrand) : "null")
        << ",\"model\":" << (haveBrand ? JsonQuote(cpuBrand) : "null")
        << ",\"brandReason\":"
        << (haveBrand ? "null" : JsonQuote("ProcessorNameString is not readable"))
        << ",\"cores\":" << processors
        << ",\"threads\":" << processors
        << ",\"processorGroups\":" << groups
        << ",\"architecture\":"
        << JsonQuote(sizeof(void*) == 8 ? "x64" : "x86") << "},";

    // Memory from GlobalMemoryStatusEx. Unavailable is not zero: say so (C-6).
    MEMORYSTATUSEX mem = {};
    mem.dwLength = sizeof(mem);
    if (::GlobalMemoryStatusEx(&mem)) {
        out << "\"memory\":{\"installed\":" << mem.ullTotalPhys
            << ",\"available\":" << mem.ullAvailPhys
            << ",\"used\":" << (mem.ullTotalPhys - mem.ullAvailPhys)
            << ",\"pct\":" << mem.dwMemoryLoad << "},"
            << "\"memoryReason\":null";
    } else {
        out << "\"memory\":null"
            << ",\"memoryReason\":" << JsonQuote("GlobalMemoryStatusEx failed");
    }

    out << "}";
    return out.str();
}

// One series id per metric, plus its per-instance siblings. The catalog is the
// contract the UI renders a series picker from, so it has to name every series
// the history endpoint will actually answer for - a picker built from a
// hand-written list silently omits the per-instance and per-core series.
std::string MetricsCatalogJson(const MetricsSample& probe) {
    std::ostringstream out;
    out << "{\"series\":[";
    bool first = true;
    const auto series = [&](const char* id, const char* label, const char* unit,
                            const char* kind, bool available) {
        if (!first) out << ",";
        first = false;
        out << "{\"id\":" << JsonQuote(id)
            << ",\"label\":" << JsonQuote(label)
            << ",\"unit\":" << JsonQuote(unit)
            << ",\"kind\":" << JsonQuote(kind)
            // Availability is reported per series, not as one global flag: CPU
            // can be readable while per-core GPU counters are absent, and the UI
            // has to grey out exactly the second one.
            << ",\"available\":" << (available ? "true" : "false")
            << "}";
    };

    series("cpu.total", "CPU Total", "%", "gauge", probe.cpuTotalKnown);
    series("mem.usedBytes", "Memory Used", "bytes", "gauge", probe.memUsedKnown);
    series("mem.totalBytes", "Memory Installed", "bytes", "gauge", probe.memTotalKnown);
    series("mem.availableBytes", "Memory Available", "bytes", "gauge", probe.memAvailableKnown);
    series("mem.cacheBytes", "Cache", "bytes", "gauge", probe.memCacheKnown);
    series("mem.kernelPagedBytes", "Kernel paged pool", "bytes", "gauge", probe.memKernelPagedKnown);
    series("mem.kernelNonPagedBytes", "Kernel non-paged pool", "bytes", "gauge", probe.memKernelNonPagedKnown);
    series("mem.commitLimitBytes", "Commit limit", "bytes", "gauge", probe.memCommitLimitKnown);
    series("mem.commitPeakBytes", "Commit peak", "bytes", "gauge", probe.memCommitPeakKnown);
    series("disk.readBps", "Disk Read", "bytes/s", "gauge", !probe.diskReadBps.empty());
    series("disk.writeBps", "Disk Write", "bytes/s", "gauge", !probe.diskWriteBps.empty());
    series("disk.activePct", "Disk Active", "%", "gauge", !probe.diskActivePct.empty());
    series("disk.queueLength", "Disk queue", "requests", "gauge", !probe.diskQueueLength.empty());
    series("disk.latencyMs", "Disk latency", "ms", "gauge", !probe.diskLatencyMs.empty());
    series("net.rxBps", "Network received", "bytes/s", "gauge", !probe.netRxBps.empty());
    series("net.txBps", "Network sent", "bytes/s", "gauge", !probe.netTxBps.empty());
    series("gpu.vramBytes", "GPU dedicated memory", "bytes", "gauge", probe.gpuVramKnown);
    series("sys.uptimeSeconds", "Uptime", "seconds", "counter", probe.uptimeKnown);
    series("sys.processCount", "Processes", "count", "gauge", probe.processCountKnown);
    series("sys.threadCount", "Threads", "count", "gauge", probe.threadCountKnown);
    series("sys.handleCount", "Handles", "count", "gauge", probe.handleCountKnown);

    // Per-core CPU, one catalog entry each, so a range picker can list them.
    for (size_t i = 0; i < probe.cpuCore.size(); ++i) {
        const bool known = i < probe.cpuCoreKnown.size() && probe.cpuCoreKnown[i];
        const std::string id = "cpu.core." + std::to_string(i);
        const std::string label = "CPU core " + std::to_string(i);
        series(id.c_str(), label.c_str(), "%", "gauge", known);
    }
    // Per-instance disk and network series, named "<family>.<label>" so the
    // history endpoint can resolve them from one id.
    for (const auto& kv : probe.diskReadBps) {
        const std::string id = "disk.readBps." + WideToUtf8(kv.first);
        series(id.c_str(), ("Disk read " + WideToUtf8(kv.first)).c_str(),
               "bytes/s", "gauge",
               probe.diskReadKnown.count(kv.first) > 0);
    }
    for (const auto& kv : probe.diskWriteBps) {
        const std::string id = "disk.writeBps." + WideToUtf8(kv.first);
        series(id.c_str(), ("Disk write " + WideToUtf8(kv.first)).c_str(),
               "bytes/s", "gauge",
               probe.diskWriteKnown.count(kv.first) > 0);
    }
    for (const auto& kv : probe.netRxBps) {
        const std::string id = "net.rxBps." + WideToUtf8(kv.first);
        series(id.c_str(), ("Network received " + WideToUtf8(kv.first)).c_str(),
               "bytes/s", "gauge", probe.netRxKnown.count(kv.first) > 0);
    }
    for (const auto& kv : probe.netTxBps) {
        const std::string id = "net.txBps." + WideToUtf8(kv.first);
        series(id.c_str(), ("Network sent " + WideToUtf8(kv.first)).c_str(),
               "bytes/s", "gauge", probe.netTxKnown.count(kv.first) > 0);
    }
    for (const auto& kv : probe.netLinkBits) {
        if (!kv.second) continue;
        const std::string id = "net.linkBits." + WideToUtf8(kv.first);
        series(id.c_str(), ("Link speed " + WideToUtf8(kv.first)).c_str(),
               "bits/s", "gauge", true);
    }
    for (const auto& kv : probe.volumes) {
        if (!kv.second.known) continue;
        const std::string id = "vol.freeBytes." + WideToUtf8(kv.first);
        series(id.c_str(), ("Free " + WideToUtf8(kv.first)).c_str(),
               "bytes", "gauge", true);
    }

    out << "]}";
    return out.str();
}

// Sum one per-instance series. `known` comes back false when NO instance
// produced a value, which is what keeps "unknown" distinct from zero (C-6).
double SumInstances(const std::map<std::wstring, double>& values,
                    const std::map<std::wstring, bool>& known,
                    bool* anyKnown) {
    double total = 0.0;
    bool saw = false;
    for (const auto& kv : values) {
        if (known.find(kv.first) == known.end() || !known.at(kv.first)) continue;
        total += kv.second;
        saw = true;
    }
    *anyKnown = saw;
    return total;
}

// Volumes and adapters as a COMPLETE JSON object.
//
// This is deliberately a whole object rather than a fragment the caller splices
// into a larger string. The first version emitted `"facts":"volumes":[{...}]`
// with no opening brace, which made every /api/metrics/now response invalid
// JSON and silently broke every consumer on the far side of the parse.
std::string MetricsFactsJson(const MetricsSample& sample) {
    std::ostringstream out;
    out << "{\"volumes\":[";
    bool first = true;
    for (const auto& kv : sample.volumes) {
        if (!kv.second.known) continue;
        if (!first) out << ",";
        first = false;
        out << "{\"label\":" << JsonQuote(WideToUtf8(kv.first))
            << ",\"fileSystem\":" << JsonQuote(WideToUtf8(kv.second.fileSystem))
            << ",\"volumeName\":" << JsonQuote(WideToUtf8(kv.second.label))
            << ",\"totalBytes\":" << kv.second.totalBytes
            << ",\"freeBytes\":" << kv.second.freeBytes << "}";
    }
    out << "],\"adapters\":[";
    first = true;
    // Iterated from netUp, not netLinkKnown: an adapter with no link speed
    // (a tunnel, a loopback alias, a virtual switch) is still an adapter the
    // user can see in Task Manager, and hiding it would be the same lie as
    // reporting its speed as zero.
    for (const auto& kv : sample.netUp) {
        if (!first) out << ",";
        first = false;
        const auto bits = sample.netLinkBits.find(kv.first);
        const bool linkKnown = bits != sample.netLinkBits.end() &&
                               sample.netLinkBits.count(kv.first) > 0;
        out << "{\"name\":" << JsonQuote(WideToUtf8(kv.first))
            << ",\"linkBits\":" << (linkKnown
                                    ? JsonNumber(static_cast<double>(bits->second))
                                    : std::string("null"))
            << ",\"linkKnown\":" << (linkKnown ? "true" : "false")
            // "up" is a link fact read straight from the interface table, not a
            // guess from traffic: a down link really can show non-zero counters
            // for a few seconds while the driver settles.
            << ",\"up\":" << (kv.second ? "true" : "false") << "}";
    }
    out << "]}";
    return out.str();
}

std::string MetricsNowJson(ServerContext& context) {
    MetricsSample sample;
    const bool have = context.metricsCollector.GetLatest(&sample);
    // Non-series facts the UI needs but that are not time series: volumes are a
    // capacity snapshot, link speed is a link property, and neither belongs in
    // the history arrays. They go in a sibling object so /api/metrics/now stays
    // a flat map of series ids plus one "facts" block.
    const std::string facts = MetricsFactsJson(sample);
    std::ostringstream out;
    out << "{";
    if (have) {
        // Every catalogued series is always present. An unavailable counter is
        // null plus a reason, never 0 - a zero here would read as "idle".
        const auto series = [&](const std::string& id, bool known, double value,
                                const char* reason) {
            out << "\"" << id << "\":" << (known ? JsonNumber(value) : std::string("null"))
                << ",\"" << id << ".reason\":"
                << (known ? "null" : JsonQuote(reason)) << ",";
        };
        const auto anyInstance = [](const auto& /*values*/, const auto& knowns,
                                    const std::wstring& key) {
            auto it = knowns.find(key);
            return it != knowns.end() && it->second;
        };

        series("cpu.total", sample.cpuTotalKnown, sample.cpuTotal,
               "PDH counter not ready");
        series("mem.usedBytes", sample.memUsedKnown,
               static_cast<double>(sample.memUsed), "PDH counter not ready");
        series("mem.totalBytes", sample.memTotalKnown,
               static_cast<double>(sample.memTotal), "PDH counter not ready");
        series("mem.availableBytes", sample.memAvailableKnown,
               static_cast<double>(sample.memAvailable), "PDH counter not ready");
        series("mem.cacheBytes", sample.memCacheKnown,
               static_cast<double>(sample.memCache),
               "this Windows build does not expose Cache Bytes");
        series("mem.kernelPagedBytes", sample.memKernelPagedKnown,
               static_cast<double>(sample.memKernelPaged), "PDH counter not ready");
        series("mem.kernelNonPagedBytes", sample.memKernelNonPagedKnown,
               static_cast<double>(sample.memKernelNonPaged), "PDH counter not ready");
        series("mem.commitLimitBytes", sample.memCommitLimitKnown,
               static_cast<double>(sample.memCommitLimit), "PDH counter not ready");
        series("mem.commitPeakBytes", sample.memCommitPeakKnown,
               static_cast<double>(sample.memCommitPeak), "PDH counter not ready");

        // Aggregates across all instances. The aggregate and the per-instance series
        // are both emitted: the KPI cards want the total, the Performance page
        // wants each disk and adapter separately.
        {
            bool known = false;
            const double diskRead = SumInstances(sample.diskReadBps,
                                                  sample.diskReadKnown, &known);
            series("disk.readBps", known, diskRead, "no disk counters available");
        }
        {
            bool known = false;
            const double diskWrite = SumInstances(sample.diskWriteBps,
                                                   sample.diskWriteKnown, &known);
            series("disk.writeBps", known, diskWrite, "no disk counters available");
        }
        {
            bool known = false;
            const double netRx = SumInstances(sample.netRxBps, sample.netRxKnown, &known);
            series("net.rxBps", known, netRx, "no network counters available");
        }
        {
            bool known = false;
            const double netTx = SumInstances(sample.netTxBps, sample.netTxKnown, &known);
            series("net.txBps", known, netTx, "no network counters available");
        }

        // Per-instance throughput, so the Performance page can draw one series
        // per disk and one per adapter.
        for (const auto& kv : sample.diskReadBps) {
            series("disk.readBps." + WideToUtf8(kv.first),
                   anyInstance(sample.diskReadBps, sample.diskReadKnown, kv.first),
                   kv.second, "this disk reported no reading");
        }
        for (const auto& kv : sample.diskWriteBps) {
            series("disk.writeBps." + WideToUtf8(kv.first),
                   anyInstance(sample.diskWriteBps, sample.diskWriteKnown, kv.first),
                   kv.second, "this disk reported no reading");
        }
        for (const auto& kv : sample.netRxBps) {
            series("net.rxBps." + WideToUtf8(kv.first),
                   anyInstance(sample.netRxBps, sample.netRxKnown, kv.first),
                   kv.second, "this adapter reported no reading");
        }
        for (const auto& kv : sample.netTxBps) {
            series("net.txBps." + WideToUtf8(kv.first),
                   anyInstance(sample.netTxBps, sample.netTxKnown, kv.first),
                   kv.second, "this adapter reported no reading");
        }
        series("gpu.vramBytes", sample.gpuVramKnown,
               static_cast<double>(sample.gpuVramUsed),
               "no GPU adapter memory counter on this machine");
        series("sys.uptimeSeconds", sample.uptimeKnown,
               static_cast<double>(sample.uptimeSeconds), "");
        series("sys.processCount", sample.processCountKnown,
               static_cast<double>(sample.processCount), "");
        series("sys.threadCount", sample.threadCountKnown,
               static_cast<double>(sample.threadCount), "");
        series("sys.handleCount", sample.handleCountKnown,
               static_cast<double>(sample.handleCount), "");

        for (const auto& kv : sample.diskActivePct) {
            series("disk.activePct." + WideToUtf8(kv.first),
                   anyInstance(sample.diskActivePct, sample.diskActiveKnown, kv.first),
                   kv.second, "");
        }
        for (const auto& kv : sample.diskQueueLength) {
            series("disk.queueLength." + WideToUtf8(kv.first),
                   anyInstance(sample.diskQueueLength, sample.diskQueueKnown, kv.first),
                   kv.second, "");
        }
        for (const auto& kv : sample.diskLatencyMs) {
            series("disk.latencyMs." + WideToUtf8(kv.first),
                   anyInstance(sample.diskLatencyMs, sample.diskLatencyKnown, kv.first),
                   kv.second, "");
        }
        for (const auto& kv : sample.gpuEnginePct) {
            series("gpu.engine." + WideToUtf8(kv.first),
                   anyInstance(sample.gpuEnginePct, sample.gpuEngineKnown, kv.first),
                   kv.second, "");
        }
        // Per-core CPU: cpu.core.<n>, null where the core reported no data.
        for (size_t i = 0; i < sample.cpuCore.size(); ++i) {
            const bool known = i < sample.cpuCoreKnown.size() && sample.cpuCoreKnown[i];
            series("cpu.core." + std::to_string(i), known, sample.cpuCore[i],
                   "core counter returned no data");
        }
        out << "\"_timestamp\":" << sample.unixTime;
    } else {
        const std::string reason = JsonQuote("sampler has not produced a sample yet");
        out << "\"cpu.total\":null,\"cpu.total.reason\":" << reason
            << ",\"mem.usedBytes\":null,\"mem.usedBytes.reason\":" << reason
            << ",\"mem.totalBytes\":null,\"mem.totalBytes.reason\":" << reason
            << ",\"mem.availableBytes\":null,\"mem.availableBytes.reason\":" << reason
            << ",\"mem.cacheBytes\":null,\"mem.cacheBytes.reason\":" << reason
            << ",\"disk.readBps\":null,\"disk.readBps.reason\":" << reason
            << ",\"disk.writeBps\":null,\"disk.writeBps.reason\":" << reason
            << ",\"net.rxBps\":null,\"net.rxBps.reason\":" << reason
            << ",\"net.txBps\":null,\"net.txBps.reason\":" << reason
            << ",\"gpu.vramBytes\":null,\"gpu.vramBytes.reason\":" << reason;
    }
    out << ",\"facts\":" << MetricsFactsJson(sample) << "}";
    return out.str();
}

// Extract one named series from a sample. `id` is either a bare series
// ("cpu.total") or an instance-qualified one ("disk.readBps.C:"), and the
// per-instance form falls back to the aggregate when the suffix does not match a
// live instance - a disk that was unplugged must not turn a whole chart into
// nulls. Returns false only when the value genuinely has no meaning here.
bool ExtractSeries(const MetricsSample& s, const std::string& id, double* value,
                   bool* known) {
    *known = false;
    *value = 0.0;

    const auto scalar = [&](bool ok, double v) {
        *known = ok;
        *value = v;
    };
    const auto instanceSplit = [&](const char* prefix,
                                   const std::map<std::wstring, double>& values,
                                   const std::map<std::wstring, bool>& knowns) {
        const size_t prefixLen = std::strlen(prefix);
        if (id.size() <= prefixLen || id.compare(0, prefixLen, prefix) != 0) {
            return false;
        }
        std::wstring suffix;
        if (!Utf8ToWide(id.substr(prefixLen), &suffix)) return true;   // known=false
        auto vit = values.find(suffix);
        if (vit == values.end()) {
            // Fall back to the family aggregate.
            bool any = false;
            *value = SumInstances(values, knowns, &any);
            *known = any;
            return true;
        }
        auto kit = knowns.find(suffix);
        *known = kit != knowns.end() && kit->second;
        *value = vit->second;
        return true;
    };

    if (id == "cpu.total") { scalar(s.cpuTotalKnown, s.cpuTotal); return true; }
    if (id == "mem.usedBytes") { scalar(s.memUsedKnown, static_cast<double>(s.memUsed)); return true; }
    if (id == "mem.totalBytes") { scalar(s.memTotalKnown, static_cast<double>(s.memTotal)); return true; }
    if (id == "mem.availableBytes") { scalar(s.memAvailableKnown, static_cast<double>(s.memAvailable)); return true; }
    if (id == "mem.cacheBytes") { scalar(s.memCacheKnown, static_cast<double>(s.memCache)); return true; }
    if (id == "mem.kernelPagedBytes") { scalar(s.memKernelPagedKnown, static_cast<double>(s.memKernelPaged)); return true; }
    if (id == "mem.kernelNonPagedBytes") { scalar(s.memKernelNonPagedKnown, static_cast<double>(s.memKernelNonPaged)); return true; }
    if (id == "mem.commitLimitBytes") { scalar(s.memCommitLimitKnown, static_cast<double>(s.memCommitLimit)); return true; }
    if (id == "mem.commitPeakBytes") { scalar(s.memCommitPeakKnown, static_cast<double>(s.memCommitPeak)); return true; }
    if (id == "gpu.vramBytes") { scalar(s.gpuVramKnown, static_cast<double>(s.gpuVramUsed)); return true; }
    if (id == "sys.uptimeSeconds") { scalar(s.uptimeKnown, static_cast<double>(s.uptimeSeconds)); return true; }
    if (id == "sys.processCount") { scalar(s.processCountKnown, static_cast<double>(s.processCount)); return true; }
    if (id == "sys.threadCount") { scalar(s.threadCountKnown, static_cast<double>(s.threadCount)); return true; }
    if (id == "sys.handleCount") { scalar(s.handleCountKnown, static_cast<double>(s.handleCount)); return true; }

    // Per-core.
    if (id.rfind("cpu.core.", 0) == 0) {
        const std::string digits = id.substr(9);
        if (digits.empty() ||
            digits.find_first_not_of("0123456789") != std::string::npos) {
            return false;
        }
        const size_t index = static_cast<size_t>(std::strtoul(digits.c_str(), nullptr, 10));
        *known = index < s.cpuCoreKnown.size() && s.cpuCoreKnown[index];
        *value = index < s.cpuCore.size() ? s.cpuCore[index] : 0.0;
        return true;
    }

    // Per-instance families. The prefix check comes first so a request for
    // "disk.readBps.C:" is recognised before the bare "disk.readBps" case below.
    if (instanceSplit("disk.readBps.", s.diskReadBps, s.diskReadKnown)) return true;
    if (instanceSplit("disk.writeBps.", s.diskWriteBps, s.diskWriteKnown)) return true;
    if (instanceSplit("disk.activePct.", s.diskActivePct, s.diskActiveKnown)) return true;
    if (instanceSplit("disk.queueLength.", s.diskQueueLength, s.diskQueueKnown)) return true;
    if (instanceSplit("disk.latencyMs.", s.diskLatencyMs, s.diskLatencyKnown)) return true;
    if (instanceSplit("net.rxBps.", s.netRxBps, s.netRxKnown)) return true;
    if (instanceSplit("net.txBps.", s.netTxBps, s.netTxKnown)) return true;
    if (instanceSplit("gpu.engine.", s.gpuEnginePct, s.gpuEngineKnown)) return true;

    // Bare family aggregates. The suffix test above would have consumed any id
    // that merely starts with "disk.readBps."; what is left is the aggregate.
    if (id == "disk.readBps") { *value = SumInstances(s.diskReadBps, s.diskReadKnown, known); return true; }
    if (id == "disk.writeBps") { *value = SumInstances(s.diskWriteBps, s.diskWriteKnown, known); return true; }
    if (id == "disk.activePct") { *value = SumInstances(s.diskActivePct, s.diskActiveKnown, known); return true; }
    if (id == "disk.queueLength") { *value = SumInstances(s.diskQueueLength, s.diskQueueKnown, known); return true; }
    if (id == "disk.latencyMs") { *value = SumInstances(s.diskLatencyMs, s.diskLatencyKnown, known); return true; }
    if (id == "net.rxBps") { *value = SumInstances(s.netRxBps, s.netRxKnown, known); return true; }
    if (id == "net.txBps") { *value = SumInstances(s.netTxBps, s.netTxKnown, known); return true; }
    return false;
}

// Series ids the endpoint accepts, so an unknown one is rejected with a message
// naming what IS available instead of silently returning an empty array.
std::vector<std::string> KnownSeriesIds() {
    return {
        "cpu.total", "mem.usedBytes", "mem.totalBytes", "mem.availableBytes",
        "mem.cacheBytes", "mem.kernelPagedBytes", "mem.kernelNonPagedBytes",
        "mem.commitLimitBytes", "mem.commitPeakBytes",
        "disk.readBps", "disk.writeBps", "disk.activePct", "disk.queueLength",
        "disk.latencyMs", "net.rxBps", "net.txBps", "gpu.vramBytes",
        "sys.uptimeSeconds", "sys.processCount", "sys.threadCount",
        "sys.handleCount",
    };
}

std::string MetricsHistoryJson(ServerContext& context, const HttpRequest& request) {
    uint64_t since = 0;
    size_t maxSamples = 900;
    std::string tierParam = "1s";
    MetricsCollector::Tier tier = MetricsCollector::Tier::A;
    // Optional explicit series selection. Absent means "everything the sample
    // carries", which is what the current callers rely on.
    std::vector<std::string> requested;
    size_t query = request.target.find('?');
    if (query != std::string::npos) {
        std::map<std::string, std::string> params;
        if (ParseForm(request.target.substr(query + 1), &params)) {
            // Strict, allocation-free integer parsing. std::stoull/std::stoul
            // throw std::invalid_argument on "abc" and std::out_of_range on
            // "99999999999999999999"; nothing above caught that, so a single
            // malformed query string unwound through the accept loop and killed
            // the whole server (0xE06D7363, with a minidump). An unparseable
            // parameter is a client error, not a fatal one.
            uint64_t parsed = 0;
            if (params.count("since") &&
                !ParseUint64Strict(params["since"], &parsed)) {
                return ErrorJson("since must be a non-negative integer");
            }
            since = parsed;
            if (params.count("max")) {
                if (!ParseUint64Strict(params["max"], &parsed)) {
                    return ErrorJson("max must be a non-negative integer");
                }
                maxSamples = parsed < 900 ? static_cast<size_t>(parsed) : 900;
            }
            if (params.count("tier")) {
                tierParam = params["tier"];
                // Only the two documented tiers. An unknown tier silently
                // falling back to tier A would return the wrong time base with
                // no indication, which is exactly the failure C-6 warns about.
                if (tierParam == "10s") {
                    tier = MetricsCollector::Tier::B;
                    if (maxSamples > 2160) maxSamples = 2160;
                } else if (tierParam != "1s") {
                    return ErrorJson("tier must be 1s or 10s");
                }
            }
            if (params.count("series")) {
                // Comma-separated ids. An unknown id is refused with the list
                // that IS valid, rather than returning an empty array that looks
                // like "this machine reports nothing".
                requested.clear();
                size_t start = 0;
                const std::string& list = params["series"];
                while (start <= list.size()) {
                    const size_t comma = list.find(',', start);
                    const std::string one = list.substr(
                        start, comma == std::string::npos ? std::string::npos : comma - start);
                    if (!one.empty()) {
                        bool known = false;
                        for (const auto& candidate : KnownSeriesIds()) {
                            if (candidate == one) { known = true; break; }
                        }
                        // Per-instance ids are validated by prefix: the suffix is
                        // whatever instance the sampler happened to see, so the
                        // family is checked instead.
                        if (!known) {
                            static const char* kFamilies[] = {
                                "disk.readBps.", "disk.writeBps.", "disk.activePct.",
                                "disk.queueLength.", "disk.latencyMs.",
                                "net.rxBps.", "net.txBps.", "gpu.engine.",
                                "cpu.core.",
                            };
                            for (const char* family : kFamilies) {
                                if (one.rfind(family, 0) == 0) { known = true; break; }
                            }
                        }
                        if (!known) {
                            return ErrorJson("unknown series '" + one +
                                "'; use /api/metrics/catalog for the available ids");
                        }
                        requested.push_back(one);
                    }
                    if (comma == std::string::npos) break;
                    start = comma + 1;
                }
                // Cap the width: 900 samples x N series is the response size
                // budget, and a client asking for 400 per-core series would
                // otherwise produce a multi-megabyte body from a sequential
                // server (C-8).
                if (requested.size() > 48) {
                    return ErrorJson("at most 48 series may be requested at once");
                }
            }
        }
    }
    auto samples = context.metricsCollector.GetHistory(tier, since, maxSamples);
    const size_t step = tier == MetricsCollector::Tier::B ? 10 : 1;
    // `samples` comes back OLDEST-first, so the newest is the back element. With
    // an empty window there is no back element at all, and every "newest"
    // lookup below has to tolerate that rather than reading past the end.
    const MetricsSample* newest = samples.empty() ? nullptr : &samples.back();
    std::ostringstream out;
    out << "{\"tier\":" << JsonQuote(tierParam) << ",\"step\":" << step
        << ",\"count\":" << samples.size() << ",\"t\":[";
    for (size_t i = 0; i < samples.size(); ++i) {
        if (i > 0) out << ",";
        out << samples[i].unixTime;
    }
    // One aligned array per series inside "series". Unknown samples are null,
    // never 0 (C-6), and every array lines up index-for-index with "t".
    out << "],\"series\":{";
    bool firstSeries = true;
    // When no explicit list is given, emit every series the newest sample
    // actually carries - including the per-instance and per-core ones, which is
    // what lets the UI discover them without a second round trip.
    std::vector<std::string> ids = requested;
    if (ids.empty()) {
        ids = KnownSeriesIds();
        // The per-instance and per-core ids only exist once the sampler has seen
        // the hardware, so they are discovered from the newest sample rather
        // than hardcoded. With no sample yet, only the fixed families are named
        // - which is the correct answer, not a missing one.
        if (newest != nullptr) {
            for (size_t i = 0; i < newest->cpuCore.size(); ++i) {
                ids.push_back("cpu.core." + std::to_string(i));
            }
            for (const auto& kv : newest->diskReadBps) ids.push_back("disk.readBps." + WideToUtf8(kv.first));
            for (const auto& kv : newest->diskWriteBps) ids.push_back("disk.writeBps." + WideToUtf8(kv.first));
            for (const auto& kv : newest->diskActivePct) ids.push_back("disk.activePct." + WideToUtf8(kv.first));
            for (const auto& kv : newest->netRxBps) ids.push_back("net.rxBps." + WideToUtf8(kv.first));
            for (const auto& kv : newest->netTxBps) ids.push_back("net.txBps." + WideToUtf8(kv.first));
        }
    }
    for (const auto& id : ids) {
        if (requested.empty()) {
            // The id is a valid family, but this machine's samples may carry no
            // such family at all (no GPU, no per-core counter). Skip the column
            // rather than emitting a screenful of nulls. An explicitly
            // requested id is always emitted, so a client asking for a series
            // gets a column (of nulls, with the reason) rather than silence.
            bool carried = false;
            for (const auto& s : samples) {
                double v = 0.0;
                bool k = false;
                if (ExtractSeries(s, id, &v, &k)) { carried = true; break; }
            }
            if (!carried) continue;
        }
        if (!firstSeries) out << ",";
        firstSeries = false;
        out << "\"" << id << "\":[";
        for (size_t i = 0; i < samples.size(); ++i) {
            if (i > 0) out << ",";
            double value = 0.0;
            bool known = false;
            if (!ExtractSeries(samples[i], id, &value, &known)) {
                out << "null";
            } else {
                out << (known ? JsonNumber(value) : std::string("null"));
            }
        }
        out << "]";
    }
    out << "}}";
    return out.str();
}

// Parse ?sort= and ?limit= for /api/processes. An unknown sort key is a 400
// naming the valid keys, because silently falling back to "pid" would hand back
// a table sorted by something the caller did not ask for and label it as if it
// were what they wanted.
bool ParseProcessQuery(const std::string& queryString, ProcessSort* sort,
                       bool* ascending, size_t* limit, std::string* error) {
    *sort = ProcessSort::Cpu;
    *ascending = false;          // "top CPU" means largest first
    *limit = 500;
    if (queryString.empty()) return true;

    std::map<std::string, std::string> parameters;
    if (!ParseForm(queryString, &parameters)) {
        if (error) *error = "could not parse the query string";
        return false;
    }
    for (const auto& kv : parameters) {
        if (kv.first == "sort") {
            const std::string key = LowerAscii(kv.second);
            if (key == "cpu") *sort = ProcessSort::Cpu;
            else if (key == "memory") *sort = ProcessSort::Memory;
            else if (key == "private") *sort = ProcessSort::PrivateBytes;
            else if (key == "ioread") *sort = ProcessSort::IoRead;
            else if (key == "iowrite") *sort = ProcessSort::IoWrite;
            else if (key == "threads") *sort = ProcessSort::Threads;
            else if (key == "name") *sort = ProcessSort::Name;
            else if (key == "pid") *sort = ProcessSort::Pid;
            else if (key == "connections") *sort = ProcessSort::Connections;
            else if (key == "listeners") *sort = ProcessSort::Listeners;
            else {
                if (error) {
                    *error = "unknown sort key '" + kv.second +
                             "'; use cpu, memory, private, ioread, iowrite, "
                             "threads, name, pid, connections or listeners";
                }
                return false;
            }
        } else if (kv.first == "dir") {
            const std::string dir = LowerAscii(kv.second);
            if (dir == "asc") *ascending = true;
            else if (dir == "desc") *ascending = false;
            else {
                if (error) *error = "dir must be asc or desc";
                return false;
            }
        } else if (kv.first == "limit") {
            uint64_t parsed = 0;
            // ParseUint64Strict, never std::stoull: the same throwing parse that
            // used to terminate the whole server on ?since=abc is what this
            // parameter would otherwise reintroduce.
            if (!ParseUint64Strict(kv.second, &parsed)) {
                if (error) *error = "limit must be a non-negative integer";
                return false;
            }
            // Capped: the response is built in memory and the server is
            // sequential, so an unbounded limit is a way to make one request
            // cost seconds. 2000 rows is well past what the UI ever asks for.
            *limit = parsed > 2000 ? 2000 : static_cast<size_t>(parsed);
        } else {
            if (error) *error = "unknown parameter '" + kv.first + "'";
            return false;
        }
    }
    return true;
}

std::string ProcessesJson(ServerContext& context, const std::string& queryString) {
    context.lastStoreAccess.store(::GetTickCount64());

    ProcessSort sort = ProcessSort::Cpu;
    bool ascending = false;
    size_t limit = 500;
    std::string error;
    if (!ParseProcessQuery(queryString, &sort, &ascending, &limit, &error)) {
        return "{\"error\":" + JsonQuote(error) + "}";
    }

    WebProcessSnapshot snapshot = context.processes.Read();
    const ULONGLONG ageMs = context.processes.AgeMs();

    std::ostringstream out;
    if (!snapshot.known) {
        // "not measured yet" must not look like "no processes exist" (C-6).
        out << "{\"processes\":[],\"known\":false,\"reason\":"
            << JsonQuote(snapshot.reason.empty() ? "the process table has not been sampled yet"
                                                 : snapshot.reason) << "}";
        return out.str();
    }

    std::vector<WebProcessRow> rows = snapshot.rows;
    std::stable_sort(rows.begin(), rows.end(),
                     [sort, ascending](const WebProcessRow& a, const WebProcessRow& b) {
                         return CompareProcesses(a, b, sort, ascending);
                     });

    const size_t total = rows.size();
    const size_t count = rows.size() < limit ? rows.size() : limit;

    out << "{\"processes\":[";
    for (size_t i = 0; i < count; ++i) {
        const WebProcessRow& row = rows[i];
        if (i > 0) out << ",";
        out << "{\"pid\":" << row.pid
            << ",\"ppid\":" << row.ppid
            << ",\"instanceId\":" << (row.stats.processCreateKnown
                ? JsonQuote(std::to_string(row.pid) + ":" +
                    std::to_string(row.stats.processCreateTime.dwHighDateTime) + ":" +
                    std::to_string(row.stats.processCreateTime.dwLowDateTime))
                : std::string("null"))
            << ",\"name\":" << JsonQuote(WideToUtf8(row.name))
            // An unreadable path is null plus a reason, never "" - an empty
            // string reads as "this process has no path", which is false.
            << ",\"path\":" << (row.path.empty()
                                  ? std::string("null,\"pathReason\":\"the image path could not be read without elevation\"")
                                  : JsonQuote(WideToUtf8(row.path)))
            << ",\"threads\":" << (row.threadsKnown ? std::to_string(row.threads)
                                                    : std::string("null"))
            << ",\"connections\":" << (row.connectionCountsKnown
                                          ? std::to_string(row.connections)
                                          : std::string("null"))
            << ",\"listeners\":" << (row.connectionCountsKnown
                                        ? std::to_string(row.listeners)
                                        : std::string("null"))
            // Per-process CPU, memory and I/O. Each carries its own known flag
            // because a process that cannot be opened reports none of them
            // while still having a perfectly good PID and name.
            << ",\"cpuPct\":" << (row.stats.cpuKnown ? JsonNumber(row.stats.cpuPct)
                                                     : std::string("null"))
            << ",\"memWs\":" << (row.stats.memKnown
                                    ? JsonExactUint64(row.stats.memWs)
                                    : std::string("null"))
            << ",\"memPrivate\":" << (row.stats.memKnown
                                        ? JsonExactUint64(row.stats.memPrivate)
                                        : std::string("null"))
            // I/O is TRANSFER bytes - file, pipe and device - not disk-only.
            // The UI labels it that way; see docs/webui.md.
            << ",\"ioRead\":" << (row.stats.ioKnown ? JsonExactUint64(row.stats.ioRead)
                                                     : std::string("null"))
            << ",\"ioWrite\":" << (row.stats.ioKnown ? JsonExactUint64(row.stats.ioWrite)
                                                      : std::string("null"))
            << "}";
    }
    out << "],\"total\":" << total << ",\"returned\":" << count
        << ",\"known\":true,\"ageMs\":" << ageMs
        << ",\"sampledAtMs\":" << snapshot.sampledAtMs
        << ",\"connectionCountsKnown\":"
        << ((total > 0 && rows[0].connectionCountsKnown) ? "true" : "false")
        << "}";
    return out.str();
}

std::string NetworkSummaryJson(ServerContext& context) {
    context.lastStoreAccess.store(::GetTickCount64());
    std::lock_guard<std::mutex> lock(g_storeMutex);
    std::map<std::string, int> byState, byProto, byFamily, byProcess;
    int loopback = 0, privateCount = 0, specific = 0, wildcard = 0;
    size_t liveRows = 0;
    auto isPrivateListenerAddress = [](const std::wstring& local) -> bool {
        std::wstring address = local;
        // IPv4-mapped IPv6 addresses follow their mapped IPv4 scope.
        const std::wstring mappedPrefix = L"::ffff:";
        if (address.rfind(mappedPrefix, 0) == 0) address = address.substr(mappedPrefix.size());
        if (address == L"10." || address.rfind(L"10.", 0) == 0) return true;
        // 172.16.0.0/12
        if (address.rfind(L"172.", 0) == 0) {
            const size_t dot = address.find(L'.', 4);
            if (dot != std::wstring::npos) {
                const int second = _wtoi(address.substr(4, dot - 4).c_str());
                if (second >= 16 && second <= 31) return true;
            }
        }
        if (address.rfind(L"192.168.", 0) == 0) return true;
        if (address.rfind(L"169.254.", 0) == 0) return true;
        // IPv6 ULA / link-local.
        if (address.rfind(L"fc", 0) == 0 || address.rfind(L"fd", 0) == 0) return true;
        if (address.rfind(L"fe8", 0) == 0 || address.rfind(L"fe9", 0) == 0 ||
            address.rfind(L"fea", 0) == 0 || address.rfind(L"feb", 0) == 0) return true;
        return false;
    };
    for (size_t i = 0; i < context.store.View().size(); ++i) {
        const Connection* row = context.store.ViewRow(i);
        if (row == nullptr || (row->flags & kRowRemoved) != 0) continue;
        ++liveRows;
        byState[WideToUtf8(row->keys.stateLabel.empty() ? L"UNKNOWN" : row->keys.stateLabel)]++;
        byProto[row->identity.protocol == IPPROTO_TCP ? "TCP" : "UDP"]++;
        byFamily[row->identity.family == AF_INET6 ? "IPv6" : "IPv4"]++;
        // Grouped by the process NAME, not a placeholder: a by-process
        // breakdown where every row reads "PROC" answers nothing. The name is
        // attacker-influenced, so it goes through JsonQuote like everything else.
        byProcess[row->display.processName.empty() ? std::string("(no process)")
                                                    : WideToUtf8(row->display.processName)]++;
        if (row->identity.protocol == IPPROTO_TCP && row->keys.stateLabel == L"LISTENING") {
            const std::wstring& local = row->display.localAddress;
            if (local == L"0.0.0.0" || local == L"::" || local == L"*") wildcard++;
            else if (local == L"127.0.0.1" || local == L"::1") loopback++;
            else if (isPrivateListenerAddress(local)) privateCount++;
            else specific++;
        }
    }
    std::ostringstream out;
    out << "{\"total\":" << liveRows << ",\"byState\":{";
    bool first = true;
    for (const auto& kv : byState) { if (!first) out << ","; first = false; out << JsonQuote(kv.first) << ":" << kv.second; }
    out << "},\"byProto\":{";
    first = true;
    for (const auto& kv : byProto) { if (!first) out << ","; first = false; out << JsonQuote(kv.first) << ":" << kv.second; }
    out << "},\"byFamily\":{";
    first = true;
    for (const auto& kv : byFamily) { if (!first) out << ","; first = false; out << JsonQuote(kv.first) << ":" << kv.second; }
    out << "},\"byProcess\":{";
    first = true;
    for (const auto& kv : byProcess) { if (!first) out << ","; first = false; out << JsonQuote(kv.first) << ":" << kv.second; }
    out << "},\"listeners\":{\"loopback\":" << loopback << ",\"private\":" << privateCount
        << ",\"specific\":" << specific << ",\"wildcard\":" << wildcard << "}";
    out << ",\"snapshotKnown\":" << (context.connectionSnapshotTick.load() > 0 ? "true" : "false");
    out << ",\"snapshotAgeMs\":" << (context.connectionSnapshotTick.load() > 0
                                       ? ::GetTickCount64() - context.connectionSnapshotTick.load()
                                       : 0);
    out << "}";
    return out.str();
}

std::string GeoSummaryJson(ServerContext& context) {
    context.lastStoreAccess.store(::GetTickCount64());
    std::lock_guard<std::mutex> lock(g_storeMutex);
    std::map<std::string, int> countries;
    int local = 0, unknown = 0;
    const bool geoLoaded = context.source.GeoIpLoaded();
    for (size_t i = 0; i < context.store.View().size(); ++i) {
        const Connection* row = context.store.ViewRow(i);
        if (row == nullptr || (row->flags & kRowRemoved) != 0) continue;
        // A listening socket has no remote peer, so it has no country. Counting
        // it as "local" would quietly inflate the loopback figure.
        if (row->keys.stateLabel == L"LISTENING") continue;
        if (row->identity.family != AF_INET) continue;
        uint32_t addr = ntohl(row->identity.remote4.S_un.S_addr);
        if (!IsGlobalUnicastV4(addr)) { local++; continue; }
        std::wstring cc = geoLoaded ? context.source.GeoIpLookupV4(addr) : L"";
        if (cc.empty()) unknown++;
        else countries[WideToUtf8(cc)]++;
    }
    std::ostringstream out;
    out << "{\"countries\":{";
    bool first = true;
    for (const auto& kv : countries) { if (!first) out << ","; first = false; out << JsonQuote(kv.first) << ":" << kv.second; }
    // asns is an empty OBJECT, not null: no ASN database is configured, which is
    // a different statement from "there are no ASNs" - and it is stated with
    // geoIpConfigured below so the UI can offer the setup card.
    out << "},\"asns\":{},\"local\":" << local << ",\"unknown\":" << unknown
        << ",\"geoIpConfigured\":" << (geoLoaded ? "true" : "false");
    out << ",\"ipv4Only\":true";
    out << ",\"snapshotKnown\":" << (context.connectionSnapshotTick.load() > 0 ? "true" : "false");
    out << "}";
    return out.str();
}

std::string DiagnosticsJson(ServerContext& context) {
    // Surface the same sampler health the CLI's `doctor` reports, so template
    // evaluators can gate on it. Unknown is never zero: a missing sampler
    // reads "null" with a reason, not "0 timeouts".
    context.lastStoreAccess.store(::GetTickCount64());
    const SocketTrafficSampler* sampler = ActiveTrafficSampler();
    const bool pdh = context.metricsCollector.IsRunning();
    const bool geoLoaded = context.source.GeoIpLoaded();
    std::ostringstream out;
    out << "{\"metrics\":{\"pdh\":" << (pdh ? "true" : "false")
        << ",\"perCore\":" << (pdh && context.metricsCollector.PerCoreAvailable() ? "true" : "false")
        << ",\"geoIp\":{\"configured\":" << (geoLoaded ? "true" : "false")
        << ",\"type\":" << (geoLoaded ? JsonQuote("GeoLite2-Country") : "null") << "}}"
        << ",\"traffic\":{\"scanEnabled\":" << (sampler != nullptr ? "true" : "false");
    if (sampler != nullptr) {
        out << ",\"timeouts\":" << sampler->TimeoutCount()
            << ",\"unreadable\":" << sampler->UnreadableCount()
            << ",\"scanFailures\":" << sampler->ScanFailureCount();
    } else {
        out << ",\"timeouts\":null,\"unreadable\":null,\"scanFailures\":null"
            << ",\"reason\":" << JsonQuote("no active traffic sampler (web UI disables per-socket scan)");
    }
    out << "},\"connectionSnapshotTick\":" << (context.connectionSnapshotTick.load() > 0 ? "true" : "false")
        << ",\"connectionSnapshotAgeMs\":" << (context.connectionSnapshotTick.load() > 0
               ? ::GetTickCount64() - context.connectionSnapshotTick.load()
               : 0)
        << ",\"connectionRefreshFailed\":" << (context.connectionRefreshFailed.load() ? "true" : "false")
        << "}";
    return out.str();
}

std::string FirewallRulesJson(ServerContext& context) {
    (void)context;
    std::vector<BlockedRule> rules;
    std::wstring error;
    std::wstring warning;
    long activeProfileTypes = 0;
    bool activeProfileKnown = false;
    const bool ok = ListFirewallInventory(&rules, &error, &warning,
                                          &activeProfileTypes,
                                          &activeProfileKnown);
    std::ostringstream out;
    if (!ok) {
        // A missing/empty result is NOT an error here: CountWinTcpRules returns
        // 0 with no error when there are no tagged rules.
        out << "{\"rules\":[],\"available\":" << (error.empty() ? "true" : "false")
            << ",\"generatedAt\":" << JsonQuote(UtcTimestamp())
            << ",\"reason\":" << (error.empty() ? "null" : JsonQuote(WideToUtf8(error)))
            << ",\"warnings\":[]"
            << ",\"activeProfileTypes\":null,\"activeProfileKnown\":false"
            << ",\"activeProfileReason\":" << JsonQuote("Firewall policy is unavailable")
            << ",\"scope\":\"Windows Firewall rules exposed by COM plus readable WinTCP-owned rules\"}"
            ;
        return out.str();
    }
    out << "{\"rules\":[";
    bool first = true;
    for (const BlockedRule& b : rules) {
        if (!first) out << ",";
        first = false;
        out << "{\"name\":" << JsonQuote(WideToUtf8(b.name))
            << ",\"ownership\":" << JsonQuote(b.wintcpOwned ? "wintcp" : "windows")
            << ",\"enabled\":" << (b.enabledKnown
                                      ? (b.enabled ? "true" : "false") : "null")
            << ",\"enabledKnown\":" << (b.enabledKnown ? "true" : "false")
            << ",\"enabledReason\":" <<
                (b.enabledKnown ? "null" : JsonQuote("Windows Firewall did not return this field"))
            << ",\"blocking\":" << (b.enabledKnown && b.blockingKnown
                                       ? (b.enabled && b.isBlocking ? "true" : "false") : "null")
            << ",\"blockingKnown\":" <<
                (b.enabledKnown && b.blockingKnown ? "true" : "false")
            << ",\"blockingReason\":" <<
                (b.enabledKnown && b.blockingKnown ? "null" :
                 JsonQuote("Windows Firewall did not return enabled state, direction or action"))
            << ",\"outboundBlockRule\":" << (b.blockingKnown
                ? (b.isBlocking ? "true" : "false") : "null")
            << ",\"outboundBlockRuleKnown\":" << (b.blockingKnown ? "true" : "false")
            << ",\"outboundBlockRuleReason\":" << (b.blockingKnown
                ? "null" : JsonQuote("Windows Firewall did not return direction or action"))
            << ",\"remoteAddrs\":" << (b.remoteAddrsKnown
                ? JsonQuote(WideToUtf8(b.remoteAddrs)) : "null")
            << ",\"remoteAddrsReason\":" << (b.remoteAddrsKnown
                ? "null" : JsonQuote("Windows Firewall did not return remote addresses"))
            << ",\"localPorts\":" << (b.localPortsKnown
                ? JsonQuote(WideToUtf8(b.localPorts)) : "null")
            << ",\"localPortsReason\":" << (b.localPortsKnown
                ? "null" : JsonQuote("Windows Firewall did not return local ports"))
            << ",\"remotePorts\":" << (b.remotePortsKnown
                ? JsonQuote(WideToUtf8(b.remotePorts)) : "null")
            << ",\"remotePortsReason\":" << (b.remotePortsKnown
                ? "null" : JsonQuote("Windows Firewall did not return remote ports"))
            << ",\"localAddrs\":" << (b.localAddrsKnown
                ? JsonQuote(WideToUtf8(b.localAddrs)) : "null")
            << ",\"localAddrsReason\":" << (b.localAddrsKnown
                ? "null" : JsonQuote("Windows Firewall did not return local addresses"))
            << ",\"application\":" << (b.applicationKnown
                ? JsonQuote(WideToUtf8(b.application)) : "null")
            << ",\"applicationReason\":" << (b.applicationKnown
                ? "null" : JsonQuote("Windows Firewall did not return application scope"))
            << ",\"service\":" << (b.serviceKnown
                ? JsonQuote(WideToUtf8(b.service)) : "null")
            << ",\"serviceReason\":" << (b.serviceKnown
                ? "null" : JsonQuote("Windows Firewall did not return service scope"))
            << ",\"direction\":" << (b.directionKnown
                ? std::to_string(b.direction) : "null")
            << ",\"directionReason\":" << (b.directionKnown
                ? "null" : JsonQuote("Windows Firewall did not return direction"))
            << ",\"action\":" << (b.actionKnown
                ? std::to_string(b.action) : "null")
            << ",\"actionReason\":" << (b.actionKnown
                ? "null" : JsonQuote("Windows Firewall did not return action"))
            << ",\"protocol\":" << (b.protocolKnown
                ? std::to_string(b.protocol) : "null")
            << ",\"protocolReason\":" << (b.protocolKnown
                ? "null" : JsonQuote("Windows Firewall did not return protocol"))
            << ",\"profiles\":" << (b.profilesKnown
                ? std::to_string(b.profiles) : "null")
            << ",\"profilesReason\":" << (b.profilesKnown
                ? "null" : JsonQuote("Windows Firewall did not return profiles"))
            << "}";
    }
    out << "],\"available\":true,\"reason\":null"
        << ",\"activeProfileTypes\":"
        << (activeProfileKnown ? std::to_string(activeProfileTypes) : "null")
        << ",\"activeProfileKnown\":" << (activeProfileKnown ? "true" : "false")
        << ",\"activeProfileReason\":"
        << (activeProfileKnown ? "null" : JsonQuote("Windows did not return the active firewall profile"))
        << ",\"warnings\":["
        << (warning.empty() ? "" : JsonQuote(WideToUtf8(warning))) << "]"
        << ",\"scope\":\"Windows Firewall rules exposed by COM plus readable WinTCP-owned rules\""
        << ",\"generatedAt\":" << JsonQuote(UtcTimestamp()) << "}";
    return out.str();
}

bool SameFirewallRuleCapture(const BlockedRule& captured,
                             const BlockedRule& current) {
    return ::CompareStringOrdinal(captured.name.c_str(),
                                  static_cast<int>(captured.name.size()),
                                  current.name.c_str(),
                                  static_cast<int>(current.name.size()), TRUE) ==
               CSTR_EQUAL &&
           captured.wintcpOwned == current.wintcpOwned &&
           captured.enabledKnown == current.enabledKnown &&
           (!captured.enabledKnown || captured.enabled == current.enabled) &&
           captured.blockingKnown == current.blockingKnown &&
           (!captured.blockingKnown || captured.isBlocking == current.isBlocking) &&
           captured.remoteAddrsKnown == current.remoteAddrsKnown &&
           (!captured.remoteAddrsKnown || captured.remoteAddrs == current.remoteAddrs) &&
           captured.localAddrsKnown == current.localAddrsKnown &&
           (!captured.localAddrsKnown || captured.localAddrs == current.localAddrs) &&
           captured.localPortsKnown == current.localPortsKnown &&
           (!captured.localPortsKnown || captured.localPorts == current.localPorts) &&
           captured.remotePortsKnown == current.remotePortsKnown &&
           (!captured.remotePortsKnown || captured.remotePorts == current.remotePorts) &&
           captured.applicationKnown == current.applicationKnown &&
           (!captured.applicationKnown || captured.application == current.application) &&
           captured.serviceKnown == current.serviceKnown &&
           (!captured.serviceKnown || captured.service == current.service) &&
           captured.directionKnown == current.directionKnown &&
           (!captured.directionKnown || captured.direction == current.direction) &&
           captured.actionKnown == current.actionKnown &&
           (!captured.actionKnown || captured.action == current.action) &&
           captured.protocolKnown == current.protocolKnown &&
           (!captured.protocolKnown || captured.protocol == current.protocol) &&
           captured.profilesKnown == current.profilesKnown &&
           (!captured.profilesKnown || captured.profiles == current.profiles);
}

std::string FirewallRuleReviewJson(const BlockedRule& rule) {
    std::ostringstream out;
    out << ",\"direction\":" << (rule.directionKnown
        ? std::to_string(rule.direction) : "null")
        << ",\"action\":" << (rule.actionKnown
        ? std::to_string(rule.action) : "null")
        << ",\"protocol\":" << (rule.protocolKnown
        ? std::to_string(rule.protocol) : "null")
        << ",\"profiles\":" << (rule.profilesKnown
        ? std::to_string(rule.profiles) : "null")
        << ",\"localAddresses\":" << (rule.localAddrsKnown
        ? JsonQuote(WideToUtf8(rule.localAddrs)) : "null")
        << ",\"remoteAddresses\":" << (rule.remoteAddrsKnown
        ? JsonQuote(WideToUtf8(rule.remoteAddrs)) : "null")
        << ",\"localPorts\":" << (rule.localPortsKnown
        ? JsonQuote(WideToUtf8(rule.localPorts)) : "null")
        << ",\"remotePorts\":" << (rule.remotePortsKnown
        ? JsonQuote(WideToUtf8(rule.remotePorts)) : "null")
        << ",\"application\":" << (rule.applicationKnown
        ? JsonQuote(WideToUtf8(rule.application)) : "null")
        << ",\"service\":" << (rule.serviceKnown
        ? JsonQuote(WideToUtf8(rule.service)) : "null");
    return out.str();
}

bool SameCreatedFirewallRule(const RuleRequest& request,
                             const BlockedRule& current) {
    const auto sameScope = [](const std::wstring& actual,
                              const std::wstring& expected) {
        if (actual == expected) return true;
        const bool actualAny = actual.empty() || actual == L"*";
        const bool expectedAny = expected.empty() || expected == L"*";
        return actualAny && expectedAny;
    };
    const LONG protocol = request.proto == L"tcp" ? 6
        : request.proto == L"udp" ? 17 : 0;
    const LONG direction = request.inbound ? 1 : 2;
    const LONG action = request.allow ? 1 : 0;
    const std::wstring process = request.process.empty() ? L"" : request.process;
    return current.wintcpOwned && current.enabledKnown && current.enabled &&
        current.directionKnown && current.direction == direction &&
        current.actionKnown && current.action == action &&
        current.protocolKnown && (protocol == 0
            ? (current.protocol == 0 || current.protocol == 256)
            : current.protocol == protocol) &&
        current.profilesKnown && current.profiles == request.profiles &&
        current.localAddrsKnown && sameScope(current.localAddrs, request.localAddress) &&
        current.remoteAddrsKnown && sameScope(current.remoteAddrs, request.address) &&
        current.localPortsKnown && sameScope(current.localPorts,
            request.localPorts.empty() ? L"*" : request.localPorts) &&
        current.remotePortsKnown && sameScope(current.remotePorts,
            request.remotePorts.empty() ? L"*" : request.remotePorts) &&
        current.applicationKnown && sameScope(current.application, process) &&
        current.serviceKnown && sameScope(current.service, request.service);
}

const BlockedRule* FindFirewallRule(const std::vector<BlockedRule>& rules,
                                    const std::wstring& name,
                                    size_t* matches) {
    const BlockedRule* found = nullptr;
    size_t count = 0;
    for (const BlockedRule& rule : rules) {
        if (::CompareStringOrdinal(rule.name.c_str(),
                                   static_cast<int>(rule.name.size()),
                                   name.c_str(), static_cast<int>(name.size()),
                                   TRUE) != CSTR_EQUAL)
            continue;
        found = &rule;
        ++count;
    }
    if (matches != nullptr) *matches = count;
    return found;
}

bool DecodeFormValue(const std::string& raw, std::string* out) {
    if (out == nullptr) return false;
    out->clear();
    for (size_t i = 0; i < raw.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(raw[i]);
        if (c == '+') c = ' ';
        else if (c == '%') {
            if (i + 2 >= raw.size()) return false;
            auto hex = [](char h) -> int {
                if (h >= '0' && h <= '9') return h - '0';
                if (h >= 'a' && h <= 'f') return h - 'a' + 10;
                if (h >= 'A' && h <= 'F') return h - 'A' + 10;
                return -1;
            };
            const int hi = hex(raw[i + 1]);
            const int lo = hex(raw[i + 2]);
            if (hi < 0 || lo < 0) return false;
            c = static_cast<unsigned char>((hi << 4) | lo);
            i += 2;
        }
        if (c < 0x20 || c == 0x7f) return false;
        out->push_back(static_cast<char>(c));
    }
    return true;
}

bool ParseForm(const std::string& body, std::map<std::string, std::string>* fields) {
    if (fields == nullptr || body.size() > 4096) return false;
    fields->clear();
    size_t start = 0;
    while (start <= body.size()) {
        const size_t amp = body.find('&', start);
        const std::string pair = body.substr(start, amp == std::string::npos
                                                      ? std::string::npos : amp - start);
        const size_t eq = pair.find('=');
        if (eq == std::string::npos) return false;
        std::string key, value;
        if (!DecodeFormValue(pair.substr(0, eq), &key) ||
            !DecodeFormValue(pair.substr(eq + 1), &value) || key.empty() ||
            fields->find(key) != fields->end()) return false;
        fields->emplace(std::move(key), std::move(value));
        if (amp == std::string::npos) break;
        start = amp + 1;
    }
    return true;
}

struct CliInvocation {
    std::wstring verb;
    std::vector<std::wstring> args;
};

bool CliWordIs(const std::wstring& value, const wchar_t* wanted) {
    size_t i = 0;
    for (; i < value.size() && wanted[i] != L'\0'; ++i) {
        wchar_t a = value[i];
        wchar_t b = wanted[i];
        if (a >= L'A' && a <= L'Z') a = static_cast<wchar_t>(a - L'A' + L'a');
        if (b >= L'A' && b <= L'Z') b = static_cast<wchar_t>(b - L'A' + L'a');
        if (a != b) return false;
    }
    return i == value.size() && wanted[i] == L'\0';
}

bool ParseCliForm(const std::string& body, bool allowNonce, bool allowConfirmed,
                  CliInvocation* invocation, std::string* nonce,
                  bool* confirmed) {
    if (invocation == nullptr) return false;
    std::map<std::string, std::string> fields;
    if (!ParseForm(body, &fields)) return false;
    const auto verb = fields.find("verb");
    const auto argcField = fields.find("argc");
    if (verb == fields.end() || argcField == fields.end() ||
        verb->second.empty() || verb->second.size() > 32) return false;
    size_t argc = 0;
    for (char c : argcField->second) {
        if (c < '0' || c > '9') return false;
        argc = argc * 10 + static_cast<size_t>(c - '0');
        if (argc > kMaxCliArgs) return false;
    }
    const bool hasNonce = fields.find("nonce") != fields.end();
    const bool hasConfirmed = fields.find("confirmed") != fields.end();
    if ((hasNonce && !allowNonce) || (hasConfirmed && !allowConfirmed) ||
        (allowNonce && hasNonce && fields["nonce"].size() > 64) ||
        (allowConfirmed && hasConfirmed && fields["confirmed"] != "1") ||
        fields.size() != argc + 2 + (hasNonce ? 1 : 0) +
                                      (hasConfirmed ? 1 : 0)) return false;
    std::wstring wideVerb;
    if (!Utf8ToWide(verb->second, &wideVerb)) return false;
    for (wchar_t& c : wideVerb) {
        if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c - L'A' + L'a');
        if (!((c >= L'a' && c <= L'z') || (c >= L'0' && c <= L'9') || c == L'-'))
            return false;
    }
    if (wideVerb.empty() || wideVerb.front() < L'a' || wideVerb.front() > L'z')
        return false;
    invocation->verb = std::move(wideVerb);
    invocation->args.clear();
    size_t commandChars = invocation->verb.size();
    for (size_t i = 0; i < argc; ++i) {
        const std::string key = "arg" + std::to_string(i);
        const auto value = fields.find(key);
        if (value == fields.end() || value->second.size() > kMaxCliArgBytes)
            return false;
        std::wstring wide;
        if (!Utf8ToWide(value->second, &wide)) return false;
        commandChars += wide.size() + 1;
        if (commandChars > 8192) return false;
        invocation->args.push_back(std::move(wide));
    }
    if (nonce != nullptr) *nonce = hasNonce ? fields["nonce"] : std::string();
    if (confirmed != nullptr) *confirmed = hasConfirmed && fields["confirmed"] == "1";
    return true;
}

bool HasCliArg(const CliInvocation& invocation, const wchar_t* wanted) {
    for (const std::wstring& arg : invocation.args) {
        if (CliWordIs(arg, wanted)) return true;
    }
    return false;
}

bool IsSensitiveCli(const CliInvocation& invocation) {
    const bool dryRun = HasCliArg(invocation, L"--dry-run");
    if (!dryRun && (invocation.verb == L"kill" || invocation.verb == L"close" ||
                    invocation.verb == L"block" || invocation.verb == L"unblock" ||
                    invocation.verb == L"capture")) return true;
    if (HasCliArg(invocation, L"--yes") || HasCliArg(invocation, L"-y") ||
        HasCliArg(invocation, L"--force")) return true;
    if (invocation.verb == L"export" || HasCliArg(invocation, L"--out")) return true;
    if (invocation.verb == L"bookmark" || invocation.verb == L"preset") {
        if (!invocation.args.empty()) {
            const std::wstring& sub = invocation.args.front();
            if (CliWordIs(sub, L"add") || CliWordIs(sub, L"remove") ||
                CliWordIs(sub, L"delete") || CliWordIs(sub, L"note") ||
                CliWordIs(sub, L"colour") || CliWordIs(sub, L"save") ||
                CliWordIs(sub, L"import")) return true;
        }
    }
    if (invocation.verb == L"alert") {
        for (const std::wstring& arg : invocation.args) {
            if (CliWordIs(arg, L"--enable") || CliWordIs(arg, L"--disable") ||
                CliWordIs(arg, L"--on-listener") || CliWordIs(arg, L"--off-listener") ||
                CliWordIs(arg, L"--on-connection") || CliWordIs(arg, L"--off-connection") ||
                CliWordIs(arg, L"--on-rst") || CliWordIs(arg, L"--off-rst") ||
                CliWordIs(arg, L"--on-closed") || CliWordIs(arg, L"--off-closed") ||
                CliWordIs(arg, L"--rule-on-new") || CliWordIs(arg, L"--rule-off-new") ||
                CliWordIs(arg, L"--rule-on-close") || CliWordIs(arg, L"--rule-off-close") ||
                CliWordIs(arg, L"--rule-on-threshold") || CliWordIs(arg, L"--bps-warn") ||
                CliWordIs(arg, L"--bps-critical") || CliWordIs(arg, L"--connections") ||
                CliWordIs(arg, L"--rule-name") || CliWordIs(arg, L"--rule-address") ||
                CliWordIs(arg, L"--rule-process")) return true;
        }
    }
    return false;
}

bool CheckCliBounds(const CliInvocation& invocation, std::string* error) {
    if (invocation.verb == L"webui") {
        if (error != nullptr) *error = "scripts cannot start another Web UI service";
        return false;
    }
    if (HasCliArg(invocation, L"--watch") || HasCliArg(invocation, L"--interval")) {
        unsigned count = 0;
        unsigned interval = 2;
        for (size_t i = 0; i < invocation.args.size(); ++i) {
            const std::wstring& arg = invocation.args[i];
            if (CliWordIs(arg, L"--count") || CliWordIs(arg, L"--interval")) {
                if (i + 1 >= invocation.args.size()) {
                    if (error != nullptr) *error = "--count and --interval require values in scripts";
                    return false;
                }
                unsigned value = 0;
                const std::wstring& text = invocation.args[++i];
                for (wchar_t c : text) {
                    if (c < L'0' || c > L'9' || value > 100000) {
                        if (error != nullptr) *error = "watch bounds must be decimal integers";
                        return false;
                    }
                    value = value * 10 + static_cast<unsigned>(c - L'0');
                }
                if (CliWordIs(arg, L"--count")) count = value;
                else interval = value;
            } else if (CliWordIs(arg, L"--watch") && i + 1 < invocation.args.size() &&
                       !invocation.args[i + 1].empty() && invocation.args[i + 1][0] != L'-') {
                unsigned value = 0;
                const std::wstring& text = invocation.args[++i];
                for (wchar_t c : text) {
                    if (c < L'0' || c > L'9' || value > 100000) {
                        if (error != nullptr) *error = "watch interval must be a decimal integer";
                        return false;
                    }
                    value = value * 10 + static_cast<unsigned>(c - L'0');
                }
                interval = value;
            }
        }
        if (count == 0 || count > 20 || interval == 0 || interval > 3600 ||
            static_cast<ULONGLONG>(count) * interval > 12) {
            if (error != nullptr)
                *error = "scripted watch commands require --count and must fit within 12 seconds";
            return false;
        }
    }
    if (invocation.verb == L"capture" && !HasCliArg(invocation, L"--dry-run")) {
        unsigned seconds = 5;
        for (size_t i = 0; i + 1 < invocation.args.size(); ++i) {
            if (!CliWordIs(invocation.args[i], L"--secs")) continue;
            seconds = 0;
            for (wchar_t c : invocation.args[i + 1]) {
                if (c < L'0' || c > L'9' || seconds > 1000) {
                    if (error != nullptr) *error = "capture duration must be a decimal integer";
                    return false;
                }
                seconds = seconds * 10 + static_cast<unsigned>(c - L'0');
            }
        }
        if (seconds > 15) {
            if (error != nullptr) *error = "scripted captures are limited to 15 seconds";
            return false;
        }
    }
    return true;
}

std::wstring QuoteWindowsArgument(const std::wstring& argument) {
    if (!argument.empty() && argument.find_first_of(L" \t\n\v\"") == std::wstring::npos)
        return argument;
    std::wstring quoted(1, L'\"');
    size_t slashes = 0;
    for (wchar_t c : argument) {
        if (c == L'\\') {
            ++slashes;
        } else if (c == L'\"') {
            quoted.append(slashes * 2 + 1, L'\\');
            quoted.push_back(c);
            slashes = 0;
        } else {
            quoted.append(slashes, L'\\');
            slashes = 0;
            quoted.push_back(c);
        }
    }
    quoted.append(slashes * 2, L'\\');
    quoted.push_back(L'\"');
    return quoted;
}

void AppendCapturedBytes(HANDLE pipe, std::string* output, bool* closed,
                         bool* truncated) {
    if (output == nullptr || closed == nullptr || truncated == nullptr || *closed) return;
    for (;;) {
        DWORD available = 0;
        if (!::PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr)) {
            *closed = true;
            return;
        }
        if (available == 0) return;
        char buffer[4096];
        const DWORD requested = (std::min)(available, static_cast<DWORD>(sizeof(buffer)));
        DWORD read = 0;
        if (!::ReadFile(pipe, buffer, requested, &read, nullptr) || read == 0) {
            *closed = true;
            return;
        }
        const size_t remaining = output->size() < kMaxCliOutputBytes
            ? kMaxCliOutputBytes - output->size() : 0;
        const size_t keep = (std::min)(remaining, static_cast<size_t>(read));
        output->append(buffer, keep);
        if (keep < read) *truncated = true;
    }
}

std::string CapturedOutputUtf8(const std::string& bytes) {
    std::wstring wide;
    if (Utf8ToWide(bytes, &wide)) return bytes;
    if (bytes.empty()) return {};
    const int count = ::MultiByteToWideChar(CP_ACP, 0, bytes.data(),
        static_cast<int>(bytes.size()), nullptr, 0);
    if (count <= 0) return "[output encoding could not be decoded]";
    wide.resize(static_cast<size_t>(count));
    if (::MultiByteToWideChar(CP_ACP, 0, bytes.data(), static_cast<int>(bytes.size()),
                              wide.data(), count) != count)
        return "[output encoding could not be decoded]";
    const int utf8Count = ::WideCharToMultiByte(CP_UTF8, 0, wide.data(), count,
                                                 nullptr, 0, nullptr, nullptr);
    if (utf8Count <= 0) return "[output encoding could not be converted]";
    std::string utf8(static_cast<size_t>(utf8Count), '\0');
    if (::WideCharToMultiByte(CP_UTF8, 0, wide.data(), count, utf8.data(),
                              utf8Count, nullptr, nullptr) != utf8Count)
        return "[output encoding could not be converted]";
    return utf8;
}

struct CliExecutionResult {
    bool started = false;
    bool timedOut = false;
    bool truncated = false;
    int exitCode = kExitFail;
    ULONGLONG durationMs = 0;
    std::string out;
    std::string err;
    std::string error;
};

CliExecutionResult ExecuteSiblingCli(const ServerContext& context,
                                    const CliInvocation& invocation) {
    CliExecutionResult result;
    const std::wstring executable = context.executableDirectory + L"wintcp.exe";
    if (::GetFileAttributesW(executable.c_str()) == INVALID_FILE_ATTRIBUTES) {
        result.error = "sibling wintcp.exe was not found beside the Web UI service";
        return result;
    }
    SECURITY_ATTRIBUTES security = {};
    security.nLength = sizeof(security);
    security.bInheritHandle = TRUE;
    HANDLE outRead = nullptr, outWrite = nullptr, errRead = nullptr, errWrite = nullptr;
    if (!::CreatePipe(&outRead, &outWrite, &security, 0) ||
        !::CreatePipe(&errRead, &errWrite, &security, 0)) {
        if (outRead) ::CloseHandle(outRead);
        if (outWrite) ::CloseHandle(outWrite);
        if (errRead) ::CloseHandle(errRead);
        if (errWrite) ::CloseHandle(errWrite);
        result.error = "could not create CLI output pipes";
        return result;
    }
    (void)::SetHandleInformation(outRead, HANDLE_FLAG_INHERIT, 0);
    (void)::SetHandleInformation(errRead, HANDLE_FLAG_INHERIT, 0);
    HANDLE nullInput = ::CreateFileW(L"NUL", GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (nullInput == INVALID_HANDLE_VALUE) {
        ::CloseHandle(outRead); ::CloseHandle(outWrite);
        ::CloseHandle(errRead); ::CloseHandle(errWrite);
        result.error = "could not open a non-interactive CLI input handle";
        return result;
    }
    std::wstring commandLine = QuoteWindowsArgument(executable) + L" " +
                               QuoteWindowsArgument(invocation.verb);
    for (const std::wstring& arg : invocation.args)
        commandLine += L" " + QuoteWindowsArgument(arg);
    STARTUPINFOW startup = {};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = nullInput;
    startup.hStdOutput = outWrite;
    startup.hStdError = errWrite;
    PROCESS_INFORMATION process = {};
    const ULONGLONG start = ::GetTickCount64();
    const BOOL created = ::CreateProcessW(executable.c_str(), commandLine.data(),
        nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr,
        context.executableDirectory.c_str(), &startup, &process);
    ::CloseHandle(nullInput);
    ::CloseHandle(outWrite);
    ::CloseHandle(errWrite);
    if (!created) {
        ::CloseHandle(outRead); ::CloseHandle(errRead);
        result.error = "could not start the local CLI process";
        return result;
    }
    result.started = true;
    bool outClosed = false, errClosed = false, childDone = false;
    for (;;) {
        AppendCapturedBytes(outRead, &result.out, &outClosed, &result.truncated);
        AppendCapturedBytes(errRead, &result.err, &errClosed, &result.truncated);
        const DWORD wait = ::WaitForSingleObject(process.hProcess, 20);
        if (wait == WAIT_OBJECT_0) childDone = true;
        if (!childDone && ::GetTickCount64() - start >= kMaxCliExecutionMs) {
            result.timedOut = true;
            (void)::TerminateProcess(process.hProcess, 124);
            (void)::WaitForSingleObject(process.hProcess, 5000);
            childDone = true;
        }
        if (childDone) {
            AppendCapturedBytes(outRead, &result.out, &outClosed, &result.truncated);
            AppendCapturedBytes(errRead, &result.err, &errClosed, &result.truncated);
            if (outClosed && errClosed) break;
        }
        if (wait == WAIT_FAILED) {
            result.error = "waiting for the local CLI process failed";
            (void)::TerminateProcess(process.hProcess, 1);
            (void)::WaitForSingleObject(process.hProcess, 5000);
            childDone = true;
        }
    }
    DWORD exitCode = 1;
    (void)::GetExitCodeProcess(process.hProcess, &exitCode);
    result.exitCode = result.timedOut ? 124 : static_cast<int>(exitCode);
    result.durationMs = ::GetTickCount64() - start;
    ::CloseHandle(process.hThread);
    ::CloseHandle(process.hProcess);
    ::CloseHandle(outRead);
    ::CloseHandle(errRead);
    result.out = CapturedOutputUtf8(result.out);
    result.err = CapturedOutputUtf8(result.err);
    return result;
}

bool ParsePort(const std::string& text, UINT* port, bool allowAll = false) {
    if (port == nullptr || text.empty() || text.size() > 5) return false;
    unsigned value = 0;
    for (char c : text) {
        if (c < '0' || c > '9') return false;
        value = value * 10 + static_cast<unsigned>(c - '0');
    }
    if (value > 65535 || (value == 0 && !allowAll)) return false;
    *port = value;
    return true;
}

bool IsIpAddress(const std::string& address) {
    IN_ADDR v4 = {};
    IN6_ADDR v6 = {};
    return ::InetPtonA(AF_INET, address.c_str(), &v4) == 1 ||
           ::InetPtonA(AF_INET6, address.c_str(), &v6) == 1;
}

bool IsServiceShortName(const std::string& name) {
    if (name.empty() || name.size() > 256) return false;
    for (unsigned char c : name) {
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.')) {
            return false;
        }
    }
    return true;
}

std::string ProcessInstanceId(const Connection& row) {
    if (!row.procMeta.processCreateKnown) return "";
    return std::to_string(row.identity.pid) + ":" +
           std::to_string(row.procMeta.processCreate.dwHighDateTime) + ":" +
           std::to_string(row.procMeta.processCreate.dwLowDateTime);
}

std::string ProcessInstanceId(const WebProcessRow& row) {
    if (!row.stats.processCreateKnown) return "";
    return std::to_string(row.pid) + ":" +
           std::to_string(row.stats.processCreateTime.dwHighDateTime) + ":" +
           std::to_string(row.stats.processCreateTime.dwLowDateTime);
}

std::string ConnectionColumnText(const Connection& row, int column) {
    wchar_t text[kMaxColumnText] = {};
    ConnectionStore::GetColumnText(row, column, text, kMaxColumnText);
    return WideToUtf8(text);
}

bool MatchesCloseCapture(const std::map<std::string, std::string>& fields,
                         const Connection& row, uint64_t* connectionId) {
    static const char* const names[] = {
        "idExact", "processInstanceId", "pid", "proto", "local", "lport",
        "remote", "rport", "state",
    };
    if (fields.size() != sizeof(names) / sizeof(names[0])) return false;
    for (const char* name : names) {
        if (fields.find(name) == fields.end()) return false;
    }
    uint64_t id = 0, pid = 0;
    if (!ParseUint64Strict(fields.at("idExact"), &id) ||
        !ParseUint64Strict(fields.at("pid"), &pid) || pid > MAXDWORD) {
        return false;
    }
    if (fields.at("processInstanceId") != ProcessInstanceId(row) ||
        fields.at("pid") != std::to_string(row.identity.pid) ||
        fields.at("proto") != ConnectionColumnText(row, COL_PROTO) ||
        fields.at("local") != ConnectionColumnText(row, COL_LOCAL) ||
        fields.at("lport") != ConnectionColumnText(row, COL_LPORT) ||
        fields.at("remote") != ConnectionColumnText(row, COL_REMOTE) ||
        fields.at("rport") != ConnectionColumnText(row, COL_RPORT) ||
        fields.at("state") != ConnectionColumnText(row, COL_STATE)) {
        return false;
    }
    if (connectionId != nullptr) *connectionId = id;
    return true;
}

bool SameCloseIdentity(const Connection& captured, const Connection& current) {
    if (!SameProcessLifetime(captured, current) ||
        captured.identity.family != AF_INET ||
        current.identity.family != AF_INET ||
        captured.identity.protocol != IPPROTO_TCP ||
        current.identity.protocol != IPPROTO_TCP ||
        captured.identity.state != MIB_TCP_STATE_ESTAB ||
        current.identity.state != MIB_TCP_STATE_ESTAB ||
        captured.identity.localPort != current.identity.localPort ||
        captured.identity.remotePort != current.identity.remotePort ||
        captured.identity.local4.S_un.S_addr != current.identity.local4.S_un.S_addr ||
        captured.identity.remote4.S_un.S_addr != current.identity.remote4.S_un.S_addr) {
        return false;
    }
    return true;
}

RuleRequest BlockRequest(const std::string& address, UINT port) {
    RuleRequest request;
    request.proto = L"tcp";
    request.address.assign(address.begin(), address.end());
    if (port != 0) request.remotePorts = std::to_wstring(port);
    request.label = L"WinTCP Web UI peer threshold";
    return request;
}

RuleRequest ApplicationBlockRequest(const std::wstring& processPath,
                                    bool allow = false) {
    RuleRequest request = BlockRequest("*", 0);
    request.process = processPath;
    request.allow = allow;
    request.label = allow ? L"WinTCP Web UI application allow"
                          : L"WinTCP Web UI application block";
    return request;
}

std::string RuleNameFromPlan(const std::string& plan) {
    constexpr char kPrefix[] = "rule ";
    if (plan.compare(0, sizeof(kPrefix) - 1, kPrefix) != 0) return {};
    const size_t end = plan.find_first_of("\r\n", sizeof(kPrefix) - 1);
    if (end == std::string::npos || end == sizeof(kPrefix) - 1) return {};
    return plan.substr(sizeof(kPrefix) - 1, end - (sizeof(kPrefix) - 1));
}

bool ReadConfigSnapshot(ServerContext& context, std::string* body,
                        std::string* etag) {
    if (!ReadFileBounded(context.configPath, kMaxBodyBytes, body) ||
        !IsValidJsonObject(*body)) {
        if (!ReadAsset(context, L"config.default.json", body) ||
            !IsValidJsonObject(*body)) {
            *body = "{\"version\":" + std::to_string(kExpectedConfigVersion) +
                    ",\"refreshSeconds\":5,\"rules\":[]}";
        }
    }
    if (context.configEtag.empty() || context.configBytes != *body) {
        std::string revision;
        if (!RandomHex(16, &revision)) return false;
        context.configBytes = *body;
        context.configEtag = "\"" + revision + "\"";
    }
    *etag = context.configEtag;
    return true;
}

// Serve an HTML shell with the session token substituted into its meta tag.
bool ServeShell(ServerContext& context, const wchar_t* asset, HttpResponse* response) {
    response->contentType = "text/html; charset=utf-8";
    if (!ReadAsset(context, asset, &response->body)) {
        response->status = 500;
        response->body = ErrorJson("Web UI asset missing; expected sibling webui folder");
        return false;
    }
    const std::string placeholder = "{{WIN_TCP_TOKEN}}";
    const size_t at = response->body.find(placeholder);
    if (at == std::string::npos) {
        response->status = 500;
        response->body = ErrorJson("Web UI page is missing its token placeholder");
        return false;
    }
    response->body.replace(at, placeholder.size(), context.token);
    return true;
}

HttpResponse HandleRequest(ServerContext& context, const HttpRequest& request) {
    HttpResponse response;
    if (!ValidHostAndOrigin(context, request)) {
        response.status = 403;
        response.body = ErrorJson("host or origin is not allowed");
        return response;
    }
    const size_t query = request.target.find('?');
    const std::string path = request.target.substr(0, query);
    if (request.method != "GET" && request.method != "HEAD" &&
        request.method != "POST") {
        response.status = 405;
        response.body = ErrorJson("method not allowed");
        return response;
    }
    if (path == "/" || path == "/index.html") {
        ServeShell(context, L"index.html", &response);
        return response;
    }
    if (path == "/app.js" || path == "/app.css") {
        response.contentType = path == "/app.js"
                                   ? "text/javascript; charset=utf-8"
                                   : "text/css; charset=utf-8";
        const wchar_t* file = path == "/app.js" ? L"app.js" : L"app.css";
        if (!ReadAsset(context, file, &response.body)) {
            response.status = 404;
            response.body = "Not found";
        }
        return response;
    }
    // Static assets: /js/*, /css/*, /vendor/*, /data/*, /img/*, /fonts/*.
    // IsSafeStaticPath owns the allow-list of prefixes AND extensions, so it is
    // the only gate here: this used to repeat the prefix list inline and had
    // already drifted from WebStatic, which is how every subdirectory asset 404'd.
    // Anything it rejects falls through to the API routes and then to 404.
    if (path.size() > 1 && path[0] == '/' && IsRejectedStaticPath(path)) {
        // Under a static prefix but refused (traversal, reserved device name,
        // disallowed extension). 403, not 404: a traversal attempt is a
        // rejection, and it must not be logged as a missing asset.
        WriteWebUiLog(context, WebUiLogLevel::Warn,
                      "static request rejected path=" + path);
        response.status = 403;
        response.body = "Forbidden";
        return response;
    }
    if (path.size() > 1 && path[0] == '/' && IsSafeStaticPath(path)) {
        // Map the URL path to a file in the webui directory.
        std::wstring relative;
        if (!Utf8ToWide(path.substr(1), &relative)) {
            response.status = 400;
            response.body = "Bad request";
            return response;
        }
        // Replace forward slashes with backslashes for Windows. IsSafeStaticPath
        // already rejected backslashes in the URL, so this is the only place a
        // separator is introduced.
        for (auto& ch : relative) { if (ch == L'/') ch = L'\\'; }
        // NOTE: read the resolved ABSOLUTE path here. ReadAsset() prepends
        // <exedir>\webui\, so passing it an already-resolved path produced
        // <exedir>\webui\<exedir>\webui\js\main.js and every subdirectory asset
        // answered 404 (the page rendered with no CSS and no JS).
        const std::wstring fullPath = context.executableDirectory + L"webui\\" + relative;
        const size_t maxBytes = StaticMaxBytesFor(path);
        // Validate every path component, not just the final one: an intermediate
        // junction or symlink could otherwise escape the webui tree.
        std::wstring current = context.executableDirectory + L"webui";
        size_t pos = 0;
        bool found = true;
        WIN32_FILE_ATTRIBUTE_DATA fad = {};
        while (true) {
            const size_t next = relative.find(L'\\', pos);
            const std::wstring component =
                (next == std::wstring::npos) ? relative.substr(pos)
                                             : relative.substr(pos, next - pos);
            if (component.empty()) break;
            current += L"\\" + component;
            if (!::GetFileAttributesExW(current.c_str(), GetFileExInfoStandard,
                                        &fad)) {
                found = false;
                break;
            }
            if ((fad.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
                response.status = 403;
                response.body = "Forbidden";
                return response;
            }
            if (next == std::wstring::npos) {
                if ((fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                    response.status = 403;
                    response.body = "Forbidden";
                    return response;
                }
            } else if ((fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
                response.status = 404;
                response.body = "Not found";
                return response;
            }
            if (next == std::wstring::npos) break;
            pos = next + 1;
        }
        if (found) {
            const ULONGLONG fileSize =
                (static_cast<ULONGLONG>(fad.nFileSizeHigh) << 32) | fad.nFileSizeLow;
            if (fileSize > maxBytes) {
                response.status = 413;
                response.body = "File too large";
                return response;
            }
        }
        // ReadFileBounded re-checks the cap, so an oversized file cannot slip
        // through between the stat above and the read.
        if (!ReadFileBounded(fullPath, maxBytes, &response.body)) {
            response.status = 404;
            response.body = "Not found";
            return response;
        }
        // Set the correct MIME type.
        size_t dot = path.rfind('.');
        if (dot != std::string::npos) {
            response.contentType = StaticMimeType(path.substr(dot));
        }
        return response;
    }
    if (path == "/api/health") {
        response.body = "{\"ok\":true,\"bind\":\"127.0.0.1\",\"version\":\"1\"}";
        return response;
    }
    if (path == "/api/connections") {
        std::wstring filter;
        if (query != std::string::npos) {
            std::map<std::string, std::string> parameters;
            if (!ParseForm(request.target.substr(query + 1), &parameters) ||
                parameters.size() != 1 || parameters.find("filter") == parameters.end() ||
                parameters["filter"].size() > 1024 ||
                !Utf8ToWide(parameters["filter"], &filter)) {
                response.status = 400;
                response.body = ErrorJson("connections accepts one valid UTF-8 filter parameter up to 1024 bytes");
                return response;
            }
            std::vector<FilterClause> clauses;
            if (!ParseFilter(filter, clauses)) {
                response.status = 400;
                response.body = ErrorJson("invalid WinTCP filter syntax");
                return response;
            }
        }
        response.body = ConnectionsJson(context, filter);
        if (response.body.find("\"error\"") == 1) response.status = 503;
        return response;
    }
    if (path == "/api/templates") {
        if (!ReadAsset(context, L"templates.json", &response.body) ||
            response.body.size() > kMaxAssetBytes) {
            response.status = 500;
            response.body = ErrorJson("template catalog missing or too large");
        }
        return response;
    }
    if (path == "/api/capabilities") {
        response.body = CapabilitiesJson(context);
        return response;
    }
    if (path == "/api/system/info") {
        response.body = SystemInfoJson(context);
        return response;
    }
    if (path == "/api/metrics/catalog") {
        // The catalog names every series the history endpoint answers for, so
        // it is built from a live sample: a hand-written list silently drifts
        // from what the sampler actually produces (per-core and per-instance
        // series only exist when the counters exist).
        MetricsSample probe;
        const bool have = context.metricsCollector.GetLatest(&probe);
        response.body = MetricsCatalogJson(have ? probe : MetricsSample{});
        return response;
    }
    if (path == "/api/metrics/now") {
        response.body = MetricsNowJson(context);
        return response;
    }
    if (path == "/api/metrics/history") {
        response.body = MetricsHistoryJson(context, request);
        // MetricsHistoryJson reports a rejected query string as an error object.
        if (response.body.compare(0, 9, "{\"error\":") == 0) response.status = 400;
        return response;
    }
    if (path == "/api/processes") {
        const std::string body = ProcessesJson(context,
                                               query == std::string::npos
                                                   ? std::string()
                                                   : request.target.substr(query + 1));
        // A bad sort key or a non-numeric limit is a client error, not an empty
        // result: 400 plus the message, so the caller can tell "you asked for
        // something invalid" from "this machine has no processes".
        // Nine characters: {"error": with no trailing space.
        if (body.compare(0, 9, "{\"error\":") == 0) response.status = 400;
        response.body = body;
        return response;
    }
    if (path == "/api/network/summary") {
        response.body = NetworkSummaryJson(context);
        return response;
    }
    if (path == "/api/geo/summary") {
        response.body = GeoSummaryJson(context);
        return response;
    }
    if (path == "/api/diagnostics") {
        response.body = DiagnosticsJson(context);
        return response;
    }
    if (path == "/api/firewall") {
        response.body = FirewallRulesJson(context);
        return response;
    }
    if (path == "/api/config" && request.method == "GET") {
        std::lock_guard<std::mutex> lock(context.configMutex);
        if (!ReadConfigSnapshot(context, &response.body, &response.etag)) {
            response.status = 500;
            response.body = ErrorJson("configuration revision could not be generated");
        }
        return response;
    }
    // ---- GeoIP database upload ------------------------------------------------
    // The browser cannot expose local filesystem paths (file.path is hidden by
    // security), so the Browse button uploads the .mmdb contents to this endpoint.
    // The server writes the blob to geoIpDbDir and echoes back the on-disk path;
    // the client then fills the input box and updates the config via /api/config.
    if (path == "/api/geoip/upload" && request.method == "POST") {
        if (!AuthenticateMutation(context, request, &response)) {
            response.body = ErrorJson("mutation authorization failed");
            return response;
        }
        if (!ContentTypeIs(request, "application/octet-stream")) {
            response.status = 415;
            response.body = ErrorJson("geoip upload requires application/octet-stream");
            return response;
        }
        if (request.body.empty()) {
            response.status = 400;
            response.body = ErrorJson("upload body is empty");
            return response;
        }
        if (request.body.size() > kMaxUploadBytes) {
            response.status = 413;
            response.body = ErrorJson("uploaded GeoIP database exceeds the size limit");
            return response;
        }
        const auto fnHeader = request.headers.find("x-filename");
        if (fnHeader == request.headers.end() || fnHeader->second.empty()) {
            response.status = 400;
            response.body = ErrorJson("missing X-Filename header");
            return response;
        }
        std::wstring filename;
        if (!Utf8ToWide(fnHeader->second, &filename)) {
            response.status = 400;
            response.body = ErrorJson("filename is not valid UTF-8");
            return response;
        }
        // Reject path separators / traversal in the filename.
        if (filename.find_first_of(L"/\\") != std::wstring::npos) {
            response.status = 400;
            response.body = ErrorJson("filename contains path separators");
            return response;
        }
        const std::wstring badChars = L":*?<\"|";
        if (filename.find_first_of(badChars) != std::wstring::npos) {
            response.status = 400;
            response.body = ErrorJson("filename contains invalid characters");
            return response;
        }
        const std::wstring destPath = context.geoIpDbDir + L"\\" + filename;
        if (!WriteFileAtomic(destPath, request.body)) {
            response.status = 500;
            response.body = ErrorJson("could not save uploaded GeoIP database");
            return response;
        }
        response.body = "{\"ok\":true,\"path\":" + JsonQuote(WideToUtf8(destPath)) + "}";
        return response;
    }
    if (path == "/api/config" && request.method == "POST") {
        if (!AuthenticateMutation(context, request, &response)) {
            response.body = ErrorJson("mutation authorization failed");
            return response;
        }
        if (!ContentTypeIs(request, "application/json")) {
            response.status = 415;
            response.body = ErrorJson("configuration requires application/json");
            return response;
        }
        if (request.body.size() > kMaxBodyBytes ||
            !IsValidJsonObject(request.body) ||
            request.body.find(context.token) != std::string::npos) {
            response.status = 400;
            response.body = ErrorJson("configuration must be a bounded JSON object without the session token");
            return response;
        }
        std::lock_guard<std::mutex> applyLock(context.configApplyMutex);
        {
            std::lock_guard<std::mutex> lock(context.configMutex);
            std::string current, currentEtag;
            if (!ReadConfigSnapshot(context, &current, &currentEtag)) {
                response.status = 500;
                response.body = ErrorJson("configuration revision could not be read");
                return response;
            }
            const auto expected = request.headers.find("if-match");
            if (expected != request.headers.end() && expected->second != currentEtag) {
                response.status = 412;
                response.etag = currentEtag;
                response.body = ErrorJson("configuration changed; reload and merge before saving");
                return response;
            }
            std::string revision;
            if (!RandomHex(16, &revision) ||
                !WriteFileAtomic(context.configPath, request.body)) {
                response.status = 500;
                response.body = ErrorJson("configuration could not be saved");
                return response;
            }
            context.configBytes = request.body;
            context.configEtag = "\"" + revision + "\"";
            response.etag = context.configEtag;
        }
        // The config changed on disk - reload GeoIP from the new path, if any.
        // A clear or invalid path unloads the previous database.
        LoadGeoIpFromConfig(context);
        response.body = "{\"ok\":true}";
        return response;
    }
    if (path == "/api/audit" && request.method == "GET") {
        std::string search;
        AuditFormat format = AuditFormat::Json;
        if (query != std::string::npos) {
            std::map<std::string, std::string> parameters;
            if (!ParseForm(request.target.substr(query + 1), &parameters)) {
                response.status = 400;
                response.body = ErrorJson("audit query parameters are malformed");
                return response;
            }
            for (const auto& kv : parameters) {
                if (kv.first == "q") {
                    if (kv.second.size() > 1024) {
                        response.status = 400;
                        response.body = ErrorJson("audit 'q' parameter exceeds 1024 bytes");
                        return response;
                    }
                } else if (kv.first == "format") {
                    if (kv.second != "json" && kv.second != "ndjson") {
                        response.status = 400;
                        response.body = ErrorJson("audit 'format' must be 'json' or 'ndjson'");
                        return response;
                    }
                } else {
                    response.status = 400;
                    response.body = ErrorJson("audit accepts only 'q' and 'format' parameters");
                    return response;
                }
            }
            if (parameters.find("q") != parameters.end()) search = parameters["q"];
            if (parameters.find("format") != parameters.end() &&
                parameters["format"] == "ndjson") {
                format = AuditFormat::Ndjson;
            }
        }
        if (format == AuditFormat::Ndjson) response.contentType = "application/x-ndjson";
        response.body = ReadAudit(context, search, format);
        return response;
    }
    if (path == "/api/audit" && request.method == "POST") {
        if (!AuthenticateMutation(context, request, &response)) {
            response.body = ErrorJson("mutation authorization failed");
            return response;
        }
        if (!ContentTypeIs(request, "application/json")) {
            response.status = 415;
            response.body = ErrorJson("audit event requires application/json");
            return response;
        }
        if (!IsValidJsonObject(request.body) || request.body.size() > 4096) {
            response.status = 400;
            response.body = ErrorJson("audit event must be a small JSON object");
            return response;
        }
        if (request.body.find(context.token) != std::string::npos) {
            response.status = 400;
            response.body = ErrorJson("audit event must not contain the session token");
            return response;
        }
        if (!AppendAudit(context, request.body)) {
            response.status = 500;
            response.body = ErrorJson("audit event could not be recorded");
            return response;
        }
        response.body = "{\"ok\":true}";
        return response;
    }
    if ((path == "/api/cli/authorize" || path == "/api/cli/run") &&
        request.method == "POST") {
        if (!AuthenticateMutation(context, request, &response)) {
            response.body = ErrorJson("mutation authorization failed");
            return response;
        }
        if (!ContentTypeIs(request, "application/x-www-form-urlencoded")) {
            response.status = 415;
            response.body = ErrorJson("CLI requests require form encoding");
            return response;
        }
        const bool authorizing = path == "/api/cli/authorize";
        CliInvocation invocation;
        std::string nonce;
        bool confirmed = false;
        if (!ParseCliForm(request.body, !authorizing, authorizing,
                          &invocation, &nonce, &confirmed)) {
            response.status = 400;
            response.body = ErrorJson("CLI request has invalid arguments or exceeds its bounds");
            return response;
        }
        std::string boundsError;
        if (!CheckCliBounds(invocation, &boundsError)) {
            response.status = 400;
            response.body = ErrorJson(boundsError);
            return response;
        }
        const bool sensitive = IsSensitiveCli(invocation);
        if (authorizing) {
            if (!confirmed) {
                response.status = 403;
                response.body = ErrorJson("explicit confirmation is required before authorizing this command");
                return response;
            }
            if (!sensitive) {
                response.status = 400;
                response.body = ErrorJson("this command does not require a sensitive-action permit");
                return response;
            }
            for (auto it = context.pendingCliActions.begin();
                 it != context.pendingCliActions.end();) {
                if (it->second.expires < ::GetTickCount64())
                    it = context.pendingCliActions.erase(it);
                else
                    ++it;
            }
            while (context.pendingCliActions.size() >= kMaxPendingCliActions)
                context.pendingCliActions.erase(context.pendingCliActions.begin());
            std::string actionNonce;
            if (!RandomHex(16, &actionNonce)) {
                response.status = 500;
                response.body = ErrorJson("secure one-use CLI permit generation failed");
                return response;
            }
            context.pendingCliActions[actionNonce] = PendingCliAction{
                invocation.verb, invocation.args, ::GetTickCount64() + 30000};
            response.body = "{\"ok\":true,\"nonce\":" + JsonQuote(actionNonce) +
                            ",\"expiresInSeconds\":30}";
            return response;
        }
        if (sensitive) {
            const auto pending = context.pendingCliActions.find(nonce);
            if (nonce.empty() || pending == context.pendingCliActions.end() ||
                pending->second.expires < ::GetTickCount64() ||
                pending->second.verb != invocation.verb ||
                pending->second.args != invocation.args) {
                if (pending != context.pendingCliActions.end())
                    context.pendingCliActions.erase(pending);
                response.status = 403;
                response.body = ErrorJson("sensitive command needs a matching, unexpired, one-use confirmation permit");
                return response;
            }
            context.pendingCliActions.erase(pending);
        } else if (!nonce.empty()) {
            response.status = 400;
            response.body = ErrorJson("a confirmation permit is not valid for this command");
            return response;
        }
        std::string verb;
        verb.reserve(invocation.verb.size());
        for (wchar_t c : invocation.verb) verb.push_back(static_cast<char>(c));
        if (sensitive && !AppendAudit(context,
                "{\"type\":\"script-cli-attempt\",\"verb\":" +
                JsonQuote(verb) + "}")) {
            response.status = 500;
            response.body = ErrorJson("sensitive CLI action was not attempted because the audit log is unavailable");
            return response;
        }
        const CliExecutionResult result = ExecuteSiblingCli(context, invocation);
        if (!result.started) {
            response.status = 500;
            response.body = ErrorJson(result.error.empty()
                ? "the local CLI process could not be started" : result.error);
            return response;
        }
        const bool outcomeRecorded = sensitive && AppendAudit(context,
            "{\"type\":\"script-cli-result\",\"verb\":" + JsonQuote(verb) +
            ",\"exitCode\":" + std::to_string(result.exitCode) +
            ",\"timedOut\":" + std::string(result.timedOut ? "true" : "false") + "}");
        response.body = "{\"ok\":true,\"verb\":" + JsonQuote(verb) +
            ",\"exitCode\":" + std::to_string(result.exitCode) +
            ",\"stdout\":" + JsonQuote(result.out) +
            ",\"stderr\":" + JsonQuote(result.err) +
            ",\"durationMs\":" + std::to_string(result.durationMs) +
            ",\"timedOut\":" + std::string(result.timedOut ? "true" : "false") +
            ",\"truncated\":" + std::string(result.truncated ? "true" : "false") +
            ",\"actionAuditRecorded\":" +
            (sensitive ? std::string(outcomeRecorded ? "true" : "false") : "null") + "}";
        return response;
    }
    if (path == "/api/connections/action/preview" &&
        request.method == "POST") {
        if (!AuthenticateMutation(context, request, &response)) {
            response.body = ErrorJson("mutation authorization failed");
            return response;
        }
        if (!ContentTypeIs(request, "application/json") ||
            request.body.size() > 4096 || !IsValidJsonObject(request.body)) {
            response.status = 400;
            response.body = ErrorJson("connection preview requires a valid JSON target");
            return response;
        }
        std::map<std::string, std::string> fields;
        static const char* const captureNames[] = {
            "idExact", "processInstanceId", "pid", "proto", "local", "lport",
            "remote", "rport", "state",
        };
        for (const char* name : captureNames) {
            std::string value;
            if (!ExtractJsonString(request.body, name, &value)) {
                response.status = 400;
                response.body = ErrorJson("connection preview is missing an exact target field");
                return response;
            }
            fields.emplace(name, std::move(value));
        }
        uint64_t requestedId = 0;
        if (!ParseUint64Strict(fields["idExact"], &requestedId)) {
            response.status = 400;
            response.body = ErrorJson("connection id must be an exact decimal string");
            return response;
        }
        Connection captured;
        size_t matches = 0;
        ULONGLONG tick = context.connectionSnapshotTick.load();
        {
            std::lock_guard<std::mutex> lock(g_storeMutex);
            for (const Connection& row : context.store.Rows()) {
                if (row.id != requestedId) continue;
                if (!MatchesCloseCapture(fields, row, nullptr)) continue;
                captured = row;
                ++matches;
            }
        }
        if (matches != 1) {
            response.status = 409;
            response.body = ErrorJson(matches == 0
                ? "captured connection is stale or does not match the current endpoint"
                : "captured connection identity is ambiguous");
            return response;
        }
        const std::string reason =
            ConnectionCloseCapabilityReason(captured, IsElevated());
        std::string nonce;
        if (reason.empty()) {
            std::lock_guard<std::mutex> actionLock(context.connectionActionMutex);
            for (auto it = context.pendingConnectionActions.begin();
                 it != context.pendingConnectionActions.end();) {
                if (it->second.expires < ::GetTickCount64())
                    it = context.pendingConnectionActions.erase(it);
                else
                    ++it;
            }
            while (context.pendingConnectionActions.size() >=
                   kMaxPendingConnectionActions)
                context.pendingConnectionActions.erase(
                    context.pendingConnectionActions.begin());
            if (!RandomHex(16, &nonce)) {
                response.status = 500;
                response.body = ErrorJson("secure preview token generation failed");
                return response;
            }
            const ULONGLONG now = ::GetTickCount64();
            const ULONGLONG age = tick > 0 && now >= tick ? now - tick : 0;
            context.pendingConnectionActions[nonce] =
                PendingConnectionAction{captured, age, now + 30000};
        }
        const ULONGLONG now = ::GetTickCount64();
        const ULONGLONG age = tick > 0 && now >= tick ? now - tick : 0;
        response.body = "{\"ok\":true,\"canExecute\":" +
            std::string(reason.empty() ? "true" : "false") +
            ",\"requiresElevation\":true,\"reason\":" +
            (reason.empty() ? "null" : JsonQuote(reason)) +
            ",\"nonce\":" + (nonce.empty() ? "null" : JsonQuote(nonce)) +
            ",\"expiresInMs\":" + (nonce.empty() ? "0" : "30000") +
            ",\"snapshotKnown\":" + std::string(tick > 0 ? "true" : "false") +
            ",\"snapshotAgeMs\":" + std::to_string(age) + "}";
        return response;
    }
    if (path == "/api/connections/action/execute" &&
        request.method == "POST") {
        if (!AuthenticateMutation(context, request, &response)) {
            response.body = ErrorJson("mutation authorization failed");
            return response;
        }
        std::string nonce;
        if (!ContentTypeIs(request, "application/json") ||
            request.body.size() > 1024 || !IsValidJsonObject(request.body) ||
            !ExtractJsonString(request.body, "nonce", &nonce) ||
            nonce.size() != 32) {
            response.status = 400;
            response.body = ErrorJson("connection execute requires a valid one-time preview token");
            return response;
        }
        PendingConnectionAction action;
        {
            std::lock_guard<std::mutex> actionLock(context.connectionActionMutex);
            const auto pending = context.pendingConnectionActions.find(nonce);
            if (pending == context.pendingConnectionActions.end() ||
                pending->second.expires < ::GetTickCount64()) {
                if (pending != context.pendingConnectionActions.end())
                    context.pendingConnectionActions.erase(pending);
                response.status = 410;
                response.body = ErrorJson("preview expired or already used; preview the action again");
                return response;
            }
            action = pending->second;
            context.pendingConnectionActions.erase(pending);
        }
        Snapshot current;
        SnapshotOptions options;
        options.resolveProcesses = true;
        bool enumerated = false;
        {
            std::lock_guard<std::mutex> lock(g_storeMutex);
            enumerated = context.source.Build(options, &current);
        }
        if (!enumerated) {
            response.status = 503;
            response.body = ErrorJson("the connection table could not be refreshed; no action was attempted");
            return response;
        }
        const Connection* target = nullptr;
        size_t matches = 0;
        for (const Connection& row : current.rows) {
            if (!SameCloseIdentity(action.captured, row)) continue;
            target = &row;
            ++matches;
        }
        if (matches != 1 || target == nullptr) {
            response.status = 409;
            response.body = ErrorJson(matches == 0
                ? "captured connection is gone or its process lifetime changed; no action was attempted"
                : "captured connection is ambiguous; no action was attempted");
            return response;
        }
        const std::string attempt = "{\"type\":\"connection-close-attempt\",\"connectionId\":" +
            JsonQuote(std::to_string(action.captured.id)) +
            ",\"pid\":" + std::to_string(action.captured.identity.pid) + "}";
        if (!AppendAudit(context, attempt)) {
            response.status = 500;
            response.body = ErrorJson("connection close was not attempted because the audit log is unavailable");
            return response;
        }
        MutateOptions mutate;
        mutate.yes = true;
        const CommandResult result = CloseRow(*target, mutate);
        const bool ok = result.exitCode == kExitOk;
        const std::string outcome = "{\"type\":\"connection-close\",\"connectionId\":" +
            JsonQuote(std::to_string(action.captured.id)) +
            ",\"result\":" + JsonQuote(ok ? "success" : "failed") + "}";
        const bool auditRecorded = AppendAudit(context, outcome);
        if (!ok) response.status = 409;
        response.body = "{\"ok\":" + std::string(ok ? "true" : "false") +
            ",\"status\":" + JsonQuote(ok ? "succeeded" : "failed") +
            ",\"connection\":{\"status\":" +
            JsonQuote(ok ? "succeeded" : "failed") +
            ",\"reason\":" + (ok ? "null" : JsonQuote(result.err + result.out)) +
            "},\"auditRecorded\":" + (auditRecorded ? "true" : "false") + "}";
        return response;
    }
    if (path == "/api/firewall/rule/create/preview" && request.method == "POST") {
        if (!AuthenticateMutation(context, request, &response)) {
            response.body = ErrorJson("mutation authorization failed");
            return response;
        }
        if (!ContentTypeIs(request, "application/x-www-form-urlencoded")) {
            response.status = 415;
            response.body = ErrorJson("rule creation preview requires form encoding");
            return response;
        }
        std::map<std::string, std::string> fields;
        static const char* const names[] = {
            "direction", "action", "proto", "address", "localAddress",
            "localPorts", "remotePorts", "process", "service", "profiles",
            "label",
        };
        if (!ParseForm(request.body, &fields) || fields.size() !=
                sizeof(names) / sizeof(names[0])) {
            response.status = 400;
            response.body = ErrorJson("rule creation preview needs the complete explicit rule form");
            return response;
        }
        for (const char* name : names) {
            if (fields.find(name) == fields.end()) {
                response.status = 400;
                response.body = ErrorJson("rule creation preview is missing an explicit field");
                return response;
            }
        }
        RuleRequest rule;
        if (fields["direction"] != "inbound" && fields["direction"] != "outbound") {
            response.status = 400;
            response.body = ErrorJson("direction must be inbound or outbound");
            return response;
        }
        if (fields["action"] != "block" && fields["action"] != "allow") {
            response.status = 400;
            response.body = ErrorJson("action must be block or allow");
            return response;
        }
        if (fields["proto"] != "tcp" && fields["proto"] != "udp" &&
            fields["proto"] != "any") {
            response.status = 400;
            response.body = ErrorJson("protocol must be tcp, udp, or any");
            return response;
        }
        uint64_t profileBits = 0;
        if (!ParseUint64Strict(fields["profiles"], &profileBits) ||
            profileBits > 0x7fffffffULL || profileBits == 0) {
            response.status = 400;
            response.body = ErrorJson("profiles must be an explicit non-empty Windows profile mask");
            return response;
        }
        if (!Utf8ToWide(fields["address"], &rule.address) ||
            !Utf8ToWide(fields["localAddress"], &rule.localAddress) ||
            !Utf8ToWide(fields["localPorts"], &rule.localPorts) ||
            !Utf8ToWide(fields["remotePorts"], &rule.remotePorts) ||
            !Utf8ToWide(fields["process"], &rule.process) ||
            !Utf8ToWide(fields["service"], &rule.service) ||
            !Utf8ToWide(fields["label"], &rule.label)) {
            response.status = 400;
            response.body = ErrorJson("rule fields must be valid UTF-8");
            return response;
        }
        rule.inbound = fields["direction"] == "inbound";
        rule.allow = fields["action"] == "allow";
        rule.proto.assign(fields["proto"].begin(), fields["proto"].end());
        rule.profiles = static_cast<LONG>(profileBits);
        if (rule.label.empty()) rule.label = L"WinTCP Web UI custom rule";
        const CommandResult plan = CmdRule(rule, true, false);
        if (plan.exitCode != kExitOk) {
            response.status = 400;
            const std::string message = plan.err + plan.out;
            const std::string field = ContainsIgnoreCase(message, "local address") ? "localAddress"
                : ContainsIgnoreCase(message, "remote address") ? "address"
                : ContainsIgnoreCase(message, "port") ? "ports"
                : ContainsIgnoreCase(message, "protocol") ? "proto"
                : ContainsIgnoreCase(message, "process") ? "process"
                : ContainsIgnoreCase(message, "service") ? "service"
                : ContainsIgnoreCase(message, "profile") ? "profiles" : "rule";
            response.body = "{\"ok\":false,\"field\":" + JsonQuote(field) +
                ",\"message\":" + JsonQuote(message) + "}";
            return response;
        }
        const std::string ruleName = RuleNameFromPlan(plan.out);
        if (ruleName.empty()) {
            response.status = 500;
            response.body = ErrorJson("rule preview did not produce an exact firewall rule identity");
            return response;
        }
        if (!IsElevated()) {
            response.body = "{\"ok\":true,\"canExecute\":false,\"requiresElevation\":true,"
                "\"reason\":\"Run WinTCP as administrator to create firewall rules\","
                "\"operation\":\"create\",\"nonce\":null,\"name\":" +
                JsonQuote(ruleName) + ",\"plan\":" + JsonQuote(plan.out) + "}";
            return response;
        }
        std::lock_guard<std::mutex> actionLock(context.firewallActionMutex);
        const ULONGLONG now = ::GetTickCount64();
        for (auto it = context.pendingFirewallActions.begin();
             it != context.pendingFirewallActions.end();) {
            if (it->second.expires < now) it = context.pendingFirewallActions.erase(it);
            else ++it;
        }
        while (context.pendingFirewallActions.size() >= kMaxPendingBlocks)
            context.pendingFirewallActions.erase(context.pendingFirewallActions.begin());
        std::string nonce;
        if (!RandomHex(16, &nonce)) {
            response.status = 500;
            response.body = ErrorJson("secure preview token generation failed");
            return response;
        }
        PendingFirewallRuleAction pending;
        pending.createRequest = rule;
        pending.operation = "create";
        pending.ruleName = ruleName;
        pending.create = true;
        pending.expires = now + 30000;
        context.pendingFirewallActions[nonce] = std::move(pending);
        response.body = "{\"ok\":true,\"canExecute\":true,\"requiresElevation\":true,"
            "\"reason\":null,\"operation\":\"create\",\"nonce\":" +
            JsonQuote(nonce) + ",\"expiresInMs\":30000,\"name\":" +
            JsonQuote(ruleName) + ",\"plan\":" + JsonQuote(plan.out) + "}";
        return response;
    }
    if (path == "/api/firewall/rule/preview" && request.method == "POST") {
        if (!AuthenticateMutation(context, request, &response)) {
            response.body = ErrorJson("mutation authorization failed");
            return response;
        }
        std::string nameUtf8;
        std::string operation;
        if (!ContentTypeIs(request, "application/json") || request.body.size() > 4096 ||
            !IsValidJsonObject(request.body) ||
            !ExtractJsonString(request.body, "name", &nameUtf8) ||
            !ExtractJsonString(request.body, "operation", &operation) ||
            (operation != "enable" && operation != "disable" && operation != "remove")) {
            response.status = 400;
            response.body = ErrorJson("rule preview requires a rule name and enable, disable, or remove operation");
            return response;
        }
        std::wstring name;
        if (!Utf8ToWide(nameUtf8, &name) || name.empty() || name.size() > kMaxRuleNameChars) {
            response.status = 400;
            response.body = ErrorJson("firewall rule name is invalid");
            return response;
        }
        std::vector<BlockedRule> rules;
        std::wstring inventoryError;
        std::wstring inventoryWarning;
        if (!ListFirewallInventory(&rules, &inventoryError, &inventoryWarning)) {
            response.status = 503;
            response.body = ErrorJson("firewall inventory is unavailable: " + WideToUtf8(inventoryError));
            return response;
        }
        size_t matches = 0;
        const BlockedRule* rule = FindFirewallRule(rules, name, &matches);
        if (matches != 1 || rule == nullptr) {
            response.status = 409;
            response.body = ErrorJson(matches == 0
                ? "firewall rule is no longer present; refresh the inventory"
                : "firewall rule identity is ambiguous; no action was prepared");
            return response;
        }
        if (!rule->wintcpOwned) {
            response.status = 403;
            response.body = ErrorJson("only rules managed by WinTCP can be changed here");
            return response;
        }
        if (operation != "remove" && !rule->enabledKnown) {
            response.status = 409;
            response.body = ErrorJson("Windows Firewall did not return this rule's enabled state");
            return response;
        }
        if ((operation == "enable" && rule->enabled) ||
            (operation == "disable" && !rule->enabled)) {
            response.status = 409;
            response.body = ErrorJson("the rule already has the requested enabled state");
            return response;
        }
        const bool elevated = IsElevated();
        if (!elevated) {
            response.body = "{\"ok\":true,\"canExecute\":false,\"requiresElevation\":true,"
                "\"reason\":\"Run WinTCP as administrator to change firewall rules\","
                "\"nonce\":null,\"expiresInMs\":0,\"operation\":" + JsonQuote(operation) +
                ",\"name\":" + JsonQuote(WideToUtf8(rule->name)) +
                ",\"enabled\":" + (rule->enabledKnown
                    ? (rule->enabled ? "true" : "false") : "null") +
                ",\"ownership\":\"wintcp\",\"warning\":" +
                    (inventoryWarning.empty() ? "null" : JsonQuote(WideToUtf8(inventoryWarning))) +
                FirewallRuleReviewJson(*rule) + "}";
            return response;
        }
        std::lock_guard<std::mutex> actionLock(context.firewallActionMutex);
        const ULONGLONG now = ::GetTickCount64();
        for (auto it = context.pendingFirewallActions.begin();
             it != context.pendingFirewallActions.end();) {
            if (it->second.expires < now) it = context.pendingFirewallActions.erase(it);
            else ++it;
        }
        while (context.pendingFirewallActions.size() >= kMaxPendingBlocks)
            context.pendingFirewallActions.erase(context.pendingFirewallActions.begin());
        std::string nonce;
        if (!RandomHex(16, &nonce)) {
            response.status = 500;
            response.body = ErrorJson("secure preview token generation failed");
            return response;
        }
        PendingFirewallRuleAction action;
        action.captured = *rule;
        action.operation = operation;
        action.ruleName = WideToUtf8(rule->name);
        action.expires = now + 30000;
        context.pendingFirewallActions[nonce] = std::move(action);
        response.body = "{\"ok\":true,\"nonce\":" + JsonQuote(nonce) +
            ",\"canExecute\":true,\"requiresElevation\":true,\"reason\":null,"
            "\"expiresInMs\":30000,\"operation\":" + JsonQuote(operation) +
            ",\"name\":" + JsonQuote(WideToUtf8(rule->name)) +
            ",\"enabled\":" + (rule->enabledKnown
                ? (rule->enabled ? "true" : "false") : "null") +
            ",\"ownership\":\"wintcp\",\"warning\":" +
                (inventoryWarning.empty() ? "null" : JsonQuote(WideToUtf8(inventoryWarning))) +
            FirewallRuleReviewJson(*rule) + "}";
        return response;
    }
    if (path == "/api/firewall/rule/execute" && request.method == "POST") {
        if (!AuthenticateMutation(context, request, &response)) {
            response.body = ErrorJson("mutation authorization failed");
            return response;
        }
        std::string nonce;
        if (!ContentTypeIs(request, "application/json") || request.body.size() > 1024 ||
            !IsValidJsonObject(request.body) ||
            !ExtractJsonString(request.body, "nonce", &nonce) || nonce.size() != 32) {
            response.status = 400;
            response.body = ErrorJson("rule execution requires a valid one-time preview token");
            return response;
        }
        PendingFirewallRuleAction action;
        {
            std::lock_guard<std::mutex> actionLock(context.firewallActionMutex);
            const auto pending = context.pendingFirewallActions.find(nonce);
            if (pending == context.pendingFirewallActions.end() ||
                pending->second.expires < ::GetTickCount64()) {
                if (pending != context.pendingFirewallActions.end())
                    context.pendingFirewallActions.erase(pending);
                response.status = 410;
                response.body = ErrorJson("preview expired or already used; preview the action again");
                return response;
            }
            action = pending->second;
            context.pendingFirewallActions.erase(pending);
        }
        if (action.create) {
            std::wstring expectedName;
            if (!Utf8ToWide(action.ruleName, &expectedName) || expectedName.empty()) {
                response.status = 500;
                response.body = ErrorJson("the reviewed rule identity is invalid");
                return response;
            }
            const std::string attempt = "{\"type\":\"firewall-rule-attempt\",\"operation\":\"create\",\"name\":" +
                JsonQuote(action.ruleName) + "}";
            if (!AppendAudit(context, attempt)) {
                response.status = 500;
                response.body = ErrorJson("rule creation was not attempted because the audit log is unavailable");
                return response;
            }
            const CommandResult created = CmdRule(action.createRequest, false, true);
            std::vector<BlockedRule> readback;
            std::wstring readbackError;
            const bool readbackAvailable = ListFirewallInventory(&readback, &readbackError);
            size_t matches = 0;
            const BlockedRule* installed = readbackAvailable
                ? FindFirewallRule(readback, expectedName, &matches) : nullptr;
            const bool verified = created.exitCode == kExitOk && readbackAvailable &&
                matches == 1 && installed != nullptr &&
                SameCreatedFirewallRule(action.createRequest, *installed);
            const bool alreadyPresent = created.out.find("already present;") != std::string::npos;
            const std::string status = verified
                ? (alreadyPresent ? "already-present" : "created")
                : (created.exitCode != kExitOk ? "failed" :
                   readbackAvailable ? "unverified" : "readback-unavailable");
            const std::string audit = "{\"type\":\"firewall-rule-result\",\"operation\":\"create\",\"name\":" +
                JsonQuote(action.ruleName) + ",\"result\":" + JsonQuote(status) + "}";
            const bool auditRecorded = AppendAudit(context, audit);
            const std::string reason = verified ? std::string()
                : created.exitCode != kExitOk ? created.err + created.out
                : !readbackAvailable ? WideToUtf8(readbackError)
                : "Windows Firewall read-back did not match every reviewed rule field";
            response.status = verified ? 200 : 409;
            response.body = "{\"ok\":" + std::string(verified ? "true" : "false") +
                ",\"operation\":\"create\",\"status\":" + JsonQuote(status) +
                ",\"ruleStatus\":" + JsonQuote(status) +
                ",\"name\":" + JsonQuote(action.ruleName) +
                ",\"ruleName\":" + JsonQuote(action.ruleName) +
                ",\"reason\":" + (verified ? "null" : JsonQuote(reason)) +
                ",\"auditRecorded\":" + (auditRecorded ? "true" : "false") + "}";
            return response;
        }
        std::vector<BlockedRule> rules;
        std::wstring inventoryError;
        if (!ListFirewallInventory(&rules, &inventoryError)) {
            response.status = 503;
            response.body = ErrorJson("firewall inventory is unavailable; no rule action was attempted");
            return response;
        }
        size_t matches = 0;
        const BlockedRule* current = FindFirewallRule(rules, action.captured.name, &matches);
        if (matches != 1 || current == nullptr ||
            !SameFirewallRuleCapture(action.captured, *current)) {
            response.status = 409;
            response.body = ErrorJson("the rule changed or disappeared after review; no action was attempted");
            return response;
        }
        const std::string attempt = "{\"type\":\"firewall-rule-attempt\",\"operation\":" +
            JsonQuote(action.operation) + ",\"name\":" + JsonQuote(WideToUtf8(action.captured.name)) + "}";
        if (!AppendAudit(context, attempt)) {
            response.status = 500;
            response.body = ErrorJson("rule action was not attempted because the audit log is unavailable");
            return response;
        }
        std::wstring actionError;
        const bool changed = action.operation == "remove"
            ? RemoveBlockedRule(action.captured.name, &actionError)
            : SetBlockedRuleEnabled(action.captured.name, action.operation == "enable", &actionError);
        std::vector<BlockedRule> readback;
        std::wstring readbackError;
        const bool readbackAvailable = ListFirewallInventory(&readback, &readbackError);
        size_t remainingMatches = 0;
        const BlockedRule* after = readbackAvailable
            ? FindFirewallRule(readback, action.captured.name, &remainingMatches) : nullptr;
        const bool verified = changed && readbackAvailable &&
            (action.operation == "remove"
                ? remainingMatches == 0
                : remainingMatches == 1 && after != nullptr && after->enabledKnown &&
                  after->enabled == (action.operation == "enable"));
        const std::string audit = "{\"type\":\"firewall-rule-result\",\"operation\":" +
            JsonQuote(action.operation) + ",\"name\":" + JsonQuote(WideToUtf8(action.captured.name)) +
            ",\"result\":" + JsonQuote(verified ? "verified" : (changed ? "unverified" : "failed")) + "}";
        const bool auditRecorded = AppendAudit(context, audit);
        response.status = verified ? 200 : 409;
        response.body = "{\"ok\":" + std::string(verified ? "true" : "false") +
            ",\"status\":" + JsonQuote(verified ? "verified" : (changed ? "unverified" : "failed")) +
            ",\"operation\":" + JsonQuote(action.operation) +
            ",\"name\":" + JsonQuote(WideToUtf8(action.captured.name)) +
            ",\"reason\":" + (verified ? "null" : JsonQuote(
                !changed ? WideToUtf8(actionError) : (!readbackAvailable
                    ? WideToUtf8(readbackError) : "Windows Firewall read-back did not match the requested change"))) +
            ",\"auditRecorded\":" + (auditRecorded ? "true" : "false") + "}";
        return response;
    }
    if (path == "/api/block/preview" && request.method == "POST") {
        if (!AuthenticateMutation(context, request, &response)) {
            response.body = ErrorJson("mutation authorization failed");
            return response;
        }
        if (!ContentTypeIs(request, "application/x-www-form-urlencoded")) {
            response.status = 415;
            response.body = ErrorJson("block preview requires form encoding");
            return response;
        }
        std::map<std::string, std::string> fields;
        if (!ParseForm(request.body, &fields)) {
            response.status = 400;
            response.body = ErrorJson("block preview form could not be parsed");
            return response;
        }
        const auto scopeField = fields.find("scope");
        const std::string scope = scopeField == fields.end() ? "peer" : scopeField->second;
        RuleRequest rule;
        if (scope == "peer") {
            UINT port = 0;
            const size_t expectedFields = scopeField == fields.end() ? 2 : 3;
            if (fields.size() != expectedFields || fields.find("address") == fields.end() ||
                fields.find("port") == fields.end() || !IsIpAddress(fields["address"]) ||
                !ParsePort(fields["port"], &port, true)) {
                response.status = 400;
                response.body = ErrorJson("peer block preview needs a literal IP address and port 0..65535 (0 means all remote TCP ports)");
                return response;
            }
            rule = BlockRequest(fields["address"], port);
        } else if (scope == "application" || scope == "application-allow") {
            uint64_t pid = 0;
            std::wstring processPath;
            const bool fieldsValid = fields.size() == 4 &&
                fields.find("process") != fields.end() &&
                fields.find("pid") != fields.end() &&
                fields.find("instanceId") != fields.end() &&
                ParseUint64Strict(fields["pid"], &pid) && pid > 0 && pid <= MAXDWORD &&
                !fields["instanceId"].empty() && fields["instanceId"].size() <= 128 &&
                Utf8ToWide(fields["process"], &processPath) && !processPath.empty();
            if (!fieldsValid) {
                response.status = 400;
                response.body = ErrorJson("application block preview needs an exact process PID, lifetime, and full image path");
                return response;
            }
            const WebProcessSnapshot snapshot = context.processes.Read();
            if (!snapshot.known || context.processes.AgeMs() > 5000) {
                response.status = 503;
                response.body = ErrorJson("the process snapshot is unavailable or stale; refresh before reviewing an application rule");
                return response;
            }
            size_t matches = 0;
            for (const WebProcessRow& row : snapshot.rows) {
                if (row.pid != static_cast<DWORD>(pid) ||
                    ProcessInstanceId(row) != fields["instanceId"] ||
                    row.path != processPath) continue;
                ++matches;
            }
            if (matches != 1) {
                response.status = 409;
                response.body = ErrorJson("the selected process lifetime or executable path changed; refresh and review again");
                return response;
            }
            rule = ApplicationBlockRequest(processPath, scope == "application-allow");
        } else if (scope == "application-peer" || scope == "service-peer") {
            const bool serviceScoped = scope == "service-peer";
            static const char* const captureNames[] = {
                "idExact", "processInstanceId", "pid", "proto", "local", "lport",
                "remote", "rport", "state",
            };
            const bool capturesPresent = fields.size() == (serviceScoped ? 13 : 12) &&
                fields.find("process") != fields.end() &&
                (!serviceScoped || fields.find("service") != fields.end());
            if (!capturesPresent) {
                response.status = 400;
                response.body = ErrorJson("application-peer preview needs the exact connection tuple and executable path");
                return response;
            }
            std::map<std::string, std::string> capture;
            for (const char* name : captureNames) {
                const auto value = fields.find(name);
                if (value == fields.end()) {
                    response.status = 400;
                    response.body = ErrorJson("application-peer preview is missing an exact connection field");
                    return response;
                }
                capture.emplace(name, value->second);
            }
            uint64_t requestedId = 0;
            uint64_t pid = 0;
            UINT remotePort = 0;
            std::wstring processPath;
            if (!ParseUint64Strict(capture["idExact"], &requestedId) ||
                !ParseUint64Strict(capture["pid"], &pid) || pid == 0 || pid > MAXDWORD ||
                !ParsePort(capture["rport"], &remotePort, false) || remotePort == 0 ||
                !IsIpAddress(capture["remote"]) ||
                fields["instanceId"] != capture["processInstanceId"] ||
                (serviceScoped && !IsServiceShortName(fields["service"])) ||
                !Utf8ToWide(fields["process"], &processPath) || processPath.empty()) {
                response.status = 400;
                response.body = ErrorJson("application-peer preview has an invalid connection target or executable path");
                return response;
            }
            Connection captured;
            size_t matches = 0;
            const ULONGLONG connectionTick = context.connectionSnapshotTick.load();
            const ULONGLONG now = ::GetTickCount64();
            if (connectionTick == 0 || now < connectionTick || now - connectionTick > 5000) {
                response.status = 503;
                response.body = ErrorJson("the connection snapshot is unavailable or stale; refresh before reviewing an application rule");
                return response;
            }
            {
                std::lock_guard<std::mutex> lock(g_storeMutex);
                for (const Connection& row : context.store.Rows()) {
                    if (row.id != requestedId || (row.flags & kRowRemoved) != 0 ||
                        !MatchesCloseCapture(capture, row, nullptr)) continue;
                    captured = row;
                    ++matches;
                }
            }
            if (matches != 1 || captured.identity.protocol != IPPROTO_TCP ||
                captured.identity.state != MIB_TCP_STATE_ESTAB ||
                captured.display.processPath.empty() ||
                captured.display.processPath != processPath ||
                !captured.procMeta.processCreateKnown) {
                response.status = 409;
                response.body = ErrorJson("the selected connection or owning process lifetime is stale, ambiguous, or unsupported");
                return response;
            }
            if (serviceScoped &&
                (captured.display.serviceName.empty() ||
                 WideToUtf8(captured.display.serviceName) != fields["service"])) {
                response.status = 409;
                response.body = ErrorJson("the selected connection has no matching known Windows service scope");
                return response;
            }
            const WebProcessSnapshot snapshot = context.processes.Read();
            if (!snapshot.known || context.processes.AgeMs() > 5000) {
                response.status = 503;
                response.body = ErrorJson("the process snapshot is unavailable or stale; refresh before reviewing an application rule");
                return response;
            }
            size_t processMatches = 0;
            for (const WebProcessRow& row : snapshot.rows) {
                if (row.pid != static_cast<DWORD>(pid) ||
                    ProcessInstanceId(row) != capture["processInstanceId"] ||
                    row.path != processPath) continue;
                ++processMatches;
            }
            if (processMatches != 1 || pid != captured.identity.pid ||
                capture["processInstanceId"] != ProcessInstanceId(captured)) {
                response.status = 409;
                response.body = ErrorJson("the owning process lifetime or executable path changed; refresh and review again");
                return response;
            }
            rule = BlockRequest(capture["remote"], remotePort);
            rule.process = processPath;
            if (serviceScoped) {
                if (!Utf8ToWide(fields["service"], &rule.service)) {
                    response.status = 400;
                    response.body = ErrorJson("the Windows service short name is not valid UTF-8");
                    return response;
                }
                rule.label = L"WinTCP Web UI service peer";
            } else {
                rule.label = L"WinTCP Web UI application peer";
            }
        } else {
            response.status = 400;
            response.body = ErrorJson("block scope must be peer, application, application-allow, application-peer, or service-peer");
            return response;
        }
        const CommandResult plan = CmdRule(rule, true, false);
        if (plan.exitCode != kExitOk) {
            response.status = 400;
            response.body = "{\"ok\":false,\"message\":" + JsonQuote(plan.err + plan.out) + "}";
            return response;
        }
        const std::string ruleName = RuleNameFromPlan(plan.out);
        if (ruleName.empty()) {
            response.status = 500;
            response.body = ErrorJson("block preview did not produce an exact firewall rule identity");
            return response;
        }
        if (!IsElevated()) {
            response.body = "{\"ok\":true,\"canExecute\":false,\"requiresElevation\":true,"
                "\"reason\":\"Run WinTCP as administrator to create firewall rules\","
                "\"scope\":" + JsonQuote(scope) +
                ",\"ruleName\":" + JsonQuote(ruleName) +
                ",\"plan\":" + JsonQuote(plan.out) + "}";
            return response;
        }
        std::string nonce;
        if (!RandomHex(16, &nonce)) {
            response.status = 500;
            response.body = ErrorJson("secure preview token generation failed");
            return response;
        }
        {
            std::lock_guard<std::mutex> actionLock(context.blockActionMutex);
            for (auto it = context.pendingBlocks.begin(); it != context.pendingBlocks.end();) {
                if (it->second.expires < ::GetTickCount64()) it = context.pendingBlocks.erase(it);
                else ++it;
            }
            while (context.pendingBlocks.size() >= kMaxPendingBlocks)
                context.pendingBlocks.erase(context.pendingBlocks.begin());
            context.pendingBlocks[nonce] = PendingBlock{
                rule, scope, ruleName, ::GetTickCount64() + 30000};
        }
        response.body = "{\"ok\":true,\"canExecute\":true,\"requiresElevation\":true,"
                        "\"reason\":null,\"nonce\":" + JsonQuote(nonce) +
                        ",\"scope\":" + JsonQuote(scope) +
                        ",\"ruleName\":" + JsonQuote(ruleName) +
                        ",\"plan\":" + JsonQuote(plan.out) + "}";
        return response;
    }
    if (path == "/api/block/commit" && request.method == "POST") {
        if (!AuthenticateMutation(context, request, &response)) {
            response.body = ErrorJson("mutation authorization failed");
            return response;
        }
        if (!ContentTypeIs(request, "application/x-www-form-urlencoded")) {
            response.status = 415;
            response.body = ErrorJson("block commit requires form encoding");
            return response;
        }
        std::map<std::string, std::string> fields;
        if (!ParseForm(request.body, &fields) || fields.size() != 1 ||
            fields.find("nonce") == fields.end()) {
            response.status = 400;
            response.body = ErrorJson("block commit requires a valid one-time preview token");
            return response;
        }
        PendingBlock action;
        {
            std::lock_guard<std::mutex> actionLock(context.blockActionMutex);
            const auto pending = context.pendingBlocks.find(fields["nonce"]);
            if (pending == context.pendingBlocks.end() ||
                pending->second.expires < ::GetTickCount64()) {
                if (pending != context.pendingBlocks.end()) context.pendingBlocks.erase(pending);
                response.status = 403;
                response.body = ErrorJson("preview expired or already used; preview the action again");
                return response;
            }
            action = pending->second;
            context.pendingBlocks.erase(pending);
        }
        const std::string attempt = "{\"type\":\"firewall-block-attempt\",\"scope\":" +
                                    JsonQuote(action.scope) + ",\"address\":" +
                                    JsonQuote(WideToUtf8(action.rule.address)) + ",\"remotePort\":" +
                                    JsonQuote(WideToUtf8(action.rule.remotePorts)) +
                                    ",\"process\":" + JsonQuote(WideToUtf8(action.rule.process)) +
                                    ",\"ruleName\":" +
                                    JsonQuote(action.ruleName) + "}";
        if (!AppendAudit(context, attempt)) {
            response.status = 500;
            response.body = ErrorJson("firewall action was not attempted because the audit log is unavailable");
            return response;
        }
        const CommandResult result = CmdRule(action.rule, false, true);
        const bool ok = result.exitCode == kExitOk;
        const std::string actualRuleName = RuleNameFromPlan(result.out);
        const bool alreadyPresent = result.out.find("already present; nothing added.") !=
                                    std::string::npos;
        const std::string event = "{\"type\":\"firewall-block\",\"scope\":" +
                                  JsonQuote(action.scope) + ",\"address\":" +
                                  JsonQuote(WideToUtf8(action.rule.address)) +
                                  ",\"remotePort\":" +
                                  JsonQuote(WideToUtf8(action.rule.remotePorts)) +
                                  ",\"process\":" +
                                  JsonQuote(WideToUtf8(action.rule.process)) +
                                  ",\"result\":" +
                                  JsonQuote(ok ? "success" : "refused-or-failed") +
                                  ",\"ruleName\":" + JsonQuote(
                                      actualRuleName.empty() ? action.ruleName : actualRuleName) +
                                  ",\"ruleStatus\":" + JsonQuote(!ok ? "failed" :
                                      (alreadyPresent ? "already-present" : "created")) + "}";
        const bool auditRecorded = AppendAudit(context, event);
        if (!ok) response.status = 403;
        response.body = "{\"ok\":" + std::string(ok ? "true" : "false") +
                        ",\"exitCode\":" + std::to_string(result.exitCode) +
                        ",\"scope\":" + JsonQuote(action.scope) +
                        ",\"ruleName\":" + JsonQuote(
                            actualRuleName.empty() ? action.ruleName : actualRuleName) +
                        ",\"ruleStatus\":" + JsonQuote(!ok ? "failed" :
                            (alreadyPresent ? "already-present" : "created")) +
                        ",\"auditRecorded\":" + (auditRecorded ? "true" : "false") +
                        ",\"message\":" + JsonQuote(result.err + result.out) + "}";
        return response;
    }
    response.status = 404;
    response.body = ErrorJson("route not found");
    return response;
}

// ---- Server-Sent Events (live updates) ------------------------------------
// The browser's EventSource cannot set headers, so the stream authenticates the
// same way the other GET routes do - Host/Origin only (no token), exactly like
// /api/connections. It is a heartbeat: one `tick` event per second. The client
// reacts by re-fetching /api/connections, so the UI reflects a change about a
// second after it happens instead of up to refreshSeconds later.
//
// Heartbeat rather than change-driven push, deliberately: the store is refreshed
// on demand by the /api/connections path, and a change-driven stream would need
// the SSE thread to own that refresh and to read the destructive TakeChangeEvents
// stream the change log also consumes. A 1s heartbeat keeps the stream lock-free
// - it only writes to its own socket - while still cutting update latency from
// the poll interval (2-30s) to ~1s.
std::string FormatSseFrame(const std::string& name, const std::string& data) {
    return "event: " + name + "\r\ndata: " + data + "\r\n\r\n";
}

bool SendSseFrame(SOCKET client, const std::string& name, const std::string& data) {
    const std::string frame = FormatSseFrame(name, data);
    return SendAll(client, frame.data(), frame.size());
}

void ServeSseStream(SOCKET client) {
    // A valid HTTP response header must precede the event frames: a browser (or
    // curl) waits for a status line before it treats the body as a stream, so
    // without this the client renders nothing. Keep-alive + no-cache so the
    // stream is never buffered or closed early.
    static const std::string kHeader =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: keep-alive\r\n"
        "\r\n";
    if (!SendAll(client, kHeader.data(), kHeader.size())) {
        ::closesocket(client);
        return;
    }
    // 2s, not 1s. Each tick makes the client re-fetch /api/connections, which
    // runs the per-socket SIO_TCP_INFO scan - and that scan's detached probe
    // threads can wedge in an uncancelable kernel call, so a 1s cadence
    // accumulates them until the server stops accepting. 2s still beats the
    // 2-30s polling fallback by a wide margin while keeping the scan rate near
    // what the endpoint can actually sustain.
    constexpr DWORD kTickMs = 2000;
    ULONGLONG tick = 0;
    for (;;) {
        if (!SendSseFrame(client, "tick", std::to_string(tick))) break;
        ++tick;
        ::Sleep(kTickMs);
    }
    ::closesocket(client);
}

void ServeClient(ServerContext& context, SOCKET client) {
    DWORD receiveTimeout = 5000;
    DWORD sendTimeout = kMaxCliExecutionMs + 10000;
    if (::setsockopt(client, SOL_SOCKET, SO_RCVTIMEO,
                     reinterpret_cast<const char*>(&receiveTimeout),
                     sizeof(receiveTimeout)) == SOCKET_ERROR ||
        ::setsockopt(client, SOL_SOCKET, SO_SNDTIMEO,
                     reinterpret_cast<const char*>(&sendTimeout),
                     sizeof(sendTimeout)) == SOCKET_ERROR) {
        ::closesocket(client);
        return;
    }
    HttpRequest request;
    int errorStatus = 400;
    if (!ReceiveRequest(client, &request, &errorStatus)) {
        HttpResponse response;
        response.status = errorStatus;
        response.body = ErrorJson("malformed or oversized HTTP request");
        WriteWebUiLog(context, WebUiLogLevel::Warn,
                      "request rejected status=" + std::to_string(errorStatus));
        SendResponse(client, response, false);
        ::closesocket(client);
        return;
    }
    const HttpResponse response = [&]() -> HttpResponse {
        // Backstop. A C++ exception that escapes HandleRequest unwinds through
        // WebUiAcceptLoop and terminates the process (observed: a malformed
        // `since=` on /api/metrics/history threw std::invalid_argument and took
        // the server down with 0xE06D7363 plus a minidump). One bad request must
        // never take the dashboard offline, so a 500 is the worst case here.
        try {
            return HandleRequest(context, request);
        } catch (const std::exception& e) {
            WriteWebUiLog(context, WebUiLogLevel::Error,
                          std::string("handler threw std::exception: ") + e.what());
            HttpResponse failure;
            failure.status = 500;
            failure.body = ErrorJson("internal error");
            return failure;
        } catch (...) {
            WriteWebUiLog(context, WebUiLogLevel::Error,
                          "handler threw a non-std exception");
            HttpResponse failure;
            failure.status = 500;
            failure.body = ErrorJson("internal error");
            return failure;
        }
    }();
    std::string path = request.target;
    const size_t query = path.find('?');
    if (query != std::string::npos) path.resize(query);
    if (path.size() > 512) path.resize(512);
    for (char& c : path) {
        const unsigned char byte = static_cast<unsigned char>(c);
        if (byte < 0x20 || byte == 0x7f) c = '?';
    }
    WriteWebUiLog(context, WebUiLogLevel::Debug,
        "request method=" + request.method + " path=" + path +
        " status=" + std::to_string(response.status));
    SendResponse(client, response, request.method == "HEAD");
    ::closesocket(client);
}

// The accept/serve loop, extracted so it can run on its OWN thread. It used to
// run on the thread that also watched for shutdown; that design meant one
// wedged request froze shutdown - and shutdown is exactly the operation a stuck
// Web UI must guarantee. A serve of /api/connections runs the socket traffic
// sampler, whose detached WSAIoctl(SIO_TCP_INFO) probe threads can sit in an
// uncancelable kernel call that holds the process-wide Winsock handle lock,
// so the closesocket() at the foot of a serve never returns and the loop never
// reaches its top-of-loop stop check. Running it here lets RunWebUiServer wait
// on the stop event from a clean thread and terminate the process outright.
struct WebUiAcceptorArgs {
    ServerContext* context;
    SOCKET listener;
    HANDLE stopEvent;
};

// One connection served on its own thread. A Win32 thread, NOT a detached
// std::thread: a burst of concurrent requests was observed to stop the accept
// loop accepting entirely with a std::thread per connection under /MT, while
// the accept loop's own CreateThread is unaffected. The worker owns the socket
// (ServeClient closes it) and frees its argument.
struct ServeClientArgs {
    ServerContext* context;
    SOCKET client;
};

DWORD WINAPI ServeClientThread(LPVOID param) {
    ServeClientArgs* args = static_cast<ServeClientArgs*>(param);
    ServeClient(*args->context, args->client);
    delete args;
    return 0;
}

DWORD WINAPI WebUiAcceptLoop(LPVOID param) {
    const WebUiAcceptorArgs* args = static_cast<WebUiAcceptorArgs*>(param);
    ServerContext& context = *args->context;
    SOCKET listener = args->listener;
    HANDLE stopEvent = args->stopEvent;
    while (!g_stop.load()) {
        if (::WaitForSingleObject(stopEvent, 0) == WAIT_OBJECT_0) {
            g_stop.store(true);
            break;
        }
        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(listener, &readable);
        timeval wait = {};
        wait.tv_usec = 250000;
        const int ready = ::select(0, &readable, nullptr, nullptr, &wait);
        if (ready == 0) continue;
        if (ready == SOCKET_ERROR) {
            if (g_stop.load()) break;
            ::Sleep(20);
            continue;
        }
        sockaddr_in peer = {};
        int peerSize = sizeof(peer);
        SOCKET client = ::accept(listener, reinterpret_cast<sockaddr*>(&peer), &peerSize);
        if (client == INVALID_SOCKET) {
            if (g_stop.load()) break;
            if (::WSAGetLastError() == WSAEINTR) continue;
            ::Sleep(20);
            continue;
        }
        if (peer.sin_family != AF_INET || peer.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
            ::closesocket(client);
            continue;
        }
        // Served INLINE, one request at a time. A worker thread per connection
        // (std::thread and CreateThread alike) was MEASURED to wedge the accept
        // loop under a burst of concurrent requests - the server stopped
        // answering entirely, though the process stayed alive - so the Web UI
        // serves sequentially. That is also why there is no SSE/push channel: a
        // long-lived stream would block this loop, so the client polls instead.
        ServeClient(context, client);
    }
    return 0;
}

}  // namespace

int RunWebUiServer(unsigned portHint) {
    ServerContext context;
    if (!GetExecutableDirectory(&context.executableDirectory)) {
        std::cout << "webui: could not resolve executable directory\r\n";
        return kExitFail;
    }
    if (!PrepareDataPaths(&context)) {
        std::cout << "webui: could not create the local configuration directory\r\n";
        return kExitFail;
    }
    if (!InitializeWebUiLogging(&context)) {
        std::cout << "webui: could not create the diagnostic log file\r\n";
        return kExitFail;
    }
    WriteWebUiLog(context, WebUiLogLevel::Info,
        std::string("service starting log_level=") +
        WebUiLogLevelName(context.logLevel));
    std::string index, script, style, catalog;
    if (!ReadAsset(context, L"index.html", &index) ||
        !ReadAsset(context, L"app.js", &script) ||
        !ReadAsset(context, L"app.css", &style) ||
        !ReadAsset(context, L"templates.json", &catalog)) {
        WriteWebUiLog(context, WebUiLogLevel::Error,
                      "required webui asset is missing beside wintcp.exe");
        std::cout << "webui: assets missing; expected a webui folder beside wintcp.exe\r\n";
        return kExitFail;
    }
    if (!RandomHex(32, &context.token)) {
        WriteWebUiLog(context, WebUiLogLevel::Error,
                      "secure session token generation failed");
        std::cout << "webui: secure session token generation failed\r\n";
        return kExitFail;
    }
    // Start the PDH sampler. It used to never be started, so the ring buffer
    // stayed empty and /api/metrics/now and /api/metrics/history reported every
    // series as null (correctly "unknown", but not useful). The collector owns
    // its own PDH query and thread; the accept loop only reads snapshots under
    // the ring buffer's own mutex.
    if (!context.metricsCollector.Start()) {
        // Not fatal: the dashboard still works, metrics read as null, and
        // /api/capabilities reports pdh=false so the UI can say why.
        WriteWebUiLog(context, WebUiLogLevel::Warn,
                      "metrics sampler did not start; metrics read as null");
    }
    // Load the GeoIP database from the persisted config, if configured. Done
    // after the metrics sampler and before the accept loop, so the first /api/
    // requests see the country/ASN enrichment already wired up.
    LoadGeoIpFromConfig(context);
    // Connection refresher. Started AFTER Winsock, because CmdListInto reads
    // the IP Helper tables and a socket stack that is not up yet would make
    // every refresh fail.
    WSADATA winsock = {};
    if (::WSAStartup(MAKEWORD(2, 2), &winsock) != 0) {
        WriteWebUiLog(context, WebUiLogLevel::Error,
                      "Winsock initialization failed");
        std::cout << "webui: Winsock initialization failed\r\n";
        return kExitFail;
    }
    context.dnsAvailable = context.dnsResolver.Start([&context](
            std::unique_ptr<DnsResolver::Result> result) {
        if (!result) return;
        std::lock_guard<std::mutex> lock(g_storeMutex);
        if (result->state == DnsResolver::State::kPending) {
            for (const Connection& row : context.store.Rows()) {
                if (WebDnsKey(row.display.remoteAddress) == result->address)
                    context.store.SetHostname(row.display.remoteAddress,
                                              DnsResolver::kPendingHost);
            }
            return;
        }
        for (const Connection& row : context.store.Rows()) {
            if (WebDnsKey(row.display.remoteAddress) == result->address)
                context.store.SetHostname(row.display.remoteAddress, result->hostname);
        }
        if (context.dnsCompleted.insert(WebDnsKey(result->address)).second) {
            context.dnsCompletionOrder.push_back(WebDnsKey(result->address));
            while (context.dnsCompletionOrder.size() > kMaxWebDnsCompletions) {
                context.dnsCompleted.erase(context.dnsCompletionOrder.front());
                context.dnsCompletionOrder.pop_front();
            }
        }
    });
    if (context.dnsAvailable) {
        context.dnsResolver.SetEnabled(true);
    } else {
        WriteWebUiLog(context, WebUiLogLevel::Warn,
                      "reverse DNS resolver did not start; hostnames remain unavailable");
    }
    HANDLE refresher = ::CreateThread(nullptr, 0, ConnectionRefresherThread, &context,
                                       0, nullptr);
    if (refresher != nullptr) ::CloseHandle(refresher);
    if (refresher == nullptr) {
        // Not fatal: /api/connections still refreshes inline, and the summary
        // endpoints will report snapshotKnown=false rather than an empty set.
        WriteWebUiLog(context, WebUiLogLevel::Warn,
                      "connection refresher did not start; summaries read stale");
    }
    SOCKET listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) {
        ::WSACleanup();
        WriteWebUiLog(context, WebUiLogLevel::Error,
                      "could not create the loopback listener");
        std::cout << "webui: could not create the loopback listener\r\n";
        return kExitFail;
    }
    sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (portHint != 0) {
        address.sin_port = htons(static_cast<u_short>(portHint));
    }
    if (::bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) ==
            SOCKET_ERROR || ::listen(listener, SOMAXCONN) == SOCKET_ERROR) {
        ::closesocket(listener);
        ::WSACleanup();
        WriteWebUiLog(context, WebUiLogLevel::Error,
                      "could not bind 127.0.0.1");
        std::cout << "webui: could not bind 127.0.0.1\r\n";
        return kExitFail;
    }
    int addressSize = static_cast<int>(sizeof(address));
    if (::getsockname(listener, reinterpret_cast<sockaddr*>(&address),
                      &addressSize) == SOCKET_ERROR) {
        ::closesocket(listener);
        ::WSACleanup();
        WriteWebUiLog(context, WebUiLogLevel::Error,
                      "could not read the selected loopback port");
        std::cout << "webui: could not read the selected loopback port\r\n";
        return kExitFail;
    }
    const std::wstring stopEventName = L"Local\\WinTCP.WebUi.Stop." +
        std::to_wstring(::GetCurrentProcessId());
    HANDLE stopEvent = ::CreateEventW(nullptr, TRUE, FALSE, stopEventName.c_str());
    if (stopEvent == nullptr) {
        ::closesocket(listener);
        ::WSACleanup();
        WriteWebUiLog(context, WebUiLogLevel::Error,
                      "could not create the process shutdown event");
        std::cout << "webui: could not create the process shutdown event\r\n";
        return kExitFail;
    }
    // Publish the stop event so the Ctrl+C handler signals the same event the
    // PID-scoped stop event signals - one signal, two sources.
    g_stopEvent.store(stopEvent);
    context.port = ntohs(address.sin_port);
    g_stop.store(false);
    (void)::SetConsoleCtrlHandler(WebUiControlHandler, TRUE);

    const std::string url = "http://127.0.0.1:" + std::to_string(context.port) + "/";
    WriteWebUiLog(context, WebUiLogLevel::Info, "listening at " + url);
    std::cout << "WinTCP Web UI listening at " << url
              << "\nLocal configuration and audit log: "
              << WideToUtf8(context.dataDirectory) << "\nPress Ctrl+C to stop.\n";
    std::cout.flush();
    if (ShouldOpenWebUiBrowser()) {
        const HINSTANCE opened = ::ShellExecuteW(nullptr, L"open",
            std::wstring(url.begin(), url.end()).c_str(), nullptr, nullptr,
            SW_SHOWNORMAL);
        if (reinterpret_cast<INT_PTR>(opened) <= 32) {
            WriteWebUiLog(context, WebUiLogLevel::Warn,
                          "browser did not open automatically");
            std::cout << "webui: browser did not open automatically; copy the URL above\r\n";
        }
    } else {
        WriteWebUiLog(context, WebUiLogLevel::Debug,
                      "automatic browser launch disabled by environment");
    }

    // The accept loop runs on a worker thread; THIS thread only waits for the
    // stop signal and then hard-exits. Splitting the watcher from the server is
    // what guarantees a stop always terminates the process: the old code served
    // on this thread and then called WSACleanup() before returning, but a serve
    // of /api/connections runs the socket traffic sampler, whose detached
    // WSAIoctl(SIO_TCP_INFO) probe threads can be wedged in an uncancelable
    // kernel call holding the process-wide Winsock handle lock. That made
    // closesocket() (and the exit WSACleanup(), which waits on the same Winsock)
    // block forever, so the loop never reached its stop check and "webui-service
    // stop" timed out leaving wintcp.exe alive. ExitProcess reaps every thread
    // at once - the probe threads included - which is the whole point of a stop.
    WebUiAcceptorArgs acceptorArgs{ &context, listener, stopEvent };
    HANDLE acceptor = ::CreateThread(nullptr, 0, WebUiAcceptLoop, &acceptorArgs,
                                    0, nullptr);
    if (acceptor != nullptr) {
        ::CloseHandle(acceptor);
        ::WaitForSingleObject(stopEvent, INFINITE);
        ::ExitProcess(0);
    }
    // Thread creation failed (essentially never). Fall back to serving on this
    // thread: bounded stop latency for the idle case, and still hard-exits on
    // stop rather than calling WSACleanup().
    WebUiAcceptLoop(&acceptorArgs);
    ::ExitProcess(0);
    return kExitOk;   // unreachable: ExitProcess does not return
}

}  // namespace wintcp
