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
#include <thread>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "Commands.h"
#include "ConnectionStore.h"
#include "Settings.h"
#include "SocketTraffic.h"
#include "Utils.h"
#include "WebMetrics.h"
#include "WebStatic.h"
#include "WebUi.h"

namespace wintcp {
namespace {

constexpr size_t kMaxHeaderBytes = 16384;
constexpr size_t kMaxBodyBytes = 65536;
constexpr size_t kMaxAssetBytes = 1024 * 1024;
constexpr int kExpectedConfigVersion = 2;
constexpr size_t kMaxAuditBytes = 2 * 1024 * 1024;
constexpr size_t kAuditRetention = 1000;
constexpr size_t kMaxPendingBlocks = 64;
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
};

struct PendingBlock {
    std::string address;
    UINT port = 0;
    ULONGLONG expires = 0;
};

struct PendingCliAction {
    std::wstring verb;
    std::vector<std::wstring> args;
    ULONGLONG expires = 0;
};

enum class WebUiLogLevel : unsigned char { Debug, Info, Warn, Error };

struct ServerContext {
    std::wstring executableDirectory;
    std::wstring dataDirectory;
    std::wstring configPath;
    std::wstring auditPath;
    std::wstring logPath;
    WebUiLogLevel logLevel = WebUiLogLevel::Debug;
    std::string token;
    USHORT port = 0;
    SnapshotSource source;
    ConnectionStore store;
    MetricsCollector metricsCollector;
    std::map<std::string, PendingBlock> pendingBlocks;
    std::map<std::string, PendingCliAction> pendingCliActions;
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
            if (c < 0x20) return false;
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
    PWSTR local = nullptr;
    const HRESULT hr = ::SHGetKnownFolderPath(FOLDERID_LocalAppData,
                                               KF_FLAG_CREATE, nullptr, &local);
    if (FAILED(hr) || local == nullptr) return false;
    std::wstring base(local);
    ::CoTaskMemFree(local);
    context->dataDirectory = base + L"\\WinTCP\\WebUi";
    std::error_code ec;
    std::filesystem::create_directories(context->dataDirectory, ec);
    if (ec) return false;
    context->configPath = context->dataDirectory + L"\\config.json";
    context->auditPath = context->dataDirectory + L"\\audit.ndjson";
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
            if (contentLength > (kMaxBodyBytes - digit) / 10) {
                *errorStatus = 413;
                return false;
            }
            contentLength = contentLength * 10 + digit;
        }
    }
    if (contentLength > kMaxBodyBytes) { *errorStatus = 413; return false; }
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
        case 413: reason = "Payload Too Large"; break;
        case 415: reason = "Unsupported Media Type"; break;
        case 431: reason = "Request Header Fields Too Large"; break;
        case 500: reason = "Internal Server Error"; break;
        case 503: reason = "Service Unavailable"; break;
        default: break;
    }
    std::ostringstream headers;
    headers << "HTTP/1.1 " << response.status << " " << reason << "\r\n"
            << "Content-Type: " << response.contentType << "\r\n"
            << "Content-Length: " << response.body.size() << "\r\n"
            << "Cache-Control: no-store\r\n"
            << "X-Content-Type-Options: nosniff\r\n"
            << "X-Frame-Options: DENY\r\n"
            << "Referrer-Policy: no-referrer\r\n"
            << "Content-Security-Policy: default-src 'self'; connect-src 'self'; "
               "style-src 'self'; script-src 'self'; img-src 'self' data:; "
               "object-src 'none'; base-uri 'none'; frame-ancestors 'none'\r\n"
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
    ListOptions options;
    options.format = "json";
    // NO traffic. The per-socket SIO_TCP_INFO scan's detached probe threads can
    // wedge in an uncancelable kernel call that holds the PROCESS-WIDE Winsock
    // lock, which stops the whole server answering - reproduced with a browser
    // polling /api/connections. The traffic column therefore reads "—" in the
    // Web UI; the CLI and GUI still show it, because they run the scan once per
    // invocation rather than on a timer.
    options.webMetadata = true;
    std::lock_guard<std::mutex> lock(g_storeMutex);
    const CommandResult result = CmdListInto(context.source, context.store, options);
    if (result.exitCode != kExitOk) return ErrorJson(result.err.empty()
                                                         ? "snapshot unavailable"
                                                         : result.err);
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
        << "},\"connections\":" << result.out;
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
    out << "{\"elevated\":false"
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
        << ",\"etw\":true,\"trafficScan\":false,\"dns\":true"
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

std::string MetricsCatalogJson() {
    std::ostringstream out;
    out << "{\"series\":["
        << "{\"id\":\"cpu.total\",\"label\":\"CPU Total\",\"unit\":\"%\",\"kind\":\"gauge\"},"
        << "{\"id\":\"mem.usedBytes\",\"label\":\"Memory Used\",\"unit\":\"bytes\",\"kind\":\"gauge\"},"
        << "{\"id\":\"mem.totalBytes\",\"label\":\"Memory Total\",\"unit\":\"bytes\",\"kind\":\"gauge\"},"
        << "{\"id\":\"disk.readBps\",\"label\":\"Disk Read\",\"unit\":\"bytes/s\",\"kind\":\"gauge\"},"
        << "{\"id\":\"disk.writeBps\",\"label\":\"Disk Write\",\"unit\":\"bytes/s\",\"kind\":\"gauge\"},"
        << "{\"id\":\"net.rxBps\",\"label\":\"Network RX\",\"unit\":\"bytes/s\",\"kind\":\"gauge\"},"
        << "{\"id\":\"net.txBps\",\"label\":\"Network TX\",\"unit\":\"bytes/s\",\"kind\":\"gauge\"}"
        << "]}";
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

std::string MetricsNowJson(ServerContext& context) {
    MetricsSample sample;
    const bool have = context.metricsCollector.GetLatest(&sample);
    std::ostringstream out;
    out << "{";
    if (have) {
        // Every catalogued series is always present. An unavailable counter is
        // null plus a reason, never 0 - a zero here would read as "idle".
        const auto series = [&](const char* id, bool known, double value,
                                const char* reason) {
            out << "\"" << id << "\":" << (known ? JsonNumber(value) : std::string("null"))
                << ",\"" << id << ".reason\":"
                << (known ? "null" : JsonQuote(reason)) << ",";
        };
        series("cpu.total", sample.cpuTotalKnown, sample.cpuTotal,
               "PDH counter not ready");
        series("mem.usedBytes", sample.memUsedKnown,
               static_cast<double>(sample.memUsed), "PDH counter not ready");
        series("mem.totalBytes", sample.memTotalKnown,
               static_cast<double>(sample.memTotal), "PDH counter not ready");
        bool diskReadKnown = false, diskWriteKnown = false;
        bool netRxKnown = false, netTxKnown = false;
        const double diskRead = SumInstances(sample.diskReadBps, sample.diskReadKnown,
                                             &diskReadKnown);
        const double diskWrite = SumInstances(sample.diskWriteBps, sample.diskWriteKnown,
                                              &diskWriteKnown);
        const double netRx = SumInstances(sample.netRxBps, sample.netRxKnown, &netRxKnown);
        const double netTx = SumInstances(sample.netTxBps, sample.netTxKnown, &netTxKnown);
        series("disk.readBps", diskReadKnown, diskRead, "no disk counters available");
        series("disk.writeBps", diskWriteKnown, diskWrite, "no disk counters available");
        series("net.rxBps", netRxKnown, netRx, "no network counters available");
        series("net.txBps", netTxKnown, netTx, "no network counters available");
        // Per-core CPU: cpu.core.<n>, null where the core reported no data. No
        // leading comma - the series() lambda above already left one.
        for (size_t i = 0; i < sample.cpuCore.size(); ++i) {
            const bool known = i < sample.cpuCoreKnown.size() && sample.cpuCoreKnown[i];
            out << "\"cpu.core." << i << "\":"
                << (known ? JsonNumber(sample.cpuCore[i]) : std::string("null"))
                << ",\"cpu.core." << i << ".reason\":"
                << (known ? "null" : JsonQuote("core counter returned no data")) << ",";
        }
        out << "\"_timestamp\":" << sample.unixTime;
    } else {
        const std::string reason = JsonQuote("sampler has not produced a sample yet");
        out << "\"cpu.total\":null,\"cpu.total.reason\":" << reason
            << ",\"mem.usedBytes\":null,\"mem.usedBytes.reason\":" << reason
            << ",\"mem.totalBytes\":null,\"mem.totalBytes.reason\":" << reason
            << ",\"disk.readBps\":null,\"disk.readBps.reason\":" << reason
            << ",\"disk.writeBps\":null,\"disk.writeBps.reason\":" << reason
            << ",\"net.rxBps\":null,\"net.rxBps.reason\":" << reason
            << ",\"net.txBps\":null,\"net.txBps.reason\":" << reason;
    }
    out << "}";
    return out.str();
}

std::string MetricsHistoryJson(ServerContext& context, const HttpRequest& request) {
    uint64_t since = 0;
    size_t maxSamples = 900;
    std::string tier = "1s";
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
            if (params.count("tier")) tier = params["tier"];
        }
    }
    auto samples = context.metricsCollector.GetHistory(since, maxSamples);
    std::ostringstream out;
    out << "{\"tier\":" << JsonQuote(tier) << ",\"step\":1,\"count\":"
        << samples.size() << ",\"t\":[";
    for (size_t i = 0; i < samples.size(); ++i) {
        if (i > 0) out << ",";
        out << samples[i].unixTime;
    }
    // One aligned array per series inside "series". Unknown samples are null,
    // never 0 (C-6), and every array lines up index-for-index with "t".
    out << "],\"series\":{";
    bool firstSeries = true;
    const auto emit = [&](const char* id, auto pick) {
        if (!firstSeries) out << ",";
        firstSeries = false;
        out << "\"" << id << "\":[";
        for (size_t i = 0; i < samples.size(); ++i) {
            if (i > 0) out << ",";
            const std::pair<bool, double> value = pick(samples[i]);
            out << (value.first ? JsonNumber(value.second) : std::string("null"));
        }
        out << "]";
    };
    emit("cpu.total", [](const MetricsSample& s) {
        return std::pair<bool, double>(s.cpuTotalKnown, s.cpuTotal);
    });
    emit("mem.usedBytes", [](const MetricsSample& s) {
        return std::pair<bool, double>(s.memUsedKnown, static_cast<double>(s.memUsed));
    });
    emit("disk.readBps", [](const MetricsSample& s) {
        bool known = false;
        const double total = SumInstances(s.diskReadBps, s.diskReadKnown, &known);
        return std::pair<bool, double>(known, total);
    });
    emit("disk.writeBps", [](const MetricsSample& s) {
        bool known = false;
        const double total = SumInstances(s.diskWriteBps, s.diskWriteKnown, &known);
        return std::pair<bool, double>(known, total);
    });
    emit("net.rxBps", [](const MetricsSample& s) {
        bool known = false;
        const double total = SumInstances(s.netRxBps, s.netRxKnown, &known);
        return std::pair<bool, double>(known, total);
    });
    emit("net.txBps", [](const MetricsSample& s) {
        bool known = false;
        const double total = SumInstances(s.netTxBps, s.netTxKnown, &known);
        return std::pair<bool, double>(known, total);
    });
    out << "}}";
    return out.str();
}

std::string ProcessesJson(ServerContext& context) {
    std::lock_guard<std::mutex> lock(g_storeMutex);
    std::ostringstream out;
    out << "{\"processes\":[";
    bool first = true;
    std::map<DWORD, int> connCount;
    std::map<DWORD, int> listenCount;
    for (size_t i = 0; i < context.store.View().size(); ++i) {
        const Connection* row = context.store.ViewRow(i);
        if (row == nullptr || (row->flags & kRowRemoved) != 0) continue;
        if (row->identity.pid == 0) continue;
        connCount[row->identity.pid]++;
        if (row->identity.protocol == IPPROTO_TCP && row->keys.stateLabel == L"LISTENING")
            listenCount[row->identity.pid]++;
    }
    for (const auto& kv : connCount) {
        if (!first) out << ",";
        first = false;
        out << "{\"pid\":" << kv.first
            << ",\"connections\":" << kv.second
            << ",\"listeners\":" << listenCount[kv.first] << "}";
    }
    out << "]}";
    return out.str();
}

std::string NetworkSummaryJson(ServerContext& context) {
    std::lock_guard<std::mutex> lock(g_storeMutex);
    std::map<std::string, int> byState, byProto, byFamily, byProcess;
    int loopback = 0, lan = 0, wildcard = 0;
    for (size_t i = 0; i < context.store.View().size(); ++i) {
        const Connection* row = context.store.ViewRow(i);
        if (row == nullptr || (row->flags & kRowRemoved) != 0) continue;
        byState[WideToUtf8(row->keys.stateLabel.empty() ? L"UNKNOWN" : row->keys.stateLabel)]++;
        byProto[row->identity.protocol == IPPROTO_TCP ? "TCP" : "UDP"]++;
        byFamily[row->identity.family == AF_INET6 ? "IPv6" : "IPv4"]++;
        byProcess[row->display.processName.empty() ? "unknown" : std::string("PROC")]++;
        if (row->identity.protocol == IPPROTO_TCP && row->keys.stateLabel == L"LISTENING") {
            const std::wstring& local = row->display.localAddress;
            if (local == L"0.0.0.0" || local == L"::" || local == L"*") wildcard++;
            else if (local == L"127.0.0.1" || local == L"::1") loopback++;
            else lan++;
        }
    }
    std::ostringstream out;
    out << "{\"byState\":{";
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
    out << "},\"listeners\":{\"loopback\":" << loopback << ",\"lan\":" << lan << ",\"wildcard\":" << wildcard << "}}";
    return out.str();
}

std::string GeoSummaryJson(ServerContext& context) {
    std::lock_guard<std::mutex> lock(g_storeMutex);
    std::map<std::string, int> countries;
    int local = 0, unknown = 0;
    for (size_t i = 0; i < context.store.View().size(); ++i) {
        const Connection* row = context.store.ViewRow(i);
        if (row == nullptr || (row->flags & kRowRemoved) != 0) continue;
        if (row->identity.family != AF_INET) continue;
        uint32_t addr = ntohl(row->identity.remote4.S_un.S_addr);
        if (!IsGlobalUnicastV4(addr)) { local++; continue; }
        std::wstring cc = context.source.GeoIpLoaded()
            ? context.source.GeoIpLookupV4(addr) : L"";
        if (cc.empty()) unknown++;
        else countries[WideToUtf8(cc)]++;
    }
    std::ostringstream out;
    out << "{\"countries\":{";
    bool first = true;
    for (const auto& kv : countries) { if (!first) out << ","; first = false; out << JsonQuote(kv.first) << ":" << kv.second; }
    out << "},\"asns\":{},\"local\":" << local << ",\"unknown\":" << unknown
        << ",\"geoIpConfigured\":" << (context.source.GeoIpLoaded() ? "true" : "false") << "}";
    return out.str();
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

RuleRequest BlockRequest(const std::string& address, UINT port) {
    RuleRequest request;
    request.proto = L"tcp";
    request.address.assign(address.begin(), address.end());
    if (port != 0) request.remotePorts = std::to_wstring(port);
    request.label = L"WinTCP Web UI peer threshold";
    return request;
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
    // The pre-upgrade dashboard, preserved verbatim under webui/legacy. It is the
    // strangler's fallback: the control room at / is still being ported page by
    // page, and until a page reaches parity the legacy build keeps every feature
    // (filter/sort/group/freeze, permit flow, scripts, templates, presets,
    // bookmarks, alerts) reachable instead of silently lost.
    if (path == "/legacy" || path == "/legacy/" || path == "/legacy/index.html") {
        ServeShell(context, L"legacy\\index.html", &response);
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
    // Static assets: /js/*, /css/*, /vendor/*, /data/*, /img/*, /fonts/*, /legacy/*.
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
        WIN32_FILE_ATTRIBUTE_DATA fad = {};
        if (::GetFileAttributesExW(fullPath.c_str(), GetFileExInfoStandard, &fad)) {
            // A reparse point (symlink, junction, mount point) inside the webui
            // tree can point anywhere on the machine, so it is refused outright
            // rather than resolved.
            if ((fad.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
                (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                response.status = 403;
                response.body = "Forbidden";
                return response;
            }
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
        response.body = MetricsCatalogJson();
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
        response.body = ProcessesJson(context);
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
    if (path == "/api/config" && request.method == "GET") {
        if (!ReadFileBounded(context.configPath, kMaxBodyBytes, &response.body)) {
            // First run: serve the SHIPPED default (webui\config.default.json)
            // rather than an in-code literal, so the file the build installs is
            // the one the server actually falls back to. A missing or malformed
            // asset degrades to a minimal object that keeps the page usable.
            if (!ReadAsset(context, L"config.default.json", &response.body) ||
                !IsValidJsonObject(response.body))
                response.body = "{\"version\":" + std::to_string(kExpectedConfigVersion) + ",\"refreshSeconds\":5,\"rules\":[]}";
        } else if (!IsValidJsonObject(response.body)) {
            // Corruption recovery: a persisted config that is no longer a
            // valid JSON object is unrecoverable as-is. Serve the shipped
            // default (current schema version) so the page stays usable, and log
            // the recovery so an operator can restore from the .1/.2 backups.
            // A user-owned file must never surface as a 500.
            if (ReadAsset(context, L"config.default.json", &response.body) &&
                IsValidJsonObject(response.body)) {
                WriteWebUiLog(context, WebUiLogLevel::Warn,
                    "config.json was corrupt; recovered to schema v" +
                    std::to_string(kExpectedConfigVersion) + " defaults (restore from .1/.2)");
            } else {
                response.body = "{\"version\":" + std::to_string(kExpectedConfigVersion) + ",\"rules\":[]}";
            }
        }
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
        if (!WriteFileAtomic(context.configPath, request.body)) {
            response.status = 500;
            response.body = ErrorJson("configuration could not be saved");
            return response;
        }
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
        UINT port = 0;
        if (!ParseForm(request.body, &fields) || fields.size() != 2 ||
            fields.find("address") == fields.end() || fields.find("port") == fields.end() ||
            !IsIpAddress(fields["address"]) ||
            !ParsePort(fields["port"], &port, true)) {
            response.status = 400;
            response.body = ErrorJson("block preview needs a literal IP address and port 0..65535 (0 means all remote TCP ports)");
            return response;
        }
        const CommandResult plan = CmdRule(BlockRequest(fields["address"], port),
                                           true, false);
        if (plan.exitCode != kExitOk) {
            response.status = 400;
            response.body = "{\"ok\":false,\"message\":" + JsonQuote(plan.err + plan.out) + "}";
            return response;
        }
        for (auto it = context.pendingBlocks.begin(); it != context.pendingBlocks.end();) {
            if (it->second.expires < ::GetTickCount64()) it = context.pendingBlocks.erase(it);
            else ++it;
        }
        while (context.pendingBlocks.size() >= kMaxPendingBlocks)
            context.pendingBlocks.erase(context.pendingBlocks.begin());
        std::string nonce;
        if (!RandomHex(16, &nonce)) {
            response.status = 500;
            response.body = ErrorJson("secure preview token generation failed");
            return response;
        }
        context.pendingBlocks[nonce] = PendingBlock{
            fields["address"], port, ::GetTickCount64() + 30000};
        response.body = "{\"ok\":true,\"nonce\":" + JsonQuote(nonce) +
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
        const auto pending = context.pendingBlocks.find(fields["nonce"]);
        if (pending == context.pendingBlocks.end() ||
            pending->second.expires < ::GetTickCount64()) {
            if (pending != context.pendingBlocks.end()) context.pendingBlocks.erase(pending);
            response.status = 403;
            response.body = ErrorJson("preview expired or already used; preview the action again");
            return response;
        }
        const PendingBlock action = pending->second;
        context.pendingBlocks.erase(pending);
        const std::string attempt = "{\"type\":\"firewall-block-attempt\",\"address\":" +
                                    JsonQuote(action.address) + ",\"port\":" +
                                    std::to_string(action.port) + "}";
        if (!AppendAudit(context, attempt)) {
            response.status = 500;
            response.body = ErrorJson("firewall action was not attempted because the audit log is unavailable");
            return response;
        }
        const CommandResult result = CmdRule(BlockRequest(action.address, action.port),
                                             false, true);
        const bool ok = result.exitCode == kExitOk;
        const std::string event = "{\"type\":\"firewall-block\",\"address\":" +
                                  JsonQuote(action.address) + ",\"port\":" +
                                  std::to_string(action.port) + ",\"result\":" +
                                  JsonQuote(ok ? "success" : "refused-or-failed") + "}";
        const bool auditRecorded = AppendAudit(context, event);
        if (!ok) response.status = 403;
        response.body = "{\"ok\":" + std::string(ok ? "true" : "false") +
                        ",\"exitCode\":" + std::to_string(result.exitCode) +
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
    (void)::setsockopt(client, SOL_SOCKET, SO_RCVTIMEO,
                       reinterpret_cast<const char*>(&receiveTimeout), sizeof(receiveTimeout));
    (void)::setsockopt(client, SOL_SOCKET, SO_SNDTIMEO,
                       reinterpret_cast<const char*>(&sendTimeout), sizeof(sendTimeout));
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

int RunWebUiServer() {
    ServerContext context;
    if (!GetExecutableDirectory(&context.executableDirectory)) {
        std::cout << "webui: could not resolve executable directory\r\n";
        return kExitFail;
    }
    if (!PrepareDataPaths(&context)) {
        std::cout << "webui: could not create %LOCALAPPDATA%\\WinTCP\\WebUi\r\n";
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
    WSADATA winsock = {};
    if (::WSAStartup(MAKEWORD(2, 2), &winsock) != 0) {
        WriteWebUiLog(context, WebUiLogLevel::Error,
                      "Winsock initialization failed");
        std::cout << "webui: Winsock initialization failed\r\n";
        return kExitFail;
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
    address.sin_port = 0;
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
                 "%LOCALAPPDATA%\\WinTCP\\WebUi\nPress Ctrl+C to stop.\n";
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
