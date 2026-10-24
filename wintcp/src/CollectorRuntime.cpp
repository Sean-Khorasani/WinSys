// CollectorRuntime.cpp
// SPDX-License-Identifier: Apache-2.0
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <sddl.h>
#include <bcrypt.h>
#include <shellapi.h>

#include "CollectorRuntime.h"
#include "EngineRuntime.h"
#include "RestrictionLease.h"
#include "RestrictionWfp.h"
#include "ConnectionEventCollector.h"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace wintcp {
namespace {

constexpr DWORD kMaxFrame = 256 * 1024;
constexpr DWORD kNonceLength = 16;

struct Identity {
    std::vector<unsigned char> sid;
    std::wstring sidText;
    DWORD session = 0;
};

bool TokenIdentity(HANDLE token, Identity* out) {
    DWORD bytes = 0;
    ::GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
    if (bytes == 0 || bytes > 65536) return false;
    std::vector<unsigned char> data(bytes);
    if (!::GetTokenInformation(token, TokenUser, data.data(), bytes, &bytes))
        return false;
    const TOKEN_USER* user = reinterpret_cast<const TOKEN_USER*>(data.data());
    const DWORD length = ::GetLengthSid(user->User.Sid);
    if (length == 0 || length > SECURITY_MAX_SID_SIZE) return false;
    out->sid.resize(length);
    if (!::CopySid(length, out->sid.data(), user->User.Sid)) return false;
    DWORD size = sizeof(out->session);
    if (!::GetTokenInformation(token, TokenSessionId, &out->session, size, &size))
        return false;
    LPWSTR text = nullptr;
    if (!::ConvertSidToStringSidW(out->sid.data(), &text)) return false;
    out->sidText = text;
    ::LocalFree(text);
    return true;
}

bool OwnIdentity(Identity* out, bool* elevated) {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation = {};
    DWORD size = 0;
    const bool ok = TokenIdentity(token, out) &&
        ::GetTokenInformation(token, TokenElevation, &elevation,
                              sizeof(elevation), &size) != FALSE;
    ::CloseHandle(token);
    if (ok && elevated != nullptr) *elevated = elevation.TokenIsElevated != 0;
    return ok;
}

std::wstring PipeName(const Identity& identity) {
    return L"\\\\.\\pipe\\WinTCP.Collector." + identity.sidText + L"." +
           std::to_wstring(identity.session);
}

bool SameClient(HANDLE pipe, const Identity& own) {
    if (!::ImpersonateNamedPipeClient(pipe)) return false;
    HANDLE token = nullptr;
    Identity peer;
    bool same = false;
    if (::OpenThreadToken(::GetCurrentThread(), TOKEN_QUERY, TRUE, &token)) {
        same = TokenIdentity(token, &peer) && peer.session == own.session &&
            ::EqualSid(peer.sid.data(), const_cast<unsigned char*>(own.sid.data())) != FALSE;
        ::CloseHandle(token);
    }
    ::RevertToSelf();
    return same;
}

bool ReadExact(HANDLE pipe, void* data, DWORD size) {
    auto* cursor = static_cast<unsigned char*>(data);
    const ULONGLONG deadline = ::GetTickCount64() + 2000;
    while (size != 0) {
        DWORD available = 0;
        if (!::PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr))
            return false;
        if (available == 0) {
            if (::GetTickCount64() >= deadline) return false;
            ::Sleep(10);
            continue;
        }
        DWORD read = 0;
        if (!::ReadFile(pipe, cursor, (size < available ? size : available),
                        &read, nullptr) || read == 0) return false;
        cursor += read;
        size -= read;
    }
    return true;
}

bool ReadFrame(HANDLE pipe, std::string* out) {
    DWORD size = 0;
    if (!ReadExact(pipe, &size, sizeof(size)) || size == 0 || size > kMaxFrame)
        return false;
    out->resize(size);
    return ReadExact(pipe, &(*out)[0], size);
}

bool WriteFrame(HANDLE pipe, const std::string& data) {
    if (data.empty() || data.size() > kMaxFrame) return false;
    const DWORD size = static_cast<DWORD>(data.size());
    const auto writeAll = [pipe](const void* data, DWORD bytes) {
        const auto* cursor = static_cast<const unsigned char*>(data);
        while (bytes != 0) {
            DWORD written = 0;
            if (!::WriteFile(pipe, cursor, bytes, &written, nullptr) ||
                written == 0) return false;
            cursor += written;
            bytes -= written;
        }
        return true;
    };
    return writeAll(&size, sizeof(size)) && writeAll(data.data(), size);
}

std::string Epoch(const std::string& status) {
    const std::string marker = "\"epoch\":\"";
    const auto begin = status.find(marker);
    if (begin == std::string::npos) return {};
    const auto first = begin + marker.size();
    const auto last = status.find('"', first);
    if (last == std::string::npos || last - first < 8 || last - first > 64)
        return {};
    return status.substr(first, last - first);
}

RestrictionNow Now() {
    FILETIME time = {};
    ::GetSystemTimeAsFileTime(&time);
    ULARGE_INTEGER value = {};
    value.LowPart = time.dwLowDateTime;
    value.HighPart = time.dwHighDateTime;
    constexpr std::uint64_t kUnixEpoch100Ns = 116444736000000000ULL;
    return {::GetTickCount64(), value.QuadPart >= kUnixEpoch100Ns
        ? (value.QuadPart - kUnixEpoch100Ns) / 10000ULL : 0};
}

std::string RandomId() {
    unsigned char bytes[16] = {};
    if (::BCryptGenRandom(nullptr, bytes, sizeof(bytes),
                          BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) return {};
    static const char hex[] = "0123456789abcdef";
    std::string id;
    id.reserve(sizeof(bytes) * 2);
    for (unsigned char byte : bytes) {
        id.push_back(hex[byte >> 4]);
        id.push_back(hex[byte & 15]);
    }
    return id;
}

std::string JsonQuote(const std::string& value) {
    static const char hex[] = "0123456789abcdef";
    std::string result = "\"";
    for (unsigned char c : value) {
        if (c == '"' || c == '\\') {
            result.push_back('\\');
            result.push_back(static_cast<char>(c));
        } else if (c < 0x20) {
            result += "\\u00";
            result.push_back(hex[c >> 4]);
            result.push_back(hex[c & 15]);
        } else result.push_back(static_cast<char>(c));
    }
    return result + '"';
}

std::string ErrorJson(const std::string& code) {
    return "{\"schemaVersion\":1,\"code\":" + JsonQuote(code) + "}";
}

bool ParseUnsigned(const std::string& text, unsigned maximum, unsigned* out) {
    if (text.empty() || text.size() > 10 || out == nullptr) return false;
    unsigned value = 0;
    for (char c : text) {
        if (c < '0' || c > '9' || value > (maximum -
            static_cast<unsigned>(c - '0')) / 10) return false;
        value = value * 10 + static_cast<unsigned>(c - '0');
    }
    *out = value;
    return true;
}

bool ParsePreview(const std::string& payload, const Identity& own,
                  RestrictionPlan* plan) {
    if (plan == nullptr || payload.size() > 2048 ||
        payload.find('\0') != std::string::npos ||
        payload.find('\r') != std::string::npos) return false;
    std::vector<std::string> fields;
    std::size_t start = 0;
    for (;;) {
        const auto end = payload.find('\n', start);
        fields.push_back(payload.substr(start, end == std::string::npos
            ? end : end - start));
        if (end == std::string::npos) break;
        start = end + 1;
        if (fields.size() >= 5) return false;
    }
    if (fields.size() != 5) return false;
    unsigned port = 0, duration = 0;
    if (!ParseUnsigned(fields[2], 65535, &port) ||
        !ParseUnsigned(fields[4], 1440, &duration)) return false;
    plan->imagePath = fields[0];
    plan->remoteAddress = fields[1];
    plan->remotePort = static_cast<std::uint16_t>(port);
    plan->protocol = fields[3] == "tcp" ? RestrictionProtocol::Tcp :
        fields[3] == "udp" ? RestrictionProtocol::Udp :
        RestrictionProtocol::TcpAndUdp;
    if (fields[3] != "tcp" && fields[3] != "udp" && fields[3] != "both")
        return false;
    plan->durationSeconds = duration * 60;
    const std::wstring& sid = own.sidText;
    const int bytes = ::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        sid.c_str(), static_cast<int>(sid.size()), nullptr, 0, nullptr, nullptr);
    if (bytes <= 0) return false;
    plan->userSid.resize(static_cast<std::size_t>(bytes));
    return ::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        sid.c_str(), static_cast<int>(sid.size()), &plan->userSid[0], bytes,
        nullptr, nullptr) == bytes;
}

bool SafeId(const std::string& id) {
    if (id.size() != 32) return false;
    for (char c : id)
        if ((c < '0' || c > '9') && (c < 'a' || c > 'f')) return false;
    return true;
}

std::string LeaseJson(const RestrictionLease& lease) {
    std::string result = "{\"id\":" + JsonQuote(lease.id) +
        ",\"owner\":" + JsonQuote(lease.owner) +
        ",\"planHash\":" + JsonQuote(lease.planHash) +
        ",\"imagePath\":" + JsonQuote(lease.plan.imagePath) +
        ",\"userSid\":" + JsonQuote(lease.plan.userSid) +
        ",\"remoteAddress\":" + JsonQuote(lease.plan.remoteAddress) +
        ",\"remotePort\":" + std::to_string(lease.plan.remotePort) +
        ",\"protocol\":" + JsonQuote(lease.plan.protocol == RestrictionProtocol::Tcp
            ? "tcp" : lease.plan.protocol == RestrictionProtocol::Udp ? "udp" : "both") +
        ",\"startedUtcMs\":\"" + std::to_string(lease.started.utcMs) +
        "\",\"deadlineUtcMs\":\"" + std::to_string(lease.deadlineUtcMs) +
        "\",\"durationSeconds\":" +
        std::to_string(lease.plan.durationSeconds) + ",\"filterIds\":[";
    for (std::size_t i = 0; i < lease.filterIds.size(); ++i) {
        if (i != 0) result += ',';
        result += '"' + std::to_string(lease.filterIds[i]) + '"';
    }
    return result + "]}";
}

std::string EventStatusJson(const ConnectionCollectorStatus& status) {
    return "{\"running\":" + std::string(status.running ? "true" : "false") +
        ",\"decoded\":\"" + std::to_string(status.decoded) +
        "\",\"queueLost\":\"" + std::to_string(status.queueLost) +
        "\",\"schemaRejected\":\"" + std::to_string(status.schemaRejected) +
        "\",\"eventsLost\":\"" + std::to_string(status.eventsLost) +
        "\",\"buffersLost\":\"" + std::to_string(status.buffersLost) +
        "\",\"historyEvicted\":\"" + std::to_string(status.historyEvicted) +
        "\",\"qpcFrequency\":\"" + std::to_string(status.qpcFrequency) +
        "\",\"attributed\":\"" + std::to_string(status.attributed) +
        "\",\"clockStable\":" + std::string(status.clockStable ? "true" : "false") +
        ",\"lateRecords\":\"" + std::to_string(status.lateRecords) +
        "\",\"flowEvicted\":\"" + std::to_string(status.flowEvicted) +
        "\",\"reorderFlushes\":\"" + std::to_string(status.reorderFlushes) +
        "\",\"published\":\"" + std::to_string(status.published) + "\"" +
        ",\"traceResult\":" + std::to_string(status.traceResult) + "}";
}

bool ParseUint64(const std::string& value, std::uint64_t* out) {
    if (value.empty() || value.size() > 20 || out == nullptr) return false;
    std::uint64_t parsed = 0;
    for (char c : value) {
        if (c < '0' || c > '9' || parsed >
            ((std::numeric_limits<std::uint64_t>::max)() - static_cast<unsigned>(c - '0')) / 10)
            return false;
        parsed = parsed * 10 + static_cast<unsigned>(c - '0');
    }
    *out = parsed;
    return true;
}

std::string ChangesWire(const RestrictionLeaseController& leases,
                         const std::string& epoch, const std::string& cursor) {
    std::uint64_t after = 0;
    if (!cursor.empty() && (cursor.size() > 64 || cursor.rfind(epoch + ':', 0) != 0 ||
        !ParseUint64(cursor.substr(epoch.size() + 1), &after)))
        return ErrorJson("cursor_expired");
    const auto& changes = leases.Changes();
    if (changes.empty() && after != 0) return ErrorJson("cursor_expired");
    if (!changes.empty() && after > changes.back().sequence)
        return ErrorJson("cursor_expired");
    const std::uint64_t lost = changes.empty() || after >= changes.front().sequence - 1
        ? 0 : changes.front().sequence - after - 1;
    std::string lines;
    std::size_t count = 0;
    for (const auto& change : changes) {
        if (change.sequence <= after) continue;
        lines += "{\"schemaVersion\":1,\"id\":" +
            JsonQuote(epoch + ":restriction-" + std::to_string(change.sequence)) +
            ",\"brokerEpoch\":" + JsonQuote(epoch) +
            ",\"kind\":\"restriction_changed\",\"source\":\"wfp_broker\",\"sequence\":\"" +
            std::to_string(change.sequence) + "\",\"state\":" + JsonQuote(change.state) +
            ",\"reason\":" + JsonQuote(change.reason) +
            ",\"occurredUtcMs\":\"" + std::to_string(change.occurred.utcMs) +
            "\",\"monotonicMs\":\"" + std::to_string(change.occurred.monotonicMs) +
            "\",\"lease\":" + LeaseJson(change.lease) + "}\n";
        after = change.sequence;
        if (++count >= 32) break;
    }
    return "WinTCP-Restriction-Changes:1\n" + epoch + ':' +
        std::to_string(after) + '\n' + std::to_string(lost) + '\n' + lines;
}

std::string LifecycleWire(const ConnectionEventCollector& events,
                           const std::string& epoch, const std::string& cursor) {
    std::uint64_t after = 0;
    if (!cursor.empty() && (cursor.size() > 64 || cursor.rfind(epoch + ':', 0) != 0 ||
        !ParseUint64(cursor.substr(epoch.size() + 1), &after)))
        return ErrorJson("cursor_expired");
    if (after > events.LastPublishedSequence()) return ErrorJson("cursor_expired");
    std::uint64_t first = 0;
    const auto page = events.ReadAfter(after, 32, &first);
    const auto lost = first == 0 || after >= first - 1 ? 0 : first - after - 1;
    std::string lines;
    const auto frequency = events.Status().qpcFrequency;
    for (const auto& observation : page) {
        lines += TraceObservationJson(observation, epoch, frequency) + '\n';
        after = observation.publicationSequence;
    }
    return "WinTCP-Lifecycle-Events:1\n" + epoch + ':' + std::to_string(after) +
        '\n' + std::to_string(lost) + '\n' + lines;
}

bool Request(unsigned char command, const std::string& payload,
             std::string* response) {
    Identity own;
    if (!OwnIdentity(&own, nullptr)) return false;
    const std::wstring pipeName = PipeName(own);
    HANDLE pipe = ::CreateFileW(pipeName.c_str(), GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, SECURITY_SQOS_PRESENT |
                                SECURITY_IMPERSONATION, nullptr);
    if (pipe == INVALID_HANDLE_VALUE && ::GetLastError() == ERROR_PIPE_BUSY &&
        ::WaitNamedPipeW(pipeName.c_str(), 200))
        pipe = ::CreateFileW(pipeName.c_str(), GENERIC_READ | GENERIC_WRITE,
            0, nullptr, OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return false;
    bool ok = WriteFrame(pipe, std::string("\1\0", 2));
    std::string nonce;
    if (ok) ok = ReadFrame(pipe, &nonce) && nonce.size() == kNonceLength;
    if (ok) {
        std::string message("\1", 1);
        message.push_back(static_cast<char>(command));
        message += nonce;
        message += payload;
        ok = WriteFrame(pipe, message) && ReadFrame(pipe, response);
    }
    ::CloseHandle(pipe);
    return ok;
}

bool StartCancellable(const std::function<bool()>& cancelled, std::string* error) {
    // UAC can wait indefinitely for the user. Put only the fixed launch step
    // in an owned child so shutting down the engine can cancel its own worker.
    std::wstring executable;
    if (!RuntimeCliPath(&executable, error)) return false;
    std::wstring command = L"\"" + executable + L"\" collector start";
    STARTUPINFOW startup = {};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION child = {};
    if (!::CreateProcessW(executable.c_str(), &command[0], nullptr, nullptr, FALSE,
                          CREATE_NO_WINDOW, nullptr, nullptr, &startup, &child)) {
        *error = "collector_launch_failed";
        return false;
    }
    ::CloseHandle(child.hThread);
    bool stopped = false;
    while (::WaitForSingleObject(child.hProcess, 100) == WAIT_TIMEOUT) {
        if (!cancelled()) continue;
        // This is only our unelevated launcher, never a collector with filters.
        (void)::TerminateProcess(child.hProcess, ERROR_CANCELLED);
        (void)::WaitForSingleObject(child.hProcess, 5000);
        stopped = true;
        break;
    }
    DWORD code = 1;
    (void)::GetExitCodeProcess(child.hProcess, &code);
    ::CloseHandle(child.hProcess);
    if (stopped) *error = "operation_cancelled";
    else if (code != 0) *error = code == 3 ? "elevation_cancelled" : "collector_launch_failed";
    return !stopped && code == 0;
}

int Run() {
    Identity own;
    bool elevated = false;
    if (!OwnIdentity(&own, &elevated)) return 1;
    if (!elevated) {
        std::fputs("collector run: administrator approval required\n", stderr);
        return 3;
    }
    std::string engineStatus;
    const std::string initialEpoch = EngineRequestStatus(&engineStatus)
        ? Epoch(engineStatus) : std::string();
    if (initialEpoch.empty()) {
        std::fputs("collector run: start the same-user engine first\n", stderr);
        return 1;
    }
    const std::string brokerEpoch = RandomId();
    if (brokerEpoch.empty()) return 1;
    const std::wstring label = L"Local\\WinTCP.Collector." + own.sidText +
        L"." + std::to_wstring(own.session);
    HANDLE single = ::CreateMutexW(nullptr, TRUE, label.c_str());
    if (single == nullptr) return 1;
    if (::GetLastError() == ERROR_ALREADY_EXISTS) {
        ::CloseHandle(single);
        return 3;
    }
    // The elevated broker is high integrity, but its paired ordinary engine
    // and CLI are medium integrity. Keep the pipe writable at medium, not low.
    const std::wstring sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;" + own.sidText +
        L")S:(ML;;NW;;;ME)";
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) {
        ::ReleaseMutex(single);
        ::CloseHandle(single);
        return 1;
    }
    SECURITY_ATTRIBUTES security = {sizeof(security), descriptor, FALSE};
    DynamicWfpBackend filters;
    std::string wfpError;
    bool wfpReady = filters.Open(&wfpError);
    RestrictionLeaseController leases(&filters);
    ConnectionEventCollector events;
    std::string eventEpoch = brokerEpoch;
    std::mutex leasesMutex;
    std::mutex eventControlMutex;
    std::atomic<bool> stopping{false};
    bool acceptingRestrictions = true;
    std::thread ticker([&] {
        while (!stopping.load()) {
            {
                std::lock_guard<std::mutex> lock(leasesMutex);
                leases.Sweep(Now());
            }
            ::Sleep(250);
        }
    });
    std::thread heartbeat([&] {
        while (!stopping.load()) {
            std::string status;
            const std::string epoch = EngineRequestStatus(&status)
                ? Epoch(status) : std::string();
            bool paired = false;
            {
                std::lock_guard<std::mutex> lock(leasesMutex);
                if (epoch == initialEpoch) leases.Heartbeat(Now());
                else if (!epoch.empty()) leases.ReleaseAll("engine_epoch_changed", Now());
                paired = leases.HeartbeatCurrent(Now());
            }
            if (!paired) {
                std::lock_guard<std::mutex> lock(eventControlMutex);
                std::string ignored;
                (void)events.Stop(&ignored);
            }
            for (int step = 0; step < 8 && !stopping.load(); ++step)
                ::Sleep(250);
        }
    });
    int result = 0;
    while (!stopping.load()) {
        HANDLE pipe = ::CreateNamedPipeW(PipeName(own).c_str(),
            PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT |
            PIPE_REJECT_REMOTE_CLIENTS, 4, kMaxFrame + 4, kMaxFrame + 4,
            0, &security);
        if (pipe == INVALID_HANDLE_VALUE) { result = 1; break; }
        if (::ConnectNamedPipe(pipe, nullptr) ||
            ::GetLastError() == ERROR_PIPE_CONNECTED) {
            std::string hello;
            if (ReadFrame(pipe, &hello) && hello == std::string("\1\0", 2) &&
                SameClient(pipe, own)) {
                unsigned char raw[kNonceLength] = {};
                const bool random = ::BCryptGenRandom(nullptr, raw,
                    kNonceLength, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
                const std::string nonce(reinterpret_cast<const char*>(raw),
                                        sizeof(raw));
                std::string request;
                if (random && WriteFrame(pipe, nonce) &&
                    ReadFrame(pipe, &request) && request.size() >= 2 + kNonceLength &&
                    request[0] == 1 &&
                    std::memcmp(request.data() + 2, nonce.data(), kNonceLength) == 0) {
                    const std::string payload = request.substr(2 + kNonceLength);
                    if (request[1] == 1 && payload.empty()) {
                        std::lock_guard<std::mutex> lock(leasesMutex);
                        (void)WriteFrame(pipe, "{\"schemaVersion\":1,\"running\":true,\"activeLeases\":" +
                            std::to_string(leases.Active().size()) +
                            ",\"pairedEngineEpoch\":" + JsonQuote(initialEpoch) +
                            ",\"brokerEpoch\":" + JsonQuote(brokerEpoch) +
                            ",\"finalCursor\":" + JsonQuote(acceptingRestrictions ? "" :
                                brokerEpoch + ':' + std::to_string(leases.Changes().empty()
                                    ? 0 : leases.Changes().back().sequence)) +
                            ",\"events\":" + EventStatusJson(events.Status()) +
                            ",\"eventEpoch\":" + JsonQuote(eventEpoch) +
                            ",\"restrictionsAvailable\":" +
                            (wfpReady && acceptingRestrictions && leases.HeartbeatCurrent(Now()) ? "true" : "false") +
                            ",\"restrictionReason\":" + JsonQuote(!acceptingRestrictions ? "collector_stopping" : !wfpReady ? wfpError :
                                leases.HeartbeatCurrent(Now()) ? "" : "engine_not_paired") + "}");
                    } else if (request[1] == 2 && payload.empty()) {
                        stopping.store(true);
                        (void)WriteFrame(pipe, "{\"schemaVersion\":1,\"stopping\":true}");
                    } else if ((request[1] == 3 || request[1] == 4) &&
                               !acceptingRestrictions) {
                        (void)WriteFrame(pipe, ErrorJson("collector_stopping"));
                    } else if (request[1] == 3) {
                        RestrictionPlan plan;
                        std::string error, identity;
                        if (!ParsePreview(payload, own, &plan) ||
                            !ReviewRestrictionTarget(plan, &error, &identity)) {
                            (void)WriteFrame(pipe, ErrorJson(error.empty()
                                ? "invalid_restriction_plan" : error));
                        } else {
                            plan.imageFileIdentity = identity;
                            std::string token;
                            bool approved = false;
                            {
                                std::lock_guard<std::mutex> lock(leasesMutex);
                                for (unsigned attempt = 0; attempt < 3 && !approved;
                                     ++attempt) {
                                    token = RandomId();
                                    if (!token.empty()) approved = leases.Preview(
                                        plan, token, Now(), &error);
                                }
                            }
                            const std::string reply = approved
                                ? "{\"schemaVersion\":1,\"confirmationToken\":" +
                                  JsonQuote(token) + ",\"planHash\":" +
                                  JsonQuote(RestrictionPlanHash(plan)) +
                                  ",\"imagePath\":" + JsonQuote(plan.imagePath) +
                                  ",\"userSid\":" + JsonQuote(plan.userSid) +
                                  ",\"remoteAddress\":" +
                                  JsonQuote(plan.remoteAddress) +
                                  ",\"remotePort\":" +
                                  std::to_string(plan.remotePort) +
                                  ",\"protocol\":" + JsonQuote(
                                      plan.protocol == RestrictionProtocol::Tcp ?
                                      "tcp" : plan.protocol == RestrictionProtocol::Udp ?
                                      "udp" : "both") +
                                  ",\"durationSeconds\":" +
                                  std::to_string(plan.durationSeconds) +
                                  ",\"warning\":\"All current and future matching app instances for this user may be affected; existing flows may continue.\"}"
                                : ErrorJson(error.empty() ? "approval_unavailable" : error);
                            (void)WriteFrame(pipe, reply);
                        }
                    } else if (request[1] == 4) {
                        if (!SafeId(payload)) {
                            (void)WriteFrame(pipe, ErrorJson("invalid_confirmation_token"));
                        } else {
                            const std::string id = RandomId();
                            std::string error;
                            bool applied = false;
                            RestrictionLease lease;
                            {
                                std::lock_guard<std::mutex> lock(leasesMutex);
                                if (!id.empty()) applied = leases.ApplyApproved(payload, id,
                                    "manual", Now(), &error);
                                if (applied) { wfpReady = true; wfpError.clear(); }
                                else if (error.rfind("wfp_", 0) == 0) {
                                    wfpReady = false;
                                    wfpError = error;
                                }
                                if (applied) lease = leases.Active().at(id);
                            }
                            (void)WriteFrame(pipe, applied ?
                                "{\"schemaVersion\":1,\"lease\":" + LeaseJson(lease) + "}" :
                                ErrorJson(error.empty() ? "restriction_apply_failed" : error));
                        }
                    } else if (request[1] == 5 && payload.empty()) {
                        std::string reply = "{\"schemaVersion\":1,\"items\":[";
                        {
                            std::lock_guard<std::mutex> lock(leasesMutex);
                            leases.Sweep(Now());
                            for (const auto& pair : leases.Active()) {
                                if (reply.back() != '[') reply += ',';
                                reply += LeaseJson(pair.second);
                            }
                        }
                        (void)WriteFrame(pipe, reply + "]}");
                    } else if (request[1] == 6 && SafeId(payload)) {
                        std::string error;
                        bool released = false;
                        {
                            std::lock_guard<std::mutex> lock(leasesMutex);
                            released = leases.Release(payload, &error, Now());
                        }
                        (void)WriteFrame(pipe, released
                            ? "{\"schemaVersion\":1,\"released\":true}"
                            : ErrorJson(error));
                    } else if (request[1] == 7 && payload.empty()) {
                        {
                            std::lock_guard<std::mutex> lock(leasesMutex);
                            leases.ReleaseAll("manual_release_all", Now());
                        }
                        (void)WriteFrame(pipe,
                            "{\"schemaVersion\":1,\"releasedAll\":true}");
                    } else if (request[1] == 8 && payload.size() <= 64) {
                        std::string reply;
                        {
                            std::lock_guard<std::mutex> lock(leasesMutex);
                            reply = ChangesWire(leases, brokerEpoch, payload);
                        }
                        (void)WriteFrame(pipe, reply);
                    } else if (request[1] == 9 && payload.empty()) {
                        std::string finalCursor;
                        {
                            std::lock_guard<std::mutex> lock(leasesMutex);
                            acceptingRestrictions = false;
                            leases.ReleaseAll("broker_exit", Now());
                            finalCursor = brokerEpoch + ':' + std::to_string(
                                leases.Changes().empty() ? 0 : leases.Changes().back().sequence);
                        }
                        (void)WriteFrame(pipe, "{\"schemaVersion\":1,\"finalCursor\":" +
                            JsonQuote(finalCursor) + "}");
                    } else if ((request[1] == 10 || request[1] == 11) && payload.empty()) {
                        bool paired = false;
                        {
                            std::lock_guard<std::mutex> lock(leasesMutex);
                            paired = acceptingRestrictions && leases.HeartbeatCurrent(Now());
                        }
                        std::string error;
                        bool ok = false;
                        {
                            std::lock_guard<std::mutex> lock(eventControlMutex);
                            if (request[1] == 11) ok = events.Stop(&error);
                            else if (paired) {
                                const bool wasRunning = events.Status().running;
                                if ((ok = events.Start(&error)) && !wasRunning)
                                    eventEpoch = events.Epoch();
                            }
                            else error = "engine_not_paired";
                        }
                        (void)WriteFrame(pipe, ok
                            ? "{\"schemaVersion\":1,\"events\":" + EventStatusJson(events.Status()) + "}"
                            : ErrorJson(error));
                    } else if (request[1] == 12 && payload.size() <= 64) {
                        (void)WriteFrame(pipe, LifecycleWire(events, eventEpoch, payload));
                    } else {
                        (void)WriteFrame(pipe, ErrorJson("invalid_collector_operation"));
                    }
                }
            }
            (void)::FlushFileBuffers(pipe);
            (void)::DisconnectNamedPipe(pipe);
        }
        ::CloseHandle(pipe);
    }
    stopping.store(true);
    heartbeat.join();
    ticker.join();
    {
        std::lock_guard<std::mutex> lock(eventControlMutex);
        std::string ignored;
        if (!events.Stop(&ignored)) ::TerminateProcess(::GetCurrentProcess(), ERROR_TIMEOUT);
    }
    {
        std::lock_guard<std::mutex> lock(leasesMutex);
        leases.ReleaseAll("broker_exit", Now());
    }
    ::LocalFree(descriptor);
    ::ReleaseMutex(single);
    ::CloseHandle(single);
    return result;
}

}  // namespace

int RunCollectorCommand(int argc, wchar_t** argv) {
    if (argc == 3 && argv[2] != nullptr &&
        (std::wstring(argv[2]) == L"--help" ||
         std::wstring(argv[2]) == L"-h")) {
        std::puts("collector start|run|status|stop|events-start|events-stop: optional elevated helper. Lifecycle tracing starts only with events-start.");
        return 0;
    }
    if (argc != 3 || argv[2] == nullptr) {
        std::fputs("usage: wintcp.exe collector start|run|status|stop|events-start|events-stop\n", stderr);
        return 2;
    }
    const std::wstring action = argv[2];
    if (action == L"run") return Run();
    if (action == L"start") {
        std::string error;
        if (!CollectorStart(&error)) {
            std::fprintf(stderr, "collector start: %s\n", error.c_str());
            return error == "elevation_cancelled" ? 3 : 1;
        }
        std::puts("collector running");
        return 0;
    }
    std::string response;
    if (action == L"events-start" || action == L"events-stop") {
        if (!Request(action == L"events-start" ? 10 : 11, "", &response)) {
            std::fputs("collector unavailable\n", stderr);
            return 1;
        }
        std::puts(response.c_str());
        return response.find("\"code\":") == std::string::npos ? 0 : 3;
    }
    if (action == L"stop") {
        std::string error;
        if (!CollectorStop(&error)) {
            std::fprintf(stderr, "collector stop: %s\n", error.c_str());
            return 1;
        }
        std::puts("collector stopping; final lease outcomes retained");
        return 0;
    }
    if (action == L"status") {
        if (!Request(1, "", &response)) {
            std::fputs("collector unavailable\n", stderr);
            return 1;
        }
        std::puts(response.c_str());
        return 0;
    }
    std::fputs("usage: wintcp.exe collector start|run|status|stop|events-start|events-stop\n", stderr);
    return 2;
}

int RunRestrictCommand(int argc, wchar_t** argv) {
    const char* usage =
        "usage: wintcp.exe restrict preview --app PATH [--peer IP] [--port N] [--proto tcp|udp|both] [--minutes 1..1440]\n"
        "       wintcp.exe restrict apply TOKEN --yes | list | release ID --yes | release-all --yes\n";
    if (argc == 3 && argv[2] != nullptr &&
        (std::wstring(argv[2]) == L"--help" ||
         std::wstring(argv[2]) == L"-h")) {
        std::fputs(usage, stdout);
        return 0;
    }
    if (argc < 3 || argv[2] == nullptr) {
        std::fputs(usage, stderr);
        return 2;
    }
    const std::wstring action = argv[2];
    unsigned char command = 0;
    std::string payload;
    if (action == L"preview") {
        std::string app, peer, protocol = "both";
        unsigned port = 0, minutes = 15;
        bool portSeen = false, minutesSeen = false, protocolSeen = false;
        for (int i = 3; i < argc; i += 2) {
            if (i + 1 >= argc || argv[i] == nullptr || argv[i + 1] == nullptr) {
                std::fputs(usage, stderr);
                return 2;
            }
            const std::wstring key = argv[i];
            const std::wstring value = argv[i + 1];
            const auto utf8 = [](const std::wstring& input) {
                const int bytes = ::WideCharToMultiByte(CP_UTF8,
                    WC_ERR_INVALID_CHARS, input.c_str(),
                    static_cast<int>(input.size()), nullptr, 0, nullptr, nullptr);
                if (bytes <= 0) return std::string();
                std::string result(static_cast<std::size_t>(bytes), '\0');
                return ::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                    input.c_str(), static_cast<int>(input.size()), &result[0],
                    bytes, nullptr, nullptr) == bytes ? result : std::string();
            };
            if (key == L"--app" && app.empty()) app = utf8(value);
            else if (key == L"--peer" && peer.empty()) peer = utf8(value);
            else if (key == L"--port" && !portSeen) {
                portSeen = true;
                if (!ParseUnsigned(utf8(value), 65535, &port)) {
                    std::fputs(usage, stderr); return 2;
                }
            } else if (key == L"--proto" && !protocolSeen) {
                protocolSeen = true;
                protocol = utf8(value);
                if (protocol != "tcp" && protocol != "udp" && protocol != "both") {
                    std::fputs(usage, stderr); return 2;
                }
            } else if (key == L"--minutes" && !minutesSeen) {
                minutesSeen = true;
                if (!ParseUnsigned(utf8(value), 1440, &minutes) || minutes == 0) {
                    std::fputs(usage, stderr); return 2;
                }
            } else { std::fputs(usage, stderr); return 2; }
        }
        if (app.empty() || app.find_first_of("\r\n") != std::string::npos ||
            app.find('\0') != std::string::npos ||
            peer.find_first_of("\r\n") != std::string::npos ||
            peer.find('\0') != std::string::npos ||
            (portSeen && peer.empty())) {
            std::fputs(usage, stderr);
            return 2;
        }
        command = 3;
        payload = app + '\n' + peer + '\n' + std::to_string(port) + '\n' +
            protocol + '\n' + std::to_string(minutes);
    } else if (action == L"apply" || action == L"release") {
        if (argc != 5 || argv[3] == nullptr || argv[4] == nullptr ||
            std::wstring(argv[4]) != L"--yes") {
            std::fputs("confirmation required: pass TOKEN/ID --yes after reviewing the preview or active lease\n", stderr);
            return argc == 4 ? 3 : 2;
        }
        const std::wstring id = argv[3];
        if (id.size() != 32) { std::fputs(usage, stderr); return 2; }
        for (wchar_t c : id) {
            if ((c < L'0' || c > L'9') && (c < L'a' || c > L'f')) {
                std::fputs(usage, stderr); return 2;
            }
            payload.push_back(static_cast<char>(c));
        }
        command = action == L"apply" ? 4 : 6;
    } else if (action == L"list" && argc == 3) {
        command = 5;
    } else if (action == L"release-all") {
        if (argc != 4 || argv[3] == nullptr ||
            std::wstring(argv[3]) != L"--yes") {
            std::fputs("release-all requires --yes\n", stderr);
            return argc == 3 ? 3 : 2;
        }
        command = 7;
    } else { std::fputs(usage, stderr); return 2; }
    std::string response;
    if (!Request(command, payload, &response)) {
        std::fputs("collector unavailable; start the same-user engine and explicitly launch an elevated collector\n", stderr);
        return 1;
    }
    std::puts(response.c_str());
    return response.find("\"code\":") == std::string::npos ? 0 : 3;
}

bool CollectorStatus(std::string* response) {
    return response != nullptr && Request(1, "", response);
}

bool CollectorOperationValid(const std::string& action,
                              const std::string& payload) {
    if (action == "start" || action == "stop" || action == "release-all" ||
        action == "events-start" || action == "events-stop")
        return payload.empty();
    if (action == "apply" || action == "release") return SafeId(payload);
    if (action != "preview") return false;
    Identity own;
    RestrictionPlan plan;
    std::string error;
    return OwnIdentity(&own, nullptr) && ParsePreview(payload, own, &plan) &&
        ValidateRestrictionPlan(plan, &error);
}

bool CollectorExecuteOperation(const std::string& action,
                                const std::string& payload,
                                std::string* result, std::string* error,
                                const std::function<bool()>& cancelled) {
    if (result == nullptr || error == nullptr) return false;
    result->clear();
    error->clear();
    if (cancelled && cancelled()) {
        *error = "operation_cancelled";
        return false;
    }
    if (!CollectorOperationValid(action, payload)) {
        *error = "invalid_collector_operation";
        return false;
    }
    if (action == "start" || action == "stop") {
        const bool ok = action == "start"
            ? (cancelled ? StartCancellable(cancelled, error) : CollectorStart(error))
            : CollectorStop(error);
        if (ok) *result = action == "start" ? "{\"running\":true}" :
                                             "{\"stopping\":true}";
        return ok;
    }
    const unsigned char operation = action == "events-start" ? 10 : action == "events-stop" ? 11 :
        action == "preview" ? 3 :
        action == "apply" ? 4 : action == "release" ? 6 : 7;
    if (!Request(operation, payload, result)) {
        *error = "collector_unavailable";
        return false;
    }
    const std::string marker = "\"code\":\"";
    const auto first = result->find(marker);
    if (first != std::string::npos) {
        const auto start = first + marker.size();
        const auto end = result->find('"', start);
        *error = end == std::string::npos ? "collector_operation_failed" :
            result->substr(start, end - start);
        result->clear();
        return false;
    }
    return true;
}

bool CollectorStop(std::string* error) {
    std::string response;
    if (!Request(9, "", &response)) {
        if (error != nullptr) *error = "collector_unavailable";
        return false;
    }
    const std::string marker = "\"finalCursor\":\"";
    const auto first = response.find(marker);
    const auto start = first == std::string::npos ? first : first + marker.size();
    const auto end = start == std::string::npos ? start : response.find('"', start);
    const std::string cursor = end == std::string::npos ? std::string() :
        response.substr(start, end - start);
    bool audited = false;
    const ULONGLONG deadline = ::GetTickCount64() + 5000;
    while (!cursor.empty() && ::GetTickCount64() < deadline) {
        std::string engine;
        if (!EngineRequestStatus(&engine)) break;
        if (engine.find("\"restrictionAudit\":{\"cursor\":" + JsonQuote(cursor)) !=
            std::string::npos) { audited = true; break; }
        ::Sleep(100);
    }
    // Release is never held hostage to a full/unavailable audit disk.
    if (!Request(2, "", &response)) {
        if (error != nullptr) *error = "collector_stop_not_confirmed";
        return false;
    }
    if (!audited) {
        if (error != nullptr) *error = "collector_stopped_audit_incomplete";
        return false;
    }
    if (error != nullptr) error->clear();
    return true;
}

bool CollectorStart(std::string* error) {
    std::string response, engine;
    if (!EngineRequestStatus(&engine)) {
        if (error != nullptr) *error = "engine_unavailable";
        return false;
    }
    if (CollectorStatus(&response)) {
        if (response.find("\"pairedEngineEpoch\":" + JsonQuote(Epoch(engine))) ==
            std::string::npos) {
            if (error != nullptr) *error = "collector_restart_required";
            return false;
        }
        if (error != nullptr) error->clear();
        return true;
    }
    std::wstring path;
    if (!RuntimeCliPath(&path, error)) return false;
    SHELLEXECUTEINFOW launch = {};
    launch.cbSize = sizeof(launch);
    launch.fMask = SEE_MASK_NOCLOSEPROCESS;
    launch.lpVerb = L"runas";
    launch.lpFile = path.c_str();
    launch.lpParameters = L"collector run";
    launch.nShow = SW_HIDE;
    if (!::ShellExecuteExW(&launch)) {
        if (error != nullptr) *error = ::GetLastError() == ERROR_CANCELLED
            ? "elevation_cancelled" : "collector_launch_failed";
        return false;
    }
    bool ready = false;
    for (unsigned attempt = 0; attempt < 50; ++attempt) {
        if (CollectorStatus(&response)) { ready = true; break; }
        if (launch.hProcess != nullptr &&
            ::WaitForSingleObject(launch.hProcess, 100) != WAIT_TIMEOUT) break;
        if (launch.hProcess == nullptr) ::Sleep(100);
    }
    if (launch.hProcess != nullptr) ::CloseHandle(launch.hProcess);
    if (!ready && error != nullptr)
        *error = "collector_identity_mismatch_or_not_reachable";
    if (ready && error != nullptr) error->clear();
    return ready;
}

bool CollectorRestrictionPreview(const std::string& imagePath,
                                  const std::string& remoteAddress,
                                  unsigned remotePort,
                                  const std::string& protocol,
                                  unsigned minutes,
                                  std::string* response) {
    if (response == nullptr || imagePath.empty() || imagePath.size() > 1024 ||
        imagePath.find_first_of("\r\n") != std::string::npos ||
        imagePath.find('\0') != std::string::npos ||
        remoteAddress.find_first_of("\r\n") != std::string::npos ||
        remoteAddress.find('\0') != std::string::npos ||
        remotePort > 65535 || minutes < 1 || minutes > 1440 ||
        (protocol != "tcp" && protocol != "udp" && protocol != "both"))
        return false;
    return Request(3, imagePath + '\n' + remoteAddress + '\n' +
        std::to_string(remotePort) + '\n' + protocol + '\n' +
        std::to_string(minutes), response);
}

bool CollectorRestrictionApply(const std::string& token,
                                std::string* response) {
    return response != nullptr && SafeId(token) && Request(4, token, response);
}

bool CollectorRestrictionList(std::string* response) {
    return response != nullptr && Request(5, "", response);
}

bool CollectorRestrictionRelease(const std::string& id,
                                  std::string* response) {
    return response != nullptr && SafeId(id) && Request(6, id, response);
}

bool CollectorRestrictionReleaseAll(std::string* response) {
    return response != nullptr && Request(7, "", response);
}

static bool ReadCollectorPage(unsigned char command, const std::string& header,
                               const std::string& cursor, CollectorChangesPage* page) {
    if (page == nullptr || cursor.size() > 64) return false;
    *page = {};
    std::string wire;
    if (!Request(command, cursor, &wire)) return false;
    if (wire == ErrorJson("cursor_expired")) {
        page->cursorExpired = true;
        return true;
    }
    if (wire.rfind(header, 0) != 0) return false;
    const auto first = wire.find('\n', header.size());
    const auto second = first == std::string::npos ? first : wire.find('\n', first + 1);
    if (second == std::string::npos) return false;
    page->nextCursor = wire.substr(header.size(), first - header.size());
    const auto colon = page->nextCursor.find(':');
    std::uint64_t sequence = 0;
    if (colon != 32 || !SafeId(page->nextCursor.substr(0, colon)) ||
        !ParseUint64(page->nextCursor.substr(colon + 1), &sequence) ||
        !ParseUint64(wire.substr(first + 1, second - first - 1), &page->lostRecords))
        return false;
    std::size_t start = second + 1;
    while (start < wire.size()) {
        const auto end = wire.find('\n', start);
        if (end == std::string::npos || end == start || page->items.size() >= 32)
            return false;
        page->items.push_back(wire.substr(start, end - start));
        start = end + 1;
    }
    return true;
}

bool CollectorRestrictionChanges(const std::string& cursor, CollectorChangesPage* page) {
    return ReadCollectorPage(8, "WinTCP-Restriction-Changes:1\n", cursor, page);
}

bool CollectorLifecycleEvents(const std::string& cursor, CollectorChangesPage* page) {
    return ReadCollectorPage(12, "WinTCP-Lifecycle-Events:1\n", cursor, page);
}

}  // namespace wintcp
