// EngineRuntime.cpp
// SPDX-License-Identifier: Apache-2.0
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <windows.h>
#include <bcrypt.h>
#include <sddl.h>
#include <shlobj.h>

#include "EngineRuntime.h"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <limits>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "NetworkEvents.h"
#include "EngineConfig.h"
#include "EngineClock.h"
#include "EngineStore.h"
#include "EngineOperations.h"
#include "CollectorRuntime.h"
#include "RecipeModel.h"
#include "Snapshot.h"
#include "SnapshotEvents.h"
#include "Utils.h"

namespace wintcp {
namespace {

constexpr DWORD kMaxFrame = 256 * 1024;
constexpr DWORD kMaxResponse = 256 * 1024;
constexpr std::size_t kChallengeBytes = 16;
void Print(const std::string& text);

bool RandomBytes(unsigned char* bytes, std::size_t count) {
    return ::BCryptGenRandom(nullptr, bytes, static_cast<ULONG>(count),
                             BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
}

std::string RandomEpoch() {
    unsigned char bytes[kChallengeBytes] = {};
    if (!RandomBytes(bytes, sizeof(bytes))) return {};
    static const char kHex[] = "0123456789abcdef";
    std::string result;
    result.reserve(sizeof(bytes) * 2);
    for (unsigned char byte : bytes) {
        result += kHex[byte >> 4];
        result += kHex[byte & 15];
    }
    return result;
}

bool EnsureDirectory(const std::wstring& path, SECURITY_ATTRIBUTES* security) {
    const DWORD attributes = ::GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        if (::GetLastError() != ERROR_FILE_NOT_FOUND &&
            ::GetLastError() != ERROR_PATH_NOT_FOUND) return false;
        if (!::CreateDirectoryW(path.c_str(), security) &&
            ::GetLastError() != ERROR_ALREADY_EXISTS) return false;
    }
    const DWORD current = ::GetFileAttributesW(path.c_str());
    return current != INVALID_FILE_ATTRIBUTES &&
           (current & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
           (current & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
}

bool LoadEngineConfig(const std::wstring& sid, EngineConfig* config,
                      std::string* error, std::wstring* storageDirectory = nullptr,
                      bool createMissing = true) {
    if (config == nullptr || error == nullptr) return false;
    const std::wstring sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;" + sid + L")";
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) {
        *error = "config_acl_failed";
        return false;
    }
    SECURITY_ATTRIBUTES security = {sizeof(security), descriptor, FALSE};
    PWSTR localAppData = nullptr;
    const HRESULT known = ::SHGetKnownFolderPath(FOLDERID_LocalAppData, 0,
                                                  nullptr, &localAppData);
    if (FAILED(known) || localAppData == nullptr) {
        if (localAppData != nullptr) ::CoTaskMemFree(localAppData);
        ::LocalFree(descriptor);
        *error = "local_app_data_unavailable";
        return false;
    }
    const std::wstring root = std::wstring(localAppData) + L"\\WinTCP";
    ::CoTaskMemFree(localAppData);
    const std::wstring directory = root + L"\\Engine";
    if (!EnsureDirectory(root, &security) ||
        !EnsureDirectory(directory, &security)) {
        ::LocalFree(descriptor);
        *error = "config_directory_unavailable";
        return false;
    }
    const std::wstring path = directory + L"\\config.txt";
    HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                 nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE && ::GetLastError() == ERROR_FILE_NOT_FOUND) {
        if (!createMissing) {
            ::LocalFree(descriptor);
            *error = "config_missing";
            return false;
        }
        const std::string defaults = FormatEngineConfig(*config);
        const std::wstring temporary = directory + L"\\config-" +
            std::to_wstring(::GetCurrentProcessId()) + L"-" +
            std::to_wstring(::GetTickCount64()) + L".tmp";
        HANDLE output = ::CreateFileW(temporary.c_str(), GENERIC_WRITE, 0,
                                      &security, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        DWORD written = 0;
        const bool saved = output != INVALID_HANDLE_VALUE &&
            ::WriteFile(output, defaults.data(), static_cast<DWORD>(defaults.size()),
                        &written, nullptr) &&
            written == static_cast<DWORD>(defaults.size()) &&
            ::FlushFileBuffers(output);
        if (output != INVALID_HANDLE_VALUE) ::CloseHandle(output);
        bool moved = false;
        if (saved) moved = ::MoveFileExW(temporary.c_str(), path.c_str(),
                                         MOVEFILE_WRITE_THROUGH) != FALSE;
        if (!moved) (void)::DeleteFileW(temporary.c_str());
        ::LocalFree(descriptor);
        if (!moved) *error = "config_create_failed";
        else if (storageDirectory != nullptr) *storageDirectory = directory;
        return moved;
    }
    if (file == INVALID_HANDLE_VALUE) {
        ::LocalFree(descriptor);
        *error = "config_open_failed";
        return false;
    }
    LARGE_INTEGER length = {};
    bool ok = ::GetFileSizeEx(file, &length) && length.QuadPart > 0 &&
              length.QuadPart <= 4096;
    std::string bytes;
    if (ok) {
        bytes.resize(static_cast<std::size_t>(length.QuadPart));
        DWORD read = 0;
        ok = ::ReadFile(file, &bytes[0], static_cast<DWORD>(bytes.size()),
                        &read, nullptr) &&
             read == static_cast<DWORD>(bytes.size());
    }
    ::CloseHandle(file);
    ::LocalFree(descriptor);
    if (!ok) {
        *error = "config_read_failed";
        return false;
    }
    if (!ParseEngineConfig(bytes, config, error)) return false;
    if (storageDirectory != nullptr) *storageDirectory = directory;
    return true;
}

bool SaveEngineText(const std::wstring& directory, const std::wstring& stem,
                    const std::string& contents,
                    SECURITY_ATTRIBUTES* security, std::string* error) {
    const std::wstring temporary = directory + L"\\" + stem + L"-" +
        std::to_wstring(::GetCurrentProcessId()) + L"-" +
        std::to_wstring(::GetTickCount64()) + L".tmp";
    const std::wstring path = directory + L"\\" + stem + L".txt";
    HANDLE output = ::CreateFileW(temporary.c_str(), GENERIC_WRITE, 0,
                                   security, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
                                   nullptr);
    DWORD written = 0;
    const bool saved = output != INVALID_HANDLE_VALUE &&
        ::WriteFile(output, contents.data(), static_cast<DWORD>(contents.size()),
                    &written, nullptr) && written == contents.size() &&
        ::FlushFileBuffers(output);
    if (output != INVALID_HANDLE_VALUE) ::CloseHandle(output);
    const bool replaced = saved &&
        ::MoveFileExW(temporary.c_str(), path.c_str(),
                      MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    if (!replaced) {
        (void)::DeleteFileW(temporary.c_str());
        if (error != nullptr) *error = "atomic_save_failed";
    }
    return replaced;
}

bool LoadRecipeCooldowns(const std::wstring& directory, RecipeEvaluator* evaluator,
                         std::uint64_t nowNs, std::uint64_t utcMs, std::string* error) {
    const std::wstring path = directory + L"\\recipe-cooldowns.txt";
    HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        if (::GetLastError() == ERROR_FILE_NOT_FOUND) return true;
        *error = "cooldown_checkpoint_unavailable";
        return false;
    }
    BY_HANDLE_FILE_INFORMATION info = {};
    LARGE_INTEGER size = {};
    bool valid = ::GetFileInformationByHandle(file, &info) &&
        !(info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) &&
        ::GetFileSizeEx(file, &size) && size.QuadPart > 0 && size.QuadPart <= 4 * 1024 * 1024;
    std::string text;
    if (valid) {
        text.resize(static_cast<std::size_t>(size.QuadPart));
        DWORD read = 0;
        valid = ::ReadFile(file, &text[0], static_cast<DWORD>(text.size()), &read, nullptr) &&
            read == text.size();
    }
    ::CloseHandle(file);
    if (!valid) { *error = "cooldown_checkpoint_invalid"; return false; }
    return evaluator->Restore(text, nowNs, utcMs, error);
}

bool SaveEngineConfig(const std::wstring& directory,
                      const EngineConfig& config,
                      SECURITY_ATTRIBUTES* security, std::string* error) {
    if (SaveEngineText(directory, L"config", FormatEngineConfig(config),
                       security, error)) return true;
    if (error != nullptr) *error = "config_save_failed";
    return false;
}

bool LoadRecipeFile(const std::wstring& directory,
                    SECURITY_ATTRIBUTES* security,
                    std::vector<RecipeDef>* recipes, std::string* error,
                    bool createMissing = true) {
    if (recipes == nullptr || error == nullptr) return false;
    const std::wstring path = directory + L"\\recipes.txt";
    const DWORD attributes = ::GetFileAttributesW(path.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES &&
        (attributes & (FILE_ATTRIBUTE_REPARSE_POINT |
                       FILE_ATTRIBUTE_DIRECTORY)) != 0) {
        *error = "recipes_file_invalid";
        return false;
    }
    HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                 nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                                 nullptr);
    if (file == INVALID_HANDLE_VALUE && ::GetLastError() == ERROR_FILE_NOT_FOUND) {
        if (!createMissing) {
            *error = "recipes_missing";
            return false;
        }
        if (!SaveEngineText(directory, L"recipes", "WinTCP-Recipes:1\n",
                            security, error)) return false;
        recipes->clear();
        return true;
    }
    if (file == INVALID_HANDLE_VALUE) {
        *error = "recipes_open_failed";
        return false;
    }
    LARGE_INTEGER length = {};
    bool valid = ::GetFileSizeEx(file, &length) && length.QuadPart >= 17 &&
                 length.QuadPart <= 256 * 1024;
    std::string bytes;
    if (valid) {
        bytes.resize(static_cast<std::size_t>(length.QuadPart));
        DWORD read = 0;
        valid = ::ReadFile(file, &bytes[0], static_cast<DWORD>(bytes.size()),
                           &read, nullptr) && read == bytes.size();
    }
    ::CloseHandle(file);
    if (!valid) {
        *error = "recipes_read_failed";
        return false;
    }
    return ParseRecipes(bytes, recipes, error);
}

bool ValidNotificationId(const std::string& id) {
    constexpr std::size_t kEpochLength = 32;
    const std::string marker = ":notification-";
    if (id.size() <= kEpochLength + marker.size() || id.size() > 80 ||
        id.compare(kEpochLength, marker.size(), marker) != 0) return false;
    for (std::size_t i = 0; i < kEpochLength; ++i)
        if ((id[i] < '0' || id[i] > '9') &&
            (id[i] < 'a' || id[i] > 'f')) return false;
    for (std::size_t i = kEpochLength + marker.size(); i < id.size(); ++i)
        if (id[i] < '0' || id[i] > '9') return false;
    return true;
}

std::string FormatAcks(const std::set<std::string>& ids) {
    std::string result = "WinTCP-Notification-Acks:1\n";
    for (const std::string& id : ids) result += id + '\n';
    return result;
}

bool LoadAcks(const std::wstring& directory, SECURITY_ATTRIBUTES* security,
              std::set<std::string>* ids, std::string* error) {
    if (ids == nullptr || error == nullptr) return false;
    const std::wstring path = directory + L"\\notification-acks.txt";
    const DWORD attributes = ::GetFileAttributesW(path.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES &&
        (attributes & (FILE_ATTRIBUTE_REPARSE_POINT |
                       FILE_ATTRIBUTE_DIRECTORY)) != 0) {
        *error = "acks_file_invalid";
        return false;
    }
    HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                 nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                                 nullptr);
    if (file == INVALID_HANDLE_VALUE && ::GetLastError() == ERROR_FILE_NOT_FOUND) {
        if (!SaveEngineText(directory, L"notification-acks",
                            FormatAcks({}), security, error)) return false;
        ids->clear();
        return true;
    }
    if (file == INVALID_HANDLE_VALUE) { *error = "acks_open_failed"; return false; }
    LARGE_INTEGER length = {};
    bool valid = ::GetFileSizeEx(file, &length) && length.QuadPart >= 27 &&
                 length.QuadPart <= 4 * 1024 * 1024;
    std::string bytes;
    if (valid) {
        bytes.resize(static_cast<std::size_t>(length.QuadPart));
        DWORD read = 0;
        valid = ::ReadFile(file, &bytes[0], static_cast<DWORD>(bytes.size()),
                           &read, nullptr) && read == bytes.size();
    }
    ::CloseHandle(file);
    if (!valid || bytes.rfind("WinTCP-Notification-Acks:1\n", 0) != 0 ||
        bytes.back() != '\n') {
        *error = "acks_read_failed";
        return false;
    }
    std::set<std::string> parsed;
    std::size_t at = std::string("WinTCP-Notification-Acks:1\n").size();
    while (at < bytes.size()) {
        const std::size_t end = bytes.find('\n', at);
        if (end == std::string::npos || parsed.size() >= 50000 ||
            !ValidNotificationId(bytes.substr(at, end - at)) ||
            !parsed.insert(bytes.substr(at, end - at)).second) {
            *error = "acks_record_invalid";
            return false;
        }
        at = end + 1;
    }
    *ids = std::move(parsed);
    error->clear();
    return true;
}

struct Identity {
    std::vector<unsigned char> sid;
    std::wstring sidText;
    DWORD session = 0;
};

bool TokenIdentity(HANDLE token, Identity* out) {
    if (out == nullptr) return false;
    DWORD bytes = 0;
    ::GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
    if (bytes == 0 || bytes > 65536) return false;
    std::vector<unsigned char> data(bytes);
    if (!::GetTokenInformation(token, TokenUser, data.data(), bytes, &bytes))
        return false;
    const TOKEN_USER* user = reinterpret_cast<const TOKEN_USER*>(data.data());
    const DWORD sidBytes = ::GetLengthSid(user->User.Sid);
    if (sidBytes == 0 || sidBytes > SECURITY_MAX_SID_SIZE) return false;
    out->sid.resize(sidBytes);
    if (!::CopySid(sidBytes, out->sid.data(), user->User.Sid)) return false;
    DWORD sessionBytes = sizeof(out->session);
    if (!::GetTokenInformation(token, TokenSessionId, &out->session,
                               sessionBytes, &sessionBytes)) return false;
    LPWSTR sidText = nullptr;
    if (!::ConvertSidToStringSidW(out->sid.data(), &sidText)) return false;
    out->sidText = sidText;
    ::LocalFree(sidText);
    return true;
}

bool OwnIdentity(Identity* out) {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    const bool ok = TokenIdentity(token, out);
    ::CloseHandle(token);
    return ok;
}

std::wstring PipeName(const Identity& identity) {
    return L"\\\\.\\pipe\\WinTCP.Engine." + identity.sidText + L"." +
           std::to_wstring(identity.session);
}

std::wstring MutexName(const Identity& identity) {
    return L"Local\\WinTCP.Engine." + identity.sidText + L"." +
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

bool ReadExact(HANDLE pipe, void* data, DWORD length) {
    unsigned char* at = static_cast<unsigned char*>(data);
    const ULONGLONG deadline = ::GetTickCount64() + 3000;
    while (length != 0) {
        DWORD available = 0;
        if (!::PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr))
            return false;
        if (available == 0) {
            if (::GetTickCount64() >= deadline) return false;
            ::Sleep(10);
            continue;
        }
        DWORD count = 0;
        if (!::ReadFile(pipe, at, (std::min)(length, available), &count, nullptr) ||
            count == 0) return false;
        at += count;
        length -= count;
    }
    return true;
}

bool WriteExact(HANDLE pipe, const void* data, DWORD length) {
    const unsigned char* at = static_cast<const unsigned char*>(data);
    while (length != 0) {
        DWORD count = 0;
        if (!::WriteFile(pipe, at, length, &count, nullptr) || count == 0) return false;
        at += count;
        length -= count;
    }
    return true;
}

bool ReadFrame(HANDLE pipe, std::vector<unsigned char>* payload) {
    DWORD size = 0;
    if (!ReadExact(pipe, &size, sizeof(size)) || size < 2 || size > kMaxFrame)
        return false;
    payload->resize(size);
    return ReadExact(pipe, payload->data(), size);
}

bool WriteFrame(HANDLE pipe, const std::string& payload) {
    if (payload.size() > kMaxResponse) return false;
    const DWORD size = static_cast<DWORD>(payload.size());
    return WriteExact(pipe, &size, sizeof(size)) &&
           WriteExact(pipe, payload.data(), size);
}

struct ClockSample {
    std::string utc;
    std::uint64_t utcMs = 0;
    std::uint64_t monotonicMs = 0;
};

ClockSample SampleClock() {
    FILETIME fileTime = {};
    ::GetSystemTimeAsFileTime(&fileTime);
    ClockSample sample;
    sample.monotonicMs = ::GetTickCount64();
    const std::uint64_t ticks =
        (static_cast<std::uint64_t>(fileTime.dwHighDateTime) << 32) |
        fileTime.dwLowDateTime;
    constexpr std::uint64_t kUnixEpochFileTimeTicks = 116444736000000000ULL;
    sample.utcMs = ticks >= kUnixEpochFileTimeTicks
        ? (ticks - kUnixEpochFileTimeTicks) / 10000ULL : 0;
    SYSTEMTIME now = {};
    if (!::FileTimeToSystemTime(&fileTime, &now)) ::GetSystemTime(&now);
    char buffer[40] = {};
    std::snprintf(buffer, sizeof(buffer), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
                  now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute,
                  now.wSecond, now.wMilliseconds);
    sample.utc = buffer;
    return sample;
}

struct State {
    std::mutex mutex;
    std::mutex historyMutex;
    std::mutex recipesMutex;
    NetworkEventJournal journal{16384, 64 * 1024 * 1024};
    EngineStore eventStore;
    EngineStore notificationStore;
    EngineStore auditStore;
    EngineStore lifecycleStore;
    std::set<std::string> acknowledgedNotifications;
    std::vector<RecipeDef> recipes;
    RecipeEvaluator recipeEvaluator;
    bool recipeCooldownDirty = false;  // protected by recipesMutex
    std::string lastSampleUtc;
    std::string sampleError;
    std::string storageError;
    std::uint64_t sampleCount = 0;
    std::uint64_t failedSamples = 0;
    std::uint64_t persistedEvents = 0;
    std::uint64_t storageLost = 0;
    std::uint64_t storageRollovers = 0;
    std::uint64_t notificationSequence = 0;
    std::uint64_t notificationsWritten = 0;
    std::uint64_t notificationsLost = 0;
    std::string notificationError;
    std::string clockMappingId;
    std::uint64_t clockChanges = 0;
    std::int64_t lastClockAdjustmentMs = 0;
    std::uint64_t clockAnchorUtcMs = 0;
    std::uint64_t clockAnchorMonotonicMs = 0;
    HANDLE stopEvent = nullptr;
    std::string epoch;
    EngineConfig config;
    std::mutex operationsMutex;
    std::condition_variable operationsReady;
    EngineOperations operations;
    bool collectorConnected = false;
    bool restrictionsAvailable = false;
    std::string collectorReason = "collector_not_connected";
    std::string collectorLastSampleUtc;
    std::uint64_t restrictionAuditLost = 0;
    std::string restrictionAuditError;
    std::string restrictionAuditCursor;
    bool lifecycleEnabled = false;
    bool lifecycleNeedsDrain = false;
    std::uint64_t lifecyclePersisted = 0;
    std::uint64_t lifecycleLost = 0;
    std::string lifecycleError;
};

bool SafeId(const std::string& id, std::size_t maxLength) {
    if (id.empty() || id.size() > maxLength) return false;
    for (char c : id) {
        if ((c < 'a' || c > 'z') && (c < 'A' || c > 'Z') &&
            (c < '0' || c > '9') && c != '-' && c != '_') return false;
    }
    return true;
}

bool RevisionSyntax(const std::string& revision) {
    if (revision.size() != 64) return false;
    for (char c : revision)
        if ((c < '0' || c > '9') && (c < 'a' || c > 'f')) return false;
    return true;
}

std::string ConfigJson(const EngineConfig& config,
                       const EngineConfig& active) {
    return "{\"schemaVersion\":1,\"revision\":\"" +
        EngineConfigRevision(config) + "\",\"snapshotIntervalMs\":" +
        std::to_string(config.snapshotIntervalMs) +
        ",\"maxEventRecords\":" + std::to_string(config.maxEventRecords) +
        ",\"maxEventBytes\":" + std::to_string(config.maxEventBytes) +
        ",\"activeSnapshotIntervalMs\":" +
        std::to_string(active.snapshotIntervalMs) +
        ",\"restartRequired\":" +
        (FormatEngineConfig(config) == FormatEngineConfig(active) ? "false" : "true") +
        "}";
}

std::string RecipesJson(const std::vector<RecipeDef>& recipes) {
    std::string result = "{\"schemaVersion\":1,\"revision\":\"" +
        RecipesRevision(recipes) + "\",\"items\":[";
    for (const RecipeDef& recipe : recipes) {
        if (result.back() != '[') result += ',';
        result += RecipeJson(recipe);
    }
    return result + "]}";
}

std::string OperationJson(const EngineOperation& operation) {
    return "{\"schemaVersion\":1,\"operationId\":\"" + operation.id +
        "\",\"status\":\"" + operation.status +
        "\",\"result\":" +
        (!operation.resultJson.empty() ? operation.resultJson :
         operation.resultRevision.empty() ? "null" :
            "{\"revision\":\"" + operation.resultRevision +
            "\",\"restartRequired\":" +
            (operation.restartRequired ? "true" : "false") + "}") +
        ",\"error\":" + (operation.error.empty() ? "null" :
            "{\"code\":" + NetworkJsonQuote(operation.error) + "}") +
        ",\"audit\":" + (operation.kind.rfind("collector.", 0) != 0 ? "null" :
            "{\"recorded\":" + std::string(operation.auditRecorded ? "true" : "false") +
            ",\"error\":" + (operation.auditError.empty() ? "null" :
                NetworkJsonQuote(operation.auditError)) + "}") + "}";
}

std::string SubmitConfig(State* state, const std::string& payload,
                         const std::wstring& sid, bool* created) {
    if (created != nullptr) *created = false;
    const std::size_t first = payload.find('\n');
    const std::size_t second = first == std::string::npos ? first :
        payload.find('\n', first + 1);
    if (second == std::string::npos || payload.size() > 4300)
        return "{\"schemaVersion\":1,\"code\":\"bad_request\"}";
    const std::string requestId = payload.substr(0, first);
    const std::string expected = payload.substr(first + 1, second - first - 1);
    const std::string configText = payload.substr(second + 1);
    EngineConfig next;
    std::string error;
    if (!SafeId(requestId, 64) || !RevisionSyntax(expected) ||
        !ParseEngineConfig(configText, &next, &error))
        return "{\"schemaVersion\":1,\"code\":\"bad_request\"}";
    const std::uint64_t now = ::GetTickCount64();
    OperationSubmission existing;
    {
        std::lock_guard<std::mutex> lock(state->operationsMutex);
        existing = state->operations.Existing(requestId, expected,
                                               configText, now);
    }
    if (existing.disposition == OperationDisposition::Reused)
        return "{\"schemaVersion\":1,\"code\":\"request_id_reused\"}";
    if (existing.disposition == OperationDisposition::Duplicate)
        return "{\"schemaVersion\":1,\"operationId\":\"" +
            existing.id + "\",\"status\":\"" + existing.status + "\"}";
    EngineConfig current;
    if (!LoadEngineConfig(sid, &current, &error, nullptr, false))
        return "{\"schemaVersion\":1,\"code\":\"config_unavailable\"}";
    if (EngineConfigRevision(current) != expected)
        return "{\"schemaVersion\":1,\"code\":\"revision_conflict\"}";
    OperationSubmission submitted;
    {
        std::lock_guard<std::mutex> lock(state->operationsMutex);
        submitted = state->operations.Submit(requestId, expected,
                                              configText, now);
    }
    if (submitted.disposition == OperationDisposition::Full)
        return "{\"schemaVersion\":1,\"code\":\"operation_queue_full\"}";
    if (created != nullptr) *created =
        submitted.disposition == OperationDisposition::Created;
    if (submitted.disposition == OperationDisposition::Created)
        state->operationsReady.notify_all();
    return "{\"schemaVersion\":1,\"operationId\":\"" +
        submitted.id + "\",\"status\":\"queued\"}";
}

std::string SubmitRecipes(State* state, const std::string& payload,
                          const std::wstring& directory, bool* created) {
    if (created != nullptr) *created = false;
    const std::size_t first = payload.find('\n');
    const std::size_t second = first == std::string::npos ? first :
        payload.find('\n', first + 1);
    if (second == std::string::npos || payload.size() > 256 * 1024 - 128)
        return "{\"schemaVersion\":1,\"code\":\"bad_request\"}";
    const std::string requestId = payload.substr(0, first);
    const std::string expected = payload.substr(first + 1, second - first - 1);
    const std::string recipeText = payload.substr(second + 1);
    std::vector<RecipeDef> next;
    std::string error;
    if (!SafeId(requestId, 64) || !RevisionSyntax(expected) ||
        !ParseRecipes(recipeText, &next, &error))
        return "{\"schemaVersion\":1,\"code\":\"bad_request\"}";
    const std::uint64_t now = ::GetTickCount64();
    OperationSubmission existing;
    {
        std::lock_guard<std::mutex> lock(state->operationsMutex);
        existing = state->operations.Existing(requestId, expected,
                                               recipeText, now, "recipes");
    }
    if (existing.disposition == OperationDisposition::Reused)
        return "{\"schemaVersion\":1,\"code\":\"request_id_reused\"}";
    if (existing.disposition == OperationDisposition::Duplicate)
        return "{\"schemaVersion\":1,\"operationId\":\"" +
            existing.id + "\",\"status\":\"" + existing.status + "\"}";
    std::vector<RecipeDef> current;
    if (!LoadRecipeFile(directory, nullptr, &current, &error, false))
        return "{\"schemaVersion\":1,\"code\":\"recipes_unavailable\"}";
    if (RecipesRevision(current) != expected)
        return "{\"schemaVersion\":1,\"code\":\"revision_conflict\"}";
    if (!ValidateRecipeUpdate(current, next, &error))
        return "{\"schemaVersion\":1,\"code\":\"" + error + "\"}";
    OperationSubmission submitted;
    {
        std::lock_guard<std::mutex> lock(state->operationsMutex);
        submitted = state->operations.Submit(requestId, expected,
                                              recipeText, now, "recipes");
    }
    if (submitted.disposition == OperationDisposition::Full)
        return "{\"schemaVersion\":1,\"code\":\"operation_queue_full\"}";
    if (created != nullptr) *created =
        submitted.disposition == OperationDisposition::Created;
    if (submitted.disposition == OperationDisposition::Created)
        state->operationsReady.notify_all();
    return "{\"schemaVersion\":1,\"operationId\":\"" +
        submitted.id + "\",\"status\":\"queued\"}";
}

std::string SubmitRecipeMutation(State* state, const std::string& payload,
                                 const std::wstring& directory) {
    const std::size_t first = payload.find('\n');
    const std::size_t second = first == std::string::npos ? first :
        payload.find('\n', first + 1);
    const std::size_t third = second == std::string::npos ? second :
        payload.find('\n', second + 1);
    if (third == std::string::npos || payload.size() > 5000)
        return "{\"schemaVersion\":1,\"code\":\"bad_request\"}";
    const std::string requestId = payload.substr(0, first);
    const std::string expected = payload.substr(first + 1, second - first - 1);
    const std::string action = payload.substr(second + 1, third - second - 1);
    const std::string value = payload.substr(third + 1);
    if (!SafeId(requestId, 64) || !RevisionSyntax(expected))
        return "{\"schemaVersion\":1,\"code\":\"bad_request\"}";
    std::vector<RecipeDef> current;
    std::string error;
    if (!LoadRecipeFile(directory, nullptr, &current, &error, false))
        return "{\"schemaVersion\":1,\"code\":\"recipes_unavailable\"}";
    if (RecipesRevision(current) != expected)
        return "{\"schemaVersion\":1,\"code\":\"revision_conflict\"}";
    std::vector<RecipeDef> next;
    if (!ApplyRecipeChange(current, action, value, &next, &error))
        return "{\"schemaVersion\":1,\"code\":\"" + error + "\"}";
    return SubmitRecipes(state, requestId + '\n' + expected + '\n' +
                         FormatRecipes(next), directory, nullptr);
}

std::string SubmitAcknowledgement(State* state, const std::string& payload) {
    const std::size_t split = payload.find('\n');
    if (split == std::string::npos || payload.find('\n', split + 1) !=
        std::string::npos)
        return "{\"schemaVersion\":1,\"code\":\"bad_request\"}";
    const std::string requestId = payload.substr(0, split);
    const std::string notificationId = payload.substr(split + 1);
    if (!SafeId(requestId, 64) || !ValidNotificationId(notificationId))
        return "{\"schemaVersion\":1,\"code\":\"bad_request\"}";
    const std::uint64_t now = ::GetTickCount64();
    OperationSubmission submitted;
    {
        std::lock_guard<std::mutex> lock(state->operationsMutex);
        submitted = state->operations.Submit(requestId, "", notificationId,
                                              now, "ack");
    }
    if (submitted.disposition == OperationDisposition::Reused)
        return "{\"schemaVersion\":1,\"code\":\"request_id_reused\"}";
    if (submitted.disposition == OperationDisposition::Full)
        return "{\"schemaVersion\":1,\"code\":\"operation_queue_full\"}";
    if (submitted.disposition == OperationDisposition::Created)
        state->operationsReady.notify_all();
    return "{\"schemaVersion\":1,\"operationId\":\"" +
        submitted.id + "\",\"status\":\"" + submitted.status + "\"}";
}

std::string SubmitCollector(State* state, const std::string& payload) {
    const auto first = payload.find('\n');
    const auto second = first == std::string::npos ? first : payload.find('\n', first + 1);
    if (second == std::string::npos || payload.size() > 2400)
        return "{\"schemaVersion\":1,\"code\":\"bad_request\"}";
    const std::string requestId = payload.substr(0, first);
    const std::string action = payload.substr(first + 1, second - first - 1);
    const std::string body = payload.substr(second + 1);
    if (!SafeId(requestId, 64) || !CollectorOperationValid(action, body))
        return "{\"schemaVersion\":1,\"code\":\"bad_request\"}";
    OperationSubmission submitted;
    {
        std::lock_guard<std::mutex> lock(state->operationsMutex);
        submitted = state->operations.Submit(requestId, "", body,
            ::GetTickCount64(), "collector." + action);
    }
    if (submitted.disposition == OperationDisposition::Reused)
        return "{\"schemaVersion\":1,\"code\":\"request_id_reused\"}";
    if (submitted.disposition == OperationDisposition::Full)
        return "{\"schemaVersion\":1,\"code\":\"operation_queue_full\"}";
    state->operationsReady.notify_all();
    return "{\"schemaVersion\":1,\"operationId\":\"" + submitted.id +
        "\",\"status\":\"" + submitted.status + "\"}";
}

bool RetainedNotificationIds(State* state, std::set<std::string>* ids) {
    ids->clear();
    std::string cursor;
    for (unsigned pageNumber = 0; pageNumber < 500; ++pageNumber) {
        const EngineStorePage page = state->notificationStore.Read(cursor, 500, 220000);
        if (page.cursorExpired || !page.error.empty()) return false;
        for (const std::string& item : page.items) {
            const std::string prefix = "{\"schemaVersion\":1,\"id\":\"";
            if (item.rfind(prefix, 0) != 0) return false;
            const std::size_t end = item.find('"', prefix.size());
            if (end == std::string::npos) return false;
            const std::string id = item.substr(prefix.size(), end - prefix.size());
            if (!ValidNotificationId(id)) return false;
            ids->insert(id);
            if (ids->size() > 50000) return false;
        }
        if (page.nextCursor == cursor || page.items.empty()) return true;
        cursor = page.nextCursor;
    }
    return false;
}

bool AuditCollectorCommand(State* state, const std::string& id,
                            const std::string& action, const std::string& phase,
                            const std::string& outcome, const std::string& result,
                            std::string* error) {
    const ClockSample clock = SampleClock();
    const std::string record = "{\"schemaVersion\":1,\"id\":" +
        NetworkJsonQuote(id + ':' + phase) +
        ",\"kind\":\"collector_command\",\"source\":\"monitor_engine\",\"operationId\":" +
        NetworkJsonQuote(id) + ",\"action\":" + NetworkJsonQuote(action) +
        ",\"state\":" + NetworkJsonQuote(phase) + ",\"reason\":" +
        NetworkJsonQuote(outcome) + ",\"occurredAtUtc\":" + NetworkJsonQuote(clock.utc) +
        ",\"result\":" + (result.empty() ? "null" : result) + "}";
    std::size_t written = 0;
    std::lock_guard<std::mutex> lock(state->historyMutex);
    return state->auditStore.Append({record}, &written, error) && written == 1;
}

void OperationLoop(State* state, const std::wstring& sid,
                   const std::wstring& directory,
                   SECURITY_ATTRIBUTES* security,
                   EngineOperationQueue queue) {
    for (;;) {
        std::string id;
        std::string expectedRevision;
        std::string configText;
        std::string kind;
        {
            std::unique_lock<std::mutex> lock(state->operationsMutex);
            state->operationsReady.wait(lock, [state, queue] {
                return state->operations.HasQueued(queue) ||
                    ::WaitForSingleObject(state->stopEvent, 0) != WAIT_TIMEOUT;
            });
            if (::WaitForSingleObject(state->stopEvent, 0) != WAIT_TIMEOUT) return;
            EngineOperation* operation = state->operations.TakeNextQueued(queue);
            if (operation == nullptr) return;
            id = operation->id;
            expectedRevision = operation->expectedRevision;
            configText = operation->configText;
            kind = operation->kind;
        }
        EngineConfig current;
        EngineConfig next;
        std::string error;
        std::string resultRevision;
        std::string resultJson;
        std::string auditError;
        bool auditRecorded = false;
        bool restartRequired = false;
        if (kind.rfind("collector.", 0) == 0) {
            const std::string action = kind.substr(10);
            const bool requested = AuditCollectorCommand(state, id, action,
                "requested", "queued_command", "", &auditError);
            const bool release = action == "stop" || action == "release" ||
                action == "release-all" || action == "events-stop";
            if (!requested && !release) error = "audit_unavailable";
            else (void)CollectorExecuteOperation(action, configText,
                    &resultJson, &error, [state] {
                        return ::WaitForSingleObject(state->stopEvent, 0) != WAIT_TIMEOUT;
                    });
            std::string completedError;
            // Never persist approval bearer tokens returned by preview.
            const bool completed = AuditCollectorCommand(state, id, action,
                error.empty() ? "succeeded" : "failed", error.empty() ? "completed" : error,
                action == "preview" ? "" : resultJson, &completedError);
            auditRecorded = requested && completed;
            if (!completedError.empty()) auditError = completedError;
            if (!auditRecorded && auditError.empty()) auditError = "audit_write_incomplete";
            if (error.empty() && (action == "events-start" || action == "events-stop")) {
                std::lock_guard<std::mutex> lock(state->mutex);
                state->lifecycleNeedsDrain = true;
            }
        } else if (kind == "ack") {
            std::lock_guard<std::mutex> historyLock(state->historyMutex);
            std::set<std::string> retained;
            if (!RetainedNotificationIds(state, &retained)) {
                error = "inbox_unavailable";
            } else if (retained.find(configText) == retained.end()) {
                error = "notification_not_found";
            } else {
                std::set<std::string> nextAcks;
                for (const std::string& ackId : state->acknowledgedNotifications)
                    if (retained.find(ackId) != retained.end())
                        nextAcks.insert(ackId);
                nextAcks.insert(configText);
                if (nextAcks.size() > 50000 ||
                    FormatAcks(nextAcks).size() > 4 * 1024 * 1024) {
                    error = "ack_capacity_exceeded";
                } else if (!SaveEngineText(directory, L"notification-acks",
                                           FormatAcks(nextAcks), security, &error)) {
                    error = "ack_save_failed";
                } else {
                    state->acknowledgedNotifications = std::move(nextAcks);
                }
            }
        } else if (kind == "recipes") {
            std::vector<RecipeDef> before, after;
            if (!LoadRecipeFile(directory, security, &before, &error, false)) {
                error = "recipes_unavailable";
            } else if (RecipesRevision(before) != expectedRevision) {
                error = "revision_conflict";
            } else if (!ParseRecipes(configText, &after, &error)) {
                error = "invalid_recipes";
            } else if (!ValidateRecipeUpdate(before, after, &error)) {
                // The worker revalidates the complete transition before save.
            } else if (!SaveEngineText(directory, L"recipes", configText,
                                       security, &error)) {
                error = "recipes_save_failed";
            } else {
                resultRevision = RecipesRevision(after);
                std::lock_guard<std::mutex> lock(state->recipesMutex);
                state->recipeEvaluator.Reconcile(after);
                state->recipes = std::move(after);
                state->recipeCooldownDirty = true;
            }
        } else if (!LoadEngineConfig(sid, &current, &error, nullptr, false)) {
            error = "config_unavailable";
        } else if (EngineConfigRevision(current) != expectedRevision) {
            error = "revision_conflict";
        } else if (!ParseEngineConfig(configText, &next, &error)) {
            error = "invalid_config";
        } else if (!SaveEngineConfig(directory, next, security, &error)) {
            // SaveEngineConfig writes a stable error code.
        } else {
            resultRevision = EngineConfigRevision(next);
            restartRequired =
                FormatEngineConfig(next) != FormatEngineConfig(state->config);
        }
        {
            std::lock_guard<std::mutex> lock(state->operationsMutex);
            EngineOperation* operation = state->operations.FindMutable(
                id, ::GetTickCount64());
            if (operation != nullptr) {
                operation->resultRevision = resultRevision;
                operation->resultJson = resultJson;
                operation->auditRecorded = auditRecorded;
                operation->auditError = auditError;
                operation->restartRequired = restartRequired;
                operation->error = error;
                operation->status = error.empty() ? "succeeded" : "failed";
                operation->completedAtMs = ::GetTickCount64();
            }
        }
    }
}

void SampleLoop(State* state, const std::wstring& directory, SECURITY_ATTRIBUTES* security) {
    SnapshotSource source;
    SnapshotEventAdapter adapter(state->epoch);
    EngineClock clock(state->epoch);
    SnapshotOptions options;
    options.resolveProcesses = true;
    while (::WaitForSingleObject(state->stopEvent, 0) == WAIT_TIMEOUT) {
        Snapshot snapshot;
        const bool success = source.Build(options, &snapshot);
        const ClockSample sampled = SampleClock();
        const ClockObservation mapping = clock.Observe(sampled.utcMs,
                                                        sampled.monotonicMs);
        const std::string& utc = sampled.utc;
        const std::uint64_t monoNs = sampled.monotonicMs * 1000000ULL;
        std::vector<NetworkEvent> events;
        if (success) events = adapter.Observe(snapshot.rows, utc, monoNs);
        const bool limitGap = success && events.size() == 1 &&
            events[0].kind == NetworkEventKind::CoverageGap;
        if (mapping.changed) {
            NetworkEvent changed;
            changed.eventId = state->epoch + ":clock-" +
                std::to_string(mapping.changes + 1);
            changed.sourceSequence = std::to_string(mapping.changes);
            changed.source = "engine_clock";
            changed.kind = NetworkEventKind::CoverageGap;
            changed.occurredAtUtc = utc;
            changed.receivedAtUtc = utc;
            changed.monotonicNs = monoNs;
            changed.timebaseId = mapping.mappingId;
            changed.lossReason = "clock_adjusted";
            changed.confidence = "observed";
            events.push_back(std::move(changed));
        }
        std::vector<std::string> persistentLines;
        if (!success) {
            NetworkEvent gap;
            gap.eventId = state->epoch + ":sample-gap-" +
                std::to_string(++state->failedSamples);
            gap.source = "snapshot";
            gap.kind = NetworkEventKind::CoverageGap;
            gap.occurredAtUtc = utc;
            gap.receivedAtUtc = utc;
            gap.monotonicNs = monoNs;
            gap.lossReason = "snapshot_failed";
            gap.lostRecords = 1;
            gap.confidence = "observed";
            events.push_back(std::move(gap));
        }
        persistentLines.reserve(events.size());
        for (NetworkEvent& event : events) {
            event.timebaseId = mapping.mappingId;
            persistentLines.push_back(NetworkEventJson(event));
        }
        std::vector<std::string> notices;
        std::string cooldownCheckpoint;
        {
            std::lock_guard<std::mutex> recipeLock(state->recipesMutex);
            for (const NetworkEvent& event : events) {
                for (const RecipeDef& recipe : state->recipes) {
                    const RecipeHit hit = state->recipeEvaluator.Evaluate(recipe,
                                                                           event);
                    if (hit.matched) state->recipeCooldownDirty = true;
                    if (!hit.fire) continue;
                    const std::string id = state->epoch + ":notification-" +
                        std::to_string(++state->notificationSequence);
                    notices.push_back(RecipeNotificationJson(recipe, event,
                                                               hit, id));
                }
            }
            if (state->recipeCooldownDirty) {
                cooldownCheckpoint = state->recipeEvaluator.Checkpoint(monoNs, sampled.utcMs);
                state->recipeCooldownDirty = false;
            }
        }
        std::size_t written = 0;
        std::size_t noticesWritten = 0;
        std::string storeError;
        std::string noticeError;
        std::string cooldownError;
        if (!cooldownCheckpoint.empty() &&
            !SaveEngineText(directory, L"recipe-cooldowns", cooldownCheckpoint,
                            security, &cooldownError))
            cooldownError = "cooldown_checkpoint_save_failed";
        if (!cooldownError.empty()) {
            std::lock_guard<std::mutex> recipeLock(state->recipesMutex);
            state->recipeCooldownDirty = true;
        }
        bool saved = false;
        bool noticesSaved = false;
        std::uint64_t rollovers = 0;
        {
            std::lock_guard<std::mutex> historyLock(state->historyMutex);
            saved = state->eventStore.Append(persistentLines, &written,
                                             &storeError);
            noticesSaved = state->notificationStore.Append(notices,
                                                           &noticesWritten,
                                                           &noticeError);
            rollovers = state->eventStore.Rollovers();
        }
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            if (saved) state->persistedEvents += written;
            else {
                state->storageLost += persistentLines.size() -
                    (storeError == "store_flush_failed" ? 0 : written);
                state->storageError = storeError;
            }
            state->storageRollovers = rollovers;
            if (noticesSaved) state->notificationsWritten += noticesWritten;
            else {
                state->notificationsLost += notices.size() - noticesWritten;
                state->notificationError = noticeError;
            }
            if (!cooldownError.empty()) state->notificationError = cooldownError;
            state->clockMappingId = mapping.mappingId;
            state->clockChanges = mapping.changes;
            state->clockAnchorUtcMs = mapping.anchorUtcMs;
            state->clockAnchorMonotonicMs = mapping.anchorMonotonicMs;
            if (mapping.changed)
                state->lastClockAdjustmentMs = mapping.adjustmentMs;
            if (success) {
                for (NetworkEvent& event : events) state->journal.Append(std::move(event));
                state->lastSampleUtc = utc;
                state->sampleError = limitGap ? "flow_limit_exceeded" : "";
                ++state->sampleCount;
            } else {
                // Keep the previous baseline: a failed pass is not an endpoint close.
                state->sampleError = "snapshot_failed";
                for (NetworkEvent& event : events)
                    state->journal.Append(std::move(event));
            }
        }
        if (::WaitForSingleObject(state->stopEvent,
                                  state->config.snapshotIntervalMs) != WAIT_TIMEOUT) break;
    }
}

std::string LoadCollectorCursor(const std::wstring& directory, std::string* error,
                                 bool lifecycle = false) {
    const std::wstring path = directory + (lifecycle ? L"\\lifecycle-cursor.txt" :
                                                       L"\\restriction-cursor.txt");
    HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        if (::GetLastError() != ERROR_FILE_NOT_FOUND) *error = "restriction_cursor_unavailable";
        return {};
    }
    BY_HANDLE_FILE_INFORMATION info = {};
    char bytes[128] = {};
    DWORD read = 0;
    const bool valid = ::GetFileInformationByHandle(file, &info) &&
        !(info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) &&
        info.nFileSizeHigh == 0 && info.nFileSizeLow < sizeof(bytes) &&
        ::ReadFile(file, bytes, info.nFileSizeLow, &read, nullptr) && read == info.nFileSizeLow;
    ::CloseHandle(file);
    const std::string text(bytes, read);
    const std::string header = lifecycle ? "WinTCP-Lifecycle-Cursor:1\n" :
                                           "WinTCP-Restriction-Cursor:1\n";
    if (!valid || text.size() < header.size() + 1 ||
        text.rfind(header, 0) != 0 || text.back() != '\n') {
        *error = "restriction_cursor_invalid";
        return {};
    }
    const std::string cursor = text.substr(header.size(), text.size() - header.size() - 1);
    const auto colon = cursor.find(':');
    if (!cursor.empty() && (colon != 32 || !SafeId(cursor.substr(0, colon), 32) ||
        cursor.size() > 64 || cursor.size() <= colon + 1 ||
        cursor.substr(colon + 1).find_first_not_of("0123456789") != std::string::npos)) {
        *error = "restriction_cursor_invalid";
        return {};
    }
    return cursor;
}

std::string QuotedStatusField(const std::string& json, const char* field) {
    const std::string marker = "\"" + std::string(field) + "\":\"";
    const auto first = json.find(marker);
    if (first == std::string::npos) return {};
    const auto start = first + marker.size();
    const auto end = json.find('"', start);
    return end == std::string::npos || end - start > 64 ? std::string() :
        json.substr(start, end - start);
}

void CollectorProbe(State* state, const std::wstring& directory,
                     SECURITY_ATTRIBUTES* security) {
    std::uint64_t lastSeen = 0;
    std::string checkpointError;
    std::string cursor = LoadCollectorCursor(directory, &checkpointError);
    bool cursorDirty = false;
    bool gapReported = false;
    bool gracefulAuditComplete = false;
    std::string observedEventEpoch, observedDecodedCount, observedPublishedCount;
    std::uint64_t gapSequence = 0;
    while (::WaitForSingleObject(state->stopEvent, 0) == WAIT_TIMEOUT) {
        std::string status;
        const bool connected = CollectorStatus(&status);
        const ClockSample clock = SampleClock();
        std::vector<std::string> audit;
        std::string nextCursor = cursor;
        std::uint64_t lost = 0;
        bool readFailed = false;
        bool moreChanges = false;
        const auto gap = [&](const char* reason, std::uint64_t count,
                             const char* kind = "coverage_gap") {
            return "{\"schemaVersion\":1,\"id\":\"" + state->epoch +
                ":restriction-gap-" + std::to_string(++gapSequence) +
                "\",\"kind\":" + NetworkJsonQuote(kind) +
                ",\"source\":\"restriction_audit\",\"reason\":\"" +
                reason + "\",\"occurredAtUtc\":\"" + clock.utc +
                "\",\"lostRecords\":\"" + std::to_string(count) + "\"}";
        };
        if (!checkpointError.empty()) audit.push_back(gap("audit_checkpoint_unavailable", 0));
        if (connected && !cursorDirty) {
            gapReported = false;
            CollectorChangesPage changes;
            if (CollectorRestrictionChanges(cursor, &changes)) {
                if (changes.cursorExpired) {
                    audit.push_back(gap("broker_epoch_changed", 0));
                    nextCursor.clear();
                } else {
                    moreChanges = changes.items.size() == 32;
                    lost = changes.lostRecords;
                    if (lost != 0) audit.push_back(gap("broker_journal_evicted", lost));
                    audit.insert(audit.end(), changes.items.begin(), changes.items.end());
                    nextCursor = changes.nextCursor;
                }
            } else readFailed = true;
        } else if (lastSeen != 0 && !gapReported && clock.monotonicMs >= lastSeen &&
                   clock.monotonicMs - lastSeen >= 3000) {
            audit.push_back(gracefulAuditComplete
                ? gap("broker_stopped_after_final_drain", 0, "collector_session_ended")
                : gap("broker_unreachable_outcome_unknown", 0));
        }
        std::string auditError;
        bool checkpointAttempted = false;
        std::size_t written = 0;
        if (!audit.empty()) {
            std::lock_guard<std::mutex> lock(state->historyMutex);
            if (state->auditStore.Append(audit, &written, &auditError) &&
                written == audit.size()) {
                cursor = nextCursor;
                cursorDirty = true;
                checkpointError.clear();
                if (!connected) gapReported = true;
            } else if (auditError.empty()) auditError = "audit_partial_write";
        } else if (cursor != nextCursor) { cursor = nextCursor; cursorDirty = true; }
        if (cursorDirty) {
            checkpointAttempted = true;
            if (SaveEngineText(directory, L"restriction-cursor",
                "WinTCP-Restriction-Cursor:1\n" + cursor + '\n', security, &auditError))
                cursorDirty = false;
        }
        if (auditError.empty() && readFailed) auditError = "collector_audit_unavailable";
        if (connected) gracefulAuditComplete = !cursorDirty && !cursor.empty() &&
            status.find("\"finalCursor\":" + NetworkJsonQuote(cursor)) != std::string::npos;
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            if (!audit.empty() || readFailed || checkpointAttempted ||
                !auditError.empty() || (connected &&
                state->restrictionAuditError == "collector_audit_unavailable"))
                state->restrictionAuditError = auditError;
            if (!cursorDirty) state->restrictionAuditCursor = cursor;
            if (!audit.empty() && written == audit.size()) state->restrictionAuditLost += lost;
            if (connected) {
                lastSeen = clock.monotonicMs;
                state->collectorConnected = true;
                state->lifecycleEnabled = status.find("\"events\":{\"running\":true") !=
                    std::string::npos;
                const std::string eventEpoch = QuotedStatusField(status, "eventEpoch");
                const std::string decodedCount = QuotedStatusField(status, "decoded");
                const std::string publishedCount = QuotedStatusField(status, "published");
                if ((state->lifecycleEnabled || (!decodedCount.empty() && decodedCount != "0")) &&
                    (eventEpoch != observedEventEpoch || decodedCount != observedDecodedCount ||
                     publishedCount != observedPublishedCount))
                    state->lifecycleNeedsDrain = true;
                observedEventEpoch = eventEpoch;
                observedDecodedCount = decodedCount;
                observedPublishedCount = publishedCount;
                state->restrictionsAvailable = status.find(
                    "\"restrictionsAvailable\":true") != std::string::npos;
                state->collectorReason.clear();
                if (!state->restrictionsAvailable) {
                    const std::string marker = "\"restrictionReason\":\"";
                    const auto first = status.find(marker);
                    const auto start = first == std::string::npos ? first : first + marker.size();
                    const auto end = start == std::string::npos ? start : status.find('"', start);
                    state->collectorReason = end == std::string::npos
                        ? "collector_not_ready" : status.substr(start, end - start);
                }
                state->collectorLastSampleUtc = clock.utc;
            } else if (lastSeen == 0 || clock.monotonicMs < lastSeen ||
                       clock.monotonicMs - lastSeen >= 3000) {
                state->collectorConnected = false;
                state->lifecycleEnabled = false;
                state->restrictionsAvailable = false;
                state->collectorReason = "collector_not_connected";
            }
        }
        if (moreChanges && auditError.empty()) continue;
        if (::WaitForSingleObject(state->stopEvent, 1000) != WAIT_TIMEOUT) return;
    }
}

void LifecycleIngestLoop(State* state, const std::wstring& directory,
                          SECURITY_ATTRIBUTES* security) {
    std::string checkpointError;
    std::string cursor = LoadCollectorCursor(directory, &checkpointError, true);
    bool dirty = false, draining = false, disconnectedReported = false;
    bool clockGapReported = false;
    std::uint64_t gapSequence = 0;
    while (::WaitForSingleObject(state->stopEvent, 0) == WAIT_TIMEOUT) {
        bool enabled = false;
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            enabled = state->lifecycleEnabled;
            draining = draining || state->lifecycleNeedsDrain;
            state->lifecycleNeedsDrain = false;
        }
        if (!enabled && !draining && !dirty) {
            if (::WaitForSingleObject(state->stopEvent, 250) != WAIT_TIMEOUT) return;
            continue;
        }
        draining = draining || enabled;
        CollectorChangesPage page;
        std::vector<std::string> lines;
        std::string error;
        const auto gap = [&](const char* reason, std::uint64_t lost) {
            return "{\"schemaVersion\":1,\"eventId\":\"" + state->epoch +
                ":lifecycle-gap-" + std::to_string(++gapSequence) +
                "\",\"kind\":\"coverage_gap\",\"source\":\"etw_raw\",\"reason\":" +
                NetworkJsonQuote(reason) + ",\"occurredAtUtc\":" +
                NetworkJsonQuote(SampleClock().utc) + ",\"lostRecords\":\"" +
                std::to_string(lost) + "\"}";
        };
        std::string nextCursor = cursor;
        bool nextClockGapReported = clockGapReported;
        bool more = false;
        if (!dirty) {
            if (!checkpointError.empty()) lines.push_back(gap("checkpoint_unavailable", 0));
            if (!CollectorLifecycleEvents(cursor, &page)) {
                error = "lifecycle_collector_unavailable";
                if (!disconnectedReported) lines.push_back(gap("collector_unreachable", 0));
                disconnectedReported = true;
                draining = false;
            } else {
                disconnectedReported = false;
                if (page.cursorExpired) {
                    lines.push_back(gap("trace_epoch_changed", 0));
                    nextClockGapReported = false;
                    nextCursor.clear();
                    more = true;
                } else {
                    if (page.lostRecords) lines.push_back(gap("source_records_unavailable", page.lostRecords));
                    for (const auto& item : page.items) {
                        if (!nextClockGapReported &&
                            QuotedStatusField(item, "timeReason") == "clock_mapping_unstable") {
                            lines.push_back(gap("source_clock_mapping_unstable", 0));
                            nextClockGapReported = true;
                        }
                        lines.push_back(item);
                    }
                    nextCursor = page.nextCursor;
                    more = page.items.size() == 32;
                    if (!enabled && !more) draining = false;
                }
            }
        }
        std::size_t written = 0;
        std::string storageError;
        if (!lines.empty()) {
            std::lock_guard<std::mutex> lock(state->historyMutex);
            if (state->lifecycleStore.Append(lines, &written, &storageError) &&
                written == lines.size()) {
                cursor = nextCursor;
                clockGapReported = nextClockGapReported;
                dirty = true;
                checkpointError.clear();
            } else if (storageError.empty()) storageError = "lifecycle_partial_write";
        } else if (cursor != nextCursor) { cursor = nextCursor; dirty = true; }
        if (dirty && SaveEngineText(directory, L"lifecycle-cursor",
            "WinTCP-Lifecycle-Cursor:1\n" + cursor + '\n', security, &storageError)) dirty = false;
        if (!storageError.empty()) error = storageError;
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            state->lifecycleError = error;
            state->lifecyclePersisted += written;
            if (written == lines.size()) state->lifecycleLost += page.lostRecords;
        }
        if (::WaitForSingleObject(state->stopEvent, more && error.empty() ? 10 : 1000) != WAIT_TIMEOUT)
            return;
    }
}

std::string StatusJson(State* state) {
    std::size_t recipeCount = 0;
    {
        std::lock_guard<std::mutex> recipeLock(state->recipesMutex);
        recipeCount = state->recipes.size();
    }
    std::lock_guard<std::mutex> lock(state->mutex);
    NetworkCapability snapshot;
    snapshot.id = "snapshots";
    snapshot.supported = true;
    snapshot.enabled = true;
    snapshot.available = state->sampleCount != 0 && state->sampleError.empty();
    snapshot.reason = snapshot.available ? "" :
        (state->sampleError.empty() ? "first_sample_pending" : state->sampleError);
    snapshot.coverage = snapshot.available ? "sampled" : "none";
    snapshot.sourceVersion = "snapshot-v1";
    snapshot.lastSampleUtc = state->lastSampleUtc;
    snapshot.lostRecords = state->journal.EvictedRecords();
    std::string capabilities = NetworkCapabilityJson(snapshot);
    NetworkCapability restriction;
    restriction.id = "restrictions.temporary";
    restriction.supported = true;
    restriction.enabled = state->collectorConnected;
    restriction.available = state->restrictionsAvailable;
    restriction.requiresElevation = true;
    restriction.reason = state->restrictionsAvailable ? "" : state->collectorReason;
    restriction.coverage = state->restrictionsAvailable ? "app_user_outbound_authorization" : "none";
    restriction.sourceVersion = "wfp-dynamic-v1";
    restriction.lastSampleUtc = state->collectorLastSampleUtc;
    capabilities += ',' + NetworkCapabilityJson(restriction);
    static const char* kUnavailable[] = {
        "events.tcpLifecycle", "events.explicitFailures", "events.udpActivity",
        "events.deniedAttempts", "events.processLifecycle", "interfaces.observedEgress",
        "interfaces.adapters", "dns.observations", "capture.packets",
        "protocol.tls", "protocol.quic",
        "browser.requests",
    };
    for (const char* id : kUnavailable) {
        NetworkCapability capability;
        capability.id = id;
        capability.requiresElevation = capability.id == "events.tcpLifecycle" ||
            capability.id == "events.explicitFailures" ||
            capability.id == "events.udpActivity" ||
            capability.id == "events.deniedAttempts" ||
            capability.id == "events.processLifecycle" ||
            capability.id == "capture.packets" ||
            capability.id == "protocol.tls" ||
            capability.id == "protocol.quic" ||
            capability.id == "restrictions.temporary";
        capability.reason = "not_implemented";
        if (capability.id == "events.tcpLifecycle" ||
            capability.id == "events.udpActivity" || capability.id == "events.processLifecycle") {
            capability.supported = true;
            capability.enabled = state->lifecycleEnabled;
            capability.reason = "normalization_pending";
            capability.coverage = state->lifecycleEnabled ? "raw_evidence_only" : "none";
            capability.sourceVersion = "tdh-classic-v1";
        }
        capabilities += ',' + NetworkCapabilityJson(capability);
    }
    return "{\"schemaVersion\":1,\"running\":true,\"epoch\":\"" +
           state->epoch + "\",\"samples\":\"" + std::to_string(state->sampleCount) +
           "\",\"eventsRetained\":" + std::to_string(state->journal.Size()) +
           ",\"snapshotIntervalMs\":" +
           std::to_string(state->config.snapshotIntervalMs) +
           ",\"clock\":{\"mappingId\":" +
           (state->clockMappingId.empty() ? "null" :
               "\"" + state->clockMappingId + "\"") +
           ",\"changes\":\"" + std::to_string(state->clockChanges) +
           "\",\"lastAdjustmentMs\":\"" +
           std::to_string(state->lastClockAdjustmentMs) +
           "\",\"anchorUtcMs\":\"" +
           std::to_string(state->clockAnchorUtcMs) +
           "\",\"anchorMonotonicMs\":\"" +
           std::to_string(state->clockAnchorMonotonicMs) + "\"}" +
           ",\"recipes\":{\"definitions\":" +
           std::to_string(recipeCount) +
           ",\"notificationsWritten\":\"" +
           std::to_string(state->notificationsWritten) +
           "\",\"notificationsLost\":\"" +
           std::to_string(state->notificationsLost) +
           "\",\"notificationError\":" +
           (state->notificationError.empty() ? "null" :
               "\"" + state->notificationError + "\"") + "}" +
           ",\"storage\":{\"available\":" +
           (state->storageError.empty() ? "true" : "false") +
           ",\"reason\":" + (state->storageError.empty() ? "null" :
               "\"" + state->storageError + "\"") +
           ",\"persistedEvents\":\"" +
           std::to_string(state->persistedEvents) +
           "\",\"lostRecords\":\"" + std::to_string(state->storageLost) +
           "\",\"rollovers\":\"" +
           std::to_string(state->storageRollovers) + "\"}" +
           ",\"lifecycle\":{\"enabled\":" + std::string(state->lifecycleEnabled ? "true" : "false") +
           ",\"persistedRecords\":\"" + std::to_string(state->lifecyclePersisted) +
           "\",\"lostRecords\":\"" + std::to_string(state->lifecycleLost) +
           "\",\"error\":" + (state->lifecycleError.empty() ? "null" :
               NetworkJsonQuote(state->lifecycleError)) + "}" +
           ",\"restrictionAudit\":{\"cursor\":\"" + state->restrictionAuditCursor +
           "\",\"lostRecords\":\"" +
           std::to_string(state->restrictionAuditLost) + "\",\"error\":" +
           (state->restrictionAuditError.empty() ? "null" :
               "\"" + state->restrictionAuditError + "\"") + "}" +
           ",\"capabilities\":[" + capabilities + "]}";
}

std::string EventsJson(State* state, const std::string& cursor, unsigned limit) {
    std::lock_guard<std::mutex> lock(state->mutex);
    const NetworkEventPage page = state->journal.Read(cursor, limit);
    if (page.cursorExpired)
        return "{\"schemaVersion\":1,\"code\":\"cursor_expired\"}";
    std::string result = "{\"schemaVersion\":1,\"items\":[";
    std::size_t included = 0;
    for (const NetworkEvent& event : page.items) {
        const std::string item = NetworkEventJson(event);
        if (result.size() + item.size() + 256 > kMaxResponse) break;
        if (result.back() != '[') result += ',';
        result += item;
        ++included;
    }
    std::string nextCursor = page.nextCursor;
    if (included < page.items.size()) {
        const std::size_t colon = nextCursor.find(':');
        const std::uint64_t last = std::stoull(nextCursor.substr(colon + 1));
        nextCursor.resize(colon + 1);
        nextCursor += std::to_string(last - (page.items.size() - included));
    }
    result += "],\"nextCursor\":\"" + nextCursor +
              "\",\"evictedRecords\":\"" +
              std::to_string(page.evictedRecords) +
              "\",\"coverage\":{\"source\":\"snapshot\",\"intervalMs\":" +
              std::to_string(state->config.snapshotIntervalMs) + ",\"loss\":" +
              (state->sampleError.empty() ? "false" : "true") + "}}";
    return result;
}

std::string ShowRecipeJson(State* state, const std::string& id) {
    std::lock_guard<std::mutex> lock(state->recipesMutex);
    const auto found = std::find_if(state->recipes.begin(), state->recipes.end(),
        [&id](const RecipeDef& recipe) { return recipe.id == id; });
    return found == state->recipes.end()
        ? "{\"schemaVersion\":1,\"code\":\"recipe_not_found\"}"
        : RecipeJson(*found);
}

std::string TestRecipeJson(State* state, const std::string& id) {
    RecipeDef recipe;
    {
        std::lock_guard<std::mutex> lock(state->recipesMutex);
        const auto found = std::find_if(state->recipes.begin(), state->recipes.end(),
            [&id](const RecipeDef& row) { return row.id == id; });
        if (found == state->recipes.end())
            return "{\"schemaVersion\":1,\"code\":\"recipe_not_found\"}";
        recipe = *found;
    }
    NetworkEventPage page;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        page = state->journal.Read("", 500);
    }
    recipe.enabled = true;  // Simulation also works before first enable.
    RecipeEvaluator evaluator;
    std::uint64_t matched = 0;
    std::uint64_t wouldNotify = 0;
    std::string examples;
    unsigned included = 0;
    for (const NetworkEvent& event : page.items) {
        const RecipeHit hit = evaluator.Evaluate(recipe, event);
        if (!hit.matched) continue;
        ++matched;
        if (!hit.fire) continue;
        ++wouldNotify;
        if (included >= 10) continue;
        const std::string serializedEvent = NetworkEventJson(event);
        if (examples.size() + serializedEvent.size() > 100000) continue;
        if (!examples.empty()) examples += ',';
        examples += "{\"event\":" + serializedEvent +
            ",\"reason\":\"" + hit.reason +
            "\",\"coverage\":\"" + hit.coverage + "\"}";
        ++included;
    }
    return "{\"schemaVersion\":1,\"recipeId\":\"" + recipe.id +
        "\",\"simulation\":true,\"effectsApplied\":false," +
        "\"source\":\"last_500_retained_snapshot_events\"," +
        "\"examined\":" + std::to_string(page.items.size()) +
        ",\"matched\":" + std::to_string(matched) +
        ",\"wouldNotify\":" + std::to_string(wouldNotify) +
        ",\"evictedBeforeReplay\":\"" +
        std::to_string(page.evictedRecords) + "\",\"examples\":[" +
        examples + "]}";
}

std::string HistoryJson(State* state, const std::string& cursor, unsigned limit,
                        bool restrictions = false, bool lifecycle = false) {
    EngineStorePage page;
    {
        std::lock_guard<std::mutex> lock(state->historyMutex);
        page = lifecycle ? state->lifecycleStore.Read(cursor, limit, 220000) :
               restrictions ? state->auditStore.Read(cursor, limit, 220000) :
                              state->eventStore.Read(cursor, limit, 220000);
    }
    if (page.cursorExpired)
        return "{\"schemaVersion\":1,\"code\":\"cursor_expired\"}";
    if (!page.error.empty())
        return "{\"schemaVersion\":1,\"code\":\"" + page.error + "\"}";
    std::string result = "{\"schemaVersion\":1,\"items\":[";
    for (const std::string& item : page.items) {
        if (result.back() != '[') result += ',';
        result += item;
    }
    std::uint64_t lost = 0;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        lost = lifecycle ? state->lifecycleLost : restrictions ? state->restrictionAuditLost : state->storageLost;
    }
    result += "],\"nextCursor\":\"" + page.nextCursor +
              "\",\"partialTail\":" +
              (page.partialTail ? "true" : "false") +
              ",\"coverage\":{\"source\":\"" +
              (lifecycle ? std::string("etw_raw") : restrictions ? std::string("restriction_audit") : std::string("snapshot")) +
              "\",\"durable\":true," +
              "\"lostRecords\":\"" + std::to_string(lost) + "\"}}";
    return result;
}

std::string NotificationsJson(State* state, const std::string& cursor,
                              unsigned limit) {
    EngineStorePage page;
    {
        std::lock_guard<std::mutex> lock(state->historyMutex);
        page = state->notificationStore.Read(cursor, limit, 220000);
        const std::string prefix = "{\"schemaVersion\":1,\"id\":\"";
        for (std::string& item : page.items) {
            if (item.rfind(prefix, 0) != 0) continue;
            const std::size_t end = item.find('"', prefix.size());
            if (end == std::string::npos) continue;
            const std::string id = item.substr(prefix.size(), end - prefix.size());
            if (state->acknowledgedNotifications.find(id) ==
                state->acknowledgedNotifications.end()) continue;
            const std::string oldValue = "\"acknowledged\":false";
            const std::size_t at = item.find(oldValue);
            if (at != std::string::npos)
                item.replace(at, oldValue.size(), "\"acknowledged\":true");
        }
    }
    if (page.cursorExpired)
        return "{\"schemaVersion\":1,\"code\":\"cursor_expired\"}";
    if (!page.error.empty())
        return "{\"schemaVersion\":1,\"code\":\"" + page.error + "\"}";
    std::string result = "{\"schemaVersion\":1,\"items\":[";
    for (const std::string& item : page.items) {
        if (result.back() != '[') result += ',';
        result += item;
    }
    result += "],\"nextCursor\":\"" + page.nextCursor +
        "\",\"partialTail\":" + (page.partialTail ? "true" : "false") + "}";
    return result;
}

bool RequestRaw(unsigned char operation, const std::string& payload,
                std::string* response) {
    if (response == nullptr || payload.size() > kMaxFrame - 2 - kChallengeBytes)
        return false;
    Identity own;
    if (!OwnIdentity(&own)) return false;
    const std::wstring name = PipeName(own);
    HANDLE pipe = INVALID_HANDLE_VALUE;
    const ULONGLONG deadline = ::GetTickCount64() + 1000;
    for (;;) {
        if (::WaitNamedPipeW(name.c_str(), 100))
            pipe = ::CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE,
                                  0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (pipe != INVALID_HANDLE_VALUE) break;
        const DWORD error = ::GetLastError();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PIPE_BUSY &&
            error != ERROR_SEM_TIMEOUT) return false;
        if (::GetTickCount64() >= deadline) return false;
        ::Sleep(10);
    }
    const DWORD helloBytes = 2;
    const unsigned char helloFrame[2] = {1, 0};
    bool ok = WriteExact(pipe, &helloBytes, sizeof(helloBytes)) &&
              WriteExact(pipe, helloFrame, helloBytes);
    std::vector<unsigned char> challenge;
    if (ok) ok = ReadFrame(pipe, &challenge) &&
                 challenge.size() == kChallengeBytes;
    std::vector<unsigned char> message = {1, operation};
    if (ok) message.insert(message.end(), challenge.begin(), challenge.end());
    message.insert(message.end(), payload.begin(), payload.end());
    const DWORD bytes = static_cast<DWORD>(message.size());
    if (ok) ok = WriteExact(pipe, &bytes, sizeof(bytes)) &&
                 WriteExact(pipe, message.data(), bytes);
    DWORD responseBytes = 0;
    if (ok) ok = ReadExact(pipe, &responseBytes, sizeof(responseBytes)) &&
                 responseBytes != 0 && responseBytes <= kMaxResponse;
    if (ok) {
        response->resize(responseBytes);
        ok = ReadExact(pipe, &(*response)[0], responseBytes);
    }
    if (ok) {
        const std::string ack("\x01\xff", 2);
        (void)WriteFrame(pipe, ack);
    }
    ::CloseHandle(pipe);
    return ok;
}

bool Request(unsigned char operation, const std::string& cursor,
             unsigned limit, std::string* response) {
    if (cursor.size() > 128 || limit > 500) return false;
    if (operation != 3 && operation != 7 && operation != 10 && operation != 16 && operation != 17)
        return RequestRaw(operation, "", response);
    std::string payload;
    payload += static_cast<char>(limit & 255);
    payload += static_cast<char>((limit >> 8) & 255);
    payload += cursor;
    return RequestRaw(operation, payload, response);
}

int Run(State* state, const Identity& own) {
    const std::wstring mutexName = MutexName(own);
    HANDLE single = ::CreateMutexW(nullptr, TRUE, mutexName.c_str());
    if (single == nullptr) return 1;
    if (::GetLastError() == ERROR_ALREADY_EXISTS) {
        ::CloseHandle(single);
        return 3;
    }
    std::string configError;
    std::wstring storageDirectory;
    if (!LoadEngineConfig(own.sidText, &state->config, &configError,
                          &storageDirectory)) {
        Print("engine config: " + configError);
        ::ReleaseMutex(single);
        ::CloseHandle(single);
        return 1;
    }
    state->journal = NetworkEventJournal(state->config.maxEventRecords,
                                          state->config.maxEventBytes);
    const std::wstring sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;" + own.sidText + L")";
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) {
        ::CloseHandle(single);
        return 1;
    }
    SECURITY_ATTRIBUTES security = {sizeof(security), descriptor, FALSE};
    if (!state->eventStore.Open(storageDirectory, L"events", 32 * 1024 * 1024,
                                security, &configError) ||
        !state->notificationStore.Open(storageDirectory, L"notifications",
                                       4 * 1024 * 1024, security, &configError) ||
        !state->auditStore.Open(storageDirectory, L"audit", 4 * 1024 * 1024,
                                security, &configError) ||
        !state->lifecycleStore.Open(storageDirectory, L"lifecycle", 8 * 1024 * 1024,
                                security, &configError)) {
        Print("engine storage: " + configError);
        ::LocalFree(descriptor);
        ::ReleaseMutex(single);
        ::CloseHandle(single);
        return 1;
    }
    if (!LoadRecipeFile(storageDirectory, &security, &state->recipes,
                        &configError)) {
        Print("engine recipes: " + configError);
        ::LocalFree(descriptor);
        ::ReleaseMutex(single);
        ::CloseHandle(single);
        return 1;
    }
    if (!LoadAcks(storageDirectory, &security,
                  &state->acknowledgedNotifications, &configError)) {
        Print("engine notification acks: " + configError);
        ::LocalFree(descriptor);
        ::ReleaseMutex(single);
        ::CloseHandle(single);
        return 1;
    }
    state->stopEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (state->stopEvent == nullptr) {
        ::LocalFree(descriptor);
        ::CloseHandle(single);
        return 1;
    }
    state->epoch = RandomEpoch();
    if (state->epoch.empty()) {
        ::CloseHandle(state->stopEvent);
        ::LocalFree(descriptor);
        ::ReleaseMutex(single);
        ::CloseHandle(single);
        return 1;
    }
    state->operations.SetEpoch(state->epoch);
    const ClockSample cooldownClock = SampleClock();
    if (!LoadRecipeCooldowns(storageDirectory, &state->recipeEvaluator,
            cooldownClock.monotonicMs * 1000000ULL, cooldownClock.utcMs, &configError))
        state->notificationError = configError;
    state->recipeEvaluator.Reconcile(state->recipes);
    std::thread sampler(SampleLoop, state, storageDirectory, &security);
    std::thread operationWorker(OperationLoop, state, own.sidText,
                                storageDirectory, &security, EngineOperationQueue::General);
    std::thread collectorWorker(OperationLoop, state, own.sidText,
                                storageDirectory, &security, EngineOperationQueue::Collector);
    std::thread collectorProbe(CollectorProbe, state, storageDirectory, &security);
    std::thread lifecycleIngest(LifecycleIngestLoop, state, storageDirectory, &security);
    const std::wstring pipeName = PipeName(own);
    int result = 0;
    for (;;) {
        HANDLE pipe = ::CreateNamedPipeW(
            pipeName.c_str(), PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            4, kMaxResponse + sizeof(DWORD), kMaxFrame + sizeof(DWORD), 0, &security);
        if (pipe == INVALID_HANDLE_VALUE) { result = 1; break; }
        if (::ConnectNamedPipe(pipe, nullptr) || ::GetLastError() == ERROR_PIPE_CONNECTED) {
            std::vector<unsigned char> message;
            // Named-pipe impersonation requires a client message to have been
            // read first. The pipe ACL bounds who can submit that first frame.
            if (ReadFrame(pipe, &message) && SameClient(pipe, own) &&
                message.size() == 2 && message[0] == 1 && message[1] == 0) {
                unsigned char nonce[kChallengeBytes] = {};
                const std::string challenge = RandomBytes(nonce, sizeof(nonce))
                    ? std::string(reinterpret_cast<const char*>(nonce), sizeof(nonce))
                    : std::string();
                if (!challenge.empty() && WriteFrame(pipe, challenge) &&
                    ReadFrame(pipe, &message) && message.size() >= 2 + kChallengeBytes &&
                    message[0] == 1 &&
                    std::memcmp(challenge.data(), message.data() + 2,
                                kChallengeBytes) == 0) {
                    std::string reply;
                    if (message[1] == 1 && message.size() == 2 + kChallengeBytes) {
                        reply = StatusJson(state);
                    } else if (message[1] == 2 && message.size() == 2 + kChallengeBytes) {
                        reply = "{\"schemaVersion\":1,\"stopping\":true}";
                        ::SetEvent(state->stopEvent);
                    } else if (message[1] == 3 && message.size() >= 4 + kChallengeBytes) {
                        const unsigned limit = static_cast<unsigned>(message[18]) |
                                               (static_cast<unsigned>(message[19]) << 8);
                        const std::string cursor(message.begin() + 20, message.end());
                        if (limit <= 500 && cursor.size() <= 128 &&
                            cursor.find_first_not_of("0123456789-:") == std::string::npos)
                            reply = EventsJson(state, cursor, limit);
                    } else if ((message[1] == 7 || message[1] == 16 || message[1] == 17) &&
                               message.size() >= 4 + kChallengeBytes) {
                        const unsigned limit = static_cast<unsigned>(message[18]) |
                                               (static_cast<unsigned>(message[19]) << 8);
                        const std::string cursor(message.begin() + 20, message.end());
                        if (limit >= 1 && limit <= 500 && cursor.size() <= 128 &&
                            cursor.find_first_not_of("0123456789abcdef:") ==
                                std::string::npos)
                            reply = HistoryJson(state, cursor, limit, message[1] == 16, message[1] == 17);
                    } else if (message[1] == 8 && message.size() == 2 + kChallengeBytes) {
                        std::lock_guard<std::mutex> lock(state->recipesMutex);
                        reply = RecipesJson(state->recipes);
                    } else if (message[1] == 9 &&
                               message.size() > 2 + kChallengeBytes &&
                               message.size() <= kMaxFrame) {
                        const std::string payload(message.begin() + 18,
                                                  message.end());
                        reply = SubmitRecipes(state, payload, storageDirectory,
                                              nullptr);
                    } else if (message[1] == 10 &&
                               message.size() >= 4 + kChallengeBytes) {
                        const unsigned limit = static_cast<unsigned>(message[18]) |
                                               (static_cast<unsigned>(message[19]) << 8);
                        const std::string cursor(message.begin() + 20, message.end());
                        if (limit >= 1 && limit <= 500 && cursor.size() <= 128 &&
                            cursor.find_first_not_of("0123456789abcdef:") ==
                                std::string::npos)
                            reply = NotificationsJson(state, cursor, limit);
                    } else if (message[1] == 11 &&
                               message.size() > 2 + kChallengeBytes &&
                               message.size() <= 2 + kChallengeBytes + 160) {
                        const std::string payload(message.begin() + 18,
                                                  message.end());
                        reply = SubmitAcknowledgement(state, payload);
                    } else if (message[1] == 12 &&
                               message.size() > 2 + kChallengeBytes &&
                               message.size() <= 2 + kChallengeBytes + 5000) {
                        const std::string payload(message.begin() + 18,
                                                  message.end());
                        reply = SubmitRecipeMutation(state, payload,
                                                     storageDirectory);
                    } else if ((message[1] == 13 || message[1] == 14) &&
                               message.size() > 2 + kChallengeBytes &&
                               message.size() <= 2 + kChallengeBytes + 64) {
                        const std::string id(message.begin() + 18,
                                             message.end());
                        if (SafeId(id, 64))
                            reply = message[1] == 13
                                ? TestRecipeJson(state, id)
                                : ShowRecipeJson(state, id);
                    } else if (message[1] == 15 &&
                               message.size() > 2 + kChallengeBytes &&
                               message.size() <= 2400 + 2 + kChallengeBytes) {
                        reply = SubmitCollector(state,
                            std::string(message.begin() + 18, message.end()));
                    } else if (message[1] == 4 && message.size() == 2 + kChallengeBytes) {
                        EngineConfig current;
                        std::string error;
                        reply = LoadEngineConfig(own.sidText, &current, &error,
                                                 nullptr, false)
                            ? ConfigJson(current, state->config)
                            : "{\"schemaVersion\":1,\"code\":\"config_unavailable\"}";
                    } else if (message[1] == 5 &&
                               message.size() > 2 + kChallengeBytes &&
                               message.size() <= 4300 + 2 + kChallengeBytes) {
                        const std::string payload(message.begin() + 18,
                                                  message.end());
                        reply = SubmitConfig(state, payload, own.sidText,
                                             nullptr);
                    } else if (message[1] == 6 &&
                               message.size() > 2 + kChallengeBytes &&
                               message.size() <= 2 + kChallengeBytes + 128) {
                        const std::string id(message.begin() + 18, message.end());
                        if (SafeId(id, 128)) {
                            reply = "{\"schemaVersion\":1,\"code\":\"operation_expired\"}";
                            std::lock_guard<std::mutex> lock(state->operationsMutex);
                            const EngineOperation* operation = state->operations.Find(
                                id, ::GetTickCount64());
                            if (operation != nullptr) reply = OperationJson(*operation);
                        }
                    }
                    if (reply.empty()) reply = "{\"schemaVersion\":1,\"code\":\"bad_request\"}";
                    if (WriteFrame(pipe, reply)) {
                        std::vector<unsigned char> ack;
                        // Bound a client that never consumes its reply. The
                        // reader acknowledges only after receiving the frame.
                        (void)ReadFrame(pipe, &ack);
                    }
                }
            }
            ::DisconnectNamedPipe(pipe);
        }
        ::CloseHandle(pipe);
        if (::WaitForSingleObject(state->stopEvent, 0) != WAIT_TIMEOUT) break;
    }
    ::SetEvent(state->stopEvent);
    state->operationsReady.notify_all();
    sampler.join();
    operationWorker.join();
    collectorWorker.join();
    collectorProbe.join();
    lifecycleIngest.join();
    ::CloseHandle(state->stopEvent);
    ::LocalFree(descriptor);
    ::ReleaseMutex(single);
    ::CloseHandle(single);
    return result;
}

void Print(const std::string& text) {
    std::fwrite(text.data(), 1, text.size(), stdout);
    std::fwrite("\n", 1, 1, stdout);
}

}  // namespace

bool EngineRequestStatus(std::string* response) {
    return Request(1, "", 0, response);
}

bool EngineSubmitCollector(const std::string& requestId,
                           const std::string& action,
                           const std::string& payload,
                           std::string* response) {
    if (!SafeId(requestId, 64) || !CollectorOperationValid(action, payload))
        return false;
    return RequestRaw(15, requestId + '\n' + action + '\n' + payload, response);
}

bool EngineRequestEvents(const std::string& cursor, unsigned limit,
                         std::string* response) {
    return Request(3, cursor, limit, response);
}

bool EngineRequestHistory(const std::string& cursor, unsigned limit,
                          std::string* response) {
    if (limit == 0) return false;
    return Request(7, cursor, limit, response);
}

bool EngineRequestRestrictionHistory(const std::string& cursor, unsigned limit,
                                     std::string* response) {
    return limit != 0 && Request(16, cursor, limit, response);
}

bool EngineRequestLifecycleHistory(const std::string& cursor, unsigned limit,
                                   std::string* response) {
    return limit != 0 && Request(17, cursor, limit, response);
}

bool EngineRequestConfig(std::string* response) {
    return RequestRaw(4, "", response);
}

bool EngineSubmitConfig(const std::string& requestId,
                        const std::string& expectedRevision,
                        const EngineConfig& config, std::string* response) {
    if (!SafeId(requestId, 64) || !RevisionSyntax(expectedRevision)) return false;
    return RequestRaw(5, requestId + '\n' + expectedRevision + '\n' +
                     FormatEngineConfig(config), response);
}

bool EngineRequestOperation(const std::string& operationId,
                            std::string* response) {
    if (!SafeId(operationId, 128)) return false;
    return RequestRaw(6, operationId, response);
}

bool EngineRequestRecipes(std::string* response) {
    return RequestRaw(8, "", response);
}

bool EngineSubmitRecipes(const std::string& requestId,
                         const std::string& expectedRevision,
                         const std::vector<RecipeDef>& recipes,
                         std::string* response) {
    if (!SafeId(requestId, 64) || !RevisionSyntax(expectedRevision)) return false;
    const std::string formatted = FormatRecipes(recipes);
    std::vector<RecipeDef> checked;
    std::string error;
    if (!ParseRecipes(formatted, &checked, &error)) return false;
    return RequestRaw(9, requestId + '\n' + expectedRevision + '\n' +
                     formatted, response);
}

bool EngineRecipeMutation(const std::string& requestId,
                          const std::string& expectedRevision,
                          const std::string& action,
                          const std::string& value,
                          std::string* response) {
    if (!SafeId(requestId, 64) || !RevisionSyntax(expectedRevision) ||
        (action != "create" && action != "enable" && action != "disable" &&
         action != "remove") || value.size() > 4500 ||
        (value.find('\n') != std::string::npos && action != "create"))
        return false;
    return RequestRaw(12, requestId + '\n' + expectedRevision + '\n' +
                      action + '\n' + value, response);
}

bool EngineTestRecipe(const std::string& recipeId, std::string* response) {
    if (!SafeId(recipeId, 64)) return false;
    return RequestRaw(13, recipeId, response);
}

bool EngineShowRecipe(const std::string& recipeId, std::string* response) {
    if (!SafeId(recipeId, 64)) return false;
    return RequestRaw(14, recipeId, response);
}

bool EngineRequestNotifications(const std::string& cursor, unsigned limit,
                                std::string* response) {
    if (limit == 0) return false;
    return Request(10, cursor, limit, response);
}

bool EngineAcknowledgeNotification(const std::string& requestId,
                                   const std::string& notificationId,
                                   std::string* response) {
    if (!SafeId(requestId, 64) || !ValidNotificationId(notificationId))
        return false;
    return RequestRaw(11, requestId + '\n' + notificationId, response);
}

bool RuntimeCliPath(std::wstring* path, std::string* error) {
    if (path == nullptr) return false;
    wchar_t modulePath[32768] = {};
    const DWORD length = ::GetModuleFileNameW(nullptr, modulePath, 32768);
    if (length == 0 || length >= 32768) {
        if (error != nullptr) *error = "executable_path_unavailable";
        return false;
    }
    *path = modulePath;
    const auto* base = reinterpret_cast<const unsigned char*>(::GetModuleHandleW(nullptr));
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    const auto* image = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (image->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI) {
        const auto slash = path->find_last_of(L"\\/");
        if (slash == std::wstring::npos) return false;
        *path = path->substr(0, slash + 1) + L"wintcp.exe";
        const DWORD attributes = ::GetFileAttributesW(path->c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES ||
            (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) {
            if (error != nullptr) *error = "cli_executable_missing";
            return false;
        }
    }
    if (error != nullptr) error->clear();
    return true;
}

bool EngineStart(std::string* error) {
    std::string response;
    if (EngineRequestStatus(&response)) return true;
    Identity own;
    if (!OwnIdentity(&own)) {
        if (error != nullptr) *error = "identity_unavailable";
        return false;
    }
    EngineConfig verify;
    std::string configError;
    if (!LoadEngineConfig(own.sidText, &verify, &configError)) {
        if (error != nullptr) *error = configError;
        return false;
    }
    std::wstring path;
    if (!RuntimeCliPath(&path, error)) return false;
    std::wstring command = L"\"" + path + L"\" engine run";
    STARTUPINFOW startup = {};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process = {};
    if (!::CreateProcessW(path.c_str(), &command[0], nullptr, nullptr, FALSE,
                          CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process)) {
        if (error != nullptr) *error = "engine_launch_failed";
        return false;
    }
    ::CloseHandle(process.hThread);
    bool ready = false;
    for (unsigned attempt = 0; attempt < 50; ++attempt) {
        if (EngineRequestStatus(&response)) { ready = true; break; }
        if (::WaitForSingleObject(process.hProcess, 100) != WAIT_TIMEOUT) break;
    }
    ::CloseHandle(process.hProcess);
    if (!ready && error != nullptr) *error = "engine_not_reachable";
    return ready;
}

bool EngineStop(std::string* error) {
    std::string response;
    if (RequestRaw(2, "", &response)) return true;
    if (error != nullptr) *error = "engine_not_reachable";
    return false;
}

std::string ResponseField(const std::string& json, const char* field) {
    const std::string prefix = "\"" + std::string(field) + "\":\"";
    const std::size_t start = json.find(prefix);
    if (start == std::string::npos) return {};
    const std::size_t value = start + prefix.size();
    const std::size_t end = json.find('"', value);
    return end == std::string::npos ? std::string() :
        json.substr(value, end - value);
}

int RunRecipeCommand(int argc, wchar_t** argv) {
    static const char* kUsage =
        "usage: wintcp.exe recipe list | show|test <id> | create <id> <name> <full-exe-path> "
        "<outbound_activity|new_listener> [cooldown-seconds] | "
        "enable|disable <id> | remove <id> --yes";
    if (argc < 3 || argv[2] == nullptr) { Print(kUsage); return 2; }
    const std::wstring action = argv[2];
    if (action == L"help" || action == L"--help") {
        Print(kUsage);
        Print("The engine must be running; create saves a disabled Passive recipe. "
              "Snapshot sightings are not proven connection attempts.");
        return 0;
    }
    if (action == L"list") {
        if (argc != 3) { Print(kUsage); return 2; }
        std::string view;
        if (!EngineRequestRecipes(&view)) {
            Print("recipe: engine unavailable; run wintcp.exe engine start");
            return 1;
        }
        Print(view);
        return 0;
    }
    if (action == L"show" || action == L"test") {
        if (argc != 4) { Print(kUsage); return 2; }
        const std::string id = WideToUtf8(argv[3]);
        if (!SafeId(id, 64)) { Print("recipe: invalid id"); return 2; }
        std::string result;
        const bool ok = action == L"show"
            ? EngineShowRecipe(id, &result) : EngineTestRecipe(id, &result);
        if (!ok) { Print("recipe: engine unavailable"); return 1; }
        Print(result);
        return ResponseField(result, "code").empty() ? 0 : 1;
    }
    std::string verb;
    std::string value;
    if (action == L"create") {
        if (argc != 7 && argc != 8) { Print(kUsage); return 2; }
        RecipeDef recipe;
        recipe.id = WideToUtf8(argv[3]);
        recipe.name = WideToUtf8(argv[4]);
        recipe.imagePath = WideToUtf8(argv[5]);
        const std::wstring trigger = argv[6];
        if (trigger == L"outbound_activity")
            recipe.trigger = RecipeTrigger::OutboundActivity;
        else if (trigger == L"new_listener")
            recipe.trigger = RecipeTrigger::NewListener;
        else { Print("recipe: unsupported trigger"); return 2; }
        if (argc == 8) {
            wchar_t* end = nullptr;
            const unsigned long parsed = std::wcstoul(argv[7], &end, 10);
            if (argv[7][0] == L'\0' || end == nullptr || *end != L'\0' ||
                parsed > 86400) {
                Print("recipe: cooldown must be 0..86400 seconds");
                return 2;
            }
            recipe.cooldownSeconds = static_cast<unsigned>(parsed);
        }
        std::string error;
        if (!ValidateRecipe(recipe, &error)) {
            Print("recipe: " + error);
            return 2;
        }
        verb = "create";
        value = FormatRecipes({recipe});
    } else if (action == L"enable" || action == L"disable" ||
               action == L"remove") {
        if ((action == L"remove" &&
             (argc != 5 || std::wstring(argv[4]) != L"--yes")) ||
            (action != L"remove" && argc != 4)) {
            if (action == L"remove" && argc == 4) {
                Print("recipe remove refused without --yes");
                return 3;
            }
            Print(kUsage);
            return 2;
        }
        verb = WideToUtf8(action);
        value = WideToUtf8(argv[3]);
        if (!SafeId(value, 64)) { Print("recipe: invalid id"); return 2; }
    } else { Print(kUsage); return 2; }
    std::string view;
    if (!EngineRequestRecipes(&view)) {
        Print("recipe: engine unavailable; run wintcp.exe engine start");
        return 1;
    }
    const std::string revision = ResponseField(view, "revision");
    if (!RevisionSyntax(revision)) {
        Print("recipe: engine returned an invalid recipe revision");
        return 1;
    }
    std::string submitted;
    if (!EngineRecipeMutation(RandomEpoch(), revision, verb, value,
                              &submitted)) {
        Print("recipe: engine unavailable");
        return 1;
    }
    const std::string operationId = ResponseField(submitted, "operationId");
    if (operationId.empty()) { Print(submitted); return 1; }
    for (unsigned attempt = 0; attempt < 40; ++attempt) {
        std::string result;
        if (!EngineRequestOperation(operationId, &result)) break;
        const std::string status = ResponseField(result, "status");
        if (status == "succeeded") { Print(result); return 0; }
        if (status == "failed") { Print(result); return 1; }
        ::Sleep(100);
    }
    Print("recipe: operation still pending; inspect " + operationId);
    return 1;
}

int RunEngineCommand(int argc, wchar_t** argv) {
    if (argc != 3 || argv[2] == nullptr) {
        Print("usage: wintcp.exe engine start|run|status|stop|events");
        return 2;
    }
    const std::wstring action = argv[2];
    if (action == L"--help" || action == L"help") {
        Print("engine start|run|status|stop|events: one optional per-user snapshot engine; events are sampled endpoints, not connection attempts");
        return 0;
    }
    if (action == L"status" || action == L"events" || action == L"stop") {
        std::string response;
        const bool ok = action == L"events" ? EngineRequestEvents("", 20, &response) :
                        Request(action == L"stop" ? 2 : 1, "", 0, &response);
        if (!ok) {
            Print("engine is not reachable for this user/session");
            return 1;
        }
        Print(response);
        return 0;
    }
    Identity own;
    if (!OwnIdentity(&own)) return 1;
    if (action == L"run") {
        State state;
        return Run(&state, own);
    }
    if (action == L"start") {
        std::string error;
        if (!EngineStart(&error)) {
            Print("engine start: " + error);
            return 1;
        }
        std::string response;
        if (EngineRequestStatus(&response)) Print(response);
        return 0;
    }
    Print("usage: wintcp.exe engine start|run|status|stop|events");
    return 2;
}

}  // namespace wintcp
