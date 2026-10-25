// IncidentArchive.cpp
// SPDX-License-Identifier: Apache-2.0
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>

#include "IncidentArchive.h"
#include "NetworkEvents.h"
#include "Version.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <map>
#include <set>
#include <utility>
#include <string>
#include <vector>

namespace wintcp {
namespace {

std::string Quote(const std::string& value) {
    static const char hex[] = "0123456789abcdef";
    std::string result = "\"";
    for (unsigned char ch : value) {
        if (ch == '"' || ch == '\\') {
            result += '\\';
            result += static_cast<char>(ch);
        } else if (ch < 0x20) {
            result += "\\u00";
            result += hex[ch >> 4];
            result += hex[ch & 15];
        } else {
            result += static_cast<char>(ch);
        }
    }
    result += '"';
    return result;
}

bool RandomHex(std::string* result) {
    if (result == nullptr) return false;
    unsigned char bytes[16] = {};
    if (::BCryptGenRandom(nullptr, bytes, sizeof(bytes),
                          BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) return false;
    static const char hex[] = "0123456789abcdef";
    result->clear();
    result->reserve(sizeof(bytes) * 2);
    for (unsigned char byte : bytes) {
        result->push_back(hex[byte >> 4]);
        result->push_back(hex[byte & 15]);
    }
    return true;
}

bool Hash(const std::string& input, std::string* output) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectBytes = 0, returned = 0, digestBytes = 0;
    std::vector<unsigned char> object;
    unsigned char digest[32] = {};
    bool ok = ::BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM,
                                             nullptr, 0) == 0 &&
        ::BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&objectBytes), sizeof(objectBytes),
            &returned, 0) == 0 && objectBytes != 0 && objectBytes <= 65536 &&
        ::BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH,
            reinterpret_cast<PUCHAR>(&digestBytes), sizeof(digestBytes),
            &returned, 0) == 0 && digestBytes == sizeof(digest);
    if (ok) object.resize(objectBytes);
    if (ok) ok = ::BCryptCreateHash(algorithm, &hash, object.data(), objectBytes,
                                     nullptr, 0, 0) == 0;
    if (ok && !input.empty())
        ok = ::BCryptHashData(hash,
            reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())),
            static_cast<ULONG>(input.size()), 0) == 0;
    if (ok) ok = ::BCryptFinishHash(hash, digest, sizeof(digest), 0) == 0;
    if (hash != nullptr) ::BCryptDestroyHash(hash);
    if (algorithm != nullptr) ::BCryptCloseAlgorithmProvider(algorithm, 0);
    if (!ok) return false;
    static const char hex[] = "0123456789abcdef";
    output->clear();
    output->reserve(sizeof(digest) * 2);
    for (unsigned char byte : digest) {
        output->push_back(hex[byte >> 4]);
        output->push_back(hex[byte & 15]);
    }
    return true;
}

bool WriteFile(const std::wstring& path, const std::string& contents,
               const SECURITY_ATTRIBUTES& security) {
    HANDLE file = ::CreateFileW(path.c_str(), GENERIC_WRITE, 0,
        const_cast<SECURITY_ATTRIBUTES*>(&security), CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    std::size_t offset = 0;
    bool ok = true;
    while (offset < contents.size()) {
        const DWORD chunk = static_cast<DWORD>((std::min)(
            contents.size() - offset,
            static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
        DWORD written = 0;
        if (!::WriteFile(file, contents.data() + offset, chunk, &written, nullptr) ||
            written == 0) {
            ok = false;
            break;
        }
        offset += written;
    }
    if (ok) ok = ::FlushFileBuffers(file) != FALSE;
    if (!::CloseHandle(file)) ok = false;
    return ok;
}

void RemoveTemporary(const std::wstring& directory) {
    const wchar_t* names[] = {L"manifest.json", L"events.ndjson",
                              L"checkpoints.ndjson", L"index.json"};
    for (const wchar_t* name : names)
        (void)::DeleteFileW((directory + L"\\" + name).c_str());
    (void)::RemoveDirectoryW(directory.c_str());
}

class JsonParser {
public:
    explicit JsonParser(const std::string& input) : input_(input) {}
    bool Object() {
        Skip();
        return position_ < input_.size() && input_[position_] == '{' &&
            Value(0) && Finish();
    }
    bool Parse() { return Value(0) && Finish(); }
private:
    void Skip() {
        while (position_ < input_.size() &&
               (input_[position_] == ' ' || input_[position_] == '\t' ||
                input_[position_] == '\r' || input_[position_] == '\n')) ++position_;
    }
    bool String() {
        if (position_ >= input_.size() || input_[position_++] != '"') return false;
        while (position_ < input_.size()) {
            const unsigned char ch = static_cast<unsigned char>(input_[position_++]);
            if (ch == '"') return true;
            if (ch < 0x20) return false;
            if (ch != '\\') continue;
            if (position_ >= input_.size()) return false;
            const char escape = input_[position_++];
            if (escape == '"' || escape == '\\' || escape == '/' ||
                escape == 'b' || escape == 'f' || escape == 'n' ||
                escape == 'r' || escape == 't') continue;
            if (escape != 'u' || input_.size() - position_ < 4) return false;
            for (unsigned i = 0; i < 4; ++i) {
                const char hex = input_[position_++];
                if (!((hex >= '0' && hex <= '9') || (hex >= 'a' && hex <= 'f') ||
                      (hex >= 'A' && hex <= 'F'))) return false;
            }
        }
        return false;
    }
    bool Number() {
        const std::size_t begin = position_;
        if (position_ < input_.size() && input_[position_] == '-') ++position_;
        if (position_ >= input_.size()) return false;
        if (input_[position_] == '0') ++position_;
        else {
            if (input_[position_] < '1' || input_[position_] > '9') return false;
            while (position_ < input_.size() && input_[position_] >= '0' &&
                   input_[position_] <= '9') ++position_;
        }
        if (position_ < input_.size() && input_[position_] == '.') {
            ++position_;
            const std::size_t fraction = position_;
            while (position_ < input_.size() && input_[position_] >= '0' &&
                   input_[position_] <= '9') ++position_;
            if (fraction == position_) return false;
        }
        if (position_ < input_.size() &&
            (input_[position_] == 'e' || input_[position_] == 'E')) {
            ++position_;
            if (position_ < input_.size() &&
                (input_[position_] == '+' || input_[position_] == '-')) ++position_;
            const std::size_t exponent = position_;
            while (position_ < input_.size() && input_[position_] >= '0' &&
                   input_[position_] <= '9') ++position_;
            if (exponent == position_) return false;
        }
        return position_ > begin;
    }
    bool Value(unsigned depth) {
        if (depth > 64) return false;
        Skip();
        if (position_ >= input_.size()) return false;
        const char ch = input_[position_];
        if (ch == '"') return String();
        if (ch == '{') {
            ++position_;
            Skip();
            if (position_ < input_.size() && input_[position_] == '}') {
                ++position_;
                return true;
            }
            std::set<std::string> keys;
            for (;;) {
                Skip();
                const std::size_t keyStart = position_;
                if (!String()) return false;
                if (!keys.insert(input_.substr(keyStart, position_ - keyStart)).second)
                    return false;
                Skip();
                if (position_ >= input_.size() || input_[position_++] != ':') return false;
                if (!Value(depth + 1)) return false;
                Skip();
                if (position_ >= input_.size()) return false;
                const char separator = input_[position_++];
                if (separator == '}') return true;
                if (separator != ',') return false;
            }
        }
        if (ch == '[') {
            ++position_;
            Skip();
            if (position_ < input_.size() && input_[position_] == ']') {
                ++position_;
                return true;
            }
            for (;;) {
                if (!Value(depth + 1)) return false;
                Skip();
                if (position_ >= input_.size()) return false;
                const char separator = input_[position_++];
                if (separator == ']') return true;
                if (separator != ',') return false;
            }
        }
        if (input_.compare(position_, 4, "true") == 0) { position_ += 4; return true; }
        if (input_.compare(position_, 5, "false") == 0) { position_ += 5; return true; }
        if (input_.compare(position_, 4, "null") == 0) { position_ += 4; return true; }
        return Number();
    }
    bool Finish() {
        Skip();
        return position_ == input_.size();
    }
    const std::string& input_;
    std::size_t position_ = 0;
};

bool ReadFileBounded(const std::wstring& path, std::size_t maximum,
                     std::string* contents) {
    if (contents == nullptr) return false;
    const DWORD attributes = ::GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0)
        return false;
    HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT |
        FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    BY_HANDLE_FILE_INFORMATION info = {};
    LARGE_INTEGER size = {};
    bool ok = ::GetFileInformationByHandle(file, &info) != FALSE &&
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
        ::GetFileSizeEx(file, &size) != FALSE && size.QuadPart >= 0 &&
        static_cast<unsigned long long>(size.QuadPart) <= maximum;
    if (ok) {
        contents->clear();
        contents->reserve(static_cast<std::size_t>(size.QuadPart));
        std::array<char, 65536> buffer = {};
        for (;;) {
            DWORD read = 0;
            if (!::ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()),
                            &read, nullptr)) { ok = false; break; }
            if (read == 0) break;
            if (read > maximum - (std::min)(contents->size(), maximum)) {
                ok = false;
                break;
            }
            contents->append(buffer.data(), read);
        }
    }
    ::CloseHandle(file);
    return ok;
}

bool SafeArchiveId(const std::string& id) {
    return id.size() == 32 && id.find_first_not_of("0123456789abcdef") ==
        std::string::npos;
}

bool SafeDirectory(const std::wstring& path) {
    if (path.empty()) return false;
    const DWORD attributes = ::GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES &&
        (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
}

bool JsonStringField(const std::string& json, const std::string& key,
                     std::string* value) {
    const std::string marker = "\"" + key + "\":\"";
    const std::size_t position = json.find(marker);
    if (position == std::string::npos ||
        json.find(marker, position + marker.size()) != std::string::npos) return false;
    const std::size_t begin = position + marker.size();
    const std::size_t end = json.find('"', begin);
    if (end == std::string::npos || json.find('\\', begin) < end) return false;
    *value = json.substr(begin, end - begin);
    return true;
}

bool Decimal64(const std::string& value, std::uint64_t* parsed) {
    if (parsed == nullptr || value.empty()) return false;
    std::uint64_t result = 0;
    for (char digit : value) {
        if (digit < '0' || digit > '9') return false;
        const unsigned number = static_cast<unsigned>(digit - '0');
        if (result > ((std::numeric_limits<std::uint64_t>::max)() - number) / 10)
            return false;
        result = result * 10 + number;
    }
    *parsed = result;
    return true;
}

std::pair<std::string, std::string> MachinePseudonym() {
    constexpr wchar_t kPath[] = L"SOFTWARE\\Microsoft\\Cryptography";
    constexpr wchar_t kValue[] = L"MachineGuid";
    DWORD type = 0, bytes = 0;
    LSTATUS status = ::RegGetValueW(HKEY_LOCAL_MACHINE, kPath, kValue,
        RRF_RT_REG_SZ, &type, nullptr, &bytes);
    if (status != ERROR_SUCCESS || type != REG_SZ || bytes < sizeof(wchar_t) ||
        bytes > 1024) return {{}, "machine_guid_unavailable"};
    std::vector<wchar_t> value(bytes / sizeof(wchar_t) + 1, L'\0');
    status = ::RegGetValueW(HKEY_LOCAL_MACHINE, kPath, kValue, RRF_RT_REG_SZ,
        &type, value.data(), &bytes);
    if (status != ERROR_SUCCESS || type != REG_SZ)
        return {{}, "machine_guid_unavailable"};
    std::string guid;
    for (wchar_t character : value) {
        if (character == L'\0') break;
        if (character < 0x21 || character > 0x7e)
            return {{}, "machine_guid_invalid"};
        guid.push_back(static_cast<char>(character));
    }
    if (guid.size() < 16 || guid.size() > 64)
        return {{}, "machine_guid_invalid"};
    std::string digest;
    if (!Hash("WinTCP incident machine pseudonym v1:" + guid, &digest))
        return {{}, "pseudonym_hash_unavailable"};
    return {digest.substr(0, 32), {}};
}

bool ReadManifest(const std::wstring& directory, const std::string& id,
                  std::string* manifest) {
    const DWORD attributes = ::GetFileAttributesW(directory.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        !ReadFileBounded(directory + L"\\manifest.json", 65536, manifest) ||
        !JsonParser(*manifest).Object()) return false;
    std::string storedId;
    return JsonStringField(*manifest, "archiveId", &storedId) && storedId == id &&
        manifest->find("\"schemaVersion\":1") != std::string::npos &&
        manifest->find("\"complete\":true") != std::string::npos;
}

bool VerifyArchiveFiles(const std::wstring& directory,
                        const std::string& manifest,
                        std::string* events,
                        std::string* checkpoints,
                        std::string* index) {
    if (!ReadFileBounded(directory + L"\\events.ndjson",
            IncidentRecorderModel::kDefaultBudgetBytes, events) ||
        !ReadFileBounded(directory + L"\\checkpoints.ndjson",
                         IncidentRecorderModel::kDefaultBudgetBytes,
                         checkpoints) ||
        !ReadFileBounded(directory + L"\\index.json", 1024 * 1024, index) ||
        !JsonParser(*index).Parse()) return false;
    std::string expectedEvents, expectedCheckpoints, expectedIndex;
    std::string actualEvents, actualCheckpoints, actualIndex;
    if (!JsonStringField(manifest, "events.ndjson", &expectedEvents) ||
        !JsonStringField(manifest, "checkpoints.ndjson", &expectedCheckpoints) ||
        !JsonStringField(manifest, "index.json", &expectedIndex) ||
        !Hash(*events, &actualEvents) || !Hash(*checkpoints, &actualCheckpoints) ||
        !Hash(*index, &actualIndex) || expectedEvents != actualEvents ||
        expectedCheckpoints != actualCheckpoints || expectedIndex != actualIndex)
        return false;
    const auto validLines = [](const std::string& content) {
        std::size_t start = 0;
        while (start < content.size()) {
            const std::size_t end = content.find('\n', start);
            if (end == std::string::npos || end == start ||
                !JsonParser(content.substr(start, end - start)).Object()) return false;
            start = end + 1;
        }
        return true;
    };
    if (!validLines(*events) || !validLines(*checkpoints)) return false;
    return true;
}

constexpr std::size_t kMaxSavedIncidents = 20;
constexpr std::uint64_t kMaxArchiveBytes = 1024ULL * 1024 * 1024;
const wchar_t* const kArchiveFilesWide[] = {
    L"manifest.json", L"events.ndjson", L"checkpoints.ndjson", L"index.json"};

bool ReadPinned(const std::wstring& directory, bool* pinned,
                std::string* error) {
    if (pinned == nullptr || error == nullptr) return false;
    const std::wstring path = directory + L"\\pinned.txt";
    const DWORD attributes = ::GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        const DWORD code = ::GetLastError();
        if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND) {
            *pinned = false;
            error->clear();
            return true;
        }
        *error = "incident_pin_read_failed";
        return false;
    }
    std::string contents;
    if ((attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
        !ReadFileBounded(path, 64, &contents) ||
        contents != "WinTCP-Incident-Pin:1\n") {
        *error = "incident_pin_invalid";
        return false;
    }
    *pinned = true;
    error->clear();
    return true;
}

bool ArchiveFileBytes(const std::wstring& directory, std::uint64_t* bytes,
                      std::string* error) {
    if (bytes == nullptr || error == nullptr) return false;
    std::uint64_t total = 0;
    for (const wchar_t* name : kArchiveFilesWide) {
        WIN32_FILE_ATTRIBUTE_DATA data = {};
        if (!::GetFileAttributesExW((directory + L"\\" + name).c_str(),
                                    GetFileExInfoStandard, &data) ||
            (data.dwFileAttributes &
                (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
            *error = "incident_archive_inventory_invalid";
            return false;
        }
        const std::uint64_t size =
            (static_cast<std::uint64_t>(data.nFileSizeHigh) << 32) |
            data.nFileSizeLow;
        if (total > (std::numeric_limits<std::uint64_t>::max)() - size) {
            *error = "incident_archive_size_overflow";
            return false;
        }
        total += size;
    }
    WIN32_FILE_ATTRIBUTE_DATA pin = {};
    if (::GetFileAttributesExW((directory + L"\\pinned.txt").c_str(),
                               GetFileExInfoStandard, &pin)) {
        if ((pin.dwFileAttributes &
                (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
            *error = "incident_pin_invalid";
            return false;
        }
        const std::uint64_t size =
            (static_cast<std::uint64_t>(pin.nFileSizeHigh) << 32) | pin.nFileSizeLow;
        if (total > (std::numeric_limits<std::uint64_t>::max)() - size) {
            *error = "incident_archive_size_overflow";
            return false;
        }
        total += size;
    } else {
        const DWORD pinError = ::GetLastError();
        if (pinError != ERROR_FILE_NOT_FOUND && pinError != ERROR_PATH_NOT_FOUND) {
            *error = "incident_pin_read_failed";
            return false;
        }
    }
    *bytes = total;
    error->clear();
    return true;
}

struct ArchiveEntry {
    std::string id;
    std::wstring directory;
    std::uint64_t bytes = 0;
    FILETIME created = {};
    bool pinned = false;
};

bool ArchiveContentsSafe(const std::wstring& directory, std::string* error) {
    WIN32_FIND_DATAW found = {};
    HANDLE search = ::FindFirstFileW((directory + L"\\*").c_str(), &found);
    if (search == INVALID_HANDLE_VALUE) {
        *error = "incident_archive_inventory_invalid";
        return false;
    }
    bool safe = true;
    do {
        const std::wstring name(found.cFileName);
        if (name == L"." || name == L"..") continue;
        bool known = name == L"pinned.txt";
        for (const wchar_t* file : kArchiveFilesWide) known = known || name == file;
        if (!known || (found.dwFileAttributes &
            (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
            safe = false;
            break;
        }
    } while (::FindNextFileW(search, &found));
    const DWORD finalError = ::GetLastError();
    ::FindClose(search);
    if (!safe || finalError != ERROR_NO_MORE_FILES) {
        *error = "incident_archive_inventory_unsafe";
        return false;
    }
    error->clear();
    return true;
}

bool CollectArchiveInventory(const std::wstring& root,
                             std::vector<ArchiveEntry>* entries,
                             std::uint64_t* totalBytes,
                             std::string* error) {
    if (entries == nullptr || totalBytes == nullptr || error == nullptr ||
        !SafeDirectory(root)) {
        if (error != nullptr) *error = "incident_archive_directory_unavailable";
        return false;
    }
    entries->clear();
    *totalBytes = 0;
    WIN32_FIND_DATAW found = {};
    HANDLE search = ::FindFirstFileW((root + L"\\incident-*").c_str(), &found);
    if (search == INVALID_HANDLE_VALUE) {
        const DWORD code = ::GetLastError();
        if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND) {
            error->clear();
            return true;
        }
        *error = "incident_archive_list_failed";
        return false;
    }
    bool ok = true;
    do {
        const std::wstring name(found.cFileName);
        const std::wstring prefix = L"incident-";
        if (name.size() != prefix.size() + 32 ||
            name.compare(0, prefix.size(), prefix) != 0) continue;
        std::string id;
        for (std::size_t i = prefix.size(); i < name.size(); ++i) {
            if (name[i] > 0x7f) { id.clear(); break; }
            id.push_back(static_cast<char>(name[i]));
        }
        if (!SafeArchiveId(id)) continue;
        if ((found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
            (found.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            *error = "incident_archive_inventory_unsafe";
            ok = false;
            break;
        }
        ArchiveEntry entry;
        entry.id = std::move(id);
        entry.directory = root + L"\\" + name;
        WIN32_FILE_ATTRIBUTE_DATA data = {};
        std::string manifest;
        if (!::GetFileAttributesExW(entry.directory.c_str(), GetFileExInfoStandard, &data) ||
            !ReadManifest(entry.directory, entry.id, &manifest) ||
            !ArchiveContentsSafe(entry.directory, error) ||
            !ArchiveFileBytes(entry.directory, &entry.bytes, error) ||
            !ReadPinned(entry.directory, &entry.pinned, error)) {
            if (error->empty()) *error = "incident_archive_inventory_invalid";
            ok = false;
            break;
        }
        entry.created = data.ftCreationTime;
        if (*totalBytes > (std::numeric_limits<std::uint64_t>::max)() - entry.bytes) {
            *error = "incident_archive_size_overflow";
            ok = false;
            break;
        }
        *totalBytes += entry.bytes;
        entries->push_back(std::move(entry));
    } while (::FindNextFileW(search, &found));
    const DWORD finalError = ::GetLastError();
    ::FindClose(search);
    if (ok && finalError != ERROR_NO_MORE_FILES) {
        *error = "incident_archive_list_incomplete";
        ok = false;
    }
    if (ok) error->clear();
    return ok;
}

bool DeleteArchiveFiles(const ArchiveEntry& entry, std::string* error) {
    bool pinned = false;
    std::string manifest, events, checkpoints, index;
    if (!ReadPinned(entry.directory, &pinned, error) || pinned) {
        if (error->empty()) *error = "incident_archive_pinned";
        return false;
    }
    if (!ReadManifest(entry.directory, entry.id, &manifest) ||
        !VerifyArchiveFiles(entry.directory, manifest, &events, &checkpoints, &index)) {
        *error = "incident_archive_integrity_failed";
        return false;
    }
    if (!ArchiveContentsSafe(entry.directory, error)) {
        if (error->empty()) *error = "incident_archive_delete_unsafe";
        return false;
    }
    for (const wchar_t* name : kArchiveFilesWide) {
        const std::wstring path = entry.directory + L"\\" + name;
        if (!::DeleteFileW(path.c_str())) {
            *error = "incident_archive_delete_failed";
            return false;
        }
    }
    const std::wstring pin = entry.directory + L"\\pinned.txt";
    const DWORD pinAttributes = ::GetFileAttributesW(pin.c_str());
    if (pinAttributes != INVALID_FILE_ATTRIBUTES &&
        (pinAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
        !::DeleteFileW(pin.c_str())) {
        *error = "incident_archive_delete_failed";
        return false;
    }
    if (!::RemoveDirectoryW(entry.directory.c_str())) {
        *error = "incident_archive_delete_failed";
        return false;
    }
    error->clear();
    return true;
}

bool MakeArchiveQuotaRoom(const std::wstring& root, std::uint64_t addedBytes,
                          std::string* error) {
    std::vector<ArchiveEntry> entries;
    std::uint64_t total = 0;
    if (!CollectArchiveInventory(root, &entries, &total, error)) return false;
    std::vector<IncidentArchiveRetentionCandidate> candidates;
    candidates.reserve(entries.size());
    for (const ArchiveEntry& entry : entries) {
        const std::uint64_t order =
            (static_cast<std::uint64_t>(entry.created.dwHighDateTime) << 32) |
            entry.created.dwLowDateTime;
        candidates.push_back({order, entry.bytes, entry.pinned});
    }
    std::vector<std::size_t> removals;
    if (!PlanIncidentArchiveRetention(candidates, addedBytes, kMaxSavedIncidents,
                                      kMaxArchiveBytes, &removals, error))
        return false;
    for (const std::size_t index : removals)
        if (!DeleteArchiveFiles(entries[index], error)) return false;
    error->clear();
    return true;
}

std::string Manifest(const IncidentSnapshot& incident, const std::string& id,
                     std::size_t eventCount, std::size_t checkpointCount,
                     std::size_t eventBytes, std::size_t checkpointBytes,
                     bool checkpointStateComplete,
                     const std::string& eventHash,
                     const std::string& checkpointHash,
                     const std::string& indexHash) {
    struct SourceStats { std::size_t records = 0; std::uint64_t lost = 0; };
    struct TimebaseAnchors {
        std::uint64_t firstNs = 0, lastNs = 0;
        std::string firstUtc, lastUtc;
    };
    constexpr std::size_t kMaxMetadataKeys = 128;
    std::map<std::string, SourceStats> sources;
    std::map<std::string, std::uint64_t> gaps;
    std::map<std::string, TimebaseAnchors> timebases;
    bool metadataIncomplete = false;
    bool hasRecordTime = false;
    std::uint64_t actualStartNs = incident.endMonotonicNs;
    std::string observedStartUtc, observedEndUtc;
    std::uint64_t observedStartSourceNs = 0, observedEndSourceNs = 0;
    for (const IncidentRecord& record : incident.records) {
        if (!hasRecordTime || record.monotonicNs < actualStartNs)
            actualStartNs = record.monotonicNs;
        hasRecordTime = true;
        std::string source, kind, lossReason, lostText, timebase, utc, sourceNsText;
        if (!JsonStringField(record.payload, "source", &source) || source.empty() ||
            source.size() > 128) {
            metadataIncomplete = true;
            source.clear();
        } else if (sources.count(source) != 0 || sources.size() < kMaxMetadataKeys) {
            SourceStats& stats = sources[source];
            ++stats.records;
            std::uint64_t lost = 0;
            if (JsonStringField(record.payload, "lostRecords", &lostText) &&
                Decimal64(lostText, &lost))
                stats.lost = lost > (std::numeric_limits<std::uint64_t>::max)() - stats.lost
                    ? (std::numeric_limits<std::uint64_t>::max)() : stats.lost + lost;
        } else metadataIncomplete = true;

        JsonStringField(record.payload, "kind", &kind);
        if (kind == "coverage_gap" ||
            JsonStringField(record.payload, "lossReason", &lossReason)) {
            if (lossReason.empty()) lossReason = "coverage_gap";
            if (lossReason.size() > 128) lossReason.resize(128);
            if (gaps.count(lossReason) != 0 || gaps.size() < kMaxMetadataKeys)
                ++gaps[lossReason];
            else metadataIncomplete = true;
        }

        if (!JsonStringField(record.payload, "timebaseId", &timebase) ||
            timebase.empty() || timebase.size() > 128 ||
            !JsonStringField(record.payload, "occurredAtUtc", &utc) || utc.size() > 64 ||
            !JsonStringField(record.payload, "monotonicNs", &sourceNsText)) {
            metadataIncomplete = true;
            continue;
        }
        std::uint64_t sourceNs = 0;
        if (!Decimal64(sourceNsText, &sourceNs)) {
            metadataIncomplete = true;
            continue;
        }
        if (timebases.count(timebase) == 0 && timebases.size() >= kMaxMetadataKeys) {
            metadataIncomplete = true;
            continue;
        }
        TimebaseAnchors& anchors = timebases[timebase];
        if (anchors.firstUtc.empty() || sourceNs < anchors.firstNs) {
            anchors.firstNs = sourceNs;
            anchors.firstUtc = utc;
        }
        if (anchors.lastUtc.empty() || sourceNs >= anchors.lastNs) {
            anchors.lastNs = sourceNs;
            anchors.lastUtc = utc;
        }
        if (observedStartUtc.empty() || sourceNs < observedStartSourceNs) {
            observedStartSourceNs = sourceNs;
            observedStartUtc = utc;
        }
        if (observedEndUtc.empty() || sourceNs >= observedEndSourceNs) {
            observedEndSourceNs = sourceNs;
            observedEndUtc = utc;
        }
    }
    const auto machine = MachinePseudonym();
    std::string sourceJson = "[";
    for (const auto& entry : sources) {
        if (sourceJson.size() > 1) sourceJson += ',';
        sourceJson += "{\"source\":" + Quote(entry.first) +
            ",\"records\":" + std::to_string(entry.second.records) +
            ",\"lostRecords\":\"" + std::to_string(entry.second.lost) + "\"}";
    }
    sourceJson += ']';
    std::string gapJson = "[";
    for (const auto& entry : gaps) {
        if (gapJson.size() > 1) gapJson += ',';
        gapJson += "{\"reason\":" + Quote(entry.first) +
            ",\"records\":" + std::to_string(entry.second) + "}";
    }
    gapJson += ']';
    std::string timebaseJson = "[";
    for (const auto& entry : timebases) {
        if (timebaseJson.size() > 1) timebaseJson += ',';
        const TimebaseAnchors& anchors = entry.second;
        timebaseJson += "{\"id\":" + Quote(entry.first) +
            ",\"firstMonotonicNs\":\"" + std::to_string(anchors.firstNs) +
            "\",\"firstUtc\":" + Quote(anchors.firstUtc) +
            ",\"lastMonotonicNs\":\"" + std::to_string(anchors.lastNs) +
            "\",\"lastUtc\":" + Quote(anchors.lastUtc) + "}";
    }
    timebaseJson += ']';
    std::string value = "{\"schemaVersion\":1,\"buildVersion\":" +
        Quote(WINTCP_VERSION_STRING) + ",\"archiveId\":" + Quote(id) +
        ",\"incidentId\":" + Quote(incident.id) +
        ",\"complete\":true,\"replayReady\":" +
        std::string(checkpointCount == 0 ? "false" : "true") +
        ",\"replayUnavailableReason\":" + (checkpointCount == 0
            ? Quote("state_checkpoints_not_recorded") : "null") +
        ",\"machinePseudonym\":" +
            (machine.first.empty() ? "null" : Quote(machine.first)) +
        ",\"machinePseudonymUnavailableReason\":" +
            (machine.second.empty() ? "null" : Quote(machine.second)) +
        ",\"filters\":{\"scope\":\"all_observed_records\",\"process\":\"all\",\"transport\":\"all_supported\"}" +
        ",\"startMonotonicNs\":\"" + std::to_string(actualStartNs) +
        "\",\"requestedWindowStartMonotonicNs\":\"" +
            std::to_string(incident.startMonotonicNs) +
        "\",\"endMonotonicNs\":\"" + std::to_string(incident.endMonotonicNs) +
        "\",\"observedStartUtc\":" +
            (observedStartUtc.empty() ? "null" : Quote(observedStartUtc)) +
        ",\"observedEndUtc\":" +
            (observedEndUtc.empty() ? "null" : Quote(observedEndUtc)) +
        ",\"prehistoryWindowNs\":\"" +
            std::to_string(incident.prehistoryWindowNs) + "\",\"prehistoryRetainedNs\":\"" +
            std::to_string(incident.prehistoryRetainedNs) + "\",\"recordCount\":" +
            std::to_string(eventCount + checkpointCount) +
        ",\"eventCount\":" + std::to_string(eventCount) +
        ",\"checkpointCount\":" + std::to_string(checkpointCount) +
        ",\"checkpointStateComplete\":" +
            std::string(checkpointStateComplete ? "true" : "false") +
        ",\"sourceCoverage\":" + sourceJson +
        ",\"coverageGaps\":" + gapJson +
        ",\"timebaseMappings\":" + timebaseJson +
        ",\"sourceMetadataIncomplete\":" +
            std::string(metadataIncomplete ? "true" : "false") +
        ",\"prehistoryIncomplete\":" +
            std::string(incident.prehistoryIncomplete ? "true" : "false") +
        ",\"postWindowIncomplete\":" +
            (incident.postWindowIncomplete ? "true" : "false") +
        ",\"recordsTruncated\":" +
            (incident.recordsTruncated ? "true" : "false") +
        ",\"triggersTruncated\":" +
            (incident.triggersTruncated ? "true" : "false") +
        ",\"lostRecords\":\"" + std::to_string(incident.lostRecords) +
        "\",\"lostTriggers\":\"" + std::to_string(incident.lostTriggers) +
        "\",\"eventBytes\":" + std::to_string(eventBytes) +
        ",\"checkpointBytes\":" + std::to_string(checkpointBytes) +
        ",\"sha256\":{\"events.ndjson\":" + Quote(eventHash) +
        ",\"checkpoints.ndjson\":" + Quote(checkpointHash) +
        ",\"index.json\":" + Quote(indexHash) + "},\"triggers\":[";
    for (std::size_t i = 0; i < incident.triggers.size(); ++i) {
        if (i != 0) value += ',';
        const IncidentTrigger& trigger = incident.triggers[i];
        value += "{\"monotonicNs\":\"" +
            std::to_string(trigger.monotonicNs) + "\",\"id\":" +
            Quote(trigger.id) + ",\"reason\":" + Quote(trigger.reason) + "}";
    }
    return value + "]}";
}

}  // namespace

bool PlanIncidentArchiveRetention(
    const std::vector<IncidentArchiveRetentionCandidate>& candidates,
    std::uint64_t addedBytes, std::size_t maxCount, std::uint64_t maxBytes,
    std::vector<std::size_t>* removeIndices, std::string* error) {
    if (removeIndices == nullptr || error == nullptr || maxCount == 0 ||
        maxBytes == 0 || addedBytes > maxBytes) {
        if (error != nullptr) *error = "incident_archive_size_limit";
        return false;
    }
    removeIndices->clear();
    std::uint64_t total = 0;
    for (const auto& candidate : candidates) {
        if (total > (std::numeric_limits<std::uint64_t>::max)() - candidate.bytes) {
            *error = "incident_archive_size_overflow";
            return false;
        }
        total += candidate.bytes;
    }
    while (candidates.size() - removeIndices->size() >= maxCount ||
           total > maxBytes - addedBytes) {
        std::size_t oldest = candidates.size();
        for (std::size_t i = 0; i < candidates.size(); ++i) {
            const auto& candidate = candidates[i];
            if (candidate.pinned || std::find(removeIndices->begin(),
                removeIndices->end(), i) != removeIndices->end()) continue;
            if (oldest == candidates.size() ||
                candidate.createdOrder < candidates[oldest].createdOrder ||
                (candidate.createdOrder == candidates[oldest].createdOrder && i < oldest))
                oldest = i;
        }
        if (oldest == candidates.size()) {
            removeIndices->clear();
            *error = "incident_archive_quota_pinned";
            return false;
        }
        removeIndices->push_back(oldest);
        total -= (std::min)(total, candidates[oldest].bytes);
    }
    std::sort(removeIndices->begin(), removeIndices->end());
    error->clear();
    return true;
}

bool SaveIncidentArchive(const std::wstring& root,
                         const SECURITY_ATTRIBUTES& security,
                         const IncidentSnapshot& incident,
                         std::string* archiveId, std::string* error) {
    if (archiveId == nullptr || error == nullptr || incident.id.empty() ||
        incident.active) {
        if (error != nullptr) *error = "incident_not_finalized";
        return false;
    }
    if (!SafeDirectory(root)) {
        *error = "incident_archive_directory_unavailable";
        return false;
    }
    if (incident.records.size() > 1000000 || incident.triggers.size() > 256) {
        *error = "incident_archive_limit";
        return false;
    }
    std::string id;
    if (!RandomHex(&id)) {
        *error = "incident_archive_id_failed";
        return false;
    }
    const std::wstring finalDirectory = root + L"\\incident-" +
        std::wstring(id.begin(), id.end());
    const std::wstring tempDirectory = root + L"\\.tmp-" +
        std::wstring(id.begin(), id.end());
    if (!::CreateDirectoryW(tempDirectory.c_str(),
                            const_cast<SECURITY_ATTRIBUTES*>(&security))) {
        *error = "incident_archive_directory_failed";
        return false;
    }

    std::string events, checkpoints;
    std::string eventOffsets = "[", checkpointOffsets = "[";
    std::size_t eventCount = 0, checkpointCount = 0;
    bool checkpointStateComplete = true;
    for (const IncidentRecord& record : incident.records) {
        const bool checkpoint = record.eventId == "state_checkpoint";
        std::string& output = checkpoint ? checkpoints : events;
        std::size_t& count = checkpoint ? checkpointCount : eventCount;
        std::string& offsets = checkpoint ? checkpointOffsets : eventOffsets;
        if (count % 100 == 0) {
            if (count != 0) offsets += ',';
            offsets += std::to_string(output.size());
        }
        output += "{\"captureMonotonicNs\":\"" +
            std::to_string(record.monotonicNs) + "\",\"eventId\":" +
            Quote(record.eventId) + ",\"event\":" + record.payload + "}\n";
        ++count;
        if (checkpoint && record.payload.find("\"complete\":false") !=
                               std::string::npos)
            checkpointStateComplete = false;
        if (events.size() + checkpoints.size() >
            IncidentRecorderModel::kDefaultBudgetBytes) {
            RemoveTemporary(tempDirectory);
            *error = "incident_archive_size_limit";
            return false;
        }
    }
    eventOffsets += ']';
    checkpointOffsets += ']';
    const std::string offsets = "{\"events\":" + eventOffsets +
        ",\"checkpoints\":" + checkpointOffsets + "}";
    std::string eventHash, checkpointHash, indexHash;
    if (!Hash(events, &eventHash) || !Hash(checkpoints, &checkpointHash) ||
        !Hash(offsets, &indexHash)) {
        RemoveTemporary(tempDirectory);
        *error = "incident_archive_hash_failed";
        return false;
    }
    const std::string manifest = Manifest(incident, id, eventCount,
        checkpointCount, events.size(), checkpoints.size(),
        checkpointCount != 0 && checkpointStateComplete, eventHash,
        checkpointHash, indexHash);
    const std::uint64_t addedBytes = static_cast<std::uint64_t>(events.size()) +
        checkpoints.size() + offsets.size() + manifest.size();
    const std::wstring base = tempDirectory + L"\\";
    const bool written = WriteFile(base + L"events.ndjson", events, security) &&
        WriteFile(base + L"checkpoints.ndjson", checkpoints, security) &&
        WriteFile(base + L"index.json", offsets, security) &&
        WriteFile(base + L"manifest.json", manifest, security);
    if (!written) {
        RemoveTemporary(tempDirectory);
        *error = "incident_archive_finalize_failed";
        return false;
    }
    if (!MakeArchiveQuotaRoom(root, addedBytes, error)) {
        RemoveTemporary(tempDirectory);
        return false;
    }
    if (!::MoveFileExW(tempDirectory.c_str(), finalDirectory.c_str(),
                       MOVEFILE_WRITE_THROUGH)) {
        RemoveTemporary(tempDirectory);
        *error = "incident_archive_finalize_failed";
        return false;
    }
    *archiveId = id;
    error->clear();
    return true;
}

bool SetIncidentArchivePinned(const std::wstring& root, const std::string& id,
                              bool pinned, const SECURITY_ATTRIBUTES& security,
                              std::string* error) {
    if (error == nullptr || !SafeDirectory(root) || !SafeArchiveId(id)) {
        if (error != nullptr) *error = "invalid_incident_archive_id";
        return false;
    }
    const std::wstring directory = root + L"\\incident-" +
        std::wstring(id.begin(), id.end());
    std::string manifest, events, checkpoints, index;
    if (!ReadManifest(directory, id, &manifest) ||
        !VerifyArchiveFiles(directory, manifest, &events, &checkpoints, &index)) {
        *error = "incident_archive_not_found_or_invalid";
        return false;
    }
    bool current = false;
    if (!ReadPinned(directory, &current, error)) return false;
    if (current == pinned) {
        error->clear();
        return true;
    }
    const std::wstring pinPath = directory + L"\\pinned.txt";
    if (pinned) {
        if (!WriteFile(pinPath, "WinTCP-Incident-Pin:1\n", security)) {
            *error = "incident_pin_write_failed";
            return false;
        }
    } else {
        const DWORD attributes = ::GetFileAttributesW(pinPath.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES ||
            (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
            !::DeleteFileW(pinPath.c_str())) {
            *error = "incident_pin_write_failed";
            return false;
        }
    }
    error->clear();
    return true;
}

std::vector<IncidentArchiveInfo> ListIncidentArchives(
    const std::wstring& root, std::size_t limit, std::string* error) {
    std::vector<IncidentArchiveInfo> archives;
    if (error == nullptr || limit == 0 || limit > 100) {
        if (error != nullptr) *error = "invalid_archive_limit";
        return archives;
    }
    if (!SafeDirectory(root)) {
        *error = "incident_archive_directory_unavailable";
        return archives;
    }
    WIN32_FIND_DATAW found = {};
    HANDLE search = ::FindFirstFileW((root + L"\\incident-*").c_str(), &found);
    if (search == INVALID_HANDLE_VALUE) {
        const DWORD code = ::GetLastError();
        if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND) {
            error->clear();
            return archives;
        }
        *error = "incident_archive_list_failed";
        return archives;
    }
    do {
        if ((found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
            (found.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) continue;
        const std::wstring name(found.cFileName);
        const std::wstring prefix = L"incident-";
        if (name.size() != prefix.size() + 32 || name.compare(0, prefix.size(), prefix) != 0)
            continue;
        std::string id;
        id.reserve(32);
        for (std::size_t i = prefix.size(); i < name.size(); ++i) {
            if (name[i] > 0x7f) { id.clear(); break; }
            id.push_back(static_cast<char>(name[i]));
        }
        if (!SafeArchiveId(id)) continue;
        std::string manifest;
        const std::wstring directory = root + L"\\" + name;
        bool pinned = false;
        std::uint64_t bytes = 0;
        if (!ReadManifest(directory, id, &manifest) ||
            !ArchiveContentsSafe(directory, error) ||
            !ArchiveFileBytes(directory, &bytes, error) ||
            !ReadPinned(directory, &pinned, error)) {
            ::FindClose(search);
            archives.clear();
            if (error->empty()) *error = "incident_archive_inventory_invalid";
            return archives;
        }
        const std::uint64_t created =
            (static_cast<std::uint64_t>(found.ftCreationTime.dwHighDateTime) << 32) |
            found.ftCreationTime.dwLowDateTime;
        archives.push_back({id, std::move(manifest), bytes, pinned, created});
    } while (::FindNextFileW(search, &found));
    const DWORD finalError = ::GetLastError();
    ::FindClose(search);
    if (finalError != ERROR_NO_MORE_FILES) {
        *error = "incident_archive_list_incomplete";
        return {};
    }
    std::sort(archives.begin(), archives.end(),
        [](const IncidentArchiveInfo& left, const IncidentArchiveInfo& right) {
            if (left.createdFileTime != right.createdFileTime)
                return left.createdFileTime > right.createdFileTime;
            return left.id > right.id;
        });
    if (archives.size() > limit) archives.resize(limit);
    error->clear();
    return archives;
}

IncidentArchivePage ReadIncidentArchivePage(const std::wstring& root,
    const std::string& id, std::size_t offset, std::size_t limit,
    std::size_t maxResponseBytes) {
    IncidentArchivePage page;
    if (!SafeDirectory(root) || !SafeArchiveId(id) || offset > 1000000 || limit == 0 || limit > 100 ||
        maxResponseBytes == 0) {
        page.error = "invalid_archive_page";
        return page;
    }
    const std::wstring directory = root + L"\\incident-" +
        std::wstring(id.begin(), id.end());
    if (!ReadManifest(directory, id, &page.manifestJson)) {
        page.error = "incident_archive_not_found_or_invalid";
        return page;
    }
    std::string events, checkpoints, index;
    if (!VerifyArchiveFiles(directory, page.manifestJson,
                            &events, &checkpoints, &index)) {
        page.error = "incident_archive_integrity_failed";
        return page;
    }
    std::size_t recordIndex = 0;
    std::size_t responseBytes = 0;
    bool responseFull = false;
    const auto appendLines = [&](const std::string& content) {
        std::size_t cursor = 0;
        while (cursor < content.size()) {
            const std::size_t end = content.find('\n', cursor);
            if (end == std::string::npos) return false;
            const std::size_t bytes = end - cursor;
            if (recordIndex >= offset && page.records.size() < limit &&
                !responseFull) {
                if (bytes > maxResponseBytes -
                    (std::min)(responseBytes, maxResponseBytes)) {
                    if (page.records.empty()) page.error = "incident_record_too_large";
                    responseFull = true;
                } else {
                    page.records.push_back(content.substr(cursor, bytes));
                    responseBytes += bytes;
                }
            }
            ++recordIndex;
            cursor = end + 1;
        }
        return true;
    };
    const bool linesValid = appendLines(events) && appendLines(checkpoints);
    if (!linesValid && page.error.empty()) page.error = "incident_archive_integrity_failed";
    if (!page.error.empty()) return page;
    page.totalRecords = recordIndex;
    if (offset > recordIndex) {
        page.error = "invalid_archive_offset";
        page.records.clear();
        return page;
    }
    page.nextOffset = offset + page.records.size();
    page.hasMore = page.nextOffset < recordIndex;
    return page;
}

}  // namespace wintcp
