// IncidentArchive.cpp
// SPDX-License-Identifier: Apache-2.0
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>

#include "IncidentArchive.h"
#include "NetworkEvents.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
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
        !ReadFileBounded(directory + L"\\checkpoints.ndjson", 1024 * 1024,
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
    std::size_t start = 0;
    while (start < events->size()) {
        const std::size_t end = events->find('\n', start);
        if (end == std::string::npos || end == start ||
            !JsonParser(events->substr(start, end - start)).Object()) return false;
        start = end + 1;
    }
    return true;
}

std::string Manifest(const IncidentSnapshot& incident, const std::string& id,
                     std::size_t eventBytes, const std::string& eventHash,
                     const std::string& checkpointHash,
                     const std::string& indexHash) {
    std::string value = "{\"schemaVersion\":1,\"archiveId\":" + Quote(id) +
        ",\"incidentId\":" + Quote(incident.id) +
        ",\"complete\":true,\"replayReady\":false," +
        "\"replayUnavailableReason\":\"state_checkpoints_not_yet_recorded\"," +
        "\"startMonotonicNs\":\"" +
            std::to_string(incident.startMonotonicNs) + "\",\"endMonotonicNs\":\"" +
            std::to_string(incident.endMonotonicNs) + "\",\"recordCount\":" +
            std::to_string(incident.records.size()) +
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

    std::string events;
    std::string offsets = "[";
    std::size_t nextIndex = 0;
    for (std::size_t i = 0; i < incident.records.size(); ++i) {
        if (i % 100 == 0) {
            if (nextIndex != 0) offsets += ',';
            offsets += std::to_string(events.size());
            ++nextIndex;
        }
        const IncidentRecord& record = incident.records[i];
        events += "{\"captureMonotonicNs\":\"" +
            std::to_string(record.monotonicNs) + "\",\"eventId\":" +
            Quote(record.eventId) + ",\"event\":" + record.payload + "}\n";
        if (events.size() > IncidentRecorderModel::kDefaultBudgetBytes) {
            RemoveTemporary(tempDirectory);
            *error = "incident_archive_size_limit";
            return false;
        }
    }
    offsets += "]";
    const std::string checkpoints = "";
    std::string eventHash, checkpointHash, indexHash;
    if (!Hash(events, &eventHash) || !Hash(checkpoints, &checkpointHash) ||
        !Hash(offsets, &indexHash)) {
        RemoveTemporary(tempDirectory);
        *error = "incident_archive_hash_failed";
        return false;
    }
    const std::string manifest = Manifest(incident, id, events.size(), eventHash,
                                          checkpointHash, indexHash);
    const std::wstring base = tempDirectory + L"\\";
    const bool written = WriteFile(base + L"events.ndjson", events, security) &&
        WriteFile(base + L"checkpoints.ndjson", checkpoints, security) &&
        WriteFile(base + L"index.json", offsets, security) &&
        WriteFile(base + L"manifest.json", manifest, security);
    if (!written || !::MoveFileExW(tempDirectory.c_str(), finalDirectory.c_str(),
                                   MOVEFILE_WRITE_THROUGH)) {
        RemoveTemporary(tempDirectory);
        *error = "incident_archive_finalize_failed";
        return false;
    }
    *archiveId = id;
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
        if (!ReadManifest(root + L"\\" + name, id, &manifest)) continue;
        archives.push_back({id, std::move(manifest)});
    } while (::FindNextFileW(search, &found));
    const DWORD finalError = ::GetLastError();
    ::FindClose(search);
    if (finalError != ERROR_NO_MORE_FILES) {
        *error = "incident_archive_list_incomplete";
        return {};
    }
    std::sort(archives.begin(), archives.end(),
        [](const IncidentArchiveInfo& left, const IncidentArchiveInfo& right) {
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
    std::size_t cursor = 0;
    std::size_t recordIndex = 0;
    std::size_t responseBytes = 0;
    while (cursor < events.size()) {
        const std::size_t end = events.find('\n', cursor);
        const std::size_t bytes = end - cursor;
        if (recordIndex >= offset && page.records.size() < limit) {
            if (bytes > maxResponseBytes - (std::min)(responseBytes, maxResponseBytes)) {
                if (page.records.empty()) page.error = "incident_record_too_large";
                break;
            }
            page.records.push_back(events.substr(cursor, bytes));
            responseBytes += bytes;
        }
        ++recordIndex;
        cursor = end + 1;
        if (page.records.size() == limit) break;
    }
    if (!page.error.empty()) return page;
    if (offset > recordIndex && cursor >= events.size()) {
        page.error = "invalid_archive_offset";
        page.records.clear();
        return page;
    }
    page.nextOffset = offset + page.records.size();
    page.hasMore = page.nextOffset < recordIndex || cursor < events.size();
    return page;
}

}  // namespace wintcp
