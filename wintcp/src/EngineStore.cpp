// EngineStore.cpp
// SPDX-License-Identifier: Apache-2.0
#include "EngineStore.h"

#include <algorithm>
#include <cstdio>
#include <limits>

namespace wintcp {
namespace {

constexpr std::size_t kMaxLineBytes = 128 * 1024;

bool ValidStem(const std::wstring& stem) {
    if (stem.empty() || stem.size() > 32) return false;
    for (wchar_t c : stem) {
        if ((c < L'a' || c > L'z') && c != L'-') return false;
    }
    return true;
}

bool WriteAll(HANDLE file, const char* bytes, DWORD length) {
    while (length != 0) {
        DWORD written = 0;
        if (!::WriteFile(file, bytes, length, &written, nullptr) || written == 0)
            return false;
        bytes += written;
        length -= written;
    }
    return true;
}

struct Reader {
    HANDLE file = INVALID_HANDLE_VALUE;
    std::string id;
    std::uint64_t size = 0;
    ~Reader() { if (file != INVALID_HANDLE_VALUE) ::CloseHandle(file); }
};

bool OpenReader(const std::wstring& path, Reader* reader,
                std::string* error) {
    reader->file = ::CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (reader->file == INVALID_HANDLE_VALUE) {
        if (::GetLastError() == ERROR_FILE_NOT_FOUND) return true;
        *error = "history_open_failed";
        return false;
    }
    BY_HANDLE_FILE_INFORMATION info = {};
    if (!::GetFileInformationByHandle(reader->file, &info)) {
        *error = "history_stat_failed";
        return false;
    }
    if ((info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT |
                                  FILE_ATTRIBUTE_DIRECTORY)) != 0) {
        *error = "history_file_invalid";
        return false;
    }
    reader->size = (static_cast<std::uint64_t>(info.nFileSizeHigh) << 32) |
                   info.nFileSizeLow;
    char id[25] = {};
    std::snprintf(id, sizeof(id), "%08lx%08lx%08lx",
                  static_cast<unsigned long>(info.dwVolumeSerialNumber),
                  static_cast<unsigned long>(info.nFileIndexHigh),
                  static_cast<unsigned long>(info.nFileIndexLow));
    reader->id = id;
    return true;
}

bool ParseCursor(const std::string& cursor, std::string* id,
                 std::uint64_t* offset) {
    if (cursor.size() < 26 || cursor.size() > 45 || cursor[24] != ':')
        return false;
    for (std::size_t i = 0; i < 24; ++i)
        if ((cursor[i] < '0' || cursor[i] > '9') &&
            (cursor[i] < 'a' || cursor[i] > 'f')) return false;
    std::uint64_t value = 0;
    for (std::size_t i = 25; i < cursor.size(); ++i) {
        const char digit = cursor[i];
        if (digit < '0' || digit > '9') return false;
        const unsigned number = static_cast<unsigned>(digit - '0');
        if (value > ((std::numeric_limits<std::uint64_t>::max)() - number) / 10)
            return false;
        value = value * 10 + number;
    }
    *id = cursor.substr(0, 24);
    *offset = value;
    return true;
}

std::string Cursor(const Reader& reader, std::uint64_t offset) {
    return reader.id + ':' + std::to_string(offset);
}

// Returns false when a page boundary or an incomplete current tail stops
// reading. A malformed complete line is reported, never silently skipped.
bool ReadSegment(const Reader& reader, bool current, std::uint64_t* offset,
                 std::size_t limit, std::size_t maxResponseBytes,
                 EngineStorePage* page) {
    constexpr DWORD kReadBytes = 512 * 1024;
    for (const std::string& existing : page->items)
        maxResponseBytes -= existing.size() + 1;
    while (*offset < reader.size && page->items.size() < limit) {
        LARGE_INTEGER at = {};
        at.QuadPart = static_cast<LONGLONG>(*offset);
        const DWORD wanted = static_cast<DWORD>((std::min)(
            static_cast<std::uint64_t>(kReadBytes), reader.size - *offset));
        std::string buffer(wanted, '\0');
        DWORD read = 0;
        if (!::SetFilePointerEx(reader.file, at, nullptr, FILE_BEGIN) ||
            !::ReadFile(reader.file, &buffer[0], wanted, &read, nullptr) ||
            read == 0) {
            page->error = "history_read_failed";
            return false;
        }
        buffer.resize(read);
        std::size_t position = 0;
        while (position < buffer.size() && page->items.size() < limit) {
            const std::size_t end = buffer.find('\n', position);
            if (end == std::string::npos) {
                if (position != 0 &&
                    reader.size - (*offset + position) >
                        buffer.size() - position &&
                    buffer.size() - position <= kMaxLineBytes) {
                    break;
                }
                if (!current || reader.size - *offset > buffer.size() ||
                    buffer.size() - position > kMaxLineBytes)
                    page->error = "history_record_incomplete";
                else page->partialTail = true;
                page->nextCursor = Cursor(reader, *offset + position);
                return false;
            }
            const std::size_t length = end - position;
            const std::string line = buffer.substr(position, length);
            if (length == 0 || length > kMaxLineBytes ||
                line.find('\0') != std::string::npos ||
                line.rfind("{\"schemaVersion\":1,", 0) != 0 ||
                line.back() != '}') {
                page->error = "history_record_invalid";
                page->nextCursor = Cursor(reader, *offset + position);
                return false;
            }
            if (page->items.size() != 0 &&
                maxResponseBytes < line.size() + 256) {
                page->nextCursor = Cursor(reader, *offset + position);
                page->hasMore = true;
                return false;
            }
            if (line.size() + 256 > maxResponseBytes) {
                page->error = "history_record_too_large";
                page->nextCursor = Cursor(reader, *offset + position);
                return false;
            }
            page->items.push_back(line);
            maxResponseBytes -= line.size() + 1;
            position = end + 1;
        }
        *offset += position;
    }
    page->nextCursor = Cursor(reader, *offset);
    page->hasMore = *offset < reader.size;
    return !page->hasMore;
}

}  // namespace

EngineStore::~EngineStore() {
    if (file_ != INVALID_HANDLE_VALUE) ::CloseHandle(file_);
}

bool EngineStore::Open(const std::wstring& directory, const std::wstring& stem,
                       std::uint64_t segmentBytes,
                       const SECURITY_ATTRIBUTES& security,
                       std::string* error) {
    if (file_ != INVALID_HANDLE_VALUE || !ValidStem(stem) ||
        segmentBytes < kMaxLineBytes * 2 || segmentBytes > 32ULL * 1024 * 1024 ||
        security.lpSecurityDescriptor == nullptr) {
        if (error != nullptr) *error = "invalid_store_configuration";
        return false;
    }
    currentPath_ = directory + L"\\" + stem + L"-current.ndjson";
    previousPath_ = directory + L"\\" + stem + L"-previous.ndjson";
    security_ = security;
    segmentBytes_ = segmentBytes;
    WIN32_FILE_ATTRIBUTE_DATA previous = {};
    if (::GetFileAttributesExW(previousPath_.c_str(), GetFileExInfoStandard,
                               &previous)) {
        const std::uint64_t length =
            (static_cast<std::uint64_t>(previous.nFileSizeHigh) << 32) |
            previous.nFileSizeLow;
        if ((previous.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
            (previous.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
            length > segmentBytes_) {
            if (error != nullptr) *error = "store_previous_invalid";
            return false;
        }
    } else if (::GetLastError() != ERROR_FILE_NOT_FOUND) {
        if (error != nullptr) *error = "store_previous_stat_failed";
        return false;
    }
    const DWORD currentAttributes = ::GetFileAttributesW(currentPath_.c_str());
    if (currentAttributes != INVALID_FILE_ATTRIBUTES &&
        (currentAttributes & (FILE_ATTRIBUTE_REPARSE_POINT |
                              FILE_ATTRIBUTE_DIRECTORY)) != 0) {
        if (error != nullptr) *error = "store_current_invalid";
        return false;
    }
    file_ = ::CreateFileW(currentPath_.c_str(), FILE_APPEND_DATA | GENERIC_READ,
                          FILE_SHARE_READ, &security_, OPEN_ALWAYS,
                          FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file_ == INVALID_HANDLE_VALUE) {
        if (error != nullptr) *error = "store_open_failed";
        return false;
    }
    LARGE_INTEGER size = {};
    if (!::GetFileSizeEx(file_, &size) || size.QuadPart < 0) {
        if (error != nullptr) *error = "store_size_failed";
        ::CloseHandle(file_);
        file_ = INVALID_HANDLE_VALUE;
        return false;
    }
    usedBytes_ = static_cast<std::uint64_t>(size.QuadPart);
    if (usedBytes_ > segmentBytes_) {
        if (error != nullptr) *error = "store_current_oversized";
        return false;
    }
    if (usedBytes_ >= segmentBytes_) return Rotate(error);
    if (usedBytes_ != 0) {
        LARGE_INTEGER offset = {};
        offset.QuadPart = static_cast<LONGLONG>(usedBytes_ - 1);
        char last = 0;
        DWORD read = 0;
        if (!::SetFilePointerEx(file_, offset, nullptr, FILE_BEGIN) ||
            !::ReadFile(file_, &last, 1, &read, nullptr) || read != 1) {
            if (error != nullptr) *error = "store_tail_read_failed";
            return false;
        }
        if (last != '\n') {
            if (usedBytes_ + 1 > segmentBytes_) return Rotate(error);
            if (!WriteAll(file_, "\n", 1)) {
                if (error != nullptr) *error = "store_tail_repair_failed";
                return false;
            }
            ++usedBytes_;
        }
    }
    if (error != nullptr) error->clear();
    return true;
}

bool EngineStore::Rotate(std::string* error) {
    if (file_ != INVALID_HANDLE_VALUE) {
        ::CloseHandle(file_);
        file_ = INVALID_HANDLE_VALUE;
    }
    if (!::MoveFileExW(currentPath_.c_str(), previousPath_.c_str(),
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        if (error != nullptr) *error = "store_rotate_failed";
        return false;
    }
    file_ = ::CreateFileW(currentPath_.c_str(), FILE_APPEND_DATA | GENERIC_READ,
                          FILE_SHARE_READ, &security_, CREATE_NEW,
                          FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file_ == INVALID_HANDLE_VALUE) {
        if (error != nullptr) *error = "store_reopen_failed";
        return false;
    }
    usedBytes_ = 0;
    ++rollovers_;
    return true;
}

bool EngineStore::WriteLine(const std::string& line, std::string* error) {
    if (file_ == INVALID_HANDLE_VALUE) {
        if (error != nullptr) *error = "store_unavailable";
        return false;
    }
    if (line.empty() || line.size() > kMaxLineBytes ||
        line.find_first_of("\r\n\0", 0, 3) != std::string::npos) {
        if (error != nullptr) *error = "invalid_store_record";
        return false;
    }
    if (usedBytes_ + line.size() + 1 > segmentBytes_ && !Rotate(error))
        return false;
    const std::string record = line + '\n';
    if (!WriteAll(file_, record.data(), static_cast<DWORD>(record.size()))) {
        if (error != nullptr) *error = "store_write_failed";
        ::CloseHandle(file_);
        file_ = INVALID_HANDLE_VALUE;
        return false;
    }
    usedBytes_ += record.size();
    return true;
}

bool EngineStore::Append(const std::vector<std::string>& lines,
                         std::size_t* written, std::string* error) {
    if (written != nullptr) *written = 0;
    if (error != nullptr) error->clear();
    for (const std::string& line : lines) {
        if (!WriteLine(line, error)) return false;
        if (written != nullptr) ++*written;
    }
    if (!lines.empty() && !::FlushFileBuffers(file_)) {
        if (error != nullptr) *error = "store_flush_failed";
        ::CloseHandle(file_);
        file_ = INVALID_HANDLE_VALUE;
        return false;
    }
    return true;
}

EngineStorePage EngineStore::Read(const std::string& cursor, std::size_t limit,
                                  std::size_t maxResponseBytes) const {
    EngineStorePage page;
    if (limit == 0 || limit > 500 || maxResponseBytes < kMaxLineBytes + 256) {
        page.error = "history_bad_limit";
        return page;
    }
    Reader previous;
    Reader current;
    if (!OpenReader(previousPath_, &previous, &page.error) ||
        !OpenReader(currentPath_, &current, &page.error)) return page;
    if (current.file == INVALID_HANDLE_VALUE) {
        page.error = "history_current_missing";
        return page;
    }
    Reader* start = previous.file != INVALID_HANDLE_VALUE ? &previous : &current;
    std::uint64_t offset = 0;
    if (!cursor.empty()) {
        std::string id;
        if (!ParseCursor(cursor, &id, &offset)) {
            page.cursorExpired = true;
            return page;
        }
        if (id == current.id) start = &current;
        else if (previous.file != INVALID_HANDLE_VALUE && id == previous.id)
            start = &previous;
        else {
            page.cursorExpired = true;
            return page;
        }
        if (offset > start->size) {
            page.cursorExpired = true;
            return page;
        }
    }
    if (!ReadSegment(*start, start == &current, &offset, limit,
                     maxResponseBytes, &page) || !page.error.empty()) return page;
    if (start == &previous && page.items.size() < limit) {
        offset = 0;
        if (!ReadSegment(current, true, &offset, limit, maxResponseBytes,
                         &page)) return page;
    } else if (start == &previous && current.size != 0) {
        page.hasMore = true;
    }
    return page;
}

}  // namespace wintcp
