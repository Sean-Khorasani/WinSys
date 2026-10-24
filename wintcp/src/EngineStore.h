// EngineStore.h
// SPDX-License-Identifier: Apache-2.0
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace wintcp {

struct EngineStorePage {
    std::vector<std::string> items;  // validated, serialized JSON records
    std::string nextCursor;
    bool cursorExpired = false;
    bool partialTail = false;
    std::string error;
};

// Two bounded NDJSON segments. Only the engine owner thread writes a store;
// readers may open the files with FILE_SHARE_READ. A torn final line is
// separated on reopen so that it cannot corrupt a subsequent valid record.
class EngineStore {
public:
    EngineStore() = default;
    ~EngineStore();
    EngineStore(const EngineStore&) = delete;
    EngineStore& operator=(const EngineStore&) = delete;

    bool Open(const std::wstring& directory, const std::wstring& stem,
              std::uint64_t segmentBytes, const SECURITY_ATTRIBUTES& security,
              std::string* error);
    bool Append(const std::vector<std::string>& lines, std::size_t* written,
                std::string* error);
    EngineStorePage Read(const std::string& cursor, std::size_t limit,
                         std::size_t maxResponseBytes) const;
    std::uint64_t Rollovers() const { return rollovers_; }

private:
    bool Rotate(std::string* error);
    bool WriteLine(const std::string& line, std::string* error);
    HANDLE file_ = INVALID_HANDLE_VALUE;
    std::wstring currentPath_;
    std::wstring previousPath_;
    SECURITY_ATTRIBUTES security_ = {};
    std::uint64_t segmentBytes_ = 0;
    std::uint64_t usedBytes_ = 0;
    std::uint64_t rollovers_ = 0;
};

}  // namespace wintcp
