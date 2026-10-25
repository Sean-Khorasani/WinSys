// IncidentArchive.h
// SPDX-License-Identifier: Apache-2.0
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

#include "IncidentRecorderModel.h"

namespace wintcp {

// Writes a finalized incident as a self-contained, same-volume directory.
// The directory is exposed only after every file has been flushed and the
// temporary directory has been renamed to its generated final name.
bool SaveIncidentArchive(const std::wstring& root,
                         const SECURITY_ATTRIBUTES& security,
                         const IncidentSnapshot& incident,
                         std::string* archiveId, std::string* error);

struct IncidentArchiveInfo {
    std::string id;
    std::string manifestJson;
    std::uint64_t bytes = 0;
    bool pinned = false;
    std::uint64_t createdFileTime = 0;
};

struct IncidentArchivePage {
    std::string manifestJson;
    std::vector<std::string> records;
    std::size_t totalRecords = 0;
    std::size_t nextOffset = 0;
    bool hasMore = false;
    std::string error;
};

struct IncidentArchiveRetentionCandidate {
    std::uint64_t createdOrder = 0;
    std::uint64_t bytes = 0;
    bool pinned = false;
};

// Pure quota planner shared by the archive writer and dev fixtures. Returned
// indices refer to candidates in input order; no filesystem mutation occurs.
bool PlanIncidentArchiveRetention(
    const std::vector<IncidentArchiveRetentionCandidate>& candidates,
    std::uint64_t addedBytes, std::size_t maxCount, std::uint64_t maxBytes,
    std::vector<std::size_t>* removeIndices, std::string* error);

std::vector<IncidentArchiveInfo> ListIncidentArchives(
    const std::wstring& root, std::size_t limit, std::string* error);
bool SetIncidentArchivePinned(const std::wstring& root, const std::string& id,
                              bool pinned, const SECURITY_ATTRIBUTES& security,
                              std::string* error);
IncidentArchivePage ReadIncidentArchivePage(const std::wstring& root,
    const std::string& id, std::size_t offset, std::size_t limit,
    std::size_t maxResponseBytes);

}  // namespace wintcp
