// IncidentArchive.h
// SPDX-License-Identifier: Apache-2.0
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

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
};

struct IncidentArchivePage {
    std::string manifestJson;
    std::vector<std::string> records;
    std::size_t nextOffset = 0;
    bool hasMore = false;
    std::string error;
};

std::vector<IncidentArchiveInfo> ListIncidentArchives(
    const std::wstring& root, std::size_t limit, std::string* error);
IncidentArchivePage ReadIncidentArchivePage(const std::wstring& root,
    const std::string& id, std::size_t offset, std::size_t limit,
    std::size_t maxResponseBytes);

}  // namespace wintcp
