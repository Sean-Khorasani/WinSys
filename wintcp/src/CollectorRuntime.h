// CollectorRuntime.h
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <string>
#include <functional>
#include <cstdint>
#include <vector>

namespace wintcp {

// Explicit elevated process mode. Normal CLI, GUI and Web UI startup never
// launches this helper or asks Windows for administrator rights.
int RunCollectorCommand(int argc, wchar_t** argv);
int RunRestrictCommand(int argc, wchar_t** argv);
bool CollectorStart(std::string* error);
bool CollectorStop(std::string* error);
bool CollectorStatus(std::string* response);
bool CollectorOperationValid(const std::string& action,
                             const std::string& payload);
bool CollectorExecuteOperation(const std::string& action,
                               const std::string& payload,
                               std::string* result, std::string* error,
                               const std::function<bool()>& cancelled = {});
bool CollectorRestrictionPreview(const std::string& imagePath,
                                 const std::string& remoteAddress,
                                 unsigned remotePort,
                                 const std::string& protocol,
                                 unsigned minutes,
                                 std::string* response);
bool CollectorRestrictionApply(const std::string& token,
                               std::string* response);
bool CollectorRestrictionList(std::string* response);
bool CollectorRestrictionRelease(const std::string& id,
                                 std::string* response);
bool CollectorRestrictionReleaseAll(std::string* response);
struct CollectorChangesPage {
    std::vector<std::string> items;
    std::string nextCursor;
    std::uint64_t lostRecords = 0;
    bool cursorExpired = false;
};
bool CollectorRestrictionChanges(const std::string& cursor,
                                 CollectorChangesPage* page);
bool CollectorLifecycleEvents(const std::string& cursor,
                               CollectorChangesPage* page);

}  // namespace wintcp
