// EngineConfig.h
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <string>

namespace wintcp {

struct EngineConfig {
    unsigned snapshotIntervalMs = 1000;
    std::size_t maxEventRecords = 16384;
    std::size_t maxEventBytes = 64 * 1024 * 1024;
};

// Strict versioned ASCII format. Unknown, repeated, or out-of-range fields
// are errors; a damaged policy is never treated as an empty default policy.
std::string FormatEngineConfig(const EngineConfig& config);
bool ParseEngineConfig(const std::string& text, EngineConfig* config,
                       std::string* error);
// Revision of the canonical config, used for optimistic conflict detection.
std::string EngineConfigRevision(const EngineConfig& config);

}  // namespace wintcp
