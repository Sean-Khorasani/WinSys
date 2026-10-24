// EngineConfig.cpp
// SPDX-License-Identifier: Apache-2.0
#include "EngineConfig.h"
#include "Sha256.h"

#include <cstdint>
#include <limits>
#include <sstream>

namespace wintcp {
namespace {

bool Decimal(const std::string& input, std::uint64_t* out) {
    if (input.empty() || out == nullptr) return false;
    std::uint64_t value = 0;
    for (char ch : input) {
        if (ch < '0' || ch > '9') return false;
        const unsigned digit = static_cast<unsigned>(ch - '0');
        if (value > ((std::numeric_limits<std::uint64_t>::max)() - digit) / 10)
            return false;
        value = value * 10 + digit;
    }
    *out = value;
    return true;
}

}  // namespace

std::string FormatEngineConfig(const EngineConfig& config) {
    return "WinTCP-Engine-Config:1\n"
           "snapshotIntervalMs=" + std::to_string(config.snapshotIntervalMs) + "\n"
           "maxEventRecords=" + std::to_string(config.maxEventRecords) + "\n"
           "maxEventBytes=" + std::to_string(config.maxEventBytes) + "\n";
}

std::string EngineConfigRevision(const EngineConfig& config) {
    const std::string canonical = FormatEngineConfig(config);
    return Sha256HexA(Sha256Bytes(
        reinterpret_cast<const unsigned char*>(canonical.data()),
        canonical.size()));
}

bool ParseEngineConfig(const std::string& text, EngineConfig* config,
                       std::string* error) {
    if (config == nullptr || text.size() > 4096 || text.find('\0') != std::string::npos) {
        if (error != nullptr) *error = "invalid_size_or_encoding";
        return false;
    }
    std::istringstream stream(text);
    std::string line;
    unsigned seen = 0;
    std::uint64_t interval = 0, records = 0, bytes = 0;
    if (!std::getline(stream, line)) {
        if (error != nullptr) *error = "missing_version";
        return false;
    }
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line != "WinTCP-Engine-Config:1") {
        if (error != nullptr) *error = "unsupported_version";
        return false;
    }
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        const std::size_t split = line.find('=');
        std::uint64_t value = 0;
        if (split == std::string::npos || !Decimal(line.substr(split + 1), &value)) {
            if (error != nullptr) *error = "invalid_field";
            return false;
        }
        const std::string key = line.substr(0, split);
        unsigned bit = 0;
        if (key == "snapshotIntervalMs") { bit = 1; interval = value; }
        else if (key == "maxEventRecords") { bit = 2; records = value; }
        else if (key == "maxEventBytes") { bit = 4; bytes = value; }
        else {
            if (error != nullptr) *error = "unknown_field";
            return false;
        }
        if ((seen & bit) != 0) {
            if (error != nullptr) *error = "duplicate_field";
            return false;
        }
        seen |= bit;
    }
    if (seen != 7 || interval < 250 || interval > 60000 ||
        records < 1 || records > 50000 ||
        bytes < 1024 * 1024 || bytes > 64ULL * 1024 * 1024) {
        if (error != nullptr) *error = "missing_or_out_of_range_field";
        return false;
    }
    config->snapshotIntervalMs = static_cast<unsigned>(interval);
    config->maxEventRecords = static_cast<std::size_t>(records);
    config->maxEventBytes = static_cast<std::size_t>(bytes);
    if (error != nullptr) error->clear();
    return true;
}

}  // namespace wintcp
