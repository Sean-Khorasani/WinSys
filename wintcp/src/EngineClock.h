// EngineClock.h
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <string>

namespace wintcp {

struct ClockObservation {
    std::string mappingId;
    bool changed = false;
    std::int64_t adjustmentMs = 0;
    std::uint64_t anchorUtcMs = 0;
    std::uint64_t anchorMonotonicMs = 0;
    std::uint64_t changes = 0;
};

// Pure monotonic/UTC mapping. A wall-clock jump never changes event ordering;
// it starts a new mapping and is reported alongside the UTC display time.
class EngineClock {
public:
    explicit EngineClock(std::string epoch);
    ClockObservation Observe(std::uint64_t utcMs,
                             std::uint64_t monotonicMs);

private:
    std::string epoch_;
    std::uint64_t lastUtcMs_ = 0;
    std::uint64_t lastMonotonicMs_ = 0;
    std::uint64_t anchorUtcMs_ = 0;
    std::uint64_t anchorMonotonicMs_ = 0;
    std::uint64_t mappingNumber_ = 0;
};

}  // namespace wintcp
