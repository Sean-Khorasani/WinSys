// EngineClock.cpp
// SPDX-License-Identifier: Apache-2.0
#include "EngineClock.h"

#include <utility>

namespace wintcp {

EngineClock::EngineClock(std::string epoch) : epoch_(std::move(epoch)) {}

ClockObservation EngineClock::Observe(std::uint64_t utcMs,
                                      std::uint64_t monotonicMs) {
    ClockObservation observation;
    if (mappingNumber_ == 0) {
        mappingNumber_ = 1;
        anchorUtcMs_ = utcMs;
        anchorMonotonicMs_ = monotonicMs;
    } else {
        const bool monotonicBackwards = monotonicMs < lastMonotonicMs_;
        const std::int64_t predicted = static_cast<std::int64_t>(lastUtcMs_) +
            (monotonicBackwards ? 0 :
                static_cast<std::int64_t>(monotonicMs - lastMonotonicMs_));
        const std::int64_t delta = static_cast<std::int64_t>(utcMs) - predicted;
        if (monotonicBackwards || delta < -2000 || delta > 2000) {
            ++mappingNumber_;
            anchorUtcMs_ = utcMs;
            anchorMonotonicMs_ = monotonicMs;
            observation.changed = true;
            observation.adjustmentMs = delta;
        }
    }
    lastUtcMs_ = utcMs;
    lastMonotonicMs_ = monotonicMs;
    observation.mappingId = epoch_ + ":clock-" +
        std::to_string(mappingNumber_);
    observation.anchorUtcMs = anchorUtcMs_;
    observation.anchorMonotonicMs = anchorMonotonicMs_;
    observation.changes = mappingNumber_ - 1;
    return observation;
}

}  // namespace wintcp
