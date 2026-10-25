// EngineClock.cpp
// SPDX-License-Identifier: Apache-2.0
#include "EngineClock.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace wintcp {

EngineClock::EngineClock(std::string epoch) : epoch_(std::move(epoch)) {}

ClockObservation EngineClock::Observe(std::uint64_t utcMs,
                                      std::uint64_t monotonicMs,
                                      std::uint64_t expectedIntervalMs) {
    ClockObservation observation;
    if (mappingNumber_ == 0) {
        mappingNumber_ = 1;
        anchorUtcMs_ = utcMs;
        anchorMonotonicMs_ = monotonicMs;
    } else {
        const bool monotonicBackwards = monotonicMs < lastMonotonicMs_;
        const std::uint64_t elapsed = monotonicBackwards ? 0 :
            monotonicMs - lastMonotonicMs_;
        observation.elapsedMonotonicMs = elapsed;
        // Avoid classifying ordinary scheduler delays as sleep/resume on fast
        // sampling configurations while still surfacing extended pauses.
        const std::uint64_t scaledInterval = expectedIntervalMs >
            (std::numeric_limits<std::uint64_t>::max)() / 5
            ? (std::numeric_limits<std::uint64_t>::max)()
            : expectedIntervalMs * 5;
        const std::uint64_t gapThreshold =
            (std::max<std::uint64_t>)(5000, scaledInterval);
        observation.samplingGap = expectedIntervalMs != 0 &&
            elapsed > gapThreshold;
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
