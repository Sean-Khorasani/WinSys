// RecipeScheduleWindows.h
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <string>

#include "RecipeModel.h"

namespace wintcp {

// Converts one UTC instant using the selected Windows dynamic time-zone rules.
// Local weekday is Sunday=0; minuteOfDay is [0, 1439].
bool WindowsRecipeScheduleLocalTimeAtUtc(const std::string& timeZoneId,
                                         std::uint64_t utcMs,
                                         unsigned* weekdaySundayZero,
                                         unsigned* minuteOfDay);
bool WindowsRecipeTimeZoneAvailable(const RecipeSchedule& schedule);
bool WindowsRecipeScheduleActiveAtUtc(const RecipeSchedule& schedule,
                                      std::uint64_t utcMs);
// Finds the first UTC minute boundary, within the next eight days, at which
// the schedule changes state. Always schedules and unavailable zones return
// false. `activeAfter` reports the state after that boundary.
bool WindowsRecipeScheduleNextTransitionAtUtc(const RecipeSchedule& schedule,
    std::uint64_t utcMs, std::uint64_t* transitionUtcMs, bool* activeAfter);

}  // namespace wintcp
