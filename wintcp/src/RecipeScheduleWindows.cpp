// RecipeScheduleWindows.cpp
// SPDX-License-Identifier: Apache-2.0
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <windows.h>

#include "RecipeScheduleWindows.h"

#include <limits>
#include <map>
#include <mutex>

namespace wintcp {
namespace {

std::string FoldTimeZoneId(const std::string& value) {
    std::string result = value;
    for (char& c : result)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return result;
}

const std::map<std::string, DYNAMIC_TIME_ZONE_INFORMATION>& WindowsTimeZones() {
    static std::once_flag loaded;
    static std::map<std::string, DYNAMIC_TIME_ZONE_INFORMATION> zones;
    std::call_once(loaded, [] {
        using EnumZones = DWORD (WINAPI*)(DWORD,
            PDYNAMIC_TIME_ZONE_INFORMATION);
        HMODULE module = ::GetModuleHandleW(L"kernelbase.dll");
        if (module == nullptr) module = ::GetModuleHandleW(L"kernel32.dll");
        const auto enumerate = module == nullptr ? nullptr :
            reinterpret_cast<EnumZones>(::GetProcAddress(
                module, "EnumDynamicTimeZoneInformation"));
        if (enumerate == nullptr) return;
        for (DWORD index = 0; index < 512; ++index) {
            DYNAMIC_TIME_ZONE_INFORMATION zone = {};
            const DWORD status = enumerate(index, &zone);
            if (status == ERROR_NO_MORE_ITEMS) break;
            if (status != ERROR_SUCCESS) continue;
            std::string key;
            for (wchar_t c : zone.TimeZoneKeyName) {
                if (c == L'\0') break;
                if (c > 0x7f) { key.clear(); break; }
                key.push_back(static_cast<char>(c));
            }
            if (!key.empty()) zones.emplace(FoldTimeZoneId(key), zone);
        }
    });
    return zones;
}

}  // namespace

bool WindowsRecipeTimeZoneAvailable(const RecipeSchedule& schedule) {
    if (schedule.type == RecipeScheduleType::Always) return true;
    const auto& zones = WindowsTimeZones();
    return zones.find(FoldTimeZoneId(schedule.timeZoneId)) != zones.end();
}

bool WindowsRecipeScheduleLocalTimeAtUtc(const std::string& timeZoneId,
                                         std::uint64_t utcMs,
                                         unsigned* weekdaySundayZero,
                                         unsigned* minuteOfDay) {
    if (weekdaySundayZero == nullptr || minuteOfDay == nullptr) return false;
    const auto& zones = WindowsTimeZones();
    const std::string zoneId = FoldTimeZoneId(timeZoneId);
    const auto zone = zones.find(zoneId);
    if (zone == zones.end() ||
        utcMs > ((std::numeric_limits<std::uint64_t>::max)() -
                 116444736000000000ULL) / 10000ULL) return false;

    struct LocalMinute { std::uint64_t utcMinute; unsigned weekday; unsigned minute; };
    static std::mutex cacheMutex;
    static std::map<std::string, LocalMinute> localMinuteCache;
    const std::uint64_t utcMinute = utcMs / 60000ULL;
    {
        std::lock_guard<std::mutex> lock(cacheMutex);
        const auto cached = localMinuteCache.find(zoneId);
        if (cached != localMinuteCache.end() &&
            cached->second.utcMinute == utcMinute) {
            *weekdaySundayZero = cached->second.weekday;
            *minuteOfDay = cached->second.minute;
            return true;
        }
    }

    const std::uint64_t ticks = 116444736000000000ULL + utcMs * 10000ULL;
    ULARGE_INTEGER value = {};
    value.QuadPart = ticks;
    FILETIME fileTime = {value.LowPart, value.HighPart};
    SYSTEMTIME utc = {}, local = {};
    if (!::FileTimeToSystemTime(&fileTime, &utc)) return false;
    TIME_ZONE_INFORMATION rules = {};
    DYNAMIC_TIME_ZONE_INFORMATION dynamicZone = zone->second;
    if (!::GetTimeZoneInformationForYear(utc.wYear, &dynamicZone, &rules) ||
        !::SystemTimeToTzSpecificLocalTime(&rules, &utc, &local)) return false;

    const LocalMinute converted{utcMinute, local.wDayOfWeek,
        static_cast<unsigned>(local.wHour) * 60 + local.wMinute};
    {
        std::lock_guard<std::mutex> lock(cacheMutex);
        if (localMinuteCache.size() >= 128 &&
            localMinuteCache.find(zoneId) == localMinuteCache.end())
            localMinuteCache.erase(localMinuteCache.begin());
        localMinuteCache[zoneId] = converted;
    }
    *weekdaySundayZero = converted.weekday;
    *minuteOfDay = converted.minute;
    return true;
}

bool WindowsRecipeScheduleActiveAtUtc(const RecipeSchedule& schedule,
                                      std::uint64_t utcMs) {
    if (schedule.type == RecipeScheduleType::Always) return true;
    unsigned weekday = 0, minute = 0;
    return WindowsRecipeScheduleLocalTimeAtUtc(schedule.timeZoneId, utcMs,
        &weekday, &minute) &&
        RecipeScheduleMatchesLocalTime(schedule, weekday, minute);
}

bool WindowsRecipeScheduleNextTransitionAtUtc(const RecipeSchedule& schedule,
    std::uint64_t utcMs, std::uint64_t* transitionUtcMs, bool* activeAfter) {
    if (transitionUtcMs == nullptr || activeAfter == nullptr ||
        schedule.type != RecipeScheduleType::WeeklyWindow ||
        !WindowsRecipeTimeZoneAvailable(schedule)) return false;
    const std::uint64_t currentMinute = utcMs / 60000ULL;
    const std::string key = FoldTimeZoneId(schedule.timeZoneId) + "|" +
        std::to_string(schedule.daysMask) + "|" +
        std::to_string(schedule.startMinute) + "|" +
        std::to_string(schedule.endMinute);
    struct TransitionCache {
        std::uint64_t currentMinute = 0;
        std::uint64_t transitionUtcMs = 0;
        bool activeAfter = false;
        bool found = false;
    };
    static std::mutex cacheMutex;
    static std::map<std::string, TransitionCache> cache;
    {
        std::lock_guard<std::mutex> lock(cacheMutex);
        const auto saved = cache.find(key);
        if (saved != cache.end() && saved->second.currentMinute == currentMinute) {
            if (saved->second.found) {
                *transitionUtcMs = saved->second.transitionUtcMs;
                *activeAfter = saved->second.activeAfter;
            }
            return saved->second.found;
        }
    }
    const bool current = WindowsRecipeScheduleActiveAtUtc(schedule, utcMs);
    constexpr std::uint64_t kMinutesToSearch = 8ULL * 24ULL * 60ULL;
    if (currentMinute > ((std::numeric_limits<std::uint64_t>::max)() / 60000ULL) -
            kMinutesToSearch) return false;
    for (std::uint64_t offset = 1; offset <= kMinutesToSearch; ++offset) {
        const std::uint64_t candidate = (currentMinute + offset) * 60000ULL;
        const bool active = WindowsRecipeScheduleActiveAtUtc(schedule, candidate);
        if (active != current) {
            *transitionUtcMs = candidate;
            *activeAfter = active;
            std::lock_guard<std::mutex> lock(cacheMutex);
            if (cache.size() >= 128 && cache.find(key) == cache.end())
                cache.erase(cache.begin());
            cache[key] = {currentMinute, candidate, active, true};
            return true;
        }
    }
    {
        std::lock_guard<std::mutex> lock(cacheMutex);
        if (cache.size() >= 128 && cache.find(key) == cache.end())
            cache.erase(cache.begin());
        cache[key] = {currentMinute, 0, false, false};
    }
    return false;
}

}  // namespace wintcp
