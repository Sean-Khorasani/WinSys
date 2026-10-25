// ProcessInstanceCache.cpp
// SPDX-License-Identifier: Apache-2.0
#include "ProcessInstanceCache.h"
#include <algorithm>

namespace wintcp {
ProcessInstanceCache::ProcessInstanceCache(std::size_t capacity)
    : capacity_((std::max)(std::size_t{1}, (std::min)(capacity, std::size_t{10000}))) {}

void ProcessInstanceCache::Invalidate(std::uint32_t pid) {
    auto begin = records_.lower_bound({pid, 0});
    auto end = begin;
    while (end != records_.end() && end->first.first == pid) ++end;
    records_.erase(begin, end);
}

bool ProcessInstanceCache::Remember(const NetworkProcessIdentity& identity,
                                    std::uint64_t firstQpc, std::uint64_t liveAtQpc) {
    if (!ProcessActionable(identity) || identity.imagePath.size() > 1024 ||
        firstQpc == 0 || liveAtQpc < firstQpc) return false;
    const auto key = std::make_pair(identity.pid, identity.creationTimeFileTime);
    const auto existing = records_.find(key);
    if (existing != records_.end()) {
        if (identity.imagePath != existing->second.identity.imagePath) {
            Invalidate(identity.pid);
            return false;
        }
        firstQpc = (std::min)(firstQpc, existing->second.first);
        liveAtQpc = (std::max)(liveAtQpc, existing->second.last);
    }
    for (auto it = records_.lower_bound({identity.pid, 0});
         it != records_.end() && it->first.first == identity.pid; ++it) {
        if (it->first != key && firstQpc <= it->second.last && liveAtQpc >= it->second.first) {
            Invalidate(identity.pid);
            return false;
        }
    }
    if (existing != records_.end()) {
        existing->second.first = firstQpc;
        existing->second.last = liveAtQpc;
        return true;
    }
    if (records_.size() >= capacity_) {
        const auto oldest = std::min_element(records_.begin(), records_.end(),
            [](const auto& a, const auto& b) { return a.second.last < b.second.last; });
        records_.erase(oldest);
    }
    records_.emplace(key, Entry{identity, firstQpc, liveAtQpc});
    return true;
}

bool ProcessInstanceCache::RevalidateLive(const NetworkProcessIdentity& identity,
                                          std::uint64_t eventQpc, std::uint64_t liveAtQpc) {
    const auto found = records_.find({identity.pid, identity.creationTimeFileTime});
    if (found == records_.end() || !ProcessActionable(identity) ||
        eventQpc < found->second.first || liveAtQpc < eventQpc ||
        liveAtQpc < found->second.last) return false;
    if (identity.imagePath != found->second.identity.imagePath) {
        Invalidate(identity.pid);
        return false;
    }
    for (auto it = records_.lower_bound({identity.pid, 0});
         it != records_.end() && it->first.first == identity.pid; ++it) {
        if (it == found) continue;
        if (found->second.first <= it->second.last && liveAtQpc >= it->second.first) {
            Invalidate(identity.pid);
            return false;
        }
    }
    found->second.last = liveAtQpc;
    return true;
}

bool ProcessInstanceCache::Find(std::uint32_t pid, std::uint64_t eventQpc,
                                NetworkProcessIdentity* identity) const {
    if (identity == nullptr) return false;
    *identity = {};
    const Entry* match = nullptr;
    for (auto it = records_.lower_bound({pid, 0});
         it != records_.end() && it->first.first == pid; ++it) {
        if (eventQpc < it->second.first || eventQpc > it->second.last) continue;
        if (match != nullptr) return false;
        match = &it->second;
    }
    if (match == nullptr) return false;
    *identity = match->identity;
    return true;
}

void ProcessInstanceCache::EndAt(std::uint32_t pid, std::uint64_t eventQpc) {
    if (pid == 0 || eventQpc == 0) return;
    auto it = records_.lower_bound({pid, 0});
    while (it != records_.end() && it->first.first == pid) {
        if (it->second.first >= eventQpc) {
            it = records_.erase(it);
        } else {
            if (it->second.last >= eventQpc)
                it->second.last = eventQpc - 1;
            ++it;
        }
    }
}
}  // namespace wintcp
