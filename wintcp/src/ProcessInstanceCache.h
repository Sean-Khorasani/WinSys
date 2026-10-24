// ProcessInstanceCache.h
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "NetworkEvents.h"
#include <map>
#include <utility>

namespace wintcp {

// Verified intervals only: a PID lookup by itself never identifies an event.
// A live handle proves one instance survived from the bound event until query.
class ProcessInstanceCache {
public:
    explicit ProcessInstanceCache(std::size_t capacity = 10000);
    bool Remember(const NetworkProcessIdentity& identity,
                  std::uint64_t firstQpc, std::uint64_t liveAtQpc);
    bool RevalidateLive(const NetworkProcessIdentity& identity,
                        std::uint64_t eventQpc, std::uint64_t liveAtQpc);
    bool Find(std::uint32_t pid, std::uint64_t eventQpc,
              NetworkProcessIdentity* identity) const;
    bool HasInstance(std::uint32_t pid, std::uint64_t creationTime) const {
        return records_.find({pid, creationTime}) != records_.end();
    }
    void Clear() { records_.clear(); }
    std::size_t Size() const { return records_.size(); }
private:
    struct Entry {
        NetworkProcessIdentity identity;
        std::uint64_t first = 0;
        std::uint64_t last = 0;
    };
    void Invalidate(std::uint32_t pid);
    std::size_t capacity_;
    std::map<std::pair<std::uint32_t, std::uint64_t>, Entry> records_;
};
}  // namespace wintcp
