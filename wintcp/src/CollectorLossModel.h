#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace wintcp {

enum class CollectorLossCounter : std::size_t {
    QueueLost = 0,
    SchemaRejected,
    EventsLost,
    BuffersLost,
    HistoryEvicted,
    FlowEvicted,
    Count,
};

struct CollectorLossSnapshot {
    std::string eventEpoch;
    std::array<std::uint64_t,
        static_cast<std::size_t>(CollectorLossCounter::Count)> totals{};
};

struct CollectorLossDelta {
    CollectorLossCounter counter = CollectorLossCounter::QueueLost;
    std::uint64_t previous = 0;
    std::uint64_t total = 0;
    std::uint64_t amount = 0;
    bool reset = false;
};

const char* CollectorLossCounterName(CollectorLossCounter counter);
const char* CollectorLossCounterReason(CollectorLossCounter counter);
const char* CollectorLossCounterUnit(CollectorLossCounter counter);

class CollectorLossTracker {
public:
    bool Restore(const std::string& checkpoint, std::string* error);
    std::vector<CollectorLossDelta> Preview(
        const CollectorLossSnapshot& snapshot) const;
    void Commit(const CollectorLossSnapshot& snapshot);
    bool Initialized() const { return initialized_; }
    const CollectorLossSnapshot& Current() const { return current_; }
    std::string Checkpoint() const;

private:
    CollectorLossSnapshot current_;
    bool initialized_ = false;
};

}  // namespace wintcp
