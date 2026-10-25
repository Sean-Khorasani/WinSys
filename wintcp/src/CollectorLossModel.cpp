#include "CollectorLossModel.h"

#include <limits>
#include <utility>

namespace wintcp {
namespace {

constexpr const char* kCheckpointHeader = "WinTCP-Collector-Loss:1\n";

bool SafeEpoch(const std::string& value) {
    if (value.size() != 32) return false;
    for (char c : value)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    return true;
}

bool ParseCounter(const std::string& value, std::uint64_t* parsed) {
    if (value.empty() || parsed == nullptr) return false;
    std::uint64_t result = 0;
    for (char c : value) {
        if (c < '0' || c > '9') return false;
        const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
        if (result > ((std::numeric_limits<std::uint64_t>::max)() - digit) / 10)
            return false;
        result = result * 10 + digit;
    }
    *parsed = result;
    return true;
}

}  // namespace

const char* CollectorLossCounterName(CollectorLossCounter counter) {
    switch (counter) {
    case CollectorLossCounter::QueueLost: return "queueLost";
    case CollectorLossCounter::SchemaRejected: return "schemaRejected";
    case CollectorLossCounter::EventsLost: return "eventsLost";
    case CollectorLossCounter::BuffersLost: return "buffersLost";
    case CollectorLossCounter::HistoryEvicted: return "historyEvicted";
    case CollectorLossCounter::FlowEvicted: return "flowEvicted";
    case CollectorLossCounter::Count: break;
    }
    return "unknown";
}

const char* CollectorLossCounterReason(CollectorLossCounter counter) {
    switch (counter) {
    case CollectorLossCounter::QueueLost: return "collector_queue_records_lost";
    case CollectorLossCounter::SchemaRejected: return "collector_schema_records_rejected";
    case CollectorLossCounter::EventsLost: return "etw_events_lost";
    case CollectorLossCounter::BuffersLost: return "etw_buffers_lost";
    case CollectorLossCounter::HistoryEvicted: return "collector_history_records_evicted";
    case CollectorLossCounter::FlowEvicted: return "flow_correlation_evicted";
    case CollectorLossCounter::Count: break;
    }
    return "collector_loss_unknown";
}

const char* CollectorLossCounterUnit(CollectorLossCounter counter) {
    switch (counter) {
    case CollectorLossCounter::QueueLost:
    case CollectorLossCounter::SchemaRejected:
    case CollectorLossCounter::EventsLost:
    case CollectorLossCounter::HistoryEvicted:
        return "records";
    case CollectorLossCounter::BuffersLost:
        return "buffers";
    case CollectorLossCounter::FlowEvicted:
        return "flows";
    case CollectorLossCounter::Count:
        break;
    }
    return "unknown";
}

bool CollectorLossTracker::Restore(const std::string& checkpoint,
                                   std::string* error) {
    if (error == nullptr) return false;
    error->clear();
    if (checkpoint.rfind(kCheckpointHeader, 0) != 0 ||
        checkpoint.size() > 512 || checkpoint.empty() ||
        checkpoint.back() != '\n') {
        *error = "collector_loss_checkpoint_invalid";
        return false;
    }
    std::vector<std::string> fields;
    std::size_t start = std::string(kCheckpointHeader).size();
    while (start < checkpoint.size()) {
        const std::size_t end = checkpoint.find('\n', start);
        if (end == std::string::npos) break;
        fields.push_back(checkpoint.substr(start, end - start));
        start = end + 1;
    }
    if (fields.size() != static_cast<std::size_t>(CollectorLossCounter::Count) + 1 ||
        !SafeEpoch(fields[0])) {
        *error = "collector_loss_checkpoint_invalid";
        return false;
    }
    CollectorLossSnapshot restored;
    restored.eventEpoch = fields[0];
    for (std::size_t i = 0; i < restored.totals.size(); ++i) {
        if (!ParseCounter(fields[i + 1], &restored.totals[i])) {
            *error = "collector_loss_checkpoint_invalid";
            return false;
        }
    }
    current_ = std::move(restored);
    initialized_ = true;
    return true;
}

std::vector<CollectorLossDelta> CollectorLossTracker::Preview(
    const CollectorLossSnapshot& snapshot) const {
    std::vector<CollectorLossDelta> deltas;
    if (!SafeEpoch(snapshot.eventEpoch)) return deltas;
    const bool sameEpoch = initialized_ && current_.eventEpoch == snapshot.eventEpoch;
    for (std::size_t i = 0; i < snapshot.totals.size(); ++i) {
        const std::uint64_t previous = sameEpoch ? current_.totals[i] : 0;
        const std::uint64_t total = snapshot.totals[i];
        if (total == previous) continue;
        CollectorLossDelta delta;
        delta.counter = static_cast<CollectorLossCounter>(i);
        delta.previous = previous;
        delta.total = total;
        delta.reset = sameEpoch && total < previous;
        delta.amount = delta.reset ? 0 : total - previous;
        deltas.push_back(delta);
    }
    return deltas;
}

void CollectorLossTracker::Commit(const CollectorLossSnapshot& snapshot) {
    if (!SafeEpoch(snapshot.eventEpoch)) return;
    current_ = snapshot;
    initialized_ = true;
}

std::string CollectorLossTracker::Checkpoint() const {
    if (!initialized_ || !SafeEpoch(current_.eventEpoch)) return {};
    std::string result = kCheckpointHeader + current_.eventEpoch + '\n';
    for (std::uint64_t total : current_.totals)
        result += std::to_string(total) + '\n';
    return result;
}

}  // namespace wintcp
