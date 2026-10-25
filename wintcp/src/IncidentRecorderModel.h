// IncidentRecorderModel.h
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <vector>

namespace wintcp {

// Payload is a previously validated, privacy-safe serialized metadata record.
// The model never interprets it as a path, command, or filesystem name.
struct IncidentRecord {
    std::uint64_t monotonicNs = 0;
    std::string eventId;
    std::string payload;
};

struct IncidentTrigger {
    std::uint64_t monotonicNs = 0;
    std::string id;
    std::string reason;
};

struct IncidentSnapshot {
    std::string id;
    std::uint64_t startMonotonicNs = 0;
    std::uint64_t firstTriggerMonotonicNs = 0;
    std::uint64_t prehistoryWindowNs = 0;
    std::uint64_t prehistoryRetainedNs = 0;
    std::uint64_t postDeadlineMonotonicNs = 0;
    std::uint64_t endMonotonicNs = 0;
    bool active = false;
    bool postWindowIncomplete = false;
    bool prehistoryIncomplete = false;
    bool recordsTruncated = false;
    bool triggersTruncated = false;
    std::uint64_t lostTriggers = 0;
    std::uint64_t lostRecords = 0;
    std::vector<IncidentTrigger> triggers;
    std::vector<IncidentRecord> records;
};

struct IncidentRecordPage {
    IncidentSnapshot incident;
    std::size_t nextOffset = 0;
    bool hasMore = false;
    std::string error;
};

// Bounded pure model for I1's pre/post-trigger window. Engine integration,
// durable finalization and replay live outside this class.
class IncidentRecorderModel {
public:
    static constexpr std::size_t kDefaultBudgetBytes = 64 * 1024 * 1024;
    static constexpr std::size_t kMaxTriggersPerIncident = 256;
    static constexpr std::uint64_t kSecondNs = 1000000000ULL;

    explicit IncidentRecorderModel(
        std::size_t budgetBytes = kDefaultBudgetBytes,
        std::uint64_t preTriggerNs = 120 * kSecondNs,
        std::uint64_t postTriggerNs = 30 * kSecondNs,
        std::uint64_t maxPostTriggerNs = 120 * kSecondNs);

    bool Observe(IncidentRecord record);
    // Related triggers merge into the current incident while it is collecting.
    bool Trigger(IncidentTrigger trigger, bool related = true);
    void Close(std::uint64_t monotonicNs);
    void Stop(std::uint64_t monotonicNs);
    IncidentSnapshot Snapshot() const;
    IncidentSnapshot Summary() const;
    IncidentRecordPage ReadPage(std::size_t offset, std::size_t limit,
                                std::size_t maxBytes) const;
    // Transfers one finalized incident to the caller before another is armed.
    IncidentSnapshot TakeSnapshot();

    std::size_t StoredBytes() const { return storedBytes_; }
    std::size_t HistoryCount() const { return history_.size(); }
    std::size_t IncidentRecordCount() const { return activeRecords_.size(); }
    std::uint64_t LostRecords() const { return lostRecords_; }
    bool IsActive() const { return active_.active; }
    bool HasIncident() const { return !active_.id.empty(); }

private:
    using SharedRecord = std::shared_ptr<const IncidentRecord>;
    struct SizedRecord {
        SharedRecord record;
        std::size_t bytes = 0;
    };

    static std::size_t RecordBytes(const IncidentRecord& record);
    static std::size_t TriggerBytes(const IncidentTrigger& trigger);
    static std::uint64_t AddSaturated(std::uint64_t a, std::uint64_t b);
    bool MakeRoom(std::size_t bytes);
    void EndActive();

    std::size_t budgetBytes_;
    std::uint64_t preTriggerNs_, postTriggerNs_, maxPostTriggerNs_;
    std::size_t storedBytes_ = 0;
    std::size_t activeTriggerBytes_ = 0;
    std::uint64_t lostRecords_ = 0;
    std::uint64_t lostThroughNs_ = 0;
    bool hasLostRecords_ = false;
    std::uint64_t firstObservedNs_ = 0;
    std::uint64_t lastObservedNs_ = 0;
    std::deque<SizedRecord> history_;
    std::vector<SizedRecord> activeRecords_;
    IncidentSnapshot active_;
};

}  // namespace wintcp
