// IncidentRecorderModel.cpp
// SPDX-License-Identifier: Apache-2.0
#include "IncidentRecorderModel.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace wintcp {

IncidentRecorderModel::IncidentRecorderModel(std::size_t budgetBytes,
    std::uint64_t preTriggerNs, std::uint64_t postTriggerNs,
    std::uint64_t maxPostTriggerNs)
    : budgetBytes_((std::max)(std::size_t{1024},
          (std::min)(budgetBytes, kDefaultBudgetBytes))),
      preTriggerNs_((std::min)(preTriggerNs, 120 * kSecondNs)),
      postTriggerNs_((std::min)(postTriggerNs, 120 * kSecondNs)),
      maxPostTriggerNs_((std::min)(maxPostTriggerNs, 120 * kSecondNs)) {
    maxPostTriggerNs_ = (std::max)(maxPostTriggerNs_, postTriggerNs_);
}

std::size_t IncidentRecorderModel::RecordBytes(const IncidentRecord& record) {
    constexpr std::size_t kOverhead = sizeof(IncidentRecord) + 64;
    if (record.eventId.size() > (std::numeric_limits<std::size_t>::max)() - kOverhead ||
        record.payload.size() > (std::numeric_limits<std::size_t>::max)() -
            kOverhead - record.eventId.size())
        return (std::numeric_limits<std::size_t>::max)();
    return kOverhead + record.eventId.size() + record.payload.size();
}

std::size_t IncidentRecorderModel::TriggerBytes(const IncidentTrigger& trigger) {
    return sizeof(IncidentTrigger) + trigger.id.size() + trigger.reason.size();
}

std::uint64_t IncidentRecorderModel::AddSaturated(std::uint64_t a,
                                                   std::uint64_t b) {
    return a > (std::numeric_limits<std::uint64_t>::max)() - b
        ? (std::numeric_limits<std::uint64_t>::max)() : a + b;
}

bool IncidentRecorderModel::MakeRoom(std::size_t bytes) {
    if (bytes > budgetBytes_) return false;
    while (storedBytes_ > budgetBytes_ - bytes && !history_.empty()) {
        SizedRecord oldest = std::move(history_.front());
        history_.pop_front();
        if (oldest.record.use_count() == 1) {
            storedBytes_ -= oldest.bytes;
            if (lostRecords_ != (std::numeric_limits<std::uint64_t>::max)())
                ++lostRecords_;
            hasLostRecords_ = true;
            lostThroughNs_ = (std::max)(lostThroughNs_,
                                       oldest.record->monotonicNs);
        }
    }
    return storedBytes_ <= budgetBytes_ - bytes;
}

void IncidentRecorderModel::EndActive() {
    active_.active = false;
}

bool IncidentRecorderModel::Observe(IncidentRecord record) {
    if (record.eventId.empty() || record.payload.empty() ||
        (lastObservedNs_ != 0 && record.monotonicNs < lastObservedNs_)) {
        if (lostRecords_ != (std::numeric_limits<std::uint64_t>::max)())
            ++lostRecords_;
        hasLostRecords_ = true;
        lostThroughNs_ = (std::max)(lostThroughNs_, record.monotonicNs);
        if (active_.active) active_.recordsTruncated = true;
        return false;
    }
    if (active_.active && record.monotonicNs > active_.postDeadlineMonotonicNs)
        EndActive();

    const std::uint64_t retainFrom = record.monotonicNs > preTriggerNs_
        ? record.monotonicNs - preTriggerNs_ : 0;
    while (!history_.empty() &&
           history_.front().record->monotonicNs < retainFrom) {
        SizedRecord expired = std::move(history_.front());
        history_.pop_front();
        if (expired.record.use_count() == 1)
            storedBytes_ -= expired.bytes;
    }

    const std::size_t bytes = RecordBytes(record);
    if (!MakeRoom(bytes)) {
        if (lostRecords_ != (std::numeric_limits<std::uint64_t>::max)())
            ++lostRecords_;
        hasLostRecords_ = true;
        lostThroughNs_ = (std::max)(lostThroughNs_, record.monotonicNs);
        if (active_.active) active_.recordsTruncated = true;
        lastObservedNs_ = record.monotonicNs;
        if (firstObservedNs_ == 0) firstObservedNs_ = record.monotonicNs;
        return false;
    }

    auto shared = std::make_shared<const IncidentRecord>(std::move(record));
    storedBytes_ += bytes;
    history_.push_back({shared, bytes});
    if (active_.active && shared->monotonicNs >= active_.startMonotonicNs) {
        activeRecords_.push_back({shared, bytes});
        active_.endMonotonicNs = shared->monotonicNs;
    }
    if (firstObservedNs_ == 0) firstObservedNs_ = shared->monotonicNs;
    lastObservedNs_ = shared->monotonicNs;
    return true;
}

bool IncidentRecorderModel::Trigger(IncidentTrigger trigger, bool related) {
    if (trigger.id.empty() || trigger.reason.empty() ||
        trigger.id.size() > 512 || trigger.reason.size() > 512 ||
        trigger.monotonicNs == 0 ||
        (lastObservedNs_ != 0 && trigger.monotonicNs < lastObservedNs_))
        return false;

    if (active_.active && related &&
        trigger.monotonicNs <= active_.postDeadlineMonotonicNs) {
        if (std::any_of(active_.triggers.begin(), active_.triggers.end(),
                [&trigger](const IncidentTrigger& existing) {
                    return existing.id == trigger.id;
                })) return true;
        if (active_.triggers.size() >= kMaxTriggersPerIncident) {
            active_.triggersTruncated = true;
            if (active_.lostTriggers !=
                (std::numeric_limits<std::uint64_t>::max)())
                ++active_.lostTriggers;
            return false;
        }
        const std::size_t triggerBytes = TriggerBytes(trigger);
        if (!MakeRoom(triggerBytes)) {
            active_.triggersTruncated = true;
            if (active_.lostTriggers !=
                (std::numeric_limits<std::uint64_t>::max)())
                ++active_.lostTriggers;
            return false;
        }
        storedBytes_ += triggerBytes;
        activeTriggerBytes_ += triggerBytes;
        active_.triggers.push_back(std::move(trigger));
        const std::uint64_t cap = AddSaturated(active_.firstTriggerMonotonicNs,
                                               maxPostTriggerNs_);
        const std::uint64_t requested = AddSaturated(
            active_.triggers.back().monotonicNs, postTriggerNs_);
        active_.postDeadlineMonotonicNs = (std::min)(cap,
            (std::max)(active_.postDeadlineMonotonicNs, requested));
        return true;
    }
    if (active_.active) return false;
    if (!active_.id.empty()) return false;
    const std::size_t triggerBytes = TriggerBytes(trigger);
    if (!MakeRoom(triggerBytes)) return false;

    active_ = {};
    storedBytes_ += triggerBytes;
    activeTriggerBytes_ = triggerBytes;
    active_.id = trigger.id;
    active_.startMonotonicNs = trigger.monotonicNs > preTriggerNs_
        ? trigger.monotonicNs - preTriggerNs_ : 0;
    active_.firstTriggerMonotonicNs = trigger.monotonicNs;
    active_.postDeadlineMonotonicNs = AddSaturated(trigger.monotonicNs,
                                                   postTriggerNs_);
    active_.endMonotonicNs = trigger.monotonicNs;
    active_.active = true;
    active_.lostRecords = lostRecords_;
    active_.prehistoryIncomplete = firstObservedNs_ == 0 ||
        firstObservedNs_ > active_.startMonotonicNs ||
        (hasLostRecords_ && lostThroughNs_ >= active_.startMonotonicNs);
    active_.recordsTruncated = hasLostRecords_ &&
        lostThroughNs_ >= active_.startMonotonicNs;
    active_.triggers.push_back(std::move(trigger));
    for (const SizedRecord& item : history_) {
        if (item.record->monotonicNs >= active_.startMonotonicNs &&
            item.record->monotonicNs <= active_.firstTriggerMonotonicNs) {
            activeRecords_.push_back(item);
            active_.endMonotonicNs = item.record->monotonicNs;
        }
    }
    active_.endMonotonicNs = active_.firstTriggerMonotonicNs;
    active_.prehistoryIncomplete = active_.prehistoryIncomplete ||
        active_.recordsTruncated;
    return true;
}

void IncidentRecorderModel::Close(std::uint64_t monotonicNs) {
    if (active_.active && monotonicNs >= active_.postDeadlineMonotonicNs) {
        active_.endMonotonicNs = active_.postDeadlineMonotonicNs;
        EndActive();
    }
}

void IncidentRecorderModel::Stop(std::uint64_t monotonicNs) {
    if (!active_.active) return;
    active_.endMonotonicNs = monotonicNs;
    active_.postWindowIncomplete = true;
    EndActive();
}

IncidentSnapshot IncidentRecorderModel::Snapshot() const {
    IncidentSnapshot result = active_;
    result.lostRecords = lostRecords_;
    result.records.reserve(activeRecords_.size());
    for (const SizedRecord& item : activeRecords_)
        result.records.push_back(*item.record);
    return result;
}

IncidentSnapshot IncidentRecorderModel::Summary() const {
    IncidentSnapshot result = active_;
    result.lostRecords = lostRecords_;
    return result;
}

IncidentRecordPage IncidentRecorderModel::ReadPage(std::size_t offset,
    std::size_t limit, std::size_t maxBytes) const {
    IncidentRecordPage page;
    page.incident = Summary();
    if (limit == 0 || limit > 100 || maxBytes == 0 || offset > activeRecords_.size()) {
        page.error = "invalid_incident_page";
        return page;
    }
    std::size_t responseBytes = 0;
    for (std::size_t i = offset;
         i < activeRecords_.size() && page.incident.records.size() < limit; ++i) {
        const SizedRecord& item = activeRecords_[i];
        if (item.bytes > maxBytes - (std::min)(responseBytes, maxBytes)) {
            if (page.incident.records.empty()) page.error = "incident_record_too_large";
            break;
        }
        responseBytes += item.bytes;
        page.incident.records.push_back(*item.record);
    }
    page.nextOffset = offset + page.incident.records.size();
    page.hasMore = page.nextOffset < activeRecords_.size();
    return page;
}

IncidentSnapshot IncidentRecorderModel::TakeSnapshot() {
    IncidentSnapshot result = Snapshot();
    if (active_.active) return result;
    for (const SizedRecord& item : activeRecords_)
        if (item.record.use_count() == 1)
            storedBytes_ -= item.bytes;
    if (activeTriggerBytes_ <= storedBytes_)
        storedBytes_ -= activeTriggerBytes_;
    activeTriggerBytes_ = 0;
    activeRecords_.clear();
    active_ = {};
    return result;
}

}  // namespace wintcp
