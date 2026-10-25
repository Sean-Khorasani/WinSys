// EngineOperations.cpp
// SPDX-License-Identifier: Apache-2.0
#include "EngineOperations.h"

#include <utility>

namespace wintcp {
namespace {
constexpr std::size_t kMaxOperations = 1000;
// Reserve a bounded lane for collector control, including release/disarm and
// stop. General UI/config traffic cannot consume these slots; lower-priority
// collector work such as previews and reactive actions cannot consume the
// safety-control reserve either.
constexpr std::size_t kMaxGeneralOutstanding = 900;
constexpr std::size_t kMaxCollectorOutstanding = 36;
constexpr std::size_t kMaxSafetyControlOutstanding = 64;
constexpr std::uint64_t kRetentionMs = 3600000;

bool Terminal(const EngineOperation& operation) {
    return operation.status == "succeeded" || operation.status == "failed";
}
bool CollectorOperation(const std::string& kind) {
    return kind.rfind("collector.", 0) == 0;
}
bool SafetyControlOperation(const std::string& kind) {
    if (!CollectorOperation(kind)) return false;
    const std::string action = kind.substr(sizeof("collector.") - 1);
    return action == "stop" || action == "release" ||
        action == "release-all" || action == "release-owner" ||
        action == "events-stop";
}
enum class OperationLane { General, Collector, SafetyControl };
OperationLane Lane(const std::string& kind) {
    if (SafetyControlOperation(kind)) return OperationLane::SafetyControl;
    return CollectorOperation(kind) ? OperationLane::Collector
                                    : OperationLane::General;
}
bool MatchesQueue(const EngineOperation& operation, EngineOperationQueue queue) {
    const bool collector = CollectorOperation(operation.kind);
    return queue == EngineOperationQueue::All ||
        (queue == EngineOperationQueue::Collector ? collector : !collector);
}
}  // namespace

void EngineOperations::SetEpoch(std::string epoch) {
    epoch_ = std::move(epoch);
}

void EngineOperations::Prune(std::uint64_t nowMs) {
    for (auto it = records_.begin(); it != records_.end();) {
        if (Terminal(*it) && nowMs >= it->completedAtMs &&
            nowMs - it->completedAtMs >= kRetentionMs)
            it = records_.erase(it);
        else ++it;
    }
}

OperationSubmission EngineOperations::Existing(
    const std::string& requestId, const std::string& revision,
    const std::string& configText, std::uint64_t nowMs,
    const std::string& kind) {
    Prune(nowMs);
    for (const EngineOperation& operation : records_) {
        if (operation.requestId != requestId) continue;
        if (operation.kind != kind || operation.expectedRevision != revision ||
            operation.configText != configText)
            return {OperationDisposition::Reused, operation.id,
                    operation.status};
        return {OperationDisposition::Duplicate, operation.id,
                operation.status};
    }
    return {OperationDisposition::Created, "", ""};
}

OperationSubmission EngineOperations::Submit(
    const std::string& requestId, const std::string& revision,
    const std::string& configText, std::uint64_t nowMs,
    const std::string& kind) {
    const OperationSubmission existing = Existing(requestId, revision,
                                                  configText, nowMs, kind);
    if (existing.disposition != OperationDisposition::Created) return existing;
    const OperationLane lane = Lane(kind);
    std::size_t outstanding = 0;
    for (const EngineOperation& operation : records_)
        if (!Terminal(operation) && Lane(operation.kind) == lane)
            ++outstanding;
    const std::size_t queueLimit = lane == OperationLane::SafetyControl
        ? kMaxSafetyControlOutstanding
        : lane == OperationLane::Collector ? kMaxCollectorOutstanding
                                            : kMaxGeneralOutstanding;
    if (outstanding >= queueLimit)
        return {OperationDisposition::Full, "", ""};
    while (records_.size() >= kMaxOperations) {
        auto it = records_.begin();
        while (it != records_.end() && !Terminal(*it)) ++it;
        if (it == records_.end())
            return {OperationDisposition::Full, "", ""};
        records_.erase(it);
    }
    EngineOperation operation;
    operation.kind = kind;
    operation.id = epoch_ + '-' + std::to_string(++nextId_);
    operation.requestId = requestId;
    operation.expectedRevision = revision;
    operation.configText = configText;
    operation.createdAtMs = nowMs;
    const std::string id = operation.id;
    records_.push_back(std::move(operation));
    return {OperationDisposition::Created, id, "queued"};
}

EngineOperation* EngineOperations::LatestQueued() {
    if (records_.empty() || records_.back().status != "queued") return nullptr;
    return &records_.back();
}

bool EngineOperations::HasQueued(EngineOperationQueue queue) const {
    for (const EngineOperation& operation : records_)
        if (operation.status == "queued" && MatchesQueue(operation, queue)) return true;
    return false;
}

EngineOperation* EngineOperations::TakeNextQueued(EngineOperationQueue queue) {
    // A queued stop/release must not wait behind preview/apply/reactive work.
    for (EngineOperation& operation : records_)
        if (operation.status == "queued" &&
            SafetyControlOperation(operation.kind) &&
            MatchesQueue(operation, queue)) {
            operation.status = "running";
            return &operation;
        }
    for (EngineOperation& operation : records_) {
        if (operation.status != "queued" ||
            SafetyControlOperation(operation.kind) ||
            !MatchesQueue(operation, queue)) continue;
        operation.status = "running";
        return &operation;
    }
    return nullptr;
}

EngineOperation* EngineOperations::FindMutable(const std::string& id,
                                                std::uint64_t nowMs) {
    Prune(nowMs);
    for (EngineOperation& operation : records_)
        if (operation.id == id) return &operation;
    return nullptr;
}

const EngineOperation* EngineOperations::Find(const std::string& id,
                                               std::uint64_t nowMs) {
    return FindMutable(id, nowMs);
}

}  // namespace wintcp
