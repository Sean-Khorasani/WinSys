// EngineOperations.h
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>

namespace wintcp {

struct EngineOperation {
    std::string kind = "config";
    std::string id;
    std::string requestId;
    std::string expectedRevision;
    std::string configText;
    std::string status = "queued";
    std::string error;
    std::string resultRevision;
    std::string resultJson;
    bool auditRecorded = false;
    std::string auditError;
    bool restartRequired = false;
    std::uint64_t createdAtMs = 0;
    std::uint64_t completedAtMs = 0;
};

enum class OperationDisposition { Created, Duplicate, Reused, Full };
enum class EngineOperationQueue { All, General, Collector };

struct OperationSubmission {
    OperationDisposition disposition = OperationDisposition::Full;
    std::string id;
    std::string status;
};

// Single-owner, bounded operation journal with reserved collector-control
// capacity. Caller supplies a monotonic clock, making expiry and idempotency
// testable without a running engine.
class EngineOperations {
public:
    void SetEpoch(std::string epoch);
    OperationSubmission Existing(const std::string& requestId,
                                 const std::string& revision,
                                 const std::string& configText,
                                 std::uint64_t nowMs,
                                 const std::string& kind = "config");
    OperationSubmission Submit(const std::string& requestId,
                               const std::string& revision,
                               const std::string& configText,
                               std::uint64_t nowMs,
                               const std::string& kind = "config");
    EngineOperation* LatestQueued();
    bool HasQueued(EngineOperationQueue queue = EngineOperationQueue::All) const;
    EngineOperation* TakeNextQueued(EngineOperationQueue queue = EngineOperationQueue::All);
    EngineOperation* FindMutable(const std::string& id,
                                 std::uint64_t nowMs);
    const EngineOperation* Find(const std::string& id, std::uint64_t nowMs);
    void Prune(std::uint64_t nowMs);
    std::size_t Size() const { return records_.size(); }

private:
    std::deque<EngineOperation> records_;
    std::string epoch_;
    std::uint64_t nextId_ = 0;
};

}  // namespace wintcp
