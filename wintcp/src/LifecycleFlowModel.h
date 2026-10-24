// LifecycleFlowModel.h
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "EventDecoder.h"
#include <deque>
#include <map>

namespace wintcp {

std::size_t TraceObservationBytes(const TraceObservation& observation);

// Single decoder owner. Orders up to 250 ms, retains bounded flow generations,
// and annotates chronology gaps without changing the original observation.
class LifecycleFlowModel {
public:
    LifecycleFlowModel(std::string epoch, std::uint64_t frequency,
                       std::size_t flowCapacity = 50000,
                       std::size_t pendingCapacity = 2048);
    std::vector<TraceObservation> Push(TraceObservation observation, std::uint64_t nowQpc);
    std::vector<TraceObservation> Drain(std::uint64_t nowQpc, bool force = false);
    std::size_t FlowCount() const { return flows_.size(); }
    std::uint64_t EvictedFlows() const { return evicted_; }
    std::uint64_t CapacityFlushes() const { return capacityFlushes_; }
    std::uint64_t LateRecords() const { return late_; }
private:
    struct Flow {
        std::string key;
        LifecycleAnnotation annotation;
        std::uint64_t start = 0, closed = 0, superseded = 0;
        std::size_t bytes = 0;
    };
    TraceObservation Normalize(TraceObservation observation, const char* flushReason);
    std::string Key(const TraceObservation& observation) const;
    Flow* CreateFlow(const std::string& key, std::uint64_t qpc,
                     LifecycleAnnotation annotation);
    void EvictOldest();
    std::string epoch_;
    std::uint64_t frequency_, highestSequence_ = 0, emittedQpc_ = 0, nextFlow_ = 0;
    std::uint64_t maxSourceQpc_ = 0, lastPushQpc_ = 0;
    std::size_t flowCapacity_, pendingCapacity_, flowBytes_ = 0, pendingBytes_ = 0;
    std::uint64_t evicted_ = 0, capacityFlushes_ = 0, late_ = 0;
    std::map<std::pair<std::uint64_t, std::uint64_t>, TraceObservation> pending_;
    std::map<std::uint64_t, Flow> flows_;
    std::map<std::string, std::deque<std::uint64_t>> index_;
};
}  // namespace wintcp
