// LifecycleFlowModel.cpp
// SPDX-License-Identifier: Apache-2.0
#include "LifecycleFlowModel.h"
#include <algorithm>
#include <limits>
#include <utility>

namespace wintcp {
namespace {
constexpr std::size_t kFlowBudget = 8 * 1024 * 1024;
constexpr std::size_t kPendingBudget = 4 * 1024 * 1024;
std::string Field(const std::string& value) { return std::to_string(value.size()) + ':' + value; }
std::string EndpointKey(const NetworkEndpoint& endpoint) {
    return Field(endpoint.address) + ':' + std::to_string(endpoint.port) + ':' +
        std::to_string(endpoint.scopeId);
}
void Incomplete(LifecycleAnnotation* annotation, const char* reason) {
    annotation->incomplete = true;
    if (annotation->chronologyReason.find(reason) != std::string::npos ||
        annotation->chronologyReason.size() >= 256) return;
    if (!annotation->chronologyReason.empty()) annotation->chronologyReason += ';';
    annotation->chronologyReason += reason;
}
}  // namespace

std::size_t TraceObservationBytes(const TraceObservation& observation) {
    return sizeof(observation) + 64 + 2 * (observation.process.imagePath.size() +
        observation.process.observedImageName.size() + observation.observedImageName.size() +
        observation.identityReason.size() + observation.timeReason.size() +
        observation.decoded.family.size() + observation.decoded.source.address.size() +
        observation.decoded.destination.address.size() + observation.lifecycle.flowId.size() +
        observation.lifecycle.local.address.size() + observation.lifecycle.remote.address.size() +
        observation.lifecycle.direction.size() + observation.lifecycle.roleConfidence.size() +
        observation.lifecycle.chronologyReason.size());
}

LifecycleFlowModel::LifecycleFlowModel(std::string epoch, std::uint64_t frequency,
    std::size_t flowCapacity, std::size_t pendingCapacity)
    : epoch_(std::move(epoch)), frequency_(frequency),
      flowCapacity_((std::max)(std::size_t{1}, (std::min)(flowCapacity, std::size_t{50000}))),
      pendingCapacity_((std::max)(std::size_t{1}, (std::min)(pendingCapacity, std::size_t{16384}))) {}

std::string LifecycleFlowModel::Key(const TraceObservation& observation) const {
    std::string a = EndpointKey(observation.decoded.source);
    std::string b = EndpointKey(observation.decoded.destination);
    if (b < a) std::swap(a, b);
    return std::to_string(observation.decoded.pid) + ':' +
        (observation.process.creationTimeKnown
            ? std::to_string(observation.process.creationTimeFileTime) : "unverified") + ':' +
        Field(observation.decoded.family) + Field(a) + Field(b) + ':' +
        (observation.decoded.correlationKeyKnown
            ? std::to_string(observation.decoded.correlationKey) : "no-key");
}

void LifecycleFlowModel::EvictOldest() {
    if (flows_.empty()) return;
    const auto oldest = flows_.begin();
    auto found = index_.find(oldest->second.key);
    if (found != index_.end()) {
        auto& ids = found->second;
        ids.erase(std::remove(ids.begin(), ids.end(), oldest->first), ids.end());
        if (ids.empty()) index_.erase(found);
    }
    flowBytes_ -= oldest->second.bytes;
    flows_.erase(oldest);
    ++evicted_;
}

LifecycleFlowModel::Flow* LifecycleFlowModel::CreateFlow(const std::string& key,
    std::uint64_t qpc, LifecycleAnnotation annotation,
    const NetworkProcessIdentity& process) {
    const std::size_t bytes = sizeof(Flow) + 256 + key.size() * 2 +
        2 * (annotation.local.address.size() + annotation.remote.address.size() +
             process.imagePath.size() + process.observedImageName.size());
    while (!flows_.empty() && (flows_.size() >= flowCapacity_ ||
                              flowBytes_ + bytes > kFlowBudget)) EvictOldest();
    if (bytes > kFlowBudget) return nullptr;
    const auto generation = ++nextFlow_;
    annotation.generation = generation;
    annotation.flowId = epoch_ + ":flow-" + std::to_string(generation);
    auto inserted = flows_.emplace(generation, Flow{key, std::move(annotation), qpc, 0, 0,
                                                     bytes, process});
    index_[key].push_back(generation);
    flowBytes_ += bytes;
    return &inserted.first->second;
}

TraceObservation LifecycleFlowModel::Normalize(TraceObservation observation,
                                               const char* flushReason) {
    auto& annotation = observation.lifecycle;
    const auto type = observation.decoded.type;
    if (frequency_ == 0 || frequency_ > 1000000000000ULL) return observation;
    const auto seconds = observation.sourceQpc / frequency_;
    if (seconds > (std::numeric_limits<std::uint64_t>::max)() / 1000000000ULL)
        return observation;
    const auto fraction = ((observation.sourceQpc % frequency_) * 1000000ULL / frequency_) * 1000;
    const auto whole = seconds * 1000000000ULL;
    if (whole > (std::numeric_limits<std::uint64_t>::max)() - fraction) return observation;
    annotation.monotonicNs = whole + fraction;
    annotation.available = type != LifecycleType::Unsupported && type != LifecycleType::ProcessRundown;
    const bool connect = type == LifecycleType::TcpConnect || type == LifecycleType::TcpAccept;
    const bool close = type == LifecycleType::TcpDisconnect;
    if (connect || type == LifecycleType::UdpSend || type == LifecycleType::UdpReceive) {
        const bool outgoing = type == LifecycleType::TcpConnect || type == LifecycleType::UdpSend;
        annotation.direction = outgoing ? "outbound" : "inbound";
        annotation.local = outgoing ? observation.decoded.source : observation.decoded.destination;
        annotation.remote = outgoing ? observation.decoded.destination : observation.decoded.source;
        annotation.roleConfidence = "source_semantics";
    }
    if (connect || close) {
        annotation.kind = connect ? NetworkEventKind::ConnectionEstablished : NetworkEventKind::ConnectionClosed;
        const std::string key = Key(observation);
        Flow* selected = nullptr;
        const auto found = index_.find(key);
        if (found != index_.end()) {
            for (const auto id : found->second) {
                auto& flow = flows_.at(id);
                if (flow.start > observation.sourceQpc ||
                    (flow.superseded != 0 && observation.sourceQpc >= flow.superseded)) continue;
                if (connect) {
                    if (flow.closed == 0 && flow.start < observation.sourceQpc) {
                        flow.superseded = observation.sourceQpc;
                        Incomplete(&annotation, "previous_generation_not_closed");
                    }
                } else if ((flow.closed == 0 || observation.sourceQpc <= flow.closed) &&
                           (selected == nullptr || selected->start < flow.start)) selected = &flow;
            }
        }
        if (connect) selected = CreateFlow(key, observation.sourceQpc, annotation,
                                            observation.process);
        else if (selected == nullptr) {
            annotation.midSession = true;
            Incomplete(&annotation, "connect_not_observed");
            selected = CreateFlow(key, observation.sourceQpc, annotation,
                                  observation.process);
        }
        if (selected != nullptr) {
            annotation.flowId = selected->annotation.flowId;
            annotation.generation = selected->annotation.generation;
            if (close) {
                selected->closed = observation.sourceQpc;
                // Carry only the source-observed name along an exact retained
                // flow match. Never upgrade it into an executable path or
                // creation-time identity for an event delivered after exit.
                if (observation.process.observedImageName.empty() &&
                    !selected->process.observedImageName.empty()) {
                    observation.process.observedImageName = selected->process.observedImageName;
                    observation.observedImageName = selected->process.observedImageName;
                    observation.identityReason = "flow_correlated_image_name_only";
                }
                annotation.local = selected->annotation.local;
                annotation.remote = selected->annotation.remote;
                annotation.direction = selected->annotation.direction;
                annotation.roleConfidence = selected->annotation.roleConfidence;
                annotation.midSession = selected->annotation.midSession;
                if (selected->annotation.incomplete && !annotation.incomplete)
                    Incomplete(&annotation, "flow_started_with_gap");
            }
        } else Incomplete(&annotation, "flow_capacity_unavailable");
    } else if (type == LifecycleType::UdpSend || type == LifecycleType::UdpReceive)
        annotation.kind = NetworkEventKind::UdpActivity;
    else if (type == LifecycleType::ProcessStart) annotation.kind = NetworkEventKind::ProcessStarted;
    else if (type == LifecycleType::ProcessExit) annotation.kind = NetworkEventKind::ProcessExited;
    if (observation.sourceQpc < emittedQpc_) {
        annotation.late = true;
        ++late_;
        Incomplete(&annotation, "outside_reorder_window");
    }
    if (flushReason != nullptr) Incomplete(&annotation, flushReason);
    emittedQpc_ = (std::max)(emittedQpc_, observation.sourceQpc);
    return observation;
}

std::vector<TraceObservation> LifecycleFlowModel::Push(TraceObservation observation,
                                                       std::uint64_t nowQpc) {
    if (observation.sequence == 0 || observation.sequence <= highestSequence_ ||
        observation.sourceQpc == 0) return {};
    highestSequence_ = observation.sequence;
    maxSourceQpc_ = (std::max)(maxSourceQpc_, observation.sourceQpc);
    lastPushQpc_ = nowQpc;
    pendingBytes_ += TraceObservationBytes(observation);
    const auto key = std::make_pair(observation.sourceQpc, observation.sequence);
    pending_.emplace(key, std::move(observation));
    auto ready = Drain(nowQpc);
    while (!pending_.empty() && (pending_.size() > pendingCapacity_ || pendingBytes_ > kPendingBudget)) {
        auto first = pending_.begin();
        pendingBytes_ -= TraceObservationBytes(first->second);
        ready.push_back(Normalize(std::move(first->second), "reorder_capacity_flush"));
        pending_.erase(first);
        ++capacityFlushes_;
    }
    return ready;
}

std::vector<TraceObservation> LifecycleFlowModel::Drain(std::uint64_t nowQpc, bool force) {
    std::vector<TraceObservation> ready;
    const auto window = (std::max)(std::uint64_t{1}, frequency_ / 4);
    const auto cutoff = maxSourceQpc_ >= window ? maxSourceQpc_ - window : 0;
    const bool quiet = nowQpc >= lastPushQpc_ && nowQpc - lastPushQpc_ >= window;
    while (!pending_.empty() && (force || quiet || pending_.begin()->first.first <= cutoff)) {
        auto first = pending_.begin();
        pendingBytes_ -= TraceObservationBytes(first->second);
        ready.push_back(Normalize(std::move(first->second), force ? "forced_drain" : nullptr));
        pending_.erase(first);
    }
    return ready;
}
}  // namespace wintcp
