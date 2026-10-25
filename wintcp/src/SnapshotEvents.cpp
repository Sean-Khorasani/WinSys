// SnapshotEvents.cpp
// SPDX-License-Identifier: Apache-2.0
#include "SnapshotEvents.h"

#include <tcpmib.h>

#include <utility>

#include "Utils.h"

namespace wintcp {
namespace {

std::uint64_t CreationTime(const FILETIME& value) {
    return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32) |
           value.dwLowDateTime;
}

std::string IdentityKey(const Connection& row) {
    // Length-prefix each variable part to avoid tuple delimiter collisions.
    std::string key;
    const auto part = [&key](const std::string& value) {
        key += std::to_string(value.size()) + ':' + value;
    };
    part(std::to_string(row.identity.pid));
    part(row.procMeta.processCreateKnown
             ? std::to_string(CreationTime(row.procMeta.processCreate)) : "unknown");
    part(std::to_string(row.identity.family));
    part(std::to_string(row.identity.protocol));
    part(WideToUtf8(row.display.localAddress));
    part(std::to_string(row.identity.localPort));
    part(std::to_string(row.identity.localScope));
    part(WideToUtf8(row.display.remoteAddress));
    part(std::to_string(row.identity.remotePort));
    part(std::to_string(row.identity.remoteScope));
    return key;
}

NetworkEvent MakeObservation(const Connection& row, const std::string& utc,
                             std::uint64_t monotonicNs) {
    NetworkEvent event;
    event.source = "snapshot";
    event.kind = NetworkEventKind::EndpointObserved;
    event.occurredAtUtc = utc;
    event.receivedAtUtc = utc;
    event.monotonicNs = monotonicNs;
    event.process.pid = row.identity.pid;
    event.process.creationTimeKnown = row.procMeta.processCreateKnown;
    if (row.procMeta.processCreateKnown)
        event.process.creationTimeFileTime = CreationTime(row.procMeta.processCreate);
    event.process.imagePath = WideToUtf8(row.display.processPath);
    event.transport = row.identity.protocol == IPPROTO_TCP ? "tcp" : "udp";
    if (row.identity.protocol == IPPROTO_TCP) {
        event.tcpState = row.identity.state == MIB_TCP_STATE_LISTEN ? "listen" :
            row.identity.state == MIB_TCP_STATE_ESTAB ? "established" : "other";
    }
    event.family = row.identity.family == AF_INET6 ? "ipv6" : "ipv4";
    event.local = {WideToUtf8(row.display.localAddress),
                   static_cast<std::uint16_t>(row.identity.localPort),
                   row.identity.localScope, true};
    if (row.identity.remotePort != 0 &&
        !row.display.remoteAddress.empty() && row.display.remoteAddress != L"*") {
        event.remote = {WideToUtf8(row.display.remoteAddress),
                        static_cast<std::uint16_t>(row.identity.remotePort),
                        row.identity.remoteScope, true};
    }
    event.interfaceReason = "not_reported_by_source";
    event.confidence = "observed";
    return event;
}

}  // namespace

SnapshotEventAdapter::SnapshotEventAdapter(std::string epoch)
    : epoch_(std::move(epoch)) {}

std::vector<NetworkEvent> SnapshotEventAdapter::Observe(
    const std::vector<Connection>& rows, const std::string& utc,
    std::uint64_t monotonicNs) {
    if (rows.size() > 50000) {
        NetworkEvent gap;
        gap.eventId = epoch_ + ':' + std::to_string(++sequence_);
        gap.sourceSequence = std::to_string(sequence_);
        gap.source = "snapshot";
        gap.kind = NetworkEventKind::CoverageGap;
        gap.occurredAtUtc = utc;
        gap.receivedAtUtc = utc;
        gap.monotonicNs = monotonicNs;
        gap.lossReason = "flow_limit_exceeded";
        gap.lostRecords = rows.size();
        gap.confidence = "observed";
        return {gap};
    }
    std::map<std::string, NetworkEvent> current;
    std::vector<NetworkEvent> emitted;
    for (const Connection& row : rows) {
        const std::string key = IdentityKey(row);
        if (current.find(key) != current.end()) continue;
        auto old = previous_.find(key);
        if (old != previous_.end()) {
            current.emplace(key, old->second);
            continue;
        }
        NetworkEvent event = MakeObservation(row, utc, monotonicNs);
        event.firstObservedMidSession = !baseline_;
        event.flowId = epoch_ + ":flow-" + std::to_string(++flowSequence_);
        event.sourceSequence = std::to_string(++sequence_);
        event.eventId = epoch_ + ':' + event.sourceSequence;
        current.emplace(key, event);
        emitted.push_back(std::move(event));
    }
    for (const auto& entry : previous_) {
        if (current.find(entry.first) != current.end()) continue;
        NetworkEvent event = entry.second;
        event.kind = NetworkEventKind::EndpointDisappeared;
        event.occurredAtUtc = utc;
        event.receivedAtUtc = utc;
        event.monotonicNs = monotonicNs;
        event.sourceSequence = std::to_string(++sequence_);
        event.eventId = epoch_ + ':' + event.sourceSequence;
        event.firstObservedMidSession = false;
        emitted.push_back(std::move(event));
    }
    previous_ = std::move(current);
    baseline_ = true;
    return emitted;
}

std::string SnapshotEventAdapter::CheckpointJson(const std::string& utc,
    std::uint64_t monotonicNs, std::size_t maxBytes) {
    constexpr std::size_t kMinimumBytes = 1024;
    constexpr std::size_t kMaximumBytes = 128 * 1024;
    maxBytes = (std::max)(kMinimumBytes, (std::min)(maxBytes, kMaximumBytes));
    std::string json = "{\"schemaVersion\":1,\"kind\":\"state_checkpoint\",";
    json += "\"source\":\"snapshot\",\"occurredAtUtc\":" +
        NetworkJsonQuote(utc) + ",\"monotonicNs\":\"" +
        std::to_string(monotonicNs) + "\",\"state\":{\"coverage\":\"snapshot_only\",";
    json += "\"complete\":";
    const std::size_t completeAt = json.size();
    json += "true,\"items\":[";
    std::size_t included = 0;
    bool complete = true;
    for (const auto& entry : previous_) {
        NetworkEvent state = entry.second;
        state.kind = NetworkEventKind::EndpointObserved;
        state.occurredAtUtc = utc;
        state.receivedAtUtc = utc;
        state.monotonicNs = monotonicNs;
        const std::string serialized = NetworkEventJson(state);
        const std::size_t separator = included == 0 ? 0 : 1;
        constexpr std::size_t kClosingReserve = 96;
        if (json.size() + kClosingReserve > maxBytes ||
            serialized.size() + separator >
                maxBytes - json.size() - kClosingReserve) {
            complete = false;
            break;
        }
        if (separator != 0) json.push_back(',');
        json += serialized;
        ++included;
    }
    json.replace(completeAt, 4, complete ? "true" : "false");
    const std::string suffix = "],\"includedEndpoints\":" +
        std::to_string(included) + ",\"totalEndpoints\":" +
        std::to_string(previous_.size()) + "}}";
    if (json.size() + suffix.size() > maxBytes) {
        // Metadata is deliberately kept even when every endpoint is omitted.
        return "{\"schemaVersion\":1,\"kind\":\"state_checkpoint\","
            "\"source\":\"snapshot\",\"occurredAtUtc\":" +
            NetworkJsonQuote(utc) + ",\"monotonicNs\":\"" +
            std::to_string(monotonicNs) +
            "\",\"state\":{\"coverage\":\"snapshot_only\","
            "\"complete\":false,\"items\":[],\"includedEndpoints\":0,"
            "\"totalEndpoints\":" + std::to_string(previous_.size()) + "}}";
    }
    json += suffix;
    return json;
}

void SnapshotEventAdapter::Reset() {
    previous_.clear();
    baseline_ = false;
}

}  // namespace wintcp
