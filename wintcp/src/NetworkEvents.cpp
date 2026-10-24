// NetworkEvents.cpp
// SPDX-License-Identifier: Apache-2.0
#include "NetworkEvents.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <limits>
#include <sstream>
#include <utility>

namespace wintcp {
namespace {

std::string Quote(const std::string& value) {
    static const char kHex[] = "0123456789abcdef";
    std::string out = "\"";
    for (unsigned char c : value) {
        if (c == '"' || c == '\\') {
            out += '\\';
            out += static_cast<char>(c);
        } else if (c < 0x20) {
            out += "\\u00";
            out += kHex[c >> 4];
            out += kHex[c & 15];
        } else {
            out += static_cast<char>(c);
        }
    }
    out += '"';
    return out;
}

std::string Nullable(const std::string& value) {
    return value.empty() ? "null" : Quote(value);
}

std::string EndpointJson(const NetworkEndpoint& endpoint) {
    if (!endpoint.known) return "null";
    return "{\"address\":" + Quote(endpoint.address) +
           ",\"port\":" + std::to_string(endpoint.port) +
           ",\"scopeId\":" + std::to_string(endpoint.scopeId) + "}";
}

bool ParseSequence(const std::string& text, std::uint64_t* result) {
    if (text.empty() || result == nullptr) return false;
    std::uint64_t n = 0;
    for (char c : text) {
        if (c < '0' || c > '9') return false;
        const unsigned digit = static_cast<unsigned>(c - '0');
        if (n > (std::numeric_limits<std::uint64_t>::max() - digit) / 10)
            return false;
        n = n * 10 + digit;
    }
    *result = n;
    return true;
}

}  // namespace

std::string NetworkJsonQuote(const std::string& value) { return Quote(value); }

const char* NetworkEventKindName(NetworkEventKind kind) {
    switch (kind) {
    case NetworkEventKind::EndpointObserved: return "endpoint_observed";
    case NetworkEventKind::EndpointDisappeared: return "endpoint_disappeared";
    case NetworkEventKind::ConnectionAttempted: return "connection_attempted";
    case NetworkEventKind::ConnectionEstablished: return "connection_established";
    case NetworkEventKind::ConnectionClosed: return "connection_closed";
    case NetworkEventKind::ConnectionFailed: return "connection_failed";
    case NetworkEventKind::UdpActivity: return "udp_activity";
    case NetworkEventKind::ConnectionDenied: return "connection_denied";
    case NetworkEventKind::ProcessStarted: return "process_started";
    case NetworkEventKind::ProcessExited: return "process_exited";
    case NetworkEventKind::DnsObserved: return "dns_observed";
    case NetworkEventKind::ProtocolObserved: return "protocol_observed";
    case NetworkEventKind::InterfaceChanged: return "interface_changed";
    case NetworkEventKind::RouteChanged: return "route_changed";
    case NetworkEventKind::RestrictionChanged: return "restriction_changed";
    case NetworkEventKind::CoverageGap: return "coverage_gap";
    }
    return "unknown";
}

bool ProcessActionable(const NetworkProcessIdentity& process) {
    return process.pid != 0 && process.creationTimeKnown &&
           process.creationTimeFileTime != 0 && !process.imagePath.empty();
}

std::string NetworkEventJson(const NetworkEvent& event) {
    std::ostringstream out;
    out << "{\"schemaVersion\":1,\"eventId\":" << Quote(event.eventId)
        << ",\"sourceSequence\":" << Nullable(event.sourceSequence)
        << ",\"source\":" << Quote(event.source)
        << ",\"kind\":" << Quote(NetworkEventKindName(event.kind))
        << ",\"occurredAtUtc\":" << Nullable(event.occurredAtUtc)
        << ",\"monotonicNs\":" << Quote(std::to_string(event.monotonicNs))
        << ",\"timebaseId\":" << Nullable(event.timebaseId)
        << ",\"receivedAtUtc\":" << Nullable(event.receivedAtUtc)
        << ",\"process\":{\"pid\":" << event.process.pid
        << ",\"creationTimeFileTime\":"
        << (event.process.creationTimeKnown
                ? Quote(std::to_string(event.process.creationTimeFileTime)) : "null")
        << ",\"imagePath\":" << Nullable(event.process.imagePath)
        << "},\"flowId\":" << Nullable(event.flowId)
        << ",\"flowGeneration\":" << (event.flowGeneration == 0 ? "null" :
            Quote(std::to_string(event.flowGeneration)))
        << ",\"lateArrival\":" << (event.lateArrival ? "true" : "false")
        << ",\"incompleteChronology\":" << (event.incompleteChronology ? "true" : "false")
        << ",\"chronologyReason\":" << Nullable(event.chronologyReason)
        << ",\"endpointRoleConfidence\":" << Nullable(event.endpointRoleConfidence)
        << ",\"firstObservedMidSession\":"
        << (event.firstObservedMidSession ? "true" : "false")
        << ",\"transport\":" << Nullable(event.transport)
        << ",\"tcpState\":" << Nullable(event.tcpState)
        << ",\"family\":" << Nullable(event.family)
        << ",\"local\":" << EndpointJson(event.local)
        << ",\"remote\":" << EndpointJson(event.remote)
        << ",\"direction\":" << Nullable(event.direction)
        << ",\"interfaceGuid\":" << Nullable(event.interfaceGuid)
        << ",\"interfaceReason\":" << Nullable(event.interfaceReason)
        << ",\"confidence\":" << Quote(event.confidence.empty() ? "unknown" : event.confidence)
        << ",\"evidenceIds\":[";
    for (std::size_t i = 0; i < event.evidenceIds.size(); ++i) {
        if (i != 0) out << ',';
        out << Quote(event.evidenceIds[i]);
    }
    out << "],\"coverageId\":" << Nullable(event.coverageId)
        << ",\"lossReason\":" << Nullable(event.lossReason)
        << ",\"lostRecords\":"
        << (event.kind == NetworkEventKind::CoverageGap
                ? Quote(std::to_string(event.lostRecords)) : "null")
        << '}';
    return out.str();
}

std::string NetworkCapabilityJson(const NetworkCapability& capability) {
    std::ostringstream out;
    out << "{\"id\":" << Quote(capability.id)
        << ",\"supported\":" << (capability.supported ? "true" : "false")
        << ",\"enabled\":" << (capability.enabled ? "true" : "false")
        << ",\"available\":" << (capability.available ? "true" : "false")
        << ",\"requiresElevation\":" << (capability.requiresElevation ? "true" : "false")
        << ",\"reason\":" << Nullable(capability.reason)
        << ",\"coverage\":" << Quote(capability.coverage)
        << ",\"sourceVersion\":" << Nullable(capability.sourceVersion)
        << ",\"lostRecords\":" << Quote(std::to_string(capability.lostRecords))
        << ",\"lastSampleUtc\":" << Nullable(capability.lastSampleUtc) << '}';
    return out.str();
}

NetworkEventJournal::NetworkEventJournal(std::size_t maxRecords, std::size_t maxBytes)
    : maxRecords_(maxRecords), maxBytes_(maxBytes) {
    static std::atomic<std::uint64_t> counter{0};
    const auto tick = std::chrono::steady_clock::now().time_since_epoch().count();
    epoch_ = std::to_string(tick) + "-" + std::to_string(++counter);
}

void NetworkEventJournal::Append(NetworkEvent event) {
    std::size_t bytes = NetworkEventJson(event).size();
    if (bytes > 128 * 1024) {
        NetworkEvent gap;
        gap.kind = NetworkEventKind::CoverageGap;
        gap.source = "engine";
        gap.eventId = event.eventId;
        gap.occurredAtUtc = event.occurredAtUtc;
        gap.receivedAtUtc = event.receivedAtUtc;
        gap.monotonicNs = event.monotonicNs;
        gap.timebaseId = event.timebaseId;
        gap.lossReason = "event_exceeds_record_limit";
        gap.lostRecords = 1;
        event = std::move(gap);
        bytes = NetworkEventJson(event).size();
        ++evictedRecords_;
    }
    Record record;
    record.sequence = nextSequence_++;
    record.bytes = bytes;
    record.event = std::move(event);
    records_.push_back(std::move(record));
    bytes_ += bytes;
    while (!records_.empty() &&
           (records_.size() > maxRecords_ || bytes_ > maxBytes_)) {
        bytes_ -= records_.front().bytes;
        records_.pop_front();
        ++evictedRecords_;
    }
}

NetworkEventPage NetworkEventJournal::Read(const std::string& cursor,
                                           std::size_t limit) const {
    NetworkEventPage page;
    page.evictedRecords = evictedRecords_;
    limit = std::min<std::size_t>(limit, 500);
    std::uint64_t after = records_.empty() ? nextSequence_ - 1
                                            : records_.front().sequence - 1;
    if (cursor.empty() && limit == 0) {
        after = nextSequence_ - 1;
    } else if (cursor.empty() && limit < records_.size()) {
        after = records_[records_.size() - limit].sequence - 1;
    } else if (!cursor.empty()) {
        const std::size_t colon = cursor.find(':');
        if (colon == std::string::npos || cursor.substr(0, colon) != epoch_ ||
            !ParseSequence(cursor.substr(colon + 1), &after) ||
            after >= nextSequence_ ||
            (!records_.empty() && after < records_.front().sequence - 1)) {
            page.cursorExpired = true;
            return page;
        }
    }
    for (const Record& record : records_) {
        if (record.sequence <= after) continue;
        if (page.items.size() == limit) break;
        page.items.push_back(record.event);
        after = record.sequence;
    }
    page.nextCursor = epoch_ + ':' + std::to_string(after);
    return page;
}

}  // namespace wintcp
