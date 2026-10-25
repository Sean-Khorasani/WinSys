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

bool FlatObject(const std::string& json, std::string* object) {
    const std::string marker = "\"normalizedFields\":{";
    const std::size_t found = json.find(marker);
    if (found == std::string::npos) return false;
    const std::size_t begin = found + marker.size() - 1;
    bool quoted = false, escaped = false;
    unsigned depth = 0;
    for (std::size_t i = begin; i < json.size(); ++i) {
        const char c = json[i];
        if (quoted) {
            if (escaped) escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == '"') quoted = false;
            continue;
        }
        if (c == '"') quoted = true;
        else if (c == '{') ++depth;
        else if (c == '}' && --depth == 0) {
            *object = json.substr(begin, i - begin + 1);
            return true;
        }
    }
    return false;
}

bool FlatValue(const std::string& object, const std::string& key,
               std::string* raw) {
    const std::string marker = "\"" + key + "\":";
    const std::size_t found = object.find(marker);
    if (found == std::string::npos) return false;
    std::size_t begin = found + marker.size();
    while (begin < object.size() && (object[begin] == ' ' || object[begin] == '\t')) ++begin;
    std::size_t end = begin;
    if (begin < object.size() && object[begin] == '"') {
        ++end;
        bool escaped = false;
        for (; end < object.size(); ++end) {
            const char c = object[end];
            if (escaped) escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == '"') { ++end; break; }
        }
        if (end > object.size() || object[end - 1] != '"') return false;
    } else {
        while (end < object.size() && object[end] != ',' && object[end] != '}' &&
               object[end] != ' ' && object[end] != '\r' && object[end] != '\n') ++end;
    }
    if (end <= begin) return false;
    *raw = object.substr(begin, end - begin);
    return true;
}

bool FlatString(const std::string& object, const std::string& key,
                std::string* value, bool* known = nullptr) {
    std::string raw;
    if (!FlatValue(object, key, &raw)) return false;
    if (raw == "null") {
        value->clear();
        if (known != nullptr) *known = false;
        return true;
    }
    if (raw.size() < 2 || raw.front() != '"' || raw.back() != '"') return false;
    value->clear();
    for (std::size_t i = 1; i + 1 < raw.size(); ++i) {
        char c = raw[i];
        if (c == '\\') {
            if (++i + 1 >= raw.size()) return false;
            c = raw[i];
            if (c == '"' || c == '\\' || c == '/') value->push_back(c);
            else if (c == 'u' && i + 4 < raw.size() && raw[i + 1] == '0' &&
                     raw[i + 2] == '0') {
                const auto nibble = [](char x) -> int {
                    if (x >= '0' && x <= '9') return x - '0';
                    if (x >= 'a' && x <= 'f') return x - 'a' + 10;
                    if (x >= 'A' && x <= 'F') return x - 'A' + 10;
                    return -1;
                };
                const int hi = nibble(raw[i + 3]), lo = nibble(raw[i + 4]);
                if (hi < 0 || lo < 0) return false;
                value->push_back(static_cast<char>((hi << 4) | lo));
                i += 4;
            } else return false;
        } else value->push_back(c);
    }
    if (known != nullptr) *known = true;
    return true;
}

bool FlatUnsigned(const std::string& object, const std::string& key,
                  std::uint64_t maximum, std::uint64_t* value) {
    std::string raw;
    if (!FlatValue(object, key, &raw)) return false;
    if (raw == "null") { *value = 0; return true; }
    if (raw.size() >= 2 && raw.front() == '"' && raw.back() == '"')
        raw = raw.substr(1, raw.size() - 2);
    if (!ParseSequence(raw, value) || *value > maximum) return false;
    return true;
}

bool FlatBool(const std::string& object, const std::string& key, bool* value) {
    std::string raw;
    if (!FlatValue(object, key, &raw) || (raw != "true" && raw != "false")) return false;
    *value = raw == "true";
    return true;
}

bool FlatEndpoint(const std::string& object, const char* prefix,
                  NetworkEndpoint* endpoint) {
    const std::string base(prefix);
    bool known = false;
    if (!FlatString(object, base + "Address", &endpoint->address, &known)) return false;
    if (!known) { *endpoint = {}; return true; }
    std::uint64_t port = 0, scope = 0;
    if (!FlatUnsigned(object, base + "Port", 65535, &port) ||
        !FlatUnsigned(object, base + "ScopeId", 0xffffffffULL, &scope)) return false;
    endpoint->port = static_cast<std::uint16_t>(port);
    endpoint->scopeId = static_cast<std::uint32_t>(scope);
    endpoint->known = true;
    return true;
}

}  // namespace

std::string NetworkJsonQuote(const std::string& value) { return Quote(value); }

bool ParseLifecycleDerivedEvent(const std::string& traceJson,
                                NetworkEvent* event, std::string* error) {
    const auto fail = [error](const char* reason) {
        if (error != nullptr) *error = reason;
        return false;
    };
    if (event == nullptr || traceJson.size() > 128 * 1024)
        return fail("lifecycle_record_invalid");
    std::string object;
    if (!FlatObject(traceJson, &object)) return fail("normalized_fields_missing");
    NetworkEvent parsed;
    std::string kind, creation, evidenceId;
    std::uint64_t pid = 0, generation = 0;
    bool creationKnown = false;
    if (!FlatString(object, "eventId", &parsed.eventId) || parsed.eventId.empty() ||
        !FlatString(object, "sourceSequence", &parsed.sourceSequence) ||
        !FlatString(object, "source", &parsed.source) ||
        !FlatString(object, "kind", &kind) ||
        !FlatString(object, "occurredAtUtc", &parsed.occurredAtUtc) ||
        !FlatUnsigned(object, "monotonicNs", (std::numeric_limits<std::uint64_t>::max)(),
                      &parsed.monotonicNs) ||
        !FlatString(object, "timebaseId", &parsed.timebaseId) ||
        !FlatString(object, "receivedAtUtc", &parsed.receivedAtUtc) ||
        !FlatUnsigned(object, "pid", 0xffffffffULL, &pid) ||
        !FlatString(object, "creationTimeFileTime", &creation, &creationKnown) ||
        !FlatString(object, "imagePath", &parsed.process.imagePath) ||
        !FlatString(object, "observedImageName", &parsed.process.observedImageName) ||
        !FlatString(object, "flowId", &parsed.flowId) ||
        !FlatUnsigned(object, "flowGeneration", (std::numeric_limits<std::uint64_t>::max)(),
                      &generation) ||
        !FlatBool(object, "lateArrival", &parsed.lateArrival) ||
        !FlatBool(object, "incompleteChronology", &parsed.incompleteChronology) ||
        !FlatString(object, "chronologyReason", &parsed.chronologyReason) ||
        !FlatString(object, "endpointRoleConfidence", &parsed.endpointRoleConfidence) ||
        !FlatBool(object, "firstObservedMidSession", &parsed.firstObservedMidSession) ||
        !FlatString(object, "transport", &parsed.transport) ||
        !FlatString(object, "tcpState", &parsed.tcpState) ||
        !FlatString(object, "family", &parsed.family) ||
        !FlatEndpoint(object, "local", &parsed.local) ||
        !FlatEndpoint(object, "remote", &parsed.remote) ||
        !FlatString(object, "direction", &parsed.direction) ||
        !FlatString(object, "interfaceGuid", &parsed.interfaceGuid) ||
        !FlatString(object, "interfaceReason", &parsed.interfaceReason) ||
        !FlatString(object, "confidence", &parsed.confidence) ||
        !FlatString(object, "evidenceId", &evidenceId) ||
        !FlatString(object, "coverageId", &parsed.coverageId))
        return fail("normalized_fields_invalid");
    parsed.process.pid = static_cast<std::uint32_t>(pid);
    parsed.process.creationTimeKnown = creationKnown;
    if (creationKnown && (!ParseSequence(creation, &parsed.process.creationTimeFileTime) ||
                          parsed.process.creationTimeFileTime == 0))
        return fail("normalized_process_identity_invalid");
    if (kind == "connection_established") parsed.kind = NetworkEventKind::ConnectionEstablished;
    else if (kind == "connection_closed") parsed.kind = NetworkEventKind::ConnectionClosed;
    else if (kind == "udp_activity") parsed.kind = NetworkEventKind::UdpActivity;
    else if (kind == "process_started") parsed.kind = NetworkEventKind::ProcessStarted;
    else if (kind == "process_exited") parsed.kind = NetworkEventKind::ProcessExited;
    else return fail("normalized_event_kind_unsupported");
    if (!evidenceId.empty()) parsed.evidenceIds.push_back(evidenceId);
    *event = std::move(parsed);
    if (error != nullptr) error->clear();
    return true;
}

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
        << ",\"observedImageName\":" << Nullable(event.process.observedImageName)
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

bool NetworkEventJournal::Append(NetworkEvent event) {
    if (!event.eventId.empty() && retainedIds_.find(event.eventId) != retainedIds_.end())
        return false;
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
    if (!record.event.eventId.empty()) retainedIds_.insert(record.event.eventId);
    records_.push_back(std::move(record));
    bytes_ += bytes;
    while (!records_.empty() &&
           (records_.size() > maxRecords_ || bytes_ > maxBytes_)) {
        bytes_ -= records_.front().bytes;
        if (!records_.front().event.eventId.empty())
            retainedIds_.erase(records_.front().event.eventId);
        records_.pop_front();
        ++evictedRecords_;
    }
    return true;
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
