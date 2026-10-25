// NetworkEvents.h
// SPDX-License-Identifier: Apache-2.0
// Versioned, source-aware observations shared by collectors and consumers.
#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>
#include <unordered_set>
#include <vector>

namespace wintcp {

enum class NetworkEventKind {
    EndpointObserved, EndpointDisappeared, ConnectionAttempted,
    ConnectionEstablished, ConnectionClosed, ConnectionFailed, UdpActivity,
    ConnectionDenied, ProcessStarted, ProcessExited, DnsObserved,
    ProtocolObserved, InterfaceChanged, RouteChanged, RestrictionChanged,
    CoverageGap,
};

const char* NetworkEventKindName(NetworkEventKind kind);

struct NetworkEndpoint {
    std::string address;             // UTF-8 numeric address, empty if unknown
    std::uint16_t port = 0;
    std::uint32_t scopeId = 0;
    bool known = false;
};

struct NetworkProcessIdentity {
    std::uint32_t pid = 0;
    std::uint64_t creationTimeFileTime = 0;
    bool creationTimeKnown = false;
    std::string imagePath;           // UTF-8; empty if unresolved
    std::string observedImageName;    // Source label only; not a verified executable path.
};

// No event kind implies another kind. A snapshot appearance is never an
// attempted connection, and unknown process creation time forbids an action.
struct NetworkEvent {
    std::string eventId;
    std::string sourceSequence;
    std::string source;
    NetworkEventKind kind = NetworkEventKind::EndpointObserved;
    std::string occurredAtUtc;
    std::uint64_t monotonicNs = 0;
    std::string timebaseId;          // UTC/monotonic mapping generation
    std::string receivedAtUtc;
    NetworkProcessIdentity process;
    std::string flowId;
    std::uint64_t flowGeneration = 0;
    bool lateArrival = false;
    bool incompleteChronology = false;
    std::string chronologyReason;
    std::string endpointRoleConfidence;
    bool firstObservedMidSession = false;
    std::string transport;           // tcp, udp, or empty if not applicable
    std::string tcpState;            // listen, established, other, or unknown
    std::string family;              // ipv4, ipv6, or empty if unknown
    NetworkEndpoint local;
    NetworkEndpoint remote;
    std::string direction;           // inbound, outbound, or empty
    std::string interfaceGuid;       // empty means unknown, not default route
    std::string interfaceReason;
    std::string confidence;          // observed, inferred, or unknown
    std::vector<std::string> evidenceIds;
    std::string coverageId;
    std::string lossReason;
    std::uint64_t lostRecords = 0;
};

std::string NetworkEventJson(const NetworkEvent& event);
std::string NetworkJsonQuote(const std::string& value);
// Parses the collector's flat normalizedFields object embedded in one raw
// lifecycle record. Raw evidence remains separately retained if this fails.
bool ParseLifecycleDerivedEvent(const std::string& traceJson,
                                NetworkEvent* event, std::string* error);
bool ProcessActionable(const NetworkProcessIdentity& process);

struct NetworkCapability {
    std::string id;
    bool supported = false;
    bool enabled = false;
    bool available = false;
    bool requiresElevation = false;
    std::string reason;
    std::string coverage = "none";
    std::string sourceVersion;
    std::uint64_t lostRecords = 0;
    std::string lastSampleUtc;
};

std::string NetworkCapabilityJson(const NetworkCapability& capability);

struct NetworkEventPage {
    std::vector<NetworkEvent> items;
    std::string nextCursor;
    bool cursorExpired = false;
    std::uint64_t evictedRecords = 0;
};

// Single-owner bounded ring. Cursors encode a journal epoch and sequence, so
// a restart or eviction fails visibly instead of silently skipping records.
class NetworkEventJournal {
public:
    explicit NetworkEventJournal(std::size_t maxRecords = 16384,
                                 std::size_t maxBytes = 8 * 1024 * 1024);
    bool Append(NetworkEvent event);
    NetworkEventPage Read(const std::string& cursor, std::size_t limit) const;
    std::size_t Size() const { return records_.size(); }
    std::uint64_t EvictedRecords() const { return evictedRecords_; }

private:
    struct Record {
        std::uint64_t sequence = 0;
        std::size_t bytes = 0;
        NetworkEvent event;
    };
    std::deque<Record> records_;
    std::unordered_set<std::string> retainedIds_;
    std::string epoch_;
    std::uint64_t nextSequence_ = 1;
    std::uint64_t evictedRecords_ = 0;
    std::size_t bytes_ = 0;
    std::size_t maxRecords_;
    std::size_t maxBytes_;
};

}  // namespace wintcp
