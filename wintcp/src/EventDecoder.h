// EventDecoder.h
// SPDX-License-Identifier: Apache-2.0
#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <cstdint>
#include <string>
#include <vector>
#include "NetworkEvents.h"

namespace wintcp {

inline constexpr GUID kProcessEventProviderGuid = {
    0x3d6fa8d0, 0xfe05, 0x11d0, {0x9d,0xda,0x00,0xc0,0x4f,0xd7,0xba,0x7c}};
enum class LifecycleType {
    Unsupported, TcpConnect, TcpAccept, TcpDisconnect, UdpSend, UdpReceive,
    ProcessStart, ProcessExit, ProcessRundown,
};
enum class EventDecodeResult { Decoded, Unsupported, Malformed, SchemaUnavailable };

struct DecodedLifecycleRecord {
    LifecycleType type = LifecycleType::Unsupported;
    std::uint32_t pid = 0;  // Always a payload field, never header.ProcessId.
    std::string family;
    NetworkEndpoint source;
    NetworkEndpoint destination;
    std::uint64_t correlationKey = 0;
    bool correlationKeyKnown = false;
    std::uint32_t bytes = 0;
    bool bytesKnown = false;
};

struct LifecycleAnnotation {
    bool available = false;
    NetworkEventKind kind = NetworkEventKind::CoverageGap;
    std::string flowId;
    std::uint64_t generation = 0;
    std::uint64_t monotonicNs = 0;
    NetworkEndpoint local, remote;
    std::string direction;
    std::string roleConfidence;
    std::string chronologyReason;
    bool late = false;
    bool incomplete = false;
    bool midSession = false;
};

struct TraceObservation {
    std::uint64_t sequence = 0;
    std::uint64_t publicationSequence = 0;
    std::uint64_t sourceQpc = 0;
    std::uint64_t receivedUtcMs = 0;
    EVENT_DESCRIPTOR descriptor = {};
    GUID provider = {};
    USHORT headerFlags = 0;
    DecodedLifecycleRecord decoded;
    NetworkProcessIdentity process;
    std::string identityReason = "attribution_pending";
    std::uint64_t occurredFileTime = 0;
    std::string timeReason = "qpc_mapping_pending";
    LifecycleAnnotation lifecycle;
};

// Injectable schema property access: production uses TDH; dev fixtures can
// exercise the exact field/byte-order checks without an elevated ETW session.
class EventPropertyReader {
public:
    virtual ~EventPropertyReader() = default;
    virtual bool Read(const wchar_t* name, std::vector<unsigned char>* bytes) = 0;
};

LifecycleType ClassifyLifecycleEvent(const EVENT_HEADER& header);
EventDecodeResult DecodeLifecycleFields(const EVENT_HEADER& header,
    EventPropertyReader& properties, DecodedLifecycleRecord* result, std::string* error);
EventDecodeResult DecodeLifecycleRecord(const EVENT_RECORD* record,
    DecodedLifecycleRecord* result, std::string* error);

}  // namespace wintcp
