// TcpReasm.h
// SPDX-License-Identifier: Apache-2.0
// Per-4-tuple TCP stream reassembly. Pure: no I/O, no windows.
//
// Takes the packet list from Pcapng and produces, for one connection, the
// two byte streams a "follow TCP stream" view needs - client-to-server and
// server-to-client - with retransmissions, out-of-order segments and overlap
// resolved by sequence number rather than by capture order.
//
// DESIGN NOTE - why sequence numbers and not capture order:
// pktmon reports each frame at more than one layer, so the same segment
// legitimately appears two or three times in the capture. Appending on
// arrival would triple every stream. Every segment is therefore placed by
// its sequence number, and a segment whose range is already covered is
// dropped as a duplicate. That also handles genuine retransmits, which are
// indistinguishable from the layer-duplicates at this level and which must
// likewise not be appended twice.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <cstdint>
#include <string>
#include <vector>

#include "Pcapng.h"

namespace wintcp {

// Identifies one connection direction-agnostically. 'a' is the endpoint that
// sent the lower of the two ports (or, failing that, sorts first), so the key
// is identical whichever way round the caller built it. The full 16-byte
// address is used, not the 32-bit truncation, so two IPv6 peers sharing a low
// word do not collide.
struct TcpKey {
    unsigned char addrA[16] = {0};
    unsigned char addrB[16] = {0};
    uint16_t portA = 0;
    uint16_t portB = 0;
    bool operator==(const TcpKey& o) const;
    bool operator!=(const TcpKey& o) const { return !(*this == o); }
};

// Which side sent a byte, relative to the connection's first SYN if we saw
// one, otherwise relative to the lexicographically smaller endpoint.
enum class StreamDir { ToServer, ToClient };

// One reassembled direction.
//
// NAMING: 'first' and 'second' refer to the canonical endpoint order (see
// TcpKey), NOT to client and server. pktmon does not report which endpoint
// sent the SYN in a way we can rely on when the capture starts mid-connection,
// so calling these "client" and "server" would assert something the data does
// not support. The UI should label them by endpoint address instead.
struct ReasmResult {
    std::string bytes;          // payload in sequence order
    // Sequence of bytes[0]. 64-bit because it is an unwrapped, signed offset
    // from the connection's base packet and can legitimately be negative.
    uint64_t firstSeq = 0;
    size_t bytesMissing = 0;    // gap bytes never observed
    size_t segments = 0;
    size_t duplicates = 0;      // retransmits and layer-duplicates
    bool sawSyn = false;
    bool sawFin = false;
    bool sawRst = false;
    uint16_t window = 0;
    // True when a gap was left unfilled. The UI must say so rather than
    // pretending the stream is contiguous - a hole in the middle of a
    // reassembled stream silently corrupts every protocol decode after it.
    bool hasGap = false;
    // True when the stream hit the in-memory cap and is incomplete.
    bool truncated = false;
};

// Diagnostics for the whole capture, so the window can be honest about what
// happened rather than just showing bytes.
struct ReasmStats {
    size_t packetsIn = 0;
    size_t packetsMatched = 0;     // belonged to the requested 4-tuple
    size_t otherStreams = 0;       // TCP, but a different connection
    size_t nonTcp = 0;
    size_t bytesToServer = 0;
    size_t bytesToClient = 0;
    size_t duplicates = 0;
    size_t gaps = 0;
    size_t gapBytes = 0;
    bool sawSyn = false;
    bool sawFin = false;
    bool sawRst = false;
};

// Reassemble one connection. 'want' must be an unordered key (both
// orientations of the same connection produce the same key, so the caller's
// orientation does not matter). Packets for other connections are counted
// but ignored.
ReasmStats ReassembleStream(const std::vector<ParsedPacket>& packets,
                            const TcpKey& want, ReasmResult* toServer,
                            ReasmResult* toClient);

// Build a key from a packet, ordered canonically.
TcpKey MakeTcpKey(const ParsedPacket& p);

// A display string for diagnostics, e.g. "10.0.0.92:52417 <-> 1.2.3.4:443".
std::wstring DescribeTcpKey(const TcpKey& k);

}  // namespace wintcp
