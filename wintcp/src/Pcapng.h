// Pcapng.h
// SPDX-License-Identifier: Apache-2.0
// A minimal, allocation-happy pcapng reader for the follow-stream feature
// Pure: it parses a byte buffer the caller supplies, and does
// no file I/O, no registry, no window work.
//
// WHY THIS EXISTS INSTEAD OF WIRESHARK: pktmon's `etl2pcap` writes an IDB
// whose LinkType is the non-standard value 6, which is not a valid
// LINKTYPE_* constant. Standard readers reject or mis-parse the file. The
// packet bytes themselves start at the IP header with no Ethernet preamble,
// so "link type 6" here means "strip nothing".
//
// Deliberately supported: the block types pktmon actually emits (SHB, IDB,
// EPB, SPB) plus a graceful skip of anything unknown, so a future pktmon
// build that adds a block does not make us fail to read the whole file.

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

namespace wintcp {

// One parsed packet: the TCP/IP payload plus the fields needed to route it
// to a 4-tuple. The payload is a *view* into the caller's buffer - it is not
// copied, so the buffer must outlive the parse results.
struct ParsedPacket {
    const unsigned char* payload = nullptr;  // TCP payload, after options
    size_t payloadLen = 0;
    uint32_t srcIp = 0;      // host byte order
    uint32_t dstIp = 0;      // host byte order
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    uint8_t ipVersion = 0;   // 4 or 6
    uint8_t tcpFlags = 0;    // the 9-bit flag byte (low 8 bits; NS is not
                             // carried in the captured data offset area)
    uint32_t seq = 0;        // 32-bit TCP sequence number
    uint32_t ack = 0;
    uint16_t window = 0;
    // The full 128-bit source address. For IPv4 only the first 4 bytes are
    // meaningful and the rest is zero. TcpReasm keys on these 16 bytes, not
    // on srcIp/dstIp: collapsing an IPv6 address to its low word would let
    // two distinct peers collide on the same 4-tuple.
    unsigned char srcIp16[16] = {0};
    unsigned char dstIp16[16] = {0};
    bool malformed = false;  // header claimed more bytes than were present
};

// A known link type comes from a file's IDB. kLinkAuto means "no IDB" and
// forces per-packet probing. Declared before PcapngParse, which uses it.
constexpr uint16_t kLinkAuto = 0;

// Result of a whole-file parse.
struct PcapngParse {
    std::vector<ParsedPacket> packets;
    size_t blocksSeen = 0;
    // Size of the file that produced this parse. Used only to tell an EMPTY
    // capture (pktmon's boilerplate, a few KB, no packets) from one whose packet
    // blocks this build failed to recognise - two very different situations that
    // otherwise produce the same "no EPB or SPB" report. See the error text in
    // ParsePcapng.
    size_t fileBytes = 0;
    size_t packetsSkipped = 0;   // non-TCP, non-IP, or malformed
    size_t badBlocks = 0;        // length field nonsense (file stopped early)
    size_t spbSeen = 0;
    size_t epbSeen = 0;
    // pktmon's own per-flow records, which `etl2pcap` interleaves with real
    // packets. They carry a 16-byte synthetic header instead of an Ethernet
    // header and are correctly discarded; counted so the UI can report
    // "N packets + M flow records" rather than a bare number.
    size_t flowRecords = 0;
    // The link type from the first IDB, or kLinkAuto when the file has none.
    // Used for display and diagnostics; parsing itself is per-packet.
    uint16_t linkType = kLinkAuto;
    bool ok = false;
    std::wstring error;
};

// Parse a pcapng image. Handles both endian variants of every field,
// because the format permits either and pktmon has been observed to vary.
PcapngParse ParsePcapng(const unsigned char* data, size_t len);

// Strip the link + IP + TCP headers from a single raw packet, filling 'out'.
// When 'linkType' is 0 the link layer is auto-detected from the IP version
// nibble, which is what pktmon files need. Exposed separately so --selftest
// can feed it hand-built packets without synthesising a pcapng container.
bool ParseIpTcp(const unsigned char* pkt, size_t len, uint16_t linkType,
                ParsedPacket* out);

const wchar_t* PcapngLinkTypeName(uint16_t linkType);

}  // namespace wintcp
