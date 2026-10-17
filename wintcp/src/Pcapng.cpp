// Pcapng.cpp
// SPDX-License-Identifier: Apache-2.0
// See Pcapng.h. Every field is read through the byte-order helpers below and
// every length is validated before it is used to index, because the input is
// a file that may be truncated mid-block (pktmon killed, disk full, or a
// capture stopped early) and a bad length must produce a parse error rather
// than an out-of-bounds read.

#include "Pcapng.h"

#include <cstring>

#include "Opt.h"

namespace wintcp {
namespace {

// pcapng block types we care about. Everything else is skipped by length.
constexpr uint32_t kBlockSHB = 0x0A0D0D0A;
constexpr uint32_t kBlockIDB = 0x00000001;
constexpr uint32_t kBlockSPB = 0x00000003;
constexpr uint32_t kBlockEPB = 0x00000006;

// pktmon's IDB link type. Not a LINKTYPE_* value - see Pcapng.h.
constexpr uint16_t kLinkTypePktmonRaw = 6;

constexpr size_t kBlockHeaderBytes = 8;   // type + total length

// Smallest legal total length per block type, checked before any field is read.
// Each is the 8-byte block header plus the fixed fields that type must carry -
// so these are the format's floors, not tuning, and a block shorter than one is
// malformed rather than merely empty. Named because the four numbers sat as
// bare literals in four different branches, where a wrong one is a read
// past the block: the shortest SPB is 16 bytes and nothing else is.
constexpr size_t kMinSectionHeaderBytes = 16;    // + byte-order magic
constexpr size_t kMinInterfaceDescBytes = 20;    // + link type + reserved
constexpr size_t kMinSimplePacketBytes = 16;     // + original length
constexpr size_t kMinEnhancedPacketBytes = 32;   // + interface + timestamps

// A capture file with no packet data on it is a capture of nothing. 64 KB is
// deliberately generous: a real pktmon capture with traffic is orders of
// magnitude larger, while the 8-32 KB of boilerplate a header-only file
// carries stays comfortably under this. Named so the threshold and the
// reasoning about it are one unit rather than an expression and a paragraph.
constexpr unsigned long kMinTrafficCaptureBytes = 64ul * 1024ul;

// IP header field offsets and lengths. These are the RFC's layout, so they are
// protocol facts rather than tuning - but they were bare numbers at eight
// sites, and an off-by-one in any of them does not throw: it reads the wrong
// bytes of the header and reports a plausible-looking wrong address. Offsets
// are from the START OF THE IP HEADER; the length is the header's own minimum.
constexpr size_t kIpv4HeaderMinBytes = 20;
constexpr size_t kIpv6HeaderBytes = 40;      // fixed by RFC 8200
constexpr size_t kIpv4SrcAddrOffset = 12;
constexpr size_t kIpv4DstAddrOffset = 16;
constexpr size_t kIpv4ProtoOffset = 9;
constexpr size_t kIpv4TotalLenOffset = 2;
constexpr size_t kIpv6SrcAddrOffset = 8;
constexpr size_t kIpv6DstAddrOffset = 24;
// A TCP header is never shorter than its five fixed words (src/dst port,
// sequence, ack) plus the data-offset word.
constexpr size_t kTcpHeaderMinBytes = 20;
// TCP field offsets, same RFC 793 layout and the same warning as the IP ones
// above: a wrong offset reads the wrong bytes and reports a plausible-looking
// wrong port, flag or window rather than failing.
constexpr size_t kTcpSeqOffset = 4;
constexpr size_t kTcpAckOffset = 8;
constexpr size_t kTcpDataOffsetOffset = 12;
constexpr size_t kTcpFlagsOffset = 13;
constexpr size_t kTcpWindowOffset = 14;
constexpr size_t kIpProtoTcp = 6;
constexpr size_t kIpVersion4 = 4;
constexpr size_t kIpVersion6 = 6;
constexpr size_t kIpv6NextHeaderOffset = 6;
constexpr size_t kIpv6PayloadLenOffset = 4;
// An IPv4 IHL counts 32-bit words, so the header length in bytes is IHL * 4.
constexpr size_t kBytesPerWord = 4;

// The EPB's fixed part before the captured bytes: iface, ts_hi, ts_lo, caplen
// and origlen. caplen is read from this offset and the packet starts after it,
// so the two must be the same number.
constexpr size_t kEnhancedPacketHeaderBytes = 28;

// pktmon's flow records share the EPB envelope but carry an undocumented
// metadata prefix in place of the link header, so the IP header has to be
// found by probing. The window is bounded rather than searching the whole
// frame: the prefix is short, and a wide scan would start finding real
// Ethernet payloads and mislabelling ordinary packets as flow records.
// (The window bounds themselves - first offset 12, last 40, stride 2,
// k+5 <= capLen - now live next to the scanner in Opt.cpp, as
// wintcp::FlowProbeOpt, where they are applied and are differential-tested
// against this comment's description.)

inline uint16_t Rd16(const unsigned char* p, bool swap) {
    uint16_t v = static_cast<uint16_t>(p[0] | (p[1] << 8));
    return swap ? static_cast<uint16_t>(((v & 0xFF00u) >> 8) |
                                       ((v & 0x00FFu) << 8))
                : v;
}

inline uint32_t Rd32(const unsigned char* p, bool swap) {
    uint32_t v = static_cast<uint32_t>(p[0]) |
                 (static_cast<uint32_t>(p[1]) << 8) |
                 (static_cast<uint32_t>(p[2]) << 16) |
                 (static_cast<uint32_t>(p[3]) << 24);
    if (!swap) return v;
    return ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8) |
           ((v & 0x00FF0000u) >> 8) | ((v & 0xFF000000u) >> 24);
}

// Strip a 802.1Q/802.1ad VLAN tag if present, returning the offset of the
// next header. Only used for link types that carry Ethernet.
// Given 'off' pointing AT the 2-byte ethertype field, return the offset of
// the encapsulated (IP) header, stepping over any stacked 802.1Q/802.1ad
// VLAN tags. Each tag replaces the ethertype with its own 2-byte field and
// re-encapsulates the payload, so the loop must re-read the tag type at the
// new position - which is why 'off' is the tag position, not the payload.
//
// Passing 14 here (the first payload byte) rather than 12 (the ethertype)
// makes 0x45 read as an unknown tag and shifts the IP header 4 bytes to the
// right, which silently produced a zero-length payload. The caller must pass
// the ethertype offset.
//
// The tag read itself is wintcp::SkipVlanOpt (Opt.cpp): one 2-byte load plus
// BSWAP instead of two byte loads, and the short-circuit order that makes the
// common (no tag) case a single compare. A/B bench: 1.15x untagged, 1.25x on
// a QinQ frame.
inline size_t SkipVlan(const unsigned char* p, size_t len, size_t off) {
    return SkipVlanOpt(p, len, off);
}

}  // namespace

// Parse the TCP header occupying [off, end) and attach the payload view.
// 'end' is already clamped to the end of the IP packet, so a captured
// frame's Ethernet padding can never leak into the payload.
static bool FinishTcp(const unsigned char* p, size_t off, size_t end,
                      wintcp::ParsedPacket* out) {
    const size_t avail = end - off;
    if (avail < kTcpHeaderMinBytes) { out->malformed = true; return false; }
    const size_t dataOff = (static_cast<size_t>(p[off + kTcpDataOffsetOffset]) >> 4) * kBytesPerWord;
    if (dataOff < kTcpHeaderMinBytes || dataOff > avail) { out->malformed = true; return false; }
    out->srcPort = static_cast<uint16_t>((p[off] << 8) | p[off + 1]);
    out->dstPort = static_cast<uint16_t>((p[off + 2] << 8) | p[off + 3]);
    out->seq = Rd32(p + off + kTcpSeqOffset, true);
    out->ack = Rd32(p + off + kTcpAckOffset, true);
    out->tcpFlags = p[off + kTcpFlagsOffset];
    out->window = static_cast<uint16_t>((p[off + kTcpWindowOffset] << 8) | p[off + 15]);
    out->payload = p + off + dataOff;
    out->payloadLen = avail - dataOff;
    return true;
}

const wchar_t* PcapngLinkTypeName(uint16_t linkType) {
    switch (linkType) {
        case 0: return L"NULL/loopback";
        case 1: return L"Ethernet";
        case kLinkTypePktmonRaw: return L"pktmon raw IP (no link header)";
        case 101: return L"raw IP";
        case 228: return L"IPv4";
        case 229: return L"IPv6";
        default: return L"";
    }
}

// Locate the IP header inside a captured frame.
// With an explicit link type (the normal case: an IDB told us) the offset is
// arithmetic and exact. The kLinkAuto fallback probes candidate offsets, but
// a candidate must ALSO carry a plausible IP protocol number, because a MAC
// address's first byte has its high nibble in 0-7 and so can masquerade as
// "IPv6 version 6" - verified against a real pktmon capture, where naive
// version-nibble probing mis-parsed 16488 good packets and rejected the
    // 8752 that it should have kept.
static bool FindIpOffset(const unsigned char* pkt, size_t len, uint16_t linkType,
                         size_t* off) {
    if (pkt == nullptr || len < 1) return false;

    if (linkType == kLinkAuto) {
        static const size_t kCandidates[] = {0, 4, 14, 18, 22};
        for (size_t c : kCandidates) {
            if (c >= len) continue;
            const unsigned char v = static_cast<unsigned char>(pkt[c] >> 4);
            if (v != 4 && v != 6) continue;
            // Version nibble alone is not enough; confirm the protocol.
            const size_t protoAt = (v == 4) ? c + 9 : c + 6;
            if (protoAt >= len) continue;
            const unsigned char proto = pkt[protoAt];
            if (proto != 6 && proto != 17 && proto != 1 && proto != 58) continue;
            *off = c;
            return true;
        }
        return false;
    }
    if (linkType == 1) {                       // Ethernet
        if (len < 14) return false;
        *off = SkipVlan(pkt, len, 12);   // 12 = the ethertype field
        return *off < len;
    }
    if (linkType == 0) {                       // BSD loopback: 4-byte family
        if (len < 4) return false;
        *off = 4;
        return *off < len;
    }
    if (linkType == 101 || linkType == 228 || linkType == 229 ||
        linkType == kLinkTypePktmonRaw) {
        *off = 0;
        return true;
    }
    return false;
}

bool ParseIpTcp(const unsigned char* pkt, size_t len, uint16_t linkType,
                ParsedPacket* out) {
    if (out == nullptr) return false;
    *out = ParsedPacket();
    size_t off = 0;
    if (!FindIpOffset(pkt, len, linkType, &off)) return false;

    const uint8_t version = static_cast<uint8_t>(pkt[off] >> 4);

    if (version == 4) {
        if (len - off < kIpv4HeaderMinBytes) { out->malformed = true; return false; }
        const size_t ihl = (static_cast<size_t>(pkt[off] & 0x0F)) * kBytesPerWord;
        if (ihl < kIpv4HeaderMinBytes || len - off < ihl) { out->malformed = true; return false; }
        const uint8_t proto = pkt[off + kIpv4ProtoOffset];
        if (proto != kIpProtoTcp) return false;            // not TCP: caller skips it
        out->ipVersion = kIpVersion4;
        // Total length is the authoritative IP packet length. It INCLUDES the
        // IP header, so it must be compared against the pre-header offset
        // ('off' as captured above), not against the post-header one. Getting
        // this backwards rejects every well-formed packet: a 20-byte TCP
        // header with a small payload yields totalLen < off+ihl+20 and the
        // packet is thrown away as malformed.
        const size_t ipStart = off;
        const uint32_t totalLen = (static_cast<uint32_t>(pkt[ipStart + kIpv4TotalLenOffset]) << 8) |
                                  pkt[ipStart + 3];
        size_t ipEnd = len;
        if (totalLen >= ihl && totalLen <= len - ipStart)
            ipEnd = ipStart + totalLen;
        std::memcpy(out->srcIp16, pkt + ipStart + kIpv4SrcAddrOffset, 4);
        std::memcpy(out->dstIp16, pkt + ipStart + kIpv4DstAddrOffset, 4);
        out->srcIp = Rd32(pkt + ipStart + kIpv4SrcAddrOffset, false);
        out->dstIp = Rd32(pkt + ipStart + kIpv4DstAddrOffset, false);
        off += ihl;
        if (ipEnd < off + kTcpHeaderMinBytes) { out->malformed = true; return false; }
        return FinishTcp(pkt, off, ipEnd, out);
    }

    if (version == 6) {
        const size_t ipStart = off;
        if (len - ipStart < kIpv6HeaderBytes) { out->malformed = true; return false; }
        const uint8_t next = pkt[ipStart + kIpv6NextHeaderOffset];  // next header directly after 40
        if (next != kIpProtoTcp) return false;
        // Payload length EXCLUDES the 40-byte IPv6 header, so unlike IPv4
        // this one is compared against the post-header offset. Documented
        // here because the two branches read similarly but are not.
        const uint32_t plen = (static_cast<uint32_t>(pkt[ipStart + kIpv6PayloadLenOffset]) << 8) |
                              pkt[ipStart + 5];
        size_t ipEnd = len;
        if (plen != 0 && kIpv6HeaderBytes + plen <= len - ipStart)
        out->ipVersion = kIpVersion6;
        std::memcpy(out->srcIp16, pkt + ipStart + kIpv6SrcAddrOffset, 16);
        std::memcpy(out->dstIp16, pkt + ipStart + kIpv6DstAddrOffset, 16);
        // The 4-tuple key uses the full 16 bytes (above). The 32-bit fields
        // are for the display/logging path only.
        std::memcpy(&out->srcIp, pkt + ipStart + kIpv6SrcAddrOffset, 4);
        std::memcpy(&out->dstIp, pkt + ipStart + kIpv6DstAddrOffset, 4);
        off = ipStart + kIpv6HeaderBytes;
        if (ipEnd < off + kTcpHeaderMinBytes) { out->malformed = true; return false; }
        return FinishTcp(pkt, off, ipEnd, out);
    }

    return false;
}

PcapngParse ParsePcapng(const unsigned char* data, size_t len) {
    PcapngParse out;
    if (data == nullptr || len < kBlockHeaderBytes) {
        out.error = L"file is empty or too short to be pcapng";
        return out;
    }
    out.fileBytes = len;   // recorded before parsing; see the no-packets error

    size_t pos = 0;
    // Byte order of the file, set by the SHB and inherited by later blocks.
    bool swap = false;
    bool haveOrder = false;
    // A real IDB gives a trustworthy link type. pktmon emits none, so this
    // stays 0 and every packet is auto-detected instead.
    uint16_t linkType = kLinkAuto;
    bool haveIdb = false;

    while (pos + kBlockHeaderBytes <= len) {
        const uint32_t type = Rd32(data + pos, false);
        // The length field's own byte order is per-block, but in practice the
        // SHB's byte-order magic establishes it for the file, so use the
        // current setting and re-sync if a block looks impossible.
        const uint32_t blockLen = Rd32(data + pos + 4, swap);
        ++out.blocksSeen;

        if (blockLen < kBlockHeaderBytes + 4 || (blockLen % 4) != 0) {
            out.badBlocks = 1;
            out.error = L"block length is not a sane multiple of 4";
            return out;
        }
        if (pos + blockLen > len) {
            out.badBlocks = 1;
            out.error = L"truncated final block (file ends mid-block)";
            return out;
        }

        if (type == kBlockSHB) {
            if (blockLen < kMinSectionHeaderBytes) { out.error = L"short section header"; return out; }
            // Byte-order magic 0x1A2B3C4D; if it reads reversed we are
            // big-endian and every later field swaps.
            const uint32_t magic = Rd32(data + pos + 8, false);
            swap = (magic != 0x1A2B3C4Du);
            haveOrder = true;
        } else if (!haveOrder) {
            out.error = L"file does not begin with a section header";
            return out;
        } else if (type == kBlockIDB) {
            if (blockLen < kMinInterfaceDescBytes) { out.error = L"short interface description"; return out; }
            if (!haveIdb) {
                linkType = Rd16(data + pos + 8, swap);
                out.linkType = linkType;
                haveIdb = true;
            }
        } else if (type == kBlockEPB) {
            // EPB layout: type,len | iface(4) ts_hi(4) ts_lo(4) caplen(4)
            // origlen(4) | packetdata(padded) ...
            ++out.epbSeen;
            if (blockLen < kMinEnhancedPacketBytes) { ++out.packetsSkipped; }
            else {
                const uint32_t capLen = Rd32(data + pos + 20, swap);
                const size_t hdr = kEnhancedPacketHeaderBytes;
                if (capLen > blockLen - hdr) {
                    ++out.packetsSkipped;
                } else {
                    const unsigned char* pkt = data + pos + hdr;
                    ParsedPacket p;
                    if (ParseIpTcp(pkt, capLen, linkType, &p)) {
                        out.packets.push_back(p);
                    } else {
                        // pktmon's flow records share the EPB envelope but
                        // carry a synthetic metadata prefix in place of the
                        // Ethernet header, so they fail the link-layer test
                        // above. Counted rather than silently inflating the
                        // skip total. The prefix length is not a documented
                        // constant, so rather than hard-coding an offset
                        // that a pktmon update could invalidate, scan a small
                        // bounded window for the IPv4 ethertype followed by
                        // an IP header - the signature of a flow record.
                        //
                        // The scan is wintcp::FlowProbeOpt (Opt.cpp), which
                        // checks eight candidate offsets per 16-byte SSE2
                        // load instead of one at a time. The candidates are
                        // the EVEN offsets 12..38 (stride 2), so the
                        // per-lane verdicts are masked with 0x5555 before
                        // movemask; the k+5<=capLen and k<40 bounds are
                        // applied exactly, and a window too short for a
                        // 16-byte load falls back to the scalar loop rather
                        // than reading past the frame. A/B bench: 1.40x on a frame with
                        // no signature (the whole window scanned), 1.75x on
                        // a 32-byte frame; 0.89x when the signature is at
                        // candidate 12, where both versions return on the
                        // first offset and the SIMD setup is pure overhead.
                        const bool isFlow = FlowProbeOpt(pkt, capLen);
                        if (isFlow)
                            ++out.flowRecords;
                        else
                            ++out.packetsSkipped;
                    }
                }
            }
        } else if (type == kBlockSPB) {
            // SPB: origlen(4) then data, padded to 4. There is no caplen
            // field, so the block length bounds the read and trailing
            // padding is trimmed by the IP total-length check in ParseIpTcp.
            ++out.spbSeen;
            if (blockLen < kMinSimplePacketBytes) { ++out.packetsSkipped; }
            else {
                ParsedPacket p;
                if (ParseIpTcp(data + pos + 4, blockLen - 8, linkType, &p))
                    out.packets.push_back(p);
                else
                    ++out.packetsSkipped;
            }
        }
        // Unknown block types fall through and are skipped by length, which
        // is what keeps a future pktmon from breaking the whole parse.

        pos += blockLen;
    }

    if (out.epbSeen == 0 && out.spbSeen == 0) {
        // WHY THE FILE IS EMPTY, not just what is missing from it.
        //
        // Measured: `capture --select "lport:<loopback>" --secs 2 --yes`
        // returned this error for a connection that was demonstrably sending
        // bytes. The capture was fine, the parse was fine, and the message sent
        // the reader after the wrong thing entirely - it reads as "pktmon
        // produced a malformed file", which is a pktmon bug and not what
        // happened. What happened is that pktmon does not capture loopback
        // (NDIS loopback is not on the NDIS filtering path), so the file is
        // legitimately empty.
        //
        // Say both: the mechanical fact, then the likeliest cause and what to do
        // about it. An error message that names the likely cause is worth
        // several paragraphs of documentation nobody reads at 2am.
        // pktmon always writes a section header, an interface-description block and
        // its own metadata even when nothing was captured, so "no packet
        // blocks" is NOT the same as "an empty file". Measured on a loopback
        // capture: 8192 bytes of section header + IDB + metadata and not one
        // EPB, which is what an empty capture genuinely looks like.
        //
        // The discriminator is the FILE SIZE relative to that boilerplate: a real
        // capture with traffic is orders of magnitude larger. 64 KB is a
        // conservative threshold - comfortably above the 8-32 KB of boilerplate
        // observed, far below the ~2 MB a 3-second capture produced.
        const bool effectivelyEmpty =
            (out.fileBytes <= kMinTrafficCaptureBytes);
        out.error =
            effectivelyEmpty
                ? L"the capture produced no packets.\r\n"
                  L"  pktmon does not capture loopback traffic, so a "
                  L"127.0.0.1 or ::1\r\n"
                  L"  connection always yields an empty capture. Capture a "
                  L"connection to a real\r\n"
                  L"  remote address instead."
                : L"the capture file has blocks but no packet blocks (no EPB "
                  L"or SPB).\r\n"
                  L"  pktmon produced a file this build cannot read; the "
                  L"capture itself may\r\n"
                  L"  still be usable with an external tool.";
        return out;
    }
    out.ok = true;
    return out;
}

}  // namespace wintcp
