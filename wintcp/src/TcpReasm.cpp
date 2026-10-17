// TcpReasm.cpp
// SPDX-License-Identifier: Apache-2.0
// See TcpReasm.h. The core is a per-direction segment store keyed by
// sequence number, rendered in order at the end. A sparse-map approach is
// used rather than appending on arrival so that out-of-order and duplicate
// segments are both handled by the same mechanism.

#include "TcpReasm.h"

#include <algorithm>
#include <cstring>
#include <map>

namespace wintcp {
namespace {

constexpr uint8_t kFin = 0x01;
constexpr uint8_t kSyn = 0x02;
constexpr uint8_t kRst = 0x04;

// Bytes in the address field of a TcpKey. Both endpoints are stored as full
// 128-bit values regardless of family - a v4 peer occupies the low four bytes
// of a zeroed 16 - so every compare and copy in this file uses the same width.
// Typing 16 at seven call sites is how the key stops matching its own copies.
constexpr size_t kIpv6AddrBytes = 16;

// Width of the diagnostic "addr:port <-> addr:port" line. The longest case is
// two v6 peers with five-digit ports, which lands well under this; swprintf_s
// truncates rather than overruns, so an unexpectedly long one cannot corrupt
// anything.
constexpr size_t kKeyDescChars = 128;

// The capture is user-triggered and short-lived, but a hostile or merely
// broken peer could still make us hold a very large stream in memory. Cap it
// rather than letting one connection exhaust the process.
constexpr size_t kMaxStreamBytes = 32u * 1024u * 1024u;

// One contiguous run of payload, tagged with the absolute sequence number of
// its first byte. Overlapping segments are trimmed, not appended, so a
// retransmit can never duplicate bytes.
//
// 'seq' MUST be 64-bit. Unwrap() returns a signed offset relative to the
// base, which is negative for a segment captured before the base packet; a
// uint32_t field truncates that to a huge positive value and the sort then
// puts pre-wrap segments last. That produced "X WX" instead of "WWXX" and
// was caught by reasm.sequence-wrap-ordered.
struct Segment {
    uint64_t seq;          // sequence of data[0], already unwrapped
    std::string data;
};

int CmpAddr(const unsigned char* a, const unsigned char* b) {
    return std::memcmp(a, b, kIpv6AddrBytes);
}

// Build a key in a canonical orientation so both directions of one
// connection hash to the same value.
TcpKey Canonical(const unsigned char* addrA, uint16_t portA,
                 const unsigned char* addrB, uint16_t portB) {
    TcpKey k;
    const int c = CmpAddr(addrA, addrB);
    const bool swap = (c > 0) || (c == 0 && portA > portB);
    if (swap) {
        std::memcpy(k.addrA, addrB, kIpv6AddrBytes);
        std::memcpy(k.addrB, addrA, kIpv6AddrBytes);
        k.portA = portB;
        k.portB = portA;
    } else {
        std::memcpy(k.addrA, addrA, kIpv6AddrBytes);
        std::memcpy(k.addrB, addrB, kIpv6AddrBytes);
        k.portA = portA;
        k.portB = portB;
    }
    return k;
}

// Unwrap a 32-bit TCP sequence number into a 64-bit absolute position
// relative to 'base'. TCP sequence numbers wrap, and a capture routinely
// crosses the wrap point, so a naive unsigned comparison silently reorders
// everything after the wrap. Standard RFC 1982 serial arithmetic.
uint64_t Unwrap(uint32_t seq, uint32_t base) {
    const uint32_t diff = seq - base;
    // Values within +/- 2^31 of the base are "near" it.
    if (diff <= 0x7FFFFFFFu) {
        return static_cast<uint64_t>(base) + diff;
    }
    // Wrapped forward past the base.
    return static_cast<uint64_t>(base) - (0x100000000ull - diff);
}

// Collects segments for one direction and renders them in order.
class Direction {
public:
    void Clear() {
        segs_.clear();
        bytes_ = 0;
        duplicates_ = 0;
        truncated_ = false;
        sawSyn_ = sawFin_ = sawRst_ = false;
        window_ = 0;
    }

    void Add(uint64_t seq, const unsigned char* data, size_t len) {
        if (len == 0) return;
        if (bytes_ >= kMaxStreamBytes) { truncated_ = true; return; }
        if (bytes_ + len > kMaxStreamBytes) {
            len = kMaxStreamBytes - bytes_;
            truncated_ = true;
        }
        // Trim against everything already stored, then take the bytes that
        // are genuinely new. With a small number of segments a linear scan
        // is faster and far simpler than an interval tree, and a real
        // capture of one connection has hundreds, not millions.
        //
        // 'consumed' tracks how much of the incoming segment has been ruled
        // out. Advancing the *pointer* as well as the count matters: an
        // earlier version trimmed 'skip' but still read from the start of
        // the buffer, which silently returned the already-covered bytes and
        // lost the tail ("WXX" instead of "WWXX").
        uint64_t s = seq;
        size_t consumed = 0;

        // Pass A: skip the head that an existing segment already covers.
        // The store is not kept sorted (segments arrive in capture order), so
        // every segment is examined rather than breaking on the first one
        // that starts beyond us.
        for (const Segment& g : segs_) {
            const uint64_t gStart = g.seq;
            const uint64_t gEnd = gStart + g.data.size();
            if (gEnd <= s) continue;                  // entirely before us
            if (gStart >= s + (len - consumed)) continue;   // can't overlap remaining head
            if (gEnd > s) {                           // overlaps our head
                const uint64_t d = gEnd - s;
                if (d >= len - consumed) {            // fully covered
                    ++duplicates_;
                    return;
                }
                consumed += static_cast<size_t>(d);
                s = gEnd;
            }
        }

        // Pass B: stop at the first existing segment that starts inside the
        // still-unclaimed tail, since bytes are contiguous from here on.
        size_t skip = len - consumed;
        for (const Segment& g : segs_) {
            const uint64_t gStart = g.seq;
            if (gStart > s && gStart < s + skip) {
                skip = static_cast<size_t>(gStart - s);
            }
        }
        if (skip == 0) { ++duplicates_; return; }
        Segment seg;
        seg.seq = s;
        seg.data.assign(
            reinterpret_cast<const char*>(data) + consumed, skip);
        segs_.push_back(std::move(seg));
        bytes_ += skip;
    }

    // Render in sequence order, recording any gap left unfilled.
    void Render(ReasmResult* out) {
        // Reset the caller's struct first. Appending into a reused result
        // would concatenate two captures, which is silent and looks exactly
        // like a corrupt stream.
        *out = ReasmResult();
        out->segments = segs_.size();
        out->duplicates = duplicates_;
        if (segs_.empty()) { out->truncated = truncated_; return; }
        std::sort(segs_.begin(), segs_.end(),
                  [](const Segment& a, const Segment& b) { return a.seq < b.seq; });

        out->firstSeq = segs_.front().seq;
        out->bytes.reserve(bytes_);
        for (size_t i = 0; i < segs_.size(); ++i) {
            if (i > 0) {
                const uint64_t prevEnd =
                    static_cast<uint64_t>(segs_[i - 1].seq) +
                    segs_[i - 1].data.size();
                const uint64_t curStart = segs_[i].seq;
                if (curStart > prevEnd) {
                    const uint64_t hole = curStart - prevEnd;
                    // The hole is real data we never saw. Record it rather
                    // than splicing the stream together as if it were
                    // contiguous: a protocol decode across a hole produces
                    // confident nonsense.
                    out->bytesMissing += static_cast<size_t>(hole);
                    out->hasGap = true;
                }
            }
            out->bytes += segs_[i].data;
        }
        out->truncated = truncated_;
    }

    void SetFlags(bool syn, bool fin, bool rst, uint16_t win) {
        sawSyn_ = sawSyn_ || syn;
        sawFin_ = sawFin_ || fin;
        sawRst_ = sawRst_ || rst;
        if (win > 0) window_ = win;
    }

    void Finish(ReasmResult* out) {
        Render(out);
        out->sawSyn = sawSyn_;
        out->sawFin = sawFin_;
        out->sawRst = sawRst_;
        out->window = window_;
    }

private:
    std::vector<Segment> segs_;
    size_t bytes_ = 0;
    size_t duplicates_ = 0;
    bool truncated_ = false;
    bool sawSyn_ = false;
    bool sawFin_ = false;
    bool sawRst_ = false;
    uint16_t window_ = 0;
};

}  // namespace

bool TcpKey::operator==(const TcpKey& o) const {
    return portA == o.portA && portB == o.portB &&
           std::memcmp(addrA, o.addrA, kIpv6AddrBytes) == 0 &&
           std::memcmp(addrB, o.addrB, kIpv6AddrBytes) == 0;
}

TcpKey MakeTcpKey(const ParsedPacket& p) {
    return Canonical(p.srcIp16, p.srcPort, p.dstIp16, p.dstPort);
}

std::wstring DescribeTcpKey(const TcpKey& k) {
    // Formatting IPv6 properly is fiddly and not worth it here: the low
    // 32 bits plus an ellipsis identify the peer well enough for a
    // diagnostic line, and a v4 address renders exactly.
    wchar_t buf[kKeyDescChars] = {0};
    const bool v4 = (k.addrA[0] == 0 && k.addrA[1] == 0 && k.addrA[2] == 0);
    if (v4) {
        ::swprintf_s(buf, L"%u.%u.%u.%u:%u <-> %u.%u.%u.%u:%u",
                     k.addrA[0], k.addrA[1], k.addrA[2], k.addrA[3], k.portA,
                     k.addrB[0], k.addrB[1], k.addrB[2], k.addrB[3], k.portB);
    } else {
        ::swprintf_s(buf, L"[%02x%02x:%02x%02x]:%u <-> [%02x%02x:%02x%02x]:%u",
                     k.addrA[0], k.addrA[1], k.addrA[2], k.addrA[3], k.portA,
                     k.addrB[0], k.addrB[1], k.addrB[2], k.addrB[3], k.portB);
    }
    return buf;
}

ReasmStats ReassembleStream(const std::vector<ParsedPacket>& packets,
                            const TcpKey& want, ReasmResult* toServer,
                            ReasmResult* toClient) {
    ReasmStats st;
    Direction a;   // the canonically-first endpoint
    Direction b;   // the canonically-second endpoint
    // A Direction is reusable, but reusing one without clearing would append
    // a second capture's segments onto the first. Clearing here makes
    // ReassembleStream idempotent regardless of what the caller did before.
    a.Clear();
    b.Clear();

    // Pass 1: flags, and the sequence base. A SYN's +1 is the true start of
    // data. Without a SYN the base must be the sequence of the FIRST packet
    // we saw for that direction - NOT the numerically lowest one. Those
    // differ across a wrap: for a stream containing 0xFFFFFFF0 and 0x00000010
    // the lowest is 0x10, which is 32 bytes LATER, so basing on it reverses
    // the order. This was caught by reasm.sequence-wrap-ordered.
    uint32_t synA = 0, synB = 0;
    uint32_t firstA = 0, firstB = 0;
    bool haveFirstA = false, haveFirstB = false;

    for (const ParsedPacket& p : packets) {
        ++st.packetsIn;
        if (p.ipVersion == 0 || p.malformed) { ++st.nonTcp; continue; }
        if (MakeTcpKey(p) != want) { ++st.otherStreams; continue; }
        ++st.packetsMatched;

        const bool fromA = (p.srcPort == want.portA) &&
                           (CmpAddr(p.srcIp16, want.addrA) == 0);
        if (fromA) {
            if (!haveFirstA) { firstA = p.seq; haveFirstA = true; }
            if ((p.tcpFlags & kSyn) && synA == 0) synA = p.seq + 1;
        } else {
            if (!haveFirstB) { firstB = p.seq; haveFirstB = true; }
            if ((p.tcpFlags & kSyn) && synB == 0) synB = p.seq + 1;
        }
        Direction& d = fromA ? a : b;
        d.SetFlags((p.tcpFlags & kSyn) != 0, (p.tcpFlags & kFin) != 0,
                   (p.tcpFlags & kRst) != 0, p.window);
        if (p.tcpFlags & kSyn) st.sawSyn = true;
        if (p.tcpFlags & kFin) st.sawFin = true;
        if (p.tcpFlags & kRst) st.sawRst = true;
    }

    // Pass 2: place payload. Separate so the sequence base is known before
    // any unwrapping happens - unwrapping needs a reference point.
    const uint32_t baseA = (synA != 0) ? synA : (haveFirstA ? firstA : 0);
    const uint32_t baseB = (synB != 0) ? synB : (haveFirstB ? firstB : 0);

    for (const ParsedPacket& p : packets) {
        if (p.ipVersion == 0 || p.malformed) continue;
        if (MakeTcpKey(p) != want) continue;
        if (p.payloadLen == 0) continue;
        const bool fromA = (p.srcPort == want.portA) &&
                           (CmpAddr(p.srcIp16, want.addrA) == 0);
        // A SYN or FIN consumes one sequence number, so payload in the SAME
        // segment starts one past seq. Handled rather than ignored: it costs
        // one increment and removes a class of off-by-one.
        uint32_t seq = p.seq;
        if (p.tcpFlags & (kSyn | kFin)) seq += 1;
        (fromA ? a : b).Add(Unwrap(seq, fromA ? baseA : baseB), p.payload,
                            p.payloadLen);
    }

    a.Finish(toServer);
    b.Finish(toClient);
    st.bytesToServer = toServer->bytes.size();
    st.bytesToClient = toClient->bytes.size();
    st.duplicates = toServer->duplicates + toClient->duplicates;
    st.gaps = (toServer->hasGap ? 1 : 0) + (toClient->hasGap ? 1 : 0);
    st.gapBytes = toServer->bytesMissing + toClient->bytesMissing;
    return st;
}

}  // namespace wintcp
