// Opt.cpp
// SPDX-License-Identifier: Apache-2.0
// Implementations of the optimized functions declared in Opt.h.
// Uses MSVC intrinsics to generate optimal assembly including SSE2 and
// BSWAP. See Opt.h for the rules about what is wired into the product and
// why nothing above SSE2 is used.

#include "Opt.h"

#include <cwchar>

#ifdef _MSC_VER
#include <intrin.h>
#endif

// SSE2 is baseline on every x64 CPU, so the substring
// scan below can rely on it unconditionally.
#ifdef _M_X64
#include <emmintrin.h>
#define WINTCP_HAS_SSE2 1
#endif

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cwctype>
#include <limits>
#include <string>
#include <unordered_map>

namespace wintcp {

// ============================================================================
// 1. GeoIP Tree Walk Optimization
// ============================================================================

bool ResolveOffsetOpt(const unsigned char bits[16], unsigned bitCount,
                      size_t startNode, size_t nodeCount,
                      size_t nodeByteSize, bool record28, size_t recordBytes,
                      const unsigned char* treeBase,
                      size_t dataSectionSize, size_t kSeparatorLen,
                      size_t* out) {
    if (bits == nullptr || treeBase == nullptr || out == nullptr) return false;
    if (nodeCount == 0 || nodeByteSize == 0) return false;
    // Mirrors Loaded(): an unloaded database refuses every walk.
    if (dataSectionSize == 0) return false;
    // recordBytes is 3 for 28-bit databases (GeoIp.cpp:825-826), but some
    // callers pass 0 together with record28=true; accept both.
    if (!record28 && recordBytes != 3 && recordBytes != 4) return false;
    // bits[16] holds at most 128 address bits; more would read out of bounds.
    if (bitCount == 0 || bitCount > 128) return false;
    // Guard the nodeCount + kSeparatorLen addition against wrap-around.
    if (kSeparatorLen > (std::numeric_limits<size_t>::max)() - nodeCount) {
        return false;
    }
    // Hoisted overflow guard: node * nodeByteSize cannot wrap for any
    // node < nodeCount, so the loop below needs no division per step.
    if (nodeCount > (std::numeric_limits<size_t>::max)() / nodeByteSize) {
        return false;
    }

    const size_t nodeCountSz = nodeCount;
    const size_t dataThreshold = nodeCountSz + kSeparatorLen;

    size_t node = startNode;

    for (unsigned depth = 0; depth < bitCount; ++depth) {
        // Optimization: use bit manipulation instead of division/modulo
        const unsigned byteIdx = depth >> 3;       // depth / 8
        const unsigned bitPos = 7 - (depth & 7);   // 7 - (depth % 8)

        const unsigned bit = (bits[byteIdx] >> bitPos) & 1u;

        if (node >= nodeCountSz) return false;
        const size_t recPos = node * nodeByteSize;
        if (recPos + nodeByteSize > nodeCount * nodeByteSize) return false;

        size_t record = 0;

        if (record28) {
            // 28-bit records: packed format, two records share middle byte
            const unsigned char* p = treeBase + recPos;
            if (bit == 0) {
                record = (static_cast<size_t>(p[3] >> 4) << 24) |
                           (static_cast<size_t>(p[0]) << 16) |
                           (static_cast<size_t>(p[1]) << 8) |
                           static_cast<size_t>(p[2]);
            } else {
                record = (static_cast<size_t>(p[3] & 0x0Fu) << 24) |
                           (static_cast<size_t>(p[4]) << 16) |
                           (static_cast<size_t>(p[5]) << 8) |
                           static_cast<size_t>(p[6]);
            }
        } else if (recordBytes == 4) {
            // 32-bit records: big-endian uint32, one per half.
            // NOTE: this selects the half (bit * 4). GeoIp.cpp:977 reads
            // recPos for both halves, so the original answers right-branch
            // walks with the left record; the benchmark keeps that bug in
            // orig_functions.cpp and this implementation is the fix.
            const unsigned char* p = treeBase + recPos + bit * 4;
            record = (static_cast<size_t>(p[0]) << 24) |
                     (static_cast<size_t>(p[1]) << 16) |
                     (static_cast<size_t>(p[2]) << 8) |
                     static_cast<size_t>(p[3]);
        } else if (recordBytes == 3) {
            // 24-bit records: 3 bytes per record
            const unsigned char* p = treeBase + recPos + bit * 3;
            record = (static_cast<size_t>(p[0]) << 16) |
                     (static_cast<size_t>(p[1]) << 8) |
                     static_cast<size_t>(p[2]);
        } else {
            return false;
        }

        if (record < nodeCountSz) {
            node = record;
            continue;
        } else if (record >= dataThreshold) {
            const size_t offset = record - nodeCountSz - kSeparatorLen;
            if (offset >= dataSectionSize) return false;
            *out = offset;
            return true;
        } else {
            return false;  // no data for this address
        }
    }

    return false;  // consumed all bits without finding data
}

// ============================================================================
// 2. TCP Reassembly Segment Overlap Optimization
// ============================================================================

bool AddSegmentOverlapOpt(uint64_t seq, size_t len,
                          const uint64_t* segSeqs, const size_t* segSizes,
                          size_t segCount, size_t* consumed, size_t* skip) {
    if (consumed == nullptr || skip == nullptr) return false;
    if (segCount != 0 && (segSeqs == nullptr || segSizes == nullptr)) {
        return false;
    }
    if (segCount == 0 || len == 0) {
        *consumed = 0;
        *skip = len;
        return len > 0;
    }

    uint64_t s = seq;
    size_t consumedVal = 0;

    // Pass A: skip the head that existing segments already cover.
    // Scalar two-pass scan, faithful to Direction::Add: the store arrives
    // in capture order (unsorted), so every segment is examined.
    for (size_t i = 0; i < segCount; ++i) {
        const uint64_t gStart = segSeqs[i];
        const uint64_t gEnd = gStart + segSizes[i];

        if (gEnd <= s) continue;                    // entirely before us
        // Overflow-safe form of (gStart >= s + (len - consumedVal)):
        // identical while s + remaining cannot wrap, correct when it can.
        const size_t remaining = len - consumedVal;
        if (gStart >= s && gStart - s >= remaining) continue;  // can't overlap remaining head

        if (gEnd > s) {                              // overlaps our head
            const uint64_t d = gEnd - s;
            if (d >= len - consumedVal) {           // fully covered
                *consumed = len;
                *skip = 0;
                return false;  // duplicate
            }
            consumedVal += static_cast<size_t>(d);
            s = gEnd;
        }
    }

    // Pass B: stop at the first existing segment that starts inside the
    // still-unclaimed tail
    size_t skipVal = len - consumedVal;
    for (size_t i = 0; i < segCount; ++i) {
        const uint64_t gStart = segSeqs[i];
        if (gStart > s && gStart < s + skipVal) {
            skipVal = static_cast<size_t>(gStart - s);
        }
    }

    *consumed = consumedVal;
    *skip = skipVal;
    return skipVal > 0;
}

// ============================================================================
// 3. Filter Matching Substring Search Optimization
// ============================================================================

// SIMD (SSE2) substring search.
//
// Strategy: scan the haystack 8 wchar_t at a time for the
// needle's FIRST character (the only character that can
// start a match), then verify each candidate with an exact
// memcmp. Every match's first character lies in exactly
// one 8-character window, so no match can be missed, and
// the memcmp guarantees no false positives - the result is
// identical to the wstring find() it replaces.
static_assert(sizeof(wchar_t) == 2,
              "the SSE2 lane logic below assumes UTF-16 wchar_t");
bool HasLowerSubstringOpt(const wchar_t* haystack, size_t hayLen,
                             const wchar_t* needle,
                             size_t needleLen) {
    if (haystack == nullptr || needle == nullptr) return false;
    if (needleLen == 0) return true;
    if (needleLen > hayLen) return false;

    const wchar_t first = needle[0];
    const size_t needleBytes = needleLen * sizeof(wchar_t);

#if defined(WINTCP_HAS_SSE2)
    const __m128i firstVec = _mm_set1_epi16(
        static_cast<short>(static_cast<unsigned short>(first)));
    size_t i = 0;
    for (; i + 8 <= hayLen; i += 8) {
        const __m128i chunk = _mm_loadu_si128(
            reinterpret_cast<const __m128i*>(haystack + i));
        const __m128i eq = _mm_cmpeq_epi16(chunk, firstVec);
        unsigned mask = static_cast<unsigned>(_mm_movemask_epi8(eq));
        // One matching wchar_t sets BOTH bits of its 16-bit lane: clear
        // the whole lane so each candidate is verified exactly once.
        while (mask != 0) {
            unsigned long bit = 0;
            if (_BitScanForward(&bit, mask) == 0) break;
            const size_t pos = i + (bit >> 1);
            mask &= ~(3u << (bit & ~1ul));
            if (pos + needleLen <= hayLen &&
                std::memcmp(haystack + pos, needle,
                              needleBytes) == 0) {
                return true;
            }
        }
    }
    // Tail: fewer than 8 wchar_t remain (a match starting
    // here still has its first character in this range).
    for (; i + needleLen <= hayLen; ++i) {
        if (haystack[i] == first &&
            std::memcmp(haystack + i, needle, needleBytes) == 0) {
            return true;
        }
    }
    return false;
#else
    for (size_t i = 0; i + needleLen <= hayLen; ++i) {
        if (haystack[i] == first &&
            std::memcmp(haystack + i, needle, needleBytes) == 0) {
            return true;
        }
    }
    return false;
#endif
}

// ============================================================================
// 4. Packet Parsing Optimization
// ============================================================================

void ParseTcpHeaderOpt(const unsigned char* p,
                       uint16_t* srcPort, uint16_t* dstPort,
                       uint32_t* seq, uint32_t* ack,
                       uint8_t* tcpFlags, uint16_t* window,
                       const unsigned char** payload, size_t* payloadLen,
                       size_t tcpOff, size_t end) {
    if (p == nullptr || srcPort == nullptr || dstPort == nullptr ||
        seq == nullptr || ack == nullptr || tcpFlags == nullptr ||
        window == nullptr || payload == nullptr || payloadLen == nullptr) {
        return;
    }
    // Zero first: every failure path below leaves the outputs exactly as
    // the original leaves them (it writes nothing on failure).
    *srcPort = 0; *dstPort = 0; *seq = 0; *ack = 0;
    *tcpFlags = 0; *window = 0;
    *payload = nullptr; *payloadLen = 0;
    if (tcpOff > end) return;  // else (end - tcpOff) wraps to a huge avail
    const size_t avail = end - tcpOff;
    if (avail < 20) {
        return;
    }

    // Data offset (upper 4 bits of byte 12) is validated BEFORE any field
    // is parsed, so a bad header length cannot leak half-parsed ports.
    const size_t dataOff = (static_cast<size_t>(p[tcpOff + 12]) >> 4) * 4;
    if (dataOff < 20 || dataOff > avail) {
        return;
    }

    // Endian conversion via the BSWAP intrinsics: the compiler
    // emits the BSWAP instruction directly (the same instruction
    // the geoip_lookup.asm reference documents), instead of a
    // shift/or sequence built from byte loads.

    // Source port (network order)
    uint16_t srcNet = 0;
    std::memcpy(&srcNet, p + tcpOff, sizeof(srcNet));
    *srcPort = _byteswap_ushort(srcNet);
    // Dest port (network order)
    uint16_t dstNet = 0;
    std::memcpy(&dstNet, p + tcpOff + 2, sizeof(dstNet));
    *dstPort = _byteswap_ushort(dstNet);

    // Sequence number (network order)
    uint32_t seqNet = 0;
    std::memcpy(&seqNet, p + tcpOff + 4, sizeof(seqNet));
    *seq = _byteswap_ulong(seqNet);

    // Ack number (network order)
    uint32_t ackNet = 0;
    std::memcpy(&ackNet, p + tcpOff + 8, sizeof(ackNet));
    *ack = _byteswap_ulong(ackNet);

    // TCP flags (byte 13)
    *tcpFlags = p[tcpOff + 13];

    // Window (network order)
    uint16_t winNet = 0;
    std::memcpy(&winNet, p + tcpOff + 14, sizeof(winNet));
    *window = _byteswap_ushort(winNet);

    // Payload
    *payload = p + tcpOff + dataOff;
    *payloadLen = avail - dataOff;
}

// ============================================================================
// 5. FormatBytes Optimization
// ============================================================================

size_t FormatBytesOpt(wchar_t* buf, size_t bufSize, uint64_t bytes) {
    if (buf == nullptr || bufSize == 0) return 0;

    const double b = static_cast<double>(bytes);

    // Optimization: for the common case (bytes), use integer arithmetic
    // and direct character encoding, avoiding format string parsing.
    if (b < 1024.0) {
        // Integer format: "<bytes> B"
        // Direct integer-to-string conversion
        wchar_t tmp[32];
        size_t i = 0;
        if (bytes == 0) {
            tmp[i++] = L'0';
        } else {
            // Convert to string in reverse
            wchar_t rev[32];
            size_t j = 0;
            uint64_t n = bytes;
            while (n > 0) {
                rev[j++] = static_cast<wchar_t>(L'0' + (n % 10));
                n /= 10;
            }
            // Reverse into tmp
            for (size_t k = 0; k < j; ++k) {
                tmp[i++] = rev[j - 1 - k];
            }
        }
        tmp[i++] = L' ';
        tmp[i++] = L'B';
        tmp[i++] = L'\0';
        // i includes the NUL terminator written above; the character
        // count (matching swprintf_s's return value) is i - 1.
        if (i > bufSize) {
            // Output (including NUL) doesn't fit — match the original
            // swprintf_s behaviour: return 0, zero the buffer.
            buf[0] = L'\0';
            return 0;
        }
        for (size_t k = 0; k < i; ++k) buf[k] = tmp[k];
        return i - 1;
    }

    // For KB/MB/GB/TB: same format policy as the original (%.1f for
    // KB/MB, %.2f for GB/TB). Format into a stack buffer first and copy
    // only when it fits: this matches swprintf_s's observable behaviour
    // (0 + empty buffer when truncated) WITHOUT invoking the CRT
    // invalid-parameter handler, which in Debug builds pops a modal
    // Abort/Retry/Ignore dialog and stalls unattended runs.
    const wchar_t* fmt = L"%.1f KB";
    double value = b / 1024.0;
    if (b < 1024.0 * 1024.0) {
        fmt = L"%.1f KB";
        value = b / 1024.0;
    } else if (b < 1024.0 * 1024.0 * 1024.0) {
        fmt = L"%.1f MB";
        value = b / (1024.0 * 1024.0);
    } else if (b < 1024.0 * 1024.0 * 1024.0 * 1024.0) {
        fmt = L"%.2f GB";
        value = b / (1024.0 * 1024.0 * 1024.0);
    } else {
        fmt = L"%.2f TB";
        value = b / (1024.0 * 1024.0 * 1024.0 * 1024.0);
    }
    wchar_t ftmp[32];
    const int written = swprintf_s(ftmp, 32, fmt, value);
    if (written < 0 || static_cast<size_t>(written) + 1 > bufSize) {
        buf[0] = L'\0';
        return 0;
    }
    for (size_t k = 0; k <= static_cast<size_t>(written); ++k) buf[k] = ftmp[k];
    return static_cast<size_t>(written);
}

// ============================================================================
// 6. Connection Key Building Optimization
// ============================================================================

void KeyOfOpt(bool ipv6, bool udp,
              const unsigned char* localAddr, uint32_t localPort,
              const unsigned char* remoteAddr, uint32_t remotePort,
              uint32_t pid,
              unsigned char* outBytes, size_t* outLen) {
    // Caller must provide at least 22 bytes (IPv4) / 46 bytes (IPv6).
    if (localAddr == nullptr || remoteAddr == nullptr ||
        outBytes == nullptr || outLen == nullptr) {
        if (outLen != nullptr) *outLen = 0;
        return;
    }
    size_t len = 0;

    // Protocol family byte
    outBytes[len++] = ipv6 ? '6' : '4';
    // Protocol byte
    outBytes[len++] = udp ? 'U' : 'T';

    if (ipv6) {
        // IPv6: 16 + 4 + 16 bytes
        std::memcpy(outBytes + len, localAddr, 16); len += 16;

        // Ports/pid as single 4-byte stores (one dword mov each, same
        // bytes memcpy writes on little-endian x64 - the byte-wise
        // version cost 4 stores per field and measured 0.6x).
        std::memcpy(outBytes + len, &localPort, 4); len += 4;

        std::memcpy(outBytes + len, remoteAddr, 16); len += 16;
    } else {
        // IPv4: 4 + 4 bytes
        std::memcpy(outBytes + len, localAddr, 4); len += 4;

        std::memcpy(outBytes + len, &localPort, 4); len += 4;

        std::memcpy(outBytes + len, remoteAddr, 4); len += 4;
    }

    // remotePort
    std::memcpy(outBytes + len, &remotePort, 4); len += 4;

    // PID
    std::memcpy(outBytes + len, &pid, 4); len += 4;

    *outLen = len;
}

// ============================================================================
// 7. WideToUtf8 Conversion Optimization
// ============================================================================

size_t WideToUtf8Opt(const wchar_t* src, size_t srcLen,
                     char* dst, size_t dstSize) {
    if (src == nullptr || dst == nullptr) return 0;
    if (dstSize == 0 || srcLen == 0) return 0;

    size_t si = 0;
    size_t di = 0;

#if defined(WINTCP_HAS_SSE2)
    // ASCII fast path: 8 wchar lanes per iteration. A lane is ASCII iff
    // its top 9 bits are clear; the 8 low bytes are packed and stored
    // together (8x fewer stores on pure-ASCII text).
    const __m128i kNonAscii = _mm_set1_epi16(static_cast<short>(0xFF80));
    const __m128i kZero = _mm_setzero_si128();
    while (si + 8 <= srcLen && di + 8 <= dstSize) {
        const __m128i chunk = _mm_loadu_si128(
            reinterpret_cast<const __m128i*>(src + si));
        if (_mm_movemask_epi8(_mm_and_si128(chunk, kNonAscii)) != 0) break;
        const __m128i packed = _mm_packus_epi16(chunk, kZero);
        _mm_storel_epi64(reinterpret_cast<__m128i*>(dst + di), packed);
        si += 8;
        di += 8;
    }
#endif

    for (; si < srcLen && di < dstSize; ++si) {
        // Unsigned: surrogate values exceed int16 range, and wchar_t
        // signedness is implementation-defined.
        const uint32_t ch = static_cast<uint32_t>(src[si]);

        if (ch < 0x80) {
            // ASCII fast path - single byte
            dst[di++] = static_cast<char>(ch);
        } else if (ch < 0x800) {
            // 2-byte UTF-8 sequence
            if (di + 2 > dstSize) break;
            dst[di++] = static_cast<char>(0xC0 | (ch >> 6));
            dst[di++] = static_cast<char>(0x80 | (ch & 0x3F));
        } else if (ch >= 0xD800 && ch <= 0xDBFF) {
            // High surrogate - expect low surrogate
            const uint32_t lo = (si + 1 < srcLen)
                                    ? static_cast<uint32_t>(src[si + 1])
                                    : 0xDBFFu + 1u;  // missing: FFFD path
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                const uint32_t cp = 0x10000 + (((ch - 0xD800) << 10) |
                                              (lo - 0xDC00));
                if (di + 4 > dstSize) break;
                dst[di++] = static_cast<char>(0xF0 | (cp >> 18));
                dst[di++] = static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
                dst[di++] = static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                dst[di++] = static_cast<char>(0x80 | (cp & 0x3F));
                ++si;
            } else {
                // Unpaired surrogate, encode as replacement (U+FFFD)
                if (di + 3 > dstSize) break;
                dst[di++] = static_cast<char>(0xEF);
                dst[di++] = static_cast<char>(0xBF);
                dst[di++] = static_cast<char>(0xBD);
            }
        } else if (ch >= 0xDC00 && ch <= 0xDFFF) {
            // Lone low surrogate: ill-formed, encode as U+FFFD
            // (the old code CESU-8-encoded it as ED xx xx).
            if (di + 3 > dstSize) break;
            dst[di++] = static_cast<char>(0xEF);
            dst[di++] = static_cast<char>(0xBF);
            dst[di++] = static_cast<char>(0xBD);
        } else {
            // 3-byte UTF-8 sequence
            if (di + 3 > dstSize) break;
            dst[di++] = static_cast<char>(0xE0 | (ch >> 12));
            dst[di++] = static_cast<char>(0x80 | ((ch >> 6) & 0x3F));
            dst[di++] = static_cast<char>(0x80 | (ch & 0x3F));
        }
    }

    return di;
}

// ============================================================================
// 8. Stream Hexdump Optimization
// ============================================================================

std::string FormatStreamHexOpt(const std::string& bytes, size_t bytesPerLine) {
    constexpr size_t kMaxPerLine = 64;
    if (bytesPerLine == 0 || bytesPerLine > kMaxPerLine) bytesPerLine = 16;
    std::string out;
    out.reserve(bytes.size() / bytesPerLine * 80 + 32);

    // Worst case per line: 8 offset + 2 spaces + 3 chars per hex byte
    // (+1 halfway gap) + 2 gutter bars + 1 ASCII byte each + CRLF.
    char line[8 + 2 + kMaxPerLine * 3 + 1 + 2 + kMaxPerLine + 8];

    static const char kHexDig[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                     '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    const size_t n = bytes.size();
    const unsigned char* p =
        reinterpret_cast<const unsigned char*>(bytes.data());
    for (size_t off = 0; off < n; off += bytesPerLine) {
        const size_t run = (std::min)(bytesPerLine, n - off);
        // Max line: 10 + 64*3 + 1 + 2 + 64 + 3 = 272 < sizeof(line) (279),
        // so the stores below cannot overrun for any clamped bytesPerLine.
        size_t at = 0;
        // One snprintf per line (kept for exact %08zx parity).
        at += static_cast<size_t>(
            ::snprintf(line + at, sizeof(line) - at, "%08zx  ", off));

        for (size_t i = 0; i < bytesPerLine; ++i) {
            if (i == bytesPerLine / 2 && run > i) line[at++] = ' ';
            if (i < run) {
                const unsigned char c = p[off + i];
                line[at++] = kHexDig[c >> 4];
                line[at++] = kHexDig[c & 0x0F];
                line[at++] = ' ';
            } else {
                line[at++] = ' ';
                line[at++] = ' ';
                line[at++] = ' ';
            }
        }
        line[at++] = ' ';
        line[at++] = '|';
        for (size_t i = 0; i < run; ++i) {
            const unsigned char c = p[off + i];
            line[at++] =
                (c >= 0x20 && c < 0x7F) ? static_cast<char>(c) : '.';
        }
        line[at++] = '|';
        line[at++] = '\r';
        line[at++] = '\n';
        out.append(line, at);
    }
    return out;
}

// ============================================================================
// 9. Wide Lowercase Optimization
// ============================================================================

std::wstring ToLowerWOpt(const std::wstring& s) {
    std::wstring out(s);
    const size_t n = out.size();
    size_t i = 0;

#if defined(WINTCP_HAS_SSE2)
    // ASCII fold: a lane folds iff 'A' <= lane <= 'Z'. Both compares are
    // SIGNED, which is exact here: the A-Z range is positive-signed, every
    // negative-signed lane (>= 0x8000) fails `ge`, and 0x80..0x7FFF fails
    // `le` - but lanes in 0x80..0xFFFF still need towlower, so blocks are
    // only folded when wholly ASCII (unsigned saturating check below).
    const __m128i kAminus1 = _mm_set1_epi16(static_cast<short>('A' - 1));
    const __m128i kZplus1 = _mm_set1_epi16(static_cast<short>('Z' + 1));
    const __m128i kAdd = _mm_set1_epi16(32);
    const __m128i k80 = _mm_set1_epi16(0x0080);
    for (; i + 8 <= n; i += 8) {
        const __m128i v = _mm_loadu_si128(
            reinterpret_cast<const __m128i*>(out.data() + i));
        // Unsigned < 0x80 test: subs saturates to 0 exactly then.
        if (_mm_movemask_epi8(_mm_subs_epu16(v, k80)) != 0) break;
        const __m128i isAZ = _mm_and_si128(_mm_cmpgt_epi16(v, kAminus1),
                                           _mm_cmplt_epi16(v, kZplus1));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out.data() + i),
                         _mm_add_epi16(v, _mm_and_si128(isAZ, kAdd)));
    }
#endif

    for (; i < n; ++i) {
        out[i] = static_cast<wchar_t>(::towlower(static_cast<wint_t>(out[i])));
    }
    return out;
}

// ============================================================================
// 10. GeoIP Big-Endian Field Reads
// ============================================================================

uint32_t ReadU32BEOpt(const unsigned char* p) {
    if (p == nullptr) return 0;
    uint32_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return _byteswap_ulong(v);
}

uint64_t ReadU64BEOpt(const unsigned char* p) {
    if (p == nullptr) return 0;
    uint64_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return _byteswap_uint64(v);
}

bool ReadBytesOpt(const unsigned char* p, size_t n, uint64_t* out) {
    if (p == nullptr || out == nullptr) return false;
    // Small sizes use shift/OR (same codegen as the original loop);
    // sizes 4..8 use constant-size memcpy + BSWAP, which inlines to
    // mov + bswap. A single runtime-size memcpy compiled to a real
    // memcpy call and measured 0.3x - never do that here.
    switch (n) {
        case 0:
            *out = 0;
            return true;
        case 1:
            *out = p[0];
            return true;
        case 2:
            *out = (static_cast<uint64_t>(p[0]) << 8) | p[1];
            return true;
        case 3:
            *out = (static_cast<uint64_t>(p[0]) << 16) |
                   (static_cast<uint64_t>(p[1]) << 8) | p[2];
            return true;
        case 4: {
            uint32_t v = 0;
            std::memcpy(&v, p, 4);
            *out = _byteswap_ulong(v);
            return true;
        }
        // Sizes 5..8 assemble from one inlined 4-byte load plus scalar
        // tail bytes: every load stays inside the n valid bytes, and no
        // 5/6/7-byte memcpy (which MSVC outlines into a call) appears.
        case 5: {
            uint32_t v = 0;
            std::memcpy(&v, p, 4);
            *out = (static_cast<uint64_t>(_byteswap_ulong(v)) << 8) | p[4];
            return true;
        }
        case 6: {
            uint32_t v = 0;
            std::memcpy(&v, p, 4);
            *out = (static_cast<uint64_t>(_byteswap_ulong(v)) << 16) |
                   (static_cast<uint64_t>(p[4]) << 8) | p[5];
            return true;
        }
        case 7: {
            uint32_t v = 0;
            std::memcpy(&v, p, 4);
            *out = (static_cast<uint64_t>(_byteswap_ulong(v)) << 24) |
                   (static_cast<uint64_t>(p[4]) << 16) |
                   (static_cast<uint64_t>(p[5]) << 8) | p[6];
            return true;
        }
        case 8: {
            uint64_t w = 0;
            std::memcpy(&w, p, 8);
            *out = _byteswap_uint64(w);
            return true;
        }
        default:
            return false;  // no caller does this; refuse, don't wrap
    }
}

// ============================================================================
// 11. TLS Big-Endian Field Reads
// ============================================================================

uint16_t TlsBe16Opt(const unsigned char* p) {
    if (p == nullptr) return 0;
    uint16_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return _byteswap_ushort(v);
}

uint32_t TlsBe24Opt(const unsigned char* p) {
    if (p == nullptr) return 0;
    // Deliberately shift/OR, not a wide load: callers guarantee only 3
    // bytes, so a 4-byte load would over-read. Same codegen as Be24.
    return (static_cast<uint32_t>(p[0]) << 16) |
           (static_cast<uint32_t>(p[1]) << 8) | p[2];
}

uint32_t TlsBe32Opt(const unsigned char* p) {
    if (p == nullptr) return 0;
    uint32_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return _byteswap_ulong(v);
}

// ============================================================================
// 12. TLS Extension Dispatch + SNI Tail Strip
// ============================================================================

TlsExtAction ClassifyTlsExtensionOpt(uint16_t type) {
    // Only 0x0000 (server_name) and 0x0010 (ALPN) are handled; every
    // other type skips. A 17-entry table turns the if/else chain into
    // one range check plus an indexed load.
    static const unsigned char kAct[17] = {
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
    };
    if (type > 16) return TlsExtAction::kSkip;
    return static_cast<TlsExtAction>(kAct[type]);
}

size_t StripSniTailOpt(char* s, size_t n) {
    if (s == nullptr) return 0;
    size_t len = n;
    // Short names go scalar straight away: one 16-byte SIMD step costs
    // more than stripping a handful of tail bytes (~0.5x measured).
    if (len < 32) {
        while (len > 0 && (s[len - 1] == '\0' || s[len - 1] == '.')) --len;
        return len;
    }

#if defined(WINTCP_HAS_SSE2)
    // Scan 16-byte blocks from the tail: a block is dropped whole iff
    // every byte is NUL or '.'. Otherwise the last kept byte is the
    // highest non-strip byte in the block.
    const __m128i kDot = _mm_set1_epi8('.');
    const __m128i kZero = _mm_setzero_si128();
    while (len >= 16) {
        const __m128i v = _mm_loadu_si128(
            reinterpret_cast<const __m128i*>(s + len - 16));
        const __m128i strip = _mm_or_si128(
            _mm_cmpeq_epi8(v, kDot), _mm_cmpeq_epi8(v, kZero));
        const unsigned m =
            static_cast<unsigned>(_mm_movemask_epi8(strip));
        if (m != 0xFFFFu) {
            unsigned long top = 0;
            // m != 0xFFFF, so ~m != 0: a top set bit always exists.
            if (_BitScanReverse(&top, ~m & 0xFFFFu) == 0) break;
            len = (len - 16) + static_cast<size_t>(top) + 1;
            return len;
        }
        len -= 16;
    }
#endif

    while (len > 0 && (s[len - 1] == '\0' || s[len - 1] == '.')) --len;
    return len;
}

// ============================================================================
// 13. Pcap Endian Loads
// ============================================================================

uint16_t Rd16Opt(const unsigned char* p, bool swap) {
    if (p == nullptr) return 0;
    uint16_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return swap ? _byteswap_ushort(v) : v;
}

uint32_t Rd32Opt(const unsigned char* p, bool swap) {
    if (p == nullptr) return 0;
    uint32_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return swap ? _byteswap_ulong(v) : v;
}

// ============================================================================
// 14. Socket-Sample Join
// ============================================================================

namespace {

struct JoinKey {
    uint64_t ports;
    const std::wstring* local;
    const std::wstring* remote;

    bool operator==(const JoinKey& o) const {
        return ports == o.ports && *local == *o.local &&
               *remote == *o.remote;
    }
};

struct JoinKeyHash {
    size_t operator()(const JoinKey& k) const noexcept {
        size_t h = std::hash<uint64_t>{}(k.ports);
        // boost::hash_combine - order-sensitive, cheap avalanche.
        h ^= std::hash<std::wstring>{}(*k.local) + 0x9e3779b9u +
             (h << 6) + (h >> 2);
        h ^= std::hash<std::wstring>{}(*k.remote) + 0x9e3779b9u +
             (h << 6) + (h >> 2);
        return h;
    }
};

}  // namespace

int JoinSamplesOpt(std::vector<JoinRow>& rows,
                   const std::vector<JoinSample>& samples) {
    if (rows.empty() || samples.empty()) return 0;

    // Index TCP rows by 4-tuple. Queues are built backwards so back()
    // is the smallest row index - the same FIFO discipline as
    // ReplaceSnapshot's PrevKeyIndex, hence the same assignment.
    std::unordered_map<JoinKey, std::vector<size_t>, JoinKeyHash> idx;
    idx.reserve(rows.size() * 2 + 1);
    for (size_t i = rows.size(); i-- > 0;) {
        const JoinRow& r = rows[i];
        if (!r.tcp) continue;  // SIO_TCP_INFO is TCP (matches orig skip)
        const JoinKey k{(static_cast<uint64_t>(r.localPort) << 32) |
                            r.remotePort,
                        &r.local, &r.remote};
        idx[k].push_back(i);
    }

    int updated = 0;
    for (const JoinSample& s : samples) {
        if (!s.known) continue;
        const JoinKey k{(static_cast<uint64_t>(s.localPort) << 32) |
                            s.remotePort,
                        &s.local, &s.remote};
        const auto it = idx.find(k);
        if (it == idx.end() || it->second.empty()) continue;
        // Each row index is handed out once: the queue front is always
        // unclaimed, so no claimed[] array is needed.
        const size_t ri = it->second.back();
        it->second.pop_back();
        JoinRow& r = rows[ri];
        r.rx = s.rx;
        r.tx = s.tx;
        r.perRow = true;
        ++updated;
    }
    return updated;
}

// ============================================================================
// 15. Long-Needle Substring BMH
// ============================================================================

bool FindSubstringLongOpt(const std::wstring& haystack,
                          const std::wstring& needle) {
    const size_t hn = haystack.size();
    const size_t nn = needle.size();
    if (nn == 0) return true;
    if (nn > hn) return false;
    const wchar_t* h = haystack.data();
    const wchar_t* n = needle.data();

    if (nn == 1) {
        const wchar_t c = n[0];
        for (size_t i = 0; i < hn; ++i) {
            if (h[i] == c) return true;
        }
        return false;
    }

    // Bad-character table on the low byte, MINIMUM shift per bucket:
    // shifting less than the true BMH shift only costs work, while
    // shifting more could skip a match - so the min is always safe.
    // Every entry is >= 1, so the scan always advances.
    size_t skip[256];
    for (size_t i = 0; i < 256; ++i) skip[i] = nn;
    for (size_t j = 0; j + 1 < nn; ++j) {
        const size_t b = static_cast<size_t>(n[j] & 0xFF);
        const size_t sh = nn - 1 - j;
        if (sh < skip[b]) skip[b] = sh;
    }

    size_t i = 0;
    while (i + nn <= hn) {
        size_t j = nn;
        while (j > 0 && h[i + j - 1] == n[j - 1]) --j;
        if (j == 0) return true;
        i += skip[static_cast<size_t>(h[i + nn - 1] & 0xFF)];
    }
    return false;
}

// ============================================================================
// 16. Lower-All Concat
// ============================================================================

std::wstring BuildLowerAllOpt(const std::wstring* const* fields, size_t count) {
    // Production always joins exactly these 10 fields; shorter input
    // yields empty, longer input joins the first 10 - mirroring the
    // original's +-chain exactly.
    if (fields == nullptr || count < 10) return std::wstring();
    size_t total = 9;  // single-space separators
    for (size_t i = 0; i < 10; ++i) total += fields[i]->size();
    std::wstring out;
    out.reserve(total);
    for (size_t i = 0; i < 10; ++i) {
        if (i != 0) out += L' ';
        out += *fields[i];
    }
    return out;
}

// ============================================================================
// 17. Wide String Compare
// ============================================================================

int CompareWideOpt(const wchar_t* a, size_t na, const wchar_t* b,
                   size_t nb) {
    if (a == nullptr || b == nullptr) {
        if (a == b) return 0;
        return (a != nullptr) ? 1 : -1;
    }
    const size_t m = (std::min)(na, nb);
    size_t i = 0;

#if defined(WINTCP_HAS_SSE2)
    for (; i + 8 <= m; i += 8) {
        const __m128i va = _mm_loadu_si128(
            reinterpret_cast<const __m128i*>(a + i));
        const __m128i vb = _mm_loadu_si128(
            reinterpret_cast<const __m128i*>(b + i));
        const unsigned eq = static_cast<unsigned>(
            _mm_movemask_epi8(_mm_cmpeq_epi16(va, vb)));
        if (eq != 0xFFFFu) {
            // First differing lane: lowest clear bit, halved.
            unsigned long bit = 0;
            if (_BitScanForward(&bit, ~eq & 0xFFFFu) == 0) break;
            const size_t j = i + (bit >> 1);
            if (a[j] == b[j]) continue;  // same lane, split bytes - keep going
            return (a[j] < b[j]) ? -1 : 1;
        }
    }
#endif

    for (; i < m; ++i) {
        if (a[i] != b[i]) return (a[i] < b[i]) ? -1 : 1;
    }
    if (na == nb) return 0;
    return (na < nb) ? -1 : 1;
}

// ============================================================================
// 18. Connection-Key Hash + Equality
// ============================================================================

size_t HashConnKeyOpt(const unsigned char* bytes, size_t len) {
    if (bytes == nullptr) return 0;
    // FNV-1a 64-bit, one lane per iteration, byte tail, length mix.
    uint64_t h = 1469598103934665603ULL;
    size_t i = 0;
    for (; i + 8 <= len; i += 8) {
        uint64_t w = 0;
        std::memcpy(&w, bytes + i, 8);
        h ^= w;
        h *= 1099511628211ULL;
    }
    for (; i < len; ++i) {
        h ^= bytes[i];
        h *= 1099511628211ULL;
    }
    h ^= static_cast<uint64_t>(len);
    h *= 1099511628211ULL;
    return static_cast<size_t>(h);
}

bool EqualConnKeyOpt(const unsigned char* a, size_t na,
                     const unsigned char* b, size_t nb) {
    if (na != nb) return false;
    if (a == nullptr || b == nullptr) return a == b;
    size_t i = 0;
#if defined(WINTCP_HAS_SSE2)
    for (; i + 16 <= na; i += 16) {
        const __m128i va = _mm_loadu_si128(
            reinterpret_cast<const __m128i*>(a + i));
        const __m128i vb = _mm_loadu_si128(
            reinterpret_cast<const __m128i*>(b + i));
        if (_mm_movemask_epi8(_mm_cmpeq_epi8(va, vb)) != 0xFFFF) {
            return false;
        }
    }
#endif
    return std::memcmp(a + i, b + i, na - i) == 0;
}

// ============================================================================
// 19. Batch Rate Computation
// ============================================================================

size_t ComputeBpsBatchOpt(const uint64_t* prevBytes,
                          const uint64_t* nowBytes, uint64_t elapsedMs,
                          double* outBps, size_t n) {
    if (prevBytes == nullptr || nowBytes == nullptr || outBps == nullptr) {
        return 0;
    }
    // No elapsed time means no rate (same-millisecond resample).
    if (elapsedMs == 0 || n == 0) return 0;
    // One reciprocal for the whole batch instead of one divide per
    // counter. Backwards counters report no reading (recycled socket).
    const double inv = 1000.0 / static_cast<double>(elapsedMs);
    size_t ok = 0;
    for (size_t i = 0; i < n; ++i) {
        if (nowBytes[i] < prevBytes[i]) {
            outBps[i] = 0.0;
            continue;
        }
        outBps[i] =
            static_cast<double>(nowBytes[i] - prevBytes[i]) * inv;
        ++ok;
    }
    return ok;
}

// ============================================================================
// 20. Per-PID Traffic Sums
// ============================================================================

void SumPidTrafficOpt(PidTrafficRow* rows, size_t n) {
    if (rows == nullptr || n == 0) return;
    // Order row indexes by PID; runs of equal PIDs are summed in one
    // linear pass. Assignment is per-row identical to the map version
    // regardless of order, so sort stability is irrelevant.
    std::vector<size_t> ord(n);
    for (size_t i = 0; i < n; ++i) ord[i] = i;
    std::sort(ord.begin(), ord.end(), [rows](size_t x, size_t y) {
        return rows[x].pid < rows[y].pid;
    });
    size_t run = 0;
    while (run < n) {
        size_t end = run + 1;
        while (end < n && rows[ord[end]].pid == rows[ord[run]].pid) ++end;
        bool any = false;
        uint64_t sumRx = 0;
        uint64_t sumTx = 0;
        for (size_t k = run; k < end; ++k) {
            const PidTrafficRow& r = rows[ord[k]];
            if (!r.counted) continue;
            any = true;
            const uint64_t rx = sumRx + r.rx;  // SatAdd (matches orig)
            sumRx = (rx < sumRx) ? ~0ULL : rx;
            const uint64_t tx = sumTx + r.tx;
            sumTx = (tx < sumTx) ? ~0ULL : tx;
        }
        for (size_t k = run; k < end; ++k) {
            PidTrafficRow& r = rows[ord[k]];
            r.sumRx = any ? sumRx : 0;
            r.sumTx = any ? sumTx : 0;
            r.hasSum = any;
        }
        run = end;
    }
}

// ============================================================================
// 21. Rate Cell Formatting
// ============================================================================

size_t FormatBpsCellOpt(wchar_t* buf, size_t bufSize, double rxBps,
                        double txBps, bool known) {
    if (buf == nullptr || bufSize == 0) return 0;
    if (!known) {
        if (bufSize < 2) return 0;
        buf[0] = L'—';
        buf[1] = L'\0';
        return 1;
    }
    if (rxBps < 0.5 && txBps < 0.5) {
        if (bufSize < 5) {
            buf[0] = L'\0';
            return 0;
        }
        buf[0] = L'i';
        buf[1] = L'd';
        buf[2] = L'l';
        buf[3] = L'e';
        buf[4] = L'\0';
        return 4;
    }
    wchar_t rx[32] = {0};
    wchar_t tx[32] = {0};
    const size_t rxLen =
        FormatBytesOpt(rx, 32, static_cast<uint64_t>(rxBps + 0.5));
    const size_t txLen =
        FormatBytesOpt(tx, 32, static_cast<uint64_t>(txBps + 0.5));
    if (rxLen == 0 || txLen == 0) {
        buf[0] = L'\0';
        return 0;
    }
    // L"↓ " + rx + L"/s  ↑ " + tx + L"/s" = 10 + rxLen + txLen chars.
    const size_t need = 10 + rxLen + txLen;
    if (need + 1 > bufSize) {
        buf[0] = L'\0';
        return 0;
    }
    size_t at = 0;
    buf[at++] = L'↓';
    buf[at++] = L' ';
    for (size_t i = 0; i < rxLen; ++i) buf[at++] = rx[i];
    buf[at++] = L'/';
    buf[at++] = L's';
    buf[at++] = L' ';
    buf[at++] = L' ';
    buf[at++] = L'↑';
    buf[at++] = L' ';
    for (size_t i = 0; i < txLen; ++i) buf[at++] = tx[i];
    buf[at++] = L'/';
    buf[at++] = L's';
    buf[at++] = L'\0';
    return need;
}

// ============================================================================
// 22. MMDB UTF-8 Widen
// ============================================================================

std::wstring WidenUtf8Opt(const unsigned char* p, size_t n) {
    std::wstring out;
    if (p == nullptr || n == 0) return out;
    out.reserve(n);

    size_t i = 0;
#if defined(WINTCP_HAS_SSE2)
    // Bulk ASCII: 16 bytes with no high bit append as-is. On the first
    // mixed block, append its leading ASCII run, then fall through to
    // the scalar validator for the rest.
    while (i + 16 <= n) {
        const __m128i v = _mm_loadu_si128(
            reinterpret_cast<const __m128i*>(p + i));
        const unsigned m =
            static_cast<unsigned>(_mm_movemask_epi8(v));
        if (m == 0) {
            for (size_t k = 0; k < 16; ++k) {
                out.push_back(static_cast<wchar_t>(p[i + k]));
            }
            i += 16;
            continue;
        }
        unsigned long first = 0;
        if (_BitScanForward(&first, m) == 0) break;
        for (unsigned long k = 0; k < first; ++k) {
            out.push_back(static_cast<wchar_t>(p[i + k]));
        }
        i += first;
        break;
    }
#endif

    // Verbatim scalar validator (GeoIp.cpp:543-571) for the remainder:
    // overlong leads, stray continuations, 4-byte sequences and
    // surrogates all become U+FFFD.
    while (i < n) {
        const unsigned char lead = p[i];
        if (lead < 0x80) {
            out.push_back(static_cast<wchar_t>(lead));
            ++i;
            continue;
        }
        uint32_t cp = 0xFFFD;
        size_t used = 1;
        if (lead >= 0xC2 && lead < 0xE0) {
            cp = lead & 0x1Fu;
        } else if (lead >= 0xE0 && lead < 0xF0) {
            cp = lead & 0x0Fu;
        } else {
            cp = 0xFFFD;
        }
        if (lead >= 0xC2 && lead < 0xF0 && i + 1 < n &&
            (p[i + 1] & 0xC0) == 0x80) {
            cp = (cp << 6) | (p[i + 1] & 0x3Fu);
            used = 2;
            if (lead >= 0xE0 && i + 2 < n && (p[i + 2] & 0xC0) == 0x80) {
                cp = (cp << 6) | (p[i + 2] & 0x3Fu);
                used = 3;
            }
        }
        if (cp > 0xFFFF || (cp >= 0xD800 && cp <= 0xDFFF)) cp = 0xFFFD;
        out.push_back(static_cast<wchar_t>(cp));
        i += used;
    }
    return out;
}

// ============================================================================
// 23. Unicast Classification
// ============================================================================

bool IsGlobalUnicastV4Opt(uint32_t a) {
    // First-octet action table: 0 = allow, 1 = deny, 2..7 = sub-test.
    // Generated FROM the predicates below; the sub-expressions are the
    // originals verbatim.
    static const unsigned char kAct[256] = {
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,  // 0-15
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 16-31
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 32-47
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 48-63
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 64-79
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 80-95
        0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 96-111
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,  // 112-127
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 128-143
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 144-159
        0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 4, 0, 0, 0,  // 160-175
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 176-191
        5, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 7, 0, 0, 0, 0,  // 192-207
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 208-223
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // 224-239
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // 240-255
    };
    const uint32_t first = (a >> 24) & 0xFFu;
    switch (kAct[first]) {
        case 0:
            return true;
        case 1:
            return false;
        case 2:  // 100.64/10 CGNAT
            return (a & 0xFFC00000u) != 0x64400000u;
        case 3:  // 169.254/16 link-local
            return (a >> 16) != 0xA9FEu;
        case 4:  // 172.16/12 private (range, handled below)
            break;
        case 5:  // 192.x sub-ranges
            if ((a >> 8) == 0xC00000u) return false;
            if ((a >> 8) == 0xC05863u) return false;
            return (a >> 16) != 0xC0A8u;
        case 6:  // 198.x sub-ranges
            if (((a >> 16) & 0xFFFEu) == 0xC612u) return false;
            return (a >> 8) != 0xC63364u;
        case 7:  // 203.0.113/24 documentation
            return (a >> 8) != 0xCB0071u;
        default:
            return true;
    }
    // 172.16/12: second octet in [16, 31].
    const uint32_t second = (a >> 16) & 0xFFu;
    return second < 16 || second > 31;
}

bool IsGlobalUnicastV6Opt(const unsigned char a[16]) {
    if (a == nullptr) return false;
    if (a[0] == 0xFF) return false;                  // ff00::/8
    if (a[0] == 0xFC || a[0] == 0xFD) return false;  // fc00::/7
    if (a[0] == 0xFE && (a[1] & 0xC0) == 0xC0) return false;
    if (a[0] == 0x20 && a[1] == 0x01 && a[2] == 0x0D && a[3] == 0xB8) {
        return false;  // 2001:db8::/32
    }
    if ((a[0] == 0x01 && a[1] == 0x00) ||
        (a[0] == 0x00 && a[1] == 0x00)) {
        // Either 100::/64-all-zero or ::/64-all-zero tail test: the 14
        // tail bytes read as two overlapping u64 words; the overlap is
        // irrelevant to a zero test.
        uint64_t lo = 0;
        uint64_t hi = 0;
        std::memcpy(&lo, a + 2, 8);
        std::memcpy(&hi, a + 8, 8);
        if ((lo | hi) == 0) return false;
    }
    return true;
}

// ============================================================================
// 24. Snapshot Pairing, Sort-Merge
// ============================================================================

namespace {

inline size_t HashSnapKey(const SnapKey& k) {
    // Same FNV-1a lanes as HashConnKeyOpt,
    // inlined here so the pairing pays no std::hash<string_view>
    // per-key cost.
    uint64_t h = 1469598103934665603ULL;
    size_t i = 0;
    for (; i + 8 <= k.len; i += 8) {
        uint64_t w = 0;
        std::memcpy(&w, k.bytes + i, 8);
        h ^= w;
        h *= 1099511628211ULL;
    }
    for (; i < k.len; ++i) {
        h ^= k.bytes[i];
        h *= 1099511628211ULL;
    }
    h ^= static_cast<uint64_t>(k.len);
    h *= 1099511628211ULL;
    return static_cast<size_t>(h);
}

struct SnapKeyHash {
    size_t operator()(const SnapKey& k) const noexcept {
        return HashSnapKey(k);
    }
};

}  // namespace

int PairSnapshotOpt(const SnapKey* prev, size_t nPrev,
                    const SnapKey* fresh, size_t nFresh, int* out) {
    if (prev == nullptr || fresh == nullptr || out == nullptr) return 0;
    for (size_t i = 0; i < nFresh; ++i) out[i] = -1;
    if (nPrev == 0 || nFresh == 0) return 0;
    // Hash + FIFO queues (the production algorithm): measurement showed
    // the sort-merge variant losing 2.4-3x at these sizes - short keys
    // hash in ~2 lanes while sort pays O(n log n) full-key compares.
    // The win over the original is the FNV lane hash + reserve.
    std::unordered_map<SnapKey, std::vector<size_t>, SnapKeyHash> prevMap;
    prevMap.reserve(nPrev * 2 + 1);
    for (size_t i = nPrev; i-- > 0;) {
        prevMap[prev[i]].push_back(i);
    }
    int paired = 0;
    for (size_t i = 0; i < nFresh; ++i) {
        const auto it = prevMap.find(fresh[i]);
        if (it == prevMap.end() || it->second.empty()) continue;
        out[i] = static_cast<int>(it->second.back());
        it->second.pop_back();
        ++paired;
    }
    return paired;
}

// ============================================================================
// 25. Counted-Key Linear Find
// ============================================================================

int FindCountedKeyOpt(const CountedKey* keys, size_t nKeys,
                      const unsigned char* want, size_t wantLen) {
    if (keys == nullptr || want == nullptr) return -1;
    if (wantLen >= 8) {
        uint64_t w = 0;
        std::memcpy(&w, want, 8);
        for (size_t i = 0; i < nKeys; ++i) {
            if (keys[i].n != wantLen) continue;
            if (keys[i].p == nullptr) continue;
            uint64_t k = 0;
            std::memcpy(&k, keys[i].p, 8);
            if (k != w) continue;
            if (std::memcmp(keys[i].p, want, wantLen) == 0) {
                return static_cast<int>(i);
            }
        }
        return -1;
    }
    for (size_t i = 0; i < nKeys; ++i) {
        if (keys[i].n != wantLen) continue;
        if (keys[i].p == nullptr) continue;
        if (std::memcmp(keys[i].p, want, wantLen) == 0) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

// ============================================================================
// 26. Flow-Key Equality + Address Compare
// ============================================================================

bool FlowKeyEqualOpt(const FlowKey& a, const FlowKey& b) {
    // Cheap reject first, exactly like the original.
    if (a.portA != b.portA || a.portB != b.portB) return false;
#if defined(WINTCP_HAS_SSE2)
    const __m128i aa =
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(a.addrA));
    const __m128i ba =
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(b.addrA));
    if (_mm_movemask_epi8(_mm_cmpeq_epi8(aa, ba)) != 0xFFFF) return false;
    const __m128i ab =
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(a.addrB));
    const __m128i bb =
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(b.addrB));
    return _mm_movemask_epi8(_mm_cmpeq_epi8(ab, bb)) == 0xFFFF;
#else
    return std::memcmp(a.addrA, b.addrA, 16) == 0 &&
           std::memcmp(a.addrB, b.addrB, 16) == 0;
#endif
}

int CmpFlowAddrOpt(const unsigned char* a, const unsigned char* b) {
    if (a == b) return 0;
    if (a == nullptr || b == nullptr) return (a != nullptr) ? 1 : -1;
#if defined(WINTCP_HAS_SSE2)
    const __m128i va = _mm_loadu_si128(
        reinterpret_cast<const __m128i*>(a));
    const __m128i vb = _mm_loadu_si128(
        reinterpret_cast<const __m128i*>(b));
    const unsigned eq = static_cast<unsigned>(
        _mm_movemask_epi8(_mm_cmpeq_epi8(va, vb)));
    if (eq != 0xFFFFu) {
        unsigned long bit = 0;
        if (_BitScanForward(&bit, ~eq & 0xFFFFu) == 0) return 0;
        // Unsigned-byte order is exactly memcmp order.
        return (a[bit] < b[bit]) ? -1 : 1;
    }
    return 0;
#else
    return std::memcmp(a, b, 16);
#endif
}

// ============================================================================
// 27. Handle-Table Filter
// ============================================================================

size_t FilterHandlesOpt(const HandleEntry* entries, size_t n,
                        const uint32_t* wantPids, size_t nPids,
                        const uint32_t* wantTypes, size_t nTypes,
                        bool typesKnown, const PidHandle* skip,
                        size_t nSkip, size_t* outIdx, size_t outCap) {
    if (entries == nullptr || outIdx == nullptr) return 0;
    if ((wantPids == nullptr && nPids != 0) ||
        (wantTypes == nullptr && nTypes != 0) ||
        (skip == nullptr && nSkip != 0)) {
        return 0;
    }
    size_t accepted = 0;
    for (size_t i = 0; i < n; ++i) {
        // UniqueProcessId wider than a DWORD cannot be one of ours.
        if (entries[i].srcPid > 0xFFFFFFFFu) continue;
        const uint32_t pid = static_cast<uint32_t>(entries[i].srcPid);
        if (!std::binary_search(wantPids, wantPids + nPids, pid)) continue;
        if (typesKnown && !std::binary_search(wantTypes, wantTypes + nTypes,
                                              entries[i].typeIndex)) {
            continue;
        }
        const PidHandle q{pid, entries[i].handle};
        if (std::binary_search(skip, skip + nSkip, q)) continue;
        if (accepted < outCap) outIdx[accepted] = i;
        ++accepted;
    }
    return accepted;
}

// ============================================================================
// 28. ETW Event Classifier + Payload
// ============================================================================

TrafficDir ClassifyEventOpt(const unsigned char guid[16], uint16_t id,
                            uint16_t opcode) {
    if (guid == nullptr) return TrafficDir::kNone;
    // Exact bytes of kTcpIpProviderGuid / kUdpIpProviderGuid
    // (EtwTrafficTypes.h:28-33): Data1..Data3 little-endian, Data4 raw.
    static const unsigned char kTcp[16] = {
        0xC0, 0x0A, 0x28, 0x9A, 0xE0, 0xC8, 0xD1, 0x11,
        0x84, 0xE2, 0x00, 0xC0, 0x4F, 0xB9, 0x98, 0xA2};
    static const unsigned char kUdp[16] = {
        0xC5, 0x50, 0x3A, 0xBF, 0xC9, 0xA9, 0x88, 0x49,
        0xA0, 0x05, 0x2D, 0xF0, 0xB7, 0xC8, 0x0F, 0x80};
    uint64_t g = 0;
    uint64_t t = 0;
    uint64_t u = 0;
    std::memcpy(&g, guid, 8);
    std::memcpy(&t, kTcp, 8);
    std::memcpy(&u, kUdp, 8);
    if (g != t && g != u) return TrafficDir::kNone;
    // First-half collision across providers is impossible here, but
    // verify the full GUID for exactness all the same.
    if (std::memcmp(guid, (g == t) ? kTcp : kUdp, 16) != 0) {
        return TrafficDir::kNone;
    }
    // Opcode table: slot i holds the only countable opcode with
    // (opcode & 31) == i, else 0. One load + compares replace the
    // 4-compare chain, with identical accept/reject behavior. The
    // stored values are all nonzero, so the != 0 guard keeps input 0
    // (slot 0's value) from matching.
    static const uint16_t kWant[32] = {
        0,  0, 0, 0, 0, 0, 0,  0, 0, 0, 10, 11, 0, 0, 0, 0,
        0,  0, 0, 0, 0, 0, 0,  0, 0, 0, 26, 27, 0, 0, 0, 0,
    };
    uint16_t type = 0;
    const uint16_t ow = kWant[opcode & 31];
    if (ow != 0 && ow == opcode) {
        type = opcode;
    } else {
        const uint16_t iw = kWant[id & 31];
        if (iw == 0 || iw != id) return TrafficDir::kNone;
        type = id;
    }
    return (type == 10 || type == 26) ? TrafficDir::kSent
                                      : TrafficDir::kReceived;
}

bool ParseEventPayloadOpt(const void* data, size_t length, uint32_t* pid,
                          uint32_t* size) {
    if (data == nullptr || length < 8) return false;
    // Single load: PID @0, size @4, little-endian like the wire.
    uint64_t w = 0;
    std::memcpy(&w, data, 8);
    const uint32_t p = static_cast<uint32_t>(w);
    const uint32_t s = static_cast<uint32_t>(w >> 32);
    if (p == 0 || s == 0) return false;  // idle PID / connect-style
    if (pid != nullptr) *pid = p;
    if (size != nullptr) *size = s;
    return true;
}

// ============================================================================
// 29. JSON String Escape
// ============================================================================

std::string JsonEscapeOpt(const std::wstring& s) {
    if (s.empty()) return std::string();
    // UTF-8 first (SSE2 ASCII path inside).
    std::string u8(s.size() * 4 + 1, '\0');
    const size_t ulen =
        WideToUtf8Opt(s.c_str(), s.size(), u8.data(), u8.size());
    u8.resize(ulen);

    static const char kHexDig[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                     '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    std::string out;
    out.reserve(ulen + 8);
    const char* p = u8.data();
    size_t i = 0;

#if defined(WINTCP_HAS_SSE2)
    const __m128i kQ = _mm_set1_epi8('"');
    const __m128i kB = _mm_set1_epi8('\\');
    const __m128i kSp = _mm_set1_epi8(0x20);
    const __m128i kZero = _mm_setzero_si128();
#endif

    auto emitSpecial = [&out](unsigned char c) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                // Identical to sprintf_s "\\u%04x" for c < 0x20.
                out += "\\u00";
                out += kHexDig[c >> 4];
                out += kHexDig[c & 0x0F];
                break;
        }
    };

    while (i < ulen) {
#if defined(WINTCP_HAS_SSE2)
        // Short tail: scalar rest, no SIMD setup.
        if (ulen - i < 16) break;
        size_t j = i;
        bool cleanToEnd = false;
        for (;;) {
            const __m128i v = _mm_loadu_si128(
                reinterpret_cast<const __m128i*>(p + j));
            const __m128i special = _mm_andnot_si128(
                // High bytes (negative signed) are NOT specials.
                _mm_cmplt_epi8(v, kZero),
                _mm_or_si128(
                    _mm_or_si128(_mm_cmpeq_epi8(v, kQ),
                                 _mm_cmpeq_epi8(v, kB)),
                    _mm_cmplt_epi8(v, kSp)));
            const unsigned m =
                static_cast<unsigned>(_mm_movemask_epi8(special));
            if (m != 0) {
                unsigned long bit = 0;
                if (_BitScanForward(&bit, m) == 0) break;
                j += bit;
                break;
            }
            j += 16;
            // Room for another full window: keep scanning. Otherwise this is
            // the tail - hand it to the scalar loop below rather than
            // treating p[j] as special, because it is usually not.
            if (j + 16 <= ulen) continue;
            cleanToEnd = true;
            break;
        }
        out.append(p + i, j - i);
        i = j;
        if (cleanToEnd || i >= ulen) break;
        emitSpecial(static_cast<unsigned char>(p[i]));
        i += 1;
#else
        break;
#endif
    }

    for (; i < ulen; ++i) {
        const unsigned char c = static_cast<unsigned char>(p[i]);
        if (c != '"' && c != '\\' && c != '\n' && c != '\r' &&
            c != '\t' && c >= 0x20) {
            out += static_cast<char>(c);
            continue;
        }
        emitSpecial(c);
    }
    return out;
}

// ============================================================================
// 30. CSV Field Escape
// ============================================================================

std::string CsvEscapeOpt(const std::string& field) {
    // No-quote fast path, verbatim (find_first_of over , " CR LF).
    if (field.find_first_of(",\"\r\n") == std::string::npos) return field;
    std::string out;
    out.reserve(field.size() + 2);
    out.push_back('"');

    const char* p = field.data();
    const size_t n = field.size();
    size_t i = 0;
#if defined(WINTCP_HAS_SSE2)
    // Quote scan with span copies; only '"' changes the output.
    const __m128i kQ = _mm_set1_epi8('"');
    while (i + 16 <= n) {
        const __m128i v = _mm_loadu_si128(
            reinterpret_cast<const __m128i*>(p + i));
        const unsigned m = static_cast<unsigned>(
            _mm_movemask_epi8(_mm_cmpeq_epi8(v, kQ)));
        if (m == 0) {
            // A clean block must be EMITTED before advancing. Skipping the
            // append here silently drops the first 16 bytes of every field
            // that needs quoting, which is exactly what the short bench
            // inputs never caught: "a,b" is 3 bytes and never reaches the
            // SIMD loop. Found by `list --format csv` on a real service
            // name ("RpcEptMapper, RpcSs" came out as "cSs").
            out.append(p + i, 16);
            i += 16;
            continue;
        }
        unsigned long bit = 0;
        if (_BitScanForward(&bit, m) == 0) break;
        out.append(p + i, bit);
        out += "\"\"";
        i += bit + 1;
    }
#endif
    for (; i < n; ++i) {
        if (p[i] == '"') {
            out += "\"\"";
        } else {
            out.push_back(p[i]);
        }
    }
    out.push_back('"');
    return out;
}

// ============================================================================
// 31. Small-Integer Formatting
// ============================================================================

namespace {

// Digit tables: two digits per entry, "00".."99".
struct DigitTable {
    char d[100][2];
};

inline const DigitTable& DecTable() {
    static const DigitTable k = [] {
        DigitTable t{};
        for (int i = 0; i < 100; ++i) {
            t.d[i][0] = static_cast<char>('0' + i / 10);
            t.d[i][1] = static_cast<char>('0' + i % 10);
        }
        return t;
    }();
    return k;
}

// Emit v (any 64-bit value) as narrow chars; returns length. Caller
// provides >= 20 bytes.
inline size_t EmitU64(char* dst, uint64_t v) {
    const DigitTable& t = DecTable();
    char tmp[20];
    size_t n = 0;
    // Two digits at a time from the least significant end.
    while (v >= 100) {
        const uint64_t q = v / 100;
        const unsigned r = static_cast<unsigned>(v - q * 100);
        tmp[n++] = t.d[r][1];
        tmp[n++] = t.d[r][0];
        v = q;
    }
    if (v >= 10) {
        const size_t vv = static_cast<size_t>(v);
        tmp[n++] = t.d[vv][1];
        tmp[n++] = t.d[vv][0];
    } else {
        tmp[n++] = static_cast<char>('0' + static_cast<unsigned>(v));
    }
    for (size_t i = 0; i < n; ++i) dst[i] = tmp[n - 1 - i];
    return n;
}

}  // namespace

size_t FormatPortOpt(wchar_t* buf, size_t bufSize, unsigned port) {
    if (buf == nullptr || bufSize == 0) return 0;
    char tmp[20] = {0};
    const size_t n = EmitU64(tmp, port);
    if (n + 1 > bufSize) {
        buf[0] = L'\0';
        return 0;
    }
    for (size_t i = 0; i < n; ++i) buf[i] = static_cast<wchar_t>(tmp[i]);
    buf[n] = L'\0';
    return n;
}

size_t FormatU64DecOpt(char* buf, size_t bufSize, uint64_t v) {
    if (buf == nullptr || bufSize == 0) return 0;
    // Two digits per 64-bit divide (at most 10 divides for 20 digits).
    const DigitTable& t = DecTable();
    char tmp[20] = {0};
    size_t n = 0;
    while (v >= 100) {
        const uint64_t q = v / 100;
        const unsigned r = static_cast<unsigned>(v - q * 100);
        tmp[n++] = t.d[r][1];
        tmp[n++] = t.d[r][0];
        v = q;
    }
    if (v >= 10) {
        const size_t vv = static_cast<size_t>(v);
        tmp[n++] = t.d[vv][1];
        tmp[n++] = t.d[vv][0];
    } else {
        tmp[n++] = static_cast<char>('0' + static_cast<unsigned>(v));
    }
    if (n + 1 > bufSize) {
        buf[0] = '\0';
        return 0;
    }
    for (size_t i = 0; i < n; ++i) buf[i] = tmp[n - 1 - i];
    buf[n] = '\0';
    return n;
}

size_t FormatDurationOpt(wchar_t* buf, size_t bufSize, uint64_t seconds) {
    if (buf == nullptr || bufSize == 0) return 0;
    // Four shapes, floored (never rounded up): "Nd Nh", "Nh Nm",
    // "Nm %02ds", "Ns". Number rendering shares EmitU64.
    char a[20] = {0};
    char b[20] = {0};
    size_t na = 0;
    size_t nb = 0;
    bool two = true;
    wchar_t unitA = L's';
    wchar_t unitB = L's';
    bool padB = false;
    if (seconds >= 86400ULL) {
        na = EmitU64(a, seconds / 86400ULL);
        nb = EmitU64(b, (seconds % 86400ULL) / 3600ULL);
        unitA = L'd';
        unitB = L'h';
    } else if (seconds >= 3600ULL) {
        na = EmitU64(a, seconds / 3600ULL);
        nb = EmitU64(b, (seconds % 3600ULL) / 60ULL);
        unitA = L'h';
        unitB = L'm';
    } else if (seconds >= 60ULL) {
        na = EmitU64(a, seconds / 60ULL);
        nb = EmitU64(b, seconds % 60ULL);
        unitA = L'm';
        unitB = L's';
        padB = true;  // %02llu
    } else {
        na = EmitU64(a, seconds);
        two = false;
        unitA = L's';
    }
    // Worst case: 10 + 1 + 1 + 1 + 2 + 1 = 16 chars + NUL.
    size_t need = na + 1;  // "N<unit>"
    if (two) need += 1 + nb + ((padB && nb < 2) ? 1 : 0) + 1;
    if (need + 1 > bufSize) {
        buf[0] = L'\0';
        return 0;
    }
    size_t at = 0;
    for (size_t i = 0; i < na; ++i) buf[at++] = static_cast<wchar_t>(a[i]);
    buf[at++] = unitA;
    if (two) {
        buf[at++] = L' ';
        if (padB && nb < 2) buf[at++] = L'0';
        for (size_t i = 0; i < nb; ++i) {
            buf[at++] = static_cast<wchar_t>(b[i]);
        }
        buf[at++] = unitB;
    }
    buf[at++] = L'\0';
    return need;
}

// ============================================================================
// 32. IP Address Emitters
// ============================================================================

std::wstring FormatIpv4Opt(const unsigned char addr[4]) {
    if (addr == nullptr) return std::wstring();
    // "255.255.255.255" = 15 chars max.
    wchar_t buf[16] = {0};
    size_t at = 0;
    for (int o = 0; o < 4; ++o) {
        if (o != 0) buf[at++] = L'.';
        const unsigned v = addr[o];
        if (v >= 100) {
            buf[at++] = static_cast<wchar_t>(L'0' + v / 100);
            buf[at++] = static_cast<wchar_t>(L'0' + (v / 10) % 10);
            buf[at++] = static_cast<wchar_t>(L'0' + v % 10);
        } else if (v >= 10) {
            buf[at++] = static_cast<wchar_t>(L'0' + v / 10);
            buf[at++] = static_cast<wchar_t>(L'0' + v % 10);
        } else {
            buf[at++] = static_cast<wchar_t>(L'0' + v);
        }
    }
    return std::wstring(buf, at);
}

std::wstring FormatIpv6Opt(const unsigned char addr[16]) {
    if (addr == nullptr) return std::wstring();
    uint16_t g[8] = {0};
    for (int i = 0; i < 8; ++i) {
        g[i] = static_cast<uint16_t>((static_cast<uint16_t>(addr[2 * i])
                                      << 8) |
                                     addr[2 * i + 1]);
    }
    // v4-mapped (::ffff:a.b.c.d): dotted tail, like InetNtopW.
    if (g[0] == 0 && g[1] == 0 && g[2] == 0 && g[3] == 0 && g[4] == 0 &&
        g[5] == 0xFFFF) {
        wchar_t tail[16] = {0};
        size_t tn = 0;
        for (int o = 12; o < 16; ++o) {
            if (o != 12) tail[tn++] = L'.';
            const unsigned v = addr[o];
            if (v >= 100) {
                tail[tn++] = static_cast<wchar_t>(L'0' + v / 100);
                tail[tn++] = static_cast<wchar_t>(L'0' + (v / 10) % 10);
                tail[tn++] = static_cast<wchar_t>(L'0' + v % 10);
            } else if (v >= 10) {
                tail[tn++] = static_cast<wchar_t>(L'0' + v / 10);
                tail[tn++] = static_cast<wchar_t>(L'0' + v % 10);
            } else {
                tail[tn++] = static_cast<wchar_t>(L'0' + v);
            }
        }
        return std::wstring(L"::ffff:") +
               std::wstring(tail, tn);
    }
    // Longest zero run of length >= 2; ties go to the first.
    int bestAt = -1;
    int bestLen = 0;
    int curAt = -1;
    int curLen = 0;
    for (int i = 0; i <= 8; ++i) {
        if (i < 8 && g[i] == 0) {
            if (curAt < 0) {
                curAt = i;
                curLen = 1;
            } else {
                ++curLen;
            }
        } else {
            if (curLen > bestLen) {
                bestLen = curLen;
                bestAt = curAt;
            }
            curAt = -1;
            curLen = 0;
        }
    }
    static const wchar_t kHex[16] = {L'0', L'1', L'2', L'3', L'4', L'5',
                                     L'6', L'7', L'8', L'9', L'a', L'b',
                                     L'c', L'd', L'e', L'f'};
    // Max without compression: 8*4 + 7 = 39 chars.
    wchar_t buf[48] = {0};
    size_t at = 0;
    const bool compress = bestLen >= 2;
    for (int i = 0; i < 8;) {
        if (compress && i == bestAt) {
            buf[at++] = L':';
            buf[at++] = L':';
            i += bestLen;
            continue;
        }
        if (at != 0 && buf[at - 1] != L':') buf[at++] = L':';
        // Group in hex, no leading zeros.
        const uint16_t v = g[i];
        bool started = false;
        for (int sh = 12; sh >= 0; sh -= 4) {
            const unsigned nib =
                static_cast<unsigned>((v >> sh) & 0xF);
            if (nib != 0 || sh == 0 || started) {
                buf[at++] = kHex[nib];
                started = true;
            }
        }
        ++i;
    }
    // "::" alone (all zeros): loop wrote exactly that; trailing "::"
    // needs no extra colon (the pair was written at the run start).
    return std::wstring(buf, at);
}

// ============================================================================
// 33. Display width (Commands.cpp:270-350)
// ============================================================================

namespace {

// The original Commands.cpp:270-291 CpWidth, verbatim - kept as a local
// helper because a flat LUT and a binary search were both measured and
// lost (see the note on CpWidthOpt below).
//
// A 12 KB flat table for cp < 0x3000 generated from this chain measured
// 0.62x/0.78x against the chain on a boundary cycle and a random sweep;
// an ASCII fast path in front of it did not close the gap. The chain is
// 4 well-predicted compares for the common low code points and no table
// load beats it.
inline size_t CpWidthChain(uint32_t cp) {
    if (cp < 0x0300) return 1;
    if (cp <= 0x036F) return 0;   // combining accents
    if (cp < 0x1100) return 1;
    if (cp <= 0x115F) return 2;   // Hangul Jamo
    if ((cp >= 0x2E80 && cp <= 0x303E) ||
        (cp >= 0x3041 && cp <= 0x33FF) ||
        (cp >= 0x3400 && cp <= 0x4DBF) ||
        (cp >= 0x4E00 && cp <= 0x9FFF) ||
        (cp >= 0xA000 && cp <= 0xA4CF) ||
        (cp >= 0xA960 && cp <= 0xA97F) ||
        (cp >= 0xAC00 && cp <= 0xD7A3) ||
        (cp >= 0xF900 && cp <= 0xFAFF) ||
        (cp >= 0xFE30 && cp <= 0xFE6F) ||
        (cp >= 0xFF00 && cp <= 0xFF60) ||
        (cp >= 0xFFE0 && cp <= 0xFFE6) ||
        (cp >= 0x1F300 && cp <= 0x1FAFF) ||
        (cp >= 0x20000 && cp <= 0x3FFFD)) {
        return 2;
    }
    return 1;
}

// Length of the codepoint starting at s[i], with its value. Byte-for-byte
// the original NextCp: a lead byte without its continuations is a 1-byte
// stray counting as itself, and a truncated tail never reads past size().
inline size_t DecodeCp(const std::string& s, size_t i, uint32_t* cp) {
    const unsigned char u = static_cast<unsigned char>(s[i]);
    const size_t n = s.size();
    size_t span = 1;
    uint32_t v = u;
    if (u >= 0xF0 && i + 4 <= n) {
        span = 4;
        v = u & 0x07u;
    } else if (u >= 0xE0 && i + 3 <= n) {
        span = 3;
        v = u & 0x0Fu;
    } else if (u >= 0xC0 && i + 2 <= n) {
        span = 2;
        v = u & 0x1Fu;
    } else {
        *cp = u;
        return 1;
    }
    for (size_t k = 1; k < span; ++k) {
        const unsigned char c = static_cast<unsigned char>(s[i + k]);
        if ((c & 0xC0u) != 0x80u) {
            *cp = u;  // malformed: count the lead byte, resync next call
            return 1;
        }
        v = (v << 6) | (c & 0x3Fu);
    }
    *cp = v;
    return span;
}

// Advance over one run of ASCII bytes from 'i', 16 at a time. Returns the
// index of the first non-ASCII byte (or s.size()). Every byte skipped is
// a 1-wide 1-byte codepoint, so the caller adds (out - i) to the width.
inline size_t SkipAscii(const std::string& s, size_t i) {
    const size_t n = s.size();
    const unsigned char* p =
        reinterpret_cast<const unsigned char*>(s.data());
    size_t j = i;
#if defined(WINTCP_HAS_SSE2)
    for (; j + 16 <= n; j += 16) {
        const __m128i chunk =
            _mm_loadu_si128(reinterpret_cast<const __m128i*>(p + j));
        if (_mm_movemask_epi8(chunk) != 0) break;
    }
#endif
    for (; j < n && p[j] < 0x80; ++j) {
    }
    return j;
}

}  // namespace

// CpWidth itself: the original chain, unchanged. Every alternative was
// measured and lost (see the note above), so this is deliberately a copy -
// the candidate's win lives in DisplayWidth / TruncateToWidth, which stop
// calling it per byte.
size_t CpWidthOpt(uint32_t cp) {
    return CpWidthChain(cp);
}

size_t NextCpOpt(const std::string& s, size_t i, uint32_t* cp) {
    return DecodeCp(s, i, cp);
}

size_t DisplayWidthOpt(const std::string& s) {
    const size_t n = s.size();
    size_t w = 0;
    size_t i = 0;
    while (i < n) {
        const size_t j = SkipAscii(s, i);
        w += (j - i);
        i = j;
        if (i >= n) break;
        uint32_t cp = 0;
        const size_t span = DecodeCp(s, i, &cp);
        w += CpWidthOpt(cp);
        i += span;
    }
    return w;
}

std::string TruncateToWidthOpt(const std::string& s, size_t width) {
    if (width == 0) return std::string();

    const size_t n = s.size();
    const size_t budget = width - 1;   // the ellipsis owns the last column
    size_t w = 0;                      // total width over the whole string
    size_t cut = 0;                    // byte index where the budget ran out
    bool cutSet = false;
    size_t i = 0;
    while (i < n) {
        const size_t j = SkipAscii(s, i);
        const size_t run = j - i;
        // Not yet past the budget: the cut lands inside this run.
        if (!cutSet && run > budget - w) {
            cut = i + (budget - w);
            cutSet = true;
        }
        w += run;
        i = j;
        if (i >= n) break;
        uint32_t cp = 0;
        const size_t span = DecodeCp(s, i, &cp);
        const size_t cw = CpWidthOpt(cp);
        if (!cutSet && cw > budget - w) {
            cut = i;
            cutSet = true;
        }
        w += cw;
        i += span;
    }
    if (w <= width) return s;   // whole value fits: unchanged, no marker
    return s.substr(0, cut) + "\xE2\x80\xA6";
}

// ============================================================================
// 27b. GeoIP tree walk: MSB-first shift register, straight-line walkers
// ============================================================================

namespace {

// The three geometry walkers share the loop skeleton; only the record
// extraction differs. Each takes the bit already extracted from the shift
// register. The guard preamble is written once in ResolveOffsetShiftOpt and
// the same invariants hold, so no walker re-checks them.

// 24-bit records (nodeByteSize 6): the node holds two 3-byte big-endian
// records. Two overlapping 4-byte loads cover the node exactly (the second
// starts two bytes in, so it also lands inside the node) and each half is
// a shift or a mask off its own word - no byte-by-byte OR chain.
inline size_t Record24(const unsigned char* treeBase, size_t recPos,
                       unsigned bit) {
    uint32_t be0 = 0;
    uint32_t be1 = 0;
    std::memcpy(&be0, treeBase + recPos, sizeof(be0));        // p[0..3]
    std::memcpy(&be1, treeBase + recPos + 2, sizeof(be1));    // p[2..5]
    be0 = _byteswap_ulong(be0);
    be1 = _byteswap_ulong(be1);
    // left  = p[0]<<16 | p[1]<<8 | p[2]
    // right = p[3]<<16 | p[4]<<8 | p[5]
    return (bit == 0) ? static_cast<size_t>(be0 >> 8)
                      : static_cast<size_t>(be1 & 0x00FFFFFFu);
}

// 32-bit records (nodeByteSize 8): two independent 4-byte big-endian
// records, so the half is a select between the two halves of the node.
inline size_t Record32(const unsigned char* treeBase, size_t recPos,
                       unsigned bit) {
    uint32_t lo = 0;
    uint32_t hi = 0;
    std::memcpy(&lo, treeBase + recPos, sizeof(lo));
    std::memcpy(&hi, treeBase + recPos + 4, sizeof(hi));
    return static_cast<size_t>(bit == 0 ? _byteswap_ulong(lo)
                                        : _byteswap_ulong(hi));
}

// 28-bit records (nodeByteSize 7): packed, two records share the middle
// byte. The record IS the node here, so this one stays byte arithmetic.
inline size_t Record28(const unsigned char* treeBase, size_t recPos,
                       unsigned bit) {
    const unsigned char* p = treeBase + recPos;
    if (bit == 0) {
        return (static_cast<size_t>(p[3] >> 4) << 24) |
               (static_cast<size_t>(p[0]) << 16) |
               (static_cast<size_t>(p[1]) << 8) | static_cast<size_t>(p[2]);
    }
    return (static_cast<size_t>(p[3] & 0x0Fu) << 24) |
           (static_cast<size_t>(p[4]) << 16) |
           (static_cast<size_t>(p[5]) << 8) | static_cast<size_t>(p[6]);
}

// The shared tail of every walk step: a record is a node number, an
// explicit "no data" marker, or a data-section pointer. The boundary is
// >= nodeCount + separator, not >, because nodeCount + 16 is EXACTLY data
// offset 0 and offset 0 is a real record (GeoIp.cpp:1029-1034). It is
// spelled out inline in ResolveOffsetShiftOpt so the "found" case can
// return instead of threading a flag through three walkers.

}  // namespace

bool ResolveOffsetShiftOpt(const unsigned char bits[16], unsigned bitCount,
                           size_t startNode, size_t nodeCount,
                           size_t nodeByteSize, bool record28,
                           size_t recordBytes,
                           const unsigned char* treeBase,
                           size_t dataSectionSize, size_t kSeparatorLen,
                           size_t* out) {
    if (bits == nullptr || treeBase == nullptr || out == nullptr) return false;
    if (nodeCount == 0 || nodeByteSize == 0) return false;
    if (dataSectionSize == 0) return false;   // mirrors Loaded()
    if (!record28 && recordBytes != 3 && recordBytes != 4) return false;
    if (bitCount == 0 || bitCount > 128) return false;
    if (kSeparatorLen > (std::numeric_limits<size_t>::max)() - nodeCount) {
        return false;
    }
    if (nodeCount > (std::numeric_limits<size_t>::max)() / nodeByteSize) {
        return false;
    }

    // Address bits as two big-endian words. Byte 0 of 'bits' is the FIRST
    // bit the original consumes, and its MSB is depth 0 (GeoIp.cpp:1017),
    // which is exactly what >> 63 on the byte-swapped word gives.
    uint64_t w0 = 0;
    uint64_t w1 = 0;
    std::memcpy(&w0, bits, 8);
    std::memcpy(&w1, bits + 8, 8);
    w0 = _byteswap_uint64(w0);
    w1 = _byteswap_uint64(w1);

    const size_t nodeCountSz = nodeCount;
    const size_t treeBytes = nodeCount * nodeByteSize;
    const size_t dataThreshold = nodeCountSz + kSeparatorLen;

    size_t node = startNode;
    uint64_t w = w0;
    unsigned leftInWord = 64;

    for (unsigned depth = 0; depth < bitCount; ++depth) {
        const unsigned bit = static_cast<unsigned>(w >> 63);
        w <<= 1;
        if (--leftInWord == 0 && depth + 1 < bitCount) {
            w = w1;                     // bits 64..127
            leftInWord = 64;
        }

        if (node >= nodeCountSz) return false;
        const size_t recPos = node * nodeByteSize;
        if (recPos + nodeByteSize > treeBytes) return false;

        size_t record = 0;
        if (record28) {
            record = Record28(treeBase, recPos, bit);
        } else if (recordBytes == 4) {
            record = Record32(treeBase, recPos, bit);
        } else {
            record = Record24(treeBase, recPos, bit);
        }

        // Inline of ApplyRecord so the found/refuse distinction is a return.
        if (record < nodeCountSz) {
            node = record;
            continue;
        }
        if (record >= dataThreshold) {
            const size_t offset = record - nodeCountSz - kSeparatorLen;
            if (offset >= dataSectionSize) return false;
            *out = offset;
            return true;
        }
        return false;
    }

    return false;
}

// ============================================================================
// 34. MMDB payload size + pointer read (GeoIp.cpp:422-442, 492-511)
// ============================================================================

namespace {

// One entry per value of the low five control bits (ctrl & 0x1F) for the
// EXTENDED codes 29..31 only - the inline codes 0..28 never touch a table,
// which is where the original's branch order belongs anyway (a 32-entry
// load measured 0.78x against the original's first-compare exit).
struct MmdbSizeEntry {
    uint8_t extra;
    uint32_t base;
};
struct MmdbSizeTable {
    MmdbSizeEntry e[3];   // indexed by (code - 29)
    constexpr MmdbSizeTable() : e{} {
        // 29: the next byte, plus 29.
        e[0].extra = 1;
        e[0].base = 29;
        // 30: 285 plus the next 2 bytes.
        e[1].extra = 2;
        e[1].base = 285;
        // 31: 65821 plus the next 3 bytes.
        e[2].extra = 3;
        e[2].base = 65821;
    }
};
constexpr MmdbSizeTable kMmdbSize;

// Big-endian read of 1..4 bytes, for the case where 4 bytes are NOT
// provably readable. A local inline (internal linkage) so it always
// inlines; the cross-TU ReadBytesOpt did NOT inline and cost 0.69x on its
// own. n is 1..4 by construction at both call sites.
inline uint64_t ReadBeN(const unsigned char* p, size_t n) {
    uint64_t v = 0;
    for (size_t i = 0; i < n; ++i) v = (v << 8) | p[i];
    return v;
}

// Big-endian read of exactly 4 bytes: one unaligned load + BSWAP. The
// caller has already established that 4 bytes are readable, and a switch
// over 1..4 compiled to a jump table (0.79x - the indirect jump
// mispredicts), so the width becomes a SHIFT of this value instead.
inline uint64_t ReadBe4(const unsigned char* p) {
    uint32_t be = 0;
    std::memcpy(&be, p, sizeof(be));
    return static_cast<uint64_t>(_byteswap_ulong(be));
}

}  // namespace

bool PayloadSizeOpt(const unsigned char* data, size_t size, unsigned char ctrl,
                    size_t pos, MmdbPayload* out) {
    const uint32_t s = ctrl & 0x1Fu;
    // Codes 0..28 are the payload value itself: no bytes read, no table.
    // This is the hot case and must stay one compare deep.
    if (s < 29) {
        out->size = s;
        out->pos = pos;
        return true;
    }
    // 29/30/31. Same bound check as the original, before the wide load.
    const MmdbSizeEntry& e = kMmdbSize.e[s - 29];
    if (pos + e.extra > size) return false;
    out->size =
        e.base + static_cast<uint32_t>(ReadBeN(data + pos, e.extra));
    out->pos = pos + e.extra;
    return true;
}

bool ReadPointerOpt(const unsigned char* data, size_t size,
                    unsigned char ctrl, size_t pos, size_t* out) {
    // kPtrSizeShift 3 / kPtrSizeMask 0x3 (GeoIp.cpp:53-54).
    const unsigned psize = (ctrl >> 3) & 0x3u;
    const size_t payload = static_cast<size_t>(psize) + 1;

    // The value is the top 'payload' bytes of a big-endian window at
    // 'pos', so when 4 bytes are safely readable one load + BSWAP + a
    // shift produces it - no loop, no width switch, no jump table.
    // The original's "payload bytes" bound is preserved exactly: nothing
    // past pos + payload is ever *used*, only read, and only when in
    // range.
    uint64_t v;
    if (pos + 4 <= size) {
        v = ReadBe4(data + pos) >> (32 - 8 * payload);
    } else if (pos + payload <= size) {
        v = ReadBeN(data + pos, payload);
    } else {
        return false;
    }

    if (psize != 3) {
        // The control byte's three bits go on top of the payload; they are
        // the value's MOST significant bits.
        v |= (static_cast<uint64_t>(ctrl) & 0x7u) << (8 * payload);
        // kPtr2Base 2048 (size 1), kPtr3Base 526336 (size 2). Immediates
        // beat a bases table: the load measured 0.78x.
        if (psize == 1) v += 2048;
        else if (psize == 2) v += 526336;
    }

    *out = static_cast<size_t>(v);
    return true;
}

// ============================================================================
// 35. VLAN skip + flow-record probe (Pcapng.cpp:119-129, 354-361)
// ============================================================================

namespace {

// Pcapng.cpp:87-88.
constexpr size_t kFlowScanFirstOffset = 12;
constexpr size_t kFlowScanLastOffset = 40;

}  // namespace

size_t SkipVlanOpt(const unsigned char* p, size_t len, size_t off) {
    while (off + 4 <= len) {
        uint16_t t = 0;
        std::memcpy(&t, p + off, sizeof(t));
        t = _byteswap_ushort(t);
        // Short-circuit order unchanged: the common case (not a tag) exits
        // on the first compare, exactly like the original.
        if (t != 0x8100 && t != 0x88A8 && t != 0x9100) break;
        off += 4;
    }
    return off + 2;   // past the ethertype that terminates the chain
}

bool FlowProbeOpt(const unsigned char* pkt, size_t capLen) {
    if (pkt == nullptr) return false;
    // The candidates are the EVEN offsets 12, 14, ... 38 (stride 2) and the
    // original admits one only when k + 5 <= capLen. The SIMD block below
    // needs k + 20: five bytes for the highest candidate in the block plus
    // the two bytes its triple reads past that.
    size_t k = kFlowScanFirstOffset;
#if defined(WINTCP_HAS_SSE2)
    // The block covers lanes 0..15 of 'k', i.e. candidates k, k+2 ... k+14.
    // Both ends must hold: the highest candidate needs k+14+5 <= capLen (and
    // the loads read up to k+17), and it must still be INSIDE the scan
    // window, so k+16 <= kFlowScanLastOffset. Anything left over is the
    // scalar tail, which re-applies the original bound exactly.
    for (; k + 20 <= capLen && k + 16 <= kFlowScanLastOffset; k += 16) {
        const __m128i a =
            _mm_loadu_si128(reinterpret_cast<const __m128i*>(pkt + k));
        const __m128i b1 =
            _mm_loadu_si128(reinterpret_cast<const __m128i*>(pkt + k + 1));
        const __m128i b2 =
            _mm_loadu_si128(reinterpret_cast<const __m128i*>(pkt + k + 2));
        // Lane j of 'pair' says candidate k+j starts (0x08 0x00).
        const __m128i pair = _mm_and_si128(
            _mm_cmpeq_epi8(a, _mm_set1_epi8(0x08)),
            _mm_cmpeq_epi8(b1, _mm_setzero_si128()));
        // Lane j of 'ver' says the byte two past k+j has version nibble 4.
        // (b >> 4) == 4  <=>  (b & 0xF0) == 0x40
        const __m128i ver = _mm_cmpeq_epi8(
            _mm_and_si128(b2, _mm_set1_epi8(static_cast<char>(0xF0))),
            _mm_set1_epi8(0x40));
        // Lane j of 'pair' already reads bytes k+j and k+j+1, and lane j
        // of 'ver' already reads the byte at k+j+2 (b2 is loaded two bytes
        // in), so the two line up candidate-by-candidate with NO lane
        // shift. Shifting 'ver' as well double-counts the stride and loses
        // every candidate - caught by the differential sweep.
        const __m128i hit = _mm_and_si128(pair, ver);
        // Stride 2: only even byte lanes are real candidates.
        if ((_mm_movemask_epi8(hit) & 0x5555) != 0) return true;
    }
#endif
    // Scalar tail (also the whole answer when capLen is short, so nothing
    // past capLen is ever read).
    for (; k + 5 <= capLen && k < kFlowScanLastOffset; k += 2) {
        if (pkt[k] == 0x08 && pkt[k + 1] == 0x00 &&
            (pkt[k + 2] >> 4) == 4) {
            return true;
        }
    }
    return false;
}

// ============================================================================
// 36. TCP reassembly render (TcpReasm.cpp:162-194 Direction::Render)
// ============================================================================

namespace {

// The rewrites that were tried and rejected, kept out of the build but
// documented so the numbers are reproducible. See RenderSegmentsOpt.
//
// A 4-pass 16-bit LSD radix sort: 65536-entry histograms, 0.02x at 96
// segments and 0.67x at 4096. The digit width, not a threshold, was the
// problem - the histogram costs more than n log n until n is in the tens of
// thousands, which a single stream never reaches.
//
// A packed {seq, index} key fed to std::sort: removes two pointer chases
// per compare but adds 12 bytes of traffic per element, 0.60x .. 0.85x.
//
// resize(bytes_) instead of reserve(): value-initialises the whole buffer,
// so it adds a full zero pass over the stream for nothing, 0.73x .. 0.93x.
//
// An already-in-order fast path: the O(n) check costs as much as the sort
// it avoids below ~4000 segments, 0.80x .. 0.87x.

}  // namespace

void RenderSegmentsOpt(const ReasmRenderView& w, size_t duplicates,
                       bool truncated, ReasmRenderResult* out) {
    // MEASURED CONCLUSION, not an oversight: this is the original's
    // algorithm, deliberately. Four rewrites were benchmarked against it
    // and all of them lost or tied, because the render is dominated by the
    // byte copy, which is memory-bandwidth bound and identical either way:
    //
    //   4-pass 16-bit LSD radix sort      0.02x (96 segs) .. 0.67x (4096)
    //   packed {seq,index} + std::sort   0.60x .. 0.85x
    //   packed {seq,index} + resize()    0.73x .. 0.93x
    //   + already-in-order fast path      0.80x .. 0.87x
    //
    // The radix sort's 65536-entry histogram costs more than n log n until
    // n is in the tens of thousands, which a single stream is never. The
    // packed key removes two pointer chases per compare but adds 12 bytes
    // of traffic per element, which is a net loss at these sizes. resize()
    // over reserve() adds a full zero pass over the stream. The in-order
    // fast path cannot help because the check itself costs as much as the
    // sort it avoids at n < 4000.
    //
    // Kept as an entry so the harness carries the evidence and the report
    // can say "do not touch this function" rather than staying silent.
    out->bytes.clear();
    out->bytesMissing = 0;
    out->hasGap = false;
    out->firstSeq = 0;
    out->segments = w.seqs.size();
    out->duplicates = duplicates;
    out->truncated = truncated;
    if (w.seqs.empty()) return;

    const size_t n = w.seqs.size();
    std::vector<uint32_t> order(n);
    for (size_t i = 0; i < n; ++i) order[i] = static_cast<uint32_t>(i);
    std::sort(order.begin(), order.end(), [&w](uint32_t a, uint32_t b) {
        return w.seqs[a] < w.seqs[b];
    });

    out->firstSeq = w.seqs[order[0]];
    size_t total = 0;
    for (size_t i = 0; i < n; ++i) total += w.sizes[order[i]];
    out->bytes.reserve(total);

    for (size_t i = 0; i < n; ++i) {
        const uint32_t s = order[i];
        if (i > 0) {
            const uint32_t p = order[i - 1];
            const uint64_t prevEnd = w.seqs[p] + w.sizes[p];
            const uint64_t curStart = w.seqs[s];
            if (curStart > prevEnd) {
                out->bytesMissing += static_cast<size_t>(curStart - prevEnd);
                out->hasGap = true;
            }
        }
        const size_t sz = w.sizes[s];
        if (sz != 0) {
            out->bytes.insert(out->bytes.end(),
                              w.pool.begin() +
                                  static_cast<ptrdiff_t>(w.starts[s]),
                              w.pool.begin() +
                                  static_cast<ptrdiff_t>(w.starts[s] + sz));
        }
    }
}

// ============================================================================
// 37. PID dedup + per-PID grouping (Snapshot.cpp:37-45, ConnectionStore.cpp:1599)
// ============================================================================

namespace {

// Power-of-two open-addressing table. Slots hold 0 when empty and
// kOccupied | pid when taken, so pid 0 and 0xFFFFFFFF are ordinary keys.
constexpr uint64_t kOccupied = 1ull << 32;

inline size_t PidSlot(uint32_t pid, size_t mask) {
    // Fibonacci hash: sequential PIDs spread instead of forming one run.
    return static_cast<size_t>(
               (static_cast<uint64_t>(pid) * 0x9E3779B97F4A7C15ull) >> 32) &
           mask;
}

size_t TableCapacityFor(size_t n) {
    size_t cap = 16;
    while (cap < n * 2 + 1) cap <<= 1;
    return cap;
}

}  // namespace

template <typename Pid>
std::vector<Pid> DistinctPidsOpt(const Pid* pids, size_t n) {
    std::vector<Pid> out;
    if (pids == nullptr || n == 0) return out;
    // Same reservation policy as the original, so the caller's sizing
    // behaviour is unchanged; the table is extra scratch.
    out.reserve(n);

    const size_t cap = TableCapacityFor(n);
    const size_t mask = cap - 1;
    std::vector<uint64_t> table(cap, 0);
    for (size_t i = 0; i < n; ++i) {
        const Pid pid = pids[i];
        const uint32_t p = static_cast<uint32_t>(pid);
        size_t j = PidSlot(p, mask);
        for (;;) {
            const uint64_t v = table[j];
            if (v == 0) {
                table[j] = kOccupied | p;
                out.push_back(pid);
                break;
            }
            if (v == (kOccupied | p)) break;   // already seen
            j = (j + 1) & mask;
        }
    }
    return out;
}

// Explicit instantiations: the product passes DWORD, the bench passes
// uint32_t. Both are 32 bits, so the table's bit-32 tag stays valid.
template std::vector<uint32_t> DistinctPidsOpt<uint32_t>(
    const uint32_t* pids, size_t n);
template std::vector<unsigned long> DistinctPidsOpt<unsigned long>(
    const unsigned long* pids, size_t n);

PidGroups GroupByPidOpt(const uint32_t* pids, size_t n) {
    PidGroups g;
    if (pids == nullptr || n == 0) return g;
    const size_t cap = TableCapacityFor(n);
    const size_t mask = cap - 1;
    // slot -> index into g.pids; empty slots hold kNoSlot.
    constexpr size_t kNoSlot = static_cast<size_t>(-1);
    std::vector<uint64_t> table(cap, 0);
    std::vector<size_t> slotOf(cap, kNoSlot);
    for (size_t i = 0; i < n; ++i) {
        const uint32_t p = pids[i];
        size_t j = PidSlot(p, mask);
        for (;;) {
            if (table[j] == 0) {
                table[j] = kOccupied | p;
                slotOf[j] = g.pids.size();
                g.pids.push_back(p);
                g.rows.emplace_back();
                break;
            }
            if (table[j] == (kOccupied | p)) break;
            j = (j + 1) & mask;
        }
        g.rows[slotOf[j]].push_back(i);
    }
    return g;
}

} // namespace wintcp
