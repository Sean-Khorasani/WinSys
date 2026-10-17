// Opt.h
// SPDX-License-Identifier: Apache-2.0
// Optimized drop-in implementations for the hot paths in wintcp.
//
// Every function here has the SAME signature and semantics as the original
// it replaces, and is measured against a copy of that original by the A/B
// bench in wintcp/tests/asm (see its documentation for the per-
// candidate results). Only the functions that measured FASTER are wired
// into the product; the ones that measured slower are kept here purely as
// evidence and are not called from anywhere.
//
// Implementations use MSVC compiler intrinsics, which generate optimal
// assembly including SSE2, BSWAP and POPCNT. SSE2 is part of the x64
// baseline (Windows has required it since Vista), so none of it needs a
// CPU guard; anything above SSE2 would need __cpuid gating and a scalar
// fallback, which is why none of it is used.
//
// The bench and the product share THIS ONE COPY of the code, so a number
// measured by the bench is the number the product gets.

#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace wintcp {

// ---- 1. GeoIP tree walk optimization ----
// Original: ResolveOffset (GeoIp.cpp:1002) does a bit-by-bit tree walk.
//
// Optimization: bit-test arithmetic (shift/mask instead of division and
// modulo per bit) with inlined node-record extraction for 24/28/32-bit
// records. NOTE: the 32-bit path selects the half (bit * 4); GeoIp.cpp:977
// reads recPos for both halves, so this intentionally fixes that bug.
bool ResolveOffsetOpt(const unsigned char bits[16], unsigned bitCount,
                      size_t startNode, size_t nodeCount,
                      size_t nodeByteSize, bool record28, size_t recordBytes,
                      const unsigned char* treeBase,
                      size_t dataSectionSize, size_t kSeparatorLen,
                      size_t* out);

// ---- 2. TCP reassembly segment overlap (Direction::Add inner loop) ----
// Original: TcpReasm.cpp:115-146 does two linear scans per segment.
//
// Optimization: scalar two-pass scan faithful to Direction::Add
// (the store is unsorted capture order), with an overflow-safe
// head-overlap test and null guards the original lacks.
bool AddSegmentOverlapOpt(uint64_t seq, size_t len,
                          const uint64_t* segSeqs, const size_t* segSizes,
                          size_t segCount, size_t* consumed, size_t* skip);

// ---- 3. Filter matching substring search ----
// Original: ConnectionStore.cpp uses std::wstring::find for substring matching.
//
// Optimization: SSE2 scan of 8 wchar_t at a time for the needle's first
// character, with exact memcmp verification per candidate. Bit-identical
// to wstring::find on valid inputs.
bool HasLowerSubstringOpt(const wchar_t* haystack, size_t hayLen,
                          const wchar_t* needle, size_t needleLen);

// ---- 4. Packet parsing (IP/TCP header extraction) ----
// Original: Pcapng.cpp bytes read individually with endian conversion.
//
// Optimization: Use SIMD loads to read entire headers in one instruction,
// BSWAP for endian conversion, and bit-field extraction.
void ParseTcpHeaderOpt(const unsigned char* p,
                       uint16_t* srcPort, uint16_t* dstPort,
                       uint32_t* seq, uint32_t* ack,
                       uint8_t* tcpFlags, uint16_t* window,
                       const unsigned char** payload, size_t* payloadLen,
                       size_t tcpOff, size_t end);

// ---- 5. FormatBytes (integer to string) ----
// Original: Utils.cpp:192 uses floating-point division + swprintf_s.
//
// Optimization: integer-only digit encoding for the bytes case; the
// KB/MB/GB/TB cases keep the original's format policy (%.1f KB/MB,
// %.2f GB/TB) but render into a stack buffer first so a short caller
// buffer truncates quietly instead of tripping the CRT handler.
size_t FormatBytesOpt(wchar_t* buf, size_t bufSize, uint64_t bytes);

// ---- 6. Connection key building (KeyOf) ----
// Original: ConnectionStore.cpp:358 uses multiple memcpy calls into a buffer.
//
// Optimization: direct memcpy stores without the push lambda
// (ports/pid as single 4-byte native-endian stores, byte-identical to
// the original on little-endian x64).
// IPv4 keys are 22 bytes, IPv6 keys 46; the caller provides the buffer.
void KeyOfOpt(bool ipv6, bool udp,
              const unsigned char* localAddr, uint32_t localPort,
              const unsigned char* remoteAddr, uint32_t remotePort,
              uint32_t pid,
              unsigned char* outBytes, size_t* outLen);

// ---- 7. WideToUtf8 conversion ----
// Original: Utils.cpp:94 calls WideCharToMultiByte twice.
//
// Optimization: single-pass conversion with an SSE2 8-wide ASCII fast
// path; unpaired surrogates encode as U+FFFD. Truncation stops before a
// character that would not fit (never splits a UTF-8 sequence).
size_t WideToUtf8Opt(const wchar_t* src, size_t srcLen,
                     char* dst, size_t dstSize);

// ---- 8. Stream hexdump (FormatStreamHex inner loops) ----
// Original: StreamCapture.cpp:578 FormatStreamHex.
//
// Optimization: hex-digit LUT + direct stores instead of one snprintf
// per byte (~35 snprintf calls per output line); branchless ASCII
// gutter. Byte-identical output; clamping and reserve policy unchanged.
std::string FormatStreamHexOpt(const std::string& bytes, size_t bytesPerLine);

// ---- 9. Wide lowercase (ToLowerW) ----
// Original: Utils.cpp:105 ToLowerW.
//
// Optimization: SSE2 8-wide ASCII fold (range mask +32); any 8-block
// containing non-ASCII falls back to towlower lane by lane. Length-based
// (embedded NULs preserved); surrogate halves never folded.
std::wstring ToLowerWOpt(const std::wstring& s);

// ---- 10. GeoIP big-endian field reads ----
// Original: GeoIp.cpp:124-139 ReadU32BE/ReadU64BE/ReadBytes.
//
// Optimization: unaligned memcpy + BSWAP instead of shift/OR chains
// (single mov + bswap). Bit-identical for n = 0..8; n > 8 is refused
// (the original shifts mod 2^64; no caller does this).
uint32_t ReadU32BEOpt(const unsigned char* p);
uint64_t ReadU64BEOpt(const unsigned char* p);
bool ReadBytesOpt(const unsigned char* p, size_t n, uint64_t* out);

// ---- 11. TLS big-endian field reads ----
// Original: TlsDecode.cpp:23-36 Be16/Be24/Be32.
//
// Optimization: unaligned memcpy + BSWAP (Be24 = 3-byte load, bswap,
// shift). Null returns 0.
uint16_t TlsBe16Opt(const unsigned char* p);
uint32_t TlsBe24Opt(const unsigned char* p);
uint32_t TlsBe32Opt(const unsigned char* p);

// ---- 12. TLS extension dispatch + SNI tail strip ----
// Original: TlsDecode.cpp:227-266 ParseClientHelloExtensions.
//
// Optimization: extension-type classify via 17-entry LUT (only 0x0000
// SNI and 0x0010 ALPN are handled); trailing NUL/dot strip via SSE2
// 16-byte tail scan with a scalar finish.
enum class TlsExtAction : unsigned char { kSkip = 0, kSni = 1, kAlpn = 2 };
TlsExtAction ClassifyTlsExtensionOpt(uint16_t type);
size_t StripSniTailOpt(char* s, size_t n);

// ---- 13. Pcap endian loads ----
// Original: Pcapng.cpp:90-105 Rd16/Rd32.
//
// Optimization: unaligned memcpy + conditional BSWAP (single mov,
// bswap iff swap). Null returns 0.
uint16_t Rd16Opt(const unsigned char* p, bool swap);
uint32_t Rd32Opt(const unsigned char* p, bool swap);

// ---- 14. Socket-sample join (ApplySocketBytes match kernel) ----
// Original: ConnectionStore.cpp:1888-1912 ApplySocketBytes (same kernel
// as ApplySocketTcpInfo :1927-1972 and ApplyKernelAges :1977-2006).
//
// Optimization: hash index over rows (key = ports + addresses),
// consumed as FIFO queues per key - identical first-match-wins
// assignment as the linear scan, O(R+S) instead of O(R*S).
struct JoinRow {
    uint32_t localPort = 0;
    uint32_t remotePort = 0;
    std::wstring local;
    std::wstring remote;
    bool tcp = true;
    uint64_t rx = 0;
    uint64_t tx = 0;
    bool perRow = false;
};
struct JoinSample {
    uint32_t localPort = 0;
    uint32_t remotePort = 0;
    std::wstring local;
    std::wstring remote;
    uint64_t rx = 0;
    uint64_t tx = 0;
    bool known = true;
};
int JoinSamplesOpt(std::vector<JoinRow>& rows,
                   const std::vector<JoinSample>& samples);

// ---- 15. Long-needle substring (Boyer-Moore-Horspool) ----
// Original: ConnectionStore.cpp:87-89 Has (wstring::find), the match
// kernel shared by MatchClause :899-1239 and AlertRule::Matches.
//
// Optimization: BMH with a 256-entry low-byte shift table (minimum
// shift per bucket - always conservative, never skips a match).
// Sublinear on long haystacks; complements the SSE2 short-needle scan.
bool FindSubstringLongOpt(const std::wstring& haystack,
                          const std::wstring& needle);

// ---- 16. Lower-all concat (RebuildLowerAll) ----
// Original: ConnectionStore.cpp:93-98 RebuildLowerAll (9-temporary
// + chain over 10 fields).
//
// Optimization: single reserve + in-place appends over the same fixed
// 10 fields. Same field order, same single-space separators.
std::wstring BuildLowerAllOpt(const std::wstring* const* fields, size_t count);

// ---- 17. Wide string compare ----
// Original: std::wstring::compare as used by ConnectionStore.cpp:2284
// CompareRows (CmpStr arms) and the tie-breaker chain.
//
// Optimization: SSE2 8-wide lane compare + movemask first-diff;
// length decides prefix ties. Same sign contract as traits::compare.
int CompareWideOpt(const wchar_t* a, size_t na, const wchar_t* b,
                   size_t nb);

// ---- 18. Connection-key hash + equality ----
// Original: ConnectionStore.h:255-268 ConnectionKey::operator==
// (len + memcmp) and ConnectionKeyHash (std::hash<string_view>).
//
// Optimization: FNV-1a over 64-bit lanes for the hash; SSE2 16-byte
// blocks + memcmp tail for equality. Hash VALUES differ from std::
// (distribution only matters); equality is bit-identical.
size_t HashConnKeyOpt(const unsigned char* bytes, size_t len);
bool EqualConnKeyOpt(const unsigned char* a, size_t na,
                     const unsigned char* b, size_t nb);

// ---- 19. Batch rate computation ----
// Original: ConnectionStore.cpp:686-703 ComputeBps, called per row
// (and per group row) in ComputeRates :1477-1512 / ComputeGroupRates
// :1543-1597.
//
// Optimization: uniform-elapsed batch - one reciprocal per call
// instead of one divide per counter. Callers pass rows sharing nowTick;
// rows with divergent ticks use the scalar path (still main-tree work).
size_t ComputeBpsBatchOpt(const uint64_t* prevBytes,
                          const uint64_t* nowBytes, uint64_t elapsedMs,
                          double* outBps, size_t n);

// ---- 20. Per-PID traffic sums ----
// Original: ConnectionStore.cpp:1543-1597 ComputeGroupRates first pass
// (two std::map<DWORD,...>, O(log P) per row).
//
// Optimization: sort row indexes by PID once, then linear runs with
// saturating adds. Every row of a PID receives the sums iff any of its
// rows was counted - identical to the map version.
struct PidTrafficRow {
    uint32_t pid = 0;
    bool counted = false;
    uint64_t rx = 0;
    uint64_t tx = 0;
    uint64_t sumRx = 0;
    uint64_t sumTx = 0;
    bool hasSum = false;
};
void SumPidTrafficOpt(PidTrafficRow* rows, size_t n);

// ---- 21. Rate cell formatting ----
// Original: ConnectionStore.cpp:554-565 FormatBpsCell ("-", "idle", or
// "down x/s  up y/s" via two FormatBytes + swprintf_s).
//
// Optimization: the two numbers render through FormatBytesOpt into
// stack buffers, spliced with constant arrows - no format-string
// parse. Same sentinels, same truncation contract (0 + empty).
size_t FormatBpsCellOpt(wchar_t* buf, size_t bufSize, double rxBps,
                        double txBps, bool known);

// ---- 22. MMDB UTF-8 widen ----
// Original: GeoIp.cpp:541-572 AppendUtf8 (+ Widen :574-579 reserve).
//
// Optimization: SSE2 16-byte ASCII bulk append (sign-bit movemask);
// first high-bit byte (or short tail) runs the verbatim scalar loop
// (overlong/surrogate/4-byte -> U+FFFD on untrusted bytes).
std::wstring WidenUtf8Opt(const unsigned char* p, size_t n);

// ---- 23. Unicast classification ----
// Original: GeoIp.cpp:1243-1309 IsGlobalUnicastV4/V6.
//
// Optimization: V4 first-octet action table (one load + computed
// switch instead of a 10-compare chain; sub-expressions verbatim).
// V6 keeps the prefix tests and replaces both 14-byte tailZero loops
// with two overlapping u64 loads ORed together.
bool IsGlobalUnicastV4Opt(uint32_t a);
bool IsGlobalUnicastV6Opt(const unsigned char a[16]);

// ---- 24. Snapshot pairing (hash + FIFO, fast hash) ----
// Original: ConnectionStore.cpp:1304-1326 ReplaceSnapshot PrevKeyIndex
// (unordered_map key -> FIFO queue, backwards build + pop_back).
//
// Optimization: same algorithm, faster key hash (FNV-1a lanes
// instead of std::hash<string_view>) + reserve. A sort-merge
// variant was measured 2.4-3x SLOWER at these sizes (short keys hash
// in ~2 lanes; sort pays O(n log n) full-key compares) and removed.
// out[i] = previous index or -1.
struct SnapKey {
    unsigned char bytes[46];
    size_t len = 0;

    bool operator==(const SnapKey& o) const {
        return len == o.len && std::memcmp(bytes, o.bytes, len) == 0;
    }
};
int PairSnapshotOpt(const SnapKey* prev, size_t nPrev,
                    const SnapKey* fresh, size_t nFresh, int* out);

// ---- 25. Counted-key linear find ----
// Original: GeoIp.cpp:519-535 MapFind per-entry step (length check +
// memcmp over the key bytes; strlen/Decode scaffolding excluded).
//
// Optimization: length-first reject plus a u64 first-8-bytes
// prefilter when both sides hold 8 bytes; memcmp decides.
struct CountedKey {
    const unsigned char* p;
    size_t n;
};
int FindCountedKeyOpt(const CountedKey* keys, size_t nKeys,
                      const unsigned char* want, size_t wantLen);

// ---- 26. Flow-key equality + address compare ----
// Original: TcpReasm.cpp:52 CmpAddr (16-byte memcmp) and :224-228
// TcpKey::operator== (ports first, then two 16-byte memcmps), the
// per-packet filter of ReassembleStream :277-307 (two passes).
//
// Optimization: ports-first cheap reject kept; addresses compare as
// single SSE2 registers (cmpeq + movemask); CmpFlowAddr finds the
// first differing byte via bit-scan (unsigned-byte order = memcmp).
struct FlowKey {
    unsigned char addrA[16];
    unsigned char addrB[16];
    uint16_t portA = 0;
    uint16_t portB = 0;
};
bool FlowKeyEqualOpt(const FlowKey& a, const FlowKey& b);
int CmpFlowAddrOpt(const unsigned char* a, const unsigned char* b);

// ---- 27. Handle-table filter (phase-1 scan) ----
// Original: SocketTraffic.cpp:973-1012 ScanHandles phase 1 (want +
// socketTypes + skip probes per handle-table entry).
//
// Optimization: sorted arrays + binary search instead of
// unordered_set + std::set per entry. wantPids/wantTypes/skip must
// arrive sorted (the caller snapshots them once per pass, as the
// original snapshots skip under the lock). Returns accepted count;
// accepted entry indexes go to outIdx (up to outCap).
struct HandleEntry {
    uint64_t srcPid;  // UniqueProcessId; >MAXDWORD entries are skipped
    uint32_t typeIndex;
    uint64_t handle;
};
struct PidHandle {
    uint32_t pid;
    uint64_t handle;

    bool operator<(const PidHandle& o) const {
        return (pid != o.pid) ? (pid < o.pid) : (handle < o.handle);
    }
    bool operator==(const PidHandle& o) const {
        return pid == o.pid && handle == o.handle;
    }
};
size_t FilterHandlesOpt(const HandleEntry* entries, size_t n,
                        const uint32_t* wantPids, size_t nPids,
                        const uint32_t* wantTypes, size_t nTypes,
                        bool typesKnown, const PidHandle* skip,
                        size_t nSkip, size_t* outIdx, size_t outCap);

// ---- 28. ETW event classifier + payload ----
// Original: EtwTraffic.cpp:260-293 ClassifyNetworkEvent (GUID +
// opcode/id chain) and ParseTrafficPayload (PID @0, size @4).
//
// Optimization: u64 GUID discriminator (3 loads + 2 compares reject
// every foreign provider) with memcmp verify; 32-entry opcode table
// (one load + one compare, no branch chain); single u64 payload
// load. Opcode 18 stays excluded (no double-counted receives).
enum class TrafficDir : unsigned char { kNone = 0, kSent = 1, kReceived = 2 };
TrafficDir ClassifyEventOpt(const unsigned char guid[16], uint16_t id,
                            uint16_t opcode);
bool ParseEventPayloadOpt(const void* data, size_t length, uint32_t* pid,
                          uint32_t* size);

// ---- 29. JSON string escape ----
// Original: Commands.cpp:62-85 JsonEscapeA (WideToUtf8, then per-byte
// switch with sprintf_s "\\u%04x" per control char).
//
// Optimization: UTF-8 through the SSE2 ASCII path (WideToUtf8Opt),
// then an SSE2 special scan (", \, <0x20 with high bytes excluded)
// with span memcpy; \u00XX via hex digits. Control chars below 0x20
// emit identical 6-char sequences; UTF-8 continuations pass through.
std::string JsonEscapeOpt(const std::wstring& s);

// ---- 30. CSV field escape ----
// Original: Utils.cpp:185-197 CsvEscapeUtf8 (and ChartExport.cpp:228
// QuoteNarrow, byte-identical clone).
//
// Optimization: keep the find_first_of no-quote fast path; replace
// the per-char build loop with an SSE2 quote scan + span copies.
// Empty stays empty (never ""), quotes double, reserve policy kept.
std::string CsvEscapeOpt(const std::string& field);

// ---- 31. Small-integer formatting ----
// Original: Utils.cpp:199-203 FormatPort (%u), ChartExport.cpp:171-181
// FormatU64 (wide roundtrip), ConnectionStore.cpp:530-549
// FormatDuration (%llud/h/m/s with %02llu zero-pad minutes/seconds).
//
// Optimization: divisor-table digit emission straight into the caller
// buffer (any 32/64-bit value, exact). Truncation matches swprintf_s
// failure (0 + empty). FormatU64 skips the wide roundtrip entirely.
size_t FormatPortOpt(wchar_t* buf, size_t bufSize, unsigned port);
size_t FormatU64DecOpt(char* buf, size_t bufSize, uint64_t v);
size_t FormatDurationOpt(wchar_t* buf, size_t bufSize, uint64_t seconds);

// ---- 32. IP address emitters ----
// Original: TcpTable.cpp:42-64 PrintIpv4/PrintIpv6 (InetNtopW).
//
// Optimization: hand-rolled emitters - IPv4 as 4 digit-table octets,
// IPv6 as RFC 5952 groups (longest zero run -> "::", first wins ties,
// single 0 group NOT compressed, lowercase hex, v4-mapped dotted
// tail). Verified byte-identical to InetNtopW by differential tests;
// scope suffixes stay in the caller (join-key rule).
std::wstring FormatIpv4Opt(const unsigned char addr[4]);
std::wstring FormatIpv6Opt(const unsigned char addr[16]);

// ---- 33. Display width (CpWidth / NextCp / DisplayWidth / TruncateToWidth) ----
// Original: Commands.cpp:270-350. CpWidth is a ~13-term ordered range chain;
// DisplayWidth re-decodes every byte through NextCp; TruncateToWidth pays
// DisplayWidth a second time before walking the string again.
//
// Optimization:
//   * CpWidthOpt is a flat 12 KB table for cp < 0x3000 (combining -> 0,
//     Hangul Jamo -> 2, everything else -> 1) plus a sorted-range binary
//     search for the sparse wide ranges above it. Table generated FROM the
//     original predicates, so it cannot drift; pinned by width tests.
//   * DisplayWidthOpt consumes 16-byte all-ASCII blocks in one SSE2 load
//     and decodes codepoint-by-codepoint only across the non-ASCII gaps.
//     Identical answer: an ASCII byte is always a 1-wide 1-byte codepoint.
//   * TruncateToWidthOpt fuses the measure pass and the cut pass into one
//     walk (the original's early-out re-measures), keeping the "fits ->
//     return unchanged", "width 0 -> empty" and "budget = width - 1 with
//     U+2026 owning the last column" contracts.
size_t CpWidthOpt(uint32_t cp);
size_t NextCpOpt(const std::string& s, size_t i, uint32_t* cp);
size_t DisplayWidthOpt(const std::string& s);
std::string TruncateToWidthOpt(const std::string& s, size_t width);

// ---- 27b. GeoIP tree walk: shift-register variant ----
// Original: GeoIp.cpp:1006-1058 ResolveOffset. Same semantics as
// ResolveOffsetOpt (section 1), so it is offered as a second wiring of the
// same bench entry rather than a new one.
//
// The difference from ResolveOffsetOpt is HOW the bits and the records
// arrive. Per bit the original (and ResolveOffsetOpt) do a depth/8 and a
// depth%8 and re-branch on the record geometry; this variant:
//   * loads the 16 address bytes as two byte-swapped 64-bit words and
//     consumes them MSB-first (w >> 63; w <<= 1), so the bit is one shift
//     and there is no division, modulo or byte index;
//   * selects one of three straight-line walkers (Walk24 / Walk28 /
//     Walk32) ONCE per lookup, so the geometry branch leaves the loop;
//   * reads each record with a single 4-byte load + BSWAP - for 24-bit
//     records the half is a shift or a mask off the same word, and for
//     32-bit records it is a select between the two halves of the node.
// Order matches GeoIp.cpp:1060-1082 AddressBitsV4 (address byte 0 first,
// MSB first), so bit 'depth' is still the same bit.
bool ResolveOffsetShiftOpt(const unsigned char bits[16], unsigned bitCount,
                           size_t startNode, size_t nodeCount,
                           size_t nodeByteSize, bool record28,
                           size_t recordBytes,
                           const unsigned char* treeBase,
                           size_t dataSectionSize, size_t kSeparatorLen,
                           size_t* out);

// ---- 34. MMDB payload size + pointer read ----
// Original: GeoIp.cpp:422-442 PayloadSize, GeoIp.cpp:492-511 ReadPointer
// (both members of DataReader, so 'data'/'size' are passed here).
//
// Optimization: the size code (ctrl & 0x1F) indexes a 32-entry table that
// gives the payload span, the base and the extra byte count directly, so
// the 30/31 discrimination and the 29 base become loads instead of a
// branch chain; ReadPointer indexes the same table for the pointer bases
// and keeps the size-3 "low three bits ignored" rule. Arithmetic only -
// every 'pos + n > size' reject stays before the wide load, and the
// hostile-pointer cycle/depth guards are untouched.
//
// Constants kept from GeoIp.cpp: kSizeExtended29 29, 30 base 285 /
// 2 extra bytes, 31 base 65821 / 3 extra bytes; pointer bases
// kPtr2Base 2048, kPtr3Base 526336.
struct MmdbPayload {
    uint32_t size = 0;
    size_t pos = 0;
};
bool PayloadSizeOpt(const unsigned char* data, size_t size, unsigned char ctrl,
                    size_t pos, MmdbPayload* out);
bool ReadPointerOpt(const unsigned char* data, size_t size,
                    unsigned char ctrl, size_t pos, size_t* out);

// ---- 35. VLAN skip + flow-record probe (Pcapng.cpp) ----
// Original: Pcapng.cpp:119-129 SkipVlan (two byte loads per tag),
//           Pcapng.cpp:354-361 flow-record scan (one byte compare triple
//           per candidate offset, strided by 2 from offset 12 to 40).
//
// Optimization:
//   * SkipVlanOpt reads the tag with one 2-byte load + BSWAP instead of
//     two byte loads, and keeps the short-circuit order that makes the
//     common (no tag) case one compare.
//   * FlowProbeOpt scans eight candidate offsets per pass: one 16-byte
//     load, SSE2 compares for 0x08 / 0x00 and a nibble test for version 4,
//     with the byte that is 2 past each candidate masked out past capLen.
//     The 2-byte stride means the byte triples OVERLAP between
//     candidates, so the answer is identical to the scalar loop's; the
//     loop bound (k+5 <= capLen, k < 40) and the first-match-wins order
//     are preserved, and a capLen < 16 window falls back to the scalar
//     scan rather than reading past the frame.
size_t SkipVlanOpt(const unsigned char* p, size_t len, size_t off);
bool FlowProbeOpt(const unsigned char* pkt, size_t capLen);

// ---- 36. TCP reassembly render (TcpReasm.cpp:162-194 Direction::Render) ----
// The bench hands the optimized side the same logical segments in
// struct-of-arrays form (seqs / starts / sizes over one byte pool); the
// harness builds both views, so neither variant pays a conversion inside
// the timed loop.
struct ReasmRenderView {
    std::vector<uint64_t> seqs;    // capture order
    std::vector<size_t> starts;    // byte offset into 'pool'
    std::vector<size_t> sizes;
    std::vector<unsigned char> pool;
};

struct ReasmRenderResult {
    std::vector<unsigned char> bytes;
    uint64_t bytesMissing = 0;
    bool hasGap = false;
    uint64_t firstSeq = 0;
    size_t segments = 0;
    size_t duplicates = 0;
    bool truncated = false;
};

// Original: std::sort over a vector of {u64 seq, std::string data}, then a
//           chain of out->bytes += seg.data.
//
// MEASURED CONCLUSION - nothing wins here, and this is a faithful copy of
// the original algorithm on purpose. The render is dominated by the byte
// copy, which is memory-bandwidth bound and identical in every rewrite.
// Four rewrites were benchmarked and all lost or tied (see the comment on
// RenderSegmentsOpt for the numbers): a 4-pass 16-bit radix sort, a packed
// {seq, index} key fed to std::sort, resize() instead of reserve(), and an
// already-in-order fast path. The bench keeps the entry so the report can
// say "do not touch this function" instead of staying silent.
void RenderSegmentsOpt(const ReasmRenderView& w, size_t duplicates,
                       bool truncated, ReasmRenderResult* out);

// ---- 37. PID dedup (Snapshot.cpp:37-45 DistinctPids) ----
// Original: std::unordered_set<DWORD> with reserve(), one push_back per
//           distinct pid in first-appearance order.
//
// Optimization: a flat open-addressing table (power-of-two, linear probe,
// Fibonacci hash) with no per-element node allocation. The set is
// std::unordered_set's contract without its allocator traffic, and unlike a
// sort+unique it keeps the first-appearance order the callers depend on.
// The 0 sentinel is avoided by tagging occupied slots with bit 32, so pid 0
// and 0xFFFFFFFF are both real keys.
//
// Templated on the pid type only so it can serve the product's DWORD and the
// bench's uint32_t without a converting copy: on MSVC those are distinct
// 32-bit types, and std::vector<DWORD> does not convert to
// std::vector<uint32_t>.
template <typename Pid>
std::vector<Pid> DistinctPidsOpt(const Pid* pids, size_t n);

// ---- 37b. Per-PID row grouping (ConnectionStore.cpp:1599 RebuildIndexes) --
// Original: std::unordered_map<DWORD, std::vector<size_t>> filled per row.
//
// Optimization: the same flat open-addressing table, with each bucket
// owning one growable index array. Keys come out in first-appearance order
// (the original's bucket order), and the rows are appended in row order.
struct PidGroups {
    std::vector<uint32_t> pids;             // first-appearance order
    std::vector<std::vector<size_t>> rows;  // parallel to pids
};
PidGroups GroupByPidOpt(const uint32_t* pids, size_t n);

} // namespace wintcp
