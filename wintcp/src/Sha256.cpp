// Sha256.cpp
// SPDX-License-Identifier: Apache-2.0
// See Sha256.h.

#include "Sha256.h"

#include <cstring>

#include "Utils.h"   // FormatSystemError

namespace wintcp {
namespace {

// FIPS 180-4 4.2.2: the first thirty-two bits of the fractional parts of the
// cube roots of the first sixty-four primes.
const uint32_t kRoundConst[64] = {
    0x428A2F98u, 0x71374491u, 0xB5C0FBCFu, 0xE9B5DBA5u, 0x3956C25Bu,
    0x59F111F1u, 0x923F82A4u, 0xAB1C5ED5u, 0xD807AA98u, 0x12835B01u,
    0x243185BEu, 0x550C7DC3u, 0x72BE5D74u, 0x80DEB1FEu, 0x9BDC06A7u,
    0xC19BF174u, 0xE49B69C1u, 0xEFBE4786u, 0x0FC19DC6u, 0x240CA1CCu,
    0x2DE92C6Fu, 0x4A7484AAu, 0x5CB0A9DCu, 0x76F988DAu, 0x983E5152u,
    0xA831C66Du, 0xB00327C8u, 0xBF597FC7u, 0xC6E00BF3u, 0xD5A79147u,
    0x06CA6351u, 0x14292967u, 0x27B70A85u, 0x2E1B2138u, 0x4D2C6DFCu,
    0x53380D13u, 0x650A7354u, 0x766A0ABBu, 0x81C2C92Eu, 0x92722C85u,
    0xA2BFE8A1u, 0xA81A664Bu, 0xC24B8B70u, 0xC76C51A3u, 0xD192E819u,
    0xD6990624u, 0xF40E3585u, 0x106AA070u, 0x19A4C116u, 0x1E376C08u,
    0x2748774Cu, 0x34B0BCB5u, 0x391C0CB3u, 0x4ED8AA4Au, 0x5B9CCA4Fu,
    0x682E6FF3u, 0x748F82EEu, 0x78A5636Fu, 0x84C87814u, 0x8CC70208u,
    0x90BEFFFAu, 0xA4506CEBu, 0xBEF9A3F7u, 0xC67178F2u,
};

// FIPS 180-4 5.3.3: the initial hash value.
const uint32_t kInit[8] = {0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u,
                           0xA54FF53Au, 0x510E527Fu, 0x9B05688Cu,
                           0x1F83D9ABu, 0x5BE0CD19u};

inline uint32_t Ror(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32u - n));
}

// One 512-bit block, 'p' pointing at 64 bytes. 'h' is the running state.
void Compress(uint32_t h[8], const unsigned char* p) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<uint32_t>(p[i * 4 + 0]) << 24) |
               (static_cast<uint32_t>(p[i * 4 + 1]) << 16) |
               (static_cast<uint32_t>(p[i * 4 + 2]) << 8) |
               static_cast<uint32_t>(p[i * 4 + 3]);
    }
    for (int i = 16; i < 64; ++i) {
        const uint32_t s0 = Ror(w[i - 15], 7) ^ Ror(w[i - 15], 18) ^
                            (w[i - 15] >> 3);
        const uint32_t s1 = Ror(w[i - 2], 17) ^ Ror(w[i - 2], 19) ^
                            (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; ++i) {
        const uint32_t S1 = Ror(e, 6) ^ Ror(e, 11) ^ Ror(e, 25);
        const uint32_t ch = (e & f) ^ (~e & g);
        const uint32_t t1 = hh + S1 + ch + kRoundConst[i] + w[i];
        const uint32_t S0 = Ror(a, 2) ^ Ror(a, 13) ^ Ror(a, 22);
        const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t t2 = S0 + maj;
        hh = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
}

// The ONE accumulate-and-compress rule, shared by the in-memory and the
// file path so there is one place for a bug to live. A message that is an
// exact multiple of 64 bytes is handled correctly because the partial buffer
// is EMPTY at the end, so the pad occupies a fresh final block.
class Sha256Stream {
public:
    Sha256Stream() { std::memcpy(h_, kInit, sizeof(h_)); }

    void Update(const unsigned char* p, size_t n) {
        total_ += n;
        while (n > 0) {
            const size_t take = (have_ + n > 64) ? (64 - have_) : n;
            std::memcpy(buf_ + have_, p, take);
            have_ += take;
            p += take;
            n -= take;
            if (have_ == 64) {
                Compress(h_, buf_);
                have_ = 0;
            }
        }
    }

    Sha256Digest Finish() {
        unsigned char tail[128] = {0};
        std::memcpy(tail, buf_, have_);
        tail[have_] = 0x80;
        const uint64_t bitLen = total_ * 8ull;
        const bool twoBlocks = (have_ + 1 + 8) > 64;
        const size_t padAt = twoBlocks ? 120 : 56;
        for (int i = 0; i < 8; ++i) {
            tail[padAt + i] =
                static_cast<unsigned char>(bitLen >> (56 - 8 * i));
        }
        Compress(h_, tail);
        if (twoBlocks) Compress(h_, tail + 64);

        Sha256Digest d{};
        for (int i = 0; i < 8; ++i) {
            d[i * 4 + 0] = static_cast<uint8_t>(h_[i] >> 24);
            d[i * 4 + 1] = static_cast<uint8_t>(h_[i] >> 16);
            d[i * 4 + 2] = static_cast<uint8_t>(h_[i] >> 8);
            d[i * 4 + 3] = static_cast<uint8_t>(h_[i]);
        }
        return d;
    }

private:
    uint32_t h_[8];
    unsigned char buf_[64] = {0};
    size_t have_ = 0;
    uint64_t total_ = 0;
};

}  // namespace

Sha256Digest Sha256Bytes(const unsigned char* data, size_t len) {
    Sha256Stream s;
    if (data != nullptr && len > 0) s.Update(data, len);
    return s.Finish();
}

std::wstring Sha256HexW(const Sha256Digest& d) {
    static const wchar_t kHex[] = L"0123456789abcdef";
    std::wstring out;
    out.reserve(d.size() * 2);
    for (uint8_t b : d) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0x0F]);
    }
    return out;
}

std::string Sha256HexA(const Sha256Digest& d) {
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(d.size() * 2);
    for (uint8_t b : d) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0x0F]);
    }
    return out;
}

ImageHashResult HashImageFile(const std::wstring& path) {
    ImageHashResult r;
    if (path.empty()) {
        r.reason = HashFailReason::kEmptyPath;
        r.message = L"no process image path was recorded for this row";
        return r;
    }

    HANDLE h = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                             nullptr, OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                             nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        r.reason = HashFailReason::kOpenFailed;
        r.message = L"could not open the image: " +
                    FormatSystemError(::GetLastError());
        return r;
    }
    LARGE_INTEGER sz = {};
    if (!::GetFileSizeEx(h, &sz)) {
        r.reason = HashFailReason::kOpenFailed;
        r.message = L"could not size the image: " +
                    FormatSystemError(::GetLastError());
        ::CloseHandle(h);
        return r;
    }
    if (sz.QuadPart < 0) {
        r.reason = HashFailReason::kOpenFailed;
        r.message = L"the image reported a negative size";
        ::CloseHandle(h);
        return r;
    }
    if (static_cast<uint64_t>(sz.QuadPart) > kHashMaxFileBytes) {
        r.reason = HashFailReason::kTooLarge;
        r.message = L"the image is over " +
                    std::to_wstring(kHashMaxFileBytes / (1024 * 1024)) +
                    L" MB; hashing it would stall the details view";
        ::CloseHandle(h);
        return r;
    }
    const uint64_t total = static_cast<uint64_t>(sz.QuadPart);

    // Stream the image through in chunks rather than loading a 200 MB file
    // into memory. The accumulator is the same rule the in-memory path uses.
    Sha256Stream stream;
    std::vector<unsigned char> buf(64 * 1024);
    uint64_t seen = 0;
    for (;;) {
        size_t want = (total > seen) ? (total - seen) : 0;
        if (want > buf.size()) want = buf.size();
        if (want == 0) break;
        DWORD got = 0;
        if (!::ReadFile(h, buf.data(), static_cast<DWORD>(want), &got,
                        nullptr)) {
            r.reason = HashFailReason::kReadFailed;
            r.message = L"a read failed part-way through the image: " +
                        FormatSystemError(::GetLastError());
            ::CloseHandle(h);
            return r;
        }
        if (got == 0) break;   // shorter than advertised: hash what arrived
        stream.Update(buf.data(), got);
        seen += got;
        r.bytesHashed = seen;
    }
    ::CloseHandle(h);

    r.digest = stream.Finish();
    r.ok = true;
    r.message.clear();
    return r;
}

}  // namespace wintcp
