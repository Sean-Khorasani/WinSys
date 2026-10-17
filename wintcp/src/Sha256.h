// Sha256.h
// SPDX-License-Identifier: Apache-2.0
// SHA-256 over a file image, plus the helpers the details view needs.
//
// WHY A LOCAL IMPLEMENTATION AND NOT BCrypt. Windows ships SHA-256 in
// bcrypt.dll, and in principle one call would do: BCryptOpenAlgorithmProvider
// -> BCryptCreateHash -> BCryptHashData -> BCryptFinishHash. In practice this
// tool runs its hash on a path the user just picked, in a Details window that
// must never pop a dialog, and the path is frequently one the process cannot
// open with FILE_READ_DATA - a protected system binary. So the failure paths
// are half the value, and a local implementation keeps them explicit and
// testable. It is also ~300 lines against the alternative's five stateful
// calls, which is a fair trade at this size.
//
// If a future change wants BCrypt after all, the contract below is the one to
// keep: a pure Sha256Bytes over memory, a HashImageWithReason that never lies
// about why it failed, and a hex formatter with no locale in it.
//
// SHA-256 is FIPS 180-4. This implementation is the straightforward one
// (64-round compression over 512-bit blocks, 64-entry round constants,
// big-endian lengths, the 0x80 pad plus a length suffix). It is correct by
// construction and pinned by the FIPS test vectors in testAssemblies/Bench.cpp
// so a future edit cannot quietly break it.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>

#include <array>
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace wintcp {

using Sha256Digest = std::array<uint8_t, 32>;

// Pure: hash 'len' bytes at 'data'. Empty input is the empty-string hash,
// which is a well-defined input and not an error.
Sha256Digest Sha256Bytes(const unsigned char* data, size_t len);

// Lowercase hex, 64 characters. No locale, no case folding, no separators -
// the form a person pastes into a search box.
std::wstring Sha256HexW(const Sha256Digest& d);
std::string Sha256HexA(const Sha256Digest& d);

// Why an image hash did not happen. Every failure the caller can see in
// practice is one of these; anything else is kOther with the OS text.
enum class HashFailReason {
    kNone,
    kEmptyPath,
    kOpenFailed,       // not present, or no read access
    kReadFailed,       // present but a read errored part-way
    kTooLarge,         // beyond kHashMaxFileBytes
};

// The ceiling. 512 MB is far above any executable image on Windows (the
// largest legitimate ones are a few hundred MB); beyond it a hash would take
// long enough that a Details window would look wedged, so it is refused with a
// reason instead.
constexpr uint64_t kHashMaxFileBytes = 512ull * 1024 * 1024;

struct ImageHashResult {
    bool ok = false;
    Sha256Digest digest{};
    uint64_t bytesHashed = 0;
    HashFailReason reason = HashFailReason::kNone;
    // Human-readable, ready for a Details line. Empty on success.
    std::wstring message;
};

// Hash a file by path. Never throws; a failure is reported with its reason.
ImageHashResult HashImageFile(const std::wstring& path);

}  // namespace wintcp
