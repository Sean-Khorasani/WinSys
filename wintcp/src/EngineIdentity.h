// EngineIdentity.h
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <string>

namespace wintcp {

// SID text is produced by ConvertSidToStringSidW from the impersonated token,
// so exact equality is equivalent to comparing those canonical SID values.
// Keeping the session check in the same predicate prevents a same-user client
// in another interactive session from reaching this engine instance.
inline bool SameEnginePeer(const std::wstring& expectedSid,
                           std::uint32_t expectedSession,
                           const std::wstring& peerSid,
                           std::uint32_t peerSession) noexcept {
    return expectedSession == peerSession && expectedSid == peerSid;
}

}  // namespace wintcp
