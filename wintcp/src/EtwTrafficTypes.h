// EtwTrafficTypes.h
// SPDX-License-Identifier: Apache-2.0
// The pure, self-contained half of the ETW traffic counter: the MOF
// provider GUIDs, the direction enum and the two parser/classifier
// declarations.
//
// These used to live behind EtwTraffic.h, which includes evntcons.h for the
// real EVENT_RECORD callback signature. That header is large, so anything
// only interested in the classification rules (notably --selftest in
// Bench.cpp) had to drag it in to test two POD structs. This header keeps
// them behind <windows.h> only.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>

namespace wintcp {

// MOF provider GUIDs of the classic network events (exposed so the
// selftest feeds the classifier the real GUIDs).
inline constexpr GUID kTcpIpProviderGuid = {
    0x9a280ac0, 0xc8e0, 0x11d1,
    {0x84, 0xe2, 0x00, 0xc0, 0x4f, 0xb9, 0x98, 0xa2}};
inline constexpr GUID kUdpIpProviderGuid = {
    0xbf3a50c5, 0xa9c9, 0x4988,
    {0xa0, 0x05, 0x2d, 0xf0, 0xb7, 0xc8, 0x0f, 0x80}};

// Direction of one network event (None = not a counted send/receive).
enum class TrafficDirection { None, Sent, Received };

// Pure classifier for classic TcpIp/UdpIp events, extracted from
// EtwTraffic::OnEvent so --selftest exercises the production logic.
// 'type' is taken from Opcode first (ground truth: classic MOF events carry
// their type in Opcode while Id is always 0) and falls back to Id; anything
// else - including the extra opcode-18 per-segment receive variant - is
// deliberately not counted (counting it would double every receive, as
// TaskExplorer/krabs also avoid).
TrafficDirection ClassifyNetworkEvent(const GUID& provider, USHORT id,
                                      USHORT opcode);

// Parses the fixed MOF payload (uint32 PID @0, uint32 size @4).
// Returns false for a short/absent buffer or degenerate values.
bool ParseTrafficPayload(const void* data, DWORD length, DWORD* pid,
                         DWORD* size);

}  // namespace wintcp
