// TcpTable.h
// SPDX-License-Identifier: Apache-2.0
// Enumeration of all TCP and UDP endpoints (IPv4 + IPv6) with owning PID,
// using the IP Helper API GetExtendedTcpTable() / GetExtendedUdpTable().

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

// NOTE: winsock2.h must come before windows.h so that winsock version 2
// declarations win over the older winsock.h pulled in by windows.h.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <string>
#include <vector>

#include "Connection.h"

namespace wintcp {

// Convert a MIB_TCP_STATE_* value to a short readable string, e.g. L"ESTABLISHED".
// Unknown values produce L"UNKNOWN(<n>)".
std::wstring TcpStateToString(DWORD state);

// Enumerate every TCP and UDP endpoint (IPv4 + IPv6) on the local machine
// into 'out' (Connection rows: identity, ports, state, pid, display strings;
// process/service/hostname fields are left empty for the caller to fill).
// On failure returns false and sets 'errorMessage' (never empty).
// Never throws.
bool EnumerateEndpoints(std::vector<Connection>& out, std::wstring& errorMessage);

// Close an IPv4 TCP connection via SetTcpEntry(MIB_TCP_STATE_DELETE_TCB)
// ("Close connection" feature). IPv4-only: Windows exposes no IPv6
// equivalent - returns false with an explanatory error for IPv6 rows.
// Returns true on success; on failure 'errorMessage' describes the problem.
bool CloseTcpConnection(const Connection& c, std::wstring& errorMessage);

}  // namespace wintcp
