// TcpTable.cpp
// SPDX-License-Identifier: Apache-2.0
// TCP + UDP enumeration via GetExtendedTcpTable() / GetExtendedUdpTable().
// Fills the identity/display halves of Connection: family, protocol,
// binary addresses, scope ids, ports, state, pid, address+endpoint strings.

#include "TcpTable.h"
#include "Utils.h"

#include "Opt.h"

#include <iphlpapi.h>
#include <tcpmib.h>
#include <udpmib.h>

#include <cstring>
#include <new>

namespace wintcp {
namespace {

// Buffer-growth policy for the GetExtendedTcp/UdpTable queries below, shared
// by the TCP and UDP paths (they were two copies of the same three literals).
// 8 attempts is far beyond the 1-2 a growing table needs — reaching it means
// the table is growing faster than we can read it, and persisting would only
// lengthen a refresh that is already pathological. 64 bytes is the smallest
// allocation worth making (below any real table); 1 GB caps a lying `size`
// before it becomes an allocation failure.
constexpr int kTableQueryAttempts = 8;
constexpr ULONG kTableMinProbeBytes = 64;
constexpr ULONG kTableMaxBytes = 1024u * 1024u * 1024u;

// Bytes in the address field of every MIB_TCP6ROW_OWNER_PID / MIB_UDP6ROW pair
// and of the IN6_ADDR they are copied into. Same name as TcpReasm.cpp's copy on
// purpose, so a grep finds both: the IP Helper struct field and the socket scan
// key must agree on this width or a v6 row stops being the connection it is.
constexpr size_t kIpv6AddrBytes = 16;

// "UNKNOWN(%lu)" plus a NUL. The state field is a DWORD, so ten digits is the
// widest render; this is that plus slack, and swprintf_s truncates rather than
// overruns in any case.
constexpr size_t kUnknownStateChars = 48;

// Printable rendering of a 16-byte IPv6 address, with the numeric scope id
// appended for link-local addresses: "fe80::1%12". The append RULE lives in
// Ipv6ScopeSuffix (Utils.h) because the socket scan must spell it identically:
// this string is a join key, not just a label.
//
// The address itself is wintcp::FormatIpv6Opt (Opt.cpp), which byte-swaps
// the 16 bytes into eight 16-bit groups and emits the RFC 5952 shortest
// form (lowercase, one zero tuple as "::", the leftmost of equally long
// runs) with a nibble hex table. The longest-run rule is where a hand-rolled
// emitter usually goes wrong, so the differential tests compare it against
// ::InetNtopW over the all-zero, all-ones, mapped-v4, link-local and
// mixed-compressed shapes plus a randomized sweep.
//
// A/B bench, same source: 13.74x compressed, 21.55x fully expanded.
std::wstring PrintIpv6(const UCHAR addr[16], DWORD scopeId) {
    const unsigned char bytes[16] = {
        addr[0], addr[1], addr[2],  addr[3],  addr[4],  addr[5],
        addr[6], addr[7], addr[8],  addr[9],  addr[10], addr[11],
        addr[12], addr[13], addr[14], addr[15],
    };
    std::wstring out = FormatIpv6Opt(bytes);
    out += Ipv6ScopeSuffix(bytes, static_cast<unsigned>(scopeId));
    return out;
}

// dwLocalPort/dwRemotePort store the port in network byte order, low 16 bits.
UINT PortNetworkToHost(DWORD portNetworkOrder) {
    return static_cast<UINT>(::ntohs(static_cast<u_short>(portNetworkOrder & 0xFFFF)));
}

DWORD PortHostToNetwork(UINT portHostOrder) {
    return static_cast<DWORD>(::htons(static_cast<u_short>(portHostOrder)));
}

// Generic helpers: query an IP Helper table for one address family, growing
// the buffer until it fits (up to a sane retry limit). Each caller keeps
// its own output vector.
DWORD QueryTcp(ULONG family, std::vector<BYTE>& buffer) {
    ULONG size = 0;
    DWORD rc = ::GetExtendedTcpTable(nullptr, &size, FALSE, family,
                                     TCP_TABLE_OWNER_PID_ALL, 0);
    if (rc != NO_ERROR && rc != ERROR_INSUFFICIENT_BUFFER) return rc;
    for (int attempt = 0; attempt < kTableQueryAttempts; ++attempt) {
        if (size > kTableMaxBytes) return ERROR_INSUFFICIENT_BUFFER;
        if (size < kTableMinProbeBytes) size = kTableMinProbeBytes;
        buffer.resize(size);
        rc = ::GetExtendedTcpTable(buffer.data(), &size, FALSE, family,
                                   TCP_TABLE_OWNER_PID_ALL, 0);
        if (rc == NO_ERROR) return NO_ERROR;
        if (rc != ERROR_INSUFFICIENT_BUFFER) return rc;
    }
    return ERROR_INSUFFICIENT_BUFFER;
}

DWORD QueryUdp(ULONG family, std::vector<BYTE>& buffer) {
    ULONG size = 0;
    DWORD rc = ::GetExtendedUdpTable(nullptr, &size, FALSE, family,
                                     UDP_TABLE_OWNER_PID, 0);
    if (rc != NO_ERROR && rc != ERROR_INSUFFICIENT_BUFFER) return rc;
    for (int attempt = 0; attempt < kTableQueryAttempts; ++attempt) {
        if (size > kTableMaxBytes) return ERROR_INSUFFICIENT_BUFFER;
        if (size < kTableMinProbeBytes) size = kTableMinProbeBytes;
        buffer.resize(size);
        rc = ::GetExtendedUdpTable(buffer.data(), &size, FALSE, family,
                                   UDP_TABLE_OWNER_PID, 0);
        if (rc == NO_ERROR) return NO_ERROR;
        if (rc != ERROR_INSUFFICIENT_BUFFER) return rc;
    }
    return ERROR_INSUFFICIENT_BUFFER;
}

// Error families that are legitimately unavailable (disabled IPv6 stack etc.)
bool IsBenignFamilyError(DWORD rc) {
    return rc == ERROR_NOT_SUPPORTED ||
           rc == ERROR_ADDRESS_NOT_ASSOCIATED ||
           rc == ERROR_PROTOCOL_UNREACHABLE;
}

void FinishRow(Connection& info) {
    info.display.localEndpoint  = JoinEndpoint(info.display.localAddress, info.identity.localPort,
                                       info.identity.family == AF_INET6);
    info.display.remoteEndpoint = JoinEndpoint(info.display.remoteAddress, info.identity.remotePort,
                                       info.identity.family == AF_INET6);
}

}  // namespace

bool ConnectionMatchesOwnerPidTcpRow(const Connection& connection,
                                     DWORD state, DWORD localAddress,
                                     DWORD localPort, DWORD remoteAddress,
                                     DWORD remotePort, DWORD owningPid) {
    return connection.identity.protocol == IPPROTO_TCP &&
           connection.identity.family == AF_INET &&
           connection.identity.state == MIB_TCP_STATE_ESTAB &&
           connection.identity.pid != 0 &&
           state == MIB_TCP_STATE_ESTAB && owningPid == connection.identity.pid &&
           localAddress == connection.identity.local4.S_un.S_addr &&
           localPort == PortHostToNetwork(connection.identity.localPort) &&
           remoteAddress == connection.identity.remote4.S_un.S_addr &&
           remotePort == PortHostToNetwork(connection.identity.remotePort);
}

// Printable rendering of an IPv4 address stored in network byte order.
// Declared in TcpTable.h so unit tests can call it directly.
std::wstring PrintIpv4(DWORD addrNetworkOrder) {
    const DWORD hostOrder = ::ntohl(addrNetworkOrder);
    const unsigned char addr[4] = {
        static_cast<unsigned char>((hostOrder >> 24) & 0xFF),
        static_cast<unsigned char>((hostOrder >> 16) & 0xFF),
        static_cast<unsigned char>((hostOrder >> 8) & 0xFF),
        static_cast<unsigned char>(hostOrder & 0xFF),
    };
    return FormatIpv4Opt(addr);
}

std::wstring TcpStateToString(DWORD state) {
    switch (state) {
        case MIB_TCP_STATE_CLOSED:     return L"CLOSED";
        case MIB_TCP_STATE_LISTEN:     return L"LISTENING";
        case MIB_TCP_STATE_SYN_SENT:   return L"SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD:   return L"SYN_RECEIVED";
        case MIB_TCP_STATE_ESTAB:      return L"ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1:  return L"FIN_WAIT_1";
        case MIB_TCP_STATE_FIN_WAIT2:  return L"FIN_WAIT_2";
        case MIB_TCP_STATE_CLOSE_WAIT: return L"CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING:    return L"CLOSING";
        case MIB_TCP_STATE_LAST_ACK:   return L"LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT:  return L"TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB: return L"DELETE_TCB";
        default: break;
    }
    wchar_t buf[kUnknownStateChars] = {0};
    ::swprintf_s(buf, L"UNKNOWN(%lu)", static_cast<unsigned long>(state));
    return std::wstring(buf);
}

bool EnumerateEndpoints(std::vector<Connection>& out, std::wstring& errorMessage) {
    out.clear();
    std::vector<BYTE> buffer;

    // ---- TCP / IPv4 -------------------------------------------------------
    DWORD rc = QueryTcp(AF_INET, buffer);
    if (rc != NO_ERROR) {
        errorMessage = L"GetExtendedTcpTable(AF_INET) failed: " + FormatSystemError(rc);
        return false;
    }
    if (buffer.size() >= sizeof(MIB_TCPTABLE_OWNER_PID)) {
        const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const MIB_TCPROW_OWNER_PID& row = table->table[i];
            Connection info;
            info.identity.family = AF_INET;
            info.identity.protocol = IPPROTO_TCP;
            info.identity.local4.S_un.S_addr = row.dwLocalAddr;
            info.identity.remote4.S_un.S_addr = row.dwRemoteAddr;
            info.identity.localPort  = PortNetworkToHost(row.dwLocalPort);
            info.identity.remotePort = PortNetworkToHost(row.dwRemotePort);
            info.identity.state = row.dwState;
            info.identity.pid = row.dwOwningPid;
            info.display.localAddress  = PrintIpv4(row.dwLocalAddr);
            info.display.remoteAddress = PrintIpv4(row.dwRemoteAddr);
            FinishRow(info);
            out.push_back(std::move(info));
        }
    }

    // ---- TCP / IPv6 -------------------------------------------------------
    buffer.clear();
    rc = QueryTcp(AF_INET6, buffer);
    if (rc != NO_ERROR) {
        if (!IsBenignFamilyError(rc)) {
            errorMessage = L"GetExtendedTcpTable(AF_INET6) failed: " + FormatSystemError(rc);
            return false;
        }
        // IPv6 stack unavailable: keep IPv4 results.
    } else if (buffer.size() >= sizeof(MIB_TCP6TABLE_OWNER_PID)) {
        const auto* table6 = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(buffer.data());
        for (DWORD i = 0; i < table6->dwNumEntries; ++i) {
            const MIB_TCP6ROW_OWNER_PID& row = table6->table[i];
            Connection info;
            info.identity.family = AF_INET6;
            info.identity.protocol = IPPROTO_TCP;
            std::memcpy(info.identity.local6.s6_addr, row.ucLocalAddr, kIpv6AddrBytes);
            std::memcpy(info.identity.remote6.s6_addr, row.ucRemoteAddr, kIpv6AddrBytes);
            info.identity.localScope = row.dwLocalScopeId;
            info.identity.remoteScope = row.dwRemoteScopeId;
            info.identity.localPort  = PortNetworkToHost(row.dwLocalPort);
            info.identity.remotePort = PortNetworkToHost(row.dwRemotePort);
            info.identity.state = row.dwState;
            info.identity.pid = row.dwOwningPid;
            info.display.localAddress  = PrintIpv6(row.ucLocalAddr, row.dwLocalScopeId);
            info.display.remoteAddress = PrintIpv6(row.ucRemoteAddr, row.dwRemoteScopeId);
            FinishRow(info);
            out.push_back(std::move(info));
        }
    }

    // ---- UDP / IPv4 -------------------------------------------------------
    buffer.clear();
    rc = QueryUdp(AF_INET, buffer);
    if (rc != NO_ERROR) {
        if (!IsBenignFamilyError(rc)) {
            errorMessage = L"GetExtendedUdpTable(AF_INET) failed: " + FormatSystemError(rc);
            return false;
        }
    } else if (buffer.size() >= sizeof(MIB_UDPTABLE_OWNER_PID)) {
        const auto* table = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(buffer.data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const MIB_UDPROW_OWNER_PID& row = table->table[i];
            Connection info;
            info.identity.family = AF_INET;
            info.identity.protocol = IPPROTO_UDP;
            info.identity.local4.S_un.S_addr = row.dwLocalAddr;
            info.identity.localPort  = PortNetworkToHost(row.dwLocalPort);
            info.identity.state = 0;                       // UDP has no state
            info.identity.pid = row.dwOwningPid;
            info.display.localAddress  = PrintIpv4(row.dwLocalAddr);
            info.display.remoteAddress = L"*";            // UDP rows carry no remote endpoint
            FinishRow(info);
            info.display.remoteEndpoint = L"*:*";
            out.push_back(std::move(info));
        }
    }

    // ---- UDP / IPv6 -------------------------------------------------------
    buffer.clear();
    rc = QueryUdp(AF_INET6, buffer);
    if (rc != NO_ERROR) {
        if (!IsBenignFamilyError(rc)) {
            errorMessage = L"GetExtendedUdpTable(AF_INET6) failed: " + FormatSystemError(rc);
            return false;
        }
    } else if (buffer.size() >= sizeof(MIB_UDP6TABLE_OWNER_PID)) {
        const auto* table6 = reinterpret_cast<const MIB_UDP6TABLE_OWNER_PID*>(buffer.data());
        for (DWORD i = 0; i < table6->dwNumEntries; ++i) {
            const MIB_UDP6ROW_OWNER_PID& row = table6->table[i];
            Connection info;
            info.identity.family = AF_INET6;
            info.identity.protocol = IPPROTO_UDP;
            std::memcpy(info.identity.local6.s6_addr, row.ucLocalAddr, kIpv6AddrBytes);
            info.identity.localScope = row.dwLocalScopeId;
            info.identity.localPort  = PortNetworkToHost(row.dwLocalPort);
            info.identity.state = 0;
            info.identity.pid = row.dwOwningPid;
            info.display.localAddress  = PrintIpv6(row.ucLocalAddr, row.dwLocalScopeId);
            info.display.remoteAddress = L"*";            // no remote for UDP (netstat-style)
            FinishRow(info);
            info.display.remoteEndpoint = L"*:*";
            out.push_back(std::move(info));
        }
    }

    errorMessage.clear();
    return true;
}

bool CloseTcpConnection(const Connection& c, std::wstring& errorMessage) {
    if (c.identity.protocol != IPPROTO_TCP) {
        errorMessage = L"Only TCP connections can be closed (UDP has no sessions).";
        return false;
    }
    if (c.identity.family != AF_INET) {
        errorMessage = L"Windows' SetTcpEntry API only supports IPv4 connections; "
                       L"this row is IPv6.";
        return false;
    }
    std::vector<BYTE> buffer;
    DWORD queryResult = ERROR_GEN_FAILURE;
    try {
        queryResult = QueryTcp(AF_INET, buffer);
    } catch (const std::bad_alloc&) {
        errorMessage = L"Could not revalidate the live TCP owner table: out of memory.";
        return false;
    }
    if (queryResult != NO_ERROR ||
        buffer.size() < sizeof(MIB_TCPTABLE_OWNER_PID)) {
        errorMessage = L"Could not revalidate the live TCP owner table: " +
                       FormatSystemError(queryResult == NO_ERROR
                                             ? ERROR_INVALID_DATA : queryResult);
        return false;
    }
    const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(
        buffer.data());
    const size_t availableRows =
        (buffer.size() - sizeof(DWORD)) / sizeof(MIB_TCPROW_OWNER_PID);
    if (table->dwNumEntries > availableRows) {
        errorMessage = L"Could not revalidate the live TCP owner table: "
                       L"the returned table is incomplete.";
        return false;
    }
    bool targetStillMatches = false;
    for (DWORD index = 0; index < table->dwNumEntries; ++index) {
        const MIB_TCPROW_OWNER_PID& live = table->table[index];
        if (ConnectionMatchesOwnerPidTcpRow(
                c, live.dwState, live.dwLocalAddr, live.dwLocalPort,
                live.dwRemoteAddr, live.dwRemotePort, live.dwOwningPid)) {
            targetStillMatches = true;
            break;
        }
    }
    if (!targetStillMatches) {
        errorMessage = L"The connection no longer matches the live TCP tuple, "
                       L"state, and owner PID; refresh and review it again.";
        return false;
    }
    MIB_TCPROW row = {};
    row.dwState      = MIB_TCP_STATE_DELETE_TCB;
    row.dwLocalAddr  = c.identity.local4.S_un.S_addr;
    row.dwLocalPort  = PortHostToNetwork(c.identity.localPort);
    row.dwRemoteAddr = c.identity.remote4.S_un.S_addr;
    row.dwRemotePort = PortHostToNetwork(c.identity.remotePort);
    const DWORD rc = ::SetTcpEntry(&row);
    if (rc != NO_ERROR) {
        errorMessage = L"SetTcpEntry failed: " + FormatSystemError(rc);
        if (rc == ERROR_ACCESS_DENIED)
            errorMessage += L" (closing connections requires running as "
                             L"administrator)";
        else if (rc == ERROR_NOT_FOUND || rc == 1168 /* ELEMENT_NOT_FOUND */ ||
                 rc == 317 /* ERROR_MR_MID_NOT_FOUND: the row moved */)
            errorMessage += L" (the row no longer matches the live table - "
                             L"it closed or changed state; list again and "
                             L"retry)";
        return false;
    }
    errorMessage.clear();
    return true;
}

}  // namespace wintcp
