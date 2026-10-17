// ExposureScore.cpp
// SPDX-License-Identifier: Apache-2.0
// See ExposureScore.h.

#include "ExposureScore.h"

#include <ws2tcpip.h>
#include <iphlpapi.h>   // IPPROTO_TCP, MIB_TCP_STATE_LISTEN

#include "GeoIp.h"   // IsPrivateAddrV4/V6, IsGlobalUnicastV4/V6 - one table

namespace wintcp {
namespace {

// All-zero: the wildcard in either family. Local rather than imported because
// the two AreUnspecified helpers live in Bookmarks.cpp in a different link
// unit, and importing them would couple the badge to the bookmark code.
bool AllZero4(const unsigned char* a) {
    return a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0;
}
bool AllZero16(const unsigned char* a) {
    for (int i = 0; i < 16; ++i) {
        if (a[i] != 0) return false;
    }
    return true;
}
// 127.0.0.1 in v4, ::1 in v6 - the two loopback forms, spelled once.
bool IsLoopback4(const unsigned char* a) { return a[0] == 127; }
// One place that renders a listener reason, so the bar and the details line
// cannot word the same finding differently.
std::wstring Describe(int proto, bool isV6, unsigned short port, bool wide) {
    wchar_t buf[80] = {0};
    if (wide) {
        ::_snwprintf_s(buf, _TRUNCATE, L"listening on *:%u (%s/%s)", port,
                       proto == IPPROTO_TCP ? L"tcp" : L"udp",
                       isV6 ? L"ipv6" : L"ipv4");
    } else {
        ::_snwprintf_s(buf, _TRUNCATE, L"listening on a specific address");
    }
    return buf;
}
// The v4 bytes are stored network-order; the host-order value is what
// IsPrivateAddrV4 expects (same convention as ConnectionStore.cpp:909).
uint32_t ReadV4Host(const unsigned char* a) {
    return (static_cast<uint32_t>(a[0]) << 24) |
           (static_cast<uint32_t>(a[1]) << 16) |
           (static_cast<uint32_t>(a[2]) << 8) | static_cast<uint32_t>(a[3]);
}
bool IsLoopback6(const unsigned char* a) {
    return a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0 && a[4] == 0 &&
           a[5] == 0 && a[6] == 0 && a[7] == 0 && a[8] == 0 && a[9] == 0 &&
           a[10] == 0 && a[11] == 0 && a[12] == 0 && a[13] == 0 && a[14] == 0 &&
           a[15] == 1;
}

}  // namespace

bool IsPrivilegedExposurePort(unsigned short port) {
    // IANA system ports: a wildcard bind on any of these is a deliberate
    // decision someone made about exposing this machine.
    if (port < 1024) return true;
    // Well-known privileged application ports. Not a guess about what is
    // "important" - each of these is a service whose exposure is routinely
    // scan-reported, and a wildcard bind on one is the thing a user would
    // want at a glance.
    return port == 3389 || port == 445 || port == 5985 || port == 5986;
}

ExposureRow ScoreListener(const unsigned char* addr, size_t localAddrLen,
                          bool isV6, unsigned short localPort, int proto,
                          unsigned int state, bool isWideBind) {
    ExposureRow row;

    // A non-listener is never exposed. The caller may pass every row for
    // simplicity; this rejects the ones that do not apply rather than trusting
    // a caller to have filtered.
    const bool isListenTcp = (proto == IPPROTO_TCP && state == MIB_TCP_STATE_LISTEN);
    const bool isListenUdp = (proto == IPPROTO_UDP);
    if (!isListenTcp && !isListenUdp) {
        return row;   // kNone
    }

    const bool specified = (addr != nullptr && localAddrLen >= (isV6 ? 16u : 4u));
    if (specified) {
        // The wildcard and loopback are the two addresses whose risk is not
        // "a specific host": :: and 0.0.0.0 mean everywhere, 127.0.0.1 and ::1
        // mean only here.
        const bool unspecified =
            isV6 ? !IsGlobalUnicastV6(addr) && AllZero16(addr)
                 : AllZero4(addr);
        const bool loopback =
            isV6 ? IsLoopback6(addr) : IsLoopback4(addr);
        if (unspecified) {
            // The wildcard: reachable from anywhere. Privileged port is what
            // turns it from "public" into the red case. The protocol and
            // family travel with the reason so a two-line table can show
            // which of the two binds is the red one.
            if (IsPrivilegedExposurePort(localPort)) {
                row.level = ExposureLevel::kExposed;
                row.reason = Describe(proto, isV6, localPort, true);
            } else {
                row.level = ExposureLevel::kPublic;
                row.reason = Describe(proto, isV6, localPort, true);
            }
            return row;
        }        if (loopback) {
            row.level = ExposureLevel::kPrivate;
            row.reason = L"loopback only";
            return row;
        }
        // A specific address, and not loopback. Private ranges (RFC1918, ULA,
        // link-local) are not internet-reachable but are LAN-reachable; a
        // specific global address is reachable from outside.
        const bool priv =
            isV6 ? IsPrivateAddrV6(addr)
                 : IsPrivateAddrV4(ReadV4Host(addr));
        if (priv) {
            row.level = ExposureLevel::kPrivate;
            row.reason = L"private range only";
            return row;
        }
        row.level = ExposureLevel::kPublic;
        row.reason = L"a specific public address";
        return row;
    }

    // The row carries no address at all - a fallback enumeration that could
    // not resolve one. Treat it as the widest case rather than guessing: if
    // the bind is wide by the row's own report it is the wildcard, and a
    // caller that cannot say where a listener is bound should not be told
    // "not exposed".
    if (isWideBind) {
        row.level = IsPrivilegedExposurePort(localPort)
                        ? ExposureLevel::kExposed
                        : ExposureLevel::kPublic;
        row.reason = Describe(proto, isV6, localPort, true);
        return row;
    }
    row.level = ExposureLevel::kPublic;
    row.reason = L"listening on a non-loopback address";
    return row;
}

ExposureSummary SummariseExposure(const std::vector<ExposureRow>& rows) {
    ExposureSummary sum;
    for (const ExposureRow& r : rows) {
        switch (r.level) {
            case ExposureLevel::kExposed: ++sum.exposed; break;
            case ExposureLevel::kPublic: ++sum.publicRows; break;
            case ExposureLevel::kPrivate: ++sum.privateRows; break;
            case ExposureLevel::kNone: break;
        }
    }
    if (sum.exposed > 0) {
        sum.line = std::to_wstring(sum.exposed) +
                   L" service(s) listening on any address, privileged port";
    } else if (sum.publicRows > 0) {
        sum.line = std::to_wstring(sum.publicRows) +
                   L" service(s) reachable beyond this machine";
    }
    // Nothing else gets a line. "loopback only" is the default state of a
    // working machine and must not occupy the status bar.
    return sum;
}

}  // namespace wintcp
