// ExposureScore.h
// SPDX-License-Identifier: Apache-2.0
// the exposure badge's decision half.
//
// The badge answers one question: is there a listening socket reachable from
// somewhere other than this machine? The red case - a
// listener on 0.0.0.0:443 owned by System and unsigned - is the case
// this module is built around.
//
// WHY A PURE MODULE AND NOT A NEW COLUMN. COL_COUNT is exactly 32 and
// static_assert(COL_COUNT <= 32) is a deliberate design decision; a 33rd
// column requires the eight-part UINT64 mask change (mask, REG_BINARY,
// kCurrentColVersion migration, IDM_COL range, ColumnTitle / GetColumnText /
// CompareRows / JsonKeyFor, GroupedDefaultColumns, the help prose) that the
// architecture note forbids arriving as a side effect. So the badge lives on
// the status bar, where it costs nothing and cannot break the mask - and the
// decision itself lives here, pure and pinned, because "which rows count as
// exposed" is a predicate the same shape as every other engine predicate in
// this tree.
//
// THE THREE AXES, and each is load-bearing on its own:
//
//   1. THE ADDRESS. 0.0.0.0 and :: are not "no address"; they are the
//      wildcard, and a wildcard bind is reachable from anywhere. A listener
//      on a specific routable address is ALSO reachable from outside. Only
//      loopback is not. So the predicate distinguishes all three rather than
//      treating "non-loopback" as one bucket.
//
//   2. THE PORT. A wildcard bind on :443 is something someone chose to
//      expose to the internet; a wildcard bind on :51593 is a CI test server
//      that will be gone tomorrow. The port is what makes a wildcard listener
//      worth a human's attention, and it is what separates kPublic from the
//      red case.
//
//   3. THE OWNER. A listener owned by System (a service) and carrying an
//      unsigned image is the classic "something is listening and nobody
//      vouched for it". The two owner flags travel with the row rather than
//      into the scoring, because a caller may weigh them differently: the
//      status bar wants to know which of its listeners is the alarming one,
//      and re-deriving the owner here would hide the very combination the
//      caller is trying to show.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>

#include <string>
#include <vector>

#include "Connection.h"   // IntegrityLevel::kIntegritySystem, kSigUnsigned

namespace wintcp {

// How exposed a single listening row is. Three axes, not one: the address
// (wildcard vs specific vs loopback), the port, and the owner. A badge that
// looked at only one of those would either miss the red case or cry wolf.
enum class ExposureLevel {
    kNone,         // not a listener, or bound to loopback only
    kPrivate,      // loopback, or a private/RFC1918 range
    kPublic,       // a specific public address, or a wildcard on a high port
    kExposed,      // wildcard on a privileged port - the red case
};

// One row's share of the verdict. 'reason' is for the status-bar line, so a
// user who asks "why" gets the same answer the badge did.
struct ExposureRow {
    ExposureLevel level = ExposureLevel::kNone;
    // Why THIS row got its level. Empty for kNone: a row that is not exposed
    // has no reason worth a slot in the bar.
    std::wstring reason;
    // Privileged owner behind the listener - the second axis of the red case.
    // 'isSystem' covers System/LocalSystem owners (services, svchost),
    // 'isUnsigned' covers a binary with no Authenticode signature. The
    // combination is what makes a public listener alarming rather than
    // merely visible.
    bool isSystem = false;
    bool isUnsigned = false;
};

// Score one listening row.
//
// 'addr' is the row's local address bytes (4 for IPv4, 16 for IPv6),
// 'localAddrLen' how many of them are valid. 'pid' identifies the owner for
// the owner-unspecified cases. 'state' is the connection state; 'proto' is
// IPPROTO_TCP or IPPROTO_UDP.
ExposureRow ScoreListener(const unsigned char* addr, size_t localAddrLen,
                          bool isV6, unsigned short localPort, int proto,
                          unsigned int state, bool isWideBind);

// The whole table's verdict, for one status-bar line.
struct ExposureSummary {
    size_t exposed = 0;     // wildcard on a privileged port
    size_t publicRows = 0;  // reachable, but not the red case
    size_t privateRows = 0; // loopback or RFC1918
    // A one-line summary suitable for the status bar. Empty when there is
    // nothing worth saying - the bar must stay silent when the machine is
    // fine, or the badge becomes noise that teaches users to ignore it.
    std::wstring line;
};

// Summarise a set of rows. 'rows' must already be the scored per-row results.
ExposureSummary SummariseExposure(const std::vector<ExposureRow>& rows);

// Is this port "privileged" for exposure purposes? Ports under 1024 are IANA
// system ports; the badge treats those, plus a handful of well-known
// privileged application ports (3389 RDP, 445 SMB, 5985/5986 WinRM), as
// privileged because a wildcard bind on any of them is a deliberate decision
// someone should be able to see at a glance.
bool IsPrivilegedExposurePort(unsigned short port);

}  // namespace wintcp
