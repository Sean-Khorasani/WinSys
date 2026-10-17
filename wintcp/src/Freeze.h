// Freeze.h
// SPDX-License-Identifier: Apache-2.0
// Pause / freeze the live view.
//
// WHY THIS IS ITS OWN MODULE. The whole feature is one boolean plus a
// timestamp, but the behaviour around it is where the bugs live, and all of
// it is testable without a window: a frozen view must NOT be replaced by the
// next auto-refresh tick, it must report its age honestly rather than
// pretending to be live, and unpausing must resume cleanly. None of that
// needs a HWND.
//
// WHAT "FREEZE" MEANS HERE, precisely. The sampler keeps running - counters
// keep accumulating, sockets keep being enumerated - and the results are
// still computed. Freeze stops the DISPLAY from being replaced. That
// distinction is the whole design: freezing must not stop the ETW session,
// must not stop the resolver, and must not make the underlying numbers go
// stale, because a user who freezes to read a table and then unfreezes wants
// to see what changed, not to resume from a stopped world.
//
// The alternative (pause the sampler) would make unfreeze show a gap, lose
// the accumulated traffic between pause and resume, and - worse - would make
// the per-PID traffic counters jump by everything that happened during the
// pause in one lump. Display-freeze avoids all three.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>

#include <cstdint>

namespace wintcp {

// The age shown in the status bar. Clamped at zero so a clock that appears to
// run backwards (which GetTickCount64 cannot do, but a computed future
// timestamp can) cannot render as a negative age.
std::uint64_t FrozenAgeMs(ULONGLONG frozenAt, ULONGLONG now);

}  // namespace wintcp
