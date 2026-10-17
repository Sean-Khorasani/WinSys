// WinCaps.h
// SPDX-License-Identifier: Apache-2.0
// Runtime capability report: which optional Windows facilities this machine
// actually offers, and why not when it does not.
//
// WHY THIS EXISTS. Until now the app answered "can I do X?" by trying X and
// interpreting the error, which is correct but invisible. Three separate
// modules each held their own private answer - `CaptureAvailable()` in
// StreamCapture.cpp, `SocketTrafficSampler::Supported()` in SocketTraffic.h,
// and a `pdhRetryIn_` countdown in SysStats.cpp - and none of them could be
// asked "so what CAN this machine do?". A user on a stripped Server Core or a
// Wine prefix who found the disk panel empty had no way to learn that the
// absence was a missing DLL rather than a bug, and no way to find out what
// would fix it.
//
// The point is not to make the app smaller. It is to make it HONEST: every
// degraded feature names its own cause, and every unavailable one says what to
// install. See the size notes section 7 for the size measurement that
// motivated gating the optional libraries behind /DELAYLOAD at all.
//
// One header, one definition, one report. Every module that owns an optional
// capability registers it here, so adding a dependency cannot be forgotten:
// the list of what this build might lack is the list of what it probes.

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

namespace wintcp {

// Why a capability is unavailable. Deliberately NOT a bool: the three states
// "this build never had it", "this machine cannot" and "not right now, try
// again later" call for three different user-facing messages, and a bool
// forces the two interesting ones to be spelled the same way.
enum class CapState {
    Available,
    Missing,      // the library or the API is not present here
    Unavailable,  // present, but refused: no elevation, counters off, ...
};

// One probed capability. 'what' is the user-facing feature name ("Disk I/O
// counters"), never a DLL name: the user does not know what pdh.dll is, and
// a report that says "pdh.dll missing" has told them nothing actionable.
// 'install' is the actionable half - the Windows feature or package that
// provides it - and is empty when there is nothing to install, which is a
// legitimate answer (see the notes on each capability).
struct Capability {
    CapState state = CapState::Available;
    std::wstring what;      // "Disk I/O counters"
    std::wstring detail;    // why, in one clause: "pdh.dll is not present"
    std::wstring install;   // what to install, or empty if nothing will help
};

// Probe every optional capability once and cache the answer. Cheap: each probe
// is one LoadLibrary of a DLL the loader already mapped, one function lookup, or
    // - for the capture row - two GetFileAttributes calls on exes
// that are always mapped into the loader's search path anyway.
//
// CALLED FROM exactly one place: BuildInfo.cpp's "This run" block, which both
// the CLI `version` command and the GUI About box render. That comment used to
// add "and from `stat`", which was false - `stat` prints a single fixed-width
// line and never builds a BuildSummary, so no capability row has ever appeared
// in it. Verified by running both: `stat` output is one line and contains no
// capability text. Correcting it here rather than adding the call, because
// `stat`'s line format is a fixed-width contract that a multi-line capability
// block would break, and no item asked for that.
const std::vector<Capability>& WinCapabilities();

// True when every probed capability is Available. Convenience for the one
// place that wants a single bit: the About box's summary line.
bool WinAllCapabilitiesPresent();

// Is a DLL loadable right now? The gate every delay-loaded subsystem must ask
// before its first call.
//
// WHY THIS MUST BE ASKED, not assumed. A /DELAYLOAD import resolves on FIRST
// CALL, not at process start, and a missing DLL then raises a structured
// delay-load exception rather than returning an error code. So delay-loading a
// library without gating its call sites converts "this feature is absent" -
// a clean, reportable condition - into a crash. The gate is what makes the
// absence a report.
//
// Deliberately a LoadLibrary probe rather than GetModuleHandle: the DLL is
// genuinely not loaded yet, which is the entire point of delay-loading it.
// The cost is one file-system lookup, once, and it is cached.
//
// Safe to call before the delay-load helper is ready - it does not touch any
// delay-loaded import itself.
bool DllAvailable(const char* dllName);

// The one gate a delay-loaded subsystem's entry point should call. Returns
// true when the library is present and the caller should carry on; returns
// false after showing the standard notice when it is not.
//
// WHY ONE HELPER RATHER THAN FIVE INLINE CHECKS. comdlg32 alone has five
// entry points (export CSV/TSV/JSON, hex-dump save, change-log save, open a
// .mmdb). Written out five times, the guards would be five chances to word the
// message differently - and, worse, five chances to write `if (!DllAvailable)
// return;`, which on a missing library looks EXACTLY like the user cancelling
// the dialog. A dialog that silently declines to open is indistinguishable
// from a broken menu item, and is precisely the confusion the capability report
// exists to remove. Route every one of them here and the failure mode is
// unreachable by construction.
//
// The message names the feature first and the DLL second: the user asked to
// export a CSV, not to load comdlg32. Naming the DLL is still worth it in the
// parenthesis - someone debugging this needs it - but it is the detail, not
// the headline.
bool DelayLoadGuard(HWND owner, const char* dllName);

}  // namespace wintcp