// CrashDump.h
// SPDX-License-Identifier: Apache-2.0
// Last-resort crash diagnostics: an unhandled-exception filter that
// writes a minidump, an on-disk breadcrumb in the dump folder and a one-line
// breadcrumb on stderr before the process dies.
//
// A crash with no artefact is unactionable - this began life as exactly the
// sentence "it just closed". This module exists so the next such report ships
// with a file and an address instead - and so that a crash where the dump
// itself failed still leaves a written record of having run, and of why.

#pragma once

#include <string>

namespace wintcp {

// Install the filter. Idempotent; call once at startup, before anything that
// can crash (which is everything). After this returns, any unhandled SEH
// exception anywhere in the process - UI thread, worker thread, scan pool -
// lands a minidump in CrashDumpDir(), a "wintcp-last-crash.txt" record beside
// it, and a one-line breadcrumb on stderr.
void InstallCrashHandler();

// %LOCALAPPDATA%\WinTCP\crashes, created on demand. Empty when the folder is
// unresolvable, in which case the filter still writes the stderr breadcrumb
// but no dump and no note (there is nowhere to write them) - a missing dump
// with a reason beats a missing dump with silence.
std::wstring CrashDumpDir();

// Deliberately crash the calling thread with a real access violation, so the
// filter above fires exactly as for a field crash. Called only by the hidden
// `crashtest` verb (golden's fuse box). [[noreturn]] doubles as documentation
// and silences unreachable-code diagnostics at the call site.
[[noreturn]] void CrashForTest();

}  // namespace wintcp
