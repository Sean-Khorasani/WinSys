// Elevate.h
// SPDX-License-Identifier: Apache-2.0
// UAC self-elevation.
//
// WHY THIS EXISTS
// The original plan was "read the live TLS session with
// SIO_TLS_INFO". That was checked against the Windows SDK and it does not
// exist: neither SIO_TLS_INFO nor TLS_INFO_v0 appears anywhere in the
// Windows Kits or Visual Studio trees, and TCP_INFO_v0/v1 carry no TLS
// field. So there is no unelevated way to learn that a live connection is
// TLS.
//
// That leaves two real options, and this module serves the first: run
// elevated and get the answer from ETW Schannel, which observes the
// handshake as it happens. The second is the pktmon capture,
// which also needs elevation.
//
// ELEVATION POLICY - read this before changing it
//   * Elevation happens ONLY when the user explicitly asks for a feature
//     that needs it (Follow TCP stream, ETW TLS). The app does not
//     self-elevate at launch. A connection viewer that demands admin
//     before it will show you your own connections is hostile.
//   * We do NOT shell out to a second process. The whole point is to keep
//     one window, one state, one set of columns. Instead the EXISTING
//     process re-launches itself with a marker argument and exits; the new
//     elevated instance is the real one. See ReelevateIfNeeded().
//   * If the account is a standard user, there is nothing to elevate to.
//     We say so and carry on unelevated rather than looping on a consent
//     dialog the user cannot satisfy.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>

#include <string>

namespace wintcp {

// True when this process holds an elevated token (not merely membership of
// the Administrators group - a filtered token is not elevation).
bool IsElevated();

// True when the user is a member of the Administrators group, whether or not
// the current token is elevated. Distinguishes "can be elevated" from
// "already is".
bool IsAdminMember();

// Why elevation is unavailable, for the UI to explain. Empty when it is.
std::wstring ElevationUnavailableReason();

// Marker argument carried across the relaunch. If this appears in the
// command line, this instance IS the elevated one and must not try to
// elevate again.
bool IsElevatedInstance();

// True when this process was started by the relaunch, i.e. the user has
// already answered the UAC prompt for this run. Used to avoid asking twice.
bool WasRelaunchedForElevation();

// Re-launch this process elevated, preserving the command line, and return
// true if a new instance was started (the caller MUST then exit
// immediately). Returns false if elevation was not attempted because it is
// unnecessary, impossible, or the user cancelled.
//
// 'featureName' is shown in the UAC consent dialog context and in any
// message, e.g. L"Follow TCP stream".
bool Reelevate(const std::wstring& featureName);

// Grant SeDebugPrivilege to this process's token, when the token holds it.
// Returned in false if the current token is not elevated or does not carry the
// privilege - which is expected and not an error for a standard user. The
// privilege defaults to Present-but-disabled in an Administrator token, so
// without this, opening handles to system-level processes (svchost, lsass,
// services) fails with ERROR_ACCESS_DENIED even for an Administrator.
// Safe to call unconditionally at startup: on a standard-user token it simply
// returns false. Weeks of debugging and confusion over "it works for me but
// not for the admin" is the cost of never calling it.
bool EnableDebugPrivilege();

}  // namespace wintcp
