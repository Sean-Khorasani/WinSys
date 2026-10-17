// Version.h
// SPDX-License-Identifier: Apache-2.0
// The single source of truth for the application version.
//
// The version used to be spelled out in four places that disagreed:
// wintcp.rc (1.0.0.0), CMakeLists.txt (1.0.0), ShowAboutBox ("WinTCP 1.1")
// and this header. The .rc / CMake value is the one the built binary
// actually reports, so it is the one kept here; ShowAboutBox now formats its
// caption from these macros and wintcp.rc mirrors them by hand (rc.exe has no
// include of its own, so the .rc numbers are kept adjacent to a comment
// pointing here).

#pragma once

#define WINTCP_VERSION_MAJOR 1
#define WINTCP_VERSION_MINOR 0
#define WINTCP_VERSION_PATCH 0

// "1.0.0" - must match the .rc four-part version. Narrow on purpose: the
// resource compiler needs a plain string, and wide code concatenates with
// a separate L"" literal (see MainWindow::ShowAboutBox).
#define WINTCP_VERSION_STRING "1.0.0"
