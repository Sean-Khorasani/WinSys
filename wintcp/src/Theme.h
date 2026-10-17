// Theme.h
// SPDX-License-Identifier: Apache-2.0
//
// The one shared system-theme palette.
//
// Every window that paints its own colours used to pick its own:
// MainWindow derived from GetSysColor, DetailsDialog substituted a
// hard-coded dark palette, and ChartsWindow baked in fixed
// light/dark constants with no high-contrast branch at all. The
// three could disagree under a custom or high-contrast scheme.
// This header is the single derivation: background, foreground,
// a dim tone and a rule line, all read from the live system
// colours so the whole app follows the OS theme - light, dark
// and high contrast - and never diverges from the main window.
//
// High contrast is detected explicitly because under HC the
// system palette is already chosen for maximum contrast and must
// be used verbatim; a window that overlaid its own dark or light
// substitute on an HC scheme produced unreadable text.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace wintcp {

// True when a high-contrast scheme is active.  Was duplicated in
// MainWindow.cpp and DetailsDialog.cpp; now shared so the two (and
// any new self-painting window) cannot drift apart.
inline bool HighContrastActive() {
    HIGHCONTRASTW hc = {};
    hc.cbSize = sizeof(hc);
    if (::SystemParametersInfoW(SPI_GETHIGHCONTRAST, sizeof(hc),
                                    &hc, 0) == 0)
        return false;
    return (hc.dwFlags & HCF_HIGHCONTRASTON) != 0;
}

// True when the system window background is a dark colour, i.e. the
// OS is in dark mode.  Derived from the live colour rather than a
// registry key so it is always in step with GetSysColor.
inline bool SystemIsDark() {
    const COLORREF bg = ::GetSysColor(COLOR_WINDOW);
    return (GetRValue(bg) + GetGValue(bg) + GetBValue(bg)) < 384;
}

// The live base palette for a self-painting window.  `grid` is a
// subtle rule line: a faint blend of the background toward the
// foreground, tuned per scheme so it reads on both light and dark
// backgrounds (the same shade the charts drew before they moved to
// the shared derivation).
struct SystemPalette {
    COLORREF bg;
    COLORREF fg;
    COLORREF dim;
    COLORREF grid;
};

inline SystemPalette LivePalette() {
    SystemPalette p;
    p.bg = ::GetSysColor(COLOR_WINDOW);
    p.fg = ::GetSysColor(COLOR_WINDOWTEXT);
    p.dim = ::GetSysColor(COLOR_GRAYTEXT);
    // Blend background toward foreground: ~15% in light mode
    // (a hair-line on white), ~20% in dark (a faint rule on the
    // dark surface).  High contrast falls out of GetSysColor on
    // its own - the system already supplies a contrasting pair.
    const int t = SystemIsDark() ? 52 : 39;
    p.grid = RGB(
        (GetRValue(p.bg) * (256 - t) + GetRValue(p.fg) * t) / 256,
        (GetGValue(p.bg) * (256 - t) + GetGValue(p.fg) * t) / 256,
        (GetBValue(p.bg) * (256 - t) + GetBValue(p.fg) * t) / 256);
    return p;
}

// The shared dark substitutes. Every self-painting window used to
// carry its own copy of 0x202020/0xF0F0F0 plus its own dim/header/grid -
// identical values, three spellings, so a tweak to one never reached the
// others. One spelling now: a dark window reads these, a light or
// high-contrast one reads LivePalette() above, and HighContrastActive()
// bypasses both in favour of the verbatim system colours.
constexpr COLORREF kSharedDarkBg = RGB(0x20, 0x20, 0x20);
constexpr COLORREF kSharedDarkFg = RGB(0xF0, 0xF0, 0xF0);
constexpr COLORREF kSharedDarkDim = RGB(0x9A, 0x9A, 0x9A);
constexpr COLORREF kSharedDarkHeader = RGB(0xFF, 0xFF, 0xFF);
constexpr COLORREF kSharedDarkGrid = RGB(0x4A, 0x4A, 0x4A);

// Mix two colours; t=0 -> a, t=255 -> b. The one derivation every tinted
// brush in the app shares, so an alternating-row stripe or a section band
// in one window is the same blend as the same stripe in another.
inline COLORREF Mix(COLORREF a, COLORREF b, int t) {
    const int r = (GetRValue(a) * (255 - t) + GetRValue(b) * t) / 255;
    const int g = (GetGValue(a) * (255 - t) + GetGValue(b) * t) / 255;
    const int bl = (GetBValue(a) * (255 - t) + GetBValue(b) * t) / 255;
    return RGB(r, g, bl);
}

}  // namespace wintcp
