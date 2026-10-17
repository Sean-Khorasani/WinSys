// SPDX-License-Identifier: Apache-2.0
// FontCache.h
// One font per (DPI, point size, weight, family) for the whole process.
//
// WHY IT EXISTS: three top-level windows - the main window, the Details sheet and
// the charts window - each built their own GDI fonts. That is a DPI-change hazard
// in three directions rather than one: every window has to know it must rebuild,
// a window created before a DPI change starts life with the wrong metrics, and the
// details window holds a *copy* of the main window's handle that a rebuild must
// chase down or it dangles.
//
// The fix is not to be more careful in three places. It is for nobody to own a
// font: a caller asks for a HFONT and does NOT delete it, because the cache owns
// every handle it hands out and releases them all in one place when the DPI
// changes. A caller that deletes a cached handle breaks every other window.
//
// Lifetime: the cache is process-wide and never freed explicitly. GDI fonts are
// released by the process teardown, and a singleton that must be destroyed at
// exit would have to run after every window is gone - which is exactly the ordering
// that cannot be expressed.
//
// Not a GDI object leak: the handles are cached, not created per call. The bound
// is the number of distinct (DPI, size, weight, family) tuples the UI actually
// asks for, which is a handful.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <utility>
#include <vector>

// The nominal point size of the app's body text, in one place so the three
// windows that used to hard-code 9 in their own LOGFONT cannot drift.
constexpr int kBodyPtSize = 9;

namespace wintcp {

class FontCache {
public:
    // The one instance. Constructed on first use; safe to call from any thread
    // that owns a window, which is every thread that asks for a font.
    static FontCache& Get();

    // A UI font. 'ptSize' is the nominal point size (kBodyPtSize for the app's body
    // text); the pixel height is derived from 'dpi' at the moment of the request,
    // which is what makes a per-monitor DPI change correct without the caller
    // knowing anything about scaling.
    //
    // 'dpi' is the caller's OWN monitor DPI, not the system's. A window on a 144dpi
    // monitor must not be handed a font measured at 96, and the cache has no way to
    // know which monitor a window is on. Callers use the same
    // QueryDpiForWindow(hwnd) they already use for layout.
    //
    // 'mono' selects a fixed-pitch face for the bytes/hex columns, which must not
    // be laid out in a proportional font or the columns do not line up.
    HFONT Get(int ptSize, int weight, unsigned dpi, bool mono = false);

    // The system DPI, for a caller with no window yet. GetDeviceCaps rather than
    // GetDpiForSystem: the project targets _WIN32_WINNT 0x0601, where
    // GetDpiForSystem does not exist, and the device-cap is the same answer for the
    // classic case this is used for.
    static unsigned SystemDpi();

    // Drop every cached handle. Call on WM_DPICHANGED, before rebuilding any
    // window's layout: the next Get() recreates at the new DPI, so a window that
    // rebuilds after this call is correct by construction.
    //
    // Ordering matters and is the caller's responsibility. A window that rebuilds
    // its font BEFORE calling this keeps the old handle and the old metrics, which
    // is the bug this cache exists to remove.
    void OnDpiChanged();

private:
    FontCache() = default;

    // A handle is identified by everything that goes into the LOGFONT that
    // produced it. Two of the four keys are redundant with 'dpi' having already
    // decided the height, but keeping them makes the key honest about what it
    // indexes, and stops a future "why is my bold font the regular one".
    struct Key {
        unsigned dpi;
        int ptSize;
        int weight;
        bool mono;
        bool operator==(const Key& o) const {
            return dpi == o.dpi && ptSize == o.ptSize && weight == o.weight &&
                   mono == o.mono;
        }
    };
    struct Hash {
        size_t operator()(const Key& k) const;
    };

    HFONT Create(const Key& k) const;

    // std::unordered_map would drag <unordered_map> into every translation unit
    // that includes this header; a sorted vector of a handful of entries is
    // faster to look at and has no such cost.
    std::vector<std::pair<Key, HFONT>> cache_;
};

}  // namespace wintcp
