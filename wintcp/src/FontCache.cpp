// SPDX-License-Identifier: Apache-2.0
// FontCache.cpp
// See FontCache.h. The whole implementation is one map lookup and one
// CreateFontIndirect, and the interesting part is what it does NOT do: it never
// returns a handle the caller has to release.

#include "FontCache.h"

#include <algorithm>
#include <vector>

namespace wintcp {
namespace {

// DPI used when the screen reports none. USER_DEFAULT_SCREEN_DPI - the value
// GetDeviceCaps(LOGPIXELSY) answers on a machine with no DPI virtualisation -
// so a fallback to it is indistinguishable from a real reading on such a
// machine. Same name as Utils.cpp's copy on purpose, so a grep finds both.
constexpr unsigned kDefaultScreenDpi = 96;

}  // namespace

FontCache& FontCache::Get() {
    // Function-local static: constructed on first use, before any window asks for
    // a font, and never destroyed - see the lifetime note in the header.
    static FontCache instance;
    return instance;
}

size_t FontCache::Hash::operator()(const Key& k) const {
    // The DPI is the only field with real spread; the rest are small enumerations
    // of the UI's actual vocabulary. Shifting them apart keeps distinct tuples
    // apart without anything clever.
    size_t h = static_cast<size_t>(k.dpi) * 2654435761u;
    h ^= static_cast<size_t>(k.ptSize) * 40503u;
    h ^= static_cast<size_t>(k.weight) * 2246822519u;
    h ^= k.mono ? 0x9E3779B9u : 0u;
    return h;
}

unsigned FontCache::SystemDpi() {
    // USER_DEFAULT_SCREEN_DPI on the default DC is what GetDeviceCaps answers,
    // and 96 is its value on a machine with no DPI virtualisation at all.
    if (HDC dc = ::GetDC(nullptr)) {
        const int x = ::GetDeviceCaps(dc, LOGPIXELSX);
        const int y = ::GetDeviceCaps(dc, LOGPIXELSY);
        ::ReleaseDC(nullptr, dc);
        if (x > 0 && y > 0) return static_cast<unsigned>((x + y) / 2);
    }
    return kDefaultScreenDpi;
}

HFONT FontCache::Get(int ptSize, int weight, unsigned dpi, bool mono) {
    if (dpi == 0) dpi = SystemDpi();
    // The DPI is the only field with real spread; the rest are small enumerations
    Key k{dpi, ptSize, weight, mono};
    for (const auto& e : cache_) {
        if (e.first == k) return e.second;
    }
    HFONT f = Create(k);
    if (f == nullptr) {
        // Out of GDI memory, or a face the system refused. A nullptr is honest:
        // the caller falls back to DEFAULT_GUI_FONT, which is what it would have
        // done with no cache at all.
        return nullptr;
    }
    cache_.push_back({k, f});
    return f;
}

void FontCache::OnDpiChanged() {
    // One loop, one place. This is the whole point: before the cache, three
    // windows each had to get this right, and each had its own list of handles to
    // release plus one cross-window copy to chase.
    for (const auto& e : cache_) {
        if (e.second != nullptr) ::DeleteObject(e.second);
    }
    cache_.clear();
}

HFONT FontCache::Create(const Key& k) const {
    LOGFONTW lf = {};
    lf.lfHeight = -::MulDiv(k.ptSize, static_cast<int>(k.dpi), 72);
    lf.lfWeight = k.weight;
    lf.lfCharSet = DEFAULT_CHARSET;
    lf.lfOutPrecision = OUT_DEFAULT_PRECIS;
    lf.lfClipPrecision = CLIP_DEFAULT_PRECIS;
    // A monospace face has to be asked for by name: DEFAULT_PITCH picks
    // whatever the mapper likes, which on some systems is a proportional font
    // that renders the byte columns unreadable.
    lf.lfQuality = CLEARTYPE_QUALITY;
    lf.lfPitchAndFamily = k.mono ? (FIXED_PITCH | FF_MODERN)
                                : DEFAULT_PITCH;
    ::wcscpy_s(lf.lfFaceName, k.mono ? L"Consolas" : L"Segoe UI");
    return ::CreateFontIndirectW(&lf);
}

}  // namespace wintcp
