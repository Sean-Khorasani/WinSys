// Presets.h
// SPDX-License-Identifier: Apache-2.0
// Saved views: the filter text, the visible-column mask, the sort column and
// direction, and the data-source toggles, stored per name under
// HKCU\Software\WinTCP\Presets\<name>.
//
// A preset is a settings store, not a scratch file. The registry has no undo,
// so nothing in here ever destroys a saved view implicitly: Save refuses to
// replace an existing name unless the caller says so, and reports which of
// the two happened.

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

#include "ColumnsWin.h"   // ClampVisibleCols (used by Save)
#include "ViewState.h"   // PresetView, PresetSource

namespace wintcp {

// The captured view is a ViewState; PresetView is an alias for it.
//
// It used to be declared here as a separate struct, which is how a view ended
// up described twice: once in MainWindow's members and once here, with nothing
// keeping them equal. That is the same fault that shipped GeoIP and 5.1
// grouping as fully-tested dead code, so the second description is now gone
// rather than kept in sync. See ViewState.h.
//
// This header is the registry storage for a view, not its definition: what a
// view IS lives in ViewState.h, and what a preset persists lives in the
// kVal* schema below.

// Why a Save returned what it returned.
//
// The split between kExists and kOverwrote is the whole point of the
// contract, so it is worth being precise about it:
//
//   * Save() with the default argument NEVER writes over an existing preset.
//     On a name collision it writes nothing at all and returns kExists. The
//     caller decides - normally by asking the user - and then repeats the
//     call with allowOverwrite = true.
//
//   * kOverwrote is a *report*, not an error: it is returned only when the
//     caller has already opted in to replacing. A caller that has confirmed
//     the replacement treats it as success.
//
// So a caller that forgets the confirm cannot lose a view, and a caller that
// has performed it still gets told which of created/overwritten happened for
// its status text and change log. The alternative - Save always writing and
// merely *reporting* the collision - leaves the safety dependent on every
// call site remembering a prior Exists() check, which is exactly the kind of
// thing that survives a refactor and then eats somebody's saved view.
enum class PresetSave {
    kCreated,       // a new preset was written
    kOverwrote,     // an existing preset was replaced (only if allowed)
    kExists,        // nothing was written: the name is taken
    kInvalidName,   // nothing was written: the name is not usable
    kFailed,        // registry error
};

// A preset name is rejected when it is empty, when it contains a backslash
// (which would silently create a subkey the user did not ask for), when it
// is longer than this, when it contains a control character (legal in a
// registry key, invisible in a dialog), or when it contains a NUL (the
// registry would truncate there and the caller's own name would then not
// match the key that got written). Surrounding whitespace is stripped
// instead of rejected, so "foo " cannot become a second, near-invisible
// preset next to "foo".
constexpr size_t kMaxPresetNameChars = 64;

// Longest filter a preset can hold. Matches Settings::filter, so a preset can
// carry exactly what the filter box can - and nothing more, so an
// over-registered string is reported as corrupt instead of truncated.
constexpr size_t kMaxPresetFilterChars = 512;

struct Presets {
    // Write 'view' under 'name'. Nothing is written when the name is invalid
    // or already taken (see PresetSave).
    static PresetSave Save(const std::wstring& name, const PresetView& view,
                           bool allowOverwrite = false);

    // Read a preset back. All-or-nothing: a preset whose schema version is
    // missing, unknown, or whose values are the wrong type / the wrong size /
    // absurdly long fails as a whole rather than loading half a view the
    // user never saved. On failure '*out' is left untouched. 'out' may be
    // null, which makes this a pure existence-and-integrity test.
    static bool Load(const std::wstring& name, PresetView* out);

    // Remove a preset. Returns true when no preset of that name exists
    // afterwards, which includes the case where it never did: deleting
    // something that is not there is not an error.
    static bool Delete(const std::wstring& name);

    // Names of every stored preset, sorted. Empty when none exist.
    static std::vector<std::wstring> List();

    // Registry-level existence (case-insensitive, as the registry is).
    static bool Exists(const std::wstring& name);

    // False for a name Save and Delete would refuse.
    static bool IsValidName(const std::wstring& name);

    // The name after the whitespace strip IsValidName applies, or L"" when
    // the name is not usable. Every path build goes through this so that
    // Save/Load/Delete/Exists can never disagree about which key is meant.
    static std::wstring CanonicalName(const std::wstring& name);
};

// Message-box text for a PresetSave result.
const wchar_t* PresetSaveToString(PresetSave result);

}  // namespace wintcp
