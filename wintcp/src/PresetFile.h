// PresetFile.h
// SPDX-License-Identifier: Apache-2.0
// preset export and import.
//
// The sibling of BookmarkFile: a preset is a ViewState, and ViewState is a
// value, so a preset file is a value too. That is what makes the codec pure -
// no registry, no store, no window - which is what lets the file format be
// pinned by tests rather than by trying it.
//
// Same design and the same refusal rules as the bookmark file, and for the
// same reasons. The reader is STRICT rather than general: a parser that
// accepts anything accepts a malformed file, and loading half of a preset
// leaves a view the user never saved - which is worse than refusing, because
// it is subtle and it is *believed*.

#pragma once

#include <string>
#include <vector>

#include "ViewState.h"

namespace wintcp {

// Schema version. Bumping it is the only sanctioned way to change what the
// file means.
constexpr int kPresetFileVersion = 1;

// Bounds, the same shape and the same refusal as the bookmark file's: over
// either, the file is refused in full so "unknown" never looks like "you have
// no view".
constexpr size_t kPresetFileMaxBytes = 4u * 1024u * 1024u;
constexpr size_t kPresetFileMaxRecords = 100000u;

// One preset plus its name. ViewState has no name of its own, because a name
// is a storage concept rather than a view concept.
struct PresetRecord {
    std::wstring name;
    ViewState view;
};

// Write 'items' as a Version=1 JSON document. Pure, and deterministic: same
// input, same bytes, so a file exported twice does not diff.
void SerialisePresets(const std::vector<PresetRecord>& items,
                      std::string* out);

// Read a Version=1 JSON document. All-or-nothing, like the bookmark file: on
// failure '*out' is left untouched and 'error' says why.
//
// Refuses, with a reason, for: invalid JSON; a missing/unknown/non-numeric
// version; a record that is not an object; one missing a field or carrying
// one of the wrong type; a name that is empty or invalid as a preset name
// (Presets::IsNameUsable is the authority here, not a second spelling of the
// rule); a column mask or sort column outside the table's range; a filter over
// kMaxPresetFilterChars; and either size bound above.
bool ParsePresets(const std::string& text, std::vector<PresetRecord>* out,
                  std::wstring* error);

}  // namespace wintcp
