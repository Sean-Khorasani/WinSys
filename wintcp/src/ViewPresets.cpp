// ViewPresets.cpp
// SPDX-License-Identifier: Apache-2.0
// See ViewPresets.h.

#include "ViewPresets.h"

#include <algorithm>

#include "PromptDialog.h"   // PromptForText

namespace wintcp {

std::wstring ViewPresetDialogs::NumberedList(
    const std::vector<std::wstring>& names, const wchar_t* question) {
    const size_t kShownPresets = 12;
    std::wstring text = std::wstring(L"Type the number of the preset to ") +
                        question + L":\r\n\r\n";
    for (size_t i = 0; i < names.size() && i < kShownPresets; ++i)
        text += std::to_wstring(i + 1) + L".  " + names[i] + L"\r\n";
    if (names.size() > kShownPresets)
        text += L"... and " + std::to_wstring(names.size() - kShownPresets) +
                L" more (type its number anyway)\r\n";
    return text;
}

size_t ViewPresetDialogs::ParseIndex(const std::wstring& answer, size_t count) {
    if (answer.empty() || answer.size() > 4) return 0;
    for (wchar_t c : answer)
        if (c < L'0' || c > L'9') return 0;
    size_t idx = 0;
    for (wchar_t c : answer) idx = idx * 10 + static_cast<size_t>(c - L'0');
    if (idx == 0 || idx > count) return 0;
    return idx;
}

std::wstring ViewPresetDialogs::Choose(const wchar_t* title,
                                       const wchar_t* question) {
    const std::vector<std::wstring> names = Presets::List();
    if (names.empty()) {
        ::MessageBoxW(owner_, L"No saved presets yet.", title,
                      MB_OK | MB_ICONINFORMATION);
        return std::wstring();
    }
    // A numbered list rather than a combo: with more than a handful of
    // presets a list box scrolls, and the numbers double as a way to refer to
    // one in the message box.
    const std::wstring text = NumberedList(names, question);
    std::wstring answer;
    if (!PromptForText(owner_, title, text.c_str(), L"1", 8, &answer))
        return std::wstring();
    const size_t idx = ParseIndex(answer, names.size());
    if (idx == 0) {
        // One message for both ways this fails: a field that is not a number
        // and a number past the end. Telling them apart would only produce a
        // longer message that says the same thing - retry.
        ::MessageBoxW(owner_, L"Enter just the number of a preset.", title,
                      MB_OK | MB_ICONERROR);
        return std::wstring();
    }
    return names[idx - 1];
}

void ViewPresetDialogs::Save() {
    std::wstring name;
    if (!PromptForText(owner_, L"Save view as preset", L"Preset name:", L"",
                       kMaxPresetNameChars, &name))
        return;
    // Presets::Save refuses to overwrite by default and says so. The confirm
    // is done HERE, not inside the store, so the store stays a dumb
    // persistence layer that cannot show UI.
    PresetSave result = Presets::Save(name, current_());
    if (result == PresetSave::kExists) {
        const std::wstring msg = L"A preset named '" + name +
                                 L"' already exists.\r\n\r\nReplace it?";
        if (::MessageBoxW(owner_, msg.c_str(), L"Save preset",
                          MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES)
            return;
        result = Presets::Save(name, current_(), true);
    }
    switch (result) {
        case PresetSave::kCreated:
            ::MessageBoxW(owner_, L"View saved.", L"Save preset",
                          MB_OK | MB_ICONINFORMATION);
            break;
        case PresetSave::kOverwrote:
            ::MessageBoxW(owner_, L"View replaced.", L"Save preset",
                          MB_OK | MB_ICONINFORMATION);
            break;
        case PresetSave::kInvalidName:
            ::MessageBoxW(owner_,
                          L"That name cannot be used. It must be 1-"
                          L"64 characters, with no backslash or control "
                          L"characters.",
                          L"Save preset", MB_OK | MB_ICONERROR);
            break;
        case PresetSave::kFailed:
            ::MessageBoxW(owner_, L"Could not write the preset to the registry.",
                          L"Save preset", MB_OK | MB_ICONERROR);
            break;
        case PresetSave::kExists:
            break;   // user declined the replace; not an error
    }
}

void ViewPresetDialogs::Load() {
    const std::wstring name = Choose(L"Load preset", L"load");
    if (name.empty()) return;
    PresetView v;
    if (!Presets::Load(name, &v)) {
        // All-or-nothing load: a partially readable preset is reported as a
        // failure rather than applied, because half a view is a state the
        // user never saved and cannot get back to.
        ::MessageBoxW(owner_,
                      L"That preset could not be read. It may be corrupt or "
                      L"from a newer version.",
                      L"Load preset", MB_OK | MB_ICONERROR);
        return;
    }
    apply_(v);
}

void ViewPresetDialogs::Delete() {
    const std::wstring name = Choose(L"Delete preset", L"delete");
    if (name.empty()) return;
    // Deleting a saved view is irreversible, so it gets a confirm naming the
    // preset. A typo must not cost the user a view they built.
    const std::wstring msg = L"Delete the preset '" + name + L"'?";
    if (::MessageBoxW(owner_, msg.c_str(), L"Delete preset",
                      MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES)
        return;
    if (!Presets::Delete(name))
        ::MessageBoxW(owner_, L"Could not delete the preset.", L"Delete preset",
                      MB_OK | MB_ICONERROR);
}

}  // namespace wintcp
