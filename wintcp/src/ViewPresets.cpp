// ViewPresets.cpp
// SPDX-License-Identifier: Apache-2.0
// See ViewPresets.h.

#include "ViewPresets.h"

#include <climits>
#include <commctrl.h>
#include <vector>

#include "PromptDialog.h"
#include "WinCaps.h"

namespace wintcp {

std::wstring ViewPresetDialogs::Choose(const wchar_t* title,
                                       const wchar_t* question) {
    const std::vector<std::wstring> names = Presets::List();
    if (names.empty()) {
        ::MessageBoxW(owner_, L"No saved presets yet.", title,
                      MB_OK | MB_ICONINFORMATION);
        return std::wstring();
    }
    if (names.size() > static_cast<size_t>(INT_MAX - 1000) ||
        !DelayLoadGuard(owner_, "comctl32.dll"))
        return std::wstring();

    std::vector<TASKDIALOG_BUTTON> choices;
    choices.reserve(names.size());
    for (size_t i = 0; i < names.size(); ++i)
        choices.push_back({1000 + static_cast<int>(i), names[i].c_str()});

    TASKDIALOGCONFIG config = {};
    config.cbSize = sizeof(config);
    config.hwndParent = owner_;
    config.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION;
    config.pszWindowTitle = title;
    const std::wstring instruction = std::wstring(L"Choose a preset to ") + question;
    config.pszMainInstruction = instruction.c_str();
    config.pszContent = L"Choose a saved view:";
    config.pRadioButtons = choices.data();
    config.cRadioButtons = static_cast<UINT>(choices.size());
    config.nDefaultRadioButton = choices.front().nButtonID;
    config.dwCommonButtons = TDCBF_OK_BUTTON | TDCBF_CANCEL_BUTTON;

    int button = 0;
    int selected = 0;
    if (::TaskDialogIndirect(&config, &button, &selected, nullptr) != S_OK ||
        button != IDOK || selected < 1000)
        return std::wstring();
    const size_t index = static_cast<size_t>(selected - 1000);
    return index < names.size() ? names[index] : std::wstring();
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
