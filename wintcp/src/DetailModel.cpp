// DetailModel.cpp
// SPDX-License-Identifier: Apache-2.0
// See DetailModel.h. The only non-trivial logic here is the plain-text
// rendering used by the Copy button, which must agree with what the window
// draws closely enough that a pasted details block is not misleading.

#include "DetailModel.h"

#include <algorithm>

namespace wintcp {
namespace {

// Width of the "YYYY-MM-DD HH:MM:SS" text, plus NUL. Same fixed format as the
// window's own timestamp cell, and swprintf_s truncates rather than overruns.
constexpr size_t kLocalTimeChars = 32;

// Column the plain-text renderer pads labels to, so the Copy button produces
// something that lines up in a monospace editor. A fixed width rather than the
// longest label seen, because the widest label is data-dependent and a sheet
// whose indentation moves as content changes looks broken - the same reasoning
// as BuildInfo.cpp's kKeyColumn.
constexpr size_t kPlainTextLabelChars = 22;

}  // namespace

std::wstring FormatFileTimeLocal(const FILETIME& ft, bool known) {
    if (!known) return std::wstring();
    FILETIME local = {};
    SYSTEMTIME st = {};
    if (!::FileTimeToLocalFileTime(&ft, &local)) return std::wstring();
    if (!::FileTimeToSystemTime(&local, &st)) return std::wstring();
    wchar_t buf[kLocalTimeChars] = {0};
    ::swprintf_s(buf, L"%04u-%02u-%02u %02u:%02u:%02u",
                 static_cast<unsigned>(st.wYear), static_cast<unsigned>(st.wMonth),
                 static_cast<unsigned>(st.wDay), static_cast<unsigned>(st.wHour),
                 static_cast<unsigned>(st.wMinute), static_cast<unsigned>(st.wSecond));
    return buf;
}

std::wstring DetailModel::ToPlainText() const {
    std::wstring out;
    if (!title.empty()) {
        out += title;
        out += L"\r\n";
    }
    if (!subtitle.empty()) {
        out += subtitle;
        out += L"\r\n";
    }
    if (!out.empty()) out += L"\r\n";

    for (const DetailSection& sec : sections) {
        out += sec.title;
        out += L"\r\n";
        for (const DetailField& f : sec.fields) {
            // Pad the label so values line up in a monospace viewer; the
            // pad is applied to the label, not the value, so a value with
            // an em-dash still reads as "this value is unknown".
            std::wstring label = f.label;
            while (label.size() < kPlainTextLabelChars) label += L' ';
            out += label;
            out += L"  ";
            out += f.value.empty() ? L"—" : f.value;
            out += L"\r\n";
        }
        if (!sec.note.empty()) {
            out += L"  ";
            out += sec.note;
            out += L"\r\n";
        }
        out += L"\r\n";
    }

    if (!connectionLines.empty()) {
        out += L"Connections (" + std::to_wstring(connectionTotal) +
               L")\r\n";
        for (const std::wstring& line : connectionLines) {
            out += L"  ";
            out += line;
            out += L"\r\n";
        }
        if (connectionTotal > connectionLines.size()) {
            out += L"  … and " +
                   std::to_wstring(connectionTotal - connectionLines.size()) +
                   L" more\r\n";
        }
    }
    return out;
}

// tab vocabulary, exposed so the renderer and selftests share one
// definition and a renamed tab is caught immediately. The order matches the
// enum - the renderer walks DetailTab in ascending ordinal and skips tabs
// that have no section, which is how an uncached TLS row simply drops the
// Security tab instead of showing an empty one.
const wchar_t* TabLabel(DetailTab t) {
    switch (t) {
        case kTabProcess:    return L"Process";
        case kTabConnection: return L"Connection";
        case kTabSockets:    return L"Sockets";
        case kTabSecurity:   return L"Security";
        case kTabNotes:      return L"Notes";
        default:             return L"—";
    }
}

std::vector<DetailTab> AvailableDetailTabs(const DetailModel& model) {
    std::vector<DetailTab> tabs;
    for (unsigned ordinal = 0; ordinal < kTabCount; ++ordinal) {
        const DetailTab tab = static_cast<DetailTab>(ordinal);
        const bool available =
            tab == kTabSockets
                ? !model.connectionLines.empty()
                : std::any_of(model.sections.begin(), model.sections.end(),
                              [tab](const DetailSection& section) {
                                  return section.tab == tab;
                              });
        if (available) tabs.push_back(tab);
    }
    return tabs;
}

}  // namespace wintcp
