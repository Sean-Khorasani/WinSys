// ConnectionsList.cpp
// SPDX-License-Identifier: Apache-2.0
// See ConnectionsList.h.

#include "ConnectionsList.h"

#include <unordered_map>

#include "DnsResolver.h"    // kPendingHost
#include "Freeze.h"         // FrozenAgeMs
#include "MainWindowInternal.h"   // kColumns, kMaxColumnText, kMsPerSecond
#include "Utils.h"          // FormatBytes, FormatDuration

namespace wintcp {

// The shared constants and helpers come from MainWindowInternal.h in
// namespace wintcp::mw; brought in unqualified because that is how every call
// site reads.
using namespace mw;

namespace {

// Row-colour flashes. The colours are chosen per theme: on a dark theme the
// pastel fills would glare, so a darker background and a light foreground are
// used instead.
struct RowColours {
    COLORREF background;
    COLORREF text;
    bool textSet;
};

RowColours FlashColours(std::uint32_t flags, bool dark) {
    if ((flags & kRowRemoved) != 0) {
        return dark ? RowColours{RGB(0x4A, 0x1F, 0x1F), RGB(0xFF, 0xB4, 0xB4), true}
                    : RowColours{RGB(0xF8, 0xC8, 0xC8), RGB(0x7A, 0x1F, 0x1F), true};
    }
    if ((flags & kRowNew) != 0) {
        return dark ? RowColours{RGB(0x1C, 0x4A, 0x1C), RGB(0xB4, 0xFF, 0xB4), true}
                    : RowColours{RGB(0xD6, 0xF5, 0xD6), 0, false};
    }
    if ((flags & kRowChanged) != 0) {
        return dark ? RowColours{RGB(0x4A, 0x42, 0x1A), RGB(0xFF, 0xFF, 0xB4), true}
                    : RowColours{RGB(0xF8, 0xF0, 0xB8), 0, false};
    }
    // The retained ghost: a socket that vanished an earlier refresh, kept
    // grey for the rest of its life so the table keeps a short history.
    return dark ? RowColours{RGB(0x2B, 0x2B, 0x2B), RGB(0xC0, 0xC0, 0xC0), true}
                : RowColours{RGB(0xEA, 0xEA, 0xEA), RGB(0x5A, 0x5A, 0x5A), true};
}

// The faint banding shade for an unmarked odd row.
COLORREF BandColour(bool dark) {
    return dark ? RGB(0x26, 0x26, 0x26) : RGB(0xF5, 0xF5, 0xF5);
}

}  // namespace

bool ConnectionsList::Create(HWND parent, HINSTANCE instance) {
    // Virtual list view: rows are supplied by LVN_GETDISPINFO from the
    // store, so refreshes never destroy/recreate items.
    //
    // LVS_SHAREIMAGELISTS is load-bearing with the system icon list:
    // without it the list view DESTROYS the image list assigned via
    // LVM_SETIMAGELIST when it is itself destroyed - and that list is the
    // shell's shared system list, not ours to destroy.
    const DWORD style = WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT |
                        LVS_OWNERDATA | LVS_SHOWSELALWAYS | WS_CLIPCHILDREN |
                        WS_VSCROLL | WS_HSCROLL | LVS_SHAREIMAGELISTS;
    hwnd_ = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"", style,
                              0, 0, 0, 0, parent,
                              reinterpret_cast<HMENU>(IDC_LIST), instance,
                              nullptr);
    if (hwnd_ == nullptr) return false;
    ::SendMessageW(hwnd_, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
                   LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES |
                       LVS_EX_DOUBLEBUFFER | LVS_EX_HEADERDRAGDROP |
                       LVS_EX_LABELTIP | LVS_EX_INFOTIP | LVS_EX_TRACKSELECT);
    ::SendMessageW(hwnd_, LVM_SETITEMCOUNT, 0, 0);
    return true;
}

void ConnectionsList::SetItemCount(size_t count) {
    if (hwnd_ == nullptr) return;
    ::SendMessageW(hwnd_, LVM_SETITEMCOUNT, static_cast<WPARAM>(count),
                   LVSICF_NOINVALIDATEALL);
}

void ConnectionsList::Invalidate() {
    if (hwnd_ != nullptr) ::InvalidateRect(hwnd_, nullptr, TRUE);
}

std::optional<LRESULT> ConnectionsList::HandleNotify(const NMHDR* hdr) {
    if (hdr == nullptr || hdr->hwndFrom != hwnd_) return std::nullopt;
    switch (hdr->code) {
        case LVN_GETDISPINFO:
            OnGetDispInfo(reinterpret_cast<NMLVDISPINFO*>(
                const_cast<NMHDR*>(hdr)));
            return 0;
        case LVN_COLUMNCLICK: {
            const auto* click = reinterpret_cast<const NMLISTVIEW*>(hdr);
            bool asc = true;
            if (click->iSubItem == store_.SortColumn())
                asc = !store_.SortAscending();
            sink_.OnSortByColumn(click->iSubItem, asc);
            return 0;
        }
        case NM_DBLCLK:
            sink_.OnRowActivated();
            return 0;
        case LVN_GETINFOTIP:
            OnGetInfoTip(reinterpret_cast<NMLVGETINFOTIPW*>(
                const_cast<NMHDR*>(hdr)));
            return 0;
        case LVN_BEGINDRAG:
            // The order is read back on a posted message, not here: at this
            // point the header still holds the OLD order. Returning TRUE
            // permits the drag - FALSE would block it, and the drag is the
            // only way to reorder the columns.
            sink_.OnColumnDragStarted();
            return 1;
        case NM_CUSTOMDRAW:
            return OnCustomDraw(reinterpret_cast<NMLVCUSTOMDRAW*>(
                const_cast<NMHDR*>(hdr)));
        default:
            return std::nullopt;
    }
}

void ConnectionsList::OnGetDispInfo(NMLVDISPINFO* di) {
    const size_t viewIdx = static_cast<size_t>(di->item.iItem);
    const Connection* c = store_.ViewRow(viewIdx);
    // The icon is requested on its own (LVIF_IMAGE) when
    // the list paints a row's image, independently of the
    // text, so it is answered before the text-only
    // early-out below.
    if (c != nullptr && (di->item.mask & LVIF_IMAGE) != 0) {
        di->item.iImage = sink_.ProcessIconIndex(c->display.processPath);
    }
    if ((di->item.mask & LVIF_TEXT) == 0) return;
    dispBuf_[0] = L'\0';
    if (c != nullptr) {
        // The control notifies with the VISIBLE index (iSubItem is the header's own
// position), so the mapping runs the other way from the menu path: visible
// index -> ColumnId. Using ColToVisible here compiles, reads correctly, and
// returns garbage - it answers "which visible slot is THIS ColumnId in", so
// every cell is drawn with a different column's text.
const int col = cols_.VisibleToCol(di->item.iSubItem);
        if (col >= 0) {
            // when the view is grouped, a row is a process, not
            // a connection. The aggregate columns show the group's
            // totals; everything else falls through to the underlying
            // connection so addresses, state and ids stay real.
            if (const ProcessGroup* g = store_.ViewGroup(viewIdx)) {
                if (wintcp::GroupColumnText(*g, col, dispBuf_, kMaxColumnText)) {
                    di->item.pszText = dispBuf_;
                    return;
                }
            }
            ConnectionStore::GetColumnText(*c, col, dispBuf_, kMaxColumnText);
        }
    }
    di->item.pszText = dispBuf_;
}

void ConnectionsList::OnGetInfoTip(NMLVGETINFOTIPW* info) {
    // full-value tooltips.
    //
    // The compact columns are abbreviated to fit their width, so a
    // 12-digit byte count or a long path is elided with an ellipsis
    // the reader cannot expand. The tooltip shows the value in full,
    // one item per line, for the columns where truncation actually
    // loses information.
    const int col = cols_.ColToVisible(info->iSubItem);
    const Connection* c = store_.ViewRow(static_cast<size_t>(info->iItem));
    if (col < 0 || c == nullptr) return;

    std::wstring tip;
    const auto add = [&tip](const wchar_t* label,
                            const std::wstring& value) {
        if (!tip.empty()) tip += L"\r\n";
        tip += label;
        tip += L": ";
        tip += value;
    };
    const auto bps = [](double v) {
        wchar_t b[48] = {0};
        ::swprintf_s(b, L"%.1f B/s", v);
        return std::wstring(b);
    };

    switch (col) {
        case COL_TRAFFIC:
            // The cell reads "1.2 MB / 340 kB"; the tooltip separates
            // the directions and names them, because "which way is
            // this?" is the question the compact form raises.
            add(L"Received", FormatBytes(c->traffic.trafficRx));
            add(L"Sent", FormatBytes(c->traffic.trafficTx));
            if (c->display.hostname == DnsResolver::kPendingHost)
                add(L"Host", L"(resolving...)");
            else if (!c->display.hostname.empty())
                add(L"Host", c->display.hostname);
            break;
        case COL_BANDWIDTH:
            if (c->rate.bpsKnown) {
                add(L"Down", bps(c->rate.rxBps));
                add(L"Up", bps(c->rate.txBps));
            } else {
                // Say WHY there is no figure instead of showing an
                // em-dash that reads as "zero traffic".
                add(L"Speed", L"not available (no counter source running)");
            }
            break;
        case COL_PATH:
            if (!c->display.processPath.empty()) add(L"Path", c->display.processPath);
            else add(L"Path", L"(not available)");
            break;
        case COL_HOST:
            if (c->display.hostname == DnsResolver::kPendingHost)
                add(L"Host", L"(resolving...)");
            else if (!c->display.hostname.empty())
                add(L"Host", c->display.hostname);
            else
                add(L"Host", L"(not resolved)");
            break;
        default:
            return;   // nothing truncated to explain
    }
    if (tip.empty()) return;
    // LVN_GETINFOTIP must return a pointer the control frees with
    // LocalFree. A std::wstring's buffer would be freed wrongly and
    // corrupt the heap - this is the single most important detail in
    // implementing this notification.
    const size_t bytes = (tip.size() + 1) * sizeof(wchar_t);
    wchar_t* out = static_cast<wchar_t*>(::LocalAlloc(LMEM_FIXED, bytes));
    if (out == nullptr) return;
    ::memcpy(out, tip.c_str(), bytes);
    info->pszText = out;
}

LRESULT ConnectionsList::OnCustomDraw(NMLVCUSTOMDRAW* cd) {
    switch (cd->nmcd.dwDrawStage) {
        case CDDS_PREPAINT:
            // CDRF_NOTIFYITEMDRAW == 0x20 == "CDRF_NOTIFYITEMPREPAINT"
            // (the SDK defines only the generic name; same value).
            // CDRF_NOTIFYPOSTPAINT (0x10) is requested too: the
            // empty-state banner is drawn once over the whole list
            // in post-paint, where the rows would have been.
            return CDRF_NOTIFYITEMDRAW | CDRF_NOTIFYPOSTPAINT;
        case CDDS_ITEMPREPAINT: {
            const Connection* c = store_.ViewRow(
                static_cast<size_t>(cd->nmcd.dwItemSpec));
            if (c == nullptr) return CDRF_DODEFAULT;
            // High Contrast schemes take precedence over every colour we would
            // paint. In HC, the system's COLOR_WINDOW/COLOR_WINDOWTEXT pairing
            // is the only legible answer: our palette would override it with
            // pale fills on the HC-black background, while the default text
            // colour would stay white. Returning CDRF_DODEFAULT lets the
            // ListView paint with the user's HC scheme. The row-flash hint is
            // a compromise we should keep off when that scheme is in effect.
            if (sink_.QueryPainting().highContrast) return CDRF_DODEFAULT;
            const bool dark = sink_.QueryPainting().darkTheme;
            const bool justDied =
                (c->flags & kRowRemoved) != 0 &&
                c->lifetime.deathTick == sink_.QueryPainting().snapshotTick;
            if (justDied) {
                // a socket that vanished THIS refresh flashes red once,
                // then settles to a muted grey retained ghost for the rest of
                // its life (up to kMaxRetainedGhosts). lifetime.deathTick is touched
                // only at vanishing, so it equals this snapshot's tick for the
                // flashing row.
                const RowColours rc = dark
                    ? RowColours{RGB(0x4A, 0x1F, 0x1F), RGB(0xFF, 0xB4, 0xB4), true}
                    : RowColours{RGB(0xF8, 0xC8, 0xC8), RGB(0x7A, 0x1F, 0x1F), true};
                cd->clrTextBk = rc.background;
                if (rc.textSet) cd->clrText = rc.text;
                return CDRF_NEWFONT;
            }
            if ((c->flags & (kRowNew | kRowChanged | kRowRemoved)) != 0) {
                const RowColours rc = FlashColours(c->flags, dark);
                cd->clrTextBk = rc.background;
                if (rc.textSet) cd->clrText = rc.text;
                return CDRF_NEWFONT;
            }
            // subtle banding on unmarked rows, so the eye can follow a
            // row across a wide table without selection. Change highlights
            // above win - a flashing row must not be banded over - and the
            // shades are faint enough to stay out of the text's way in
            // both themes. (Hover itself is LVS_EX_TRACKSELECT on the list.)
            if ((static_cast<size_t>(cd->nmcd.dwItemSpec) % 2) == 1) {
                cd->clrTextBk = BandColour(dark);
                return CDRF_NEWFONT;
            }
            return CDRF_DODEFAULT;
        }
        case CDDS_POSTPAINT: {
            // The empty-state banner. When the view
            // is empty there are no rows to paint, so the reason is
            // drawn where the rows would have been - in the list
            // itself - instead of only in the status bar, which a
            // user scanning the table never looks at. The hint is
            // only set for the cases that have a fix, so a plain,
            // healthy "no traffic yet" table stays quiet.
            const ConnectionsListSink::Painting p = sink_.QueryPainting();
            const std::wstring* hint = p.emptyStateHint;
            if (store_.View().empty() && hint != nullptr && !hint->empty()) {
                const RECT rc = cd->nmcd.rc;
                ::SetBkMode(cd->nmcd.hdc, TRANSPARENT);
                ::SetTextColor(cd->nmcd.hdc, ::GetSysColor(COLOR_GRAYTEXT));
                ::DrawTextW(cd->nmcd.hdc, hint->c_str(),
                            static_cast<int>(hint->size()), const_cast<RECT*>(&rc),
                            DT_CENTER | DT_VCENTER | DT_WORDBREAK | DT_NOPREFIX);
            }
            return CDRF_DODEFAULT;
        }
        default:
            return CDRF_DODEFAULT;
    }
}

void ConnectionsList::CaptureSelection(std::vector<std::uint64_t>& ids,
                                       std::uint64_t* focusedId,
                                       int* topIdx) const {
    ids.clear();
    *focusedId = 0;
    *topIdx = 0;
    if (hwnd_ == nullptr) return;
    int item = -1;
    while ((item = static_cast<int>(::SendMessageW(
                hwnd_, LVM_GETNEXTITEM, static_cast<WPARAM>(item),
                MAKELPARAM(LVNI_SELECTED, 0)))) != -1) {
        const Connection* c = store_.ViewRow(static_cast<size_t>(item));
        if (c != nullptr) ids.push_back(c->id);
    }
    const int f = static_cast<int>(::SendMessageW(
        hwnd_, LVM_GETNEXTITEM, static_cast<WPARAM>(-1),
        MAKELPARAM(LVNI_FOCUSED, 0)));
    const Connection* fc = store_.ViewRow(static_cast<size_t>(f));
    if (fc != nullptr) *focusedId = fc->id;
    *topIdx = static_cast<int>(::SendMessageW(hwnd_, LVM_GETTOPINDEX, 0, 0));
}

void ConnectionsList::RestoreSelection(const std::vector<std::uint64_t>& ids,
                                       std::uint64_t focusedId,
                                       int topIdx) {
    if (hwnd_ == nullptr) return;

    // id -> view position, built once for all lookups.
    std::unordered_map<std::uint64_t, size_t> pos;
    const size_t count = store_.View().size();
    pos.reserve(count * 2 + 1);
    for (size_t v = 0; v < count; ++v) {
        const Connection* c = store_.ViewRow(v);
        if (c != nullptr) pos[c->id] = v;
    }

    LVITEMW st = {};
    st.mask = LVIF_STATE;
    st.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
    ::SendMessageW(hwnd_, LVM_SETITEMSTATE, static_cast<WPARAM>(-1),
                   reinterpret_cast<LPARAM>(&st));   // clears all

    for (std::uint64_t id : ids) {
        const auto it = pos.find(id);
        if (it == pos.end()) continue;
        LVITEMW sel = {};
        sel.mask = LVIF_STATE;
        sel.stateMask = LVIS_SELECTED;
        sel.state = LVIS_SELECTED;
        ::SendMessageW(hwnd_, LVM_SETITEMSTATE,
                       static_cast<WPARAM>(it->second),
                       reinterpret_cast<LPARAM>(&sel));
    }
    if (focusedId != 0) {
        const auto it = pos.find(focusedId);
        if (it != pos.end()) {
            LVITEMW fo = {};
            fo.mask = LVIF_STATE;
            fo.stateMask = LVIS_FOCUSED;
            fo.state = LVIS_FOCUSED;
            ::SendMessageW(hwnd_, LVM_SETITEMSTATE,
                           static_cast<WPARAM>(it->second),
                           reinterpret_cast<LPARAM>(&fo));
        }
    }

    // Best-effort scroll preservation. Set the top index directly instead
    // of LVM_SCROLL with a pixel delta: the old code measured the row
    // height from item 0 (not the first visible item) and could scroll
    // far past the end of a list that shrank under the filter.
    //
    // LVM_SETTOPINDEX is behind an NTDDI_VERSION guard that the Win7
    // _WIN32_WINNT=0x0601 target hides, so the message is defined here
    // rather than bumping the project's minimum OS version for one call.
    const UINT msgSetTopIndex = LVM_FIRST + 119;   // LVM_SETTOPINDEX
    if (topIdx > 0 && count > 0) {
        const int cur = static_cast<int>(::SendMessageW(hwnd_, LVM_GETTOPINDEX,
                                                        0, 0));
        const int maxTop = static_cast<int>(count) - 1;
        const int want = (topIdx < maxTop) ? topIdx : maxTop;
        if (cur >= 0 && cur != want)
            ::SendMessageW(hwnd_, msgSetTopIndex, static_cast<WPARAM>(want),
                           0);
    }
}

bool ConnectionsList::SelectedRowIndices(std::vector<int>& out) const {
    out.clear();
    if (hwnd_ == nullptr) return false;
    int item = -1;
    while ((item = static_cast<int>(::SendMessageW(
                hwnd_, LVM_GETNEXTITEM, static_cast<WPARAM>(item),
                MAKELPARAM(LVNI_SELECTED, 0)))) != -1) {
        out.push_back(item);
    }
    return !out.empty();
}

const Connection* ConnectionsList::FirstSelectedRow() const {
    if (hwnd_ == nullptr) return nullptr;
    int item = static_cast<int>(::SendMessageW(
        hwnd_, LVM_GETNEXTITEM, static_cast<WPARAM>(-1),
        MAKELPARAM(LVNI_FOCUSED | LVNI_SELECTED, 0)));
    if (item == -1)
        item = static_cast<int>(::SendMessageW(
            hwnd_, LVM_GETNEXTITEM, static_cast<WPARAM>(-1),
            MAKELPARAM(LVNI_SELECTED, 0)));
    if (item == -1) return nullptr;
    return store_.ViewRow(static_cast<size_t>(item));
}

std::optional<Connection> ConnectionsList::SelectedCopy() const {
    const Connection* row = FirstSelectedRow();
    if (row == nullptr) return std::nullopt;
    return *row;
}

size_t ConnectionsList::SelectedCount() const {
    if (hwnd_ == nullptr) return 0;
    return static_cast<size_t>(::SendMessageW(hwnd_, LVM_GETSELECTEDCOUNT,
                                              0, 0));
}

void ConnectionsList::SelectAll() {
    if (hwnd_ == nullptr) return;
    LVITEMW st = {};
    st.mask = LVIF_STATE;
    st.stateMask = LVIS_SELECTED;
    st.state = LVIS_SELECTED;
    ::SendMessageW(hwnd_, LVM_SETITEMSTATE, static_cast<WPARAM>(-1),
                   reinterpret_cast<LPARAM>(&st));
}

std::wstring ConnectionsList::RowsToText(const std::vector<Connection>& rows,
                                         const ListViewColumns& cols) {
    std::wstring out;
    // Header = visible columns, tab separated.
    const std::vector<int>& vis = cols.VisibleOrder();
    for (size_t i = 0; i < vis.size(); ++i) {
        if (i != 0) out += L"\t";
        out += kColumns[static_cast<size_t>(vis[i])].title;
    }
    out += L"\r\n";

    wchar_t buf[kMaxColumnText] = {0};
    for (const Connection& c : rows) {
        for (size_t i = 0; i < vis.size(); ++i) {
            ConnectionStore::GetColumnText(c, vis[i], buf, kMaxColumnText);
            if (i != 0) out += L"\t";
            out += buf;
        }
        out += L"\r\n";
    }
    return out;
}

std::wstring ConnectionsList::SelectedRowsText(
    bool copyAll, bool grouped, bool frozen, ULONGLONG frozenAtMs,
    const ListViewColumns& cols) const {
    std::wstring out;
    // a copy of a grouped or frozen view says so up front, so the
    // pasted table cannot be mistaken for a live flat one. '#' comment
    // lines, matching the CLI's own comment convention, so a TSV reader
    // that skips comment lines keeps working and a human reader sees the
    // state the rows were copied in.
    if (grouped) {
        out += L"# WinTCP: rows grouped by process (per-process aggregates, "
               L"not individual connections)\r\n";
    }
    if (frozen) {
        const ULONGLONG age = FrozenAgeMs(frozenAtMs, ::GetTickCount64());
        out += L"# WinTCP: view frozen " +
               ((age < kMsPerSecond) ? std::wstring(L"<1s")
                                     : FormatDuration(age / kMsPerSecond)) +
               L" ago (stale snapshot, not live)\r\n";
    }
    // The visible ORDER is the column order: a copy pasted into a
    // spreadsheet should match what the table shows, and the ROW set is the
    // selection - or every row, when the caller asked for all.
    std::vector<int> idx;
    std::vector<Connection> rows;
    if (copyAll || !SelectedRowIndices(idx)) {
        rows = store_.Rows();
    } else {
        rows.reserve(idx.size());
        for (int i : idx) {
            const Connection* c = store_.ViewRow(static_cast<size_t>(i));
            if (c != nullptr) rows.push_back(*c);
        }
    }
    // RowsToText writes the header and the rows; the comment lines above it
    // are the view state, which only this method knows.
    const std::wstring body = RowsToText(rows, cols);
    return out + body;
}

}  // namespace wintcp
