// BlockedPeersDialog.cpp
// SPDX-License-Identifier: Apache-20
// See BlockedPeersDialog.h.

#include "BlockedPeersDialog.h"

#include <algorithm>
#include <commctrl.h>
#include <cstring>
#include <cwctype>
#include <netfw.h>
#include <shellapi.h>
#include <sstream>
#include <vector>

#include "BlockConn.h"
#include "Opt.h"
#include "Utils.h"

namespace wintcp {
namespace {

// Dialog ids, local to this module because the dialog is built in memory and
// has no entry in the .rc - the same reasoning as PromptDialog's ids.
enum : int {
    kIdList = 2000,
    // enable/disable join the editor's actions. They are NOT aliases
    // for delete: a disabled rule stays installed with its identity, so
    // "turn this off for an hour" is one step rather than delete-then-rederive.
    kIdDelete = IDOK + 1,
    kIdRemoveAll = IDOK + 2,
    kIdClose = IDCANCEL,
    kIdEnable = IDOK + 3,
    kIdDisable = IDOK + 4,
    kIdOpenFirewall = IDOK + 5,
    kIdSearch = IDOK + 6,
    kIdDetails = IDOK + 7,
};

constexpr int kControlCount = 9;

constexpr size_t Pad4(size_t bytes) { return (bytes + 3) & ~static_cast<size_t>(3); }

// The capacity the writer allocates. A list rows hold at most one rule name
// each, and a rule name is bounded by kMaxRuleNameChars; the captions are
// compile-time literals. Slack for the six font/title/extra-data slots that
// are shared rather than per-control.
constexpr size_t kTemplateSlack = 512;
constexpr size_t kRowTextChars = 1024;

struct BlockedPeersState {
    std::vector<BlockedRule> rules;
    std::vector<BlockedRule> visibleRules;
    BlockedPeersChoice choice = BlockedPeersChoice::kRefused;
    std::wstring failure;
    std::wstring filter;
    // Set the moment a rule is actually deleted, enabled,
    // disabled or every rule removed. The close paths report
    // kChanged only when this is set, so dismissing the viewer
    // without touching anything reports kClosed - a refresh of
    // the main table is earned, not assumed.
    bool dirty = false;
    // click-to-sort state. Column, then direction; a second click on
    // the same header flips the direction, a click elsewhere re-sorts
    // ascending. Name order is the default, matching the ledger.
    int sortCol = kBlockedColRule;
    bool sortAsc = true;
};

// ---------------------------------------------------------------------------
// The template writer. Same contract as PromptDialog's TemplateFits: every
// write is preceded by a bounds check on what is LEFT, the cursor only moves
// after the write, and a refusal returns false with the buffer shrunk to
// whatever prefix was written. The caller turns a false into an empty template
// and does not call the dialog manager at all.
// ---------------------------------------------------------------------------

// Write one DLGITEMTEMPLATE. 'end' exists so the alignment step can be
// re-checked after it: padding can land p exactly on end, or just past it for
// a buffer whose end is not DWORD-aligned, so "is there room" has to be asked
// again after the move and not only before it.
bool WriteItem(BYTE** cursor, const BYTE* end, DWORD style,
               short ix, short iy, short icx, short icy, int id, WORD cls,
               const wchar_t* caption) {
    BYTE*& p = *cursor;
    const auto usable = [&p, end](size_t n) {
        const std::ptrdiff_t room = end - p;
        return room >= 0 && n <= static_cast<size_t>(room);
    };

    const auto addr = reinterpret_cast<uintptr_t>(p);
    const auto aligned = (addr + 3u) & ~static_cast<uintptr_t>(3u);
    if (aligned < addr) return false;
    const size_t skip = static_cast<size_t>(aligned - addr);
    if (!usable(skip)) return false;
    if (end - p < 0) return false;
    p = reinterpret_cast<BYTE*>(aligned);

    if (!usable(sizeof(DLGITEMTEMPLATE))) return false;
    auto* it = reinterpret_cast<DLGITEMTEMPLATE*>(p);
    it->style = style;
    it->x = ix;
    it->y = iy;
    it->cx = icx;
    it->cy = icy;
    it->id = static_cast<WORD>(id);
    p += sizeof(DLGITEMTEMPLATE);

    if (!usable(4)) return false;
    *reinterpret_cast<WORD*>(p) = 0xFFFF;   // the class is an ordinal
    *reinterpret_cast<WORD*>(p + 2) = cls;  // 0x83 listbox, 0x80 edit, 0x81 button
    p += 4;

    const size_t n = (caption == nullptr) ? 1 : wcslen(caption) + 1;
    const size_t bytes = Pad4(n * sizeof(wchar_t));
    if (!usable(bytes)) return false;
    if (caption != nullptr) {
        memcpy(p, caption, n * sizeof(wchar_t));
    } else {
        memset(p, 0, bytes);
    }
    p += bytes;

    if (!usable(2)) return false;
    memset(p, 0, 2);   // no extra data
    p += 2;
    return true;
}

// Build the whole template. Returns an empty vector on any refusal; the caller
// must not hand a partial template to the dialog manager, because cdit says
// kControlCount and fewer controls would make it read past the end.
// Write one DLGITEMTEMPLATE whose class is a STRING (e.g. L"SysListView32")
// rather than an ordinal. Same bounds-checked contract as WriteItem above:
// alignment first, every write preceded by a capacity check, false on any
// refusal. The caption is the control's initial text (null for the list:
// its columns and rows are filled at runtime, not from the template).
bool WriteItemWithClass(BYTE** cursor, const BYTE* end, DWORD style,
                        short ix, short iy, short icx, short icy, int id,
                        const wchar_t* className, const wchar_t* caption) {
    BYTE*& p = *cursor;
    const auto usable = [&p, end](size_t n) {
        const std::ptrdiff_t room = end - p;
        return room >= 0 && n <= static_cast<size_t>(room);
    };

    const auto addr = reinterpret_cast<uintptr_t>(p);
    const auto aligned = (addr + 3u) & ~static_cast<uintptr_t>(3u);
    if (aligned < addr) return false;
    const size_t skip = static_cast<size_t>(aligned - addr);
    if (!usable(skip)) return false;
    if (end - p < 0) return false;
    p = reinterpret_cast<BYTE*>(aligned);

    if (!usable(sizeof(DLGITEMTEMPLATE))) return false;
    auto* it = reinterpret_cast<DLGITEMTEMPLATE*>(p);
    it->style = style;
    it->x = ix;
    it->y = iy;
    it->cx = icx;
    it->cy = icy;
    it->id = static_cast<WORD>(id);
    p += sizeof(DLGITEMTEMPLATE);

    // Class as a null-terminated string, DWORD-padded like every string in
    // a template. An ordinal (0xFFFF + value) would also work for the
    // six built-in classes, but SysListView32 is not one of them.
    if (className == nullptr) return false;
    const size_t classChars = wcslen(className) + 1;
    const size_t classBytes = Pad4(classChars * sizeof(wchar_t));
    if (!usable(classBytes)) return false;
    memcpy(p, className, classChars * sizeof(wchar_t));
    p += classBytes;

    const size_t n = (caption == nullptr) ? 1 : wcslen(caption) + 1;
    const size_t bytes = Pad4(n * sizeof(wchar_t));
    if (!usable(bytes)) return false;
    if (caption != nullptr) {
        memcpy(p, caption, n * sizeof(wchar_t));
    } else {
        memset(p, 0, bytes);
    }
    p += bytes;

    if (!usable(2)) return false;
    memset(p, 0, 2);   // no extra data
    p += 2;
    return true;
}
std::vector<BYTE> MakeTemplate(const wchar_t* title) {
    if (title == nullptr) return std::vector<BYTE>();

    const size_t titleBytes = Pad4((wcslen(title) + 1) * sizeof(wchar_t));
    constexpr wchar_t kFont[] = L"Segoe UI";
    const size_t fontBytes = Pad4((sizeof(kFont) / sizeof(wchar_t)) * sizeof(wchar_t));

    // Four items: the list plus Delete / Remove all / Close.
    size_t capacity = sizeof(DLGTEMPLATE) + 4 + titleBytes + 2 + fontBytes +
                      kTemplateSlack;
    for (int i = 0; i < kControlCount; ++i) {
        capacity += sizeof(DLGITEMTEMPLATE) + 4 +
                    Pad4(kRowTextChars * sizeof(wchar_t)) + 2;
    }

    std::vector<BYTE> buf(capacity, 0);
    BYTE* p = buf.data();
    BYTE* const begin = p;
    BYTE* const end = buf.data() + buf.size();

    const auto usable = [&p, end](size_t n) {
        const std::ptrdiff_t room = end - p;
        return room >= 0 && n <= static_cast<size_t>(room);
    };

    if (!usable(sizeof(DLGTEMPLATE))) return std::vector<BYTE>();
    auto* dlg = reinterpret_cast<DLGTEMPLATE*>(p);
    dlg->style = DS_ABSALIGN | DS_CENTER | WS_POPUP | WS_CAPTION | WS_SYSMENU |
                 WS_THICKFRAME | WS_MAXIMIZEBOX | DS_SETFONT;
    dlg->dwExtendedStyle = 0;
    dlg->cdit = static_cast<WORD>(kControlCount);
    dlg->x = 0;
    dlg->y = 0;
    dlg->cx = 460;
    dlg->cy = 310;
    p += sizeof(DLGTEMPLATE);

    if (!usable(4)) return std::vector<BYTE>();
    memset(p, 0, 4);   // no menu, default window class
    p += 4;

    const size_t tChars = wcslen(title) + 1;
    if (!usable(titleBytes)) return std::vector<BYTE>();
    memcpy(p, title, tChars * sizeof(wchar_t));
    p += titleBytes;

    if (!usable(2)) return std::vector<BYTE>();
    *reinterpret_cast<WORD*>(p) = 9;   // 9pt, matching PromptDialog
    p += 2;

    if (!usable(fontBytes)) return std::vector<BYTE>();
    memcpy(p, kFont, (sizeof(kFont) / sizeof(wchar_t)) * sizeof(wchar_t));
    p += fontBytes;

    if (!WriteItem(&p, end,
                   WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 8,
                   8, 444, 20, kIdSearch, 0x80, L"")) {
        return std::vector<BYTE>();
    }
    const DWORD listStyle = WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP |
                            LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL;
    if (!WriteItemWithClass(&p, end, listStyle, 8, 32, 444, 150, kIdList,
                            L"SysListView32", nullptr)) {
        return std::vector<BYTE>();
    }
    if (!WriteItem(&p, end,
                   WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_MULTILINE |
                       ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL,
                   8, 186, 444, 44, kIdDetails, 0x81,
                   L"Select a rule to inspect its effective scope.")) {
        return std::vector<BYTE>();
    }
    if (!WriteItem(&p, end,
                   WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON, 8,
                   236, 88, 23, kIdDelete, 0x81, L"Delete") ||
        !WriteItem(&p, end, WS_CHILD | WS_VISIBLE | WS_TABSTOP, 100, 236,
                   88, 23, kIdEnable, 0x81, L"Enable") ||
        !WriteItem(&p, end, WS_CHILD | WS_VISIBLE | WS_TABSTOP, 192, 236,
                   88, 23, kIdDisable, 0x81, L"Disable") ||
        !WriteItem(&p, end, WS_CHILD | WS_VISIBLE | WS_TABSTOP, 8, 263,
                   104, 23, kIdRemoveAll, 0x81, L"Remove all") ||
        !WriteItem(&p, end, WS_CHILD | WS_VISIBLE | WS_TABSTOP, 116, 263,
                   104, 23, kIdOpenFirewall, 0x81, L"Open Firewall") ||
        !WriteItem(&p, end, WS_CHILD | WS_VISIBLE | WS_TABSTOP, 224, 263,
                   104, 23, kIdClose, 0x81, L"Close")) {
        return std::vector<BYTE>();
    }

    buf.resize(static_cast<size_t>(p - begin));
    return buf;
}

// Sort rank for the Status column: blocking-and-enabled first (the
// healthy state), then disabled, then rules that are no longer blocks at
// all. Any total order would sort; this one puts the surprising rows last,
// where a reader scanning for trouble looks.
int StatusRank(const BlockedRule& r) {
    if (!r.blockingKnown || (r.isBlocking && !r.enabledKnown)) return 3;
    if (!r.isBlocking) return 2;
    return r.enabled ? 0 : 1;
}

// Order st->rules by the current click-to-sort column, with the rule name
// as the tiebreak so Status/Remote sorts are stable in a way a reader can
// follow (two "disabled" rows keep ledger order otherwise only by luck of
// stable_sort - and luck is not a contract).
void SortRules(BlockedPeersState* st) {
    if (st == nullptr) return;
    const int col = st->sortCol;
    const bool asc = st->sortAsc;
    std::stable_sort(st->rules.begin(), st->rules.end(),
                     [col, asc](const BlockedRule& a, const BlockedRule& b) {
                         int c = 0;
                         if (col == kBlockedColRemote) {
                             c = BlockedPeersCellText(a, col).compare(
                                 BlockedPeersCellText(b, col));
                         } else if (col == kBlockedColStatus) {
                             c = StatusRank(a) - StatusRank(b);
                         } else {
                             c = a.name.compare(b.name);
                         }
                         if (c == 0 && col != kBlockedColRule)
                             c = a.name.compare(b.name);
                         return asc ? (c < 0) : (c > 0);
                     });
}

// The one selected rule, or -1. Single-select list, so "the selection" is
// one index - the multi-select walk the list box needed is gone with it.
int SelectedRuleIndex(HWND list) {
    if (list == nullptr) return -1;
    return static_cast<int>(::SendMessageW(
        list, LVM_GETNEXTITEM, static_cast<WPARAM>(-1),
        MAKELPARAM(LVNI_SELECTED, 0)));
}

// Enable the per-rule actions only when there is a rule to act on. The
// empty list carries a placeholder row that is not a rule, so the
// buttons must not invite acting on it.
void SyncActionButtons(HWND dlg, bool haveSelection, bool canEnable,
                       bool canDisable) {
    if (dlg == nullptr) return;
    HWND deleteButton = ::GetDlgItem(dlg, kIdDelete);
    if (deleteButton != nullptr) ::EnableWindow(deleteButton, haveSelection ? TRUE : FALSE);
    HWND enableButton = ::GetDlgItem(dlg, kIdEnable);
    if (enableButton != nullptr) ::EnableWindow(enableButton, canEnable ? TRUE : FALSE);
    HWND disableButton = ::GetDlgItem(dlg, kIdDisable);
    if (disableButton != nullptr) ::EnableWindow(disableButton, canDisable ? TRUE : FALSE);
}

bool ContainsInsensitive(const std::wstring& value, const std::wstring& query) {
    if (query.empty()) return true;
    if (value.size() < query.size()) return false;
    const auto equal = [](wchar_t left, wchar_t right) {
        return std::towlower(left) == std::towlower(right);
    };
    return std::search(value.begin(), value.end(), query.begin(), query.end(),
                       equal) != value.end();
}

bool MatchesFilter(const BlockedRule& rule, const std::wstring& query) {
    return ContainsInsensitive(rule.name, query) ||
           ContainsInsensitive(rule.remoteAddrs, query) ||
           ContainsInsensitive(rule.localAddrs, query) ||
           ContainsInsensitive(rule.remotePorts, query) ||
           ContainsInsensitive(rule.localPorts, query) ||
           ContainsInsensitive(rule.application, query) ||
           ContainsInsensitive(rule.service, query);
}

std::wstring KnownField(const std::wstring& value, bool known) {
    if (!known) return L"Unknown (not reported)";
    return value.empty() ? L"Any" : value;
}

void UpdateRuleDetails(HWND dlg, const BlockedPeersState* st) {
    if (dlg == nullptr || st == nullptr) return;
    HWND list = ::GetDlgItem(dlg, kIdList);
    const int selected = SelectedRuleIndex(list);
    std::wstring text = L"Select a rule to inspect its effective scope.";
    if (selected >= 0 && static_cast<size_t>(selected) < st->visibleRules.size()) {
        const BlockedRule& rule = st->visibleRules[static_cast<size_t>(selected)];
        const std::wstring direction = !rule.directionKnown ? L"Unknown" :
            rule.direction == NET_FW_RULE_DIR_IN ? L"Inbound" : L"Outbound";
        const std::wstring action = !rule.actionKnown ? L"Unknown" :
            rule.action == NET_FW_ACTION_BLOCK ? L"Block" : L"Allow";
        std::wstring protocol = L"Unknown";
        if (rule.protocolKnown) {
            protocol = rule.protocol == NET_FW_IP_PROTOCOL_TCP ? L"TCP" :
                rule.protocol == NET_FW_IP_PROTOCOL_UDP ? L"UDP" :
                rule.protocol == NET_FW_IP_PROTOCOL_ANY ? L"Any" :
                std::to_wstring(rule.protocol);
        }
        std::wstring status = !rule.enabledKnown ? L"Unknown" :
            rule.enabled ? L"Enabled" : L"Disabled";
        std::wostringstream detail;
        detail << rule.name << L"\r\n"
               << direction << L" " << action << L" / " << protocol << L" / "
               << status << L" / profiles "
               << (rule.profilesKnown ? std::to_wstring(rule.profiles) : L"Unknown")
               << L"\r\nLocal " << KnownField(rule.localAddrs, rule.localAddrsKnown)
               << L" ports " << KnownField(rule.localPorts, rule.localPortsKnown)
               << L"  |  Remote " << KnownField(rule.remoteAddrs, rule.remoteAddrsKnown)
               << L" ports " << KnownField(rule.remotePorts, rule.remotePortsKnown)
               << L"\r\nApplication " << KnownField(rule.application, rule.applicationKnown)
               << L"  |  Service " << KnownField(rule.service, rule.serviceKnown);
        text = detail.str();
    }
    ::SetWindowTextW(::GetDlgItem(dlg, kIdDetails), text.c_str());
}

// The header's sort arrow follows st->sortCol/st->sortAsc, so the header
// says which column orders the list instead of the user having to guess.
void UpdateSortIndicator(HWND list, const BlockedPeersState* st) {
    if (list == nullptr || st == nullptr) return;
    HWND hdr = reinterpret_cast<HWND>(
        ::SendMessageW(list, LVM_GETHEADER, 0, 0));
    if (hdr == nullptr) return;
    for (int c = 0; c < kBlockedColCount; ++c) {
        HDITEMW hdi = {};
        hdi.mask = HDI_FORMAT;
        if (::SendMessageW(hdr, HDM_GETITEMW, static_cast<WPARAM>(c),
                           reinterpret_cast<LPARAM>(&hdi)) == FALSE)
            continue;
        hdi.fmt &= ~(HDF_SORTUP | HDF_SORTDOWN);
        if (c == st->sortCol)
            hdi.fmt |= (st->sortAsc ? HDF_SORTUP : HDF_SORTDOWN);
        ::SendMessageW(hdr, HDM_SETITEMW, static_cast<WPARAM>(c),
                       reinterpret_cast<LPARAM>(&hdi));
    }
}

// Create the Rule/Remote/Status columns once, sharing the list's width.
// Fixed fractions adapt to the current client width and keep their sum exact.
void SetupColumns(HWND list) {
    if (list == nullptr) return;
    HWND hdr = reinterpret_cast<HWND>(
        ::SendMessageW(list, LVM_GETHEADER, 0, 0));
    if (hdr != nullptr &&
        ::SendMessageW(hdr, HDM_GETITEMCOUNT, 0, 0) > 0)
        return;   // already built (a second Show reuses the dialog)
    RECT rc = {};
    ::GetClientRect(list, &rc);
    int total = rc.right - rc.left;
    if (total <= 0) total = 320;
    const wchar_t* titles[kBlockedColCount] = {L"Rule", L"Remote", L"Status"};
    const int widths[kBlockedColCount] = {total * 45 / 100,
                                          total * 32 / 100,
                                          total - total * 45 / 100 -
                                              total * 32 / 100};
    for (int c = 0; c < kBlockedColCount; ++c) {
        LVCOLUMNW col = {};
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM | LVCF_FMT;
        col.fmt = LVCFMT_LEFT;
        col.cx = (widths[c] > 0) ? widths[c] : 10;
        col.pszText = const_cast<LPWSTR>(titles[c]);
        col.iSubItem = c;
        ::SendMessageW(list, LVM_INSERTCOLUMNW, static_cast<WPARAM>(c),
                       reinterpret_cast<LPARAM>(&col));
    }
    ::SendMessageW(list, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
                   LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER |
                       LVS_EX_LABELTIP);
}

void ResizeRuleColumns(HWND list) {
    if (list == nullptr) return;
    RECT rc = {};
    ::GetClientRect(list, &rc);
    const int total = (std::max)(60, static_cast<int>(rc.right - rc.left));
    const int first = total * 45 / 100;
    const int second = total * 32 / 100;
    ::SendMessageW(list, LVM_SETCOLUMNWIDTH, kBlockedColRule, first);
    ::SendMessageW(list, LVM_SETCOLUMNWIDTH, kBlockedColRemote, second);
    ::SendMessageW(list, LVM_SETCOLUMNWIDTH, kBlockedColStatus,
                   total - first - second);
}

void ResizeControls(HWND dlg) {
    if (dlg == nullptr) return;
    RECT client = {};
    ::GetClientRect(dlg, &client);
    RECT pad = {0, 0, 8, 8};
    RECT button = {0, 0, 88, 23};
    RECT detail = {0, 0, 400, 44};
    RECT search = {0, 0, 400, 20};
    ::MapDialogRect(dlg, &pad);
    ::MapDialogRect(dlg, &button);
    ::MapDialogRect(dlg, &detail);
    ::MapDialogRect(dlg, &search);
    const int margin = (std::max)(4, static_cast<int>(pad.right));
    const int gap = (std::max)(3, static_cast<int>(pad.bottom / 2));
    const int buttonHeight = (std::max)(20, static_cast<int>(button.bottom));
    const int buttonY = client.bottom - margin - buttonHeight;
    const int firstButtonY = buttonY - gap - buttonHeight;
    const int detailBottom = firstButtonY - gap;
    const int detailTop = (std::max)(static_cast<int>(search.bottom) + margin * 3,
                                      detailBottom - static_cast<int>(detail.bottom));
    const int searchHeight = (std::max)(18, static_cast<int>(search.bottom));
    const int searchWidth = (std::max)(80, static_cast<int>(client.right) - margin * 2);
    const int listTop = margin + searchHeight + gap;
    const int listBottom = detailTop - gap;
    const int listHeight = (std::max)(40, listBottom - listTop);
    const int innerWidth = (std::max)(120, static_cast<int>(client.right) - margin * 2);
    const int columnGap = gap * 2;
    const int buttonWidth = (std::max)(48, (innerWidth - columnGap) / 3);
    ::MoveWindow(::GetDlgItem(dlg, kIdSearch), margin, margin, searchWidth,
                 searchHeight, TRUE);
    ::MoveWindow(::GetDlgItem(dlg, kIdList), margin, listTop, innerWidth,
                 listHeight, TRUE);
    ::MoveWindow(::GetDlgItem(dlg, kIdDetails), margin, detailTop, innerWidth,
                 (std::max)(static_cast<int>(detail.bottom), detailBottom - detailTop), TRUE);
    const int x0 = margin;
    const int x1 = x0 + buttonWidth + gap;
    const int x2 = x1 + buttonWidth + gap;
    ::MoveWindow(::GetDlgItem(dlg, kIdDelete), x0, firstButtonY, buttonWidth,
                 buttonHeight, TRUE);
    ::MoveWindow(::GetDlgItem(dlg, kIdEnable), x1, firstButtonY, buttonWidth,
                 buttonHeight, TRUE);
    ::MoveWindow(::GetDlgItem(dlg, kIdDisable), x2, firstButtonY, buttonWidth,
                 buttonHeight, TRUE);
    ::MoveWindow(::GetDlgItem(dlg, kIdRemoveAll), x0, buttonY, buttonWidth,
                 buttonHeight, TRUE);
    ::MoveWindow(::GetDlgItem(dlg, kIdOpenFirewall), x1, buttonY, buttonWidth,
                 buttonHeight, TRUE);
    ::MoveWindow(::GetDlgItem(dlg, kIdClose), x2, buttonY, buttonWidth,
                 buttonHeight, TRUE);
    ResizeRuleColumns(::GetDlgItem(dlg, kIdList));
}

// Render st->rules into the list: sorted, with the selection following the
// rule it was on. keepName is the selected rule before the rebuild (empty
// = none); the row is found by NAME because a re-sort moves indices.
void FillItems(HWND list, BlockedPeersState* st,
               const std::wstring& keepName) {
    if (list == nullptr || st == nullptr) return;
    SortRules(st);
    st->visibleRules.clear();
    for (const BlockedRule& rule : st->rules)
        if (MatchesFilter(rule, st->filter)) st->visibleRules.push_back(rule);
    ::SendMessageW(list, WM_SETREDRAW, FALSE, 0);
    ::SendMessageW(list, LVM_DELETEALLITEMS, 0, 0);
    if (st->rules.empty()) {
        // an empty viewer names its next action instead of sitting
        // blank. Blocking a connection is what adds the first row, so
        // the placeholder points there.
        LVITEMW it = {};
        it.mask = LVIF_TEXT;
        it.iItem = 0;
        it.iSubItem = 0;
        wchar_t place[] =
            L"(no blocked rules \u2014 blocking a connection adds one here)";
        it.pszText = place;
        ::SendMessageW(list, LVM_INSERTITEMW, 0,
                       reinterpret_cast<LPARAM>(&it));
    } else if (st->visibleRules.empty()) {
        LVITEMW it = {};
        it.mask = LVIF_TEXT;
        it.iItem = 0;
        it.iSubItem = 0;
        wchar_t place[] = L"(no firewall rule matches this search)";
        it.pszText = place;
        ::SendMessageW(list, LVM_INSERTITEMW, 0,
                       reinterpret_cast<LPARAM>(&it));
    } else {
        for (size_t i = 0; i < st->visibleRules.size(); ++i) {
            const BlockedRule& r = st->visibleRules[i];
            std::wstring cells[kBlockedColCount];
            for (int c = 0; c < kBlockedColCount; ++c)
                cells[c] = BlockedPeersCellText(r, c);
            LVITEMW it = {};
            it.mask = LVIF_TEXT;
            it.iItem = static_cast<int>(i);
            it.iSubItem = 0;
            it.pszText = cells[0].data();
            const LRESULT at = ::SendMessageW(
                list, LVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&it));
            if (at < 0) continue;
            for (int c = 1; c < kBlockedColCount; ++c) {
                LVITEMW sub = {};
                sub.mask = LVIF_TEXT;
                sub.iItem = static_cast<int>(at);
                sub.iSubItem = c;
                sub.pszText = cells[c].data();
                ::SendMessageW(list, LVM_SETITEMTEXTW,
                               static_cast<WPARAM>(at),
                               reinterpret_cast<LPARAM>(&sub));
            }
        }
    }
    // Restore the selection by name, or park it on the first rule. The
    // placeholder is never selected: it is not a rule and the actions
    // refuse anything that is not one.
    int restore = -1;
    if (!st->visibleRules.empty()) {
        for (size_t i = 0; i < st->visibleRules.size(); ++i) {
            if (st->visibleRules[i].name == keepName) {
                restore = static_cast<int>(i);
                break;
            }
        }
        if (restore < 0) restore = 0;
        LVITEMW sel = {};
        sel.mask = LVIF_STATE;
        sel.iItem = restore;
        sel.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
        sel.state = LVIS_SELECTED | LVIS_FOCUSED;
        ::SendMessageW(list, LVM_SETITEMSTATE, static_cast<WPARAM>(restore),
                       reinterpret_cast<LPARAM>(&sel));
    }
    ::SendMessageW(list, WM_SETREDRAW, TRUE, 0);
    ::InvalidateRect(list, nullptr, TRUE);
    UpdateSortIndicator(list, st);
    const int selected = SelectedRuleIndex(list);
    const BlockedRule* selectedRule = selected >= 0 &&
        static_cast<size_t>(selected) < st->visibleRules.size()
        ? &st->visibleRules[static_cast<size_t>(selected)] : nullptr;
    SyncActionButtons(::GetParent(list), selectedRule != nullptr,
        selectedRule != nullptr && selectedRule->enabledKnown && !selectedRule->enabled,
        selectedRule != nullptr && selectedRule->enabledKnown && selectedRule->enabled);
    HWND removeAll = ::GetDlgItem(::GetParent(list), kIdRemoveAll);
    if (removeAll != nullptr) ::EnableWindow(removeAll, st->rules.empty() ? FALSE : TRUE);
    UpdateRuleDetails(::GetParent(list), st);
}

// Repopulate the list from the firewall. Called on init and after every
// action, so the manager shows what the firewall holds rather than what the
// dialog believed when it opened.
//
// an action that closed the modal was a reader with extra buttons. The
// point of an editor is that you change one thing and SEE the result, so this
// spends the cost of a re-list and keeps the selection on the same rule when
// it still exists.
void ReloadRules(HWND list, BlockedPeersState* st) {
    if (list == nullptr || st == nullptr) return;
    const int sel = SelectedRuleIndex(list);
    std::wstring keepName;
    if (sel >= 0 && static_cast<size_t>(sel) < st->visibleRules.size())
        keepName = st->visibleRules[static_cast<size_t>(sel)].name;

    std::wstring error;
    std::vector<BlockedRule> fresh;
    if (!ListBlockedRules(&fresh, &error)) {
        // Leave the list as it was rather than emptying it: an empty list on a
        // failed read would read as "you have no rules", which is the one
        // answer this dialog must never give wrongly.
        if (!error.empty()) {
            ::MessageBoxW(
                list,
                (L"Could not re-read the firewall rules:\r\n" + error).c_str(),
                L"WinTCP", MB_OK | MB_ICONERROR);
        }
        return;
    }
    st->rules = std::move(fresh);
    FillItems(list, st, keepName);
}

// A header click re-sorts what is already shown. The firewall is NOT
// re-queried: sorting is a view operation, and a COM round trip per
// click would make the header feel stuck.
void OnSortClick(HWND list, BlockedPeersState* st, int col) {
    if (list == nullptr || st == nullptr) return;
    if (col < 0 || col >= kBlockedColCount) return;
    if (st->sortCol == col) {
        st->sortAsc = !st->sortAsc;
    } else {
        st->sortCol = col;
        st->sortAsc = true;
    }
    const int sel = SelectedRuleIndex(list);
    std::wstring keep;
    if (sel >= 0 && static_cast<size_t>(sel) < st->visibleRules.size())
        keep = st->visibleRules[static_cast<size_t>(sel)].name;
    FillItems(list, st, keep);
}

INT_PTR CALLBACK BlockedPeersProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    auto* st = reinterpret_cast<BlockedPeersState*>(
        GetWindowLongPtrW(hwnd, DWLP_USER));
    if (msg == WM_INITDIALOG) {
        st = reinterpret_cast<BlockedPeersState*>(lp);
        SetWindowLongPtrW(hwnd, DWLP_USER, reinterpret_cast<LONG_PTR>(st));
    }
    if (st == nullptr) return FALSE;

    switch (msg) {
        case WM_INITDIALOG: {
            HWND list = GetDlgItem(hwnd, kIdList);
            ::SendMessageW(GetDlgItem(hwnd, kIdSearch), EM_SETCUEBANNER, TRUE,
                           reinterpret_cast<LPARAM>(L"Filter by rule, address, application or service"));
            SetupColumns(list);
            ResizeControls(hwnd);
            ResizeRuleColumns(list);
            ReloadRules(list, st);
            RECT rc = {};
            ::GetWindowRect(hwnd, &rc);
            RECT own = {};
            ::GetWindowRect(::GetParent(hwnd), &own);
            const int w = rc.right - rc.left;
            const int h = rc.bottom - rc.top;
            ::SetWindowPos(hwnd, HWND_TOP,
                           own.left + ((own.right - own.left) - w) / 2,
                           own.top + ((own.bottom - own.top) - h) / 2, 0, 0,
                           SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
            return TRUE;
        }
        case WM_SIZE:
            ResizeControls(hwnd);
            ResizeRuleColumns(GetDlgItem(hwnd, kIdList));
            return TRUE;
        case WM_DPICHANGED: {
            const auto* suggested = reinterpret_cast<const RECT*>(lp);
            if (suggested != nullptr) {
                ::SetWindowPos(hwnd, nullptr, suggested->left, suggested->top,
                               suggested->right - suggested->left,
                               suggested->bottom - suggested->top,
                               SWP_NOZORDER | SWP_NOACTIVATE);
                ResizeControls(hwnd);
                ResizeRuleColumns(GetDlgItem(hwnd, kIdList));
            }
            return TRUE;
        }
        case WM_GETMINMAXINFO: {
            auto* limits = reinterpret_cast<MINMAXINFO*>(lp);
            if (limits != nullptr) {
                RECT minimum = {0, 0, 380, 275};
                ::MapDialogRect(hwnd, &minimum);
                limits->ptMinTrackSize.x = minimum.right +
                    ::GetSystemMetrics(SM_CXSIZEFRAME) * 2;
                limits->ptMinTrackSize.y = minimum.bottom +
                    ::GetSystemMetrics(SM_CYSIZEFRAME) * 2 +
                    ::GetSystemMetrics(SM_CYCAPTION);
            }
            return TRUE;
        }
        case WM_NOTIFY: {
            // header clicks sort. The notification arrives from the
            // list's header with the list's own id, so anything else is
            // left to the default handler.
            auto* nm = reinterpret_cast<LPNMHDR>(lp);
            if (nm != nullptr && nm->idFrom == kIdList &&
                nm->code == HDN_ITEMCLICK) {
                auto* hn = reinterpret_cast<LPNMHEADERW>(lp);
                OnSortClick(GetDlgItem(hwnd, kIdList), st, hn->iItem);
                return TRUE;
            }
            if (nm != nullptr && nm->idFrom == kIdList &&
                nm->code == LVN_ITEMCHANGED) {
                auto* change = reinterpret_cast<LPNMLISTVIEW>(lp);
                if (change != nullptr && (change->uChanged & LVIF_STATE) != 0 &&
                    ((change->uNewState | change->uOldState) & LVIS_SELECTED) != 0) {
                    UpdateRuleDetails(hwnd, st);
                    const int selected = SelectedRuleIndex(GetDlgItem(hwnd, kIdList));
                    const bool hasSelection = selected >= 0 &&
                        static_cast<size_t>(selected) < st->visibleRules.size();
                    const BlockedRule* selectedRule = hasSelection
                        ? &st->visibleRules[static_cast<size_t>(selected)] : nullptr;
                    SyncActionButtons(hwnd, hasSelection,
                        selectedRule != nullptr && selectedRule->enabledKnown && !selectedRule->enabled,
                        selectedRule != nullptr && selectedRule->enabledKnown && selectedRule->enabled);
                    HWND removeAll = GetDlgItem(hwnd, kIdRemoveAll);
                    if (removeAll != nullptr)
                        ::EnableWindow(removeAll, st->rules.empty() ? FALSE : TRUE);
                }
                return TRUE;
            }
            break;
        }
        case WM_COMMAND: {
            const int id = LOWORD(wp);
            const int code = HIWORD(wp);
            if (id == kIdSearch && code == EN_CHANGE) {
                HWND search = GetDlgItem(hwnd, kIdSearch);
                const int length = ::GetWindowTextLengthW(search);
                std::vector<wchar_t> text(static_cast<size_t>(length) + 1, L'\0');
                ::GetWindowTextW(search, text.data(), length + 1);
                st->filter.assign(text.data());
                HWND list = GetDlgItem(hwnd, kIdList);
                const int selected = SelectedRuleIndex(list);
                const std::wstring keep = selected >= 0 &&
                    static_cast<size_t>(selected) < st->visibleRules.size()
                    ? st->visibleRules[static_cast<size_t>(selected)].name : L"";
                FillItems(list, st, keep);
                return TRUE;
            }
            if (id == kIdClose || id == IDCANCEL) {
                // dismissing the viewer is not a change. Only
                // report kChanged when a rule was actually added to
                // or removed from the blocked set - otherwise the
                // caller refreshes the main table for nothing.
                st->choice = st->dirty
                                 ? BlockedPeersChoice::kChanged
                                 : BlockedPeersChoice::kClosed;
                ::EndDialog(hwnd, TRUE);
                return TRUE;
            }
            if (id == kIdOpenFirewall && code == BN_CLICKED) {
                const HINSTANCE opened = ::ShellExecuteW(
                    hwnd, L"open", L"wf.msc", nullptr, nullptr, SW_SHOWNORMAL);
                if (reinterpret_cast<INT_PTR>(opened) <= 32) {
                    ::MessageBoxW(
                        hwnd,
                        L"Windows Firewall with Advanced Security could not be opened. "
                        L"You can launch wf.msc from the Windows Start menu.",
                        L"WinTCP", MB_OK | MB_ICONERROR);
                }
                return TRUE;
            }
            if (code != BN_CLICKED) break;
            HWND list = GetDlgItem(hwnd, kIdList);
            const int sel = SelectedRuleIndex(list);
            if (id == kIdDelete || id == kIdEnable || id == kIdDisable) {
                // The empty list's placeholder row is not a rule,
                // and a click with no selection is not an action either.
                // Each refusal names its own cause so neither reads as a
                // broken button.
                if (st->rules.empty()) {
                    ::MessageBoxW(hwnd, L"There are no blocked rules.",
                                  L"WinTCP", MB_OK | MB_ICONINFORMATION);
                    return TRUE;
                }
                if (sel < 0 ||
                    static_cast<size_t>(sel) >= st->visibleRules.size()) {
                    ::MessageBoxW(hwnd, L"Select a rule first.", L"WinTCP",
                                  MB_OK | MB_ICONINFORMATION);
                    return TRUE;
                }
                const std::wstring name =
                    st->visibleRules[static_cast<size_t>(sel)].name;
                std::wstring error;
                bool ok = false;
                const wchar_t* what = L"delete";
                if (id == kIdDelete) {
                    // Deleting a rule is not reversible from
                    // here: the rule is gone and the peer can
                    // connect again, so it is confirmed by name
                    // before it runs. Enable and disable
                    // are reversible and need no confirm.
                    std::wstring prompt =
                        L"Delete the block on \"" + name +
                        L"\"?\r\n\r\nThe peer will be able to "
                        L"connect again.";
                    if (::MessageBoxW(hwnd, prompt.c_str(),
                                      L"WinTCP - Delete block",
                                      MB_YESNO | MB_ICONWARNING |
                                          MB_DEFBUTTON2) != IDYES)
                        return TRUE;
                    ok = RemoveBlockedRule(name, &error);
                } else if (id == kIdEnable) {
                    ok = SetBlockedRuleEnabled(name, true, &error);
                    what = L"enable";
                } else {
                    ok = SetBlockedRuleEnabled(name, false, &error);
                    what = L"disable";
                }
                if (!ok) {
                    ::MessageBoxW(hwnd,
                                  (std::wstring(L"Could not ") + what +
                                   L" the rule:\r\n" + error)
                                      .c_str(),
                                  L"WinTCP", MB_OK | MB_ICONERROR);
                    return TRUE;
                }
                st->dirty = true;   // a rule was changed
                // Stay open and re-read. A manager that closes after every
                // action is three actions per change.
                ReloadRules(list, st);
                return TRUE;
            }
            if (id == kIdRemoveAll) {
                if (st->rules.empty()) {
                    ::MessageBoxW(hwnd, L"No rules to remove.",
                                  L"WinTCP", MB_OK | MB_ICONINFORMATION);
                    return TRUE;
                }
                // The list is ledger-backed and contains each installed
                // WinTCP rule, including both names in a peer-rule pair.
                const std::wstring prompt =
                    L"Remove all " + std::to_wstring(st->rules.size()) +
                    L" WinTCP-managed firewall rules?\r\n\r\n"
                    L"This unblocks the peers covered by those rules."
                    L" Any WinTCP rules created since this view was loaded"
                    L" are included too.";
                if (::MessageBoxW(hwnd, prompt.c_str(),
                                  L"WinTCP - Remove all blocks",
                                  MB_YESNO | MB_ICONWARNING |
                                      MB_DEFBUTTON2) != IDYES)
                    return TRUE;
                std::vector<std::wstring> beforeNames;
                beforeNames.reserve(st->rules.size());
                for (const BlockedRule& rule : st->rules)
                    beforeNames.push_back(rule.name);
                std::wstring error;
                if (!RemoveAllWinTcpRules(&error)) {
                    ReloadRules(list, st);
                    const bool changed = beforeNames.size() != st->rules.size() ||
                        std::any_of(beforeNames.begin(), beforeNames.end(),
                            [&](const std::wstring& name) {
                                return std::none_of(st->rules.begin(), st->rules.end(),
                                    [&](const BlockedRule& current) {
                                        return current.name == name;
                                    });
                            });
                    if (changed) st->dirty = true;
                    ::MessageBoxW(
                        hwnd,
                        (L"Could not remove every rule:\r\n" + error).c_str(),
                        L"WinTCP", MB_OK | MB_ICONERROR);
                    return TRUE;
                }
                st->dirty = true;   // every rule was removed
                ReloadRules(list, st);
                return TRUE;
            }
            break;
        }
        case WM_CLOSE:
            st->choice = st->dirty
                             ? BlockedPeersChoice::kChanged
                             : BlockedPeersChoice::kClosed;
            ::EndDialog(hwnd, FALSE);
            return TRUE;
        default:
            break;
    }
    return FALSE;
}
}  // namespace

// The single-column row text from the old list-box layout. NOT what the
// dialog shows any more - the report view paints Rule/Remote/Status cells
// (BlockedPeersCellText). It stays exported because
// the selftest pins it: a truncation capacity is untestable through a modal
// the UI harness cannot dismiss, so what is tested is what ships as a
// unit-tested helper rather than nothing.
std::wstring BlockedPeersRowText(const BlockedRule& r) {
    std::wstring text = r.name;
    if (!r.enabledKnown) text += L"  [status unknown]";
    else if (!r.enabled) text += L"  [disabled]";
    if (!r.blockingKnown) text += L"  [rule type unknown]";
    else if (!r.isBlocking) text += L"  [not a block]";
    if (!r.remoteAddrsKnown) text += L"  [remote scope unknown]";
    else if (!r.remoteAddrs.empty() && r.remoteAddrs != L"*")
        text += L"  " + r.remoteAddrs;
    if (!r.remotePortsKnown) text += L"  [remote ports unknown]";
    else if (!r.remotePorts.empty() && r.remotePorts != L"*")
        text += L":" + r.remotePorts;
    if (text.size() > kRowTextChars) {
        return Utf8ToWide(
            TruncateToWidthOpt(WideToUtf8(text), kRowTextChars).c_str());
    }
    return text;
}

int BlockedPeersControlCount() {
    return kControlCount;
}

// One cell of the report view. The columns render the same fields
// the single-line row text renders, split so each is sortable: the name
// identifies, Remote scopes ("any" when the rule carries no scope), and
// Status states - with the two warning states as column values rather
// than text suffixes, so sorting by Status groups them.
std::wstring BlockedPeersCellText(const BlockedRule& r, int column) {
    if (column == kBlockedColRemote) {
        if (!r.remoteAddrsKnown || !r.remotePortsKnown)
            return std::wstring(L"unknown");
        std::wstring text = (r.remoteAddrs.empty() || r.remoteAddrs == L"*")
                                ? L"any" : r.remoteAddrs;
        if (!r.remotePorts.empty() && r.remotePorts != L"*")
            text += L":" + r.remotePorts;
        if (text.size() > kRowTextChars) {
            return Utf8ToWide(
                TruncateToWidthOpt(WideToUtf8(text), kRowTextChars).c_str());
        }
        return text;
    }
    if (column == kBlockedColStatus) {
        if (!r.blockingKnown || (r.isBlocking && !r.enabledKnown))
            return std::wstring(L"unknown");
        if (!r.isBlocking) return std::wstring(L"not a block");
        return r.enabled ? std::wstring(L"enabled")
                         : std::wstring(L"disabled");
    }
    return r.name;
}

size_t BlockedPeersTemplateCapacity(size_t titleChars) {
    const size_t titleBytes = Pad4((titleChars + 1) * sizeof(wchar_t));
    constexpr wchar_t kFont[] = L"Segoe UI";
    const size_t fontBytes =
        Pad4((sizeof(kFont) / sizeof(wchar_t)) * sizeof(wchar_t));
    size_t capacity = sizeof(DLGTEMPLATE) + 4 + titleBytes + 2 + fontBytes +
                      kTemplateSlack;
    for (int i = 0; i < kControlCount; ++i) {
        capacity += sizeof(DLGITEMTEMPLATE) + 4 +
                    Pad4(kRowTextChars * sizeof(wchar_t)) + 2;
    }
    return capacity;
}

// Exported for the selftest, which pins the writer's arithmetic. Keeping it
// out of the anonymous namespace is what makes "what is tested is what
// ships" true, the same way PromptDialog's TemplateFits does.
bool BlockedPeersTemplateFits(const wchar_t* title, std::vector<BYTE>* buf) {
    if (title == nullptr || buf == nullptr || buf->empty()) return false;
    std::vector<BYTE> made = MakeTemplate(title);
    if (made.size() > buf->size()) return false;
    buf->assign(made.begin(), made.end());
    return true;
}

BlockedPeersChoice ShowBlockedPeersDialog(HWND owner, std::wstring* failure) {
    std::wstring error;
    std::vector<BlockedRule> rules;
    if (!ListBlockedRules(&rules, &error)) {
        if (failure != nullptr) *failure = error;
        return BlockedPeersChoice::kRefused;
    }

    std::vector<BYTE> tpl = MakeTemplate(L"Blocked peers");
    if (tpl.empty()) {
        if (failure != nullptr) *failure = L"could not build the dialog";
        return BlockedPeersChoice::kRefused;
    }

    BlockedPeersState st;
    st.rules = std::move(rules);
    const INT_PTR rc = ::DialogBoxIndirectParamW(
        ::GetModuleHandleW(nullptr), reinterpret_cast<LPCDLGTEMPLATEW>(tpl.data()),
        owner, BlockedPeersProc, reinterpret_cast<LPARAM>(&st));
    if (rc <= 0) {
        if (failure != nullptr) *failure = L"the dialog could not be shown";
        return BlockedPeersChoice::kRefused;
    }
    return st.choice;
}

}  // namespace wintcp
