// UiProbe.cpp
// SPDX-License-Identifier: Apache-2.0
//
// The in-process UI test harness - the only definition of it.
//
// THIS FILE IS NOT LINKED INTO wintcp.exe. It is linked into wintcp-dev.exe
// and into the test driver, and into nothing else. Nothing in the product
// calls MainWindow::UiProbe and nothing in the product can reach it: the
// declaration lives in MainWindow.h where the harness can see it, the
// definition lives here, and the product link line never mentions this file.
//
// Why it moved out of MainWindow.cpp: the product and the harness are two
// audiences with two link lines, and until now the only thing separating them
// was a promise. ~450 lines of the 5,000 in MainWindow.cpp existed for the
// test, were compiled into the shipped binary for no runtime benefit, and
// were reachable by any caller who knew the call - with nothing in the build
// showing which lines were for the user and which for the test.
//
// What the harness drives is the SAME HandleMessage() the user's keyboard and
// mouse go through, so this is not a second implementation of the program;
// it is the program answering questions about itself. Every branch reports
// OBSERVED state, never intent: if a menu command silently did nothing, the
// field it should have changed is still false and this says "false".

#include "MainWindow.h"

#include <algorithm>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "Commands.h"         // PidKillVerdict: the kill-guard's verdict
#include "ConnectionStore.h"   // the column/mask the probe reports
#include "MainWindowInternal.h"   // kProbeBufChars and the shared constants
#include "ProcessInfo.h"       // ProcessRecord, EnumerateProcesses
#include "RefreshEngine.h"     // PidKillVerdict: the kill-guard's verdict
#include "RowAccessible.h"     // the accessible-name builders it reads
#include "Settings.h"          // the persisted settings the probe reports

namespace wintcp {

// In-process UI harness (UiHarness.cpp) --------------------------------------
//
// The harness sends real messages - WM_COMMAND with resource ids, WM_CHAR,
// WM_NOTIFY - through the same HandleMessage() the user's keyboard and mouse
// go through. What it cannot do is read the RESULT, because every field here
// is private and there is no interactive desktop in this environment for an
// out-of-process reader to look at. So the window answers questions about
// itself.
//
// Every branch below reports OBSERVED state, never intent. If a menu command
// silently did nothing, frozen_ is still false and this says "false" - and
// that is the whole point: checking that a menu item EXISTS is not checking
// that activating it changes anything, and the second is what this is for.
// ---------------------------------------------------------------------------
// The shared constants (kProbeBufChars and friends) live in wintcp::mw via
// MainWindowInternal.h; brought in unqualified because that is how every call
// site reads.
using namespace mw;

const wchar_t* MainWindow::UiProbe(const wchar_t* op, const wchar_t* arg) const {
    static wchar_t buf[kProbeBufChars];
    if (op == nullptr) return nullptr;

    if (::wcscmp(op, L"frozen") == 0) {
        return frozen_ ? L"1" : L"0";
    }
    if (::wcscmp(op, L"colOffered") == 0) {
        // Is this ColumnId offered at all? A reserved column is defined and
        // has a mask bit, but is not shown - see the note on the enum in
        // Columns.h. Exposed so the gate can pin the offer set.
        const int col = ::_wtoi(arg);
        return ListViewColumns::IsOffered(col) ? L"1" : L"0";
    }
    if (::wcscmp(op, L"offeredCount") == 0) {
        // How many columns are offered. COL_COUNT minus the reserved ones, so
        // a change to the offer set is a visible change here rather than a
        // silent one.
        ::swprintf_s(buf, L"%zu", ListViewColumns::OfferedColumns().size());
        return buf;
    }
    if (::wcscmp(op, L"grouped") == 0) {
        return groupByProcess_ ? L"1" : L"0";
    }
    if (::wcscmp(op, L"treeMode") == 0) {
        // whether the main window is showing the tree instead of
        // the list. Read from the control's state rather than from a
        // re-derived variable, so a mode that failed to apply cannot lie.
        return (treeMode_ && hwndTree_ != nullptr) ? L"1" : L"0";
    }
    if (::wcscmp(op, L"treeItems") == 0) {
        // The tree control's OWN item count, not the store's process count:
        // this is what a reader would see, so an empty tree reads as 0 even
        // when the store is full (a fill that silently failed, say).
        if (hwndTree_ == nullptr) return L"-1";
        const LRESULT n = ::SendMessageW(hwndTree_, TVM_GETCOUNT, 0, 0);
        ::swprintf_s(buf, L"%lld", (long long)n);
        return buf;
    }
    if (::wcscmp(op, L"enumeratedAtFill") == 0) {
        // How many processes the LAST tree fill drew from. Comparing the
        // tree's item count with THIS (rather than with a fresh
        // enumeration) is the only race-free form of "the tree is the
        // machine's process list": the machine changes between two
        // enumerations, and a process starting in that window used to read
        // as one extra tree item.
        ::swprintf_s(buf, L"%zu", treeEnumeratedAtFill_);
        return buf;
    }
    if (::wcscmp(op, L"enumeratedProcesses") == 0) {
        // How many processes the machine reports, straight from the same
        // enumeration the tree is built from. The harness compares it with
        // the tree's item count: a tree that drew only what the connection
        // table happened to hold is smaller than this, and that difference
        // is the user's "chrome's 32 processes are missing" in one number.
        const std::vector<ProcessRecord> machine = EnumerateProcesses();
        ::swprintf_s(buf, L"%zu", machine.size());
        return buf;
    }
    if (::wcscmp(op, L"distinctConnectionPids") == 0) {
        // Distinct PIDs across the connection rows - the size of the tree
        // the old implementation produced.
        std::set<DWORD> pids;
        for (const Connection& c : store_.Rows()) pids.insert(c.identity.pid);
        ::swprintf_s(buf, L"%zu", pids.size());
        return buf;
    }
    if (::wcscmp(op, L"connectionPidList") == 0) {
        // The same set, comma-separated, so the harness can pick a tree node
        // that owns NO connection and drive the path that answers it. Without
        // this the harness has a count to compare with and no way to choose a
        // node - and the connection-less process is most of the tree.
        std::set<DWORD> pids;
        for (const Connection& c : store_.Rows()) pids.insert(c.identity.pid);
        std::wstring all;
        for (DWORD p : pids) {
            if (!all.empty()) all += L',';
            all += std::to_wstring(p);
        }
        ::wcscpy_s(buf, all.c_str());
        return buf;
    }
    if (::wcscmp(op, L"treeSelection") == 0) {
        // The list selection the tree's current node mapped to, as the pid
        // the node carries. Empty when nothing is selected or the tree has
        // no caret item - the harness asserts the mapping exists at all.
        if (hwndTree_ == nullptr) return L"";
        const HTREEITEM item = reinterpret_cast<HTREEITEM>(
            ::SendMessageW(hwndTree_, TVM_GETNEXTITEM, TVGN_CARET, 0));
        if (item == nullptr) return L"";
        TVITEMW it = {};
        it.mask = TVIF_PARAM | TVIF_HANDLE;
        it.hItem = item;
        if (::SendMessageW(hwndTree_, TVM_GETITEMW, 0,
                           reinterpret_cast<LPARAM>(&it)) == 0)
            return L"";
::swprintf_s(buf, L"%lu", static_cast<unsigned long>(it.lParam));
return buf;
}

// What the MODEL says for one row and one COLUMN ID. Uses the COLUMN ID,
// not the visible index, because the caller is naming a column.
if (::wcscmp(op, L"rowCell") == 0 && arg != nullptr) {
    const wchar_t* comma = ::wcschr(arg, L',');
    if (comma == nullptr) return L"";
    const std::wstring rowS(arg, comma - arg);
    const size_t row = static_cast<size_t>(::_wtoi(rowS.c_str()));
    const int colId = ::_wtoi(comma + 1);
    const Connection* c = store_.ViewRow(row);
    if (c == nullptr || colId < 0) return L"";
    static wchar_t cell[kProbeBufChars];
    ConnectionStore::GetColumnText(*c, colId, cell, kProbeBufChars);
    return cell;
}

// What the list view ACTUALLY DREW.
//
// Every other probe here reads the MODEL, and a full model says nothing about
// a control whose cells render blank. That is not hypothetical: the list view
// was extracted into its own translation unit while the harness was still
// checking only the item COUNT, so a broken LVN_GETDISPINFO would have left
// every cell empty with all 66 checks green - and it took a person opening the
// window to notice.
//
// LVM_GETITEMTEXT reaches the control's own cell text, which LVN_GETDISPINFO
// filled, so this is the drawn truth rather than the intended one.
//
// arg is "row,col": the view row and the VISIBLE column index, both of which
// the control itself works in.
if (::wcscmp(op, L"cellText") == 0 && arg != nullptr) {
    const wchar_t* comma = ::wcschr(arg, L',');
    if (comma == nullptr) return L"";
    const std::wstring rowS(arg, comma - arg);
    const int row = ::_wtoi(rowS.c_str());
    const int vis = ::_wtoi(comma + 1);
    if (list_.Handle() == nullptr || row < 0 || vis < 0) return L"";
    // STATIC, not a local: the harness copies the string on return, but
    // returning a pointer to a local array is a dangling read the moment the
    // next probe runs. Every other probe here returns a static or a member
    // buffer for the same reason.
    static wchar_t cell[kProbeBufChars];
    cell[0] = L'\0';
    LVITEMW li = {};
    li.mask = LVIF_TEXT;
    li.iItem = row;
    li.iSubItem = vis;
    li.pszText = cell;
    li.cchTextMax = kProbeBufChars;
    ::SendMessageW(list_.Handle(), LVM_GETITEMTEXTW,
                   static_cast<WPARAM>(row),
                   reinterpret_cast<LPARAM>(&li));
    return cell;
}

// The list view's own image index for a row, or -1. Read from the control
// rather than derived from the store, because the icon is resolved by the
// shell at paint time and "no icon" has several legitimate causes (a process
// with no readable path, the System process, a machine with no shell32). What
// the harness can assert is that SOME row on a real machine carries one -
// which is what catches the image list never having been attached, or the
// image never having been set, both of which render as "no icons at all".
if (::wcscmp(op, L"rowImage") == 0 && arg != nullptr) {
    const int row = ::_wtoi(arg);
    if (list_.Handle() == nullptr || row < 0) return L"";
    LVITEMW li = {};
    li.mask = LVIF_IMAGE;
    li.iItem = row;
    li.cchTextMax = 0;
    ::SendMessageW(list_.Handle(), LVM_GETITEMW, 0,
                   reinterpret_cast<LPARAM>(&li));
    ::swprintf_s(buf, L"%d", li.iImage);
    return buf;
}

if (::wcscmp(op, L"listSelectionCount") == 0) {
        const LRESULT n = ::SendMessageW(list_.Handle(), LVM_GETSELECTEDCOUNT, 0, 0);
        ::swprintf_s(buf, L"%lld", (long long)n);
        return buf;
    }
    if (::wcscmp(op, L"listSelectionPid") == 0) {
        // The PID of the first selected list row, or nothing. The harness
        // compares it with the tree's caret pid so "the node mapped to a
        // selection" is checked EXACTLY rather than as "a selection exists
        // somewhere" - the caret can legitimately sit on a process that owns
        // no connection (System, PID 4), where no row can be selected and an
        // empty answer is the correct one.
        const int sel = static_cast<int>(::SendMessageW(
            list_.Handle(), LVM_GETNEXTITEM, static_cast<WPARAM>(-1),
            MAKELPARAM(LVNI_SELECTED, 0)));
        if (sel == -1) return L"";
        const Connection* c = store_.ViewRow(static_cast<size_t>(sel));
        if (c == nullptr) return L"";
        ::swprintf_s(buf, L"%lu", static_cast<unsigned long>(c->identity.pid));
        return buf;
    }
    if (::wcscmp(op, L"preserveSelection") == 0) {
        return preserveSelection_ ? L"1" : L"0";
    }
    if (::wcscmp(op, L"rowCount") == 0) {
        // The virtual list's count is the observable contract; read it from
        // the control rather than from the store, so a view that was never
        // pushed to the screen shows up as 0 here.
        const LRESULT n = ::SendMessageW(list_.Handle(), LVM_GETITEMCOUNT, 0, 0);
        ::swprintf_s(buf, L"%lld", (long long)n);
        return buf;
    }
    if (::wcscmp(op, L"accRow") == 0) {
        // the accessible name|description the MSAA wrapper reports for
        // a view row, read without COM. Same builders the wrapper uses
        // (grouped rows name the aggregate), so the harness asserts on what
        // a screen reader actually hears. Empty for a bad index.
        long idx = -1;
        if (arg != nullptr) idx = ::wcstol(arg, nullptr, 10);
        if (idx < 0 || static_cast<size_t>(idx) >= store_.View().size())
            return L"";
        const size_t viewIdx = static_cast<size_t>(idx);
        AccessibleRowText text;
        bool have = false;
        if (const ProcessGroup* g = store_.ViewGroup(viewIdx)) {
            text = GroupRowAccessibleText(*g);
            have = true;
        } else if (const Connection* c = store_.ViewRow(viewIdx)) {
            text = FlatRowAccessibleText(*c, store_.CountForPid(c->identity.pid));
            have = true;
        }
        if (!have) return L"";
        ::swprintf_s(buf, L"%ls|%ls", text.name.c_str(),
                     text.description.c_str());
        return buf;
    }
    if (::wcscmp(op, L"columnsMenuMissing") == 0) {
        // guard: the View > Columns popup must offer a command for EVERY
        // ColumnId, or that column cannot be shown in the GUI at all - there is
        // no other way to set its bit (the mask is only writable from here).
        // Six were once missing this way (NOTE, the four `ss -i` columns and
        // GROUPRATE): resource.h had their ids and IDM_COL_COUNT counted them,
        // so the compile-time guard was satisfied, while wintcp.rc had no
        // MENUITEM for them. The guard could not see it because resource.h and
        // wintcp.rc are different files, and nothing compared them.
        //
        // Reports the ColumnId ordinals, so a failure says WHICH column is
        // unreachable rather than only how many; 'columnsMenuMissingCount' is
        // the machine-readable form the harness asserts on.
        HMENU sub = FindColumnsMenu(::GetMenu(hwnd_));
        if (sub == nullptr) return L"-1";   // popup itself not found
        wchar_t missing[kMissingColListChars] = {0};
        int count = 0;
        for (int c = 0; c < COL_COUNT; ++c) {
            if (::GetMenuState(sub, IDM_COL_BASE + c, MF_BYCOMMAND) ==
                0xFFFFFFFF) {
                wchar_t one[kCommaColChars] = {0};
                ::swprintf_s(one, L"%s%d", (count == 0) ? L"" : L",", c);
                ::wcscat_s(missing, one);
                ++count;
            }
        }
        if (count == 0) return L"0";
        // Into `buf`, not `missing`: every other branch returns the static
        // buffer, and returning a local's address would dangle the moment this
        // function returned.
        ::wcsncpy_s(buf, missing, _TRUNCATE);
        return buf;
    }
    if (::wcscmp(op, L"columnsMenuMissingCount") == 0) {
        HMENU sub = FindColumnsMenu(::GetMenu(hwnd_));
        if (sub == nullptr) return L"-1";
        int count = 0;
        for (int c = 0; c < COL_COUNT; ++c) {
            if (::GetMenuState(sub, IDM_COL_BASE + c, MF_BYCOMMAND) ==
                0xFFFFFFFF)
                ++count;
        }
        ::swprintf_s(buf, L"%d", count);
        return buf;
    }
    if (::wcscmp(op, L"lastRefreshTime") == 0) {
        ::wcsncpy_s(buf, lastRefreshTime_.c_str(), _TRUNCATE);
        return buf;
    }
    if (::wcscmp(op, L"pendingRefresh") == 0) {
        // The worker's callback inserts here BEFORE posting WM_APP_REFRESH_RESULT
        // and OnRefreshResult erases from it. A non-zero count with an empty
        // store therefore means the message was posted but never dispatched -
        // which is exactly the "list never populates" symptom.
        // mutable so this const accessor can take the lock.
        std::lock_guard<std::mutex> lk(Sink()->m);
        ::swprintf_s(buf, L"%zu", Sink()->pendingRefresh.size());
        return buf;
    }
    if (::wcscmp(op, L"engineRunning") == 0) {
        return engine_.Running() ? L"1" : L"0";
    }
    if (::wcscmp(op, L"lastError") == 0) {
        ::wcsncpy_s(buf, lastError_.c_str(), _TRUNCATE);
        return buf;
    }
    if (::wcscmp(op, L"autoRefresh") == 0) {
        return autoRefresh_ ? L"1" : L"0";
    }
    if (::wcscmp(op, L"detailsVisible") == 0) {
        return details_.IsVisible() ? L"1" : L"0";
    }
    if (::wcscmp(op, L"detailsTitle") == 0) {
        // The current details model's header, e.g. "chrome.exe". The pid is
        // NOT in it (the model puts it in the subtitle), so a check that needs
        // to know WHICH process the window describes reads 'detailsPid'
        // instead - which is also the pid the window tracks for its live
        // updates, and therefore the thing that is wrong when the wrong
        // Details opens.
        return detailsModel_.title.c_str();
    }
    if (::wcscmp(op, L"detailsPid") == 0) {
        // The pid the details window is describing. Set by every path that
        // opens it, so an empty answer means "Details was never opened".
        if (detailsPid_ == 0) return L"";
        ::swprintf_s(buf, L"%lu", static_cast<unsigned long>(detailsPid_));
        return buf;
    }
    if (::wcscmp(op, L"chartsVisible") == 0) {
        return charts_.IsVisible() ? L"1" : L"0";
    }
    if (::wcscmp(op, L"changeLogVisible") == 0) {
        return changeLog_.IsVisible() ? L"1" : L"0";
    }
    // whether the change-log window was actually CREATED, as distinct from
    // visible. IsVisible() is false both for a window that was never created and
    // for one that exists and is hidden (the WM_CLOSE path), so on its own it
    // cannot tell "the menu item did nothing" from "the log is open but behind
    // something". The harness check needs that distinction to report
    // anything useful when it fails.
    if (::wcscmp(op, L"changeLogCreated") == 0) {
        return changeLog_.IsOpen() ? L"1" : L"0";
    }
    // What Commands::PidKillVerdict() says about a PID, as this process
    // sees it. The harness runs INSIDE wintcp.exe, so asking it about
    // GetCurrentProcessId() exercises the exact self-kill case the bug report
    // was about, with the real self PID and the real rule - which is the only
    // way to catch a wiring mistake that a selftest on synthetic PIDs cannot.
    if (::wcscmp(op, L"killVerdict") == 0) {
        DWORD pid = 0;
        if (arg != nullptr)
            pid = static_cast<DWORD>(::wcstoul(arg, nullptr, 10));
        switch (PidKillVerdict(pid, ::GetCurrentProcessId(), true)) {
            case PidVerdict::Ok:         return L"ok";
            case PidVerdict::IsSelf:     return L"self";
            case PidVerdict::Pseudo:     return L"pseudo";
            case PidVerdict::NotPermitted: return L"nopermit";
        }
        return L"?";
    }
    if (::wcscmp(op, L"changeLogMaskAppear") == 0) {
        return changeLog_.EventAppear() ? L"1" : L"0";
    }
    // diagnostic: how many times the log window's WM_CREATE handler has run
    // over this session's lifetime. A count of 0 with the window VISIBLE means
    // the window was created but its controls were never built, which is the
    // one failure mode a visibility probe cannot distinguish from success.
    if (::wcscmp(op, L"changeLogCreates") == 0) {
        return std::to_wstring(changeLog_.CreateCount()).c_str();
    }
    // ...and how many children that handler currently holds. Zero with a
    // non-zero create count means the creations FAILED, which points at the
    // CreateWindowExW arguments rather than at the message plumbing.
    if (::wcscmp(op, L"changeLogChildren") == 0) {
        return std::to_wstring(changeLog_.ChildCount()).c_str();
    }
    if (::wcscmp(op, L"changeLogLastError") == 0) {
        return std::to_wstring(
                   static_cast<unsigned long>(changeLog_.LastChildError()))
            .c_str();
    }
    // "streamVisible" was removed with the hex window. Nothing queried it, and
    // a property that always answers "0" would be a lie waiting for a caller.
    if (::wcscmp(op, L"geoLoaded") == 0) {
        return enrich_.CountryLoaded() ? L"1" : L"0";
    }
    if (::wcscmp(op, L"trafficTimeouts") == 0) {
        if (socketTraffic_ == nullptr) return L"0";
        ::swprintf_s(buf, L"%u", socketTraffic_->TimeoutCount());
        return buf;
    }
    // a pass that could not read the handle table at all. Kept beside
    // trafficTimeouts because the two look identical in a table - blank traffic
    // - and a reader who cannot name the cause cannot act on it.
    if (::wcscmp(op, L"trafficScanFailures") == 0) {
        if (socketTraffic_ == nullptr) return L"0";
        ::swprintf_s(buf, L"%u", socketTraffic_->ScanFailureCount());
        return buf;
    }
    // settings writes attempted, and writes that failed. The gap between
    // them is the loss. Both read zero for the whole life of a healthy window -
    // SaveSettings runs once, from ~MainWindow - so these are diagnostic only.
    if (::wcscmp(op, L"settingsSaveAttempts") == 0) {
        ::swprintf_s(buf, L"%u", settingsSaveAttempts_);
        return buf;
    }
    if (::wcscmp(op, L"settingsSaveFailures") == 0) {
        ::swprintf_s(buf, L"%u", settingsSaveFailures_);
        return buf;
    }
    if (::wcscmp(op, L"selectionCount") == 0) {
        std::vector<int> idx;
        const bool any = list_.SelectedRowIndices(idx);
        ::swprintf_s(buf, L"%zu", any ? idx.size() : 0);
        return buf;
    }
    if (::wcscmp(op, L"selectedColumnText") == 0) {
        // Read a cell back out of the virtual list. arg is the visible index.
        const int v = (arg != nullptr) ? ::_wtoi(arg) : -1;
        if (ColToVisible(VisibleToCol(v)) != v) return L"";
        const LRESULT row = ::SendMessageW(list_.Handle(), LVM_GETNEXTITEM,
                                           static_cast<WPARAM>(-1),
                                           LVNI_FOCUSED);
        if (row < 0) return L"";
        // Ask the OWNER-DATA handler for one cell, through the same WM_NOTIFY
        // the list itself uses. iSubItem lives on the item sub-struct, which
        // is how the production LVN_GETDISPINFO handler reads it.
        NMLVDISPINFO di = {};
        di.hdr.hwndFrom = list_.Handle();
        di.hdr.idFrom = ::GetDlgCtrlID(list_.Handle());
        di.hdr.code = LVN_GETDISPINFO;
        di.item.mask = LVIF_TEXT;
        di.item.iItem = static_cast<int>(row);
        di.item.iSubItem = v;
        di.item.cchTextMax = static_cast<int>(kMaxColumnText);
        di.item.pszText = buf;
        ::SendMessageW(hwnd_, WM_NOTIFY, 0,
                       reinterpret_cast<LPARAM>(&di));
        return buf;
    }
    if (::wcscmp(op, L"rowLabel") == 0) {
        // The label OnTypeJumpChar builds its candidate list from for the
        // row named in 'arg': the process name where there is one, the local
        // address otherwise. Same string 'jumpLabel' reports, but for ANY
        // row rather than only the focused one.
        //
        // Why it exists: the type-to-jump check used to type 'a'..'z' and
        // pass only when the live process table happened to contain a row
        // starting with one of them. That made it pass or fail on which
        // processes were running rather than on whether the feature works -
        // it failed once on a machine where every label started with a digit
        // or a multi-byte sequence. A test that depends on the machine is not
        // a test of the code. With this op the check derives its letter from
        // the rows that are actually on screen.
        if (arg == nullptr) return L"";
        const long row = ::_wtol(arg);
        if (row < 0) return L"";
        const Connection* c = store_.ViewRow(static_cast<size_t>(row));
        if (c == nullptr) return L"";
        ::wcsncpy_s(buf, c->display.processName.empty() ? c->display.localAddress.c_str()
                                                : c->display.processName.c_str(),
                    _TRUNCATE);
        return buf;
    }
    if (::wcscmp(op, L"jumpLabel") == 0) {
        // The exact string OnTypeJumpChar builds its candidate list from for
        // the focused row: the process name where there is one, the local
        // address otherwise. Exposed so a test can assert the jump landed on
        // a row that really matches the typed prefix, rather than on a row
        // that merely moved.
        const LRESULT row = ::SendMessageW(list_.Handle(), LVM_GETNEXTITEM,
                                           static_cast<WPARAM>(-1),
                                           LVNI_FOCUSED);
        if (row < 0) return L"";
        const Connection* c = store_.ViewRow(static_cast<size_t>(row));
        if (c == nullptr) return L"";
        ::wcsncpy_s(buf, c->display.processName.empty() ? c->display.localAddress.c_str()
                                                : c->display.processName.c_str(),
                    _TRUNCATE);
        return buf;
    }
    if (::wcscmp(op, L"columnOrder") == 0) {
        // The persisted order, as a comma list, so the harness can prove
        // a drag actually changed the order and that it round-tripped.
        for (std::size_t i = 0; i < cols_.Order().size() && i < kMaxColOrderSlots; ++i) {
            const std::wstring piece = L" " + std::to_wstring(cols_.Order()[i]);
            ::wcsncat_s(buf, piece.c_str(), _TRUNCATE);
        }
        return buf;
    }
    if (::wcscmp(op, L"visibleCol") == 0) {
        const int v = (arg != nullptr) ? ::_wtoi(arg) : -1;
        const int col = VisibleToCol(v);
        ::swprintf_s(buf, L"%d", col);
        return buf;
    }
    if (::wcscmp(op, L"columnWidth") == 0) {
        const int v = (arg != nullptr) ? ::_wtoi(arg) : -1;
        const int col = VisibleToCol(v);
        if (col < 0) return L"";
        ::swprintf_s(buf, L"%d", cols_.Width(col));
        return buf;
    }
    if (::wcscmp(op, L"trayShown") == 0) {
        return tray_.IsShown() ? L"1" : L"0";
    }
    // which child control holds keyboard focus, so the harness can prove
    // the `/` shortcut moved focus to the filter box. "list", "filter", or ""
    // (neither - the window or another control has it).
    if (::wcscmp(op, L"focusTarget") == 0) {
        const HWND fg = ::GetFocus();
        if (fg == list_.Handle()) return L"list";
        if (fg == hwndSearchEdit_) return L"filter";
        if (fg == hwnd_) return L"window";
        return L"";
    }
    // the live bookmark count, so the harness can prove `*` toggled one.
    if (::wcscmp(op, L"bookmarkCount") == 0) {
        ::swprintf_s(buf, L"%zu", Bookmarks::List().size());
        return buf;
    }
    if (::wcscmp(op, L"topMost") == 0) {
        return topMost_ ? L"1" : L"0";
    }
    if (::wcscmp(op, L"colOrderSize") == 0) {
        ::swprintf_s(buf, L"%zu", cols_.Order().size());
        return buf;
    }
    return nullptr;
}
}  // namespace wintcp
