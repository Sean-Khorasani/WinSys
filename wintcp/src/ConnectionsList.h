// ConnectionsList.h
// SPDX-License-Identifier: Apache-2.0
//
// The connections list view: its control, its row text, its painting, and its
// selection. Four of the five things the main window spends its life doing.
//
// Extracted from MainWindow because these are the parts that are genuinely
// about the list - what text a cell shows, what colour a row flashes, which
// rows are selected, what the copy path emits - and they were sitting in a
// window class that also owned the tray, the alerts, the settings, the
// presets and the worker threads.
//
// The interface is deliberately one-directional, the same rule RowEnrichment
// and TrayIcon follow: the list reports UP through ConnectionsListSink
// (a sort was requested, a row was activated, a drag started) and reads DOWN
// through QueryPainting. It never calls the window, so it can be driven - and
// reasoned about - without one.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>
#include <commctrl.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "Connection.h"
#include "ConnectionStore.h"   // FormatBytes, FormatDuration
#include "Freeze.h"            // FrozenAgeMs
#include "Grouping.h"          // ProcessGroup, GroupColumnText
#include "ListViewColumns.h"

namespace wintcp {

// What the list may ask its owner to do - and what it must be told. The
// painting decisions belong to the window (its theme, its high-contrast
// state, its empty-state hint); the list only reads them, once per paint,
// rather than reaching into the window for each.
class ConnectionsListSink {
public:
    virtual ~ConnectionsListSink() = default;

    // A header column was clicked: set the sort, repaint, re-apply.
    virtual void OnSortByColumn(int columnId, bool ascending) = 0;
    // A row was double-clicked or Entered.
    virtual void OnRowActivated() = 0;
    // A header drag started. The order is read back on a posted message,
    // because the header still holds the OLD order while the drag is
    // starting and there is no end-of-drag notification to hook.
    virtual void OnColumnDragStarted() = 0;
    // The index in the shell's system image list for a process image, or -1.
    virtual int ProcessIconIndex(const std::wstring& path) const = 0;

    // What the painter needs about the owner.
    struct Painting {
        bool highContrast = false;
        bool darkTheme = false;
        ULONGLONG snapshotTick = 0;
        const std::wstring* emptyStateHint = nullptr;   // may be null
    };
    virtual Painting QueryPainting() const = 0;
};

class ConnectionsList {
public:
    // The column geometry is a separate object on purpose (ListViewColumns),
    // and the list needs it because a cell's text is chosen BY COLUMN: the
    // control notifies with a visible index, and the mapping to a ColumnId
    // is the geometry's. Passed in by reference because the window owns it
    // and it outlives the list.
    ConnectionsList(ConnectionStore& store, ListViewColumns& cols,
                    ConnectionsListSink& sink)
        : store_(store), cols_(cols), sink_(sink) {}

    // Create the virtual list control under 'parent'. False on failure.
    bool Create(HWND parent, HINSTANCE instance);

    HWND Handle() const { return hwnd_; }

    // The item count, which is the view's row count - the store decides what
    // those rows ARE, and the list only says how many there are.
    void SetItemCount(size_t count);

    // Repaint. The one thing every refresh result ends with.
    void Invalidate();

    // Handle a WM_NOTIFY from this control. Returns an empty optional when
    // the notification was not for this list (or not recognised); otherwise
    // the exact value the parent's window proc must return. The result rather
    // than a bool, because the two questions differ: LVN_BEGINDRAG has to
    // return non-zero to PERMIT the drag, and "handled it" alone would block
    // it.
    std::optional<LRESULT> HandleNotify(const NMHDR* hdr);

    // ---- selection -------------------------------------------------------
    // Capture as row IDS (not indices): the view is rebuilt between the
    // capture and the restore, and an index captured against one view
    // selects the wrong row against the next.
    void CaptureSelection(std::vector<std::uint64_t>& ids,
                          std::uint64_t* focusedId, int* topIdx) const;
    void RestoreSelection(const std::vector<std::uint64_t>& ids,
                          std::uint64_t focusedId, int topIdx);

    bool SelectedRowIndices(std::vector<int>& out) const;
    const Connection* FirstSelectedRow() const;
    std::optional<Connection> SelectedCopy() const;
    size_t SelectedCount() const;

    // Select every row: the window's "select all" path.
    void SelectAll();

    // ---- the copy/export text -------------------------------------------
    // 'grouped' and 'frozen' are the view state the header comments name;
    // 'cols' supplies which columns are visible, in what order. Both are the
    // window's state, passed in rather than copied here, so the window has
    // one answer to each.
    std::wstring SelectedRowsText(bool copyAll, bool grouped, bool frozen,
                                  ULONGLONG frozenAtMs,
                                  const ListViewColumns& cols) const;

    // The tab-separated text for an explicit row set (the export verb).
    static std::wstring RowsToText(const std::vector<Connection>& rows,
                                   const ListViewColumns& cols);

private:
    void OnGetDispInfo(NMLVDISPINFO* di);
    void OnGetInfoTip(NMLVGETINFOTIPW* info);
    LRESULT OnCustomDraw(NMLVCUSTOMDRAW* cd);

    ConnectionStore& store_;
    ListViewColumns& cols_;
    ConnectionsListSink& sink_;
    HWND hwnd_ = nullptr;
    // The LVN_GETDISPINFO scratch: the control keeps the pointer until the
    // next request, so this outlives the handler that fills it.
    wchar_t dispBuf_[kMaxColumnText] = {0};
};

}  // namespace wintcp
