// ListViewColumns.h
// SPDX-License-Identifier: Apache-2.0
//
// The list view's column geometry: which columns are visible (a 32-bit mask,
// one bit per ColumnId), what width each has (96-dpi logical units), the
// order they appear in, and the visible-index <-> ColumnId mapping the
// control itself uses.
//
// Extracted from MainWindow because it is the one part of the window that is
// state plus control messages and nothing else - it never asks about a row,
// a filter or a refresh, which is what makes it the first safe move of the
// deep split. Ordering the state this way means the header drag path, the
// menu-tick path and the persistence path all talk to one object instead of
// three copies of a bitmask.
//
// What is deliberately NOT here and stays with the window: the dialogs (the
// last-visible-column warning), the side effects (the traffic counters a
// traffic column implies), the persistence (which settings key it lands in)
// and the repaint. A class that owned those would own the window.

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
#include <vector>

#include "Columns.h"
#include "MainWindowInternal.h"   // kDisplayOrder: the offered-column set
#include "Settings.h"      // the stored mask / widths / order

namespace wintcp {

class ListViewColumns {
public:
    // The design pixel size the stored widths are in. A width is converted
    // once, at the control boundary, because storing physical pixels and
    // moving the window to another monitor made every column wrong.
    static constexpr int kUnscaledDpi = 96;

    // The settings round trip: the visible mask, the widths and the order.
    // Kept here, in one pair of methods, because it was three loops in
    // OnCreate and three more across the two save paths - each of which had
    // to agree with the others about what a stored width meant.
    void LoadFromSettings(const Settings& s);
    void SaveToSettings(Settings* s) const;

    // The built-in state: default mask, default order, default widths. What
    // the Reset-layout command restores and what a first run starts from.
    void Reset();

    // Replace the visible mask. Clamped so no bit outside COL_COUNT can be
    // set - a mask read from a file that says more columns exist than this
    // build has would otherwise corrupt every later test of the bit.
    void SetVisibleMask(std::uint32_t mask);

    // Rebuild the control's columns from the order and the mask, and rebuild
    // the visible-index mapping the control's own notifications are read
    // through. Not const: the mapping is state, and it is rebuilt here so a
    // caller cannot be left holding a version that claims a column the
    // control refused to insert.
    void SyncColumns(HWND list, int dpi);

    // Read the control's current widths back into logical units, so a rebuild
    // does not clobber widths the user dragged.
    void HarvestWidths(HWND list, int dpi);

    // Fold a header drag back into the full permutation. Returns true when
    // the order actually changed, so the caller persists and re-applies only
    // for a real drag. The folding rule is the shared one in Settings.h - the
    // selftest needs it too, so it is not duplicated here.
    bool SyncOrderFromHeader(HWND list);

    // Toggle one column. Returns false and changes nothing when this would
    // hide the last visible column - the caller reports that, because a
    // dialog is a window concern.
    bool Toggle(int columnId);

    // The View > Columns ticks.
    void SyncMenuChecks(HMENU mainMenu) const;

    // The sort arrow on the sorted column's header.
    void UpdateSortIndicator(HWND list, int sortColumn, bool ascending) const;

    // In grouped mode the aggregation column's header carries the live group
    // count. 'grouped' rather than the group count alone, so a flat view
    // restores the plain title.
    void SetGroupTitle(HWND list, bool grouped, size_t groupCount) const;

    // The control's visible index <-> ColumnId mapping.
    int VisibleToCol(int visibleIndex) const;
    int ColToVisible(int columnId) const;

    std::uint32_t VisibleMask() const { return visibleCols_; }
    bool IsVisible(int columnId) const {
        return columnId >= 0 && columnId < COL_COUNT &&
               (visibleCols_ & (1u << columnId)) != 0;
    }
    int Width(int columnId) const {
        if (columnId < 0 || columnId >= COL_COUNT) return 0;
        return colWidths_[static_cast<size_t>(columnId)];
    }
    const std::vector<int>& Order() const { return colOrder_; }
    const std::vector<int>& VisToCol() const { return visToCol_; }

    // True when any of the ETW-fed traffic columns is shown. The window needs
    // this to decide whether to keep paying for socket scans, so it is a
    // question rather than something the window recomputes from the mask.
    bool AnyTrafficVisible() const;

    // The copy path needs the column titles in display order, and the
    // tab-separated export needs the ids in the same order. Both are the
    // control's own mapping, exposed rather than re-derived per caller.
    const std::vector<int>& VisibleOrder() const { return visToCol_; }

    // The order the columns are offered in, which doubles as the set of
    // columns that are offered AT ALL. kDisplayOrder (MainWindowInternal.h)
    // is the single source: a ColumnId absent from it is not inserted into the
    // header, not offered in the menu, and not saved into a preset. See the
    // free functions in ListViewColumns.cpp, which are the one implementation.
    static const std::vector<int>& OfferedColumns();
    static bool IsOffered(int columnId);
    // The full permutation (offered first, unoffered appended), which is what
    // colOrder_ is seeded from and what the settings round trip writes.
    static const std::vector<int>& OrderedColumns();

private:
    // Scale a logical width to pixels at 'dpi'.
    int Scale(int logical, int dpi) const;

    std::uint32_t visibleCols_ = 0;   // one bit per ColumnId
    int colWidths_[COL_COUNT] = {};   // 96-dpi logical units
    std::vector<int> visToCol_;       // visible index -> ColumnId
    // The user's column order: a permutation over ALL ColumnIds, seeded from
    // kDisplayOrder and rewritten by a header drag. A vector, not an array,
    // because a settings file can name fewer ids than this build has and the
    // defensive path below must be able to resize.
    //
    // ALL ColumnIds, including the unoffered ones: the settings round trip
    // writes and reads COL_COUNT entries, so a short permutation would shift
    // every saved position. Unoffered ids are appended after the offered ones,
    // so they never reach the header.
    std::vector<int> colOrder_ = std::vector<int>(COL_COUNT, 0);
};

}  // namespace wintcp
