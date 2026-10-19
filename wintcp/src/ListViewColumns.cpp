// ListViewColumns.cpp
// SPDX-License-Identifier: Apache-2.0
// See ListViewColumns.h.

#include "ListViewColumns.h"

#include "MainWindowInternal.h"   // kColumns, kDisplayOrder, FindColumnsMenu, IsTrafficColumn
#include "resource.h"
#include "Settings.h"              // FoldVisibleOrder

namespace wintcp {

// The shared constants and helpers come from MainWindowInternal.h in
// namespace wintcp::mw; brought in unqualified because that is how every call
// site reads.
using namespace mw;

// ---- the offered-column set ---------------------------------------------
//
// Two different sets, deliberately separate:
//
//   OfferedColumns() - the columns we WILL show. kDisplayOrder as-is, and its
//                      length is whatever is listed there.
//   OrderedColumns() - a full permutation over all COL_COUNT ids, the offered
//                      ones first and the unoffered ones appended.
//
// They differ because colOrder_ has to be a complete permutation: the settings
// round trip writes and reads COL_COUNT entries, and a short one would shift
// every saved position. The offer question has only the offered ids in it.
// Conflating them made "is this column offered" true for every id - including
// the reserved one - which is exactly what the new gate check caught.
//
// kDisplayOrder is a DEDUCED-size array, not `[COL_COUNT]`: declaring it with
// a fixed size and then removing an entry zero-fills the tail, which every
// iterating caller would read as COL_PROTO a second time.
//
// A ColumnId absent from kDisplayOrder is reserved: not inserted into the
// header, not offered in View > Columns, and not saved into a preset. COL_TLS
// is the one case - no socket-level TLS source exists, so it answers "unknown"
// on every row. The ColumnId, its mask bit and its width all stay defined.
namespace {

std::vector<int> BuildOrderedColumns() {
    std::vector<int> order;
    order.reserve(static_cast<size_t>(COL_COUNT) + 1);
    std::vector<char> offered(static_cast<size_t>(COL_COUNT), 0);
    for (const int c : mw::kDisplayOrder) {
        if (c < 0 || c >= COL_COUNT) continue;
        order.push_back(c);
        offered[static_cast<size_t>(c)] = 1;
    }
    // The unoffered ids still exist in the permutation - see above. Appended
    // after the offered ones, so they never reach the header.
    for (int c = 0; c < COL_COUNT; ++c)
        if (!offered[static_cast<size_t>(c)]) order.push_back(c);
    return order;
}

}  // namespace

const std::vector<int>& ListViewColumns::OfferedColumns() {
    static const std::vector<int> offered(
        std::begin(mw::kDisplayOrder), std::end(mw::kDisplayOrder));
    return offered;
}

const std::vector<int>& ListViewColumns::OrderedColumns() {
    static const std::vector<int> order = BuildOrderedColumns();
    return order;
}

bool ListViewColumns::IsOffered(int columnId) {
    if (columnId < 0 || columnId >= COL_COUNT) return false;
    for (const int c : OfferedColumns())
        if (c == columnId) return true;
    return false;
}
void ListViewColumns::LoadFromSettings(const Settings& s) {
    // Order first: Start from the built-in order and only override it if the
    // registry holds a validated permutation. Settings::Load has already
    // rejected anything malformed, so no re-check is needed here.
    colOrder_ = OrderedColumns();
    if (s.colOrderValid) {
        for (int i = 0; i < COL_COUNT; ++i)
            colOrder_[static_cast<size_t>(i)] = s.colOrder[i];
    }
    Reset();                                  // default mask + widths first
    SetVisibleMask(s.colVisible);
    if (s.colWidthsValid) {
        for (int i = 0; i < COL_COUNT; ++i) {
            if (s.colWidths[i] > 0)
                colWidths_[static_cast<size_t>(i)] = s.colWidths[i];
        }
    }
}

void ListViewColumns::SaveToSettings(Settings* s) const {
    if (s == nullptr) return;
    s->colVisible = visibleCols_;
    for (int i = 0; i < COL_COUNT; ++i)
        s->colWidths[i] = colWidths_[static_cast<size_t>(i)];
    s->colWidthsValid = true;
    for (int i = 0; i < COL_COUNT && i < static_cast<int>(colOrder_.size()); ++i)
        s->colOrder[i] = colOrder_[static_cast<size_t>(i)];
}

void ListViewColumns::Reset() {
    // The full permutation, offered columns first, so a header rebuild and the
    // settings round trip both see COL_COUNT entries.
    colOrder_ = OrderedColumns();
    for (int i = 0; i < COL_COUNT; ++i)
        colWidths_[static_cast<size_t>(i)] = kColumns[i].width;
    visibleCols_ = kDefaultVisibleCols;
    visToCol_.clear();
}

namespace {

// All bits that name a real column. Computed at compile time so the shift is
// never emitted: COL_COUNT is 32 today (the 32-column freeze, enforced by a
// static_assert on the mask width), and spelling "all 32 bits" as
// `1u << 32` is undefined even though the branch would never be taken.
constexpr std::uint32_t AllColumnBits(int count) {
    return (count >= 32) ? 0xFFFFFFFFu
                         : ((count > 0) ? ((std::uint32_t{1} << count) - 1u)
                                        : 0u);
}
constexpr std::uint32_t kAllColumnBits = AllColumnBits(COL_COUNT);

}  // namespace

void ListViewColumns::SetVisibleMask(std::uint32_t mask) {
    // No bit outside this build's columns: the mask is persisted and read
    // back from a file that could have come from a newer build.
    visibleCols_ = mask & kAllColumnBits;
}

int ListViewColumns::Scale(int logical, int dpi) const {
    return ::MulDiv(logical, dpi, kUnscaledDpi);
}

void ListViewColumns::SyncColumns(HWND list, int dpi) {
    if (list == nullptr) return;
    HWND hdr = ListView_GetHeader(list);
    if (hdr != nullptr) {
        const int existing = Header_GetItemCount(hdr);
        for (int i = existing - 1; i >= 0; --i)
            ::SendMessageW(list, LVM_DELETECOLUMN, static_cast<WPARAM>(i), 0);
    }

    // The mapping is rebuilt, not extended: deleting the columns above leaves
    // the old mapping claiming columns the control no longer has, and every
    // later notification is read through it. Clearing here is what makes the
    // second rebuild of a column set produce the same mapping as the first.
    visToCol_.clear();
    // colOrder_ is sized at construction, but a defensive check here costs
    // nothing and turns a would-be null-deref into a visibly empty list: a
    // release-only crash in a column loop is not worth debugging twice.
    if (static_cast<int>(colOrder_.size()) != COL_COUNT) {
        Reset();
        return;
    }
    LVCOLUMNW col = {};
    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT | LVCF_SUBITEM;
    for (const int c : colOrder_) {
        // Two gates, both necessary. The mask bit is the user's choice; the
        // offered set is the tool's. A column whose bit is set but which is
        // reserved (COL_TLS from a settings file written by an older build,
        // say) must not appear - the bit alone would put a blank column back.
        if (!IsOffered(c)) continue;
        if ((visibleCols_ & (1u << c)) == 0) continue;
        col.pszText = const_cast<LPWSTR>(kColumns[static_cast<size_t>(c)].title);
        col.cx = Scale(colWidths_[static_cast<size_t>(c)], dpi);
        col.fmt = kColumns[static_cast<size_t>(c)].fmt;
        col.iSubItem = static_cast<int>(visToCol_.size());
        const LRESULT idx = ::SendMessageW(
            list, LVM_INSERTCOLUMNW,
            static_cast<WPARAM>(visToCol_.size()),
            reinterpret_cast<LPARAM>(&col));
        if (idx >= 0) visToCol_.push_back(c);
    }
}

void ListViewColumns::HarvestWidths(HWND list, int dpi) {
    if (list == nullptr) return;
    HWND hdr = ListView_GetHeader(list);
    if (hdr == nullptr) return;
    const int existing = Header_GetItemCount(hdr);
    for (int i = 0; i < existing && i < static_cast<int>(visToCol_.size()); ++i) {
        HDITEMW hdi = {};
        hdi.mask = HDI_WIDTH;
        if (Header_GetItem(hdr, i, &hdi)) {
            // Physical pixels -> logical 96-dpi units.
            colWidths_[static_cast<size_t>(visToCol_[static_cast<size_t>(i)])] =
                ::MulDiv(hdi.cxy, kUnscaledDpi, dpi);
        }
    }
}

bool ListViewColumns::SyncOrderFromHeader(HWND list) {
    if (list == nullptr) return false;
    HWND hdr = ListView_GetHeader(list);
    if (hdr == nullptr) return false;
    const int count = Header_GetItemCount(hdr);
    if (count <= 0 || static_cast<int>(visToCol_.size()) != count) return false;

    std::vector<int> headerOrder(static_cast<size_t>(count), -1);
    if (!ListView_GetColumnOrderArray(list, count, headerOrder.data()))
        return false;

    // The order the control ended up in, as ColumnIds.
    std::vector<int> newVisible;
    newVisible.reserve(static_cast<size_t>(count));
    std::vector<bool> seen(static_cast<size_t>(count), false);
    for (const int subItem : headerOrder) {
        if (subItem < 0 || subItem >= count ||
            seen[static_cast<size_t>(subItem)])
            return false;
        seen[static_cast<size_t>(subItem)] = true;
        const int col = VisibleToCol(subItem);
        if (col < 0) return false;
        newVisible.push_back(col);
    }
    if (newVisible == visToCol_) return false;   // no drag actually happened

    // Fold the visible result back into a full-order permutation. Shared with
    // the selftest (Settings.h) so the rule cannot drift: a copy of this
    // logic in the window would be a second thing to keep correct.
    std::uint32_t offeredVisibleMask = 0;
    for (const int column : OfferedColumns()) {
        if ((visibleCols_ & (std::uint32_t{1} << column)) != 0)
            offeredVisibleMask |= std::uint32_t{1} << column;
    }
    const std::vector<int> result =
        FoldVisibleOrder(colOrder_, offeredVisibleMask, newVisible);
    if (result.size() != colOrder_.size()) return false;   // paranoia
    if (result == colOrder_) return false;
    colOrder_ = result;
    // visToCol_ is deliberately NOT written here: the caller's SyncColumns
    // rebuilds it, and overwriting it first would discard the mapping the
    // header state was just read through.
    return true;
}

bool ListViewColumns::Toggle(int columnId) {
    if (columnId < 0 || columnId >= COL_COUNT) return false;
    // A reserved column cannot be shown, however its mask bit is set. The menu
    // item does not exist, so this is reachable only from a stale setting or a
    // future caller - and silently toggling an unshowable column would be a
    // command that appears to do nothing.
    if (!IsOffered(columnId)) return false;
    const std::uint32_t bit = 1u << columnId;
    // Never let the last visible column be hidden: the list would render
    // empty and the only way back is this same menu.
    if ((visibleCols_ & bit) != 0 && (visibleCols_ & bit) == visibleCols_)
        return false;
    visibleCols_ ^= bit;
    return true;
}

void ListViewColumns::SyncMenuChecks(HMENU mainMenu) const {
    HMENU colsMenu = FindColumnsMenu(mainMenu);
    if (colsMenu == nullptr) return;
    // The columns we OFFER, which is kDisplayOrder - not every ColumnId that
    // exists. A ColumnId can exist without being offered (COL_TLS is reserved
    // and never populated), and ticking a menu item for a column that cannot
    // be shown is a menu item that does nothing when clicked.
    for (const int c : kDisplayOrder) {
        if (c < 0 || c >= COL_COUNT) continue;
        ::CheckMenuItem(colsMenu, IDM_COL_BASE + c,
                        MF_BYCOMMAND |
                        ((visibleCols_ & (1u << c)) ? MF_CHECKED : MF_UNCHECKED));
    }
}

void ListViewColumns::UpdateSortIndicator(HWND list, int sortColumn,
                                         bool ascending) const {
    if (list == nullptr) return;
    HWND hdr = ListView_GetHeader(list);
    if (hdr == nullptr) return;
    const int n = Header_GetItemCount(hdr);
    const int target = ColToVisible(sortColumn);
    for (int i = 0; i < n; ++i) {
        HDITEMW hdi = {};
        hdi.mask = HDI_FORMAT;
        if (!Header_GetItem(hdr, i, &hdi)) continue;
        hdi.fmt &= ~(HDF_SORTUP | HDF_SORTDOWN);
        if (i == target)
            hdi.fmt |= ascending ? HDF_SORTUP : HDF_SORTDOWN;
        Header_SetItem(hdr, i, &hdi);
    }
}

void ListViewColumns::SetGroupTitle(HWND list, bool grouped,
                                    size_t groupCount) const {
    if (list == nullptr) return;
    HWND hdr = ListView_GetHeader(list);
    if (hdr == nullptr) return;
    const int vi = ColToVisible(COL_PROCESS);
    if (vi < 0) return;
    // In grouped mode the rows are per-process aggregates, and the header of
    // the column that carries the aggregation says so with the live group
    // count. A flat view keeps the plain title, so the label is state rather
    // than decoration.
    std::wstring title = kColumns[COL_PROCESS].title;
    if (grouped) {
        title += L" (";
        title += std::to_wstring(groupCount);
        title += L" groups)";
    }
    HDITEMW hdi = {};
    hdi.mask = HDI_TEXT;
    hdi.pszText = const_cast<LPWSTR>(title.c_str());
    ::SendMessageW(hdr, HDM_SETITEMW, static_cast<WPARAM>(vi),
                   reinterpret_cast<LPARAM>(&hdi));
}

int ListViewColumns::VisibleToCol(int visibleIndex) const {
    if (visibleIndex < 0 || visibleIndex >= static_cast<int>(visToCol_.size()))
        return -1;
    return visToCol_[static_cast<size_t>(visibleIndex)];
}

int ListViewColumns::ColToVisible(int columnId) const {
    for (size_t i = 0; i < visToCol_.size(); ++i)
        if (visToCol_[i] == columnId) return static_cast<int>(i);
    return -1;
}

bool ListViewColumns::AnyTrafficVisible() const {
    return (visibleCols_ & ((1u << COL_TRAFFIC) | (1u << COL_RX) |
                            (1u << COL_TX) | (1u << COL_NETTOTAL))) != 0;
}

}  // namespace wintcp
