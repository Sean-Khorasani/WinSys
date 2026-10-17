// ViewState.h
// SPDX-License-Identifier: Apache-2.0
// What to show: filter, sort, grouping, freeze, column set. One struct, shared
// by the GUI's live view and by a saved preset.
//
// WHY THIS EXISTS. "Which rows are visible, in what order, in what shape" is
// currently decided in two places that must agree and are not connected: a
// MainWindow member per axis (filterProgram_, groupByProcess_, frozen_, the
// sort through ConnectionStore) and PresetView, which stores a second,
// near-identical copy of most of the same decisions. Two descriptions of one
// view is two things to forget to update - the same class of fault that let
// GeoIP (778 lines, fully tested, never called) and 5.1 grouping (tested,
// wired to nothing) ship dead.
//
// So there is one type. A preset stores this; the GUI holds this; the CLI
// builds this from flags. PresetView is gone rather than kept in sync, because
// "in sync" is exactly the property that does not survive a refactor.
//
// THE INVARIANT. ViewState::ApplyTo is the ONLY place a view is built. The GUI
// must not assemble a ViewQuery itself, and the CLI must not either - both call
// ApplyTo. That is what makes a command testable without a window, and what
// stops the two front ends drifting (the fault that already cost one round:
// the CLI had a private copy of the snapshot pipeline and had silently drifted
// from the GUI's).
//
// NO HWND APPEARS HERE, AND NONE MAY BE ADDED. That is the whole point.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

#include "ColumnsWin.h"   // COL_COUNT, kDefaultVisibleCols
#include "ConnectionStore.h"   // ViewQuery, FilterClause, kProtoMaskAll, kAllStates

namespace wintcp {

// Which enrichment sources a view wants running while it is applied.
//
// These live here rather than in Settings because they are the toggles that
// decide *what the list can show* - the same decision as the filter and the
// column mask - so a view is not a view without them. A mask of 0 is
// legitimate: "just show me the rows, as fast as possible".
//
// MOVED HERE FROM Presets.h. They describe a view, not a registry record; they
// were only ever in Presets.h because PresetView was the first struct to carry
// them. A CLI that never touches the registry still needs to say "resolve
// hostnames", so the enum cannot depend on the storage that happens to persist
// it today.
enum PresetSource : unsigned {
    kPresetSourceNone   = 0,
    kPresetSourceHosts  = 1u << 0,   // reverse-DNS the remote addresses
    kPresetSourceEtw    = 1u << 1,   // per-PID traffic counters (needs elevation)
    kPresetSourceSocket = 1u << 2,   // per-socket rate sampling (Speed column)
    kPresetSourceGeoIp  = 1u << 3,   // GeoIP enrichment: country and/or ASN
    kPresetSourceAll    = 0x0Fu,
};

// The complete description of a view.
//
// Plain values only - no window handles, no pointers into a store - so a
// ViewState can be copied, stored, sent across a thread, or written to the
// registry as-is. Everything a front end needs to show the same rows in the
// same shape is here; anything a front end still computes on its own is a bug.
struct ViewState {
    // ---- the row set -------------------------------------------------------

    // Raw filter text, exactly as the GUI's filter box holds it. Kept raw
    // rather than pre-parsed because this is the string a preset round-trips
    // and the user edits; ApplyTo parses it. Parsing is cheap for short
    // strings and happens once per ApplyTo, not per keystroke (the GUI's
    // debounce owns the rate).
    std::wstring filter;

    // Protocol/family mask and the state filter. Defaults mean "everything",
    // matching ConnectionStore's own defaults so an untouched ViewState is a
    // valid "show me all of it".
    unsigned protoMask = kProtoMaskAll;
    DWORD stateFilter = kAllStates;   // 0 = "— (none)", else MIB_TCP_STATE_*

    // ---- the order ---------------------------------------------------------

    int sortColumn = COL_PID;
    bool sortAsc = true;

    // ---- the shape ---------------------------------------------------------

    // 5.1: one row per process instead of one per connection. Changes the
    // SHAPE of the list only; the underlying rows are untouched, so turning it
    // off restores the flat list exactly.
    bool grouped = false;

    // 5.5: freeze stops the DISPLAY being replaced by the next refresh tick.
    // The sampler keeps running underneath, so unfreezing shows what changed
    // rather than resuming from a stopped world. See Freeze.h for why that
    // distinction matters. Purely a display state - it does not affect which
    // rows ApplyTo selects - so it lives here for one reason: it is part of
    // "what the user is looking at", and a preset that captured a frozen view
    // should say so rather than silently thawing.
    bool frozen = false;
    // GetTickCount64() value at the moment of freezing; 0 when not frozen.
    ULONGLONG frozenAtMs = 0;

    // 7.4: keep the selected rows selected across a rebuild. A view preference,
    // not a row filter - same reasoning as frozen.
    bool preserveSelection = true;

    // ---- the columns -------------------------------------------------------

    // Which logical columns are shown. Display ORDER is deliberately NOT here:
    // it is a per-user drag-and-drop arrangement (Settings::colOrder), not part
    // of a preset - see the note in ViewState.cpp.
    UINT32 colVisible = kDefaultVisibleCols;

    // ---- the data sources --------------------------------------------------

    // PresetSource bits: which enrichment the view wants running. Part of a
    // preset because "show me the rows as fast as possible" (mask 0) and "show
    // me hostnames too" are both legitimate views, and a preset that kept the
    // filter but dropped the source flags would open a window that cannot
    // render its own columns.
    unsigned sources = kPresetSourceNone;

    // ---- the one way to apply this -----------------------------------------

    // Push this view onto 'store': set the sort, set the grouping, and set the
    // filtered/sorted view the store publishes. After this returns, the store's
    // View() is exactly what this ViewState describes.
    //
    // Order matters and is fixed here rather than at each call site: sort
    // before grouping, because grouping collapses an already-ordered list and
    // group order is meant to follow the sorted order. A call site that got
    // that backwards would produce groups in an order nothing else agrees with.
    //
    // 'out' (optional) receives the parsed filter program. The GUI needs it
    // because two other code paths ask "is a text filter active?" and must not
    // re-parse the box to find out; passing it out here means the filter is
    // parsed exactly once per apply rather than twice.
    void ApplyTo(ConnectionStore* store,
                 std::vector<FilterClause>* out = nullptr) const;

    // True when this view would show every row unfiltered and unsorted in the
    // default order. The CLI uses it to skip building a view at all for a bare
    // "give me the table" pass - the common case, and the one that should not
    // pay for a parse.
    bool IsTrivial() const;
};

// ---- PresetView is now an alias ------------------------------------------
//
// PresetView predates this file and stored {filter, colVisible, sortCol,
// sortAsc, sources} - four of the axes above plus the sources, with its own
// defaults and its own copy of the concepts. It is kept as a type alias so
// Presets.cpp, Settings.cpp and MainWindow.cpp keep compiling, but it is no
// longer a separate description: a preset IS a ViewState.
//
// ONE FIELD WAS RENAMED: PresetView::sortCol is ViewState::sortColumn. The
// alias could not have preserved the old name without a wrapper struct, and a
// wrapper struct is precisely the second description this file exists to
// delete. Three call sites in Presets.cpp and two in MainWindow.cpp were
// updated; the registry schema did NOT change, so every preset saved by an
// earlier build still loads.
//
// Note what this does NOT do: the GUI-only axes (frozen, preserveSelection) are
// present on the type but not persisted by Presets::Save, which writes a named
// subset of fields. That asymmetry is deliberate, and is why merging these two
// types was safe at all: the on-disk schema is untouched.

// A saved preset IS a ViewState.
using PresetView = ViewState;

}  // namespace wintcp
