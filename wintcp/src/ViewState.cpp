// ViewState.cpp
// SPDX-License-Identifier: Apache-2.0
// See ViewState.h.

#include "ViewState.h"

#include "ConnectionStore.h"
#include "Utils.h"

namespace wintcp {

void ViewState::ApplyTo(ConnectionStore* store,
                        std::vector<FilterClause>* out) const {
    if (store == nullptr) return;

    // 1. Sort FIRST, before filtering, because grouping later collapses an
    //    already-ordered list and the group order is meant to follow the row
    //    order. Doing it in any other order would produce a group ordering that
    //    nothing else agrees with.
    store->SetSort(sortColumn, sortAsc);

    // 2. Grouping is a flag plus a rebuild. Set before SetView so that the
    //    single rebuild at the end of SetView produces the final shape; doing
    //    it after would rebuild twice for the same result.
    store->SetGrouped(grouped);

    // 3. Filter + sort + (re)build the view. ParseFilter never fails: text it
    //    cannot understand degrades to a plain substring match, which is the
    //    documented behaviour of the GUI's filter box too. Parsing here rather
    //    than at each call site is what keeps the two front ends honest - the
    //    GUI's filter box and the CLI's --filter go down the identical path.
    std::vector<FilterClause> program;
    if (!filter.empty()) ParseFilter(filter, program);
    if (out != nullptr) *out = program;

    ViewQuery q;
    q.protoMask = protoMask;
    q.stateFilter = stateFilter;
    q.program = program.empty() ? nullptr : &program;
    store->SetView(q);
}

bool ViewState::IsTrivial() const {
    return filter.empty() &&
           protoMask == kProtoMaskAll &&
           stateFilter == kAllStates &&
           sortColumn == COL_PID &&
           sortAsc &&
           !grouped;
}

}  // namespace wintcp
