// ViewState.cpp
// SPDX-License-Identifier: Apache-2.0
// See ViewState.h.

#include "ViewState.h"

#include "ConnectionStore.h"
#include "Utils.h"

namespace wintcp {

void ViewState::ApplyTo(ConnectionStore* store,
                        std::vector<FilterClause>* out,
                        std::wstring* filterError) const {
    if (filterError != nullptr) filterError->clear();
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

    // 3. Filter + sort + (re)build the view. A malformed quote keeps a literal
    //    fallback clause for compatibility while reporting the syntax issue
    //    to callers that can present it.
    std::vector<FilterClause> program;
    if (!filter.empty()) ParseFilter(filter, program, filterError);
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
