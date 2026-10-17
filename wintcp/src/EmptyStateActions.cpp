// EmptyStateActions.cpp
// SPDX-License-Identifier: Apache-2.0
// See EmptyStateActions.h.

#include "EmptyStateActions.h"

namespace wintcp {

EmptyStateOffer DecideEmptyState(size_t rowsTotal, size_t viewCount,
                                 bool countryColumnVisible, bool geoLoaded,
                                 bool asnLoaded, bool trafficColumnVisible,
                                 bool etwRunning, bool socketFallback,
                                 bool processElevated) {
    EmptyStateOffer offer;

    // 1. NO ROWS > 2. DATABASE > 3. TRAFFIC. The same order
    // MainWindow::UpdateEmptyState uses, and for the same reason: with no rows
    // at all the other two answer a question nobody asked.
    //
    // The filter case is "there IS traffic, the filter hides it". A store with
    // no rows at all is the normal case on a quiet machine and is not an empty
    // state, which is why rowsTotal is the discriminator and not viewCount
    // alone.
    if (rowsTotal != 0 && viewCount == 0) {
        offer.caze = EmptyStateCase::kNoFilterMatch;
        offer.message = L"no rows match this filter";
        // [Clear] does the thing the sentence already names, and [Edit] puts
        // the caret in the box so the expression can be fixed rather than
        // thrown away. Both are offered because "clear it" and "fix it" are
        // different intentions and guessing on the user's behalf loses work.
        offer.offerClear = true;
        offer.offerEdit = true;
        return offer;
    }

    // Both databases count, because either fills the cell - the same predicate
    // the window uses.
    if (countryColumnVisible && !geoLoaded && !asnLoaded) {
        offer.caze = EmptyStateCase::kNoGeoIp;
        offer.message = L"no GeoIP database loaded";
        offer.offerPickGeo = true;
        return offer;
    }

    if (trafficColumnVisible && !etwRunning && !socketFallback) {
        offer.caze = EmptyStateCase::kNoTraffic;
        offer.message = L"traffic not being measured";

        // [Run as admin] ONLY when not already elevated. The one click that
        // helps here is relaunching with more rights; a process that already
        // has them cannot restart itself into a higher one, so the button
        // would do nothing at all.
        if (!processElevated) {
            offer.offerRunAdmin = true;
        }
        return offer;
    }

    return offer;   // kNone, no buttons
}

}  // namespace wintcp
