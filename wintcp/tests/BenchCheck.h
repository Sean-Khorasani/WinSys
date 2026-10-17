// BenchCheck.h
// SPDX-License-Identifier: Apache-2.0
// The `Check` helper, shared between Bench.cpp and BenchSync.cpp.
//
// WHY A HEADER. `Check` recorded into `TestResult` from inside Bench.cpp's
// anonymous namespace, so the split could not reach it. The alternatives
// were worse: hoisting into Bench.cpp proper would mean touching every
// call site in a 9,700-line file to qualify a name they all rely on
// unqualified, and duplicating the helper would have made two definitions
// of the one function that records every check - and the count V3 prints
// would have silently split in two.
//
// So the declaration lives here, the definition in Bench.cpp, and
// `FormatCheckAreas` with it (it is the other half of V3: the counting and
// the printing of it).
//
// The names are kept non-static: a `static` function in a header included
// by two translation units is a separate copy in each, which is exactly the
// duplication this file exists to avoid.

#pragma once

#include <map>
#include <string>

namespace wintcp {

struct TestResult;   // Bench.h

// Record one check. 'name' is "<area>.<...>"; the part before the first dot
// is what V3's per-area count buckets on.
void Check(TestResult& r, const char* name, bool ok,
           const std::string& detail = std::string());

// V3: the check count by area, for the summary line. See the definition for
// why it is deliberately not a fixed table of areas.
std::string FormatCheckAreas(const std::map<std::string, size_t>& areas);

}  // namespace wintcp
