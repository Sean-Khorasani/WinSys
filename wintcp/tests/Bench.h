// Bench.h
// `--selftest` (internal consistency checks) and `--bench`
// (micro-benchmark of the view pipeline: snapshot diff, filter, sort,
// column-text formatting). Both are plain-English stdout modes; no test
// framework dependency (zero-dependency build).

#pragma once

#include <map>
#include <string>
#include <vector>

namespace wintcp {

struct TestResult {
    int exitCode = 0;           // 0 = all checks passed, 1 = failures
    std::string output;         // ready to print (CRLF line endings)

    // V3. How many checks were written, bucketed by the area their name
    // carries (every check name is "<area>.<...>"). This is a COUNT OF
    // CHECKS, not coverage and not branch coverage - the harness has no
    // instrumentation, so this is the only figure it can honestly produce.
    // It says where the checks are concentrated and where they are thin,
    // which is what the count is always being asked to answer.
    std::map<std::string, size_t> checkArea;
};

// Runs the internal checks: filter parser/matcher, snapshot diff + change
// events, ghost rows, sort determinism, UDP column text, shared column
// titles, UTF-8/CSV helpers, traffic counters. Never throws, never touches
// the registry or the network.
TestResult RunSelfTest();

// Benchmark clamp ranges (A4). Owned here so the doc comment above, the
// clamping code in RunBench, and the CLI that passes raw positionals all read
// the same numbers.
constexpr unsigned kBenchMinRows = 100;
constexpr unsigned kBenchMaxRows = 1000000;
constexpr unsigned kBenchMinIters = 1;
constexpr unsigned kBenchMaxIters = 1000;
// Defaults when neither switch nor positional is given (B6).
constexpr unsigned kBenchDefaultRows = 50000;
constexpr unsigned kBenchDefaultIters = 20;

// Benchmarks the model pipeline over synthetic rows. Returns a report as
// text (ms/op and Mrows/s per stage). Parameters are clamped to
// [kBenchMinRows .. kBenchMaxRows] x [kBenchMinIters .. kBenchMaxIters].
std::string RunBench(unsigned rows, unsigned iters);

}  // namespace wintcp
