// Cli.h
// SPDX-License-Identifier: Apache-2.0
// Unified command line for the standalone console application.

#pragma once

namespace wintcp {

// Dispatch the unified grammar. Returns the process exit code:
//   0 = success (with --quiet: at least one row matched)
//   1 = failure, or an empty result (with --quiet: nothing matched)
//   2 = bad arguments / unknown command
//   3 = refused: a mutating command without --yes
int RunCli(int argc, wchar_t** argv);

}  // namespace wintcp
