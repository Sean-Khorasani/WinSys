// CliCommands.h
// SPDX-License-Identifier: Apache-2.0
// Unified command line: wintcp.exe <command> [switches]. Script-friendly,
// Linux-tool-like (ps/top/lsof/ip). This is the ONLY CLI mode: every verb
// prints and exits like `dir` - nothing waits for a keypress, and only an
// explicit --watch polls (bounded by --count for scripts).

#pragma once

namespace wintcp {

// Dispatch a subcommand line. Returns the process exit code:
//   0 ok, 1 failure/empty, 2 bad args, 3 refused (--yes missing).
int RunCliCommand(int argc, wchar_t** argv);

}  // namespace wintcp
