// Cli.cpp
// SPDX-License-Identifier: Apache-2.0
// Unified command-line entry: wintcp.exe <command> [switches].
//
// There is exactly ONE CLI mode. An earlier revision had a second,
// flag-style mode (-c, --csv, --json, ...); it was removed because two
// grammars meant two parsers, two help texts and twice the confusion, for
// zero extra capability - every legacy switch has a verb spelling:
//
//   -c / --csv / --json      ->  list --format csv|json | export --format ...
//   --format <set>           ->  --columns <set>  (applies to json too)
//   --watch [sec]            ->  --watch [sec] on list/ps/top/stat
//   -q / --quiet             ->  list|ps --quiet (rc answers, no output)
//   --version                ->  version  (the FLAG stays rejected, exit 2:
//                                the `version` verb is the supported form.
//                                Do not re-add the flag.)
//   -h / --help              ->  help     (this one IS still accepted)
//   --selftest / --bench     ->  none: removed together with the harness,
//                                which now lives in the test binary. Both
//                                spellings exit 2 ("unknown command"), so do
//                                not re-add a verb spelling here.
//   -a / -n / --once         ->  dropped (accepted-and-ignored parity flags;
//                                the verbs always list all numeric endpoints
//                                in one pass)
//
// The GUI has its own Windows-subsystem entry point. This executable is always
// the CLI, including when invoked without arguments.

#include "Cli.h"

#include <string>
#include <vector>

#include "CliCommands.h"
#include "EngineRuntime.h"
#include "CollectorRuntime.h"
#include "Utils.h"

namespace wintcp {
namespace {

// The elevation marker Reelevate() appends. A process-level flag, never a
// command or a switch: it is stripped before parsing, and IsElevatedInstance
// keeps reading it from the raw command line, so nothing else changes.
bool IsMarker(const wchar_t* a) {
    return a != nullptr &&
           ::wcscmp(a, L"--__wintcp-elevated") == 0;
}

bool IsGlobalHelp(const std::wstring& a) {
    return a == L"--help" || a == L"-h" || a == L"-?" || a == L"/?" ||
           a == L"/help";
}

}  // namespace

int RunCli(int argc, wchar_t** argv) {
    // Strip the elevation marker: it must be invisible to the parser
    // wherever it appears (front, back, or beside a real command, as the
    // elevated relaunch preserves the original arguments).
    std::vector<wchar_t*> args;
    args.reserve(static_cast<size_t>(argc));
    args.push_back(argv[0]);
    for (int i = 1; i < argc; ++i) {
        if (!IsMarker(argv[i])) args.push_back(argv[i]);
    }
    const int n = static_cast<int>(args.size());
    if (n < 2) {
        static wchar_t kHelp[] = L"help";
        wchar_t* helpArgs[] = {args[0], kHelp};
        return RunCliCommand(2, helpArgs);
    }

    // Global help outranks everything, wherever it appears first.
    const std::wstring first = args[1] != nullptr ? args[1] : L"";
    if (first == L"engine")
        return RunEngineCommand(n, args.data());
    if (first == L"collector")
        return RunCollectorCommand(n, args.data());
    if (first == L"restrict")
        return RunRestrictCommand(n, args.data());
    if (first == L"recipe")
        return RunRecipeCommand(n, args.data());
    if (IsGlobalHelp(first)) {
        // `wintcp --help [cmd]` behaves like `wintcp help [cmd]`.
        std::vector<wchar_t*> helpArgs;
        helpArgs.reserve(static_cast<size_t>(n + 1));
        helpArgs.push_back(args[0]);
        static wchar_t kHelp[] = L"help";
        helpArgs.push_back(kHelp);
        for (int i = 2; i < n; ++i) helpArgs.push_back(args[i]);
        return RunCliCommand(static_cast<int>(helpArgs.size()),
                             helpArgs.data());
    }
    return RunCliCommand(n, args.data());
}

}  // namespace wintcp
