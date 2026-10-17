# AGENTS.md

WinTCP is a dependency-free native Win32 C++17 application that lists live TCP/UDP
endpoints with their owning processes. It ships as `wintcp.exe` (console CLI),
`wintcp-gui.exe` (native GUI), plus an optional loopback Web UI (static assets
in `wintcp/webui`). Three build paths must stay in step: `build.bat`,
`fast-build.bat`/`fast-build.ps1`, and `CMakeLists.txt` (the .vcxproj files
mirror them).

## Dev environment

- Windows 10/11 + Visual Studio 2022 (or later) with the "Desktop development with
  C++" workload (MSVC + Windows SDK). No third-party dependencies, no package
  manager, no admin rights needed.
- The shell here is MSYS/bash, not PowerShell or cmd.exe; `cl.exe` is not on PATH.
  `build.bat` and `fast-build.ps1` self-locate vcvars64.bat, so they run from any
  shell. For direct `cl`/`link` calls from bash, discover the toolset with
  vswhere and prepend `.../VC/Tools/MSVC/<ver>/bin/Hostx64/x64` to PATH.
- When a .bat wrapper exists, drive it via `cmd.exe /c "<wrapper>.bat"` — never
  invoke `cl.exe`/`link.exe` straight from bash. Quote the whole path: unquoted
  backslashes are stripped by bash and mangle the filename.

## Build & test

Exact commands, from the repo root:

- `build.bat` — the shipped-binary gate. Full rebuild, /W4 /WX, /GL /LTCG,
  re-embeds web assets. Outputs: `build/wintcp.exe`, `build/wintcp-gui.exe`,
  `build/dev/wintcp-dev.exe`. `build.bat clean` wipes `build/`.
- `cmd.exe /c fast-build.bat -Test` — the dev loop: incremental parallel compile,
  CLI smoke gate, harness self-check, unit driver. Exit codes: 0 ok,
  1 build failed, 2 tests failed, 3 setup. Other flags: `-TestOnly`, `-Force`,
 `-Clean`.
- CMake: `cmake -S . -B build-cmake -G "Visual Studio 17 2022" -A x64 &&
  cmake --build build-cmake --config Release` (single-config Ninja also works).
- Unit tests: `build\dev\wintcp-dev.exe unit` (exit 0 = all checks pass). Also
  `bench [rows] [iters]` and `ui` (needs an interactive desktop). Not shipped;
  running it bare prints usage.
- Web UI assets have no compiled gate: run `node --check wintcp/webui/app.js`.
- Background dashboard: `webui-service.bat start|status|stop` (logs to
  `%LOCALAPPDATA%\WinTCP\WebUi\webui.log`); foreground: `wintcp.exe webui serve`.

## Conventions

- Every build path compiles with `/W4 /WX` (warnings are errors), `/permissive-`,
  `/Zc:__cplusplus`, `/utf-8`, static CRT (`/MT`), `/guard:cf`, `/MANIFEST:NO`
  (`wintcp.rc` already embeds the manifest). Keep all paths in step.
- Adding a source file: `build.bat` and `wintcp.vcxproj` list it by hand;
  `CMakeLists.txt` and `fast-build.ps1` glob. Never edit anything under `build\`,
  `build-fast\`, or `build-cmake\`.
- The product carries no test code. Tests/benchmarks/UI harness live only in
  `wintcp-dev.exe` (entry `wintcp/tests/TestMain.cpp`); `wintcp.exe` rejects
  `selftest`/`bench`/`--uiharness` as unknown commands.
- The column set is frozen at 32 (UINT32 mask): a `static_assert` in
  `ColumnsWin.h` fails the build at 33. Reuse an existing column instead.
- Naming: PascalCase types and methods, `kCamelCase` constants, `UPPER_CASE` macros,
  `#pragma once`, UTF-8 without BOM.
- CLI contract: exit 0 ok, 1 failure/empty, 2 bad arguments, 3 refused. A switch a
  command does not honour exits 2 naming the switch — never silently ignored.
- Docs are the contract: user-facing command changes must update `docs/` and the
  CLI example corpus `wintcp/tests/examples.txt` (it carries `;expect=` exit-code
  annotations).
- Commits follow `Add <path>: <description>` (see git log). Commit only files you
  authored — this checkout routinely contains other uncommitted work.

## Pitfalls

- After any source edit, `fast-build.bat -Test` first reports "gated binary is
  STALE" (exit 2) until `build.bat` rebuilds `build/wintcp.exe`. Expected, not a
  regression. Do not "fix" it with `-TestOnly`; rebuild first.
- Only `build.bat` embeds web assets into the shipped binary. Editing
  `wintcp/webui/*` and fast-building leaves `build/wintcp.exe` carrying the old
  dashboard.
- `build.bat` takes minutes (full /GL /LTCG). Run it in the background and do not
  edit sources while it compiles — a header change mid-pass fails the run.
- `fast-build.ps1`'s header still references `docs/development.md` and
  `wintcp/dev/cli.bat`; neither exists. The real gates are `fast-build.bat -Test`
  and `wintcp-dev.exe unit`.
- A bash/MSYS `link` on PATH can shadow MSVC's linker; check `link /?` prints the
  Microsoft banner before diagnosing link errors.
- The Web UI binds an ephemeral port on 127.0.0.1 only; 6 of the 40 monitor
  templates have evaluators (unsupported templates stay disabled).
- `wintcp.exe webui serve` OPENS THE USER'S DEFAULT BROWSER (ShellExecuteW) unless
  `WINTCP_WEBUI_OPEN_BROWSER` is `0`/`false`/`no`/`off`. Never launch it bare
  while testing - it hijacks the user's desktop. Use
  `cmd.exe /c webui-service.bat start`, which sets the flag for the child and
  prints the URL. Drive the UI with curl or headless Playwright instead.
- Playwright/Chromium is dev-only (`tools/webui-e2e`); always run it headless.
