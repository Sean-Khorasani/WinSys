# fast-build.ps1 - incremental MSVC build + smoke gate for WinTCP (the dev loop).
#
# WHY THIS EXISTS
#   build.bat compiles every source file in a single cl invocation and pays for
#   the full /GL + /LTCG link on every change. That is the correct gate for
#   shipping - and the wrong cost for a development loop. This script runs cl
#   once per stale .cpp (in parallel, with real header dependencies traced
#   from #include lines), relinks, and with -Test runs a small headless CLI
#   smoke gate plus the internal unit driver.
#
#   It does NOT replace the existing gates. Before shipping, build and test
#   with the real system: build.bat, then wintcp\\dev\\cli.bat, examples.bat,
#   gui.bat and wintcp-dev.exe unit, as documented in docs\development.md.
#   Every assertion below (exit codes, markers) is drawn from cli.bat; if the
#   two ever disagree, cli.bat and the product win.
#
# WHAT IS DELIBERATELY DIFFERENT FROM build.bat
#   * /Gy /GL /LTCG are OFF. The link returns in seconds instead of minutes
#     and no whole-program optimisation runs. The result is a DEV artifact:
#     use it for compile feedback, smoke tests and pdb debugging. The
#     shipping binary is build.bat's, with LTCG and its measured size
#     benefit, exactly as it has always been.
#   * /Zi + /DEBUG produce build-fast\wintcp.pdb so a crash in a dev build
#     has symbols. build.bat links /DEBUG:NONE on purpose; do not read this
#     difference as an improvement.
#   * /FS is on because cl runs per file, several at once: parallel cl.exe
#     share the vc140.pdb program database and must serialize writes, or they
#     die with C1041. A single cl (build.bat) never needed it.
#   * Everything else is identical to build.bat's product line: /std:c++17
#     /EHsc /W4 /WX /permissive- /Zc:__cplusplus /utf-8, the five /D defines,
#     /O2 /Os /MT, /guard:cf, /SUBSYSTEM:CONSOLE, /MANIFEST:NO, the library
#     list and the six /DELAYLOADs. /WX stays ON: a warning must still fail
#     the build here, or this loop stops being a pre-gate.
#   * The test driver (wintcp-dev.exe, built only with -Test) links the SAME
#     shared .obj files as the product - same sources, same flags, one object
#     set, so a unit run exercises exactly the code the fast build compiled.
#
# USAGE (Developer Command Prompt for VS 2022, or any prompt: it locates
# vcvars64.bat itself. Use fast-build.bat to dodge execution policy.)
#   fast-build.bat -Test      build what changed + CLI smoke + unit  <- the loop
#   fast-build.bat            build what changed (product exe only)
#   fast-build.bat -TestOnly  skip the build, just run the tests
#   fast-build.bat -Force     recompile everything, same fast flags
#   fast-build.bat -Clean     delete build-fast\
#
# Exit codes: 0 ok, 1 build failed, 2 tests failed, 3 environment/setup.
#
# State lives in build-fast\ (objs, pdb, res, logs, a flag-state file, a lock).
# The tree is separate from build\ (build.bat) and build-cmake\ - this tool
# never writes to either, and deleting build-fast\ is always safe.

[CmdletBinding()]
param(
    [switch]$Test,        # after building, run the CLI smoke gate + unit driver
    [switch]$TestOnly,    # skip the build, run the tests (needs a prior -Test run)
    [switch]$Force,       # recompile everything (still the fast flags)
    [switch]$Clean        # remove build-fast\ and exit
)

$ErrorActionPreference = 'Stop'
$StartTime = Get-Date

$Root      = $PSScriptRoot
$Build     = Join-Path $Root 'build-fast'
$GatedExe  = Join-Path $Root 'build\wintcp.exe'   # build.bat's output: the shipped one
$ObjDir    = Join-Path $Build 'obj'
$LogDir    = Join-Path $Build 'log'
$TstDir    = Join-Path $Build 'dev'
$SrcDir    = Join-Path $Root 'wintcp\src'
$TstSrc    = Join-Path $Root 'wintcp\tests'
$ResDir    = Join-Path $Root 'wintcp\res'
$ResFile   = Join-Path $Build 'wintcp.res'
$ProdExe   = Join-Path $Build 'wintcp.exe'
$GuiExe    = Join-Path $Build 'wintcp-gui.exe'
$TstExe    = Join-Path $TstDir 'wintcp-dev.exe'
$StateFile = Join-Path $Build 'state.txt'
$LockDir   = Join-Path $Build '.lock'

function Say([string]$m) { [Console]::WriteLine("[fast-build] $m") }
function Die([int]$code, [string]$m) { [Console]::WriteLine("[fast-build] ERROR: $m"); exit $code }
function Rel([string]$p) {
    if ([System.IO.Path]::IsPathRooted($p)) {
        try { return [System.IO.Path]::GetRelativePath($Root, $p) } catch { return $p }
    }
    return $p
}
function Read-Text([string]$p) {
    # Get-Content -Raw on an empty file returns $null, and a [string] cast of
    # $null is still $null in PowerShell - so guard explicitly.
    if (-not (Test-Path -LiteralPath $p)) { return '' }
    $t = Get-Content -LiteralPath $p -Raw
    if ($null -eq $t) { return '' }
    return [string]$t
}

# ---- clean --------------------------------------------------------------------
if ($Clean) {
    if (Test-Path -LiteralPath $Build) { Remove-Item -LiteralPath $Build -Recurse -Force }
    Say "cleaned $Build"
    exit 0
}

# ---- single-instance lock (mkdir is atomic on Windows) --------------------------
if (Test-Path -LiteralPath $LockDir) {
    $lockStamp = Join-Path $LockDir 'stamp.txt'
    $holder    = ''
    $stale     = $true
    if (Test-Path -LiteralPath $lockStamp) {
        $holder = (Get-Content -LiteralPath $lockStamp -ErrorAction SilentlyContinue)
        $age    = (Get-Date) - (Get-Item -LiteralPath $lockStamp).LastWriteTime
        $stale  = $age.TotalMinutes -gt 15
    }
    if ($stale) {
        Remove-Item -LiteralPath $LockDir -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        Die 3 "another fast-build is running (pid $holder). Wait for it, or remove $LockDir if it is dead."
    }
}
New-Item -ItemType Directory -Path $LockDir | Out-Null
"$PID" | Set-Content -LiteralPath (Join-Path $LockDir 'stamp.txt')
$Locked = $true

try {
    # ---- toolchain ----------------------------------------------------------------
    function Have-Tool([string]$n) { [bool](Get-Command $n -ErrorAction SilentlyContinue) }

    function Find-Vcvars {
        $bases    = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ }
        $versions = @('2022', '18')
        $editions = @('Community', 'Professional', 'Enterprise', 'BuildTools')
        foreach ($base in $bases) {
            foreach ($v in $versions) {
                foreach ($e in $editions) {
                    $p = Join-Path $base "Microsoft Visual Studio\$v\$e\VC\Auxiliary\Build\vcvars64.bat"
                    if (Test-Path -LiteralPath $p) { return $p }
                }
            }
        }
        return $null
    }

    if (-not (Have-Tool 'cl.exe')) {
        $vc = Find-Vcvars
        if ($vc) {
            Say "cl.exe not on PATH; importing toolchain environment from:"
            Say "  $vc"
            $envLines = & cmd.exe /c "call `"$vc`" >nul 2>&1 && set"
            foreach ($line in $envLines) {
                if ($line -match '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
                    Set-Item -Path "Env:$($matches[1])" -Value $matches[2]
                }
            }
        }
    }
    if (-not (Have-Tool 'cl.exe')) {
        Die 3 "cl.exe not found. Open the Developer Command Prompt for VS 2022, or install the C++ workload."
    }
    if (-not (Have-Tool 'rc.exe')) {
        Die 3 "rc.exe not found. Install the Windows SDK with the C++ workload."
    }
    $clPath = (Get-Command cl.exe).Source
    $rcPath = (Get-Command rc.exe).Source

    # ---- sources --------------------------------------------------------------------
    # The CLI product is main.cpp + shared sources, with no GUI entry point.
    # The standalone GUI is GuiMain.cpp + the same shared sources and resources.
    # The dev binary is shared sources minus both product entry points, PLUS
    # UiProbe.cpp and tests. d2probe.cpp is deliberately NOT part of either
    # (docs/development.md).
    #
    # GLOB, never a hand list. This line used to name 'TestMain.cpp',
    # 'Bench.cpp' and 'UiHarness.cpp' explicitly while claiming to be a glob
    # just above it, and adding wintcp\\dev\\BenchSync.cpp (9.6.2/C12) broke
    # the link with eight LNK2019s - build.bat, CMakeLists.txt and the vcxproj
    # were all updated and this one was not. That is the same "four build
    # paths must stay in step" trap reached
    # through the one path that spelled itself out. So it globs now.
    #
    # The UiProbe exclusion is the ONE exception to the glob rule, and it is
    # an exclusion rather than an opt-in for a reason: a new test-support file
    # dropped in wintcp\src must NOT silently enter the shipped binary, so the
    # default is "harness, and therefore dev-only" until it is named below.
    $srcCpp  = @(Get-ChildItem -LiteralPath $SrcDir -Filter '*.cpp' | ForEach-Object { $_.FullName })
    $mainCpp = Join-Path $SrcDir 'main.cpp'
    if (-not (Test-Path -LiteralPath $mainCpp)) { Die 3 "wintcp\src\main.cpp not found; is the tree complete?" }
    $guiCpp = Join-Path $SrcDir 'GuiMain.cpp'
    if (-not (Test-Path -LiteralPath $guiCpp)) { Die 3 "wintcp\src\GuiMain.cpp not found; is the tree complete?" }
    $launcherCpp = Join-Path $SrcDir 'GuiLauncher.cpp'
    $probeCpp = Join-Path $SrcDir 'UiProbe.cpp'
    if (-not (Test-Path -LiteralPath $probeCpp)) { Die 3 "wintcp\src\UiProbe.cpp not found; is the tree complete?" }
    $coreCpp = @($srcCpp | Where-Object { $_.ToLower() -ne $mainCpp.ToLower() -and $_.ToLower() -ne $probeCpp.ToLower() -and $_.ToLower() -ne $guiCpp.ToLower() -and $_.ToLower() -ne $launcherCpp.ToLower() })
    $tstCpp  = @(Get-ChildItem -LiteralPath $TstSrc -Filter '*.cpp' | Where-Object { $_.Name -ne 'd2probe.cpp' } | ForEach-Object { $_.FullName })
    foreach ($f in $tstCpp) { if (-not (Test-Path -LiteralPath $f)) { Die 3 "missing $f" } }

    $prodCpp = @($mainCpp) + $coreCpp                       # the product: no harness
    $devCpp  = @($probeCpp) + $coreCpp + $tstCpp            # the harness binary
    $allCpp  = $prodCpp + $tstCpp + @($probeCpp, $guiCpp)    # everything compiled

    # One obj per file, flat. If two files ever share a base name this breaks
    # silently - refuse now instead.
    $names = $allCpp | ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_).ToLower() }
    if ($names.Count -ne (@($names | Select-Object -Unique)).Count) {
        Die 3 "source files share a base name; object names would collide."
    }

    # ---- flags (identical to build.bat except the differences documented above)
    # /FS: with /Zi, parallel cl.exe processes share the C140 program database
    # (vc140.pdb) and must serialize writes or die with C1041. build.bat runs a
    # single cl and does not need it.
    $clBase     = @('/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/permissive-', '/Zc:__cplusplus',
                    '/utf-8', '/DUNICODE', '/D_UNICODE', '/D_WIN32_WINNT=0x0601', '/DWIN32_LEAN_AND_MEAN',
                    '/O2', '/Os', '/MT', '/Zi', '/FS', '/guard:cf')
    $libs       = @('iphlpapi.lib', 'ws2_32.lib', 'comctl32.lib', 'psapi.lib', 'user32.lib', 'gdi32.lib',
                    'comdlg32.lib', 'shell32.lib', 'advapi32.lib', 'crypt32.lib', 'wintrust.lib',
                    'pdh.lib', 'ole32.lib', 'oleaut32.lib', 'bcrypt.lib', 'delayimp.lib')
    $linkOpts   = @('/SUBSYSTEM:CONSOLE', '/guard:cf', '/MANIFEST:NO', '/DEBUG', '/OPT:REF', '/OPT:ICF')
    $delayLoads = @('/DELAYLOAD:comdlg32.dll', '/DELAYLOAD:crypt32.dll', '/DELAYLOAD:ole32.dll',
                    '/DELAYLOAD:oleaut32.dll', '/DELAYLOAD:pdh.dll', '/DELAYLOAD:shell32.dll')

    # State: if the flags or the source list change since the last build, every
    # obj is suspect. mtime logic cannot see a flag change, so record the input
    # the objs were produced from.
    $stateInput = [string]::Join('|', (($clBase + $libs + $linkOpts + $delayLoads + @('GUI:/SUBSYSTEM:WINDOWS')) + $allCpp))
    $sha        = [System.Security.Cryptography.SHA256]::Create()
    $stateHash  = [BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($stateInput))).Replace('-', '')
    $stateMatches = $false
    if (Test-Path -LiteralPath $StateFile) {
        $stateMatches = (Read-Text $StateFile).Trim() -eq $stateHash
    }
    $forceAll = $Force -or (-not $stateMatches)
    if ($forceAll -and -not $Force) {
        Say "build inputs changed since the last fast build; recompiling everything"
    }

    # ---- header dependencies ------------------------------------------------------------
    # A .cpp is stale when it is newer than its .obj, or any header in its
    # #include "..." closure is newer. Quoted includes are resolved relative to
    # the including file, then (for the tests files) via wintcp\src - exactly
    # the /I wintcp\src the old test build line used. Angle-bracket includes
    # are SDK/STL by construction; if the SDK changes, run -Force (or
    # build.bat, which is the real gate).
    $mtimes = @{}
    function Get-Mtime([string]$p) {
        $k = $p.ToLower()
        if ($mtimes.ContainsKey($k)) { return $mtimes[$k] }
        $t = [System.IO.File]::GetLastWriteTimeUtc($p)
        $mtimes[$k] = $t
        return $t
    }

    # The cache above exists so the ~200 header comparisons in Test-ObjStale do
    # not each re-stat the disk. It is only valid for READS. The compile step
    # WRITES every .obj it plans, and Test-ObjStale has already read (and
    # cached) each of those .obj's pre-compile timestamp - so the link step,
    # which runs afterwards and asks "is any input newer than the exe?", got
    # the stale cached answer and concluded the exe was current. Effect: any run
    # that compiled anything left the exes UNRELINKED, and `-Test` then silently
    # exercised the previous binary. Deterministic repro: touch one .cpp, run,
    # the .obj advances and the .exe does not. Drop the cache once the writers
    # are done.
    function Clear-MtimeCache { $mtimes.Clear() }

    $projectSet = @{}
    foreach ($d in @($SrcDir, $TstSrc, $ResDir)) {
        if (Test-Path -LiteralPath $d) {
            Get-ChildItem -LiteralPath $d -Recurse -File | ForEach-Object { $projectSet[$_.FullName.ToLower()] = $true }
        }
    }

    $incRe = [regex]'^\s*#\s*include\s*"([^"]+)"'
    $deps  = @{}
    foreach ($cpp in $allCpp) {
        $k     = $cpp.ToLower()
        $queue = New-Object System.Collections.Generic.Queue[string]
        $queue.Enqueue($k)
        $seen  = @{}
        $seen[$k] = $true
        $list  = New-Object System.Collections.Generic.List[string]
        while ($queue.Count -gt 0) {
            $cur     = $queue.Dequeue()
            $curFull = [System.IO.Path]::GetFullPath($cur)
            foreach ($line in [System.IO.File]::ReadLines($curFull)) {
                $m = $incRe.Match($line)
                if (-not $m.Success) { continue }
                $inc  = $m.Groups[1].Value
                $dir  = [System.IO.Path]::GetDirectoryName($curFull)
                $cand = [System.IO.Path]::GetFullPath((Join-Path $dir $inc)).ToLower()
                if ($seen.ContainsKey($cand)) { continue }
                if (-not $projectSet.ContainsKey($cand)) {
                    # the tests files resolve "Connection.h" via wintcp\src
                    $alt = [System.IO.Path]::GetFullPath((Join-Path $SrcDir $inc)).ToLower()
                    if ($projectSet.ContainsKey($alt)) { $cand = $alt }
                    else { continue }   # outside the project tree; not fast-trackable
                }
                $seen[$cand] = $true
                $list.Add($cand)
                $queue.Enqueue($cand)
            }
        }
        $deps[$k] = $list.ToArray()
    }

    # Resource script: depends on itself, its quoted includes and everything in
    # wintcp\res (icon, manifest). rc is fast; over-depending here is harmless.
    $rcFile  = Join-Path $SrcDir 'wintcp.rc'
    $resDeps = New-Object System.Collections.Generic.List[string]
    $resDeps.Add($rcFile.ToLower())
    foreach ($line in [System.IO.File]::ReadLines($rcFile)) {
        $m = $incRe.Match($line)
        if (-not $m.Success) { continue }
        $c = [System.IO.Path]::GetFullPath((Join-Path $SrcDir $m.Groups[1].Value)).ToLower()
        if (Test-Path -LiteralPath $c) { $resDeps.Add($c) }
    }
    Get-ChildItem -LiteralPath $ResDir -File | ForEach-Object { $resDeps.Add($_.FullName.ToLower()) }
    $resDeps = @($resDeps | Select-Object -Unique)

    function Test-ObjStale([string]$obj, [string]$src, [string[]]$headerDeps, [bool]$force) {
        if ($force) { return $true }
        if (-not (Test-Path -LiteralPath $obj)) { return $true }
        $o = Get-Mtime $obj
        if ((Get-Mtime $src) -gt $o) { return $true }
        foreach ($h in $headerDeps) { if ((Get-Mtime $h) -gt $o) { return $true } }
        return $false
    }

    # ---- plan ---------------------------------------------------------------------------
    $needTests = $Test -or $TestOnly
    $doBuild   = -not $TestOnly
    if ($TestOnly) {
        if (-not (Test-Path -LiteralPath $ProdExe)) {
            Die 3 "no fast build to test yet; run 'fast-build.bat -Test' once first."
        }
        if (-not (Test-Path -LiteralPath $GuiExe)) {
            Die 3 "no standalone fast GUI yet; run 'fast-build.bat -Test' once first."
        }
        if ($needTests -and -not (Test-Path -LiteralPath $TstExe)) {
            Die 3 "no test driver in the fast build yet; run 'fast-build.bat -Test' once first."
        }
        Say "test-only: running the checks against the existing fast build"
    }

    if (Test-Path -LiteralPath $LogDir) { Remove-Item -LiteralPath $LogDir -Recurse -Force }
    New-Item -ItemType Directory -Path $LogDir | Out-Null
    if ($doBuild) {
        New-Item -ItemType Directory -Path $ObjDir, $TstDir -Force | Out-Null
    }

    $compilePlan = New-Object System.Collections.Generic.List[object]
    foreach ($cpp in $allCpp) {
        $isTest = $cpp.ToLower().StartsWith($TstSrc.ToLower() + '\')
        if ($isTest -and -not $needTests) { continue }    # tests driver not requested
        $name  = [System.IO.Path]::GetFileNameWithoutExtension($cpp)
        $obj   = Join-Path $ObjDir ($name + '.obj')
        if (Test-ObjStale $obj $cpp $deps[$cpp.ToLower()] $forceAll) {
            $compilePlan.Add([pscustomobject]@{
                Cpp  = $cpp; Obj = $obj; Name = $name
                Log  = Join-Path $LogDir ($name + '.out')
                Test = $isTest
            })
        }
    }

    # ---- compile (skipped by -TestOnly) ---------------------------------------------------
    $compiled = 0
    if ($doBuild) {
    if ($compilePlan.Count -gt 0) {
        $jobs = 8
        if ($env:FASTBUILD_JOBS) { $jobs = [int]$env:FASTBUILD_JOBS }
        $jobs = [Math]::Max(1, [Math]::Min($jobs, [Environment]::ProcessorCount))

        Say ("compiling {0} of {1} files, {2} in parallel:" -f $compilePlan.Count, $allCpp.Count, $jobs)
        foreach ($w in $compilePlan) { Say ("  - " + (Rel $w.Cpp)) }

        for ($i = 0; $i -lt $compilePlan.Count; $i += $jobs) {
            $end   = [Math]::Min($i + $jobs, $compilePlan.Count)
            $procs = New-Object System.Collections.Generic.List[object]
            $batchW = New-Object System.Collections.Generic.List[object]
            for ($j = $i; $j -lt $end; $j++) {
                $w   = $compilePlan[$j]
                $arg = [string]::Join(' ', $clBase) + ' /Fo"build-fast/obj/" /c "' + $w.Cpp + '"'
                if ($w.Test) { $arg += ' /I "' + $SrcDir + '"' }
                $p = Start-Process -FilePath $clPath -ArgumentList $arg -WorkingDirectory $Root `
                    -WindowStyle Hidden -PassThru `
                    -RedirectStandardOutput $w.Log `
                    -RedirectStandardError ($w.Log + '.err')
                # Cache the native handle NOW. Without this, .NET is free to let
                # go of it, and ExitCode then reads $null once the process has
                # exited - at which point `$null -ne 0` is TRUE and a file that
                # compiled perfectly is reported as a failure. Observed: 8 of 43
                # files "failed" with empty cl rc while all 43 .obj existed.
                $null = $p.Handle
                $procs.Add($p)
                $batchW.Add($w)
            }
            foreach ($p in $procs) { $p.WaitForExit() }

            $failures = @()
            for ($b = 0; $b -lt $procs.Count; $b++) {
                # A $null ExitCode is never proof of success - decide from the log.
                $rc = $procs[$b].ExitCode
                if ($null -eq $rc) {
                    # We lost the process handle, so the exit code is
                    # unknowable. Fall back to the compiler log: cl writes every
                    # diagnostic there, so a non-empty log IS a failure. The old
                    # `-ne 0` test reported a failure here *by accident* - with
                    # $null it reported one even when the compile had succeeded.
                    # Read-Text returns '' for a missing or empty log.
                    if ((Read-Text $batchW[$b].Log).Trim().Length -gt 0) {
                        $failures += ,@($batchW[$b], 'unreadable rc, compiler log NOT empty')
                    } else {
                        Say ('WARN  could not read the exit code for {0}; the compiler log is empty, so treating it as success' -f (Rel $batchW[$b].Cpp))
                    }
                    continue
                }
                if ($rc -ne 0) { $failures += ,@($batchW[$b], $rc) }
            }
            if ($failures.Count -gt 0) {
                foreach ($f in $failures) {
                    $w  = $f[0]
                    Say ("COMPILE FAILED: " + (Rel $w.Cpp) + " (cl rc " + $f[1] + ")")
                    $t = (Read-Text $w.Log).TrimEnd("`r")
                    $e = (Read-Text ($w.Log + '.err')).TrimEnd("`r")
                    if ($t.Length -gt 0) { [Console]::WriteLine($t) }
                    if ($e.Length -gt 0) { [Console]::WriteLine($e) }
                }
                Die 1 ("{0} of {1} files failed to compile; logs kept in build-fast\log" -f $failures.Count, $compilePlan.Count)
            }
            for ($j = $i; $j -lt $end; $j++) { $compiled++ }
        }
        Say ("compiled {0} file(s) in {1:N1}s" -f $compiled, ((Get-Date) - $StartTime).TotalSeconds)
    } else {
        Say "nothing to recompile (all objects current)"
    }
    }

    # ---- resource (skipped by -TestOnly) ------------------------------------------------------
    if ($doBuild) {
    $resStale = $forceAll -or (-not (Test-Path -LiteralPath $ResFile))
    if (-not $resStale) {
        $r = Get-Mtime $ResFile
        foreach ($h in $resDeps) {
            if ((Get-Mtime $h) -gt $r) { $resStale = $true; break }
        }
    }
    if ($resStale) {
        $rout = & $rcPath /nologo /fo "$ResFile" "$rcFile" 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { [Console]::WriteLine($rout); Die 1 "resource compile failed (wintcp.rc)" }
        Say "compiled resource (wintcp.res)"
    } else {
        Say "resource current (wintcp.res)"
    }
    }

    # ---- link (skipped by -TestOnly) -----------------------------------------------------------
    # Every .obj the compile step rewrote is still cached at its OLD timestamp
    # (see Clear-MtimeCache). Re-read from disk or the exe looks up to date.
    Clear-MtimeCache
    if ($doBuild) {
    # Same library list and delay-load set as build.bat. /SUBSYSTEM:CONSOLE is
    # load-bearing (main.cpp's wmain + the batch gates); /MANIFEST:NO because
    # the RC already embeds RT_MANIFEST id 1 (a second one is CVT1100/LNK1123);
    # /guard:cf matches the product. No /LTCG here - see the header.
    $prodObjs = @($prodCpp | ForEach-Object { Join-Path $ObjDir ([System.IO.Path]::GetFileNameWithoutExtension($_) + '.obj') })
    $tstObjs  = @($coreCpp | ForEach-Object { Join-Path $ObjDir ([System.IO.Path]::GetFileNameWithoutExtension($_) + '.obj') }) +
                @($probeCpp | ForEach-Object { Join-Path $ObjDir ([System.IO.Path]::GetFileNameWithoutExtension($_) + '.obj') }) +
                @($tstCpp  | ForEach-Object { Join-Path $ObjDir ([System.IO.Path]::GetFileNameWithoutExtension($_) + '.obj') })

    function Link-Exe([string]$name, [string[]]$inputs, [string]$out, [string]$pdb, [switch]$WindowsSubsystem) {
        # Build ONE command line and hand it to Start-Process. Passing an args
        # array to cl via `& cl @largs` relied on PowerShell native-splatting quote
        # handling, which dropped the `:` out of /PDB ("/PDB"$pdb"" -> /PBBD:...)
        # and mangled /Fe, yielding /PBBD and a stray "wintcp.exe\". A single
        # delimited string through Start-Process is exact - same pattern as the
        # compile step. /Fe names the exe; cl forwards /PDB to the linker.
        $arg = '/nologo /guard:cf /Zi /Fe"' + $out + '"'
        foreach ($i in $inputs) { $arg += ' "' + $i + '"' }
        $arg += ' /link'
        foreach ($lib in $libs) { $arg += ' ' + $lib }
        foreach ($o in $linkOpts) {
            if ($WindowsSubsystem -and $o -eq '/SUBSYSTEM:CONSOLE') {
                $arg += ' /SUBSYSTEM:WINDOWS'
            } else { $arg += ' ' + $o }
        }
        foreach ($dl in $delayLoads) { $arg += ' ' + $dl }
        $arg += ' /PDB:"' + $pdb + '"'

        $t0 = Get-Date
        $lp = Join-Path $LogDir ('link-' + $name + '.out')
        # -Wait -PassThru returns a Process whose ExitCode is already populated
        # (the process has exited by the time Start-Process returns). The
        # handle-caching dance the compile loop needs is NOT wanted here:
        # touching .Handle on an exited process can throw.
        $p  = Start-Process -FilePath $clPath -ArgumentList $arg -WorkingDirectory $Root `
                -WindowStyle Hidden -Wait -PassThru `
                -RedirectStandardOutput $lp `
                -RedirectStandardError ($lp + '.err')
        $p.WaitForExit()
        if ($p.ExitCode -ne 0) {
            Say (Read-Text $lp)
            Say (Read-Text ($lp + '.err'))
            Die 1 ("link failed: " + $name)
        }
        Say ("linked {0} in {1:N1}s" -f (Rel $out), ((Get-Date) - $t0).TotalSeconds)
    }

    $linkProd = -not (Test-Path -LiteralPath $ProdExe)
    if (-not $linkProd) {
        $p = Get-Mtime $ProdExe
        foreach ($inp in ($prodObjs + $ResFile)) { if ((Get-Mtime $inp) -gt $p) { $linkProd = $true; break } }
    }
    if ($linkProd) { Link-Exe 'wintcp.exe' (@($prodObjs) + $ResFile) $ProdExe (Join-Path $Build 'wintcp.pdb') }
    else { Say "wintcp.exe current" }

    $guiObjs = @($coreCpp | ForEach-Object { Join-Path $ObjDir ([System.IO.Path]::GetFileNameWithoutExtension($_) + '.obj') }) +
               @($guiCpp | ForEach-Object { Join-Path $ObjDir ([System.IO.Path]::GetFileNameWithoutExtension($_) + '.obj') })
    $linkGui = -not (Test-Path -LiteralPath $GuiExe)
    if (-not $linkGui) {
        $p = Get-Mtime $GuiExe
        foreach ($inp in ($guiObjs + $ResFile)) { if ((Get-Mtime $inp) -gt $p) { $linkGui = $true; break } }
    }
    if ($linkGui) {
        Link-Exe 'wintcp-gui.exe' (@($guiObjs) + $ResFile) $GuiExe (Join-Path $Build 'wintcp-gui.pdb') -WindowsSubsystem
    } else { Say "wintcp-gui.exe current" }

    if ($needTests) {
        $linkTst = -not (Test-Path -LiteralPath $TstExe)
        if (-not $linkTst) {
            $t = Get-Mtime $TstExe
            foreach ($inp in ($tstObjs + $ResFile)) { if ((Get-Mtime $inp) -gt $t) { $linkTst = $true; break } }
        }
        if ($linkTst) {
            Link-Exe 'wintcp-dev.exe' (@($tstObjs) + $ResFile) $TstExe (Join-Path $TstDir 'wintcp-dev.pdb')
        } else { Say "wintcp-dev.exe current" }
    }
    }

    if ($doBuild) {
    $assetSource = Join-Path $Root 'wintcp\webui'
    $assetTarget = Join-Path $Build 'webui'
    if (-not (Test-Path -LiteralPath $assetSource)) { Die 3 "missing Web UI assets at wintcp\webui" }
    New-Item -ItemType Directory -Force -Path $assetTarget | Out-Null
    Get-ChildItem -LiteralPath $assetSource -File | Copy-Item -Destination $assetTarget -Force
    $stateHash | Set-Content -LiteralPath $StateFile -NoNewline
    $elapsed = ((Get-Date) - $StartTime).TotalSeconds
    $kb = [math]::Round((Get-Item -LiteralPath $ProdExe).Length / 1KB)
    Say ("build OK in {0:N1}s: {1} compiled, {2:N0} KB -> {3}" -f $elapsed, $compiled, $kb, (Rel $ProdExe))
    }

    # ---- tests ----------------------------------------------------------------------------------
    if ($Test -or $TestOnly) {
        if (-not (Test-Path -LiteralPath $ProdExe)) { Die 3 "wintcp.exe not built" }
        if ($needTests -and -not (Test-Path -LiteralPath $TstExe)) {
            Die 1 "wintcp-dev.exe missing after the build step - something went wrong"
        }
        if (-not $TestOnly) { Say "smoke gate: CLI checks + unit driver (headless, nothing mutating)" }

        # Run-Cli: run a binary with argument words, capture both streams.
        function Invoke-Proc([string]$exe, [string[]]$argv, [string]$out) {
            $err = $out + '.err'
            $start = @{
                FilePath               = $exe
                WorkingDirectory       = $Root
                WindowStyle            = 'Hidden'
                Wait                   = $true
                PassThru               = $true
                RedirectStandardOutput = $out
                RedirectStandardError  = $err
            }
            if ($argv.Count -gt 0) { $start.ArgumentList = [string]::Join(' ', $argv) }
            $p = Start-Process @start
            $p.WaitForExit()
            $text = (Read-Text $out) + "`n" + (Read-Text $err)
            return [pscustomobject]@{ Rc = $p.ExitCode; Text = $text }
        }

        # A check passes when the rc is in Want AND the marker (if any) occurs
        # in the combined output, case-insensitively. Markers and exit codes
        # are drawn from wintcp\\dev\\cli.bat; if they ever disagree, cli.bat
        # wins - this is a smoke gate, not the gate.
        function Test-Check([int]$rc, [string]$text, $want, [string]$marker) {
            $ok = $false
            foreach ($w in @($want)) { if ($rc -eq $w) { $ok = $true; break } }
            if (-not $ok) { return $false }
            if ($marker -and $marker.Length -gt 0) {
                return $text.IndexOf($marker, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
            }
            return $true
        }

        $t = Join-Path $LogDir 'smoke'
        if (-not (Test-Path -LiteralPath $t)) { New-Item -ItemType Directory -Path $t -Force | Out-Null }
        $tmpExport = Join-Path $env:TEMP ("wfast_export_" + $PID + ".csv")
        $checks = @(
            @('no-argument CLI help',    '',                                               0,       'Usage:'),
            @('version banner',        'version',                                        0,       'WinTCP'),
            @('help overview',         '--help',                                         0,       'Usage:'),
            @('list header',           'list --limit 1',                                 0,       'Proto'),
            @('list json columns',     'list --format json --columns proto,pid --limit 1', 0,     'proto'),
            @('stat line',             'stat',                                           0,       'CPU'),
            @('ps quiet (rows exist)', 'ps --quiet',                                     0,       ''),
            @('list changes baseline', 'list --watch 1 --changes --count 1',             0,       'baseline:'),
            @('help of unknown cmd',   'help bogus',                                     2,       'unknown command'),
            @('unknown command',       'nonsense',                                       2,       "Try 'wintcp.exe help'"),
            @('kill pseudo pid 4',     'kill --pid 4',                                   2,       'refusing'),
            @('kill without --yes',    'kill --pid 999999',                              3,       'refused: pass --yes to proceed'),
            @('strict switch refusal', "export --out $tmpExport --limit 5",              2,       'not accepted'),
            @('port filter quiet',     'list --filter port:443 --quiet',                 @(0, 1), '')
        )

        $fails = 0
        foreach ($c in $checks) {
            $name = $c[0]; $cmd = $c[1]; $want = $c[2]; $marker = [string]$c[3]
            $argv  = @([regex]::Matches($cmd, '"([^"]+)"|\S+') | ForEach-Object { if ($_.Groups[1].Success) { $_.Groups[1].Value } else { $_.Value } })
            $rfile = Join-Path $t ("cli_" + [Guid]::NewGuid().ToString('N') + ".txt")
            $r = Invoke-Proc -exe $ProdExe -argv $argv -out $rfile
            if (Test-Check $r.Rc $r.Text $want $marker) {
                Say ("ok    {0} [rc={1}]" -f $name, $r.Rc)
            } else {
                $fails++
                Say ("FAIL  {0} [rc={1}, want {2}; marker '{3}'{4}]" -f `
                     $name, $r.Rc, ($want -join '|'), $marker, $(if ($marker) { ' missing' } else { '' }))
            }
            Remove-Item -LiteralPath $rfile, ($rfile + '.err') -ErrorAction SilentlyContinue
        }

        # Harness self-check (same convention as cli.bat/gui.bat): deliberately
        # run an impossible check and confirm the harness flags it. A harness
        # that cannot fail gives every later run a vacuous PASS.
        $r      = Invoke-Proc -exe $ProdExe -argv @('nonsense') -out (Join-Path $t 'selftest.txt')
        $badRc  = 99
        $selfOk = -not (Test-Check $r.Rc $r.Text $badRc 'definitely-no-such-marker')
        if (-not $selfOk) {
            $fails++
            Say "FAIL  harness self-check: an impossible check was NOT flagged"
        } else {
            Say "ok    harness self-check (an impossible check is flagged)"
        }
        Remove-Item -LiteralPath (Join-Path $t 'selftest.txt'), (Join-Path $t 'selftest.txt.err') -ErrorAction SilentlyContinue

        # unit driver: the production code, exercised directly
        if ($needTests) {
            $r = Invoke-Proc -exe $TstExe -argv @('unit') -out (Join-Path $t 'unit.txt')
            if ($r.Rc -eq 0 -and $r.Text.IndexOf('selftest: all checks passed', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                Say "ok    unit driver (wintcp-dev.exe unit)"
            } else {
                $fails++
                Say ("FAIL  unit driver [rc={0}]" -f $r.Rc)
                $lines = $r.Text.Trim().Split("`n")
                for ($k = [Math]::Max(0, $lines.Count - 25); $k -lt $lines.Count; $k++) { Say ("    " + $lines[$k]) }
            }
            Remove-Item -LiteralPath (Join-Path $t 'unit.txt'), ((Join-Path $t 'unit.txt') + '.err') -ErrorAction SilentlyContinue
        }

        # The stale-gate trap: fast-build writes HERE (build-fast\) and the
        # shipped binary comes from build.bat (build\). A dev loop that ends
        # here therefore leaves the gated binary older than the one just
        # verified, and the next person to run build\wintcp.exe tests code
        # that no longer exists in the tree. That happened: a fixed process
        # tree was verified in build-fast while build\wintcp.exe, the binary
        # actually being run, was two hours stale - and the user read it as
        # "the fix does not work".
        #
        # So the dev gate now refuses to be green while that is true. The
        # check is skipped, not failed, when build\ does not exist (a clean
        # clone, or build.bat has never run): nothing is stale then.
        if (Test-Path -LiteralPath $GatedExe) {
            $devM = Get-Mtime $ProdExe
            $gateM = Get-Mtime $GatedExe
            if ($gateM -lt $devM) {
                $fails++
                Say "FAIL  gated binary is STALE (build\wintcp.exe is older than build-fast\wintcp.exe)"
                Say "      The code just verified here is NOT what build\wintcp.exe contains."
                Say "      Run build.bat before testing build\wintcp.exe, or run build-fast\wintcp.exe."
            } else {
                Say "ok    gated binary current (build\wintcp.exe >= build-fast\wintcp.exe)"
            }
        } else {
            Say "note  gated binary absent (build.bat has not run here); nothing to compare"
        }
        if (Test-Path -LiteralPath $tmpExport) { Remove-Item -LiteralPath $tmpExport -ErrorAction SilentlyContinue }

        # Counts the gated-binary check only when it could run (build\ exists),
        # so the denominator is what actually ran rather than a fixed number.
        $gatedCheckRan = (Test-Path -LiteralPath $GatedExe)
        $extra = 1 + $(if ($needTests) { 1 } else { 0 }) + $(if ($gatedCheckRan) { 1 } else { 0 })
        $totalChecks = $checks.Count + $extra
        if ($fails -gt 0) {
            Say ("FAST: FAIL - {0} of {1} checks failed (logs: build-fast\log)" -f $fails, $totalChecks)
            exit 2
        }
        Say ("FAST: PASS - {0}/{1} checks ok (CLI smoke + harness self-check{2})" -f `
             $totalChecks, $totalChecks, $(if ($needTests) { ' + unit driver' } else { '' }))
    }
    exit 0
}
finally {
    if ($Locked) { Remove-Item -LiteralPath $LockDir -Recurse -Force -ErrorAction SilentlyContinue }
}
