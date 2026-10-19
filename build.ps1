# build.ps1 - Unified MSVC build for WinTCP.
#
# Modes:
#   build.bat            incremental: compile only changed .cpp, relink
#   build.bat fresh      clean all artifacts, then full rebuild
#   build.bat rebuild    alias for fresh
#   build.bat web        copy webui assets to build\ only, no compile
#   build.bat clean      remove build\ and exit
#   build.bat -Test      build, then run the CLI smoke gate + unit driver
#
# All modes use /GL /LTCG at link time. Only the incremental path uses
# per-file /Zi + /FS (parallel-safe) instead of a single monolithic cl call.

$ErrorActionPreference = 'Stop'
$StartTime = Get-Date

$Root      = $PSScriptRoot
$Build     = Join-Path $Root 'build'
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

function Say([string]$m) { [Console]::WriteLine("[build] $m") }
function Die([int]$code, [string]$m) { [Console]::WriteLine("[build] ERROR: $m"); exit $code }
function Rel([string]$p) {
    if ([System.IO.Path]::IsPathRooted($p)) {
        try { return [System.IO.Path]::GetRelativePath($Root, $p) } catch { return $p }
    }
    return $p
}
function Read-Text([string]$p) {
    if (-not (Test-Path -LiteralPath $p)) { return '' }
    $t = Get-Content -LiteralPath $p -Raw
    if ($null -eq $t) { return '' }
    return [string]$t
}

# ---- Parse arguments (use $args, not param(), so -Test does not clash) --------
$doFresh = $false
$doWeb   = $false
$doClean = $false
$doTest  = $false

foreach ($a in $args) {
    $al = $a.ToLower()
    if ($al -eq 'fresh')     { $doFresh = $true }
    elseif ($al -eq 'rebuild') { $doFresh = $true }
    elseif ($al -eq 'web')   { $doWeb   = $true }
    elseif ($al -eq 'clean') { $doClean = $true }
    elseif ($al -eq '-test') { $doTest  = $true }
    elseif ($al -eq '-clean') { $doClean = $true }
    elseif ($al -eq '-testonly') { $doTest  = $true }
}

if ($doClean -and -not $doFresh -and -not $doTest -and -not $doWeb) {
    if (Test-Path -LiteralPath $Build) { Remove-Item -LiteralPath $Build -Recurse -Force }
    Say "cleaned $Build"
    exit 0
}

if ($doWeb) {
    if (-not (Test-Path -LiteralPath (Join-Path $Root 'wintcp\webui'))) {
        Die 3 "missing Web UI assets at wintcp\webui"
    }
    if (-not (Test-Path -LiteralPath $Build)) { New-Item -ItemType Directory -Path $Build | Out-Null }
    $assetSource = Join-Path $Root 'wintcp\webui'
    $assetTarget = Join-Path $Build 'webui'
    New-Item -ItemType Directory -Force -Path $assetTarget | Out-Null
    Get-ChildItem -LiteralPath $assetSource -Recurse -File | ForEach-Object {
        $rel = $_.FullName.Substring($assetSource.Length)
        $dest = Join-Path $assetTarget $rel
        $destDir = Split-Path -Parent $dest
        if (-not (Test-Path -LiteralPath $destDir)) { New-Item -ItemType Directory -Force -Path $destDir | Out-Null }
        Copy-Item -LiteralPath $_.FullName -Destination $dest -Force
    }
    Say "Web UI assets copied to $(Rel $assetTarget)"
    exit 0
}

# ---- fresh: clean first -------------------------------------------------------
if ($doFresh) {
    Say "cleaning $Build for fresh rebuild..."
    if (Test-Path -LiteralPath $Build) { Remove-Item -LiteralPath $Build -Recurse -Force }
}

# ---- single-instance lock ------------------------------------------------------
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
        Die 3 "another build is running (pid $holder). Wait for it, or remove $LockDir if it is dead."
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
    # The CLI product is main.cpp + core sources, with no GUI entry point.
    # The standalone GUI is GuiMain.cpp + the same core sources + resources.
    # The dev binary is core + UiProbe.cpp + tests (minus main.cpp).
    #
    # GLOB for core sources so added files stay in the build and test targets.
    #
    $srcCpp  = @(Get-ChildItem -LiteralPath $SrcDir -Filter '*.cpp' | ForEach-Object { $_.FullName })
    $mainCpp = Join-Path $SrcDir 'main.cpp'
    if (-not (Test-Path -LiteralPath $mainCpp)) { Die 3 "wintcp\src\main.cpp not found" }
    $guiCpp = Join-Path $SrcDir 'GuiMain.cpp'
    if (-not (Test-Path -LiteralPath $guiCpp)) { Die 3 "wintcp\src\GuiMain.cpp not found" }
    $probeCpp = Join-Path $SrcDir 'UiProbe.cpp'
    if (-not (Test-Path -LiteralPath $probeCpp)) { Die 3 "wintcp\src\UiProbe.cpp not found" }
    $launcherCpp = Join-Path $SrcDir 'GuiLauncher.cpp'

    # Exclude harness entry points from the core set.
    $coreCpp = @($srcCpp | Where-Object {
        $_.ToLower() -ne $mainCpp.ToLower() -and
        $_.ToLower() -ne $probeCpp.ToLower() -and
        $_.ToLower() -ne $guiCpp.ToLower() -and
        $_.ToLower() -ne $launcherCpp.ToLower()
    })

    $tstCpp  = @(Get-ChildItem -LiteralPath $TstSrc -Filter '*.cpp' | Where-Object { $_.Name -ne 'd2probe.cpp' } | ForEach-Object { $_.FullName })

    $prodCpp = @($mainCpp) + $coreCpp
    $devCpp  = @($probeCpp) + $coreCpp + $tstCpp
    $allCpp  = $prodCpp + $tstCpp + @($probeCpp, $guiCpp)

    $names = $allCpp | ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_).ToLower() }
    if ($names.Count -ne (@($names | Select-Object -Unique)).Count) {
        Die 3 "source files share a base name; object names would collide."
    }

    # ---- flags (fast incremental flags; /LTCG at link time) --------------------
    $clBase = @('/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/permissive-', '/Zc:__cplusplus',
                '/utf-8', '/DUNICODE', '/D_UNICODE', '/D_WIN32_WINNT=0x0601', '/DWIN32_LEAN_AND_MEAN',
                '/O2', '/Oy-', '/Zi', '/MT', '/FS', '/guard:cf')
    $libs   = @('iphlpapi.lib', 'ws2_32.lib', 'comctl32.lib', 'psapi.lib', 'user32.lib', 'gdi32.lib',
                'comdlg32.lib', 'shell32.lib', 'advapi32.lib', 'crypt32.lib', 'wintrust.lib',
                'pdh.lib', 'ole32.lib', 'oleaut32.lib', 'bcrypt.lib', 'delayimp.lib')
    $linkOpts = @('/SUBSYSTEM:CONSOLE', '/guard:cf', '/MANIFEST:NO', '/LTCG', '/OPT:REF', '/OPT:ICF', '/DEBUG:NONE')
    $delayLoads = @('/DELAYLOAD:comdlg32.dll', '/DELAYLOAD:crypt32.dll', '/DELAYLOAD:ole32.dll',
                    '/DELAYLOAD:oleaut32.dll', '/DELAYLOAD:pdh.dll', '/DELAYLOAD:shell32.dll')

    # ---- header dependency tracking -----------------------------------------------
    $mtimes = @{}
    function Get-Mtime([string]$p) {
        $k = $p.ToLower()
        if ($mtimes.ContainsKey($k)) { return $mtimes[$k] }
        $t = [System.IO.File]::GetLastWriteTimeUtc($p)
        $mtimes[$k] = $t
        return $t
    }
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
                    $alt = [System.IO.Path]::GetFullPath((Join-Path $SrcDir $inc)).ToLower()
                    if ($projectSet.ContainsKey($alt)) { $cand = $alt }
                    else { continue }
                }
                $seen[$cand] = $true
                $list.Add($cand)
                $queue.Enqueue($cand)
            }
        }
        $deps[$k] = $list.ToArray()
    }

    # Resource script dependencies
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

    # ---- directories ------------------------------------------------------------
    if (-not (Test-Path -LiteralPath $Build)) { New-Item -ItemType Directory -Path $Build | Out-Null }
    New-Item -ItemType Directory -Path $Build -Force | Out-Null
    if (Test-Path -LiteralPath $LogDir) { Remove-Item -LiteralPath $LogDir -Recurse -Force }
    New-Item -ItemType Directory -Path $LogDir | Out-Null
    if (-not (Test-Path -LiteralPath $ObjDir)) { New-Item -ItemType Directory -Path $ObjDir | Out-Null }
    if (-not (Test-Path -LiteralPath $TstDir)) { New-Item -ItemType Directory -Path $TstDir | Out-Null }

    $needTests = $doTest
    $doBuild   = $true
    if ($doFresh) {
        Say "full rebuild (fresh)"
    } else {
        Say "incremental build"
    }

    # ---- compile ---------------------------------------------------------------
    $stateInput = [string]::Join('|', (($clBase + $libs + $linkOpts + $delayLoads + @('GUI:/SUBSYSTEM:WINDOWS')) + $allCpp))
    $sha        = [System.Security.Cryptography.SHA256]::Create()
    $stateHash  = [BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($stateInput))).Replace('-', '')
    $stateMatches = $false
    if (Test-Path -LiteralPath $StateFile) {
        $stateMatches = (Read-Text $StateFile).Trim() -eq $stateHash
    }
    $forceAll = $doFresh -or (-not $stateMatches)
    if ($forceAll -and -not $doFresh) {
        Say "build inputs changed since the last build; recompiling everything"
    }

    $compilePlan = New-Object System.Collections.Generic.List[object]
    foreach ($cpp in $allCpp) {
        $isTest = $cpp.ToLower().StartsWith($TstSrc.ToLower() + '\')
        if ($isTest -and -not $needTests) { continue }
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

    $compiled = 0
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
                $arg = [string]::Join(' ', $clBase) + ' /Fo"' + $ObjDir + '\\" /c "' + $w.Cpp + '"'
                if ($w.Test) { $arg += ' /I "' + $SrcDir + '"' }
                $p = Start-Process -FilePath $clPath -ArgumentList $arg -WorkingDirectory $Root `
                    -WindowStyle Hidden -PassThru `
                    -RedirectStandardOutput $w.Log `
                    -RedirectStandardError ($w.Log + '.err')
                $null = $p.Handle
                $procs.Add($p)
                $batchW.Add($w)
            }
            foreach ($p in $procs) { $p.WaitForExit() }

            $failures = @()
            for ($b = 0; $b -lt $procs.Count; $b++) {
                $rc = $procs[$b].ExitCode
                if ($null -eq $rc) {
                    if ((Read-Text $batchW[$b].Log).Trim().Length -gt 0) {
                        $failures += ,@($batchW[$b], 'unreadable rc, compiler log not empty')
                    } else {
                        Say ('WARN  could not read the exit code for {0}; treating as success' -f (Rel $batchW[$b].Cpp))
                    }
                    continue
                }
                if ($rc -ne 0) { $failures += ,@($batchW[$b], $rc) }
            }
            if ($failures.Count -gt 0) {
                foreach ($f in $failures) {
                    $w  = $f[0]
                    Say ("COMPILE FAILED: " + (Rel $w.Cpp) + " (cl rc " + $f[1] + ")")
                    Say (Read-Text $w.Log)
                    Say (Read-Text ($w.Log + '.err'))
                }
                Die 1 ("{0} of {1} files failed to compile; logs kept in $(Rel $LogDir)" -f $failures.Count, $compilePlan.Count)
            }
            for ($j = $i; $j -lt $end; $j++) { $compiled++ }
        }
        Say ("compiled {0} file(s) in {1:N1}s" -f $compiled, ((Get-Date) - $StartTime).TotalSeconds)
    } else {
        Say "nothing to recompile (all objects current)"
    }

    # ---- resource ------------------------------------------------------------
    $resStale = $forceAll -or (-not (Test-Path -LiteralPath $ResFile))
    if (-not $resStale) {
        $r = Get-Mtime $ResFile
        foreach ($h in $resDeps) { if ((Get-Mtime $h) -gt $r) { $resStale = $true; break } }
    }
    if ($resStale) {
        $rout = & $rcPath /nologo /fo "$ResFile" "$rcFile" 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { [Console]::WriteLine($rout); Die 1 "resource compile failed (wintcp.rc)" }
        Say "compiled resource (wintcp.res)"
    } else {
        Say "resource current (wintcp.res)"
    }

    # ---- link ----------------------------------------------------------------
    # Clear the mtime cache so newly written .obj files are seen with fresh
    # on-disk timestamps by the link staleness check.
    Clear-MtimeCache

    $prodObjs = @($prodCpp | ForEach-Object { Join-Path $ObjDir ([System.IO.Path]::GetFileNameWithoutExtension($_) + '.obj') })
    $linkProd = $forceAll -or (-not (Test-Path -LiteralPath $ProdExe))
    if (-not $linkProd) {
        $p = Get-Mtime $ProdExe
        foreach ($inp in ($prodObjs + $ResFile)) { if ((Get-Mtime $inp) -gt $p) { $linkProd = $true; break } }
    }
    if ($linkProd) {
        # Delete old exe first
        if (Test-Path -LiteralPath $ProdExe) { Remove-Item -LiteralPath $ProdExe -Force }
        $arg = '/nologo /guard:cf /Fe"' + $ProdExe + '"'
        foreach ($i in $prodObjs) { $arg += ' "' + $i + '"' }
        $arg += ' "' + $ResFile + '"'
        $arg += ' /link'
        foreach ($lib in $libs) { $arg += ' ' + $lib }
        foreach ($o in $linkOpts) { $arg += ' ' + $o }
        foreach ($dl in $delayLoads) { $arg += ' ' + $dl }
        $t0 = Get-Date
        $lp = Join-Path $LogDir 'link-wintcp.out'
        $p  = Start-Process -FilePath $clPath -ArgumentList $arg -WorkingDirectory $Root `
                -WindowStyle Hidden -Wait -PassThru `
                -RedirectStandardOutput $lp `
                -RedirectStandardError ($lp + '.err')
        $p.WaitForExit()
        if ($p.ExitCode -ne 0) {
            Say (Read-Text $lp)
            Say (Read-Text ($lp + '.err'))
            Die 1 "product link failed"
        }
        Say ("linked wintcp.exe in {0:N1}s" -f ((Get-Date) - $t0).TotalSeconds)
    } else {
        Say "wintcp.exe current"
    }

    # GUI
    $guiObjs = @($coreCpp | ForEach-Object { Join-Path $ObjDir ([System.IO.Path]::GetFileNameWithoutExtension($_) + '.obj') })
    $guiObjs = @($guiObjs) + @(Join-Path $ObjDir 'GuiMain.obj')
    if (Test-ObjStale (Join-Path $ObjDir 'GuiMain.obj') $guiCpp $deps[$guiCpp.ToLower()] $forceAll) {
        $arg = [string]::Join(' ', $clBase) + ' /Fo"' + $ObjDir + '\\" /c "' + $guiCpp + '"'
        $lp = Join-Path $LogDir 'compile-GuiMain.out'
        $p = Start-Process -FilePath $clPath -ArgumentList $arg -WorkingDirectory $Root `
            -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput $lp -RedirectStandardError ($lp + '.err')
        $p.WaitForExit()
        if ($p.ExitCode -ne 0) { Say (Read-Text $lp); Die 1 "GuiMain.cpp compile failed" }
    }
    $linkGui = $forceAll -or (-not (Test-Path -LiteralPath $GuiExe))
    if (-not $linkGui) {
        $p = Get-Mtime $GuiExe
        foreach ($inp in ($guiObjs + $ResFile)) { if ((Get-Mtime $inp) -gt $p) { $linkGui = $true; break } }
    }
    if ($linkGui) {
        if (Test-Path -LiteralPath $GuiExe) { Remove-Item -LiteralPath $GuiExe -Force }
        $arg = '/nologo /guard:cf /Fe"' + $GuiExe + '"'
        foreach ($i in $guiObjs) { $arg += ' "' + $i + '"' }
        $arg += ' "' + $ResFile + '"'
        $arg += ' /link /SUBSYSTEM:WINDOWS /MACHINE:X64 /INCREMENTAL:NO'
        foreach ($lib in $libs) { $arg += ' ' + $lib }
        $arg += ' /OPT:REF /OPT:ICF /DEBUG:NONE /MANIFEST:NO /LTCG /GUARD:CF'
        foreach ($dl in $delayLoads) { $arg += ' ' + $dl }
        $t0 = Get-Date
        $lp = Join-Path $LogDir 'link-wintcp-gui.out'
        $p  = Start-Process -FilePath $clPath -ArgumentList $arg -WorkingDirectory $Root `
                -WindowStyle Hidden -Wait -PassThru `
                -RedirectStandardOutput $lp `
                -RedirectStandardError ($lp + '.err')
        $p.WaitForExit()
        if ($p.ExitCode -ne 0) {
            Say (Read-Text $lp)
            Say (Read-Text ($lp + '.err'))
            Die 1 "GUI link failed"
        }
        Say ("linked wintcp-gui.exe in {0:N1}s" -f ((Get-Date) - $t0).TotalSeconds)
    } else {
        Say "wintcp-gui.exe current"
    }

    # ---- dev test driver (only with -Test) ------------------------------------
    if ($needTests) {
        $tstObjs = @($coreCpp | ForEach-Object { Join-Path $ObjDir ([System.IO.Path]::GetFileNameWithoutExtension($_) + '.obj') })
        $tstObjs = @($tstObjs) + @(Join-Path $ObjDir 'UiProbe.obj')

        foreach ($cpp in $tstCpp) {
            $name = [System.IO.Path]::GetFileNameWithoutExtension($cpp)
            $obj = Join-Path $ObjDir ($name + '.obj')
            if (Test-ObjStale $obj $cpp $deps[$cpp.ToLower()] $forceAll) {
                $arg = [string]::Join(' ', $clBase) + ' /Fo"' + $ObjDir + '\\" /c "' + $cpp + '" /I "' + $SrcDir + '"'
                $lp = Join-Path $LogDir ($name + '.out')
                $p = Start-Process -FilePath $clPath -ArgumentList $arg -WorkingDirectory $Root `
                    -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput $lp -RedirectStandardError ($lp + '.err')
                $p.WaitForExit()
                if ($p.ExitCode -ne 0) { Say (Read-Text $lp); Die 1 ($name + ".cpp compile failed") }
            }
            $tstObjs = @($tstObjs) + @($obj)
        }

        $linkTst = $forceAll -or (-not (Test-Path -LiteralPath $TstExe))
        if (-not $linkTst) {
            $p = Get-Mtime $TstExe
            foreach ($inp in ($tstObjs + $ResFile)) { if ((Get-Mtime $inp) -gt $p) { $linkTst = $true; break } }
        }
        if ($linkTst) {
            if (Test-Path -LiteralPath $TstExe) { Remove-Item -LiteralPath $TstExe -Force }
            $arg = '/nologo /guard:cf /Fe"' + $TstExe + '"'
            foreach ($i in $tstObjs) { $arg += ' "' + $i + '"' }
            $arg += ' "' + $ResFile + '"'
            $arg += ' /link'
            foreach ($lib in $libs) { $arg += ' ' + $lib }
            foreach ($o in $linkOpts) { $arg += ' ' + $o }
            foreach ($dl in $delayLoads) { $arg += ' ' + $dl }
            $lp = Join-Path $LogDir 'link-wintcp-dev.out'
            $p  = Start-Process -FilePath $clPath -ArgumentList $arg -WorkingDirectory $Root `
                    -WindowStyle Hidden -Wait -PassThru `
                    -RedirectStandardOutput $lp `
                    -RedirectStandardError ($lp + '.err')
            $p.WaitForExit()
            if ($p.ExitCode -ne 0) {
                Say (Read-Text $lp)
                Say (Read-Text ($lp + '.err'))
                Die 1 "test driver link failed"
            }
            Say ("linked wintcp-dev.exe")
        } else {
            Say "wintcp-dev.exe current"
        }
    }

    # ---- webui assets ---------------------------------------------------------
    $assetSource = Join-Path $Root 'wintcp\webui'
    $assetTarget = Join-Path $Build 'webui'
    if (-not (Test-Path -LiteralPath $assetSource)) { Die 3 "missing Web UI assets at wintcp\webui" }
    New-Item -ItemType Directory -Force -Path $assetTarget | Out-Null
    Get-ChildItem -LiteralPath $assetSource -Recurse -File | ForEach-Object {
        $rel = $_.FullName.Substring($assetSource.Length)
        $dest = Join-Path $assetTarget $rel
        $destDir = Split-Path -Parent $dest
        if (-not (Test-Path -LiteralPath $destDir)) { New-Item -ItemType Directory -Force -Path $destDir | Out-Null }
        Copy-Item -LiteralPath $_.FullName -Destination $dest -Force
    }

    $stateHash | Set-Content -LiteralPath $StateFile -NoNewline
    $elapsed = ((Get-Date) - $StartTime).TotalSeconds
    $kb = [math]::Round((Get-Item -LiteralPath $ProdExe).Length / 1KB)
    Say ("build OK in {0:N1}s: {1} compiled, {2:N0} KB -> {3}" -f $elapsed, $compiled, $kb, (Rel $ProdExe))

    # ---- tests ----------------------------------------------------------------
    if ($doTest) {
        if (-not (Test-Path -LiteralPath $ProdExe)) { Die 3 "wintcp.exe not built" }
        if (-not (Test-Path -LiteralPath $TstExe)) { Die 1 "wintcp-dev.exe missing after build step" }

        Say "smoke gate: CLI checks + unit driver (headless, nothing mutating)"

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
        if (-not (Test-Path -LiteralPath $t)) { New-Item -ItemType Directory -Path $t | Out-Null }

        $checks = @(
            @('no-argument CLI help',    @(),                                       0,       'Usage:'),
            @('version banner',          @('version'),                              0,       'WinTCP'),
            @('help overview',           @('--help'),                               0,       'Usage:'),
            @('list header',             @('list','--limit','1'),                   0,       'Proto'),
            @('list json columns',       @('list','--format','json','--columns','proto,pid','--limit','1'), 0, 'proto'),
            @('stat line',               @('stat'),                                 0,       'CPU'),
            @('ps quiet',                @('ps','--quiet'),                         0,       ''),
            @('list changes baseline',   @('list','--watch','1','--changes','--count','1'), 0, 'baseline:'),
            @('help of unknown cmd',     @('help','bogus'),                         2,       'unknown command'),
            @('unknown command',         @('nonsense'),                             2,       "Try 'wintcp.exe help'"),
            @('kill pseudo pid 4',       @('kill','--pid','4'),                     2,       'refusing'),
            @('kill without --yes',      @('kill','--pid','999999'),                3,       'refused: pass --yes to proceed'),
            @('strict switch refusal',   @('export','--out','C:\temp\fast.csv','--limit','5'), 2, 'not accepted'),
            @('port filter quiet',       @('list','--filter','port:443','--quiet'), @(0,1), '')
        )

        $fails = 0
        foreach ($c in $checks) {
            $name = $c[0]; $cmd = $c[1]; $want = $c[2]; $marker = [string]$c[3]
            $rfile = Join-Path $t ("cli_" + [Guid]::NewGuid().ToString('N') + ".txt")
            $r = Invoke-Proc -exe $ProdExe -argv $cmd -out $rfile
            if (Test-Check $r.Rc $r.Text $want $marker) {
                Say ("ok    {0} [rc={1}]" -f $name, $r.Rc)
            } else {
                $fails++
                Say ("FAIL  {0} [rc={1}, want {2}; marker '{3}'{4}]" -f `
                     $name, $r.Rc, ($want -join '|'), $marker, $(if ($marker) { ' missing' } else { '' }))
            }
            Remove-Item -LiteralPath $rfile, ($rfile + '.err') -ErrorAction SilentlyContinue
        }

        # Harness self-check
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

        # Unit driver
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

        if ($fails -gt 0) {
            Say ("FAIL - {0} of {1} checks failed (logs: $(Rel $LogDir))" -f $fails, ($checks.Count + 2))
            exit 2
        }
        Say ("PASS - {0} of {1} checks ok (CLI smoke + harness self-check + unit driver)" -f ($checks.Count + 2), ($checks.Count + 2))
    }
    exit 0
}
finally {
    if ($Locked) { Remove-Item -LiteralPath $LockDir -Recurse -Force -ErrorAction SilentlyContinue }
}
