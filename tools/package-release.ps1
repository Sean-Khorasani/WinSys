param(
    [string]$Version
)

$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$versionHeader = Join-Path $repoRoot 'wintcp\src\Version.h'
$versionText = [IO.File]::ReadAllText($versionHeader)
$versionMatch = [regex]::Match($versionText, '#define WINTCP_VERSION_STRING "([0-9]+\.[0-9]+\.[0-9]+)"')
if (-not $versionMatch.Success) { throw 'Could not read WINTCP_VERSION_STRING from Version.h.' }
$sourceVersion = $versionMatch.Groups[1].Value
if ([string]::IsNullOrWhiteSpace($Version)) { $Version = $sourceVersion }
if ($Version -notmatch '^\d+\.\d+\.\d+$' -or $Version -ne $sourceVersion) {
    throw "Requested package version '$Version' does not match Version.h ($sourceVersion)."
}

$buildRoot = Join-Path $repoRoot 'build'
$cliPath = Join-Path $buildRoot 'wintcp.exe'
$guiPath = Join-Path $buildRoot 'wintcp-gui.exe'
$webRoot = Join-Path $buildRoot 'webui'
foreach ($required in @($cliPath, $guiPath, (Join-Path $webRoot 'index.html'))) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required release build input is missing: $required (run build.bat first)."
    }
}

$versionOutput = (& $cliPath version 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0 -or $versionOutput -notmatch "(?m)^WinTCP $([regex]::Escape($Version))\s*$") {
    throw "CLI build does not report WinTCP $Version; rebuild before packaging."
}
$guiVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($guiPath).FileVersion
if ($guiVersion -notmatch "^$([regex]::Escape($Version))(\.0)?$") {
    throw "GUI file version '$guiVersion' does not match $Version."
}
$manifestPath = Join-Path $repoRoot 'wintcp\res\wintcp.manifest'
[xml]$appManifest = [IO.File]::ReadAllText($manifestPath)
$assemblyVersion = $appManifest.assembly.assemblyIdentity.version
if ($assemblyVersion -ne "$Version.0") {
    throw "Application manifest version '$assemblyVersion' does not match $Version.0."
}

$releaseDir = Join-Path $repoRoot 'release'
if (-not (Test-Path -LiteralPath $releaseDir -PathType Container)) {
    New-Item -ItemType Directory -Path $releaseDir | Out-Null
}
$packageName = "WinTCP-$Version-Windows-x64.zip"
$zipPath = Join-Path $releaseDir $packageName
$checksumPath = "$zipPath.sha256"
if (Test-Path -LiteralPath $zipPath) {
    throw "Refusing to overwrite existing package: $zipPath"
}
if (Test-Path -LiteralPath $checksumPath) {
    throw "Refusing to overwrite existing checksum: $checksumPath"
}

$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
$stagePath = Join-Path $tempBase ("WinTCP-release-" + [guid]::NewGuid().ToString('N'))
$stagePath = [IO.Path]::GetFullPath($stagePath)
if (-not $stagePath.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to stage package outside the temporary directory: $stagePath"
}
$packageRoot = Join-Path $stagePath "WinTCP-$Version-Windows-x64"
$createdZip = $false
$createdChecksum = $false

function Copy-PackageFile([string]$RelativePath) {
    $source = Join-Path $repoRoot $RelativePath
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "Required package file is missing: $RelativePath"
    }
    $destination = Join-Path $packageRoot $RelativePath
    $destinationDirectory = Split-Path -Parent $destination
    if (-not (Test-Path -LiteralPath $destinationDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
    }
    Copy-Item -LiteralPath $source -Destination $destination
}

try {
    New-Item -ItemType Directory -Path $packageRoot -Force | Out-Null
    Copy-Item -LiteralPath $cliPath -Destination (Join-Path $packageRoot 'wintcp.exe')
    Copy-Item -LiteralPath $guiPath -Destination (Join-Path $packageRoot 'wintcp-gui.exe')
    Copy-Item -LiteralPath $webRoot -Destination (Join-Path $packageRoot 'webui') -Recurse
    foreach ($path in @(
        'README.md', 'CHANGELOG.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md',
        'webui-service.bat', 'webui-service.ps1',
        'docs\architecture.md', 'docs\cli.md', 'docs\cookbook.md',
        'docs\filters.md', 'docs\gui.md', 'docs\traffic.md',
        'docs\webui-design.md', 'docs\webui.md',
        'docs\img\webui-map-2d.png', 'docs\img\webui-map-globe.png',
        'docs\img\webui-map.png', 'docs\img\webui-network-flows.png',
        'docs\img\webui-network.png', 'docs\img\webui-overview.png',
        'docs\img\webui-processes-treemap.png', 'docs\img\webui-processes.png'
    )) {
        Copy-PackageFile $path
    }

    $allFiles = @(Get-ChildItem -LiteralPath $packageRoot -Recurse -File)
    if (-not ($allFiles | Where-Object { $_.Name -eq 'wintcp.exe' }) -or
        -not ($allFiles | Where-Object { $_.Name -eq 'wintcp-gui.exe' })) {
        throw 'The package is missing one of the two user-facing executables.'
    }
    $unexpectedExecutables = @($allFiles | Where-Object {
        $_.Extension -eq '.exe' -and $_.Name -notin @('wintcp.exe', 'wintcp-gui.exe')
    })
    if ($unexpectedExecutables.Count -gt 0) {
        throw "Unexpected executable in package staging tree: $($unexpectedExecutables[0].FullName)"
    }
    $forbidden = @($allFiles | Where-Object {
        $relativePath = $_.FullName.Substring($packageRoot.Length).TrimStart([char[]]@('\', '/'))
        $_.Extension -in @('.pdb', '.obj', '.ilk', '.exp', '.lib', '.mmdb', '.log') -or
        $_.Name -in @('AGENTS.md', 'tasks.md', 'todo.md') -or
        $relativePath -match '(?i)(^|[\\/])(node_modules|build-cmake|tests|temp)([\\/]|$)'
    })
    if ($forbidden.Count -gt 0) {
        throw "Development or machine-specific file entered the release package: $($forbidden[0].FullName)"
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory(
        $stagePath, $zipPath, [IO.Compression.CompressionLevel]::Optimal, $false)
    $createdZip = $true

    $archive = [IO.Compression.ZipFile]::OpenRead($zipPath)
    try {
        $entries = @($archive.Entries | ForEach-Object { $_.FullName.Replace('\', '/') })
        $expectedPrefix = "WinTCP-$Version-Windows-x64/"
        foreach ($expected in @(
            'wintcp.exe', 'wintcp-gui.exe', 'README.md', 'CHANGELOG.md',
            'LICENSE', 'THIRD_PARTY_NOTICES.md', 'webui/index.html',
            'webui/vendor/LICENSES/MapLibre-BSD-3-Clause.txt', 'docs/webui.md'
        )) {
            $expectedEntry = $expectedPrefix + $expected
            if ($expectedEntry -notin $entries) {
                throw "The ZIP is missing required package entry: $expected"
            }
        }
        if ($entries | Where-Object { $_ -match '(?i)(\.mmdb|\.pdb|\.log|/tasks\.md$|/AGENTS\.md$)' }) {
            throw 'The ZIP contains a forbidden database, build/debug artifact, log, or handoff file.'
        }
    }
    finally { $archive.Dispose() }

    $sha256 = [Security.Cryptography.SHA256]::Create()
    $zipStream = [IO.File]::OpenRead($zipPath)
    try {
        $hash = [BitConverter]::ToString($sha256.ComputeHash($zipStream)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $zipStream.Dispose()
        $sha256.Dispose()
    }
    [IO.File]::WriteAllText($checksumPath, "$hash  $packageName`r`n", [Text.Encoding]::ASCII)
    $createdChecksum = $true
    Write-Output "release-package=$zipPath"
    Write-Output "release-sha256=$hash"
    Write-Output "release-files=$($allFiles.Count)"
}
catch {
    if ($createdZip -and (Test-Path -LiteralPath $zipPath -PathType Leaf)) {
        Remove-Item -LiteralPath $zipPath
    }
    if ($createdChecksum -and (Test-Path -LiteralPath $checksumPath -PathType Leaf)) {
        Remove-Item -LiteralPath $checksumPath
    }
    throw
}
finally {
    if (Test-Path -LiteralPath $stagePath -PathType Container) {
        $resolvedStage = [IO.Path]::GetFullPath($stagePath)
        if (-not $resolvedStage.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to remove staging path outside the temporary directory: $resolvedStage"
        }
        Remove-Item -LiteralPath $resolvedStage -Recurse -Force
    }
}
