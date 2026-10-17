[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('start', 'stop', 'status')]
    [string]$Action,

    [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR')]
    [string]$LogLevel = 'DEBUG'
)

$ErrorActionPreference = 'Stop'
$script:Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:DataDirectory = Join-Path $env:LOCALAPPDATA 'WinTCP\WebUi'
$script:PidFile = Join-Path $script:DataDirectory 'webui-service.pid'
$script:LogFile = Join-Path $script:DataDirectory 'webui.log'
$script:LogLevel = $LogLevel.ToUpperInvariant()
$script:LevelRank = @{ DEBUG = 0; INFO = 1; WARN = 2; ERROR = 3 }
$script:Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

function Write-ServiceLog {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR')]
        [string]$Severity,
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    if ($script:LevelRank[$Severity] -lt $script:LevelRank[$script:LogLevel]) {
        return
    }
    $line = '{0} [{1}] manager {2}{3}' -f `
        [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ'),
        $Severity, $Message, "`r`n"
    [IO.File]::AppendAllText($script:LogFile, $line, $script:Utf8NoBom)
}

function Read-ServiceRecord {
    if (-not (Test-Path -LiteralPath $script:PidFile -PathType Leaf)) {
        return $null
    }
    $values = @{}
    foreach ($line in [IO.File]::ReadAllLines($script:PidFile)) {
        $parts = $line -split '=', 2
        if ($parts.Count -eq 2) {
            $values[$parts[0]] = $parts[1]
        }
    }
    $servicePid = 0
    [long]$startUtcTicks = 0
    if (-not $values.ContainsKey('PID') -or
        -not [int]::TryParse($values['PID'], [ref]$servicePid) -or
        $servicePid -le 0 -or
        -not $values.ContainsKey('STARTUTC') -or
        -not [long]::TryParse($values['STARTUTC'], [ref]$startUtcTicks) -or
        $startUtcTicks -le 0 -or
        [string]::IsNullOrWhiteSpace($values['EXE'])) {
        throw "Invalid service record at $script:PidFile; refusing to guess which process to stop."
    }
    return [pscustomobject]@{ PID = $servicePid; Exe = $values['EXE']; StartUtcTicks = $startUtcTicks }
}

function Get-ProcessRecord {
    param([Parameter(Mandatory = $true)][int]$Id)
    return Get-Process -Id $Id -ErrorAction SilentlyContinue
}

function Test-ManagedProcess {
    param(
        [Parameter(Mandatory = $true)]$Process,
        [Parameter(Mandatory = $true)][string]$ExpectedExe,
        [Parameter(Mandatory = $true)][long]$ExpectedStartUtcTicks
    )
    if ($null -eq $Process -or
        $Process.ProcessName -ne 'wintcp' -or
        [string]::IsNullOrWhiteSpace($Process.Path)) {
        return $false
    }
    try {
        $actual = [IO.Path]::GetFullPath($Process.Path)
        $expected = [IO.Path]::GetFullPath($ExpectedExe)
        $actualStartUtcTicks = $Process.StartTime.ToUniversalTime().Ticks
    } catch {
        return $false
    }
    return $actual.Equals($expected, [StringComparison]::OrdinalIgnoreCase) -and
        $actualStartUtcTicks -eq $ExpectedStartUtcTicks
}

function Get-WebUiExe {
    $candidates = @(
        (Join-Path $script:Root 'build\wintcp.exe'),
        (Join-Path $script:Root 'wintcp.exe')
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return [IO.Path]::GetFullPath($candidate)
        }
    }
    throw "wintcp.exe not found. Build it under '$script:Root\build' or place it beside this script."
}

function Stop-ManagedProcess {
    param([Parameter(Mandatory = $true)]$Record)
    $process = Get-ProcessRecord -Id $Record.PID
    if ($null -eq $process) {
        Remove-Item -LiteralPath $script:PidFile -Force -ErrorAction SilentlyContinue
        Write-ServiceLog INFO "service was already stopped pid=$($Record.PID)"
        return
    }
    if (-not (Test-ManagedProcess -Process $process -ExpectedExe $Record.Exe `
                              -ExpectedStartUtcTicks $Record.StartUtcTicks)) {
        throw "PID $($Record.PID) no longer identifies this WinTCP Web UI. It was not stopped; inspect '$script:PidFile'."
    }

    Write-ServiceLog DEBUG "graceful stop requested pid=$($Record.PID)"
    $eventName = "Local\WinTCP.WebUi.Stop.$($Record.PID)"
    try {
        $stopEvent = [Threading.EventWaitHandle]::OpenExisting($eventName)
    } catch {
        throw "Could not open the Web UI shutdown event for PID $($Record.PID): $($_.Exception.Message)"
    }
    try {
        $null = $stopEvent.Set()
    } finally {
        $stopEvent.Dispose()
    }
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        Start-Sleep -Milliseconds 250
        if ($null -eq (Get-ProcessRecord -Id $Record.PID)) { break }
    }
    if ($null -ne (Get-ProcessRecord -Id $Record.PID)) {
        throw "The Web UI shutdown event was signaled, but PID $($Record.PID) did not exit within 10 seconds."
    }
    Remove-Item -LiteralPath $script:PidFile -Force -ErrorAction SilentlyContinue
    Write-ServiceLog INFO "service stopped pid=$($Record.PID)"
}

try {
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        throw 'LOCALAPPDATA is not available for the current user.'
    }
    New-Item -ItemType Directory -Path $script:DataDirectory -Force | Out-Null

    switch ($Action.ToLowerInvariant()) {
        'start' {
            $exe = Get-WebUiExe
            $asset = Join-Path (Split-Path -Parent $exe) 'webui\index.html'
            if (-not (Test-Path -LiteralPath $asset -PathType Leaf)) {
                throw "Web UI assets missing beside '$exe'. The sibling webui folder must include index.html."
            }

            $record = Read-ServiceRecord
            if ($null -ne $record) {
                $existing = Get-ProcessRecord -Id $record.PID
                if ($null -ne $existing) {
                    if (Test-ManagedProcess -Process $existing -ExpectedExe $record.Exe `
                                            -ExpectedStartUtcTicks $record.StartUtcTicks) {
                        Write-Host "WinTCP Web UI is already running (PID $($record.PID))."
                        Write-Host "Log: $script:LogFile"
                        exit 0
                    }
                    throw "PID $($record.PID) is occupied by a different process; refusing to replace the service record."
                }
                Remove-Item -LiteralPath $script:PidFile -Force
                Write-ServiceLog WARN 'removed a stale Web UI PID record'
            }

            $level = $script:LogLevel
            Write-ServiceLog INFO "start requested log_level=$level"
            $oldLevel = [Environment]::GetEnvironmentVariable('WINTCP_WEBUI_LOG_LEVEL', 'Process')
            $oldFile = [Environment]::GetEnvironmentVariable('WINTCP_WEBUI_LOG_FILE', 'Process')
            $oldBrowser = [Environment]::GetEnvironmentVariable('WINTCP_WEBUI_OPEN_BROWSER', 'Process')
            try {
                $env:WINTCP_WEBUI_LOG_LEVEL = $level
                $env:WINTCP_WEBUI_LOG_FILE = $script:LogFile
                $env:WINTCP_WEBUI_OPEN_BROWSER = '0'
                $started = Start-Process -FilePath $exe -ArgumentList @('webui', 'serve') `
                    -WorkingDirectory (Split-Path -Parent $exe) -WindowStyle Hidden -PassThru
                $null = $started.Handle
            } finally {
                [Environment]::SetEnvironmentVariable('WINTCP_WEBUI_LOG_LEVEL', $oldLevel, 'Process')
                [Environment]::SetEnvironmentVariable('WINTCP_WEBUI_LOG_FILE', $oldFile, 'Process')
                [Environment]::SetEnvironmentVariable('WINTCP_WEBUI_OPEN_BROWSER', $oldBrowser, 'Process')
            }

            $record = [pscustomobject]@{
                PID = $started.Id
                Exe = $exe
                StartUtcTicks = $started.StartTime.ToUniversalTime().Ticks
            }
            $recordText = "PID=$($record.PID)`r`nEXE=$($record.Exe)`r`nSTARTUTC=$($record.StartUtcTicks)`r`n"
            [IO.File]::WriteAllText($script:PidFile, $recordText, $script:Utf8NoBom)

            $readyLine = $null
            $deadline = [DateTime]::UtcNow.AddSeconds(10)
            do {
                $current = Get-ProcessRecord -Id $record.PID
                if ($null -eq $current) {
                    Remove-Item -LiteralPath $script:PidFile -Force -ErrorAction SilentlyContinue
                    throw "Web UI exited during startup. Review '$script:LogFile'."
                }
                if (Test-Path -LiteralPath $script:LogFile -PathType Leaf) {
                    $pattern = "\[INFO\] pid=$($record.PID) listening at http://127\.0\.0\.1:\d+/"
                    $readyLine = Get-Content -LiteralPath $script:LogFile -Tail 200 |
                        Where-Object { $_ -match $pattern } | Select-Object -Last 1
                }
                if ($readyLine) { break }
                Start-Sleep -Milliseconds 250
            } while ([DateTime]::UtcNow -lt $deadline)

            if (-not $readyLine) {
                Stop-ManagedProcess -Record $record
                throw "Web UI did not report ready within 10 seconds. Review '$script:LogFile'."
            }
            $url = [regex]::Match($readyLine, 'http://127\.0\.0\.1:\d+/').Value
            Write-Host "WinTCP Web UI started in the background (PID $($record.PID))."
            Write-Host "URL: $url"
            Write-Host "Log level: $level"
            Write-Host "Log: $script:LogFile"
        }
        'stop' {
            $record = Read-ServiceRecord
            if ($null -eq $record) {
                Write-Host 'No Web UI process is recorded by this manager.'
            } else {
                Stop-ManagedProcess -Record $record
                Write-Host "WinTCP Web UI stopped. Log: $script:LogFile"
            }
        }
        'status' {
            $record = Read-ServiceRecord
            if ($null -eq $record) {
                Write-Host "WinTCP Web UI is not running under this manager. Log: $script:LogFile"
            } else {
                $process = Get-ProcessRecord -Id $record.PID
                if ($null -eq $process) {
                    Remove-Item -LiteralPath $script:PidFile -Force -ErrorAction SilentlyContinue
                    Write-ServiceLog WARN 'removed a stale Web UI PID record during status check'
                    Write-Host "WinTCP Web UI is not running. Log: $script:LogFile"
                } elseif (-not (Test-ManagedProcess -Process $process -ExpectedExe $record.Exe `
                                                   -ExpectedStartUtcTicks $record.StartUtcTicks)) {
                    throw "PID $($record.PID) is occupied by a different process; status is uncertain and no action was taken."
                } else {
                    Write-Host "WinTCP Web UI is running in the background (PID $($record.PID))."
                    if (Test-Path -LiteralPath $script:LogFile -PathType Leaf) {
                        $pattern = "\[INFO\] pid=$($record.PID) listening at http://127\.0\.0\.1:\d+/"
                        $readyLine = Get-Content -LiteralPath $script:LogFile -Tail 200 |
                            Where-Object { $_ -match $pattern } | Select-Object -Last 1
                        if ($readyLine) {
                            Write-Host ("URL: " + [regex]::Match($readyLine, 'http://127\.0\.0\.1:\d+/').Value)
                        }
                    }
                    Write-Host "Log: $script:LogFile"
                }
            }
        }
    }
} catch {
    try { Write-ServiceLog ERROR $_.Exception.Message } catch { }
    [Console]::Error.WriteLine("webui-service: {0}", $_.Exception.Message)
    exit 1
}
