param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^http://127\.0\.0\.1:[0-9]+/?$')]
    [string]$Url
)

$ErrorActionPreference = 'Stop'

# Focused live acceptance check. It suspends only the exact WinTCP engine
# process launched from this checkout's build\wintcp.exe. The runtime history
# gains the deliberate coverage-gap record; no recipe or notification state is
# changed. Use the unit suite for the independent recipe/baseline assertions.

$base = $Url.TrimEnd('/')
$handle = [IntPtr]::Zero
$suspended = $false
$passed = $false
$failure = $null

try {
    $html = (Invoke-WebRequest "$base/" -UseBasicParsing).Content
    $token = [regex]::Match($html,
        'wintcp-api-token.{0,30}' + [char]34 + '([a-f0-9]{64})').Groups[1].Value
    if ($token.Length -ne 64) { throw 'Could not obtain a session token.' }
    $headers = @{ 'X-WinTCP-Token' = $token }

    $recipes = Invoke-RestMethod "$base/api/engine/recipes" -Headers $headers
    if (@($recipes.items).Count -ne 0) {
        throw 'Recipe store is not empty; preserving existing recipes and aborting.'
    }
    $notificationsBefore = Invoke-RestMethod `
        "$base/api/engine/notifications?limit=100" -Headers $headers
    $beforeNoticeIds = @($notificationsBefore.items | ForEach-Object { $_.id })
    $engine = Invoke-RestMethod "$base/api/engine" -Headers $headers
    if (-not $engine.running) { throw 'Engine is not running.' }
    $intervalMs = [uint64]$engine.snapshotIntervalMs
    if ($intervalMs -eq 0) { throw 'Engine reported an invalid snapshot interval.' }
    $collectorInventoryAvailable = $false
    try {
        $null = Invoke-RestMethod "$base/api/restrictions" -Headers $headers
        $collectorInventoryAvailable = $true
    }
    catch {
        $statusCode = 0
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        if ($statusCode -ne 503) { throw }
    }
    if ($collectorInventoryAvailable) {
        throw 'Collector is connected; stop it before pausing the engine.'
    }
    $beforeEvents = Invoke-RestMethod `
        "$base/api/engine/events?limit=500" -Headers $headers
    $beforeEventIds = @($beforeEvents.items | ForEach-Object { $_.eventId })

    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class WinTcpProcessPause {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint access, bool inherit, int processId);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr handle);
    [DllImport("ntdll.dll")]
    public static extern int NtSuspendProcess(IntPtr processHandle);
    [DllImport("ntdll.dll")]
    public static extern int NtResumeProcess(IntPtr processHandle);
}
'@
    $enginePath = Join-Path (Get-Location).Path 'build\wintcp.exe'
    $engineProcesses = @(Get-CimInstance Win32_Process `
        -Filter "name = 'wintcp.exe'" | Where-Object {
            $_.ExecutablePath -ieq $enginePath -and
            $_.CommandLine -match 'engine run'
        })
    if ($engineProcesses.Count -ne 1) {
        throw "Expected one exact engine process, found $($engineProcesses.Count)."
    }
    $enginePid = [int]$engineProcesses[0].ProcessId
    $handle = [WinTcpProcessPause]::OpenProcess(0x0800, $false, $enginePid)
    if ($handle -eq [IntPtr]::Zero) {
        throw "OpenProcess failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    $status = [WinTcpProcessPause]::NtSuspendProcess($handle)
    if ($status -ne 0) { throw ('NtSuspendProcess failed: 0x{0:X8}' -f $status) }
    $suspended = $true
    $pauseMs = [int]([math]::Max(5000.0, 5.0 * $intervalMs) + 2000.0)
    Start-Sleep -Milliseconds $pauseMs
    $status = [WinTcpProcessPause]::NtResumeProcess($handle)
    if ($status -ne 0) { throw ('NtResumeProcess failed: 0x{0:X8}' -f $status) }
    $suspended = $false

    $gap = $null
    $eventPage = $null
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        Start-Sleep -Milliseconds 250
        $eventPage = Invoke-RestMethod `
            "$base/api/engine/events?limit=500" -Headers $headers
        $gap = @($eventPage.items | Where-Object {
            $_.source -eq 'snapshot' -and $_.lossReason -eq 'sampling_gap' -and
            $beforeEventIds -notcontains $_.eventId
        } | Select-Object -Last 1)
        if ($gap.Count -gt 0) { break }
    }
    if (@($gap).Count -eq 0) {
        throw 'No new sampling_gap record was retained after the engine pause.'
    }
    $gapNs = [uint64]$gap[0].monotonicNs
    $postGapBaseline = @($eventPage.items | Where-Object {
        $_.source -eq 'snapshot' -and $_.kind -eq 'endpoint_observed' -and
        $_.firstObservedMidSession -and [uint64]$_.monotonicNs -ge $gapNs
    })
    $notificationsAfter = Invoke-RestMethod `
        "$base/api/engine/notifications?limit=100" -Headers $headers
    $afterNoticeIds = @($notificationsAfter.items | ForEach-Object { $_.id })
    $newNoticeIds = @($afterNoticeIds | Where-Object { $beforeNoticeIds -notcontains $_ })
    if ($postGapBaseline.Count -eq 0) {
        throw 'No first post-gap endpoint was labeled as a non-alerting baseline.'
    }
    if ($newNoticeIds.Count -ne 0) {
        throw 'Notification inbox changed during a test with no recipes configured.'
    }
    $passed = $true
    Write-Output "runtime-pause-test=PASS gap=$($gap[0].eventId) postGapBaseline=$($postGapBaseline.Count) notificationsUnchanged=$($afterNoticeIds.Count)"
}
catch {
    $failure = $_.Exception.Message
}
finally {
    if ($suspended -and $handle -ne [IntPtr]::Zero) {
        [void][WinTcpProcessPause]::NtResumeProcess($handle)
    }
    if ($handle -ne [IntPtr]::Zero) {
        [void][WinTcpProcessPause]::CloseHandle($handle)
    }
}

if (-not $passed) {
    if ($failure) { Write-Output "runtime-pause-test=FAIL $failure" }
    exit 1
}
