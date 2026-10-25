param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^http://127\.0\.0\.1:[0-9]+/?$')]
    [string]$Url
)

$ErrorActionPreference = 'Stop'
$base = $Url.TrimEnd('/')
$headers = $null
$collectorStartRequested = $false
$listener = $null
$clientProcess = $null
$failure = $null
$cleanupFailure = $null
$enginePath = Join-Path (Get-Location).Path 'build\wintcp.exe'

function Get-OwnCollectorProcesses {
    return @(Get-CimInstance Win32_Process -Filter "name = 'wintcp.exe'" |
        Where-Object {
            $_.ExecutablePath -ieq $script:enginePath -and
            $_.CommandLine -match 'collector run'
        })
}

function Wait-OwnCollectorExit([int]$TimeoutMs = 5000) {
    $deadline = [datetime]::UtcNow.AddMilliseconds($TimeoutMs)
    do {
        if ((Get-OwnCollectorProcesses).Count -eq 0) { return $true }
        Start-Sleep -Milliseconds 100
    } while ([datetime]::UtcNow -lt $deadline)
    return (Get-OwnCollectorProcesses).Count -eq 0
}

function Get-Api([string]$Path) {
    return Invoke-RestMethod -Uri ($script:base + $Path) -Headers $script:headers
}

function Invoke-EngineOperation([string]$Path, [hashtable]$Fields) {
    $Fields.requestId = [guid]::NewGuid().ToString('N')
    $body = ($Fields.GetEnumerator() | ForEach-Object {
        [System.Net.WebUtility]::UrlEncode([string]$_.Key) + '=' +
            [System.Net.WebUtility]::UrlEncode([string]$_.Value)
    }) -join '&'
    $postHeaders = @{
        'X-WinTCP-Token' = $script:headers['X-WinTCP-Token']
        Origin = $script:base
    }
    $accepted = Invoke-WebRequest -UseBasicParsing -Method Post `
        -Uri ($script:base + $Path) -Headers $postHeaders `
        -ContentType 'application/x-www-form-urlencoded' -Body $body
    if ([int]$accepted.StatusCode -ne 202) {
        throw "Operation submission failed: HTTP $([int]$accepted.StatusCode) $($accepted.Content)"
    }
    $queued = $accepted.Content | ConvertFrom-Json
    $deadline = [datetime]::UtcNow.AddSeconds(120)
    do {
        $operation = Get-Api "/api/engine/operations/$($queued.operationId)"
        if ($operation.status -in @('succeeded', 'failed')) { break }
        Start-Sleep -Milliseconds 200
    } while ([datetime]::UtcNow -lt $deadline)
    if ($operation.status -ne 'succeeded') {
        throw "Operation $($Fields.action) did not succeed: $($operation.error.code)"
    }
    return $operation.result
}

function Get-LifecyclePage([string]$Cursor) {
    $path = '/api/engine/lifecycle?limit=500'
    if ($Cursor) { $path += '&cursor=' + [uri]::EscapeDataString($Cursor) }
    return Get-Api $path
}

function Has-TestPort([object]$Event, [int]$Port) {
    return ($Event.sourceEndpoint -and $Event.sourceEndpoint.port -eq $Port) -or
        ($Event.destinationEndpoint -and $Event.destinationEndpoint.port -eq $Port)
}

try {
    $html = (Invoke-WebRequest -UseBasicParsing -Uri ($base + '/')).Content
    $token = [regex]::Match($html,
        'name="wintcp-api-token"\s+content="([a-f0-9]{64})"').Groups[1].Value
    if ($token.Length -ne 64) { throw 'Could not obtain the Web UI session token.' }
    $headers = @{ 'X-WinTCP-Token' = $token }

    $existingCollectors = @(Get-CimInstance Win32_Process -Filter "name = 'wintcp.exe'" |
        Where-Object { $_.CommandLine -match 'collector run' })
    if ($existingCollectors.Count -ne 0) {
        throw 'A WinTCP collector is already running; leaving it untouched.'
    }
    $recipes = Get-Api '/api/engine/recipes'
    if (@($recipes.items).Count -ne 0) {
        throw 'Recipe store is not empty; preserving existing recipes and aborting.'
    }
    $status = Get-Api '/api/engine'
    if (-not $status.running) { throw 'The per-user engine is not running.' }
    $initialLifecycleCount = [uint64]$status.lifecycle.persistedRecords

    $collectorStartRequested = $true
    $null = Invoke-EngineOperation '/api/collector/control' @{ action = 'start' }
    $eventsResult = Invoke-EngineOperation '/api/collector/control' @{ action = 'events-start' }
    if ($eventsResult.events.running -ne $true) {
        throw "Lifecycle trace did not start: $($eventsResult.events.traceResult)"
    }
    if ([int]$eventsResult.events.traceResult -ne 0) {
        throw "Lifecycle trace reported an ETW start error: $($eventsResult.events.traceResult)"
    }
    if (-not $eventsResult.events.clockStable -or
        [uint64]$eventsResult.events.clockMappingGeneration -lt 1 -or
        [uint64]$eventsResult.events.clockRecoveries -ne 0) {
        throw 'Initial ETW clock mapping status is missing or inconsistent.'
    }
    $traceVisible = $false
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        $engineStatus = Get-Api '/api/engine'
        if ($engineStatus.lifecycle.enabled) { $traceVisible = $true; break }
        Start-Sleep -Milliseconds 250
    }
    if (-not $traceVisible) { throw 'Engine did not observe the running lifecycle trace.' }

    # Connect the short-lived child directly to the dashboard's loopback
    # listener. The TCP/IP ETW provider is already known to report these local
    # flows, and this avoids relying on an ephemeral test listener being visible
    # to every Windows build's local-interface routing path.
    $testAddress = '127.0.0.1'
    $port = ([uri]$base).Port
    $listener = [System.Net.Sockets.TcpListener]::new(
        [System.Net.IPAddress]::Parse($testAddress), 0)
    $listener.Start()
    $sourcePort = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    $listener.Stop()
    $listener = $null

    $curlPath = (Get-Command curl.exe -ErrorAction SilentlyContinue).Source
    if (-not $curlPath) { throw 'Windows curl.exe is required for the local ETW fixture.' }
    $clientProcess = Start-Process -FilePath $curlPath `
        -ArgumentList @('--silent', '--show-error', '--max-time', '10',
            '--local-port', [string]$sourcePort, '--output', 'NUL', ($base + '/')) `
        -WindowStyle Hidden -PassThru
    $clientPid = $clientProcess.Id
    if (-not $clientProcess.WaitForExit(15000)) {
        Stop-Process -Id $clientPid -Force
        throw 'The disposable local curl client did not exit in time.'
    }
    if ($clientProcess.ExitCode -ne 0) {
        throw "The disposable local curl client failed before closing its flow (exit=$($clientProcess.ExitCode))."
    }
    $connect = $null
    $disconnect = $null
    $processExit = $null
    $testPortEvents = [System.Collections.Generic.List[string]]::new()
    $eventStopResult = Invoke-EngineOperation '/api/collector/control' @{ action = 'events-stop' }
    if ($eventStopResult.events.running -ne $false -or
        [int]$eventStopResult.events.traceResult -ne 0) {
        throw "Lifecycle trace did not stop cleanly: running=$($eventStopResult.events.running) traceResult=$($eventStopResult.events.traceResult)"
    }
    foreach ($counter in @('queueLost', 'eventsLost', 'buffersLost', 'historyEvicted')) {
        if ([uint64]$eventStopResult.events.$counter -ne 0) {
            throw "Lifecycle trace reported $counter=$($eventStopResult.events.$counter)."
        }
    }
    $stableCount = 0
    $lastCount = $initialLifecycleCount
    for ($attempt = 0; $attempt -lt 80 -and $stableCount -lt 4; $attempt++) {
        Start-Sleep -Milliseconds 250
        $latestStatus = Get-Api '/api/engine'
        $currentCount = [uint64]$latestStatus.lifecycle.persistedRecords
        if ($currentCount -eq $lastCount) { $stableCount++ }
        else { $stableCount = 0; $lastCount = $currentCount }
    }

    $cursor = ''
    for ($pageNumber = 0; $pageNumber -lt 200; $pageNumber++) {
        $page = Get-LifecyclePage $cursor
        if ($page.code) { throw "Lifecycle history query failed: $($page.code)" }
        foreach ($event in $page.items) {
            $pidValue = [uint32]$event.process.pid
            if ($testPortEvents.Count -lt 20 -and (Has-TestPort $event $sourcePort)) {
                $testPortEvents.Add("$($event.kind):$pidValue")
            }
            if ($pidValue -eq $clientPid -and $event.kind -eq 'process_exit') {
                $processExit = $event
            }
            if (-not (Has-TestPort $event $sourcePort) -or $pidValue -ne $clientPid) {
                continue
            }
            if ($event.kind -eq 'tcp_connect') { $connect = $event }
            if ($event.kind -eq 'tcp_disconnect') { $disconnect = $event }
        }
        $next = [string]$page.nextCursor
        if (@($page.items).Count -eq 0 -or -not $next -or $next -eq $cursor) { break }
        $cursor = $next
    }
    if (-not $connect) {
        throw "No TCP connect record for the exited local client was retained (pid=$clientPid sourcePort=$sourcePort observed=$($testPortEvents -join ','))."
    }
    if (-not $disconnect) {
        throw "No TCP disconnect record for the exited local client was retained (pid=$clientPid sourcePort=$sourcePort observed=$($testPortEvents -join ','))."
    }
    if (-not $processExit) {
        throw "No process-exit record for the disposable client was retained (pid=$clientPid port=$port)."
    }
    if ($connect.derived.kind -ne 'connection_established' -or
        $disconnect.derived.kind -ne 'connection_closed') {
        throw 'The raw TCP lifecycle was not normalized into established/closed history.'
    }
    if ($processExit.derived.kind -ne 'process_exited') {
        throw 'The raw process-exit record was not normalized into process history.'
    }
    foreach ($event in @($connect, $disconnect, $processExit)) {
        $mappingGeneration = [uint64]$event.clockMappingGeneration
        if ($mappingGeneration -lt 1 -or
            $event.timebaseId -notlike "*:qpc-$mappingGeneration" -or
            $event.clockMappingRecovered -isnot [bool]) {
            throw "ETW record $($event.eventId) lacks explicit clock-generation evidence."
        }
    }
    $expectedEventIds = @(
        [string]$connect.derived.eventId,
        [string]$disconnect.derived.eventId,
        [string]$processExit.derived.eventId)
    $sharedHistory = $false
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        $sharedEvents = Get-Api '/api/engine/events?limit=500'
        $retainedIds = @($sharedEvents.items | ForEach-Object { $_.eventId })
        if (@($expectedEventIds | Where-Object { $retainedIds -contains $_ }).Count -eq
            $expectedEventIds.Count) {
            $sharedHistory = $true
            break
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $sharedHistory) {
        throw 'Normalized connect, disconnect, and process-exit events did not reach shared engine history.'
    }
    $process = $connect.process
    $hasIdentityEvidence = $process.imagePath -or $process.observedImageName -or
        $process.identityReason
    if (-not $hasIdentityEvidence) {
        throw 'The retained connect record has neither identity evidence nor an explicit uncertainty reason.'
    }
    $identity = if ($process.imagePath) { 'verified_path' } else { 'explicitly_uncertain' }

    $null = Invoke-EngineOperation '/api/collector/control' @{ action = 'stop' }
    if (-not (Wait-OwnCollectorExit)) {
        throw 'Collector stop completed but the helper process is still running.'
    }
    $collectorStartRequested = $false
    Write-Output "lifecycle-exit-test=PASS pid=$clientPid rawConnect=true rawDisconnect=true rawProcessExit=true normalizedSharedHistory=true identity=$identity sourcePort=$sourcePort destinationPort=$port"
}
catch {
    $failure = $_.Exception.Message
}
finally {
    if ($clientProcess -and -not $clientProcess.HasExited) {
        Stop-Process -Id $clientProcess.Id -Force -ErrorAction SilentlyContinue
    }
    if ($headers -and $collectorStartRequested) {
        $remainingCollectors = Get-OwnCollectorProcesses
        if ($remainingCollectors.Count -gt 0) {
            try {
                $null = Invoke-EngineOperation '/api/collector/control' @{ action = 'events-stop' }
            } catch { $cleanupFailure = "events-stop cleanup failed: $($_.Exception.Message)" }
            try {
                $null = Invoke-EngineOperation '/api/collector/control' @{ action = 'stop' }
            } catch {
                $message = "collector-stop cleanup failed: $($_.Exception.Message)"
                $cleanupFailure = if ($cleanupFailure) { "$cleanupFailure; $message" } else { $message }
            }
            if (-not (Wait-OwnCollectorExit)) {
                # This test never applies a restriction and begins only when no
                # collector exists. Terminate only the exact helper it launched
                # after graceful stop has failed, letting its dynamic WFP
                # session close without touching another WinTCP process.
                foreach ($process in (Get-OwnCollectorProcesses)) {
                    Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
                }
                if (-not (Wait-OwnCollectorExit)) {
                    $message = 'Collector process remained after exact-process cleanup.'
                    $cleanupFailure = if ($cleanupFailure) { "$cleanupFailure; $message" } else { $message }
                }
            }
        }
    }
}

if ($cleanupFailure) { throw "$failure; $cleanupFailure" }
if ($failure) { throw $failure }
