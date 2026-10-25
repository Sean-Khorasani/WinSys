param(
    [string]$Executable = (Join-Path $PSScriptRoot "..\..\build\wintcp.exe")
)

$ErrorActionPreference = "Stop"
$Executable = [System.IO.Path]::GetFullPath($Executable)
if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) {
    throw "WinTCP executable not found: $Executable"
}

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$sid = $identity.User.Value
$session = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
$pipeName = "WinTCP.Engine.$sid.$session"

function Connect-EnginePipe {
    $pipe = [System.IO.Pipes.NamedPipeClientStream]::new(
        ".", $pipeName,
        [System.IO.Pipes.PipeDirection]::InOut,
        [System.IO.Pipes.PipeOptions]::None)
    try {
        $pipe.Connect(3000)
        return $pipe
    } catch {
        $pipe.Dispose()
        throw
    }
}

function Write-Frame([System.IO.Stream]$Pipe, [byte[]]$Payload) {
    $length = [System.BitConverter]::GetBytes([uint32]$Payload.Length)
    $Pipe.Write($length, 0, $length.Length)
    $Pipe.Write($Payload, 0, $Payload.Length)
    $Pipe.Flush()
}

function Read-Exact([System.IO.Stream]$Pipe, [int]$Length) {
    $bytes = [byte[]]::new($Length)
    $offset = 0
    while ($offset -lt $Length) {
        $count = $Pipe.Read($bytes, $offset, $Length - $offset)
        if ($count -le 0) { throw "Engine closed the pipe during a framed response." }
        $offset += $count
    }
    return ,$bytes
}

function Read-Frame([System.IO.Stream]$Pipe) {
    $header = Read-Exact $Pipe 4
    $length = [System.BitConverter]::ToUInt32($header, 0)
    if ($length -lt 2 -or $length -gt 262144) {
        throw "Engine returned an invalid frame length: $length"
    }
    return ,(Read-Exact $Pipe ([int]$length))
}

function Assert-EngineResponsive([string]$Case) {
    $output = & $Executable engine status 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Engine did not remain responsive after '$Case' (exit $LASTEXITCODE): $output"
    }
    $status = ($output -join "`n") | ConvertFrom-Json
    if (-not $status.running) {
        throw "Engine status after '$Case' did not report running."
    }
    Write-Output "PASS: engine remains responsive after $Case"
}

# A bad greeting version must be rejected before a challenge is issued.
$pipe = Connect-EnginePipe
try {
    Write-Frame $pipe ([byte[]]@(2, 0))
    Start-Sleep -Milliseconds 150
} finally {
    $pipe.Dispose()
}
Assert-EngineResponsive "wrong-version greeting"

# Advertise one byte above the documented cap; no body is sent.
$pipe = Connect-EnginePipe
try {
    $header = [System.BitConverter]::GetBytes([uint32]262145)
    $pipe.Write($header, 0, $header.Length)
    $pipe.Flush()
    Start-Sleep -Milliseconds 150
} finally {
    $pipe.Dispose()
}
Assert-EngineResponsive "oversized advertised frame"

# A complete valid hello receives a per-connection nonce. A mismatched nonce
# must not dispatch the otherwise-valid status operation.
$pipe = Connect-EnginePipe
try {
    Write-Frame $pipe ([byte[]]@(1, 0))
    $challenge = Read-Frame $pipe
    if ($challenge.Length -ne 16) { throw "Unexpected challenge length: $($challenge.Length)" }
    $badRequest = [byte[]]::new(18)
    $badRequest[0] = 1
    $badRequest[1] = 1
    Write-Frame $pipe $badRequest
    Start-Sleep -Milliseconds 150
} finally {
    $pipe.Dispose()
}
Assert-EngineResponsive "mismatched connection challenge"

# A truncated body is abandoned only after the engine's bounded read timeout.
$pipe = Connect-EnginePipe
try {
    $header = [System.BitConverter]::GetBytes([uint32]2)
    $pipe.Write($header, 0, $header.Length)
    $oneByte = [byte[]]@(1)
    $pipe.Write($oneByte, 0, $oneByte.Length)
    $pipe.Flush()
    Start-Sleep -Milliseconds 3400
} finally {
    $pipe.Dispose()
}
Assert-EngineResponsive "truncated frame timeout"

Write-Output "PASS: same-session engine IPC fault checks completed; no engine state was changed."
