param(
    [Parameter(Mandatory = $true)]
    [string]$OwnerSid,
    [Parameter(Mandatory = $true)]
    [uint32]$OwnerSession
)

$ErrorActionPreference = "Stop"
$parsedSid = [System.Security.Principal.SecurityIdentifier]::new($OwnerSid)
$OwnerSid = $parsedSid.Value
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$callerSid = $identity.User.Value
$callerSession = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
if ($callerSid -eq $OwnerSid -and $callerSession -eq $OwnerSession) {
    throw "Run this probe from a different SID or logon session than the engine owner."
}

$pipeName = "WinTCP.Engine.$OwnerSid.$OwnerSession"
$pipe = [System.IO.Pipes.NamedPipeClientStream]::new(
    ".", $pipeName,
    [System.IO.Pipes.PipeDirection]::InOut,
    [System.IO.Pipes.PipeOptions]::None)

function Write-Frame([System.IO.Stream]$Pipe, [byte[]]$Payload) {
    $length = [System.BitConverter]::GetBytes([uint32]$Payload.Length)
    $Pipe.Write($length, 0, $length.Length)
    $Pipe.Write($Payload, 0, $Payload.Length)
    $Pipe.Flush()
}

function Read-ExactOrClosed([System.IO.Stream]$Pipe, [int]$Length) {
    $bytes = [byte[]]::new($Length)
    $offset = 0
    while ($offset -lt $Length) {
        $task = $Pipe.ReadAsync($bytes, $offset, $Length - $offset)
        if (-not $task.Wait(3000)) {
            throw "Owner engine did not reject the foreign client within three seconds."
        }
        try { $count = $task.GetAwaiter().GetResult() }
        catch [System.IO.IOException] { return $null }
        catch [System.ObjectDisposedException] { return $null }
        catch [System.AggregateException] {
            $cause = $_.Exception.GetBaseException()
            if ($cause -is [System.IO.IOException] -or
                $cause -is [System.ObjectDisposedException]) { return $null }
            throw $cause
        }
        if ($count -eq 0) { return $null }
        $offset += $count
    }
    return ,$bytes
}

try {
    try {
        $pipe.Connect(3000)
    } catch {
        $exception = $_.Exception
        while ($exception -ne $null) {
            if ($exception -is [System.UnauthorizedAccessException] -or
                ($exception -is [System.ComponentModel.Win32Exception] -and
                 $exception.NativeErrorCode -eq 5)) {
                Write-Output "PASS: foreign identity rejected by named-pipe ACL (Access Denied)"
                exit 0
            }
            $exception = $exception.InnerException
        }
        throw
    }

    # If the DACL allows connection, the server must still reject this SID or
    # session after reading the greeting and before issuing its nonce.
    Write-Frame $pipe ([byte[]]@(1, 0))
    $header = Read-ExactOrClosed $pipe 4
    if ($null -eq $header) {
        Write-Output "PASS: foreign identity connected but server closed before challenge"
        exit 0
    }
    $length = [System.BitConverter]::ToUInt32($header, 0)
    if ($length -lt 2 -or $length -gt 262144) {
        throw "Owner engine returned an invalid frame length: $length"
    }
    $challenge = Read-ExactOrClosed $pipe ([int]$length)
    if ($null -eq $challenge) {
        Write-Output "PASS: foreign identity connected but server closed before challenge"
        exit 0
    }
    throw "Owner engine issued a challenge to a different SID/session."
} finally {
    $pipe.Dispose()
}
