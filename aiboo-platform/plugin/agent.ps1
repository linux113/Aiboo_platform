param(
    [string]$ConfigPath = "$PSScriptRoot\config.txt",
    [string]$AuthToken = "",
    [switch]$Debug
)

# ── AiBoO Plugin Agent ─────────────────────────────────────
# Runs as a scheduled task. Reads the server IP from config.txt,
# fetches recent Security events, and forwards them to the dashboard.
# ──────────────────────────────────────────────────────────

$script:RetryQueue = [System.Collections.ArrayList]::new()
$script:SeenRecordIds = [System.Collections.Generic.HashSet[long]]::new()
$script:MaxBatchRecords = 50

function Write-Dbg {
    param([string]$Message)
    if ($Debug) {
        Write-Host "[DEBUG] $Message" -ForegroundColor DarkGray
    }
}

if (!(Test-Path $ConfigPath)) {
    Write-Dbg "Config not found at $ConfigPath"
    exit 0
}

$raw = Get-Content $ConfigPath -First 1
if (-not $raw) { Write-Warning "Empty config at $ConfigPath"; exit 0 }
$server = $raw.Trim()

# Validate IP: each octet 0-255, exactly 4 octets
if (!($server -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')) {
    Write-Dbg "Invalid IP format: $server"
    exit 0
}

# Bounds check each octet
$valid = $true
foreach ($octet in $Matches[1..4]) {
    $octetVal = [int]$octet
    if ($octetVal -lt 0 -or $octetVal -gt 255) { $valid = $false; break }
}
if (-not $valid) {
    Write-Dbg "IP octets out of range: $server"
    exit 0
}

# Read auth token from second line of config if present
$authToken = $AuthToken
if (-not $authToken) {
    $secondLine = Get-Content $ConfigPath -TotalCount 2 | Select-Object -Skip 1
    if ($secondLine) { $authToken = $secondLine.Trim() }
}

$api = "http://${server}:8001/events"
$runFile = "$env:TEMP\aiboo_plugin_running.txt"
$auditFile = "$env:TEMP\aiboo_plugin_audit.csv"

# Prevent overlapping runs
if (Test-Path $runFile) {
    $lastRun = (Get-Item $runFile).LastWriteTime
    if (((Get-Date) - $lastRun).TotalMinutes -lt 2) {
        Write-Dbg "Skipping - last run was less than 2 minutes ago"
        exit 0
    }
}
try {
    [System.IO.File]::WriteAllText($runFile, (Get-Date).ToString('o'))
} catch {
    Write-Dbg "Failed to write run file: $_"
}

# Flush retry queue from previous runs
$retryFile = "$env:TEMP\aiboo_plugin_retry.json"
if (Test-Path $retryFile) {
    try {
        $saved = Get-Content $retryFile -Raw | ConvertFrom-Json
        foreach ($item in $saved) {
            $null = $script:RetryQueue.Add($item)
        }
        Remove-Item $retryFile -Force -ErrorAction SilentlyContinue
        Write-Dbg "Loaded $($saved.Count) events from retry queue"
    } catch {
        Write-Dbg "Failed to load retry queue: $_"
    }
}

# Process retry queue first
$flushed = @()
foreach ($item in $script:RetryQueue) {
    try {
        $body = $item.body
        $headers = @{ "Content-Type" = "application/json" }
        if ($authToken) { $headers["Authorization"] = "Bearer $authToken" }
        $null = Invoke-RestMethod -Uri $api -Method Post -Body $body -Headers $headers -ContentType 'application/json' -TimeoutSec 5
        $flushed += $item
        Write-Dbg "Retry success: $($item.eventId)"
    } catch {
        Write-Dbg "Retry failed: $($item.eventId) - $_"
    }
}
foreach ($item in $flushed) { $script:RetryQueue.Remove($item) }

try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName='Security'; Id=4625,4624,4672,4648,4688,5156,5157,5140,5145
    } -MaxEvents $script:MaxBatchRecords -ErrorAction Stop
} catch {
    Write-Dbg "Failed to read events: $_"
    exit 0
}

foreach ($e in $events) {
    # Deduplicate by EventRecordId
    if ($script:SeenRecordIds.Contains($e.RecordId)) {
        Write-Dbg "Skipping duplicate RecordId: $($e.RecordId)"
        continue
    }

    $t = 'unknown'; $s = 'medium'; $u = 'unknown'; $msg = $null

    switch ($e.Id) {
        4625 {
            $t = 'failed_logon'; $s = 'high'
            if ($e.Properties.Count -gt 5 -and $e.Properties[5]) { $u = $e.Properties[5].Value.ToString() }
            $msg = "Failed logon attempt from user $u"
        }
        4624 {
            $t = 'logon_success'; $s = 'low'
            if ($e.Properties.Count -gt 5 -and $e.Properties[5]) { $u = $e.Properties[5].Value.ToString() }
            $msg = "Successful logon: $u"
        }
        4672 {
            $t = 'privilege_use'; $s = 'medium'
            if ($e.Properties.Count -gt 1 -and $e.Properties[1]) { $u = $e.Properties[1].Value.ToString() }
            $msg = "Special privilege assigned to $u"
        }
        4648 {
            $t = 'explicit_credential'; $s = 'medium'
            if ($e.Properties.Count -gt 5 -and $e.Properties[5]) { $u = $e.Properties[5].Value.ToString() }
            $msg = "Explicit credential use: $u"
        }
        4688 {
            $t = 'process_created'; $s = 'low'
            if ($e.Properties.Count -gt 1 -and $e.Properties[1]) { $u = $e.Properties[1].Value.ToString() }
            $msg = "New process created: $u"
        }
        5156 {
            $t = 'connection_allowed'; $s = 'low'
            $destIp = if ($e.Properties.Count -gt 3 -and $e.Properties[3]) { $e.Properties[3].Value } else { "unknown" }
            $destPort = if ($e.Properties.Count -gt 5 -and $e.Properties[5]) { $e.Properties[5].Value } else { "unknown" }
            $msg = "Connection allowed to ${destIp}:${destPort}"
        }
        5157 {
            $t = 'connection_denied'; $s = 'medium'
            $destIp = if ($e.Properties.Count -gt 3 -and $e.Properties[3]) { $e.Properties[3].Value } else { "unknown" }
            $destPort = if ($e.Properties.Count -gt 5 -and $e.Properties[5]) { $e.Properties[5].Value } else { "unknown" }
            $msg = "Connection blocked to ${destIp}:${destPort}"
        }
        5140 {
            $t = 'share_accessed'; $s = 'medium'
            if ($e.Properties.Count -gt 4 -and $e.Properties[4]) { $u = $e.Properties[4].Value.ToString() }
            $shareName = if ($e.Properties.Count -gt 6 -and $e.Properties[6]) { $e.Properties[6].Value } else { "unknown" }
            $msg = "Share accessed: ${shareName} by $u"
        }
        5145 {
            $t = 'share_access_checked'; $s = 'medium'
            if ($e.Properties.Count -gt 4 -and $e.Properties[4]) { $u = $e.Properties[4].Value.ToString() }
            $shareName = if ($e.Properties.Count -gt 6 -and $e.Properties[6]) { $e.Properties[6].Value } else { "unknown" }
            $msg = "Share access checked: ${shareName} by $u"
        }
    }

    if ($t -eq 'unknown') { continue }

    if (-not $msg) {
        if ($e.Message) {
            $msg = $e.Message.Substring(0, [Math]::Min(200, $e.Message.Length))
        } else {
            $msg = "Event $($e.Id) with no message"
        }
    }

    $body = @{
        timestamp  = $e.TimeCreated.ToString('o')
        source     = $env:COMPUTERNAME
        event_type = $t
        message    = $msg
        severity   = $s
        payload    = @{
            event_id = $e.Id
            sequence = $e.RecordId
            user_id  = $u
            computer = $env:COMPUTERNAME
        }
    } | ConvertTo-Json -Compress

    try {
        $headers = @{ "Content-Type" = "application/json" }
        if ($authToken) { $headers["Authorization"] = "Bearer $authToken" }
        $null = Invoke-RestMethod -Uri $api -Method Post -Body $body -Headers $headers -ContentType 'application/json' -TimeoutSec 5
        $null = $script:SeenRecordIds.Add($e.RecordId)
        Write-Dbg "Sent: $($e.Id) $t - $u"
        # Append to audit trail
        try {
            $auditLine = "$(Get-Date -Format 'o'),$($e.RecordId),$($e.Id),$t,sent"
            Add-Content -Path $auditFile -Value $auditLine -ErrorAction SilentlyContinue
        } catch {}
    } catch {
        Write-Dbg "Send failed for $($e.Id): $_"
        $null = $script:RetryQueue.Add(@{
            body = $body
            eventId = $e.Id
            recordId = $e.RecordId
        })
        try {
            $auditLine = "$(Get-Date -Format 'o'),$($e.RecordId),$($e.Id),$t,buffered"
            Add-Content -Path $auditFile -Value $auditLine -ErrorAction SilentlyContinue
        } catch {}
    }
}

# Save retry queue for next run
if ($script:RetryQueue.Count -gt 0) {
    try {
        $queueJson = $script:RetryQueue | ConvertTo-Json -Compress
        [System.IO.File]::WriteAllText($retryFile, $queueJson)
        Write-Dbg "Saved $($script:RetryQueue.Count) events to retry queue"
    } catch {
        Write-Dbg "Failed to save retry queue: $_"
    }
}
