param(
    [string]$ServerUrl = "http://192.168.1.100:8001",
    [int]$Interval = 15,
    [int]$MaxRetries = 5,
    [string]$AuthToken = "",
    [switch]$UseTls,
    [switch]$Debug
)

# ── AiBoO Remote Log Sender ──────────────────────────────────
# Copy this script to any Windows PC on your network and run:
#   powershell -File remote-log-sender.ps1 -ServerUrl "http://192.168.1.100:8001"
#
# It tails Windows Security events and forwards them to your
# AiBoO dashboard in real time.
# ─────────────────────────────────────────────────────────────

# Global buffer for offline event caching
$script:EventBuffer = [System.Collections.ArrayList]::new()
$script:AuditLog = "$env:TEMP\aiboo_sender_audit.csv"
$script:Running = $true

# Register graceful shutdown handler
Register-ObjectEvent -InputObject ([Console]) -EventName CancelKeyPress -Action {
    $script:Running = $false
    Write-Host "`nShutting down gracefully..." -ForegroundColor Yellow
} | Out-Null

# Resolve API URL
$baseUrl = $ServerUrl.TrimEnd('/')
if ($UseTls) {
    $baseUrl = $baseUrl -replace '^http:', 'https:'
}
$api = "$baseUrl/events"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  AiBoO Remote Log Sender" -ForegroundColor Cyan
Write-Host "  Forwarding logs from $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "  -> $api" -ForegroundColor Cyan
Write-Host "  Interval: ${Interval}s" -ForegroundColor Cyan
if ($AuthToken) { Write-Host "  Auth: enabled" -ForegroundColor Cyan }
if ($UseTls) { Write-Host "  TLS: enabled" -ForegroundColor Cyan }
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Track last seen event by SequenceNumber to avoid duplicates
$lastSequenceNumber = -1

# Event IDs: 4625=failed logon, 4624=success logon, 4672=admin logon,
# 4648=logon with explicit creds, 4688=process created, 5156=connection,
# 5140=share accessed, 5145=share checked
$eventIds = @(4625, 4624, 4672, 4648, 4688, 5156, 5157, 5140, 5145)

function Write-DebugLog {
    param([string]$Message)
    if ($Debug) {
        Write-Host "  [DEBUG] $Message" -ForegroundColor DarkGray
    }
}

function Write-Audit {
    param([string]$EventId, [string]$Status)
    try {
        $line = "$(Get-Date -Format 'o'),$env:COMPUTERNAME,$EventId,$Status"
        Add-Content -Path $script:AuditLog -Value $line -ErrorAction Stop
    } catch {
        Write-DebugLog "Failed to write audit: $_"
    }
}

function Send-Event {
    param(
        $event,
        [string]$eventType,
        [string]$severity,
        [string]$user
    )

    $message = ""
    if ($event.Message) {
        $message = $event.Message.Substring(0, [Math]::Min(300, $event.Message.Length))
    }

    $body = @{
        timestamp  = $event.TimeCreated.ToString("o")
        source     = "$env:COMPUTERNAME"
        event_type = $eventType
        message    = $message
        severity   = $severity
        payload    = @{
            event_id  = $event.Id
            sequence  = $event.RecordId
            user_id   = $user
            computer  = $env:COMPUTERNAME
            log_name  = $event.LogName
        }
    } | ConvertTo-Json -Compress

    $headers = @{ "Content-Type" = "application/json" }
    if ($AuthToken) {
        $headers["Authorization"] = "Bearer $AuthToken"
    }

    $retries = 0
    $delay = 1
    while ($retries -lt $MaxRetries) {
        try {
            $params = @{
                Uri         = $api
                Method      = "Post"
                Body        = $body
                Headers     = $headers
                ContentType = "application/json"
                TimeoutSec  = 10
            }
            $null = Invoke-RestMethod @params
            Write-Host "  [$((Get-Date).ToString('HH:mm:ss'))] $($event.Id) $eventType - $user" -ForegroundColor Green
            Write-Audit -EventId $event.Id -Status "sent"
            return $true
        } catch {
            $retries++
            if ($retries -lt $MaxRetries) {
                Write-Host "  [!] Retry $retries/$MaxRetries in ${delay}s..." -ForegroundColor DarkYellow
                Start-Sleep -Seconds $delay
                $delay = [Math]::Min($delay * 2, 30)
            } else {
                Write-Host "  [FAIL] $($event.Id) $eventType - $user (queued)" -ForegroundColor Red
                $null = $script:EventBuffer.Add(@{
                    body     = $body
                    eventId  = $event.Id
                    eventType = $eventType
                    user     = $user
                    timestamp = $event.TimeCreated
                })
                Write-Audit -EventId $event.Id -Status "buffered"
                return $false
            }
        }
    }
}

function Flush-Buffer {
    $flushed = @()
    foreach ($item in $script:EventBuffer) {
        $retries = 0
        $delay = 1
        while ($retries -lt $MaxRetries) {
            try {
                $headers = @{ "Content-Type" = "application/json" }
                if ($AuthToken) {
                    $headers["Authorization"] = "Bearer $AuthToken"
                }
                $null = Invoke-RestMethod -Uri $api -Method Post -Body $item.body -Headers $headers -ContentType "application/json" -TimeoutSec 10
                Write-Host "  [FLUSH] $($item.eventId) $($item.eventType) - $($item.user)" -ForegroundColor Green
                $flushed += $item
                Write-Audit -EventId $item.eventId -Status "flushed"
                break
            } catch {
                $retries++
                if ($retries -lt $MaxRetries) {
                    Start-Sleep -Seconds $delay
                    $delay = [Math]::Min($delay * 2, 10)
                }
            }
        }
    }
    foreach ($item in $flushed) {
        $script:EventBuffer.Remove($item)
    }
    if ($flushed.Count -gt 0) {
        Write-Host "  [BUFFER] Flushed $($flushed.Count) queued events" -ForegroundColor Cyan
    }
}

while ($script:Running) {
    try {
        # Flush any buffered events first
        if ($script:EventBuffer.Count -gt 0) {
            Flush-Buffer
        }

        # Calculate StartTime window: look back 2 intervals to catch missed events
        $startTime = (Get-Date).AddSeconds(-$Interval * 2)

        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = $eventIds
            StartTime = $startTime
        } -ErrorAction Stop | Sort-Object TimeCreated, RecordId

        foreach ($ev in $events) {
            # Deduplicate using SequenceNumber (RecordId)
            if ($ev.RecordId -le $lastSequenceNumber) { continue }

            $userId = "unknown"
            $severity = "medium"
            $eventType = "unknown"

            switch ($ev.Id) {
                4625 {
                    $eventType = "failed_logon"
                    $severity = "high"
                    if ($ev.Properties.Count -gt 5 -and $ev.Properties[5]) { $userId = $ev.Properties[5].Value.ToString() }
                }
                4624 {
                    $eventType = "logon_success"
                    $severity = "low"
                    if ($ev.Properties.Count -gt 5 -and $ev.Properties[5]) { $userId = $ev.Properties[5].Value.ToString() }
                }
                4672 {
                    $eventType = "privilege_use"
                    $severity = "medium"
                    if ($ev.Properties.Count -gt 1 -and $ev.Properties[1]) { $userId = $ev.Properties[1].Value.ToString() }
                }
                4648 {
                    $eventType = "explicit_credential"
                    $severity = "medium"
                    if ($ev.Properties.Count -gt 5 -and $ev.Properties[5]) { $userId = $ev.Properties[5].Value.ToString() }
                }
                4688 {
                    $eventType = "process_created"
                    $severity = "low"
                    if ($ev.Properties.Count -gt 1 -and $ev.Properties[1]) { $userId = $ev.Properties[1].Value.ToString() }
                }
                5156 {
                    $eventType = "connection_allowed"
                    $severity = "low"
                }
                5157 {
                    $eventType = "connection_denied"
                    $severity = "medium"
                }
                5140 {
                    $eventType = "share_accessed"
                    $severity = "medium"
                    if ($ev.Properties.Count -gt 4 -and $ev.Properties[4]) { $userId = $ev.Properties[4].Value.ToString() }
                }
                5145 {
                    $eventType = "share_access_checked"
                    $severity = "medium"
                    if ($ev.Properties.Count -gt 4 -and $ev.Properties[4]) { $userId = $ev.Properties[4].Value.ToString() }
                }
            }

            if ($eventType -ne "unknown") {
                Send-Event -event $ev -eventType $eventType -severity $severity -user $userId
                $lastSequenceNumber = $ev.RecordId
            }
        }
    } catch [Exception] {
        Write-Host "  [!] Error reading events: $_" -ForegroundColor DarkYellow
        Write-DebugLog "StackTrace: $($_.ScriptStackTrace)"
    }

    if (-not $script:Running) { break }
    Start-Sleep -Seconds $Interval
}

Write-Host "Remote log sender stopped." -ForegroundColor Yellow
