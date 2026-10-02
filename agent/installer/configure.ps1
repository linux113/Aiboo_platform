# AiBoO agent - first-time settings (called by install_service.bat and run_agent.bat)
#
#  1. asks for the server address (ngrok address or http://<server IP>:4000)
#  2. optional: API key
#  3. sets endpoint_name to THIS PC's name (warns if config.ini came from another PC)
#  4. tests the connection (<server>/health)
#  5. turns on the Windows audit settings AiBoO needs
#
# Exit code 0 = OK, 1 = cancelled / failed.

$ErrorActionPreference = 'Stop'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ini = Join-Path $dir 'config.ini'
$template = Join-Path $dir 'config.template.ini'

function Line($text, $color = 'Gray') { Write-Host $text -ForegroundColor $color }

if (-not (Test-Path $ini)) {
    if (Test-Path $template) { Copy-Item $template $ini }
    else { Set-Content -Path $ini -Value "[AIBOO]`r`nremote_url =`r`napi_key = dev-key-change-in-production`r`nendpoint_name =`r`nserver_ip = 127.0.0.1`r`nlog_level = INFO`r`n" -Encoding ASCII }
}
$script:text = [IO.File]::ReadAllText($ini)

function Get-Key([string]$name) {
    $m = [regex]::Match($script:text, "(?m)^[ \t]*$name[ \t]*=[ \t]*(.*?)[ \t]*\r?$")
    if ($m.Success) { return $m.Groups[1].Value.Trim() } else { return '' }
}
function Set-Key([string]$name, [string]$value) {
    $rx = "(?m)^[ \t]*$name[ \t]*=.*?(\r?)$"
    if ([regex]::IsMatch($script:text, $rx)) {
        $script:text = [regex]::Replace($script:text, $rx, { param($m) "$name = $value" + $m.Groups[1].Value })
    } else {
        $script:text = $script:text.TrimEnd() + "`r`n$name = $value`r`n"
    }
}

Line ''
Line '=============================================' Cyan
Line '  AiBoO agent - settings' Cyan
Line '=============================================' Cyan

# ---- 1. server address -------------------------------------------------------
$url = Get-Key 'remote_url'
$placeholder = (-not $url) -or ($url -match 'your-ngrok-url|example\.com')
Line ''
if ($placeholder) {
    Line 'Type the AiBoO SERVER address (ask the person who runs the dashboard).'
} else {
    Line "Current server address: $url" Yellow
    Line 'Press ENTER to keep it, or type a new address (ngrok addresses change when ngrok restarts).'
}
Line '  Other network : https://abcd-1234.ngrok-free.dev   (the ngrok address)'
Line '  Same network  : http://192.168.1.5:4000            (server PC IP + :4000)'
while ($true) {
    $answer = (Read-Host 'Server address').Trim().TrimEnd('/')
    if (-not $answer -and -not $placeholder) { break }
    if ($answer -match '/health$') { $answer = $answer -replace '/health$', '' }
    if ($answer -match '^https?://[^\s/]+(:\d+)?$') { $url = $answer; Set-Key 'remote_url' $url; break }
    Line '  Not valid. It must start with https:// or http:// and have nothing after the address (no /health).' Red
}

# ---- 2. API key --------------------------------------------------------------
$key = Get-Key 'api_key'
if (-not $key) { $key = 'dev-key-change-in-production' }
Line ''
Line "API key now: $key"
$answer = (Read-Host 'Press ENTER to keep it, or type the key (AGENT_API_KEY from the server backend\.env)').Trim()
if ($answer) { $key = $answer }
Set-Key 'api_key' $key

# ---- 3. this PC's name -------------------------------------------------------
$pc = [System.Net.Dns]::GetHostName()
$name = Get-Key 'endpoint_name'
if ($name -and $name -ne $pc) {
    Line ''
    Line "config.ini says endpoint_name = '$name', but THIS PC is '$pc'." Yellow
    Line 'Two PCs with the same name get mixed up on the dashboard.'
    $answer = (Read-Host "Use '$pc' instead? (Y/n)").Trim()
    if ($answer -notmatch '^(n|no)$') { $name = $pc }
}
if (-not $name) { $name = $pc }
Set-Key 'endpoint_name' $name

[IO.File]::WriteAllText($ini, $script:text, (New-Object System.Text.UTF8Encoding($false)))
Line ''
Line "Saved $ini" Green
Line "  remote_url    = $url"
Line "  endpoint_name = $name"

# ---- 4. connection test ------------------------------------------------------
Line ''
Line "Testing $url/health ..."
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $r = Invoke-WebRequest -Uri "$url/health" -UseBasicParsing -TimeoutSec 15 `
         -Headers @{ 'ngrok-skip-browser-warning' = 'true' }
    if ($r.Content -match '"status"\s*:\s*"ok"') {
        Line '  OK - the AiBoO server answered.' Green
    } else {
        Line '  WARNING - something answered, but it is not the AiBoO server:' Yellow
        Line ('  ' + $r.Content.Substring(0, [Math]::Min(150, $r.Content.Length)))
        Line '  Check the address. (ngrok running on the server PC? backend running?)'
    }
} catch {
    Line "  WARNING - cannot reach the server: $($_.Exception.Message)" Yellow
    Line '  The agent will keep trying by itself. Check on the SERVER PC that the backend'
    Line '  (npm run dev) and ngrok are running, and that the address above is right.'
}

# ---- 5. Windows audit settings -------------------------------------------------
Line ''
Line 'Turning on Windows security logging (needed to see wrong passwords, new users, ...):'
# Subcategory GUIDs work on every Windows language (names are translated).
$audit = @(
    @('Logon',                      '{0CCE9215-69AE-11D9-BED3-505054503030}', $true),
    @('User Account Management',    '{0CCE9235-69AE-11D9-BED3-505054503030}', $false),
    @('Security Group Management',  '{0CCE9237-69AE-11D9-BED3-505054503030}', $false),
    @('Audit Policy Change',        '{0CCE922F-69AE-11D9-BED3-505054503030}', $false),
    @('Other Object Access Events', '{0CCE9227-69AE-11D9-BED3-505054503030}', $false)
)
foreach ($a in $audit) {
    $argList = @('/set', "/subcategory:$($a[1])", '/success:enable')
    if ($a[2]) { $argList += '/failure:enable' }
    & auditpol.exe @argList *> $null
    if ($LASTEXITCODE -eq 0) { Line "  OK  $($a[0])" Green } else { Line "  ??  $($a[0]) (could not set - run as Administrator)" Yellow }
}
Line ''
exit 0
