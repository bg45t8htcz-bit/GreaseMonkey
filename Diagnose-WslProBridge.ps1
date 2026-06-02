#Requires -Version 5.1
<#
.SYNOPSIS
    Diagnoses why the Ubuntu Pro WSL bridge (wsl-pro-service) cannot reach the
    Windows-side Ubuntu Pro agent.

    It reports, and then gives a verdict on, the exact failing layer:
      * agent not listening (not running / wrong port)
      * agent bound to loopback only (unreachable from WSL in NAT mode)
      * Windows Defender Public-profile firewall dropping inbound on vEthernet (WSL)
      * Hyper-V firewall dropping inbound (mirrored networking mode)
      * connectivity is actually fine (just needs a service restart)

.DESCRIPTION
    READ-ONLY. The script changes nothing. It prints ready-to-run fix commands
    at the end so you (or your endpoint team) can apply the right one.

    Key signal it relies on:  a TCP *timeout* means packets are silently dropped
    (firewall);  a *refused* means the host is reachable but nothing is listening
    on that address/port (binding problem).

.PARAMETER Port
    Override the agent port. If omitted, it is read from %USERPROFILE%\.ubuntupro\.address.

.PARAMETER Distro
    Override the WSL distro name. If omitted, the default distro is used.

.NOTES
    Run in an ELEVATED PowerShell on the Windows host (Run as Administrator).
    Example:  powershell -ExecutionPolicy Bypass -File .\Diagnose-WslProBridge.ps1
#>

[CmdletBinding()]
param(
    [int]$Port,
    [string]$Distro,
    [string]$AgentProcessHint = "ubuntu-pro-agent"
)

$ErrorActionPreference = 'Continue'
$env:WSL_UTF8 = 1   # makes wsl.exe emit UTF-8 instead of UTF-16 (easier to parse)

function Write-Section($t) { Write-Host ""; Write-Host ("==== {0} " -f $t).PadRight(70,'=') -ForegroundColor Cyan }
function Write-OK($t)    { Write-Host "  [OK]   $t"   -ForegroundColor Green }
function Write-Bad($t)   { Write-Host "  [FAIL] $t"   -ForegroundColor Red }
function Write-Info($t)  { Write-Host "  [info] $t"   -ForegroundColor Gray }

# --- Raw TCP connect test that distinguishes timeout from refused -------------
function Test-Tcp {
    param([string]$TargetHost, [int]$TargetPort, [int]$TimeoutMs = 4000)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($TargetHost, $TargetPort, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            try { $client.EndConnect($iar); return [pscustomobject]@{ State='CONNECTED'; Detail='connected' } }
            catch { return [pscustomobject]@{ State='REFUSED'; Detail=$_.Exception.GetBaseException().Message } }
        }
        return [pscustomobject]@{ State='TIMEOUT'; Detail='no response within timeout (typical of a firewall drop)' }
    }
    catch { return [pscustomobject]@{ State='ERROR'; Detail=$_.Exception.GetBaseException().Message } }
    finally { $client.Close() }
}

function Invoke-Wsl([string]$Cmd) {
    $args = @()
    if ($Distro) { $args += @('-d', $Distro) }
    $args += @('--', 'bash', '-lc', $Cmd)
    try { (& wsl.exe @args) 2>$null } catch { $null }
}

Write-Host "Ubuntu Pro WSL bridge diagnostics" -ForegroundColor Yellow
Write-Host ("Run time: {0}" -f (Get-Date))

# =============================================================================
Write-Section "1. Networking mode"
$wslconfig = Join-Path $env:USERPROFILE ".wslconfig"
$mode = "nat (default)"
if (Test-Path $wslconfig) {
    $m = Select-String -Path $wslconfig -Pattern 'networkingMode\s*=\s*(\w+)' -ErrorAction SilentlyContinue
    if ($m) { $mode = $m.Matches[0].Groups[1].Value.ToLower() }
}
$mirrored = $mode -eq 'mirrored'
Write-Info "WSL networking mode: $mode"
if ($mirrored) { Write-Info "Mirrored mode: WSL should reach the host via 127.0.0.1; Hyper-V firewall applies." }
else           { Write-Info "NAT mode: WSL reaches the host via the gateway IP; the vEthernet (WSL) adapter's firewall profile applies." }

# =============================================================================
Write-Section "2. Agent port"
$addrFile = Join-Path $env:USERPROFILE ".ubuntupro\.address"
$addrRaw  = $null
if (-not $Port) {
    if (Test-Path $addrFile) {
        $addrRaw = (Get-Content -Raw -Path $addrFile).Trim()
        Write-Info "Address file: $addrFile"
        Write-Info "Address file contents: '$addrRaw'"
        if ($addrRaw -match ':(\d+)\s*$') { $Port = [int]$Matches[1] }
    } else {
        Write-Bad "Address file not found: $addrFile"
        Write-Info "The Windows agent has not written its address. It is probably not running."
    }
}
if (-not $Port) {
    $Port = 53618
    Write-Info "Falling back to port $Port. Pass -Port <n> to override."
} else {
    Write-OK "Using agent port: $Port"
}

# =============================================================================
Write-Section "3. Is the agent listening, and on what address?"
$listeners = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
$bindScope = 'none'
if ($listeners) {
    foreach ($l in $listeners) {
        $proc = $null
        try { $proc = (Get-Process -Id $l.OwningProcess -ErrorAction Stop).ProcessName } catch {}
        Write-OK ("Listening on {0}:{1}  (pid {2} / {3})" -f $l.LocalAddress, $l.LocalPort, $l.OwningProcess, $proc)
    }
    $addrs = $listeners.LocalAddress
    if ($addrs -contains '0.0.0.0' -or $addrs -contains '::') { $bindScope = 'all' }
    elseif (($addrs | Where-Object { $_ -notin @('127.0.0.1','::1') }).Count -gt 0) { $bindScope = 'specific' }
    else { $bindScope = 'loopback' }
    Write-Info "Bind scope: $bindScope"
} else {
    Write-Bad "Nothing is listening on port $Port."
}

# =============================================================================
Write-Section "4. Host address WSL uses + WSL service state"
$gateway = (Invoke-Wsl "ip route show default 2>/dev/null | awk '{print `$3; exit}'") | Select-Object -First 1
if (-not $gateway) { $gateway = (Invoke-Wsl "grep -m1 nameserver /etc/resolv.conf 2>/dev/null | awk '{print `$2}'") | Select-Object -First 1 }
if ($gateway) { Write-Info "Gateway/host IP as seen from WSL: $gateway" }
else          { Write-Bad "Could not determine the host IP from inside WSL (is the distro running?)" }

$svc = (Invoke-Wsl "systemctl is-active wsl-pro.service 2>/dev/null") | Select-Object -First 1
if ($svc) { Write-Info "wsl-pro.service state: $svc" }

# =============================================================================
Write-Section "5. Reachability tests"
$loop = Test-Tcp -TargetHost '127.0.0.1' -TargetPort $Port
if ($loop.State -eq 'CONNECTED') { Write-OK "Windows -> 127.0.0.1:$Port  : $($loop.State)" }
else { Write-Bad "Windows -> 127.0.0.1:$Port  : $($loop.State) ($($loop.Detail))" }

$gwTest = $null
if ($gateway) {
    $gwTest = Test-Tcp -TargetHost $gateway -TargetPort $Port
    if ($gwTest.State -eq 'CONNECTED') { Write-OK "Windows -> ${gateway}:$Port  : $($gwTest.State)" }
    else { Write-Bad "Windows -> ${gateway}:$Port  : $($gwTest.State) ($($gwTest.Detail))" }
}

# Decisive test: from inside the WSL VM itself
$wslTest = $null
$target = if ($mirrored) { '127.0.0.1' } else { $gateway }
if ($target) {
    $probe = "if timeout 5 bash -c 'exec 3<>/dev/tcp/$target/$Port' 2>/dev/null; then echo CONNECTED; else rc=`$?; if [ `$rc -eq 124 ]; then echo TIMEOUT; else echo REFUSED; fi; fi"
    $wslTest = (Invoke-Wsl $probe | Select-Object -First 1)
    if ($wslTest -eq 'CONNECTED') { Write-OK "WSL -> ${target}:$Port  : $wslTest  (decisive)" }
    elseif ($wslTest) { Write-Bad "WSL -> ${target}:$Port  : $wslTest  (decisive)" }
    else { Write-Info "WSL-origin test produced no output (distro not running?)" }
}

# =============================================================================
Write-Section "6. Firewall state on the WSL interface"
$wslAdapter = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -like 'vEthernet (WSL*' -or $_.InterfaceDescription -like '*WSL*'
} | Select-Object -First 1
$wslAlias = $null
if ($wslAdapter) {
    $wslAlias = $wslAdapter.Name
    Write-Info "WSL adapter: $wslAlias"
    $profile = Get-NetConnectionProfile -InterfaceIndex $wslAdapter.ifIndex -ErrorAction SilentlyContinue
    if ($profile) {
        Write-Info "Network category: $($profile.NetworkCategory)"
        $fp = Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $profile.NetworkCategory }
        if ($fp) { Write-Info "Profile '$($fp.Name)': Enabled=$($fp.Enabled), DefaultInboundAction=$($fp.DefaultInboundAction)" }
    }
} else {
    Write-Info "No vEthernet (WSL) adapter found (expected in mirrored mode)."
}

# Any inbound allow rule already covering this port?
$portRuleExists = $false
try {
    $allow = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue
    foreach ($r in $allow) {
        $pf = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
        if ($pf -and ($pf.LocalPort -eq "$Port" -or $pf.LocalPort -contains "$Port")) { $portRuleExists = $true; break }
    }
} catch {}
if ($portRuleExists) { Write-Info "An inbound ALLOW rule already covers port $Port." }

# Hyper-V firewall (mirrored mode)
$hvDefault = $null
try {
    $hv = Get-NetFirewallHyperVVMSetting -PolicyStore ActiveStore -ErrorAction Stop
    if ($hv) { $hvDefault = ($hv | Select-Object -First 1).DefaultInboundAction; Write-Info "Hyper-V firewall DefaultInboundAction: $hvDefault" }
} catch { Write-Info "Hyper-V firewall settings not present on this build." }

# =============================================================================
Write-Section "VERDICT"
$wslGuid = '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}'   # well-known WSL VMCreatorId

if ($bindScope -eq 'none') {
    Write-Bad "The Windows Ubuntu Pro agent is NOT listening on port $Port."
    Write-Host "  Fix: start/repair the agent. Check it is installed and running, then re-run this script." -ForegroundColor Yellow
    Write-Host "       (Look for the 'ubuntu-pro-agent' / Ubuntu Pro background process; reinstall UP4W if absent.)" -ForegroundColor Yellow
}
elseif ($bindScope -eq 'loopback') {
    Write-Bad "The agent is bound to LOOPBACK only (127.0.0.1 / ::1)."
    if ($mirrored) {
        Write-Host "  In mirrored mode WSL reaches 127.0.0.1 directly, so check the Hyper-V firewall below." -ForegroundColor Yellow
    } else {
        Write-Host "  In NAT mode WSL cannot reach a loopback-only listener on ANY host IP." -ForegroundColor Yellow
        Write-Host "  Best fix: switch to mirrored networking so 127.0.0.1 works from WSL. Add to $wslconfig :" -ForegroundColor Yellow
        Write-Host "      [wsl2]" -ForegroundColor White
        Write-Host "      networkingMode=mirrored" -ForegroundColor White
        Write-Host "  then run:  wsl --shutdown   (and re-open the distro)" -ForegroundColor White
    }
}
elseif ($wslTest -eq 'CONNECTED') {
    Write-OK "Connectivity is fine right now - the bridge can reach the agent."
    Write-Host "  If the service still shows errors, just restart it inside WSL:" -ForegroundColor Yellow
    Write-Host "      sudo systemctl restart wsl-pro.service" -ForegroundColor White
}
elseif ($wslTest -eq 'TIMEOUT' -or ($gwTest -and $gwTest.State -eq 'TIMEOUT')) {
    Write-Bad "A FIREWALL is silently dropping inbound traffic to the agent (timeout, not refused)."
    if ($mirrored) {
        Write-Host "  Mirrored mode -> this is the Hyper-V firewall. Run (elevated):" -ForegroundColor Yellow
        Write-Host "      New-NetFirewallHyperVRule -Name 'WSLProBridge' -DisplayName 'Allow WSL Pro bridge' ``" -ForegroundColor White
        Write-Host "        -Direction Inbound -Action Allow -VMCreatorId '$wslGuid' -Protocol TCP -LocalPorts $Port" -ForegroundColor White
        Write-Host "  (Broader option:  Set-NetFirewallHyperVVMSetting -Name '$wslGuid' -DefaultInboundAction Allow )" -ForegroundColor White
    } else {
        $alias = if ($wslAlias) { $wslAlias } else { 'vEthernet (WSL)' }
        Write-Host "  NAT mode -> the vEthernet (WSL) adapter is in the Public profile, which blocks inbound." -ForegroundColor Yellow
        Write-Host "  Least-privilege fix (elevated), scoped to this port + interface:" -ForegroundColor Yellow
        Write-Host "      New-NetFirewallRule -DisplayName 'Allow WSL Pro bridge inbound' -Direction Inbound ``" -ForegroundColor White
        Write-Host "        -Action Allow -Protocol TCP -LocalPort $Port -InterfaceAlias `"$alias`"" -ForegroundColor White
        Write-Host "  Broader fallback (whole WSL interface):" -ForegroundColor Yellow
        Write-Host "      New-NetFirewallRule -DisplayName 'Allow WSL inbound' -Direction Inbound -Action Allow -InterfaceAlias `"$alias`"" -ForegroundColor White
    }
    Write-Host "  NOTE: on a managed VDI this rule may be reverted by GPO or by endpoint security" -ForegroundColor DarkYellow
    Write-Host "        (Qualys/Proofpoint/etc.). If it does not stick, raise it with your endpoint team." -ForegroundColor DarkYellow
}
elseif ($wslTest -eq 'REFUSED' -or ($gwTest -and $gwTest.State -eq 'REFUSED')) {
    Write-Bad "Connection REFUSED - host is reachable but not listening on this address/port."
    Write-Host "  The agent is likely bound to an address WSL is not dialing, or the port is wrong." -ForegroundColor Yellow
    Write-Host "  Re-check section 3 (bind address) vs the address file in section 2, and confirm the port." -ForegroundColor Yellow
}
else {
    Write-Info "Inconclusive. Make sure the distro is running, then re-run. Most useful line above is the 'WSL -> ...' decisive test."
}

Write-Host ""
Write-Host "Done." -ForegroundColor Yellow
