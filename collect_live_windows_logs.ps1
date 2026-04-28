<#
Jigsaw XDR+ OmniParser live/offline collector
Author: Kennedy Aikohi
Purpose: Export local Windows Event Logs into offline EVTX artefacts, then parse them with Jigsaw.
Run PowerShell as Administrator for Security.evtx access.
#>
param(
  [string]$OutDir = ".\jigsaw-live-logs",
  [switch]$RunHunt
)
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$logs = @(
  "Security",
  "System",
  "Application",
  "Windows PowerShell",
  "Microsoft-Windows-PowerShell/Operational",
  "Microsoft-Windows-Sysmon/Operational",
  "Microsoft-Windows-TaskScheduler/Operational",
  "Microsoft-Windows-WMI-Activity/Operational",
  "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
  "Microsoft-Windows-Defender/Operational"
)
foreach ($log in $logs) {
  $safe = ($log -replace '[\\/]', '-') + ".evtx"
  $dest = Join-Path $OutDir $safe
  try {
    wevtutil epl $log $dest /ow:true
    Write-Host "[+] Exported $log -> $dest"
  } catch {
    Write-Warning "Could not export $log : $($_.Exception.Message)"
  }
}
if ($RunHunt) {
  New-Item -ItemType Directory -Force -Path ".\out" | Out-Null
  python .\jigsaw_cli.py hunt $OutDir --report .\out\analysis_report.txt --json .\out\detections.json --csv .\out\detections.csv --events-json .\out\events.json
  Write-Host "[+] Results written to .\out"
}
