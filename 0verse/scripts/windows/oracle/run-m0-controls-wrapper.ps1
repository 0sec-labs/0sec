#requires -RunAsAdministrator
[CmdletBinding()]
param(
  [ValidateSet('witness','crash','all')]
  [string]$Arm = 'all',
  [string]$Root = 'C:\oracle-lab'
)

$ErrorActionPreference = 'Stop'
$runner = Join-Path $PSScriptRoot 'run-m0-controls.ps1'
$transcript = Join-Path $Root 'logs\m0-controls.log'
$exitCode = 1

try {
  Start-Transcript -Path $transcript -Force | Out-Null
  & $runner -Arm $Arm -Root $Root
  $exitCode = 0
} catch {
  # Keep the original diagnostic without letting ErrorActionPreference bypass
  # the explicit process exit below.
  Write-Error -ErrorRecord $_ -ErrorAction Continue
} finally {
  Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
}

exit $exitCode
