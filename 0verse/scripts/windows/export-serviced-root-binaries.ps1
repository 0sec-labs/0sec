$ErrorActionPreference = 'Stop'

$output = Get-Volume | Where-Object {
    $_.DriveLetter -and (Test-Path (Join-Path ($_.DriveLetter + ':') 'OUTPUT.TAG'))
} | Select-Object -First 1
if (-not $output) { throw 'output exchange volume not found' }
$outputRoot = $output.DriveLetter + ':\'

$files = @(
    @{ Source = 'C:\Windows\System32\ntoskrnl.exe'; Name = 'ntoskrnl.exe' },
    @{ Source = 'C:\Windows\System32\hal.dll'; Name = 'hal.dll' },
    @{ Source = 'C:\Windows\System32\securekernel.exe'; Name = 'securekernel.exe' },
    @{ Source = 'C:\Windows\System32\drivers\winhv.sys'; Name = 'winhv.sys' },
    @{ Source = 'C:\Windows\System32\drivers\winhvr.sys'; Name = 'winhvr.sys' },
    @{ Source = 'C:\Windows\System32\drivers\vid.sys'; Name = 'vid.sys' },
    @{ Source = 'C:\Windows\System32\hvix64.exe'; Name = 'hvix64.exe' },
    @{ Source = 'C:\Windows\System32\hvax64.exe'; Name = 'hvax64.exe' }
)

$manifest = @()
foreach ($file in $files) {
    if (-not (Test-Path $file.Source)) { continue }
    $destination = Join-Path $outputRoot $file.Name
    Copy-Item $file.Source $destination -Force
    $item = Get-Item $destination
    $hash = Get-FileHash $destination -Algorithm SHA256
    $manifest += [pscustomobject]@{
        source = $file.Source
        output = $file.Name
        length = $item.Length
        file_version = $item.VersionInfo.FileVersion
        product_version = $item.VersionInfo.ProductVersion
        sha256 = $hash.Hash.ToLowerInvariant()
    }
}

$manifest | ConvertTo-Json -Depth 4 | Out-File (Join-Path $outputRoot 'root-binaries-manifest.json') -Encoding utf8
New-Item (Join-Path $outputRoot 'ROOT-BINARIES-DONE.TAG') -ItemType File -Force | Out-Null
shutdown.exe /s /t 5
