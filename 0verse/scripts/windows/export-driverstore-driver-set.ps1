$ErrorActionPreference = 'Stop'

$output = Get-Volume | Where-Object {
    $_.DriveLetter -and (Test-Path (Join-Path ($_.DriveLetter + ':') 'OUTPUT.TAG'))
} | Select-Object -First 1
if (-not $output) { throw 'output exchange volume not found' }

$outputRoot = $output.DriveLetter + ':\'
$driverRoot = 'C:\Windows\System32\DriverStore\FileRepository'
$destinationRoot = Join-Path $outputRoot 'driverstore'
New-Item $destinationRoot -ItemType Directory -Force | Out-Null

$manifest = @()
$drivers = Get-ChildItem $driverRoot -Filter '*.sys' -File -Recurse -ErrorAction SilentlyContinue
foreach ($driver in $drivers) {
    $relative = $driver.FullName.Substring($driverRoot.Length).TrimStart('\')
    $destination = Join-Path $destinationRoot $relative
    $destinationDirectory = Split-Path $destination -Parent
    New-Item $destinationDirectory -ItemType Directory -Force | Out-Null
    Copy-Item $driver.FullName $destination -Force

    $retained = Get-Item $destination
    $hash = Get-FileHash $destination -Algorithm SHA256
    $manifest += [pscustomobject]@{
        source = $driver.FullName
        output = Join-Path 'driverstore' $relative
        length = $retained.Length
        file_version = $retained.VersionInfo.FileVersion
        product_version = $retained.VersionInfo.ProductVersion
        sha256 = $hash.Hash.ToLowerInvariant()
    }
}

$manifest | ConvertTo-Json -Depth 4 |
    Out-File (Join-Path $outputRoot 'driverstore-driver-set-manifest.json') -Encoding utf8
New-Item (Join-Path $outputRoot 'DRIVERSTORE-DRIVERS-DONE.TAG') -ItemType File -Force | Out-Null
shutdown.exe /s /t 5
