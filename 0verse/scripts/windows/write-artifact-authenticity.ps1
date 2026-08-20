param(
    [Parameter(Mandatory = $true)][string]$ArtifactPath,
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [Parameter(Mandatory = $true)]
    [ValidateSet('network-isolated', 'network-enabled')]
    [string]$NetworkMode
)

$ErrorActionPreference = 'Stop'
$ProofLimit = 'Producer-observed Windows trust result only; Microsoft root pinning, explicit catalog membership, package-to-output provenance, servicing replay, vulnerability status, and redistribution rights are unproven.'
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop

function Get-Sha256([string]$Path) {
    $stream = [System.IO.File]::OpenRead($Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ($sha.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') }) -join ''
    } finally {
        $sha.Dispose()
        $stream.Dispose()
    }
}

function Convert-Certificate([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate) {
    if ($null -eq $Certificate) { return $null }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $certSha = ($sha.ComputeHash($Certificate.RawData) | ForEach-Object { $_.ToString('x2') }) -join ''
    } finally {
        $sha.Dispose()
    }
    return [ordered]@{
        subject = [string]$Certificate.Subject
        issuer = [string]$Certificate.Issuer
        serial_number = [string]$Certificate.SerialNumber
        thumbprint_sha1 = ([string]$Certificate.Thumbprint).ToUpperInvariant()
        cert_sha256 = $certSha
        not_before_utc = $Certificate.NotBefore.ToUniversalTime().ToString('o')
        not_after_utc = $Certificate.NotAfter.ToUniversalTime().ToString('o')
    }
}

$artifact = Get-Item -LiteralPath $ArtifactPath
if ($artifact.PSIsContainer) { throw 'artifact must be a file' }
if (Test-Path -LiteralPath $OutputPath) { throw 'output receipt already exists' }
$outputDirectory = Split-Path -Parent $OutputPath
if (-not $outputDirectory) { $outputDirectory = (Get-Location).Path }
if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
    throw 'output receipt parent does not exist'
}

$before = Get-Sha256 $artifact.FullName
$beforeLength = $artifact.Length
$signature = Get-AuthenticodeSignature -LiteralPath $artifact.FullName
$after = Get-Sha256 $artifact.FullName
$afterItem = Get-Item -LiteralPath $artifact.FullName
if ($before -ne $after -or $beforeLength -ne $afterItem.Length) {
    throw 'artifact changed during signature verification'
}
if ([string]$signature.Status -ne 'Valid') {
    throw "signature status is $($signature.Status)"
}
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$receipt = [ordered]@{
    schema_version = '0verse.windows-authenticity-observation/v1'
    producer = 'zeroverse.windows-authenticity/powershell-v1'
    artifact = [ordered]@{
        path = $afterItem.Name
        sha256 = $after
        size_bytes = $afterItem.Length
    }
    verification = [ordered]@{
        status = [string]$signature.Status
        status_message = [string]$signature.StatusMessage
        signature_type = [string]$signature.SignatureType
        is_os_binary = [bool]$signature.IsOSBinary
        verified_at_utc = [DateTime]::UtcNow.ToString('o')
        trust_mode = 'windows-local-machine'
        revocation_mode = 'get-authenticode-signature-default'
        network_mode = $NetworkMode
        signer_certificate = Convert-Certificate $signature.SignerCertificate
        timestamper_certificate = Convert-Certificate $signature.TimeStamperCertificate
        verifier = [ordered]@{
            powershell_version = $PSVersionTable.PSVersion.ToString()
            os_build_lab_ex = [string]$cv.BuildLabEx
        }
    }
    verified_claims = @('producer-observed-windows-valid-signature', 'retained-content-sha256')
    proof_limit = $ProofLimit
}

$temporary = Join-Path $outputDirectory ('.authenticity-' + [Guid]::NewGuid().ToString('N') + '.json')
try {
    $receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $OutputPath
    $final = Get-Sha256 $artifact.FullName
    if ($final -ne $before) {
        Remove-Item -LiteralPath $OutputPath -Force
        throw 'artifact changed after receipt publication'
    }
} finally {
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
}
