param(
    [Parameter(Mandatory)] [string]$InstallerDirectory,
    [string]$KeyDirectory = (Join-Path ([Environment]::GetFolderPath('Desktop')) 'BeszelReleaseKeys'),
    [long]$Counter = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
)
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$tool = Join-Path $PSScriptRoot 'BeszelAgentManager.ReleaseSigning\bin\Release\net10.0\BeszelAgentManager.ReleaseSigning.exe'
if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { throw 'Build ReleaseSigning in Release first.' }
$installers = (Resolve-Path -LiteralPath $InstallerDirectory).Path
$version = (Get-Content -LiteralPath (Join-Path $root 'VERSION') -Raw).Trim()
$channel = (Get-Content -LiteralPath (Join-Path $root 'RELEASE_CHANNEL') -Raw).Trim()
$tag = if ($channel -eq 'stable') { $version } else { "$version-$channel" }
if ($Counter -le 0) { throw 'Counter must exceed all previously published role counters.' }
$output = Join-Path $installers "public-metadata-$Counter"
New-Item -ItemType Directory -Path $output -ErrorAction Stop | Out-Null
function Run-Signer([string[]]$Arguments) {
    & $tool @Arguments
    if ($LASTEXITCODE -ne 0) { throw 'Signing stopped. Keep completed files; do not publish partial metadata.' }
}
function Expiry([int]$Days) { [DateTime]::UtcNow.AddDays($Days).ToString("yyyy-MM-ddTHH:mm:ssZ") }
Write-Host "Approve ONLY the tested installers from this checkout ($tag). Private keys stay local."
Run-Signer @('targets', $installers, $tag, "$Counter", (Expiry 90), (Join-Path $output 'targets.unsigned.json'))
Run-Signer @('sign', (Join-Path $output 'targets.unsigned.json'), (Join-Path $KeyDirectory 'targets.private.pk8'), (Join-Path $output 'targets.json'))
Run-Signer @('snapshot', (Join-Path $output 'targets.json'), "$Counter", (Expiry 7), (Join-Path $output 'snapshot.unsigned.json'))
Run-Signer @('sign', (Join-Path $output 'snapshot.unsigned.json'), (Join-Path $KeyDirectory 'snapshot.private.pk8'), (Join-Path $output 'snapshot.json'))
Run-Signer @('timestamp', (Join-Path $output 'snapshot.json'), "$Counter", (Expiry 1), (Join-Path $output 'timestamp.unsigned.json'))
Run-Signer @('sign', (Join-Path $output 'timestamp.unsigned.json'), (Join-Path $KeyDirectory 'timestamp.private.pk8'), (Join-Path $output 'timestamp.json'))
Copy-Item -LiteralPath (Join-Path $root 'src\BeszelAgentManager.Core\Updates\Trust\root.json') -Destination (Join-Path $output '1.root.json')
Run-Signer @('verify-release', $output, $installers, $tag)
Write-Host "Verified public metadata: $output"
Write-Host 'Attach only signed targets.json, snapshot.json, timestamp.json and versioned public roots. Never upload keys or unsigned intermediates.'
