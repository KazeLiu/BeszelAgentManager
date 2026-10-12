param(
    [Parameter(Mandatory)] [string]$NssmPath
)
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$nssm = (Resolve-Path -LiteralPath $NssmPath).Path
if (-not (Test-Path -LiteralPath $nssm -PathType Leaf)) { throw 'Trusted NSSM binary is missing.' }
$version = (Get-Content -LiteralPath (Join-Path $root 'VERSION') -Raw).Trim()
$channel = (Get-Content -LiteralPath (Join-Path $root 'RELEASE_CHANNEL') -Raw).Trim()
$output = Join-Path $root ('build\private-tests\' + $version + '-' + $channel + '-' + [DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))
New-Item -ItemType Directory -Path $output | Out-Null
$compiler = (Get-Command ISCC.exe -ErrorAction Stop).Source

function Clear-GeneratedBin([string]$relative) {
    if ($relative -notin @('src\BeszelAgentManager.WinUI\bin', 'src\BeszelAgentManager.Helper\bin')) { throw 'Unexpected build cleanup path.' }
    $path = [IO.Path]::GetFullPath((Join-Path $root $relative))
    if (-not $path.StartsWith($root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Build cleanup escapes checkout.' }
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force }
}

Push-Location $root
try {
    foreach ($edition in @('bundled','lite')) {
        Clear-GeneratedBin 'src\BeszelAgentManager.WinUI\bin'
        Clear-GeneratedBin 'src\BeszelAgentManager.Helper\bin'
        $selfContained = if ($edition -eq 'bundled') { 'true' } else { 'false' }
        & dotnet build src/BeszelAgentManager.WinUI -c Release -p:Platform=x64 -r win-x64 --self-contained $selfContained
        if ($LASTEXITCODE -ne 0) { throw "$edition application build failed." }
        $dist = Join-Path $output $edition
        New-Item -ItemType Directory -Path $dist | Out-Null
        $source = Join-Path $root 'src\BeszelAgentManager.WinUI\bin\x64\Release\net10.0-windows10.0.26100.0\win-x64'
        Copy-Item -Path (Join-Path $source '*') -Destination $dist -Recurse
        Copy-Item -LiteralPath $nssm -Destination (Join-Path $dist 'nssm.exe')
        & (Join-Path $root 'installer\New-FileManifest.ps1') -DistDir $dist
        $arguments = @('/Q', 'installer\BeszelAgentManager.iss', "/DAppVersion=$version", "/DDistDir=$dist", "/DInstallerOutputDir=$output")
        if ($edition -eq 'lite') { $arguments += '/DLiteInstaller' }
        & $compiler @arguments
        if ($LASTEXITCODE -ne 0) { throw "$edition installer compilation failed." }
    }
    $checksums = foreach ($name in @('BeszelAgentManagerSetup.exe','BeszelAgentManagerSetup-Lite.exe')) {
        $hash = (Get-FileHash -LiteralPath (Join-Path $output $name) -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $name"
    }
    $checksums | Set-Content -LiteralPath (Join-Path $output 'SHA256SUMS.txt') -Encoding ascii
    Write-Host "Private test installers: $output"
} finally { Pop-Location }
