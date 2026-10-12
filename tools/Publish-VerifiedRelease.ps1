param(
    [Parameter(Mandatory)] [string]$Tag,
    [switch]$Publish
)
$ErrorActionPreference = 'Stop'
$repo = 'MiranoVerhoef/BeszelAgentManager'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:GITHUB_REPOSITORY -ne $repo -or $env:GITHUB_REF -ne 'refs/heads/main') {
    throw 'Run only through the official main-only publication workflow.'
}
if ($Tag -notmatch '^4\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})(-rc[1-9][0-9]{0,5})?$') { throw 'Invalid release tag.' }
function Api([string]$Path) {
    $json = & gh api $Path
    if ($LASTEXITCODE -ne 0) { throw 'GitHub API request failed.' }
    return ($json | ConvertFrom-Json)
}
function Identity($Release) {
    return ($Release | Select-Object id,tag_name,draft,prerelease,target_commitish,updated_at,
        @{n='assets';e={ @($_.assets | Sort-Object id | Select-Object id,name,size,digest,updated_at,state) }} |
        ConvertTo-Json -Depth 8 -Compress)
}
$matchesByTag = @(Api "repos/$repo/releases?per_page=100" | Where-Object tag_name -CEQ $Tag)
if ($matchesByTag.Count -ne 1) { throw 'Draft tag is missing or ambiguous in recent releases.' }
$release = $matchesByTag[0]
if (-not $release.draft -or $release.tag_name -cne $Tag) { throw 'Expected an unpublished draft.' }
$rc = $Tag.Contains('-rc')
if ([bool]$release.prerelease -ne $rc) { throw 'Release channel differs from tag.' }
if ($release.target_commitish -notmatch '^[0-9a-f]{40}$') { throw 'Draft must target an exact commit.' }
& git merge-base --is-ancestor $release.target_commitish HEAD
if ($LASTEXITCODE -ne 0) { throw 'Release commit is not in trusted main history.' }
$latest = Api "repos/$repo/releases/latest"
if ($latest.tag_name -notmatch '^4\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$' -or
    [version]($Tag -replace '-rc[0-9]+$','') -le [version]$latest.tag_name) { throw 'Release must advance latest stable.' }
$latestId = $latest.id
$before = Identity $release
$required = @('BeszelAgentManagerSetup.exe','BeszelAgentManagerSetup-Lite.exe','targets.json','snapshot.json','timestamp.json','1.root.json')
$assets = @($release.assets | Where-Object { $_.name -in $required -or $_.name -match '^[1-9][0-9]*\.root\.json$' })
foreach ($name in $required) {
    if (@($assets | Where-Object name -CEQ $name).Count -ne 1) { throw "Missing or duplicate asset: $name" }
}
if ($assets.Count -gt 70) { throw 'Excessive root chain.' }
$directory = Join-Path $env:RUNNER_TEMP ('approved-release-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $directory | Out-Null
foreach ($asset in $assets) {
    $max = if ($asset.name.EndsWith('.exe')) { 512MB } else { 256KB }
    if ($asset.state -ne 'uploaded' -or $asset.size -le 0 -or $asset.size -gt $max -or
        $asset.digest -notmatch '^sha256:[0-9a-f]{64}$') { throw 'Invalid asset properties.' }
    & gh release download $Tag --repo $repo --pattern $asset.name --dir $directory
    if ($LASTEXITCODE -ne 0) { throw 'Asset download failed.' }
    $file = Get-Item -LiteralPath (Join-Path $directory $asset.name)
    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($file.Length -ne $asset.size -or "sha256:$hash" -cne $asset.digest) { throw 'Downloaded asset differs from draft.' }
}
$root = Join-Path $PSScriptRoot '..'
$anchor = Join-Path $root 'src/BeszelAgentManager.Core/Updates/Trust/root.json'
if ((Get-FileHash $anchor).Hash -ne (Get-FileHash (Join-Path $directory '1.root.json')).Hash) { throw 'Initial public root differs from embedded trust.' }
& dotnet build (Join-Path $PSScriptRoot 'BeszelAgentManager.ReleaseSigning') -c Release
if ($LASTEXITCODE -ne 0) { throw 'Verifier build failed.' }
$tool = Join-Path $PSScriptRoot 'BeszelAgentManager.ReleaseSigning/bin/Release/net10.0/BeszelAgentManager.ReleaseSigning.exe'
& $tool verify-release $directory $directory $Tag
if ($LASTEXITCODE -ne 0) { throw 'Signature, expiry, version or installer verification failed.' }
if ((Identity (Api "repos/$repo/releases/$($release.id)")) -cne $before -or
    (Api "repos/$repo/releases/latest").id -ne $latestId) { throw 'Release state changed during verification; rerun.' }
if ($Publish) {
    # This step never signs, replaces assets, executes an installer or takes key material.
    $body = @{draft=$false; make_latest=$(if ($rc) {'false'} else {'true'})} | ConvertTo-Json -Compress
    $result = $body | & gh api "repos/$repo/releases/$($release.id)" --method PATCH --input -
    if ($LASTEXITCODE -ne 0) { throw 'Publication failed.' }
    $published = $result | ConvertFrom-Json
    if ($published.draft -or $published.tag_name -cne $Tag) { throw 'Unexpected publication result.' }
    Write-Host "Published verified release: $Tag"
} else { Write-Host "Verified draft: $Tag" }
