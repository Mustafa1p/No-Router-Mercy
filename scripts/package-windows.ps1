[CmdletBinding()]
param(
    [ValidateSet('x86', 'x64')]
    [string]$Architecture = 'x64',
    [string]$OutputDirectory,
    [string]$IsccPath = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path (Split-Path $repo -Parent) 'No-Router-Mercy-releases'
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if (-not (Test-Path -LiteralPath $IsccPath -PathType Leaf)) {
    throw 'Install Inno Setup 6.3+ or pass -IsccPath to ISCC.exe.'
}
function Assert-Success([string]$Step) {
    if ($LASTEXITCODE -ne 0) { throw "$Step failed (exit $LASTEXITCODE)" }
}
Push-Location $repo
try {
    $metadataJson = & cargo metadata --no-deps --format-version 1 --locked
    Assert-Success 'Cargo metadata'
    $metadata = $metadataJson | ConvertFrom-Json
    $package = $metadata.packages | Where-Object name -eq 'no-router-mercy'
    $version = $package.version
    $target = if ($Architecture -eq 'x86') { 'i686-pc-windows-msvc' } else { 'x86_64-pc-windows-msvc' }
    & cargo build --release --locked --target $target
    Assert-Success 'Release build'
    $binary = Join-Path $metadata.target_directory "$target/release/no-router-mercy.exe"
    New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
    $stem = "No-Router-Mercy-$version-windows-$Architecture"
    # Unique staging avoids overwriting unrelated files or reusing stale package contents.
    $stage = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $stage | Out-Null
    Copy-Item -LiteralPath $binary -Destination $stage
    foreach ($name in @('README.md', 'THIRD_PARTY_NOTICES.md', 'CONTRIBUTING.md', 'CHANGELOG.md')) {
        Copy-Item -LiteralPath (Join-Path $repo $name) -Destination $stage
    }
    Copy-Item -LiteralPath (Join-Path $repo 'examples') -Destination $stage -Recurse
    Copy-Item -LiteralPath (Join-Path $repo 'docs') -Destination $stage -Recurse
    New-Item -ItemType Directory -Path (Join-Path $stage 'src-media') | Out-Null
    Copy-Item -LiteralPath (Join-Path $repo 'src-media/app-icon.png') -Destination (Join-Path $stage 'src-media')
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath (Join-Path $OutputDirectory "$stem-portable.zip") -Force
    & $IsccPath '/Qp' "/DAppVersion=$version" "/DAppArch=$Architecture" "/DBinaryPath=$binary" "/DReleaseDir=$OutputDirectory" (Join-Path $repo 'installer/windows.iss')
    Assert-Success 'Inno Setup compilation'
    foreach ($name in @("$stem-portable.zip", "$stem-setup.exe")) {
        $file = Join-Path $OutputDirectory $name
        $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
        [IO.File]::WriteAllText("$file.sha256", "$hash  $name`n")
    }
    Write-Host "Release artifacts: $OutputDirectory"
} finally {
    if ($stage -and (Test-Path -LiteralPath $stage)) {
        $resolvedStage = [IO.Path]::GetFullPath($stage)
        $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
        if (-not $resolvedStage.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to clean a staging folder outside TEMP'
        }
        Remove-Item -LiteralPath $resolvedStage -Recurse -Force
    }
    Pop-Location
}
