[CmdletBinding()]
param(
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version = '0.2.0',
    [string]$ISCC
)

$ErrorActionPreference = 'Stop'
chcp 65001 > $null
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
$projectRoot = Split-Path -Parent $PSScriptRoot
$stagingDir = Join-Path $projectRoot 'dist/windows-amd64'
$distDir = Join-Path $projectRoot 'dist'

if (-not $ISCC) {
    $compiler = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($compiler) { $ISCC = $compiler.Source }
    foreach ($candidate in @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 7\ISCC.exe"
    )) {
        if (-not $ISCC -and (Test-Path -LiteralPath $candidate)) { $ISCC = $candidate }
    }
}
if (-not $ISCC -or -not (Test-Path -LiteralPath $ISCC)) {
    throw 'Inno Setup compiler not found. Install Inno Setup 6 or pass -ISCC <absolute path>.'
}

New-Item -ItemType Directory -Force -Path $stagingDir | Out-Null
Push-Location $projectRoot
$previousGOOS, $previousGOARCH, $previousCGO = $env:GOOS, $env:GOARCH, $env:CGO_ENABLED
try {
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    $env:CGO_ENABLED = '0'
    & go build -trimpath -ldflags "-s -w -X netlens/internal/model.Version=$Version" -o (Join-Path $stagingDir 'netlens-cli.exe') ./cmd/netlens
    if ($LASTEXITCODE -ne 0) { throw 'Go build failed.' }
    & (Join-Path $PSScriptRoot 'build-desktop.ps1') -Version $Version -Output (Join-Path $stagingDir 'NetLens.exe')
    Copy-Item -LiteralPath README.md, THIRD_PARTY_NOTICES.txt -Destination $stagingDir -Force
    Copy-Item -LiteralPath THIRD_PARTY_LICENSES -Destination $stagingDir -Recurse -Force
    New-Item -ItemType Directory -Force -Path (Join-Path $stagingDir 'examples'), (Join-Path $stagingDir 'docs') | Out-Null
    Copy-Item -LiteralPath examples/mcp-http.json, examples/mcp-windows.json -Destination (Join-Path $stagingDir 'examples') -Force
    Copy-Item -LiteralPath docs/windows.md -Destination (Join-Path $stagingDir 'docs') -Force
    & $ISCC "/DAppVersion=$Version" "/DSourceDir=$stagingDir" "/DOutputDir=$distDir" packaging/windows/netlens.iss
    if ($LASTEXITCODE -ne 0) { throw 'Inno Setup compilation failed.' }
    $installer = Join-Path $distDir "NetLens-$Version-windows-amd64-setup.exe"
    $portable = Join-Path $distDir "NetLens-$Version-windows-amd64.zip"
    Compress-Archive -Path (Join-Path $stagingDir '*') -DestinationPath $portable -Force
    $checksumLines = foreach ($file in @($installer, $portable)) {
        '{0}  {1}' -f (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant(), (Split-Path -Leaf $file)
    }
    [System.IO.File]::WriteAllLines((Join-Path $distDir 'SHA256SUMS.txt'), [string[]]$checksumLines, [System.Text.UTF8Encoding]::new($false))
    Write-Output "Installer: $installer"
    Write-Output "Portable: $portable"
} finally {
    $env:GOOS, $env:GOARCH, $env:CGO_ENABLED = $previousGOOS, $previousGOARCH, $previousCGO
    Pop-Location
}
